"""Optional independent host-attestation and person-authentication checks.

The TPM verifier is a separate trust domain: it must validate a fresh TPM 2.0
quote and measured-boot evidence against an approved reference profile, then
sign the decision returned here. Validators only trust a pinned verifier key.
The OIDC path validates an ID token locally against pinned JWKS.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import time
from typing import Any

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature

from crypto.governance import canonical_json


def _enabled(name: str) -> bool:
    return os.environ.get(name, "0").strip().lower() in {"1", "true", "yes", "on"}


def validate_assurance_configuration() -> None:
    """Fail service startup when an enabled assurance mode is misconfigured."""
    if _enabled("SIGILCHAIN_REQUIRE_PERSON_AUTH"):
        issuer = os.environ.get("SIGILCHAIN_OIDC_ISSUER", "").strip()
        audience = os.environ.get("SIGILCHAIN_OIDC_AUDIENCE", "").strip()
        jwks_file = os.environ.get("SIGILCHAIN_OIDC_JWKS_FILE", "").strip()
        jwks_url = os.environ.get("SIGILCHAIN_OIDC_JWKS_URL", "").strip()
        if not issuer or not audience or not (jwks_file or jwks_url.startswith("https://")):
            raise RuntimeError("person-auth mode requires OIDC issuer, audience, and a JWKS file or HTTPS JWKS URL")
        if jwks_file:
            try:
                _load_jwks()
            except (OSError, ValueError, json.JSONDecodeError, httpx.HTTPError) as exc:
                raise RuntimeError(f"person-auth mode cannot load its configured OIDC JWKS: {exc}") from exc
    if _enabled("SIGILCHAIN_REQUIRE_TPM_ATTESTATION"):
        url = os.environ.get("SIGILCHAIN_TPM_VERIFIER_URL", "").strip()
        host_id = os.environ.get("SIGILCHAIN_TPM_HOST_ID", "").strip()
        profile_id = os.environ.get("SIGILCHAIN_TPM_PROFILE_ID", "").strip()
        verifier_key = os.environ.get("SIGILCHAIN_TPM_VERIFIER_PUBLIC_KEY", "").strip()
        if not url.startswith("https://") or not host_id or not profile_id:
            raise RuntimeError("TPM mode requires HTTPS verifier URL, host ID, and approved profile ID")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(verifier_key))
        except (TypeError, ValueError) as exc:
            raise RuntimeError("TPM mode requires a valid pinned Ed25519 verifier public key") from exc


def _b64url(raw: str) -> bytes:
    return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4))


def decode_jwt_unverified(token: str) -> tuple[dict, dict, bytes, bytes]:
    """Parse a compact JWT without trusting its contents or signature."""
    if not isinstance(token, str) or len(token) > 32768:
        raise ValueError("OIDC assertion is missing or too large")
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("OIDC assertion must be a compact signed JWT")
    try:
        header = json.loads(_b64url(parts[0]))
        payload = json.loads(_b64url(parts[1]))
        signature = _b64url(parts[2])
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("OIDC assertion has malformed base64url or JSON") from exc
    if not isinstance(header, dict) or not isinstance(payload, dict) or not signature:
        raise ValueError("OIDC assertion header, claims, or signature are malformed")
    return header, payload, f"{parts[0]}.{parts[1]}".encode("ascii"), signature


def person_auth_claims(token: str, recipient_id: str) -> dict:
    """Extract the minimal claim set that the recipient will sign into a session."""
    _, claims, _, _ = decode_jwt_unverified(token)
    issuer, subject, jti, nonce = (claims.get("iss"), claims.get("sub"),
                                   claims.get("jti"), claims.get("nonce"))
    auth_time = claims.get("auth_time")
    if (not isinstance(issuer, str) or not isinstance(subject, str) or not subject
            or not isinstance(jti, str) or not jti
            or not isinstance(nonce, str) or len(nonce) < 16
            or not isinstance(auth_time, int) or isinstance(auth_time, bool)):
        raise ValueError("OIDC token must contain iss, sub, jti, nonce, and integer auth_time claims")
    return {"issuer": issuer, "subject": subject, "jti": jti,
            "nonce": nonce, "auth_time": auth_time,
            "recipient_id": recipient_id,
            "assertion_sha256": hashlib.sha256(token.encode("ascii")).hexdigest()}


def person_auth_watermark_id(issuer: str, jti: str) -> str:
    """Make a single-use session lookup ID from the issuer's unique token ID."""
    return hashlib.sha256(f"sigilchain/person-auth/v1\0{issuer}\0{jti}".encode()).hexdigest()[:32]


def _load_jwks() -> dict[str, Any]:
    path = os.environ.get("SIGILCHAIN_OIDC_JWKS_FILE", "").strip()
    if path and os.path.isfile(path):
        with open(path, encoding="utf-8") as stream:
            value = json.load(stream)
    else:
        url = os.environ.get("SIGILCHAIN_OIDC_JWKS_URL", "").strip()
        if not url or not url.startswith("https://"):
            raise ValueError("OIDC requires SIGILCHAIN_OIDC_JWKS_FILE or an HTTPS SIGILCHAIN_OIDC_JWKS_URL")
        response = httpx.get(url, timeout=5.0)
        response.raise_for_status()
        value = response.json()
    if not isinstance(value, dict) or not isinstance(value.get("keys"), list):
        raise ValueError("OIDC JWKS must contain a keys array")
    return value


def _verify_oidc_signature(header: dict, signing_input: bytes, signature: bytes) -> None:
    algorithm, kid = header.get("alg"), header.get("kid")
    if algorithm != "RS256" or not isinstance(kid, str):
        raise ValueError("Only pinned OIDC RS256 signing keys with a kid are accepted")
    try:
        jwks = _load_jwks()
    except (OSError, ValueError, json.JSONDecodeError, httpx.HTTPError) as exc:
        raise ValueError(f"Could not load configured OIDC JWKS: {exc}") from exc
    keys = [item for item in jwks["keys"] if isinstance(item, dict) and item.get("kid") == kid]
    if len(keys) != 1:
        raise ValueError("OIDC signing key is absent or ambiguous in the configured JWKS")
    jwk = keys[0]
    if jwk.get("kty") != "RSA" or jwk.get("use", "sig") != "sig" or jwk.get("alg", "RS256") != "RS256":
        raise ValueError("OIDC JWKS key is not an RSA signature key")
    try:
        modulus, exponent = int.from_bytes(_b64url(jwk["n"]), "big"), int.from_bytes(_b64url(jwk["e"]), "big")
        key = rsa.RSAPublicNumbers(exponent, modulus).public_key()
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    except (KeyError, TypeError, ValueError, InvalidSignature) as exc:
        raise ValueError("OIDC assertion signature is invalid") from exc


def verify_person_auth(token: str, expected: dict, recipient_id: str) -> dict:
    """Verify a fresh OIDC assertion bound to this recipient and signed record."""
    if not _enabled("SIGILCHAIN_REQUIRE_PERSON_AUTH"):
        return {}
    if not isinstance(expected, dict):
        raise ValueError("decryption record has no person-authentication claims")
    header, claims, signing_input, signature = decode_jwt_unverified(token)
    _verify_oidc_signature(header, signing_input, signature)
    issuer = os.environ.get("SIGILCHAIN_OIDC_ISSUER", "").strip()
    audience = os.environ.get("SIGILCHAIN_OIDC_AUDIENCE", "").strip()
    recipient_claim = os.environ.get("SIGILCHAIN_OIDC_RECIPIENT_CLAIM", "sigilchain_recipient_id")
    if not issuer or not audience:
        raise ValueError("OIDC issuer and audience must be configured")
    now = int(time.time())
    max_age = int(os.environ.get("SIGILCHAIN_OIDC_MAX_AUTH_AGE_SECONDS", "120"))
    token_issuer, token_audience = claims.get("iss"), claims.get("aud")
    audiences = token_audience if isinstance(token_audience, list) else [token_audience]
    auth_time, issued_at, expires_at = claims.get("auth_time"), claims.get("iat"), claims.get("exp")
    not_before = claims.get("nbf", 0)
    if (token_issuer != issuer or audience not in audiences
            or not isinstance(auth_time, int) or isinstance(auth_time, bool)
            or not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or not isinstance(not_before, int) or isinstance(not_before, bool)
            or now > expires_at or not_before > now + 30 or issued_at > now + 30
            or auth_time > now + 30 or now - auth_time > max_age
            or now - issued_at > max_age):
        raise ValueError("OIDC issuer, audience, expiration, or authentication freshness check failed")
    actual = person_auth_claims(token, recipient_id)
    if claims.get(recipient_claim) != recipient_id:
        raise ValueError("authenticated OIDC subject is not mapped to this recipient identity")
    if any(actual.get(key) != expected.get(key) for key in
           ("issuer", "subject", "jti", "nonce", "auth_time", "recipient_id", "assertion_sha256")):
        raise ValueError("OIDC claims do not match the recipient-signed session record")
    if (person_auth_watermark_id(actual["issuer"], actual["jti"]) != expected.get("session_id")
            or expected.get("session_id") != expected.get("watermark_id")):
        raise ValueError("OIDC token ID is not bound to this single-use decryption session")
    return {key: actual[key] for key in ("issuer", "subject", "jti", "auth_time", "recipient_id")}


def verify_tpm_host_attestation(validator_id: str, operation_id: str) -> dict | None:
    """Require a fresh, signed approval from an independent TPM quote verifier."""
    if not _enabled("SIGILCHAIN_REQUIRE_TPM_ATTESTATION"):
        return None
    url = os.environ.get("SIGILCHAIN_TPM_VERIFIER_URL", "").strip().rstrip("/")
    host_id = os.environ.get("SIGILCHAIN_TPM_HOST_ID", "").strip()
    profile_id = os.environ.get("SIGILCHAIN_TPM_PROFILE_ID", "").strip()
    verifier_key = os.environ.get("SIGILCHAIN_TPM_VERIFIER_PUBLIC_KEY", "").strip()
    if not url or not host_id or not profile_id or not url.startswith("https://"):
        raise PermissionError("TPM mode requires an HTTPS verifier URL, host ID, and approved profile ID")
    try:
        key_bytes = bytes.fromhex(verifier_key)
        verifier = Ed25519PublicKey.from_public_bytes(key_bytes)
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise PermissionError("TPM verifier Ed25519 public key is not configured correctly") from exc
    challenge = secrets.token_hex(32)
    try:
        response = httpx.post(url + "/v1/attest", json={
            "schema": "sigilchain-tpm-challenge-v1", "validator_id": validator_id,
            "host_id": host_id, "operation_id": operation_id, "nonce": challenge,
        }, timeout=10.0)
        response.raise_for_status()
        envelope = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise PermissionError(f"independent TPM verifier is unavailable or returned invalid JSON: {exc}") from exc
    statement, signature_hex = envelope.get("statement"), envelope.get("signature_hex")
    if not isinstance(statement, dict) or not isinstance(signature_hex, str):
        raise PermissionError("TPM verifier returned a malformed signed decision")
    try:
        verifier.verify(bytes.fromhex(signature_hex), canonical_json(statement))
    except (TypeError, ValueError, InvalidSignature) as exc:
        raise PermissionError("TPM verifier decision signature is invalid") from exc
    issued_at, expires_at = statement.get("issued_at"), statement.get("expires_at")
    now = int(time.time())
    quote_digest = statement.get("quote_sha256")
    if (statement.get("schema") != "sigilchain-tpm-attestation-v1"
            or statement.get("validator_id") != validator_id
            or statement.get("host_id") != host_id
            or statement.get("profile_id") != profile_id
            or statement.get("nonce") != challenge
            or statement.get("operation_id") != operation_id
            or statement.get("approved") is not True
            or not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or not isinstance(expires_at, int) or isinstance(expires_at, bool)
            or issued_at > now + 15 or now - issued_at > 30 or expires_at <= now
            or expires_at - issued_at > 60
            or not isinstance(quote_digest, str) or not re.fullmatch(r"[0-9a-f]{64}", quote_digest)):
        raise PermissionError("TPM quote decision is denied, stale, or bound to another operation/host/profile")
    return {"schema": "sigilchain-tpm-receipt-v1", "validator_id": validator_id,
            "host_id": host_id, "profile_id": profile_id,
            "operation_id": operation_id, "quote_sha256": quote_digest,
            "evidence_id": statement.get("evidence_id"), "issued_at": issued_at,
            "expires_at": expires_at, "verifier_statement": statement,
            "verifier_public_key": verifier_key.lower(),
            "verifier_signature_hex": signature_hex.lower()}


def verify_tpm_receipt(evidence: dict, verifier_public_key_hex: str,
                       validator_id: str) -> bool:
    """Check the verifier's signed statement embedded in a validator receipt."""
    try:
        if not isinstance(evidence, dict):
            return False
        pinned = bytes.fromhex(verifier_public_key_hex)
        if bytes.fromhex(evidence["verifier_public_key"]) != pinned:
            return False
        if evidence.get("schema") != "sigilchain-tpm-receipt-v1":
            return False
        statement = evidence["verifier_statement"]
        if not isinstance(statement, dict):
            return False
        issued_at, expires_at = statement["issued_at"], statement["expires_at"]
        if (not isinstance(statement, dict)
                or statement.get("schema") != "sigilchain-tpm-attestation-v1"
                or statement.get("validator_id") != validator_id
                or evidence.get("validator_id") != validator_id
                or statement.get("host_id") != evidence.get("host_id")
                or statement.get("profile_id") != evidence.get("profile_id")
                or statement.get("operation_id") != evidence.get("operation_id")
                or statement.get("quote_sha256") != evidence.get("quote_sha256")
                or not isinstance(statement.get("nonce"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", statement.get("nonce", ""))
                or not isinstance(statement.get("quote_sha256"), str)
                or not re.fullmatch(r"[0-9a-f]{64}", statement.get("quote_sha256", ""))
                or statement.get("issued_at") != evidence.get("issued_at")
                or statement.get("expires_at") != evidence.get("expires_at")
                or statement.get("approved") is not True
                or not isinstance(issued_at, int) or isinstance(issued_at, bool)
                or not isinstance(expires_at, int) or isinstance(expires_at, bool)
                or expires_at <= issued_at or expires_at - issued_at > 60):
            return False
        Ed25519PublicKey.from_public_bytes(pinned).verify(
            bytes.fromhex(evidence["verifier_signature_hex"]), canonical_json(statement))
        return True
    except Exception:
        return False
