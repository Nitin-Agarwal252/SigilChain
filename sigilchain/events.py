"""Canonical recipient-signed decryption event claims."""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

import oqs

from .identity import SIG_ALG


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_claim(document_id: str, recipient_id: str, key_version: int,
                watermark_id: str, marked_pdf: bytes, timestamp: int | None = None) -> dict[str, Any]:
    id_pattern = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
    if not isinstance(document_id, str) or not re.fullmatch(id_pattern, document_id):
        raise ValueError("Document IDs must be 1-64 letters, digits, dot, underscore, or hyphen.")
    if not isinstance(recipient_id, str) or not re.fullmatch(id_pattern, recipient_id):
        raise ValueError("Recipient IDs must be 1-64 letters, digits, dot, underscore, or hyphen.")
    if type(key_version) is not int or key_version < 1:
        raise ValueError("Key version must be a positive integer.")
    if not isinstance(watermark_id, str) or not re.fullmatch(r"[0-9a-f]{24}", watermark_id):
        raise ValueError("Watermark IDs must be 24 lowercase hexadecimal characters.")
    if not isinstance(marked_pdf, bytes):
        raise ValueError("Marked document content must be bytes.")
    claimed_at = int(time.time()) if timestamp is None else timestamp
    if type(claimed_at) is not int or claimed_at < 1:
        raise ValueError("Claim timestamp must be a positive integer.")
    return {"schema": "sigilchain-decrypt-claim-v1", "document_id": document_id,
            "recipient_id": recipient_id, "key_version": key_version,
            "watermark_id": watermark_id, "timestamp_claim": claimed_at,
            "marked_file_sha256": hashlib.sha256(marked_pdf).hexdigest()}


def sign_claim(claim: dict[str, Any], private_key_hex: str) -> str:
    with oqs.Signature(SIG_ALG, secret_key=bytes.fromhex(private_key_hex)) as signer:
        return signer.sign(canonical_json(claim)).hex()


def is_well_formed_claim(claim: Any) -> bool:
    """Check v1 claim shape and value types before identity or ledger access."""
    if not isinstance(claim, dict) or set(claim) != {
        "schema", "document_id", "recipient_id", "key_version",
        "watermark_id", "timestamp_claim", "marked_file_sha256",
    }:
        return False
    return (
        claim["schema"] == "sigilchain-decrypt-claim-v1"
        and isinstance(claim["document_id"], str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", claim["document_id"]) is not None
        and isinstance(claim["recipient_id"], str)
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", claim["recipient_id"]) is not None
        and type(claim["key_version"]) is int and claim["key_version"] >= 1
        and type(claim["timestamp_claim"]) is int and claim["timestamp_claim"] >= 1
        and isinstance(claim["watermark_id"], str)
        and re.fullmatch(r"[0-9a-f]{24}", claim["watermark_id"]) is not None
        and isinstance(claim["marked_file_sha256"], str)
        and re.fullmatch(r"[0-9a-f]{64}", claim["marked_file_sha256"]) is not None
    )


def verify_claim(claim: dict[str, Any], signature_hex: str,
                 public_key_hex: str, sig_alg: str = SIG_ALG) -> bool:
    if sig_alg != SIG_ALG or not is_well_formed_claim(claim):
        return False
    try:
        if not isinstance(signature_hex, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", signature_hex):
            return False
        if not isinstance(public_key_hex, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", public_key_hex):
            return False
        with oqs.Signature(SIG_ALG) as verifier:
            return bool(verifier.verify(canonical_json(claim), bytes.fromhex(signature_hex),
                                        bytes.fromhex(public_key_hex)))
    except Exception:
        return False
