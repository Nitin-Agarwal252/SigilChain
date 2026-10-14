"""
SigilChain — agent-side quorum submission.

This client submits the same signed record to every configured validator
node and checks distinct validator receipts. In Compose mode the validator
nodes first commit the event through the shared etcd/Raft ordered log.
The agent treats the marked PDF as releasable only after `required`
distinct, trusted receipts validate; this receipt quorum is separate from
Raft's 2-of-3 crash-fault commit quorum.
"""

import hashlib
import json
import os
import httpx

import config
from validator.attestation import verify_receipt
from crypto.governance import build_governance_event, canonical_json
from security.runtime_assurance import verify_tpm_receipt


def _validate_receipt(data: dict, watermark_id: str, entry_hash: str | None = None) -> tuple[bool, str]:
    receipt = data.get("receipt")
    validator_id = data.get("validator_id") or (receipt or {}).get("validator_id")
    public_key = data.get("validator_public_key")
    if not isinstance(receipt, dict) or not validator_id or not public_key:
        return False, "validator response has no signed receipt"
    sig_alg = data.get("validator_sig_alg") or receipt.get("validator_sig_alg")
    receipt_alg = receipt.get("validator_sig_alg")
    if sig_alg and receipt_alg and sig_alg != receipt_alg:
        return False, "validator signature algorithm does not match the signed receipt"
    pinned = config.trusted_validator_keys().get(validator_id)
    if config.REQUIRE_TRUSTED_VALIDATORS and not pinned:
        return False, f"validator {validator_id!r} is not pinned in the trusted validator roster"
    if pinned and not config.validator_key_is_trusted(validator_id, public_key, sig_alg):
        return False, f"validator {validator_id!r} public key does not match the pinned roster"
    if (receipt.get("validator_id") != validator_id
            or receipt.get("watermark_id") != watermark_id
            or (entry_hash and receipt.get("entry_hash") != entry_hash)):
        return False, "validator receipt fields do not match the response"
    if data.get("ledger_backend") and receipt.get("ledger_backend") != data["ledger_backend"]:
        return False, "validator receipt does not bind the declared ledger backend"
    if data.get("signature_hex"):
        try:
            signature_hash = hashlib.sha256(bytes.fromhex(data["signature_hex"])).hexdigest()
        except (TypeError, ValueError):
            return False, "validator response contains an invalid recipient signature"
        if receipt.get("signature_hash") != signature_hash:
            return False, "validator receipt does not bind the returned recipient signature"
    if isinstance(data.get("record"), dict):
        record_bytes = (canonical_json(data["record"])
                        if data["record"].get("event_type") == "governance_change"
                        else json.dumps(data["record"], sort_keys=True,
                                        separators=(",", ":")).encode("utf-8"))
        if receipt.get("record_hash") != hashlib.sha256(record_bytes).hexdigest():
            return False, "validator receipt does not bind the returned record"
    if not verify_receipt(receipt, data.get("receipt_signature_hex", ""), public_key, sig_alg):
        return False, "validator receipt signature is invalid"
    record = data.get("record")
    person_auth = record.get("person_auth") if isinstance(record, dict) else None
    if person_auth is not None:
        auth_result = receipt.get("person_auth_verification")
        if (not isinstance(auth_result, dict)
                or any(auth_result.get(field) != person_auth.get(field)
                       for field in ("issuer", "subject", "jti", "auth_time", "recipient_id"))
                or not isinstance(auth_result.get("verified_at"), int)
                or isinstance(auth_result.get("verified_at"), bool)):
            return False, "validator receipt does not attest matching person-auth token validation"
    require_tpm = os.environ.get("SIGILCHAIN_REQUIRE_TPM_ATTESTATION", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }
    if require_tpm:
        machine = receipt.get("machine_attestation")
        verifier_key = os.environ.get("SIGILCHAIN_TPM_VERIFIER_PUBLIC_KEY", "").strip()
        if not isinstance(machine, dict) or not verifier_key or not verify_tpm_receipt(
                machine, verifier_key, validator_id):
            return False, "validator receipt has no valid TPM verifier signature under the pinned key"
    return True, "verified"


def _headers() -> dict:
    """Attaches the shared deployment API key (config.py) when one is
    configured; sends nothing extra when it isn't, matching the nodes'
    own no-key-means-open-access default."""
    if config.API_KEY:
        return {config.API_KEY_HEADER: config.API_KEY}
    return {}


def submit_to_quorum(node_urls: list[str], watermark_id: str, record_bytes: bytes,
                      signature: bytes, recipient_id: str, required: int = 2,
                      timeout: float = 5.0, auth_token: str | None = None) -> dict:
    """
    POSTs the record to every node in node_urls. Returns a summary dict:
    {
        "committed": bool,          # True if >= `required` nodes accepted
        "accepted_by": [...],       # which node URLs accepted
        "rejected_by": [...],       # which node URLs rejected (with reasons)
        "unreachable": [...],       # which node URLs couldn't be reached at all
    }
    """
    payload = {
        "watermark_id": watermark_id,
        "record_hex": record_bytes.hex(),
        "signature_hex": signature.hex(),
        "recipient_id": recipient_id,
    }
    if auth_token is not None:
        payload["auth_token"] = auth_token

    accepted_by, rejected_by, unreachable = [], [], []

    for url in node_urls:
        try:
            resp = httpx.post(f"{url.rstrip('/')}/submit", json=payload,
                               headers=_headers(), timeout=timeout)
            if resp.status_code == 401:
                rejected_by.append({"url": url, "reason": "authentication failed -- "
                                     "check SIGILCHAIN_API_KEY matches what this node expects"})
                continue
            resp.raise_for_status()
            data = resp.json()
            if data.get("accepted"):
                valid, reason = _validate_receipt(data, watermark_id, data.get("entry_hash"))
                if valid:
                    accepted_by.append({"url": url, "validator_id": data["validator_id"],
                                        "entry_hash": data.get("entry_hash"),
                                        "ledger_backend": data.get("ledger_backend"),
                                        "receipt": data["receipt"],
                                        "receipt_signature_hex": data["receipt_signature_hex"],
                                        "validator_public_key": data["validator_public_key"],
                                        "validator_sig_alg": data.get("validator_sig_alg")
                                            or data["receipt"].get("validator_sig_alg")})
                else:
                    rejected_by.append({"url": url, "reason": reason})
            else:
                rejected_by.append({"url": url, "reason": data.get("reason")})
        except httpx.HTTPError as e:
            unreachable.append({"url": url, "error": str(e)})

    return {
        "committed": len({item["validator_id"] for item in accepted_by}) >= required,
        "accepted_by": accepted_by,
        "rejected_by": rejected_by,
        "unreachable": unreachable,
    }


def submit_governance_change(node_urls: list[str], action: dict, approvals: dict,
                            required: int = 2, timeout: float = 5.0) -> dict:
    """Commit a threshold-signed administrator action before local application."""
    event = build_governance_event(action, approvals)
    return submit_to_quorum(node_urls, event["event_id"], canonical_json(event),
                            b"", "__governance__", required=required, timeout=timeout)


def check_watermark(node_urls: list[str], watermark_id: str, timeout: float = 5.0) -> list[dict]:
    """
    Query every node for a given watermark_id -- used by the trace console
    (Part 6) to show the person how many configured nodes return the
    record, not just trust the first one that answers.
    """
    results = []
    for url in node_urls:
        try:
            resp = httpx.get(f"{url.rstrip('/')}/verify/{watermark_id}",
                              headers=_headers(), timeout=timeout)
            if resp.status_code == 401:
                results.append({"url": url, "found": False,
                                 "error": "authentication failed -- check SIGILCHAIN_API_KEY"})
                continue
            resp.raise_for_status()
            view = {"url": url, **resp.json()}
            if view.get("found"):
                trusted, trust_reason = _validate_receipt(view, watermark_id, view.get("entry_hash"))
                view["validator_trusted"] = trusted
                view["validator_trust_error"] = None if trusted else trust_reason
                proof_resp = httpx.get(f"{url.rstrip('/')}/chain-proof/{watermark_id}",
                                        headers=_headers(), timeout=timeout)
                proof_resp.raise_for_status()
                proof = proof_resp.json()
                view["chain_proof"] = proof.get("entries", [])
                proof_entries = view["chain_proof"]
                target_matches = False
                if proof_entries:
                    target = proof_entries[-1]
                    canonical_record = json.dumps(
                        view["record"], sort_keys=True, separators=(",", ":")
                    )
                    target_matches = (
                        target.get("watermark_id") == watermark_id
                        and target.get("record_json") == canonical_record
                        and target.get("signature_hex") == view.get("signature_hex")
                        and target.get("entry_hash") == view.get("entry_hash")
                        and target.get("id") == view.get("receipt", {}).get("sequence")
                        and target.get("prev_hash") == view.get("receipt", {}).get("prev_hash")
                        and target.get("committed_at") == view.get("receipt", {}).get("committed_at")
                    )
                view["chain_valid"] = (
                    target_matches and verify_chain_proof(proof_entries, watermark_id)
                )
            results.append(view)
        except httpx.HTTPError as e:
            results.append({"url": url, "found": False, "error": str(e)})
    return results


def list_transfer_children(node_urls: list[str], parent_transfer_event_id: str,
                           timeout: float = 5.0) -> list[str]:
    """Collect candidate branch IDs; callers must verify each event and its quorum."""
    children = set()
    for url in node_urls:
        try:
            response = httpx.get(
                f"{url.rstrip('/')}/transfer-children/{parent_transfer_event_id}",
                headers=_headers(), timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
            if payload.get("parent_transfer_event_id") != parent_transfer_event_id:
                continue
            for item in payload.get("children", []):
                event_id = item.get("event_id") if isinstance(item, dict) else None
                if isinstance(event_id, str) and len(event_id) == 32:
                    children.add(event_id)
        except (httpx.HTTPError, ValueError, TypeError):
            continue
    return sorted(children)


def verify_chain_proof(entries: list[dict], watermark_id: str) -> bool:
    """Verify a node-provided chain prefix locally, starting from genesis."""
    previous = "0" * 64
    matched = False
    try:
        for expected_sequence, entry in enumerate(entries, start=1):
            if int(entry["id"]) != expected_sequence:
                return False
            if entry["prev_hash"] != previous:
                return False
            record_bytes = entry["record_json"].encode("utf-8")
            signature = bytes.fromhex(entry["signature_hex"])
            calculated = hashlib.sha256(previous.encode() + record_bytes + signature).hexdigest()
            if calculated != entry["entry_hash"]:
                return False
            previous = calculated
            matched = entry["watermark_id"] == watermark_id
        return bool(entries) and matched
    except (KeyError, TypeError, ValueError):
        return False


def lookup_identity_remote(node_urls: list[str], recipient_id: str, timeout: float = 5.0) -> dict:
    """
    Scaling piece: resolve a recipient's public keys over the network via
    any reachable validator node's /identity endpoint, instead of
    requiring local access to identity_registry.db. This is what lets a
    sender encrypt for a recipient on a completely different machine --
    tries each node in order and returns the first successful answer.

    Raises KeyError if no reachable node has this recipient_id registered.
    """
    last_error = None
    for url in node_urls:
        try:
            resp = httpx.get(f"{url.rstrip('/')}/identity/{recipient_id}",
                              headers=_headers(), timeout=timeout)
            if resp.status_code == 401:
                last_error = "authentication failed -- check SIGILCHAIN_API_KEY"
                continue
            resp.raise_for_status()
            data = resp.json()
            if data.get("found"):
                return {
                    "recipient_id": data["recipient_id"],
                    "kem_alg": data["kem_alg"],
                    "sig_alg": data["sig_alg"],
                    "kem_public": data["kem_public"],
                    "sig_public": data["sig_public"],
                    "key_version": data["key_version"],
                }
        except httpx.HTTPError as e:
            last_error = e
            continue
    raise KeyError(
        f"No reachable validator node has an identity registered for '{recipient_id}'"
        + (f" (last error: {last_error})" if last_error else "")
    )
