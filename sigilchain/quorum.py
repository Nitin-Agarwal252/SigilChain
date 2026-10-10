"""Fail-closed client for validator submission, receipts, and trace evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import oqs

from . import config, ledger
from .events import canonical_json, verify_claim
from .identity import SIG_ALG


def _headers() -> dict[str, str]:
    return {config.API_KEY_HEADER: config.API_KEY} if config.API_KEY else {}


def load_pins(path: str | None = None) -> dict[str, Any]:
    roster_path = Path(path or config.VALIDATOR_TRUST)
    try:
        roster = json.loads(roster_path.read_text(encoding="utf-8"))
        return roster if isinstance(roster, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _is_pinned(validator_id: str, public_hex: str, pins: dict[str, Any]) -> bool:
    pin = pins.get(validator_id)
    candidates = [pin] if isinstance(pin, dict) else []
    candidates += pin.get("previous", []) if isinstance(pin, dict) else []
    return any(isinstance(item, dict) and item.get("public_key") == public_hex
               and item.get("sig_alg") == SIG_ALG for item in candidates)


def verify_receipt(evidence: dict, watermark_id: str, entry: dict, pins: dict[str, Any]) -> bool:
    receipt = evidence.get("receipt")
    validator_id = receipt.get("validator_id") if isinstance(receipt, dict) else None
    public_hex = evidence.get("validator_public_key")
    if not validator_id or not public_hex or not _is_pinned(validator_id, public_hex, pins):
        return False
    if receipt.get("watermark_id") != watermark_id or receipt.get("entry_hash") != entry.get("entry_hash"):
        return False
    if receipt.get("ledger_backend") != entry.get("ledger_backend"):
        return False
    if receipt.get("sequence") != entry.get("sequence") or receipt.get("previous_hash") != entry.get("previous_hash"):
        return False
    if receipt.get("claim_hash") != hashlib.sha256(entry["claim_json"].encode()).hexdigest():
        return False
    if receipt.get("recipient_signature_hash") != hashlib.sha256(bytes.fromhex(entry["signature_hex"])).hexdigest():
        return False
    try:
        with oqs.Signature(SIG_ALG) as verifier:
            return bool(verifier.verify(canonical_json(receipt), bytes.fromhex(evidence["receipt_signature_hex"]),
                                        bytes.fromhex(public_hex)))
    except Exception:
        return False


def submit_to_quorum(nodes: list[str], claim: dict, signature_hex: str,
                     required: int = 2, pins: dict[str, Any] | None = None) -> dict:
    pins = pins if pins is not None else load_pins()
    accepted, rejected, unreachable = [], [], []
    for base in nodes:
        try:
            response = httpx.post(base + "/submit", json={"watermark_id": claim["watermark_id"],
                "claim": claim, "signature_hex": signature_hex}, headers=_headers(), timeout=10.0)
            response.raise_for_status()
            item = response.json()
            if item.get("accepted") and verify_receipt(item, claim["watermark_id"], item["entry"], pins):
                accepted.append({"url": base, **item})
            else:
                rejected.append({"url": base, "reason": "receipt failed pin or signature verification"})
        except httpx.HTTPError as exc:
            unreachable.append({"url": base, "reason": str(exc)})
    unique = {item["receipt"]["validator_id"] for item in accepted}
    return {"committed": len(unique) >= required, "accepted_by": accepted,
            "rejected_by": rejected, "unreachable": unreachable,
            "required_quorum": required}


def lookup_remote(base_urls: list[str], recipient_id: str) -> dict | None:
    for base in base_urls:
        try:
            response = httpx.get(f"{base}/identity/{recipient_id}", headers=_headers(), timeout=4.0)
            response.raise_for_status()
            data = response.json()
            if data.get("found"):
                return data["identity"]
        except httpx.HTTPError:
            continue
    return None


def check_watermark(nodes: list[str], watermark_id: str, required: int = 2,
                    pins: dict[str, Any] | None = None) -> list[dict]:
    pins = pins if pins is not None else load_pins()
    found = []
    for base in nodes:
        try:
            response = httpx.get(f"{base}/verify/{watermark_id}", headers=_headers(), timeout=5.0)
            response.raise_for_status()
            view = response.json()
            if not view.get("found") or not view.get("chain_valid"):
                continue
            entry = view["entry"]
            proof = view.get("proof", [])
            if not ledger.verify_chain(proof, watermark_id):
                continue
            evidence = view.get("receipt_evidence") or {}
            if not verify_receipt(evidence, watermark_id, entry, pins):
                continue
            claim = json.loads(entry["claim_json"])
            identity_response = httpx.get(f"{base}/identity/{claim['recipient_id']}",
                params={"key_version": claim.get("key_version")}, headers=_headers(), timeout=5.0)
            identity_response.raise_for_status()
            identity = identity_response.json().get("identity") or {}
            if not identity or not verify_claim(claim, entry["signature_hex"], identity["sig_public"], identity["sig_alg"]):
                continue
            found.append({"url": base, "entry": entry, "claim": claim,
                          "recipient_identity": identity, "receipt": evidence,
                          "proof": proof, "ledger_backend": entry["ledger_backend"]})
        except (httpx.HTTPError, KeyError, ValueError, TypeError):
            continue
    distinct = {item["receipt"]["receipt"]["validator_id"] for item in found}
    return found if len(distinct) >= required else []
