"""Offline JSON evidence bundle verification and export helpers."""
from __future__ import annotations

import argparse
import json
import sqlite3
from pathlib import Path
from typing import Any

from . import config, ledger
from .events import canonical_json, verify_claim
from .identity import lookup_identity
from .quorum import verify_receipt


def make_bundle(watermark_id: str, matches: list[dict], confidence: float,
                extraction_source: str) -> dict[str, Any]:
    if not matches:
        raise ValueError("No verified validator quorum for this watermark.")
    first = matches[0]
    entry, claim, identity = first["entry"], first["claim"], first["recipient_identity"]
    validators = []
    for item in matches:
        validators.append({"validator_id": item["receipt"]["receipt"]["validator_id"],
            "receipt": item["receipt"]["receipt"],
            "receipt_signature_hex": item["receipt"]["receipt_signature_hex"],
            "validator_public_key": item["receipt"]["validator_public_key"],
            "validator_sig_alg": item["receipt"]["validator_sig_alg"],
            "entry": item["entry"], "proof": item["proof"]})
    return {"format": "sigilchain-evidence-v1", "extracted_watermark_id": watermark_id,
        "claim": claim, "canonical_claim_hex": canonical_json(claim).hex(),
        "recipient_signature_hex": entry["signature_hex"],
        "recipient_public_identity": identity, "ledger_backend": entry["ledger_backend"],
        "required_quorum": config.QUORUM_REQUIRED, "validator_evidence": validators,
        "extraction_confidence": confidence, "extraction_source": extraction_source,
        "claim_limit": "This links the recovered mark to a registered key-signed session claim. It does not prove human presence, physical leak distribution, or trusted time.",
        "consensus_limit": "etcd/Raft provides crash-fault consensus, not Byzantine consensus; colocated validators share a host failure domain."}


def verify_bundle(bundle: dict[str, Any], identity_db: str | None = None,
                  validator_trust: str | None = None, required_quorum: int | None = None) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(bundle, dict):
        return False, ["Malformed evidence bundle: top-level value must be an object."]
    claim = bundle.get("claim")
    watermark_id = bundle.get("extracted_watermark_id")
    recipient = bundle.get("recipient_public_identity")
    signature = bundle.get("recipient_signature_hex")
    if not isinstance(claim, dict):
        return False, ["Malformed evidence bundle: claim must be an object."]
    if not isinstance(recipient, dict):
        return False, ["Malformed evidence bundle: recipient identity must be an object."]
    if not isinstance(watermark_id, str) or not isinstance(signature, str):
        return False, ["Malformed evidence bundle: watermark ID and signature must be strings."]
    canonical = canonical_json(claim)
    evidence_items = bundle.get("validator_evidence", [])
    if not isinstance(evidence_items, list):
        errors.append("Malformed evidence bundle: validator_evidence must be an array.")
        evidence_items = []
    if bundle.get("format") != "sigilchain-evidence-v1":
        errors.append("Unsupported evidence bundle format.")
    if claim.get("watermark_id") != watermark_id:
        errors.append("Extracted watermark ID differs from the signed claim.")
    for item in evidence_items:
        if not isinstance(item, dict):
            errors.append("Malformed validator evidence item.")
            continue
        entry = item.get("entry")
        if not isinstance(entry, dict) or entry.get("watermark_id") != watermark_id:
            errors.append("A validator ledger entry watermark ID differs from the extracted mark.")
    if bundle.get("canonical_claim_hex") != canonical.hex():
        errors.append("Canonical claim bytes do not match the claim object.")
    if recipient.get("recipient_id") != claim.get("recipient_id"):
        errors.append("Included public identity does not match the claim recipient.")
    if not verify_claim(claim, signature, recipient.get("sig_public", ""), recipient.get("sig_alg", "")):
        errors.append("Recipient ML-DSA signature is invalid.")
    if identity_db:
        try:
            trusted = lookup_identity(claim["recipient_id"], db_path=identity_db,
                key_version=int(claim["key_version"]), allow_revoked=True)
            if not trusted or trusted["sig_public"] != recipient["sig_public"] or trusted["sig_alg"] != recipient["sig_alg"]:
                errors.append("Recipient key does not match the trusted identity registry.")
        except (KeyError, OSError, sqlite3.Error, ValueError) as exc:
            errors.append(f"Could not check recipient against trusted registry: {exc}")
    trust_path = Path(validator_trust or config.VALIDATOR_TRUST)
    try:
        pins = json.loads(trust_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pins = {}
    valid: set[str] = set()
    seen: set[str] = set()
    for item in evidence_items:
        try:
            if not isinstance(item, dict):
                continue
            validator_id = item["validator_id"]
            if validator_id in seen:
                continue
            seen.add(validator_id)
            entry, proof = item["entry"], item["proof"]
            if not isinstance(entry, dict) or not isinstance(proof, list):
                continue
            if not ledger.verify_chain(proof, watermark_id) or not proof or proof[-1] != entry:
                continue
            if entry.get("claim_json") != canonical.decode() or entry.get("signature_hex") != signature:
                continue
            evidence = {"receipt": item["receipt"],
                "receipt_signature_hex": item["receipt_signature_hex"],
                "validator_public_key": item["validator_public_key"]}
            if verify_receipt(evidence, watermark_id, entry, pins):
                valid.add(validator_id)
        except (AttributeError, KeyError, TypeError, ValueError, IndexError):
            continue
    try:
        declared_quorum = int(bundle.get("required_quorum", config.QUORUM_REQUIRED))
        operator_quorum = int(required_quorum) if required_quorum is not None else config.QUORUM_REQUIRED
        if declared_quorum < 1 or operator_quorum < 1 or config.QUORUM_REQUIRED < 1:
            raise ValueError("quorum must be positive")
        # Bundle metadata may require stricter verification, but cannot weaken
        # the local operator's configured threshold.
        required = max(config.QUORUM_REQUIRED, declared_quorum, operator_quorum)
    except (TypeError, ValueError):
        required = max(1, config.QUORUM_REQUIRED)
        errors.append("Evidence quorum value is malformed or below the local minimum.")
    if len(valid) < required:
        errors.append(f"Only {len(valid)} distinct pinned validator receipts and chain proofs verify; {required} required.")
    return not errors, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an offline SigilChain evidence JSON bundle")
    parser.add_argument("bundle")
    parser.add_argument("--identity-db")
    parser.add_argument("--validator-trust")
    args = parser.parse_args(argv)
    try:
        bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read evidence bundle: {exc}")
        return 2
    ok, errors = verify_bundle(bundle, args.identity_db, args.validator_trust)
    if ok:
        print("Evidence verified: recipient claim signature, pinned validator receipts, and chain proofs pass.")
        print("This verifies a key-signed session claim; it does not identify the physical distributor of a leak.")
        return 0
    for error in errors:
        print(f"FAIL: {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
