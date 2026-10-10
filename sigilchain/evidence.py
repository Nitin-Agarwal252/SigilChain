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
    try:
        claim = bundle["claim"]
        watermark_id = bundle["extracted_watermark_id"]
        recipient = bundle["recipient_public_identity"]
        signature = bundle["recipient_signature_hex"]
    except (KeyError, TypeError) as exc:
        return False, [f"Malformed evidence bundle: {exc}"]
    canonical = canonical_json(claim)
    if bundle.get("format") != "sigilchain-evidence-v1":
        errors.append("Unsupported evidence bundle format.")
    if claim.get("watermark_id") != watermark_id:
        errors.append("Extracted watermark ID differs from the signed claim.")
    if any(item.get("entry", {}).get("watermark_id") != watermark_id
           for item in bundle.get("validator_evidence", []) if isinstance(item, dict)):
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
    for item in bundle.get("validator_evidence", []):
        try:
            validator_id = item["validator_id"]
            if validator_id in seen:
                continue
            seen.add(validator_id)
            entry, proof = item["entry"], item["proof"]
            if not ledger.verify_chain(proof, watermark_id) or not proof or proof[-1] != entry:
                continue
            if entry.get("claim_json") != canonical.decode() or entry.get("signature_hex") != signature:
                continue
            evidence = {"receipt": item["receipt"],
                "receipt_signature_hex": item["receipt_signature_hex"],
                "validator_public_key": item["validator_public_key"]}
            if verify_receipt(evidence, watermark_id, entry, pins):
                valid.add(validator_id)
        except (KeyError, TypeError, ValueError, IndexError):
            continue
    try:
        required = required_quorum or int(bundle.get("required_quorum", config.QUORUM_REQUIRED))
    except (TypeError, ValueError):
        required = config.QUORUM_REQUIRED
        errors.append("Evidence quorum value is malformed.")
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
