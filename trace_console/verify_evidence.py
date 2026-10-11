"""Offline verifier for exported SigilChain evidence bundles.

The bundle proves that its record verifies under the included recipient
public key and that each included ledger prefix is internally consistent.
Use --identity-db with a trusted enrollment registry to check the key-to-ID
binding; a public key included in the bundle cannot establish that binding
by itself.
"""

import argparse
import hashlib
import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.quorum_client import verify_chain_proof
from crypto.keys import lookup_identity
from crypto.sign import serialize_record, verify_record
from validator.attestation import verify_receipt
import config


def verify_bundle(bundle: dict, identity_db: str | None = None,
                  validator_trust_file: str | None = None) -> tuple[bool, list[str]]:
    errors = []
    try:
        record = bundle["record"]
        watermark_id = bundle["extracted_watermark_id"]
        public_identity = bundle["recipient_public_identity"]
        record_bytes = serialize_record(record)
        signature = bytes.fromhex(bundle["signature_hex"])
        public_key = bytes.fromhex(public_identity["sig_public"])
        sig_alg = public_identity["sig_alg"]
    except (KeyError, TypeError, ValueError) as exc:
        return False, [f"Malformed evidence bundle: {exc}"]

    if record.get("watermark_id") != watermark_id:
        errors.append("Extracted watermark ID does not match the signed record.")
    if public_identity.get("recipient_id") != record.get("recipient_id"):
        errors.append("Included public identity does not match the signed record recipient.")
    if bundle.get("canonical_record_bytes_hex") != record_bytes.hex():
        errors.append("Canonical record bytes do not match the record object.")
    if not verify_record(record_bytes, signature, sig_alg, public_key):
        errors.append("Recipient signature does not verify under the included public key.")

    if identity_db:
        try:
            trusted = lookup_identity(
                record["recipient_id"], db_path=identity_db,
                key_version=record.get("key_version", 1), allow_revoked=True,
            )
            if (trusted["sig_alg"] != sig_alg
                    or trusted["sig_public"] != public_identity["sig_public"]):
                errors.append("Included public key does not match the trusted identity registry.")
        except (KeyError, OSError, sqlite3.Error) as exc:
            errors.append(f"Could not verify recipient identity against registry: {exc}")

    evidence = bundle.get("validator_evidence", [])
    proofs = bundle.get("validator_chain_proofs", [])
    declared_backend = bundle.get("ledger_backend")
    if declared_backend == "etcd-raft" and any(
        item.get("ledger_backend") != "etcd-raft" for item in evidence
    ):
        errors.append("Evidence declares an etcd/Raft log but includes a validator response from another backend.")
    if declared_backend and any(item.get("ledger_backend") != declared_backend for item in evidence):
        errors.append("Validator evidence does not consistently identify the declared ledger backend.")
    trust_path = validator_trust_file or config.VALIDATOR_TRUST_FILE
    try:
        with open(trust_path, encoding="utf-8") as f:
            trusted_validators = json.load(f)
    except (OSError, json.JSONDecodeError):
        trusted_validators = {}
    valid_nodes = set()
    for index, proof in enumerate(proofs):
        if not verify_chain_proof(proof, watermark_id) or not proof:
            continue
        tail = proof[-1]
        matches_record = (
            tail.get("watermark_id") == watermark_id
            and tail.get("record_json") == record_bytes.decode("utf-8")
            and tail.get("signature_hex") == bundle.get("signature_hex")
        )
        if not matches_record:
            continue
        if index >= len(evidence):
            continue
        item = evidence[index]
        node_id = item.get("validator_id")
        receipt = item.get("receipt")
        validator_key = item.get("validator_public_key")
        if not node_id or not receipt or not validator_key:
            continue
        pinned = trusted_validators.get(node_id)
        if config.REQUIRE_TRUSTED_VALIDATORS and not pinned:
            continue
        validator_sig_alg = (item.get("validator_sig_alg")
                             or receipt.get("validator_sig_alg"))
        if pinned and not config.validator_key_is_trusted(
                node_id, validator_key, validator_sig_alg):
            continue
        if not verify_receipt(receipt, item.get("receipt_signature_hex", ""),
                              validator_key, validator_sig_alg):
            continue
        if (receipt.get("validator_id") != node_id
                or receipt.get("watermark_id") != watermark_id
                or (declared_backend and receipt.get("ledger_backend") != declared_backend)
                or receipt.get("entry_hash") != tail.get("entry_hash")
                or receipt.get("sequence") != tail.get("id")
                or receipt.get("prev_hash") != tail.get("prev_hash")
                or receipt.get("committed_at") != tail.get("committed_at")
                or receipt.get("entry_hash") != item.get("entry_hash")
                or receipt.get("record_hash") != hashlib.sha256(record_bytes).hexdigest()
                or receipt.get("signature_hash") != hashlib.sha256(signature).hexdigest()):
            continue
        valid_nodes.add(node_id)

    try:
        required_quorum = int(bundle.get("required_quorum", 2))
    except (TypeError, ValueError):
        required_quorum = 2
        errors.append("Required quorum field is invalid.")
    if required_quorum < 1 or len(valid_nodes) < required_quorum:
        errors.append(
            f"Only {len(valid_nodes)} distinct pinned validator receipts and chain proofs match the signed record; "
            f"{required_quorum} are required."
        )

    transfer_trail = bundle.get("transfer_trail", [])
    if record.get("transfer_event_id") and not transfer_trail:
        errors.append("The session references a transfer event, but the verified transfer trail is missing.")
    previous_event_id = None
    for hop_number, hop in enumerate(transfer_trail, start=1):
        try:
            transfer = hop["record"]
            transfer_id = transfer["event_id"]
            transfer_bytes = serialize_record(transfer)
            transfer_signature = bytes.fromhex(hop["signature_hex"])
            transfer_identity = hop["sender_public_identity"]
            sender_id = transfer["from_id"]
            sender_version = transfer["from_key_version"]
            if (transfer.get("event_type") != "document_transfer"
                    or transfer_identity.get("recipient_id") != sender_id
                    or transfer_identity.get("key_version") != sender_version
                    or transfer_identity.get("sig_alg") != transfer.get("from_sig_alg")
                    or not verify_record(transfer_bytes, transfer_signature,
                                         transfer_identity["sig_alg"],
                                         bytes.fromhex(transfer_identity["sig_public"]))):
                errors.append(f"Transfer hop {hop_number}: sender signature or identity is invalid.")
                continue
            if previous_event_id is not None and transfer.get("parent_transfer_event_id") != previous_event_id:
                errors.append(f"Transfer hop {hop_number}: parent link does not match the preceding event.")
            if hop_number > 1:
                prior_transfer = transfer_trail[hop_number - 2]["record"]
                if (prior_transfer.get("to_id") != transfer.get("from_id")
                        or prior_transfer.get("doc_id") != transfer.get("doc_id")
                        or prior_transfer.get("target_package_id") != transfer.get("source_package_id")
                        or prior_transfer.get("target_package_sha256") != transfer.get("source_package_sha256")
                        or prior_transfer.get("target_document_sha256") != transfer.get("source_document_sha256")):
                    errors.append(f"Transfer hop {hop_number}: package, holder, document, or content-hash link is invalid.")
            if identity_db:
                trusted_sender = lookup_identity(sender_id, db_path=identity_db,
                                                 key_version=sender_version, allow_revoked=True)
                if (trusted_sender["sig_alg"] != transfer_identity["sig_alg"]
                        or trusted_sender["sig_public"] != transfer_identity["sig_public"]):
                    errors.append(f"Transfer hop {hop_number}: sender key does not match the trusted registry.")
            hop_nodes = set()
            hop_evidence = hop.get("validator_evidence", [])
            hop_proofs = hop.get("validator_chain_proofs", [])
            transfer_bytes_hex = transfer_bytes.decode("utf-8")
            for hop_index, hop_proof in enumerate(hop_proofs):
                if (not verify_chain_proof(hop_proof, transfer_id) or not hop_proof
                        or hop_index >= len(hop_evidence)):
                    continue
                tail = hop_proof[-1]
                if (tail.get("watermark_id") != transfer_id
                        or tail.get("record_json") != transfer_bytes_hex
                        or tail.get("signature_hex") != hop["signature_hex"]):
                    continue
                item = hop_evidence[hop_index]
                node_id = item.get("validator_id")
                receipt = item.get("receipt") or {}
                validator_key = item.get("validator_public_key")
                if not node_id or not validator_key:
                    continue
                pinned = trusted_validators.get(node_id)
                if config.REQUIRE_TRUSTED_VALIDATORS and not pinned:
                    continue
                validator_alg = item.get("validator_sig_alg") or receipt.get("validator_sig_alg")
                if pinned and not config.validator_key_is_trusted(node_id, validator_key, validator_alg):
                    continue
                if not verify_receipt(receipt, item.get("receipt_signature_hex", ""),
                                      validator_key, validator_alg):
                    continue
                if (receipt.get("validator_id") != node_id
                        or receipt.get("watermark_id") != transfer_id
                        or receipt.get("ledger_backend") != item.get("ledger_backend")
                        or receipt.get("entry_hash") != tail.get("entry_hash")
                        or receipt.get("sequence") != tail.get("id")
                        or receipt.get("prev_hash") != tail.get("prev_hash")
                        or receipt.get("committed_at") != tail.get("committed_at")
                        or receipt.get("entry_hash") != item.get("entry_hash")
                        or receipt.get("record_hash") != hashlib.sha256(transfer_bytes).hexdigest()
                        or receipt.get("signature_hash") != hashlib.sha256(transfer_signature).hexdigest()):
                    continue
                hop_nodes.add(node_id)
            if len(hop_nodes) < required_quorum:
                errors.append(f"Transfer hop {hop_number}: only {len(hop_nodes)} distinct pinned validator receipts and chain proofs verify; {required_quorum} are required.")
            previous_event_id = transfer_id
        except (KeyError, TypeError, ValueError, OSError, sqlite3.Error) as exc:
            errors.append(f"Transfer hop {hop_number}: malformed or unverifiable evidence ({exc}).")
    if transfer_trail:
        last_hop = transfer_trail[-1].get("record", {})
        if (record.get("transfer_event_id") != last_hop.get("event_id")
                or last_hop.get("to_id") != record.get("recipient_id")
                or last_hop.get("doc_id") != record.get("doc_id")
                or last_hop.get("target_package_id") != record.get("package_id")):
            errors.append("Transfer trail endpoint does not match the signed decryption session.")
    return not errors, errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a SigilChain JSON evidence bundle offline.")
    parser.add_argument("bundle", help="Path to the downloaded SigilChain evidence JSON")
    parser.add_argument("--identity-db", help="Trusted SQLite identity registry for checking recipient key binding")
    parser.add_argument("--validator-trust", help="Pinned validator ID-to-public-key JSON roster")
    args = parser.parse_args()

    with open(args.bundle, encoding="utf-8") as f:
        bundle = json.load(f)
    valid, errors = verify_bundle(bundle, identity_db=args.identity_db,
                                  validator_trust_file=args.validator_trust)
    if valid:
        print("Evidence checks passed: recipient signature, transfer trail (if present), pinned validator receipts, and ledger chain proofs verify.")
        if bundle.get("ledger_backend") == "etcd-raft":
            print("The shared log uses etcd/Raft crash-fault consensus; this is not Byzantine fault tolerant. Receipt times remain local clock claims, not trusted timestamps.")
        else:
            print("Validator receipt times are each validator's reported local clock; this bundle does not establish a shared Raft consensus log or trusted timestamp.")
        if not args.identity_db:
            print("Identity note: the included key was not checked against a trusted enrollment registry.")
        return 0
    print("Evidence checks failed:")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
