"""Export and verify externally held, threshold-approved ledger checkpoints.

Capture on the SigilChain host, get the exact generated action approved by the
required offline governance signers, then seal and copy the checkpoint to a
separate machine or offline drive. Verification queries a validator quorum and
checks that the current hash chain still extends that held checkpoint.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time

import httpx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
from crypto.governance import action_id, make_action, verify_approval_bundle
from validator.attestation import verify_attestation


def _read(path: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write(path: str, value: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    temporary = path + ".tmp"
    with open(temporary, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _nodes(raw: str | None) -> list[str]:
    values = raw.split(",") if raw else config.NODE_URLS
    return [value.strip().rstrip("/") for value in values if value.strip()]


def _get(url: str, path: str) -> dict:
    headers = {config.API_KEY_HEADER: config.API_KEY} if config.API_KEY else {}
    response = httpx.get(url + path, headers=headers, timeout=10.0)
    response.raise_for_status()
    value = response.json()
    if not isinstance(value, dict):
        raise ValueError(f"{url} returned a malformed response")
    return value


def _attested_head(state: dict) -> tuple[str, dict]:
    attestation = state.get("attestation")
    if not isinstance(attestation, dict):
        raise ValueError("validator did not sign its chain-head response")
    statement = attestation.get("statement")
    public_key = attestation.get("validator_public_key")
    signature = attestation.get("signature_hex")
    if (not isinstance(statement, dict) or statement.get("schema") != "sigilchain-chain-head-v1"
            or statement.get("intact") is not True or statement.get("head") != state.get("head")
            or statement.get("validator_sig_alg") not in {"ML-DSA-65", "Ed25519"}):
        raise ValueError("validator chain-head statement is malformed or inconsistent")
    validator_id = statement.get("validator_id")
    algorithm = statement["validator_sig_alg"]
    head = statement.get("head")
    if (not isinstance(validator_id, str) or not isinstance(head, dict)
            or not isinstance(head.get("sequence"), int) or isinstance(head.get("sequence"), bool)
            or head["sequence"] < 0
            or not isinstance(head.get("entry_hash"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", head["entry_hash"])
            or head.get("ledger_backend") not in {"etcd-raft", "local-sqlite"}):
        raise ValueError("validator chain head has malformed sequence, hash, or backend")
    if not config.validator_key_is_trusted(validator_id, public_key, algorithm):
        raise ValueError(f"validator signing key {validator_id!r} is not in the local pinned trust roster")
    if not verify_attestation(statement, signature, public_key, algorithm):
        raise ValueError(f"validator {validator_id!r} returned an invalid chain-head signature")
    return validator_id, statement["head"]


def _digest_entry(previous: str, entry: dict) -> str:
    try:
        record = entry["record_json"].encode("utf-8")
        signature = bytes.fromhex(entry["signature_hex"])
        return hashlib.sha256(previous.encode("ascii") + record + signature).hexdigest()
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("ledger suffix contains malformed event bytes") from exc


def capture(args) -> None:
    responses = []
    failures = []
    for node in _nodes(args.nodes):
        try:
            state = _get(node, "/chain-state")
            if state.get("intact") and isinstance(state.get("head"), dict):
                validator_id, head = _attested_head(state)
                responses.append((node, validator_id, head))
            else:
                failures.append(f"{node}: reported a broken chain")
        except Exception as exc:
            failures.append(f"{node}: {exc}")
    counts: dict[tuple[int, str, str], list[tuple[str, str]]] = {}
    for node, validator_id, head in responses:
        key = (head.get("sequence"), head.get("entry_hash"), head.get("ledger_backend"))
        counts.setdefault(key, []).append((node, validator_id))
    matching = max(counts.items(), key=lambda item: len(item[1]), default=None)
    distinct = {validator_id for _, validator_id in (matching[1] if matching else [])}
    if matching is None or len(distinct) < args.quorum:
        raise RuntimeError(f"Only {len(distinct)} trusted validators agreed on an intact head; quorum={args.quorum}. "
                           + "; ".join(failures))
    (sequence, entry_hash, backend), agreeing_pairs = matching
    agreeing = [node for node, _ in agreeing_pairs]
    action = make_action("ledger.checkpoint", {
        "sequence": sequence, "entry_hash": entry_hash,
        "ledger_backend": backend, "captured_at": int(time.time()),
        "agreeing_validators": agreeing,
        "agreeing_validator_ids": sorted(distinct),
    })
    _write(args.out, action)
    print(f"Captured intact head {sequence} ({entry_hash}) from {len(agreeing)} validators.")
    print(f"Governance action written to {args.out}\nAction ID: {action_id(action)}")
    print("Have the required independent governance key holders approve this exact action, then run seal.")
    if failures:
        print("Unavailable/rejected validators: " + "; ".join(failures))


def seal(args) -> None:
    action, bundle, roster = _read(args.action), _read(args.approvals), _read(args.roster)
    if action.get("action") != "ledger.checkpoint":
        raise ValueError("action must be a ledger.checkpoint proposal")
    _validate_checkpoint_action(action)
    result = verify_approval_bundle(action, bundle, roster)
    checkpoint = {"schema": "sigilchain-ledger-checkpoint-v1",
                  "action": action, "approvals": bundle}
    _write(args.out, checkpoint)
    print(f"Sealed checkpoint {action['details']['sequence']} with {len(result['valid_signers'])}-of-{result['threshold']} governance signatures.")
    print(f"Copy {args.out} and the independently pinned roster to an offline or separately administered location.")


def verify(args) -> None:
    checkpoint = _read(args.checkpoint)
    roster = _read(args.roster)
    if checkpoint.get("schema") != "sigilchain-ledger-checkpoint-v1":
        raise ValueError("Unsupported checkpoint schema")
    action, bundle = checkpoint.get("action"), checkpoint.get("approvals")
    if not isinstance(action, dict) or action.get("action") != "ledger.checkpoint":
        raise ValueError("Checkpoint action is malformed")
    _validate_checkpoint_action(action)
    verified = verify_approval_bundle(action, bundle, roster)
    details = action["details"]
    sequence, trusted_hash = details["sequence"], details["entry_hash"]
    suffixes, failures = [], []
    for node in _nodes(args.nodes):
        try:
            state = _get(node, "/chain-state")
            validator_id, signed_head = _attested_head(state)
            suffix = _get(node, f"/chain-suffix/{sequence}")
            head = signed_head
            if not state.get("intact") or not isinstance(head, dict):
                raise ValueError("node reports a broken chain")
            if head.get("sequence", -1) < sequence:
                raise ValueError("live ledger is behind the held checkpoint (possible rollback)")
            if suffix.get("head") != head:
                raise ValueError("node returned inconsistent head responses")
            previous, expected_sequence = trusted_hash, sequence + 1
            for entry in suffix.get("entries", []):
                if int(entry.get("id", -1)) != expected_sequence or entry.get("prev_hash") != previous:
                    raise ValueError(f"chain does not extend checkpoint at sequence {expected_sequence}")
                computed = _digest_entry(previous, entry)
                if computed != entry.get("entry_hash"):
                    raise ValueError(f"entry hash mismatch at sequence {expected_sequence}")
                previous, expected_sequence = computed, expected_sequence + 1
            if expected_sequence - 1 != head["sequence"] or previous != head["entry_hash"]:
                raise ValueError("verified suffix does not reach the live ledger head")
            suffixes.append((node, validator_id, head))
        except Exception as exc:
            failures.append(f"{node}: {exc}")
    head_counts: dict[tuple[int, str], list[str]] = {}
    for node, validator_id, head in suffixes:
        head_counts.setdefault((head["sequence"], head["entry_hash"]), []).append((node, validator_id))
    winner = max(head_counts.items(), key=lambda item: len(item[1]), default=None)
    distinct = {validator_id for _, validator_id in (winner[1] if winner else [])}
    if winner is None or len(distinct) < args.quorum:
        raise RuntimeError(f"Only {len(distinct)} trusted validators verified an extension of the checkpoint; quorum={args.quorum}. "
                           + "; ".join(failures))
    current_sequence, current_hash = winner[0]
    print(f"VALID: checkpoint signatures {len(verified['valid_signers'])}-of-{verified['threshold']}.")
    print(f"Held sequence {sequence} is an ancestor of current sequence {current_sequence}.")
    print(f"Current head: {current_hash}; verified by {len(distinct)} trusted validators.")
    if failures:
        print("Unavailable/rejected validators: " + "; ".join(failures))


def _validate_checkpoint_action(action: dict) -> None:
    """Reject malformed or ambiguous checkpoint metadata before signature use."""
    details = action.get("details")
    if not isinstance(details, dict):
        raise ValueError("Checkpoint details are malformed")
    sequence, entry_hash, backend = (details.get("sequence"), details.get("entry_hash"),
                                    details.get("ledger_backend"))
    if (not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0
            or not isinstance(entry_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", entry_hash)
            or backend not in {"etcd-raft", "local-sqlite"}):
        raise ValueError("Checkpoint sequence, hash, or ledger backend is malformed")
    captured_at = details.get("captured_at")
    validators, validator_ids = (details.get("agreeing_validators"),
                                 details.get("agreeing_validator_ids"))
    if (not isinstance(captured_at, int) or isinstance(captured_at, bool) or captured_at <= 0
            or not isinstance(validators, list) or not validators
            or any(not isinstance(item, str) or not item for item in validators)
            or not isinstance(validator_ids, list) or not validator_ids
            or any(not isinstance(item, str) or not item for item in validator_ids)
            or len(set(validators)) != len(validators)
            or len(set(validator_ids)) != len(validator_ids)):
        raise ValueError("Checkpoint capture metadata is malformed")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("capture", help="Capture an intact head agreed by a validator quorum")
    create.add_argument("--nodes", help="Comma-separated validator URLs")
    create.add_argument("--quorum", type=int, default=config.QUORUM_REQUIRED)
    create.add_argument("--out", required=True)
    create.set_defaults(func=capture)
    seal_parser = sub.add_parser("seal", help="Attach threshold governance signatures to a captured checkpoint")
    seal_parser.add_argument("--action", required=True)
    seal_parser.add_argument("--approvals", required=True)
    seal_parser.add_argument("--roster", required=True)
    seal_parser.add_argument("--out", required=True)
    seal_parser.set_defaults(func=seal)
    check = sub.add_parser("verify", help="Verify a held checkpoint against a live validator quorum")
    check.add_argument("--checkpoint", required=True)
    check.add_argument("--roster", required=True)
    check.add_argument("--nodes", help="Comma-separated validator URLs")
    check.add_argument("--quorum", type=int, default=config.QUORUM_REQUIRED)
    check.set_defaults(func=verify)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
