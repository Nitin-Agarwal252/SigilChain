"""Threshold approval primitives for high impact SigilChain changes.

Governance approvals are separate ML-DSA-65 keys, not recipient or validator
keys. Each approval signs the exact canonical action bytes so it cannot be
reused for a different identity, validator roster, or key version.

This module verifies approvals only. The validator quorum must still commit
the verified action before an application applies it; a local approval file
alone is not a distributed governance decision.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from typing import Any

import oqs

GOVERNANCE_SIG_ALG = "ML-DSA-65"
ACTION_SCHEMA = "sigilchain-governance-action-v1"
APPROVAL_SCHEMA = "sigilchain-governance-approvals-v1"


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def action_id(action: dict) -> str:
    """Return the stable digest of an exact, validated proposal."""
    if not isinstance(action, dict) or action.get("schema") != ACTION_SCHEMA:
        raise ValueError("Unsupported governance action schema")
    if (not isinstance(action.get("action"), str)
            or not isinstance(action.get("details"), dict)
            or not action["details"]):
        raise ValueError("Governance action must have a type and non-empty details object")
    return hashlib.sha256(canonical_json(action)).hexdigest()


def validate_roster(roster: dict) -> tuple[int, dict[str, str]]:
    if not isinstance(roster, dict) or roster.get("schema") != "sigilchain-governance-roster-v1":
        raise ValueError("Unsupported governance roster")
    members = roster.get("members")
    threshold = roster.get("threshold")
    if (not isinstance(members, list) or not isinstance(threshold, int)
            or isinstance(threshold, bool) or not 1 <= threshold <= len(members)):
        raise ValueError("Governance threshold must be between one and the member count")
    keys: dict[str, str] = {}
    for member in members:
        if not isinstance(member, dict):
            raise ValueError("Governance roster member must be an object")
        member_id, algorithm, public_key = (member.get("id"), member.get("sig_alg"),
                                             member.get("public_key"))
        if (not isinstance(member_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", member_id)
                or member_id in keys):
            raise ValueError("Governance member IDs must be unique valid identifiers")
        if algorithm != GOVERNANCE_SIG_ALG:
            raise ValueError(f"Governance keys must use {GOVERNANCE_SIG_ALG}")
        try:
            decoded_key = bytes.fromhex(public_key)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Governance public key for {member_id!r} is not hex") from exc
        if not decoded_key:
            raise ValueError(f"Governance public key for {member_id!r} is empty")
        keys[member_id] = public_key
    if not keys:
        raise ValueError("Governance roster must contain at least one key")
    return threshold, keys


def make_roster(members: list[dict], threshold: int = 2) -> dict:
    roster = {"schema": "sigilchain-governance-roster-v1",
              "sig_alg": GOVERNANCE_SIG_ALG, "threshold": threshold,
              "members": sorted(members, key=lambda item: item["id"])}
    validate_roster(roster)
    return roster


def make_action(action_type: str, details: dict) -> dict:
    """Build a typed action object; details are included verbatim in its digest."""
    if not re.fullmatch(r"[a-z][a-z0-9_.-]{2,63}", action_type):
        raise ValueError("Invalid governance action type")
    if not isinstance(details, dict) or not details:
        raise ValueError("Governance action details must be a non-empty object")
    action = {"schema": ACTION_SCHEMA, "action": action_type, "details": details}
    action_id(action)
    return action


def sign_action(action: dict, signer_id: str, secret_key: bytes) -> dict:
    payload = canonical_json(action)
    with oqs.Signature(GOVERNANCE_SIG_ALG, secret_key=secret_key) as signer:
        signature = signer.sign(payload)
    return {"signer_id": signer_id, "sig_alg": GOVERNANCE_SIG_ALG,
            "signature": signature.hex()}


def make_approval_bundle(action: dict, approvals: list[dict]) -> dict:
    return {"schema": APPROVAL_SCHEMA, "action_id": action_id(action),
            "approvals": approvals}


def build_governance_event(action: dict, bundle: dict) -> dict:
    """Wrap a threshold-approved action as a deterministic validator-log event."""
    expected_id = action_id(action)
    if bundle.get("action_id") != expected_id:
        raise ValueError("Approval bundle does not match the governance action")
    return {"event_type": "governance_change", "event_id": expected_id[:32],
            "action_id": expected_id, "action": action, "approvals": bundle}


def verify_governance_event(event: dict, roster: dict) -> dict:
    if not isinstance(event, dict) or event.get("event_type") != "governance_change":
        raise ValueError("Not a governance change event")
    action = event.get("action")
    expected_id = action_id(action)
    if event.get("action_id") != expected_id or event.get("event_id") != expected_id[:32]:
        raise ValueError("Governance event ID does not match its signed action")
    result = verify_approval_bundle(action, event.get("approvals"), roster)
    result["event_id"] = event["event_id"]
    return result


def verify_approval_bundle(action: dict, bundle: dict, roster: dict) -> dict:
    """Verify the exact action, distinct authorized signers, and threshold."""
    threshold, keys = validate_roster(roster)
    if not isinstance(bundle, dict) or bundle.get("schema") != APPROVAL_SCHEMA:
        raise ValueError("Unsupported governance approval bundle")
    expected_id = action_id(action)
    if bundle.get("action_id") != expected_id:
        raise ValueError("Approvals do not bind to this exact action")
    approvals = bundle.get("approvals")
    if not isinstance(approvals, list):
        raise ValueError("Approval bundle must contain an approvals list")
    valid_ids: set[str] = set()
    seen_ids: set[str] = set()
    invalid: list[str] = []
    payload = canonical_json(action)
    for approval in approvals:
        if not isinstance(approval, dict):
            invalid.append("malformed approval")
            continue
        signer_id = approval.get("signer_id")
        if signer_id not in keys:
            invalid.append(f"unauthorized signer {signer_id!r}")
            continue
        if signer_id in seen_ids:
            invalid.append(f"duplicate signer {signer_id!r}")
            continue
        seen_ids.add(signer_id)
        if approval.get("sig_alg") != GOVERNANCE_SIG_ALG:
            invalid.append(f"wrong signature algorithm for {signer_id!r}")
            continue
        try:
            signature = bytes.fromhex(approval.get("signature", ""))
            with oqs.Signature(GOVERNANCE_SIG_ALG) as verifier:
                valid = verifier.verify(payload, signature, bytes.fromhex(keys[signer_id]))
        except (TypeError, ValueError) as exc:
            invalid.append(f"malformed signature for {signer_id!r}")
            continue
        if valid:
            valid_ids.add(signer_id)
        else:
            invalid.append(f"invalid signature from {signer_id!r}")
    if len(valid_ids) < threshold:
        details = "; ".join(invalid) if invalid else "not enough distinct valid signers"
        raise PermissionError(
            f"Governance threshold not met: {len(valid_ids)} of {threshold} approvals; {details}"
        )
    return {"action_id": expected_id, "threshold": threshold,
            "valid_signers": sorted(valid_ids)}


def governance_required() -> bool:
    return os.environ.get("SIGILCHAIN_REQUIRE_GOVERNANCE_APPROVALS", "0").strip().lower() in {
        "1", "true", "yes", "on"
    }


def read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def write_json_atomic(path: str, value: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         delete=False, dir=parent,
                                         prefix=".sigilchain-governance-") as stream:
            temp_path = stream.name
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


def require_approval(action: dict, approval_bundle: dict | None = None) -> dict | None:
    """Apply governance only when explicitly enabled; otherwise preserve demo behavior.

    When an approval file is missing, persist the exact action as a proposal
    before refusing the mutation, so a second administrator can approve the
    same bytes instead of asking the first operator to regenerate the change.
    """
    if not governance_required():
        return None
    roster_path = os.environ.get("SIGILCHAIN_GOVERNANCE_ROSTER")
    approvals_path = os.environ.get("SIGILCHAIN_GOVERNANCE_APPROVALS")
    if approval_bundle is None and approvals_path:
        approval_bundle = read_json(approvals_path)
    if not roster_path:
        raise PermissionError("Governance is enabled but SIGILCHAIN_GOVERNANCE_ROSTER is not configured")
    roster = read_json(roster_path)
    directory = os.environ.get("SIGILCHAIN_GOVERNANCE_PROPOSALS_DIR", "governance-proposals")
    proposal_path = os.path.join(directory, action_id(action) + ".json")
    write_json_atomic(proposal_path, action)
    if approval_bundle is None:
        raise PermissionError(
            f"Change requires threshold governance approval. Proposal written to {proposal_path}; "
            "have approvers sign it, then set SIGILCHAIN_GOVERNANCE_APPROVALS to the merged bundle and retry/apply."
        )
    try:
        verified = verify_approval_bundle(action, approval_bundle, roster)
    except (ValueError, PermissionError) as exc:
        raise PermissionError(f"Approvals rejected. Exact proposal retained at {proposal_path}: {exc}") from exc
    if os.environ.get("SIGILCHAIN_GOVERNANCE_APPLY_CONTEXT") != action_id(action):
        raise PermissionError(
            "Threshold approval alone cannot mutate the registry. Commit through scripts/governance_cli.py apply first."
        )
    return verified
