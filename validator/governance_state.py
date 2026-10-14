"""Rebuild mutable authorization state from threshold-approved ledger events.

The identity database and validator trust roster are working copies. Once a
governance snapshot has been committed, this module derives their authoritative
contents from the ordered ledger and rewrites drifted copies at validator
startup. The governance roster itself is a trust anchor and must be pinned
outside the validator host (SIGILCHAIN_GOVERNANCE_ROSTER_SHA256).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import tempfile

from crypto.governance import canonical_json, verify_governance_event
from validator import ledger


def _digest(value: dict) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def validate_identity(identity: dict) -> None:
    """Validate the supported recipient algorithms and exact public-key sizes."""
    if not isinstance(identity, dict):
        raise ValueError("governance identity must be an object")
    recipient_id = identity.get("recipient_id")
    if not isinstance(recipient_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", recipient_id):
        raise ValueError("governance identity has an invalid recipient ID")
    if identity.get("kem_alg") != "ML-KEM-768" or identity.get("sig_alg") != "ML-DSA-65":
        raise ValueError(f"identity {recipient_id!r} has unsupported algorithms")
    expected_lengths = {"kem_public": 1184, "sig_public": 1952}
    for field, length in expected_lengths.items():
        try:
            raw = bytes.fromhex(identity.get(field, ""))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"identity {recipient_id!r} has malformed {field}") from exc
        if len(raw) != length:
            raise ValueError(f"identity {recipient_id!r} has invalid {field} length")
    version = identity.get("key_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise ValueError(f"identity {recipient_id!r} has invalid key version")


def validate_validator_trust_roster(trust: dict) -> None:
    """Validate validator identifiers, retained-key shape, algorithms and bytes."""
    if not isinstance(trust, dict) or not trust:
        raise ValueError("validator trust roster must be a non-empty object")
    for validator_id, value in trust.items():
        if not isinstance(validator_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", validator_id):
            raise ValueError("validator trust roster contains an invalid validator ID")
        previous = value.get("previous", []) if isinstance(value, dict) else []
        if not isinstance(previous, list):
            raise ValueError(f"validator pin {validator_id!r} has malformed previous keys")
        candidates = [value, *previous] if isinstance(value, dict) else ([value] if isinstance(value, str) else [])
        if not candidates:
            raise ValueError(f"validator pin {validator_id!r} is malformed")
        for candidate in candidates:
            public_key = candidate if isinstance(candidate, str) else candidate.get("public_key") if isinstance(candidate, dict) else None
            algorithm = candidate.get("sig_alg") if isinstance(candidate, dict) else None
            try:
                decoded_key = bytes.fromhex(public_key) if isinstance(public_key, str) else b""
                lengths = {32, 1952} if algorithm is None else (
                    {32} if algorithm == "Ed25519" else {1952} if algorithm == "ML-DSA-65" else set()
                )
                if len(decoded_key) not in lengths:
                    raise ValueError
            except ValueError as exc:
                raise ValueError(f"validator pin {validator_id!r} has malformed public key or algorithm") from exc


def _validate_snapshot(details: dict) -> tuple[dict[str, dict], dict[tuple[str, int], dict], dict]:
    snapshot = details.get("snapshot")
    if not isinstance(snapshot, dict) or snapshot.get("schema") != "sigilchain-state-snapshot-v1":
        raise ValueError("governance snapshot has an unsupported schema")
    if not isinstance(snapshot.get("identities"), list) or not isinstance(snapshot.get("history"), list):
        raise ValueError("snapshot identities and history must be arrays")
    identities: dict[str, dict] = {}
    history: dict[tuple[str, int], dict] = {}
    for item in snapshot.get("identities", []):
        if not isinstance(item, dict):
            raise ValueError("snapshot identity must be an object")
        recipient_id = item.get("recipient_id")
        if not isinstance(recipient_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", recipient_id):
            raise ValueError("snapshot contains an invalid recipient ID")
        if recipient_id in identities:
            raise ValueError("snapshot contains duplicate recipient IDs")
        validate_identity(item)
        if (item.get("revoked_at") is not None
                and (not isinstance(item["revoked_at"], int) or isinstance(item["revoked_at"], bool))):
            raise ValueError(f"snapshot identity {recipient_id!r} has invalid revocation time")
        identities[recipient_id] = {key: item.get(key) for key in
            ("recipient_id", "kem_alg", "sig_alg", "kem_public", "sig_public", "key_version", "revoked_at")}
    for item in snapshot.get("history", []):
        if not isinstance(item, dict):
            raise ValueError("snapshot history row must be an object")
        recipient_id, version = item.get("recipient_id"), item.get("key_version")
        if recipient_id not in identities or not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise ValueError("snapshot contains invalid identity history")
        key = (recipient_id, version)
        if key in history:
            raise ValueError("snapshot contains duplicate identity history versions")
        history[key] = {field: item.get(field) for field in
            ("recipient_id", "key_version", "kem_alg", "sig_alg", "kem_public", "sig_public", "created_at", "revoked_at")}
        if not isinstance(history[key]["created_at"], int):
            raise ValueError("snapshot history row has invalid creation time")
        historical_identity = {field: history[key][field] for field in
                               ("recipient_id", "key_version", "kem_alg", "sig_alg", "kem_public", "sig_public")}
        validate_identity(historical_identity)
        if (history[key]["revoked_at"] is not None
                and (not isinstance(history[key]["revoked_at"], int)
                     or isinstance(history[key]["revoked_at"], bool))):
            raise ValueError("snapshot history row has invalid revocation time")
    for recipient_id, identity in identities.items():
        active = history.get((recipient_id, identity["key_version"]))
        if active is None or any(active[field] != identity[field] for field in
            ("kem_alg", "sig_alg", "kem_public", "sig_public")):
            raise ValueError(f"snapshot active key for {recipient_id!r} does not match its history")
        if active["revoked_at"] != identity.get("revoked_at"):
            raise ValueError(f"snapshot active revocation state for {recipient_id!r} is inconsistent")
        versions = {version for (owner, version) in history if owner == recipient_id}
        if versions != set(range(1, identity["key_version"] + 1)):
            raise ValueError(f"snapshot key history for {recipient_id!r} is incomplete")
    trust = snapshot.get("validator_trust_roster")
    validate_validator_trust_roster(trust)
    return identities, history, trust


def validate_snapshot(details: dict) -> None:
    """Validate snapshot contents before an event is allowed into the log."""
    _validate_snapshot(details)


def _apply_event(record: dict, entry: dict, identities: dict[str, dict],
                 history: dict[tuple[str, int], dict], trust: dict) -> dict:
    action = record["action"]
    action_type, details = action["action"], action["details"]
    committed_at = int(entry["committed_at"])
    if action_type == "identity.enroll":
        identity = details["identity"]
        validate_identity(identity)
        recipient_id = identity["recipient_id"]
        if recipient_id in identities or identity.get("key_version") != 1:
            raise ValueError(f"invalid enrollment transition for {recipient_id!r}")
        row = {**identity, "revoked_at": None}
        identities[recipient_id] = row
        history[(recipient_id, 1)] = {**row, "created_at": committed_at}
    elif action_type == "identity.rotate":
        identity = details["identity"]
        validate_identity(identity)
        recipient_id = identity["recipient_id"]
        current = identities.get(recipient_id)
        previous = details.get("previous_key_version")
        if (current is None or current.get("revoked_at") is not None
                or current["key_version"] != previous
                or identity.get("key_version") != previous + 1):
            raise ValueError(f"invalid rotation transition for {recipient_id!r}")
        old = history.get((recipient_id, previous))
        if old is None:
            raise ValueError(f"rotation has no prior history for {recipient_id!r}")
        old["revoked_at"] = committed_at
        row = {**identity, "revoked_at": None}
        identities[recipient_id] = row
        history[(recipient_id, identity["key_version"])] = {**row, "created_at": committed_at}
    elif action_type == "identity.revoke":
        recipient_id, version = details.get("recipient_id"), details.get("key_version")
        current = identities.get(recipient_id)
        if current is None or current["key_version"] != version or current.get("revoked_at") is not None:
            raise ValueError(f"invalid revocation transition for {recipient_id!r}")
        current["revoked_at"] = committed_at
        history[(recipient_id, version)]["revoked_at"] = committed_at
    elif action_type == "validator.trust_roster":
        new_roster = details.get("validators")
        validate_validator_trust_roster(new_roster)
        if details.get("previous_roster_sha256") != _digest(trust):
            raise ValueError("validator roster event does not extend the current roster")
        trust = new_roster
    else:
        raise ValueError(f"unsupported committed governance action {action_type!r}")
    return trust


def rebuild(entries: list[dict], roster: dict, db_path: str, trust_path: str) -> dict:
    """Validate the governance history and restore its latest committed state.

    Returns a summary. No state is changed when validation fails.
    """
    governance_entries = []
    for entry in entries:
        try:
            record = json.loads(entry["record_json"])
        except (KeyError, TypeError, ValueError):
            continue
        if record.get("event_type") == "governance_change":
            governance_entries.append((entry, record))
    if not governance_entries:
        return {"snapshot": False, "governance_events": 0, "restored": False}

    verified = []
    for entry, record in governance_entries:
        record_bytes = canonical_json(record)
        if (entry.get("watermark_id") != record.get("event_id")
                or entry.get("record_json", "").encode("utf-8") != record_bytes
                or entry.get("signature_hex") != ""):
            raise ValueError("governance event ledger bytes or ID are invalid")
        verify_governance_event(record, roster)
        verified.append((entry, record))

    snapshots = [(index, entry, record) for index, (entry, record) in enumerate(verified)
                 if record.get("action", {}).get("action") == "identity.snapshot"]
    if not snapshots:
        raise ValueError("governance events exist but no approved identity.snapshot baseline is committed; run governance_cli.py snapshot")
    snapshot_index, snapshot_entry, snapshot_event = snapshots[-1]
    details = snapshot_event["action"]["details"]
    expected_head = details.get("base_head")
    if (not isinstance(expected_head, dict)
            or expected_head.get("sequence") != int(snapshot_entry["id"]) - 1
            or expected_head.get("entry_hash") != snapshot_entry.get("prev_hash")):
        raise ValueError("snapshot baseline does not bind to the immediately preceding ledger head")
    identities, history, trust = _validate_snapshot(details)
    for entry, record in verified[snapshot_index + 1:]:
        trust = _apply_event(record, entry, identities, history, trust)

    # Avoid writing on normal request checks. Direct edits to either working
    # copy are detected by comparing them to the derived state and repaired.
    expected_current = sorted(
        (row["recipient_id"], row["kem_alg"], row["sig_alg"], row["kem_public"],
         row["sig_public"], row["key_version"], row.get("revoked_at"))
        for row in identities.values()
    )
    expected_history = sorted(
        (row["recipient_id"], row["key_version"], row["kem_alg"], row["sig_alg"],
         row["kem_public"], row["sig_public"], row["created_at"], row.get("revoked_at"))
        for row in history.values()
    )
    conn = sqlite3.connect(db_path, timeout=30)
    actual_current = sorted(conn.execute(
        "SELECT recipient_id,kem_alg,sig_alg,kem_public,sig_public,key_version,revoked_at FROM identities"
    ).fetchall())
    actual_history = sorted(conn.execute(
        "SELECT recipient_id,key_version,kem_alg,sig_alg,kem_public,sig_public,created_at,revoked_at FROM identity_history"
    ).fetchall())
    conn.close()
    try:
        with open(trust_path, encoding="utf-8") as stream:
            actual_trust = json.load(stream)
    except (OSError, json.JSONDecodeError):
        actual_trust = None
    drifted = (actual_current != expected_current or actual_history != expected_history
               or not isinstance(actual_trust, dict) or canonical_json(actual_trust) != canonical_json(trust))
    if not drifted:
        return {"snapshot": True, "governance_events": len(verified),
                "restored": False, "drifted": False, "identities": len(identities),
                "validator_keys": len(trust)}

    # Replace both working copies transactionally/idempotently. SQLite serializes
    # concurrent validator startup/request-time repairs to the shared volume.
    conn = sqlite3.connect(db_path, timeout=30)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("DELETE FROM identities")
        conn.execute("DELETE FROM identity_history")
        conn.executemany(
            "INSERT INTO identities (recipient_id,kem_alg,sig_alg,kem_public,sig_public,key_version,revoked_at) "
            "VALUES (?,?,?,?,?,?,?)",
            [(row["recipient_id"], row["kem_alg"], row["sig_alg"], row["kem_public"],
              row["sig_public"], row["key_version"], row.get("revoked_at"))
             for row in identities.values()],
        )
        conn.executemany(
            "INSERT INTO identity_history (recipient_id,key_version,kem_alg,sig_alg,kem_public,sig_public,created_at,revoked_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            [(row["recipient_id"], row["key_version"], row["kem_alg"], row["sig_alg"],
              row["kem_public"], row["sig_public"], row["created_at"], row.get("revoked_at"))
             for row in history.values()],
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    parent = os.path.dirname(os.path.abspath(trust_path))
    os.makedirs(parent, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".sigilchain-trust-", dir=parent, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(trust, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, trust_path)
    finally:
        if os.path.exists(temporary):
            os.remove(temporary)
    return {"snapshot": True, "governance_events": len(verified),
            "restored": True, "drifted": True, "identities": len(identities),
            "validator_keys": len(trust)}
