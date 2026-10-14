"""
SigilChain — ledger storage and hash-chain verification.

In the Docker Compose demo, the canonical ordered event log is the shared
three-member etcd/Raft cluster (see validator.consensus). SQLite stores
each validator's signed receipt cache and provides a single-process,
local-ledger fallback when etcd is not configured. It is not a replicated
SQLite consensus system.

Every event hash depends on the previous event hash. A verifier can detect
edits within the retained chain by recomputing links from genesis. A hash
chain alone does not stop an operator who controls the storage from
replacing the whole database and rebuilding a locally consistent history.

This module is pure Python + sqlite3 (both stdlib) — no PQC, no network.
It's deliberately kept separate from signature verification: node.py
(FastAPI layer) verifies the recipient's ML-DSA signature BEFORE calling
append_entry(); this module provides local storage and hash-chain integrity
checks, not an external trust anchor or protection from full storage
replacement.
"""

import hashlib
import json
import sqlite3
import time

from validator import consensus

GENESIS_HASH = "0" * 64


def init_db(db_path: str) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ledger (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            watermark_id TEXT NOT NULL,
            record_json TEXT NOT NULL,
            signature_hex TEXT NOT NULL,
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL UNIQUE,
            committed_at INTEGER NOT NULL
        )
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_watermark ON ledger(watermark_id)")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS validator_receipts (
            watermark_id TEXT PRIMARY KEY,
            validator_id TEXT NOT NULL,
            receipt_json TEXT NOT NULL,
            receipt_signature_hex TEXT NOT NULL,
            validator_public_key TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def save_validator_receipt(db_path: str, watermark_id: str, validator_id: str,
                           receipt: dict, signature_hex: str, public_key: str) -> dict:
    """Persist the first submission acknowledgement so later reads reuse its signature."""
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT OR IGNORE INTO validator_receipts "
        "(watermark_id,validator_id,receipt_json,receipt_signature_hex,validator_public_key) "
        "VALUES (?,?,?,?,?)",
        (watermark_id, validator_id, json.dumps(receipt, sort_keys=True, separators=(",", ":")),
         signature_hex, public_key),
    )
    conn.commit()
    conn.close()
    saved = get_validator_receipt(db_path, watermark_id)
    if saved is None:
        raise RuntimeError("Could not persist validator receipt")
    return saved


def get_validator_receipt(db_path: str, watermark_id: str) -> dict | None:
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT validator_id,receipt_json,receipt_signature_hex,validator_public_key "
        "FROM validator_receipts WHERE watermark_id=?", (watermark_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return {"validator_id": row[0], "receipt": json.loads(row[1]),
            "receipt_signature_hex": row[2], "validator_public_key": row[3]}


def _last_hash(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT entry_hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row else GENESIS_HASH


def append_entry(db_path: str, watermark_id: str, record_bytes: bytes, signature: bytes) -> str:
    """
    Append a new entry to the chain. Only call this AFTER the caller (the
    FastAPI node in Part 5b) has already verified the ML-DSA signature —
    this function trusts its caller completely; it only guarantees
    tamper-evidence of what's already been accepted.

    Returns the new entry's hash.
    """
    if consensus.enabled():
        return consensus.append_entry(watermark_id, record_bytes, signature)

    conn = sqlite3.connect(db_path)
    prev_hash = _last_hash(conn)
    entry_hash = hashlib.sha256(prev_hash.encode() + record_bytes + signature).hexdigest()
    conn.execute(
        "INSERT INTO ledger (watermark_id, record_json, signature_hex, prev_hash, entry_hash, committed_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (watermark_id, record_bytes.decode("utf-8"), signature.hex(), prev_hash, entry_hash, int(time.time())),
    )
    conn.commit()
    conn.close()
    return entry_hash


def get_by_watermark_id(db_path: str, watermark_id: str) -> dict | None:
    """Look up a committed entry by its watermark ID — what the trace
    console (Part 6) calls after extracting a mark from a leaked image."""
    if consensus.enabled():
        committed = consensus.get_by_watermark_id(watermark_id)
        if committed is not None:
            return committed

    conn = sqlite3.connect(db_path)
    row = conn.execute(
        "SELECT id, watermark_id, record_json, signature_hex, prev_hash, entry_hash, committed_at "
        "FROM ledger WHERE watermark_id = ? ORDER BY id DESC LIMIT 1",
        (watermark_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return {
        "id": row[0],
        "watermark_id": row[1],
        "record_json": row[2],
        "signature_hex": row[3],
        "prev_hash": row[4],
        "entry_hash": row[5],
        "committed_at": row[6],
    }


def get_chain_proof(db_path: str, watermark_id: str) -> list[dict] | None:
    """Return the ledger from genesis through the latest entry for this mark.

    A caller can recompute every link instead of trusting a node's
    /chain-integrity boolean. This proves internal chain consistency for
    the returned prefix; it does not prevent an operator from replacing an
    entire ledger with a newly constructed history.
    """
    if consensus.enabled():
        committed_proof = consensus.get_chain_proof(watermark_id)
        if committed_proof is not None:
            return committed_proof

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT id, watermark_id, record_json, signature_hex, prev_hash, entry_hash, committed_at "
        "FROM ledger ORDER BY id ASC"
    ).fetchall()
    conn.close()

    last_match = max((i for i, row in enumerate(rows) if row[1] == watermark_id), default=None)
    if last_match is None:
        return None
    return [
        {
            "id": row[0],
            "watermark_id": row[1],
            "record_json": row[2],
            "signature_hex": row[3],
            "prev_hash": row[4],
            "entry_hash": row[5],
            "committed_at": row[6],
        }
        for row in rows[:last_match + 1]
    ]


def list_entries(db_path: str) -> list[dict]:
    """Return all committed events in their canonical ledger order."""
    if consensus.enabled():
        return consensus.list_entries()
    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT id, watermark_id, record_json, signature_hex, prev_hash, entry_hash, committed_at "
        "FROM ledger ORDER BY id ASC"
    ).fetchall()
    conn.close()
    return [{"id": row[0], "watermark_id": row[1], "record_json": row[2],
             "signature_hex": row[3], "prev_hash": row[4], "entry_hash": row[5],
             "committed_at": row[6], "ledger_backend": "local-sqlite"} for row in rows]


def chain_head(db_path: str) -> dict:
    """Return the current sequence/hash pair used by portable checkpoints."""
    entries = list_entries(db_path)
    if not entries:
        return {"sequence": 0, "entry_hash": GENESIS_HASH,
                "ledger_backend": "etcd-raft" if consensus.enabled() else "local-sqlite"}
    last = entries[-1]
    return {"sequence": int(last["id"]), "entry_hash": last["entry_hash"],
            "ledger_backend": last.get("ledger_backend", "local-sqlite")}


def find_by_watermark_id(db_path: str, watermark_id: str) -> dict | None:
    """Return an existing entry, allowing idempotent record submissions."""
    if consensus.enabled():
        committed = consensus.find_by_watermark_id(watermark_id)
        if committed is not None:
            return committed
    return get_by_watermark_id(db_path, watermark_id)


def list_transfer_children(db_path: str, parent_transfer_event_id: str) -> list[dict]:
    """List transfer events directly branching from a given transfer event."""
    if consensus.enabled():
        entries = consensus.list_entries()
    else:
        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT id,watermark_id,record_json,signature_hex,prev_hash,entry_hash,committed_at "
            "FROM ledger ORDER BY id ASC"
        ).fetchall()
        conn.close()
        entries = [{"id": row[0], "watermark_id": row[1], "record_json": row[2],
                    "signature_hex": row[3], "prev_hash": row[4],
                    "entry_hash": row[5], "committed_at": row[6]} for row in rows]
    matches = []
    for entry in entries:
        try:
            record = json.loads(entry["record_json"])
        except (KeyError, TypeError, ValueError):
            continue
        if (record.get("event_type") == "document_transfer"
                and record.get("parent_transfer_event_id") == parent_transfer_event_id):
            matches.append({"event_id": entry["watermark_id"]})
    return matches


def verify_chain_integrity(db_path: str) -> tuple[bool, str]:
    """
    Walk the entire chain from genesis, recomputing every hash. Returns
    (True, summary) if intact, (False, reason) at the first broken link.
    This detects edits to rows in the current retained chain. It does not
    detect an operator replacing the whole database with a rebuilt chain;
    that requires independently retained checkpoints or signatures.
    """
    if consensus.enabled():
        consensus_ok, consensus_detail = consensus.verify_chain_integrity()
        if not consensus_ok:
            return consensus_ok, consensus_detail

    conn = sqlite3.connect(db_path)
    rows = conn.execute(
        "SELECT id, record_json, signature_hex, prev_hash, entry_hash FROM ledger ORDER BY id ASC"
    ).fetchall()
    conn.close()

    expected_prev = GENESIS_HASH
    for i, (sequence, record_json, signature_hex, prev_hash, entry_hash) in enumerate(rows, start=1):
        if sequence != i:
            return False, f"entry {i}: sequence number is {sequence}, expected {i}"
        if prev_hash != expected_prev:
            return False, f"entry {i}: prev_hash doesn't match previous entry's hash (chain broken or reordered)"
        try:
            recomputed = hashlib.sha256(
                prev_hash.encode() + record_json.encode("utf-8") + bytes.fromhex(signature_hex)
            ).hexdigest()
        except (AttributeError, TypeError, ValueError):
            return False, f"entry {i}: record or signature bytes are malformed"
        if recomputed != entry_hash:
            return False, f"entry {i}: entry_hash doesn't match its own content (record was tampered with)"
        expected_prev = entry_hash

    local_detail = f"legacy local chain intact — {len(rows)} entries verified from genesis"
    if consensus.enabled():
        return True, f"shared log: {consensus_detail}; {local_detail}"
    return True, f"chain intact — {len(rows)} entries verified from genesis"
