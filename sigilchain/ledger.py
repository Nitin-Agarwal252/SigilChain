"""Ordered append-only hash chain; etcd/Raft is the Compose consensus backend."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path
from urllib.parse import quote

import httpx

from . import config
from .events import canonical_json

GENESIS = "0" * 64
PREFIX = "/sigilchain/v1/"
HEAD = PREFIX + "head"
ENTRIES = PREFIX + "entries/"
WATERMARKS = PREFIX + "watermarks/"
RECEIPTS = PREFIX + "receipts/"


class LedgerUnavailable(RuntimeError):
    pass


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value)


def _prefix_end(prefix: str) -> str:
    raw = bytearray(prefix.encode())
    for index in range(len(raw) - 1, -1, -1):
        if raw[index] < 255:
            raw[index] += 1
            return raw[:index + 1].decode()
    return "\0"


def _etcd(path: str, body: dict, timeout: float = 3.0) -> dict:
    errors = []
    for endpoint in config.ETCD_ENDPOINTS:
        try:
            response = httpx.post(endpoint + path, json=body, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(f"{endpoint}: {exc}")
    raise LedgerUnavailable("No etcd endpoint responded: " + "; ".join(errors))


def _range(key: str, end: str | None = None) -> tuple[dict | None, int]:
    body = {"key": _b64(key.encode())}
    if end:
        body["range_end"] = _b64(end.encode())
    data = _etcd("/v3/kv/range", body)
    kvs = data.get("kvs", [])
    item = None
    if kvs:
        item = {"key": _unb64(kvs[0]["key"]).decode(),
                "value": _unb64(kvs[0]["value"]),
                "create_revision": int(kvs[0].get("create_revision", "0")),
                "mod_revision": int(kvs[0].get("mod_revision", "0"))}
    return item, int(data.get("header", {}).get("revision", "0"))


def _get_value(key: str) -> dict | None:
    item, _ = _range(key)
    return json.loads(item["value"]) if item else None


def _set_if_absent(key: str, value: dict) -> bool:
    result = _etcd("/v3/kv/txn", {
        "compare": [{"key": _b64(key.encode()), "target": "CREATE", "result": "EQUAL", "create_revision": "0"}],
        "success": [{"request_put": {"key": _b64(key.encode()), "value": _b64(canonical_json(value))}}],
        "failure": []})
    return bool(result.get("succeeded"))


def get_event(watermark_id: str) -> dict | None:
    if config.ETCD_ENDPOINTS:
        return _get_value(WATERMARKS + quote(watermark_id, safe=""))
    path = os.environ.get("SIGILCHAIN_LOCAL_LEDGER", "local-ledger.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS entries (sequence INTEGER PRIMARY KEY AUTOINCREMENT, watermark_id TEXT UNIQUE, payload TEXT NOT NULL)")
    row = conn.execute("SELECT payload FROM entries WHERE watermark_id=?", (watermark_id,)).fetchone()
    conn.close()
    return json.loads(row[0]) if row else None


def append_event(watermark_id: str, claim: dict, signature_hex: str) -> dict:
    claim_json = canonical_json(claim).decode()
    if config.ETCD_ENDPOINTS:
        mark_key = WATERMARKS + quote(watermark_id, safe="")
        for _ in range(32):
            existing = get_event(watermark_id)
            if existing:
                if existing["claim_json"] == claim_json and existing["signature_hex"] == signature_hex:
                    return existing
                raise ValueError("Watermark ID already commits to a different claim.")
            head_item, _ = _range(HEAD)
            if head_item:
                prior_head = json.loads(head_item["value"])
                previous = prior_head["entry_hash"]
                sequence = int(prior_head["sequence"]) + 1
                compare_head = {"key": _b64(HEAD.encode()), "target": "MOD",
                                "result": "EQUAL", "mod_revision": str(head_item["mod_revision"])}
            else:
                previous, sequence = GENESIS, 1
                compare_head = {"key": _b64(HEAD.encode()), "target": "CREATE",
                                "result": "EQUAL", "create_revision": "0"}
            entry_hash = hashlib.sha256(previous.encode() + claim_json.encode() + bytes.fromhex(signature_hex)).hexdigest()
            entry = {"sequence": sequence, "watermark_id": watermark_id,
                     "claim_json": claim_json, "signature_hex": signature_hex,
                     "previous_hash": previous, "entry_hash": entry_hash,
                     "committed_at_claim": int(time.time()), "ledger_backend": "etcd-raft"}
            head = {"sequence": sequence, "entry_hash": entry_hash}
            body = {"compare": [compare_head], "success": [
                {"request_put": {"key": _b64(mark_key.encode()), "value": _b64(canonical_json(entry))}},
                {"request_put": {"key": _b64((ENTRIES + f"{sequence:020d}").encode()), "value": _b64(canonical_json(entry))}},
                {"request_put": {"key": _b64(HEAD.encode()), "value": _b64(canonical_json(head))}}], "failure": []}
            result = _etcd("/v3/kv/txn", body, timeout=8.0)
            if result.get("succeeded"):
                return entry
        raise LedgerUnavailable("Repeated head contention; failed closed without committing.")

    path = os.environ.get("SIGILCHAIN_LOCAL_LEDGER", "local-ledger.db")
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS entries (sequence INTEGER PRIMARY KEY AUTOINCREMENT, watermark_id TEXT UNIQUE, payload TEXT NOT NULL)")
    conn.execute("BEGIN IMMEDIATE")
    existing_row = conn.execute("SELECT payload FROM entries WHERE watermark_id=?", (watermark_id,)).fetchone()
    if existing_row:
        existing = json.loads(existing_row[0])
        conn.rollback()
        conn.close()
        if existing["claim_json"] == claim_json and existing["signature_hex"] == signature_hex:
            return existing
        raise ValueError("Watermark ID already commits to a different claim.")
    row = conn.execute("SELECT sequence,payload FROM entries ORDER BY sequence DESC LIMIT 1").fetchone()
    previous = GENESIS
    sequence = 1
    if row:
        last = json.loads(row[1])
        previous, sequence = last["entry_hash"], row[0] + 1
    entry_hash = hashlib.sha256(previous.encode() + claim_json.encode() + bytes.fromhex(signature_hex)).hexdigest()
    entry = {"sequence": sequence, "watermark_id": watermark_id,
             "claim_json": claim_json, "signature_hex": signature_hex,
             "previous_hash": previous, "entry_hash": entry_hash,
             "committed_at_claim": int(time.time()), "ledger_backend": "local-sqlite"}
    conn.execute("INSERT INTO entries(watermark_id,payload) VALUES (?,?)", (watermark_id, canonical_json(entry).decode()))
    conn.commit()
    conn.close()
    return entry


def get_chain_proof(watermark_id: str) -> list[dict] | None:
    target = get_event(watermark_id)
    if not target:
        return None
    if config.ETCD_ENDPOINTS:
        data = _etcd("/v3/kv/range", {"key": _b64(ENTRIES.encode()), "range_end": _b64(_prefix_end(ENTRIES).encode())})
        entries = [json.loads(_unb64(kv["value"])) for kv in data.get("kvs", [])]
        entries.sort(key=lambda item: item["sequence"])
        for index, entry in enumerate(entries):
            if entry["watermark_id"] == watermark_id:
                return entries[:index + 1]
        return None
    path = os.environ.get("SIGILCHAIN_LOCAL_LEDGER", "local-ledger.db")
    conn = sqlite3.connect(path)
    rows = conn.execute("SELECT payload FROM entries ORDER BY sequence").fetchall()
    conn.close()
    entries = [json.loads(row[0]) for row in rows]
    for index, entry in enumerate(entries):
        if entry["watermark_id"] == watermark_id:
            return entries[:index + 1]
    return None


def verify_chain(proof: list[dict], watermark_id: str) -> bool:
    previous = GENESIS
    found = False
    for expected_sequence, entry in enumerate(proof, start=1):
        try:
            claim = entry["claim_json"].encode()
            signature = bytes.fromhex(entry["signature_hex"])
            digest = hashlib.sha256(previous.encode() + claim + signature).hexdigest()
            if (entry["sequence"] != expected_sequence or entry["previous_hash"] != previous
                    or entry["entry_hash"] != digest):
                return False
            previous = digest
            if entry["watermark_id"] == watermark_id:
                found = True
                if expected_sequence != len(proof):
                    return False
        except (KeyError, ValueError, TypeError):
            return False
    return found


def save_receipt(watermark_id: str, validator_id: str, receipt: dict) -> dict:
    key = RECEIPTS + quote(watermark_id, safe="") + "/" + validator_id
    if config.ETCD_ENDPOINTS:
        _set_if_absent(key, receipt)
        return _get_value(key) or receipt
    path = os.environ.get("SIGILCHAIN_LOCAL_LEDGER", "local-ledger.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS receipts (watermark_id TEXT, validator_id TEXT, payload TEXT, PRIMARY KEY(watermark_id,validator_id))")
    conn.execute("INSERT OR IGNORE INTO receipts VALUES (?,?,?)", (watermark_id, validator_id, canonical_json(receipt).decode()))
    conn.commit()
    row = conn.execute("SELECT payload FROM receipts WHERE watermark_id=? AND validator_id=?", (watermark_id, validator_id)).fetchone()
    conn.close()
    return json.loads(row[0])


def get_receipt(watermark_id: str, validator_id: str) -> dict | None:
    key = RECEIPTS + quote(watermark_id, safe="") + "/" + validator_id
    if config.ETCD_ENDPOINTS:
        return _get_value(key)
    path = os.environ.get("SIGILCHAIN_LOCAL_LEDGER", "local-ledger.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE IF NOT EXISTS receipts (watermark_id TEXT, validator_id TEXT, payload TEXT, PRIMARY KEY(watermark_id,validator_id))")
    row = conn.execute("SELECT payload FROM receipts WHERE watermark_id=? AND validator_id=?", (watermark_id, validator_id)).fetchone()
    conn.close()
    return json.loads(row[0]) if row else None
