"""Replicated, totally ordered event log backed by a three-member etcd cluster.

etcd uses Raft and acknowledges a write only after a majority commits it.
This protects against crash/unavailable members, not malicious validators.
The log stores signed recipient events; validator receipts remain separately
signed by each validator after it observes the committed log entry.
"""

import base64
import hashlib
import json
import os
import time
from urllib.parse import quote

import httpx

GENESIS_HASH = "0" * 64
PREFIX = "/sigilchain/v1/"
HEAD_KEY = PREFIX + "head"
ENTRY_PREFIX = PREFIX + "entries/"


def _prefix_end(prefix: str) -> str:
    raw = bytearray(prefix.encode("utf-8"))
    for index in range(len(raw) - 1, -1, -1):
        if raw[index] < 0xFF:
            raw[index] += 1
            return raw[:index + 1].decode("utf-8")
    return "\0"


class ConsensusUnavailable(RuntimeError):
    pass


class ConsensusConflict(RuntimeError):
    pass


def endpoints() -> list[str]:
    return [item.strip().rstrip("/") for item in os.environ.get("SIGILCHAIN_ETCD_ENDPOINTS", "").split(",") if item.strip()]


def enabled() -> bool:
    return bool(endpoints())


def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _decode_kv(kv: dict) -> tuple[str, bytes, int]:
    return (base64.b64decode(kv["key"]).decode("utf-8"),
            base64.b64decode(kv["value"]), int(kv.get("mod_revision", "0")))


def _request(path: str, body: dict | None = None, timeout: float = 2.0) -> dict:
    errors = []
    for endpoint in endpoints():
        try:
            response = httpx.post(endpoint + path, json=body or {}, timeout=timeout)
            response.raise_for_status()
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError("etcd returned a non-object response")
            return data
        except (httpx.HTTPError, ValueError, KeyError) as exc:
            errors.append(f"{endpoint}: {exc}")
    raise ConsensusUnavailable("No etcd endpoint responded: " + "; ".join(errors))


def _range(key: str, range_end: str | None = None) -> tuple[dict | None, int]:
    body = {"key": _b64(key.encode())}
    if range_end:
        body["range_end"] = _b64(range_end.encode())
    data = _request("/v3/kv/range", body)
    header_revision = int(data.get("header", {}).get("revision", "0"))
    values = data.get("kvs", [])
    return (_decode_kv(values[0]) if values else None), header_revision


def _entry_key(watermark_id: str) -> str:
    # Hex IDs currently have safe characters, but quote makes the key format robust.
    return ENTRY_PREFIX + quote(watermark_id, safe="")


def get_by_watermark_id(watermark_id: str) -> dict | None:
    item, _ = _range(_entry_key(watermark_id))
    return json.loads(item[1]) if item else None


def find_by_watermark_id(watermark_id: str) -> dict | None:
    return get_by_watermark_id(watermark_id)


def append_entry(watermark_id: str, record_bytes: bytes, signature: bytes) -> str:
    """CAS the ordered hash-chain head; etcd commits each transaction with Raft."""
    record_json = record_bytes.decode("utf-8")
    for _ in range(16):
        existing = get_by_watermark_id(watermark_id)
        if existing:
            if (existing["record_json"].encode() == record_bytes
                    and existing["signature_hex"] == signature.hex()):
                return existing["entry_hash"]
            raise ConsensusConflict("watermark_id is already committed to another event")

        head_item, _ = _range(HEAD_KEY)
        if head_item:
            head = json.loads(head_item[1])
            previous_hash = head["entry_hash"]
            sequence = int(head["sequence"]) + 1
            compare = {"key": _b64(HEAD_KEY.encode()), "target": "MOD",
                       "result": "EQUAL", "mod_revision": str(head_item[2])}
        else:
            previous_hash = GENESIS_HASH
            sequence = 1
            compare = {"key": _b64(HEAD_KEY.encode()), "target": "CREATE",
                       "result": "EQUAL", "create_revision": "0"}

        entry_hash = hashlib.sha256(previous_hash.encode() + record_bytes + signature).hexdigest()
        entry = {
            "id": sequence, "watermark_id": watermark_id, "record_json": record_json,
            "signature_hex": signature.hex(), "prev_hash": previous_hash,
            "entry_hash": entry_hash, "committed_at": int(time.time()),
            "ledger_backend": "etcd-raft",
        }
        head = {"sequence": sequence, "entry_hash": entry_hash}
        body = {
            "compare": [compare],
            "success": [
                {"request_put": {"key": _b64(_entry_key(watermark_id).encode()),
                                  "value": _b64(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode())}},
                {"request_put": {"key": _b64(HEAD_KEY.encode()),
                                  "value": _b64(json.dumps(head, sort_keys=True, separators=(",", ":")).encode())}},
            ],
            "failure": [],
        }
        result = _request("/v3/kv/txn", body, timeout=5.0)
        if result.get("succeeded"):
            return entry_hash
    raise ConsensusUnavailable("Could not append after repeated concurrent head changes")


def get_chain_proof(watermark_id: str) -> list[dict] | None:
    target = get_by_watermark_id(watermark_id)
    if target is None:
        return None
    end = _prefix_end(ENTRY_PREFIX)
    data = _request("/v3/kv/range", {"key": _b64(ENTRY_PREFIX.encode()),
                                      "range_end": _b64(end.encode())})
    entries = [json.loads(_decode_kv(kv)[1]) for kv in data.get("kvs", [])]
    entries.sort(key=lambda item: item["id"])
    for index, entry in enumerate(entries):
        if entry["watermark_id"] == watermark_id:
            return entries[:index + 1]
    return None


def verify_chain_integrity() -> tuple[bool, str]:
    data = _request("/v3/kv/range", {"key": _b64(PREFIX.encode()),
                                      "range_end": _b64(_prefix_end(PREFIX).encode())})
    values = [_decode_kv(kv) for kv in data.get("kvs", [])]
    entries = [json.loads(value) for key, value, _ in values if key.startswith(ENTRY_PREFIX)]
    head_item = next((value for key, value, _ in values if key == HEAD_KEY), None)
    entries.sort(key=lambda item: item["id"])
    previous = GENESIS_HASH
    for index, entry in enumerate(entries, 1):
        if entry.get("id") != index or entry.get("prev_hash") != previous:
            return False, f"entry {index}: sequence or previous hash is invalid"
        try:
            digest = hashlib.sha256(previous.encode() + entry["record_json"].encode()
                                    + bytes.fromhex(entry["signature_hex"])).hexdigest()
        except (KeyError, ValueError):
            return False, f"entry {index}: malformed content"
        if digest != entry.get("entry_hash"):
            return False, f"entry {index}: entry hash is invalid"
        previous = digest
    if entries:
        head = json.loads(head_item) if head_item else {}
        if head.get("sequence") != len(entries) or head.get("entry_hash") != previous:
            return False, "shared log head does not match the verified chain tail"
    elif head_item is not None:
        return False, "shared log has a head but no event entries"
    return True, f"Raft-backed chain prefix intact — {len(entries)} entries verified"
