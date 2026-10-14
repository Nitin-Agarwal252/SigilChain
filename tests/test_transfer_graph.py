"""SQLite branch-index checks for the signed handoff graph."""

import json
import hashlib
import os
import sqlite3
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

# The storage-only test exercises SQLite fallback and never makes HTTP calls.
if "httpx" not in sys.modules:
    try:
        import httpx  # noqa: F401
    except ImportError:
        sys.modules["httpx"] = types.SimpleNamespace()

from validator import ledger


def _append_transfer(db_path: str, event_id: str, parent_id: str | None,
                     sender: str, recipient: str) -> None:
    record = json.dumps({
        "event_type": "document_transfer",
        "event_id": event_id,
        "parent_transfer_event_id": parent_id,
        "from_id": sender,
        "to_id": recipient,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    # This tests the branch query only; cryptographic validation is performed
    # by validator.node before real events reach ledger.append_entry.
    connection = sqlite3.connect(db_path)
    row = connection.execute("SELECT entry_hash FROM ledger ORDER BY id DESC LIMIT 1").fetchone()
    previous = row[0] if row else ledger.GENESIS_HASH
    digest = hashlib.sha256(previous.encode() + record + b"signature").hexdigest()
    connection.execute(
        "INSERT INTO ledger (watermark_id,record_json,signature_hex,prev_hash,entry_hash,committed_at) "
        "VALUES (?,?,?,?,?,?)",
        (event_id, record.decode("utf-8"), b"signature".hex(), previous, digest, 1),
    )
    connection.commit()
    connection.close()


class TransferGraphTests(unittest.TestCase):
    def test_fanout_and_descendant_are_separate_branches(self):
        with tempfile.TemporaryDirectory(dir=os.path.dirname(__file__)) as temp_dir:
            db_path = os.path.join(temp_dir, "ledger.db")
            ledger.init_db(db_path)
            _append_transfer(db_path, "a" * 32, None, "A", "B")
            _append_transfer(db_path, "b" * 32, "a" * 32, "B", "C")
            _append_transfer(db_path, "c" * 32, "a" * 32, "B", "D")
            _append_transfer(db_path, "d" * 32, "c" * 32, "D", "E")

            with patch("validator.ledger.consensus.enabled", return_value=False):
                self.assertEqual(
                    ledger.list_transfer_children(db_path, "a" * 32),
                    [{"event_id": "b" * 32}, {"event_id": "c" * 32}],
                )
                self.assertEqual(
                    ledger.list_transfer_children(db_path, "c" * 32),
                    [{"event_id": "d" * 32}],
                )
                self.assertEqual(ledger.list_transfer_children(db_path, "b" * 32), [])


if __name__ == "__main__":
    unittest.main()
