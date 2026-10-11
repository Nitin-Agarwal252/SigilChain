"""Integration checks for the Compose etcd/Raft ledger.

These tests append synthetic events, so they run only when
SIGILCHAIN_TEST_ETCD_ENDPOINTS explicitly points at a disposable cluster.
Do not point this variable at the live demo ledger.
"""

import json
import os
import secrets
import unittest
from concurrent.futures import ThreadPoolExecutor

TEST_ETCD_ENDPOINTS = os.environ.get("SIGILCHAIN_TEST_ETCD_ENDPOINTS", "").strip()
if TEST_ETCD_ENDPOINTS:
    # Override any normal Compose endpoints before the module captures them.
    os.environ["SIGILCHAIN_ETCD_ENDPOINTS"] = TEST_ETCD_ENDPOINTS

from validator import consensus


@unittest.skipUnless(
    TEST_ETCD_ENDPOINTS,
    "requires SIGILCHAIN_TEST_ETCD_ENDPOINTS pointing to a disposable etcd cluster",
)
class ConsensusIntegrationTests(unittest.TestCase):
    def test_concurrent_order_idempotency_conflict_and_chain(self):
        ids = [secrets.token_hex(12) for _ in range(8)]

        def append(watermark_id):
            record = json.dumps({"watermark_id": watermark_id, "test": "raft"},
                                sort_keys=True, separators=(",", ":")).encode()
            signature = secrets.token_bytes(32)
            result_hash = consensus.append_entry(watermark_id, record, signature)
            return watermark_id, record, signature, result_hash

        with ThreadPoolExecutor(max_workers=8) as pool:
            written = list(pool.map(append, ids))

        for watermark_id, record, signature, entry_hash in written:
            self.assertEqual(consensus.append_entry(watermark_id, record, signature), entry_hash)
            saved = consensus.get_by_watermark_id(watermark_id)
            self.assertEqual(saved["entry_hash"], entry_hash)
            with self.assertRaises(consensus.ConsensusConflict):
                consensus.append_entry(watermark_id, record + b" ", signature)
            proof = consensus.get_chain_proof(watermark_id)
            self.assertTrue(proof)
            self.assertEqual(proof[-1]["watermark_id"], watermark_id)

        intact, detail = consensus.verify_chain_integrity()
        self.assertTrue(intact, detail)

    def test_unavailable_majority_fails_closed(self):
        previous = os.environ.get("SIGILCHAIN_ETCD_ENDPOINTS")
        os.environ["SIGILCHAIN_ETCD_ENDPOINTS"] = "http://127.0.0.1:1"
        try:
            with self.assertRaises(consensus.ConsensusUnavailable):
                consensus.append_entry(secrets.token_hex(12), b"{}", b"no-majority")
        finally:
            if previous is None:
                os.environ.pop("SIGILCHAIN_ETCD_ENDPOINTS", None)
            else:
                os.environ["SIGILCHAIN_ETCD_ENDPOINTS"] = previous


if __name__ == "__main__":
    unittest.main()
