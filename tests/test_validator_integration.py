"""Run the shared-log outage test from a Compose validator container."""
from __future__ import annotations

import unittest
import importlib
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi import HTTPException

from sigilchain import config
from sigilchain.ledger import LedgerUnavailable, get_event


class EtcdIntegrationTests(unittest.TestCase):
    def test_unavailable_cluster_fails_closed(self):
        with patch.object(config, "ETCD_ENDPOINTS", ["http://127.0.0.1:1"]):
            with self.assertRaises(LedgerUnavailable):
                get_event("not-present")

    def test_submit_rejects_malformed_claim_before_identity_lookup(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            config, "VALIDATOR_KEY_PATH", str(Path(directory) / "validator.json")
        ):
            validator = importlib.import_module("sigilchain.validator")
            request = validator.SubmitRequest(
                watermark_id="ab" * 12,
                claim={"schema": "sigilchain-decrypt-claim-v1", "recipient_id": []},
                signature_hex="00",
            )
            with patch.object(validator, "lookup_identity") as lookup:
                with self.assertRaises(HTTPException) as raised:
                    validator.submit(request, None)
            self.assertEqual(raised.exception.status_code, 400)
            lookup.assert_not_called()


if __name__ == "__main__":
    unittest.main()
