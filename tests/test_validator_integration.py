"""Run the shared-log outage test from a Compose validator container."""
from __future__ import annotations

import unittest
import importlib
import tempfile
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from sigilchain import config
from sigilchain.ledger import LedgerUnavailable, get_event


class EtcdIntegrationTests(unittest.TestCase):
    def test_unavailable_cluster_fails_closed(self):
        with patch.object(config, "ETCD_ENDPOINTS", ["http://127.0.0.1:1"]):
            with self.assertRaises(LedgerUnavailable):
                get_event("not-present")

    def test_submit_request_rejects_malformed_claim_during_parsing(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            config, "VALIDATOR_KEY_PATH", str(Path(directory) / "validator.json")
        ):
            validator = importlib.import_module("sigilchain.validator")
            with patch.object(validator, "lookup_identity") as lookup:
                valid_claim = {
                    "schema": "sigilchain-decrypt-claim-v1",
                    "document_id": "doc-1",
                    "recipient_id": "recipient-1",
                    "key_version": 1,
                    "watermark_id": "ab" * 12,
                    "timestamp_claim": 1,
                    "marked_file_sha256": "cd" * 32,
                }
                invalid_claims = [
                    {"schema": "sigilchain-decrypt-claim-v1", "recipient_id": []},
                    dict(valid_claim, unexpected="field"),
                    dict(valid_claim, key_version=True),
                    dict(valid_claim, document_id="x" * 65),
                ]
                for claim in invalid_claims:
                    with self.subTest(claim=claim):
                        with self.assertRaises(ValidationError):
                            validator.SubmitRequest(
                                watermark_id="ab" * 12,
                                claim=claim,
                                signature_hex="00" * 3309,
                            )
            lookup.assert_not_called()
            with self.assertRaises(ValidationError):
                validator.SubmitRequest(
                    watermark_id="ab" * 12,
                    claim=valid_claim,
                    signature_hex="00" * 3309,
                    unexpected="field",
                )
            with self.assertRaises(ValidationError):
                validator.SubmitRequest(watermark_id="short", claim={}, signature_hex="00")
            with self.assertRaises(ValidationError):
                validator.SubmitRequest(watermark_id="ab" * 12, claim={}, signature_hex="00" * 3310)


if __name__ == "__main__":
    unittest.main()
