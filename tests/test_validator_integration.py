"""Run the shared-log outage test from a Compose validator container."""
from __future__ import annotations

import unittest
import importlib
import asyncio
import json
import os
import stat
import tempfile
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError
import httpx
import oqs

from sigilchain import config
from sigilchain.identity import SIG_ALG
from sigilchain.ledger import LedgerUnavailable, get_event


class EtcdIntegrationTests(unittest.TestCase):
    def test_validator_signing_pair_check_rejects_mismatch(self):
        validator = importlib.import_module("sigilchain.validator")
        with oqs.Signature(SIG_ALG) as first_signer:
            first_public = first_signer.generate_keypair()
            first_private = first_signer.export_secret_key()
        with oqs.Signature(SIG_ALG) as second_signer:
            second_public = second_signer.generate_keypair()
        validator._check_signing_keypair(first_private, first_public)
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            validator._check_signing_keypair(first_private, second_public)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "validator.json"
            validator._persist_signing_key(path, first_private, first_public)
            stored = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(stored["sig_alg"], SIG_ALG)
            self.assertEqual(bytes.fromhex(stored["private_key_hex"]), first_private)
            self.assertEqual(bytes.fromhex(stored["public_key_hex"]), first_public)
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(list(path.parent.glob(".validator.json.*.tmp")), [])

    def test_unavailable_cluster_fails_closed(self):
        with patch.object(config, "ETCD_ENDPOINTS", ["http://127.0.0.1:1"]):
            with self.assertRaises(LedgerUnavailable):
                get_event("not-present")

    def test_submit_request_rejects_malformed_claim_during_parsing(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(
            config, "VALIDATOR_KEY_PATH", str(Path(directory) / "validator.json")
        ):
            validator = importlib.import_module("sigilchain.validator")
            async def post_oversized_request():
                transport = httpx.ASGITransport(app=validator.app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    return await client.post(
                        "/submit", json={"extra": "x" * validator.MAX_SUBMIT_REQUEST_BYTES}
                    )

            response = asyncio.run(post_oversized_request())
            self.assertEqual(response.status_code, 413)

            async def post_chunked_oversized_request():
                async def chunks():
                    yield b"{" + b" " * 9000
                    yield b" " * 8000 + b"}"

                transport = httpx.ASGITransport(app=validator.app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    return await client.post("/submit", content=chunks())

            chunked_response = asyncio.run(post_chunked_oversized_request())
            self.assertEqual(chunked_response.status_code, 413)
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
