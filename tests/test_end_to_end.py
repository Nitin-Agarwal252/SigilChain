"""End-to-end flow against the local Compose validator and etcd cluster."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path

import httpx
import pymupdf

from sigilchain import config
from sigilchain.agent import decrypt_and_mark
from sigilchain.crypto import encrypt_pdf
from sigilchain.evidence import make_bundle, verify_bundle
from sigilchain.identity import enroll, load_private
from sigilchain.quorum import check_watermark
from sigilchain.watermark import extract_page, pdf_pages


class EndToEndTests(unittest.TestCase):
    def test_recipient_decrypt_trace_and_portable_evidence(self):
        recipient = "e2e-" + uuid.uuid4().hex[:16]
        passphrase = "test-only passphrase 123"
        public = enroll(recipient, passphrase)
        private = load_private(recipient, passphrase)

        roster = {}
        headers = {config.API_KEY_HEADER: config.API_KEY} if config.API_KEY else {}
        for node in config.NODE_URLS:
            response = httpx.get(node + "/node-info", headers=headers, timeout=5.0)
            response.raise_for_status()
            info = response.json()
            key = info["validator_public_key"]
            roster[info["validator_id"]] = {
                "sig_alg": info["validator_sig_alg"],
                "public_key": key,
                "fingerprint": hashlib.sha256(bytes.fromhex(key)).hexdigest(),
            }
        self.assertGreaterEqual(len(roster), config.QUORUM_REQUIRED)

        with pymupdf.open() as document:
            page = document.new_page(width=612, height=792)
            page.insert_text((72, 72), "SigilChain end-to-end acceptance fixture")
            source_pdf = document.tobytes()
        package = encrypt_pdf(source_pdf, {recipient: public})

        with tempfile.TemporaryDirectory() as output_dir, tempfile.TemporaryDirectory() as trust_dir:
            trust_path = Path(trust_dir) / "validator_trust.json"
            trust_path.write_text(json.dumps(roster), encoding="utf-8")
            result = decrypt_and_mark(package, recipient, "e2e-document", output_dir,
                private=private, nodes=config.NODE_URLS, pins=roster)
            marked_pdf = Path(result["output_path"]).read_bytes()
            page_ids = [extract_page(page_image)[0].hex() for page_image in pdf_pages(marked_pdf)]
            self.assertTrue(page_ids)
            self.assertIn(result["watermark_id"], page_ids)

            confidence = max(extract_page(page_image)[1] for page_image in pdf_pages(marked_pdf))
            matches = check_watermark(config.NODE_URLS, result["watermark_id"], pins=roster)
            bundle = make_bundle(result["watermark_id"], matches, confidence, "end-to-end test")
            verified, errors = verify_bundle(bundle, validator_trust=str(trust_path))
            self.assertTrue(verified, errors)
            self.assertEqual(bundle["claim"]["recipient_id"], recipient)


if __name__ == "__main__":
    unittest.main()
