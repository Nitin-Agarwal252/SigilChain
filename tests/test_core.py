"""Core acceptance tests; cryptographic cases require the liboqs runtime."""
from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import numpy as np
import pymupdf
from PIL import Image

from sigilchain import config, ledger
from sigilchain.crypto import decrypt_pdf, encrypt_pdf
from sigilchain.documents import DocumentError, normalize
from sigilchain.events import build_claim, sign_claim, verify_claim
from sigilchain.identity import enroll, load_private, lookup_identity, rotate, revoke
from sigilchain.quorum import _effective_quorum, submit_to_quorum
from sigilchain.watermark import embed_page, extract_page, new_watermark_id


class IdentityAndCryptoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.old_keys = config.KEYS_DIR
        config.KEYS_DIR = str(self.root / "keys")
        self.db = str(self.root / "identities.db")

    def tearDown(self):
        config.KEYS_DIR = self.old_keys
        self.temp.cleanup()

    def test_passphrase_wrong_recipient_and_tamper(self):
        alice_pub = enroll("alice", "correct horse battery", self.db)
        bob_pub = enroll("bob", "another long passphrase", self.db)
        alice = load_private("alice", "correct horse battery")
        package = encrypt_pdf(b"%PDF-1.4\ntest\n%%EOF", {"alice": alice_pub, "bob": bob_pub})
        self.assertEqual(decrypt_pdf(package, "alice", alice), b"%PDF-1.4\ntest\n%%EOF")
        with self.assertRaises(ValueError):
            load_private("alice", "incorrect passphrase")
        with self.assertRaises(PermissionError):
            decrypt_pdf(package, "carol", alice)
        tampered = json.loads(json.dumps(package))
        tampered["document_ciphertext"] = "00" + tampered["document_ciphertext"][2:]
        with self.assertRaises(ValueError):
            decrypt_pdf(tampered, "alice", alice)
        self.assertEqual(lookup_identity("alice", self.db)["sig_public"], alice_pub["sig_public"])

    def test_wrong_private_key_rejected(self):
        alice_pub = enroll("alice", "correct horse battery", self.db)
        enroll("bob", "another long passphrase", self.db)
        bob = load_private("bob", "another long passphrase")
        package = encrypt_pdf(b"pdf", {"alice": alice_pub})
        with self.assertRaises(ValueError):
            decrypt_pdf(package, "alice", bob)

    def test_rotation_revocation_and_old_key_history(self):
        first = enroll("alice", "correct horse battery", self.db)
        second = rotate("alice", "new key passphrase 123", self.db)
        self.assertEqual(second["key_version"], 2)
        self.assertEqual(lookup_identity("alice", self.db)["key_version"], 2)
        self.assertEqual(lookup_identity("alice", self.db, key_version=1, allow_revoked=True)["sig_public"], first["sig_public"])
        revoke("alice", self.db)
        self.assertIsNone(lookup_identity("alice", self.db))


class DocumentTests(unittest.TestCase):
    def test_image_pdf_and_unsupported_input(self):
        with tempfile.TemporaryDirectory() as directory:
            image_path = Path(directory) / "page.png"
            Image.new("RGB", (120, 160), "white").save(image_path)
            data = normalize(image_path)
            with pymupdf.open(stream=data, filetype="pdf") as pdf:
                self.assertEqual(pdf.page_count, 1)
            unsupported = Path(directory) / "page.exe"
            unsupported.write_bytes(b"no")
            with self.assertRaises(DocumentError):
                normalize(unsupported)

    def test_malformed_pdf_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fake.pdf"
            path.write_bytes(b"%PDF-not-really")
            with self.assertRaises(DocumentError):
                normalize(path)


class WatermarkTests(unittest.TestCase):
    def test_dct_reed_solomon_round_trip_and_distinct_ids(self):
        page = np.tile(np.linspace(60, 220, 1024, dtype=np.uint8), (768, 1))
        first, second = new_watermark_id(), new_watermark_id()
        self.assertNotEqual(first, second)
        with patch.object(config, "WATERMARK_TRANSFORM", "dct"):
            marked = embed_page(page, first)
            recovered, confidence = extract_page(marked)
        self.assertEqual(recovered, first)
        self.assertGreaterEqual(confidence, 0.95)

    def test_jpeg_recompression_recovers_mark(self):
        page = np.random.default_rng(77).normal(180, 26, (768, 1024)).clip(0, 255).astype(np.uint8)
        page[80:100, 90:900] = 20
        watermark_id = new_watermark_id()
        with patch.object(config, "WATERMARK_TRANSFORM", "dct"):
            marked = embed_page(page, watermark_id)
            buffer = __import__("io").BytesIO()
            Image.fromarray(marked.astype(np.uint8)).save(buffer, format="JPEG", quality=45)
            compressed = np.asarray(Image.open(__import__("io").BytesIO(buffer.getvalue())).convert("L"))
            recovered, _ = extract_page(compressed)
        self.assertEqual(recovered, watermark_id)

    def test_dwt_dct_round_trip(self):
        page = np.random.default_rng(32).normal(175, 22, (1024, 1536)).clip(0, 255).astype(np.uint8)
        watermark_id = new_watermark_id()
        with patch.object(config, "WATERMARK_TRANSFORM", "dwt-dct"), patch.object(config, "EMBED_REPEAT", 30):
            marked = embed_page(page, watermark_id)
            recovered, confidence = extract_page(marked)
        self.assertEqual(recovered, watermark_id)
        self.assertGreaterEqual(confidence, 0.90)

    def test_event_signature_binds_claim(self):
        with tempfile.TemporaryDirectory() as directory:
            previous = config.KEYS_DIR
            config.KEYS_DIR = str(Path(directory) / "keys")
            try:
                public = enroll("signer", "signer passphrase 123", str(Path(directory) / "ids.db"))
                private = load_private("signer", "signer passphrase 123")
                claim = build_claim("memo", "signer", 1, "ab" * 12, b"marked", timestamp=100)
                signature = sign_claim(claim, private["sig_secret"])
                self.assertTrue(verify_claim(claim, signature, public["sig_public"]))
                self.assertFalse(verify_claim(dict(claim, document_id="other"), signature, public["sig_public"]))
                malformed = dict(claim, timestamp_claim=True)
                malformed_signature = sign_claim(malformed, private["sig_secret"])
                self.assertFalse(verify_claim(malformed, malformed_signature, public["sig_public"]))
                with self.assertRaises(ValueError):
                    build_claim("memo", "signer", 1, "ab" * 16, b"marked", timestamp=100)
                for invalid_args in (
                    ("memo", "../signer", 1, "ab" * 12, b"marked", 100),
                    ("memo", "signer", True, "ab" * 12, b"marked", 100),
                    ("memo", "signer", 1, "ab" * 12, b"marked", 0),
                ):
                    with self.subTest(invalid_args=invalid_args):
                        with self.assertRaises(ValueError):
                            build_claim(*invalid_args[:5], timestamp=invalid_args[5])
            finally:
                config.KEYS_DIR = previous


class LocalLedgerTests(unittest.TestCase):
    def test_hash_chain_proof_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(config, "ETCD_ENDPOINTS", []):
            db = str(Path(directory) / "ledger.db")
            with patch.dict(os.environ, {"SIGILCHAIN_LOCAL_LEDGER": db}):
                first = ledger.append_event("wm-a", {"watermark_id": "wm-a"}, "11")
                ledger.append_event("wm-b", {"watermark_id": "wm-b"}, "22")
                self.assertEqual(ledger.get_event("wm-a"), first)
                proof = ledger.get_chain_proof("wm-b")
                self.assertTrue(ledger.verify_chain(proof, "wm-b"))
                proof[0]["claim_json"] = "{}"
                self.assertFalse(ledger.verify_chain(proof, "wm-b"))

    def test_insufficient_or_unreachable_quorum_fails_closed(self):
        result = submit_to_quorum(["http://127.0.0.1:1"],
            {"watermark_id": "wm-uncommitted"}, "00", required=2, pins={})
        self.assertFalse(result["committed"])
        self.assertEqual(result["accepted_by"], [])
        self.assertEqual(len(result["unreachable"]), 1)

    def test_requested_quorum_cannot_weaken_local_policy(self):
        with patch.object(config, "QUORUM_REQUIRED", 3):
            self.assertEqual(_effective_quorum(None), 3)
            self.assertEqual(_effective_quorum(1), 3)
            self.assertEqual(_effective_quorum(4), 4)
            with self.assertRaises(ValueError):
                _effective_quorum(0)
            result = submit_to_quorum([], {"watermark_id": "policy-test"}, "00",
                                      required=1, pins={})
            self.assertEqual(result["required_quorum"], 3)
            self.assertFalse(result["committed"])


if __name__ == "__main__":
    unittest.main()
