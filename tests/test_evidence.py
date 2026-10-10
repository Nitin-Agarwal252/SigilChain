"""Evidence-bundle verification must fail closed on tampered material."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import oqs

from sigilchain import config
from sigilchain.events import build_claim, canonical_json, sign_claim
from sigilchain.evidence import main as evidence_main, make_bundle, verify_bundle
from sigilchain.identity import enroll, load_private
from sigilchain.ledger import GENESIS
from sigilchain.quorum import SIG_ALG


class EvidenceTests(unittest.TestCase):
    def test_valid_bundle_and_tampering(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous = config.KEYS_DIR
            config.KEYS_DIR = str(root / "keys")
            try:
                identity_db = str(root / "identities.db")
                recipient = enroll("alice", "correct horse battery", identity_db)
                private = load_private("alice", "correct horse battery")
                claim = build_claim("memo", "alice", 1, "ab" * 12, b"marked-content", timestamp=123)
                recipient_sig = sign_claim(claim, private["sig_secret"])
                claim_json = canonical_json(claim).decode()
                digest = hashlib.sha256(GENESIS.encode() + claim_json.encode() + bytes.fromhex(recipient_sig)).hexdigest()
                entry = {"sequence": 1, "watermark_id": claim["watermark_id"],
                    "claim_json": claim_json, "signature_hex": recipient_sig,
                    "previous_hash": GENESIS, "entry_hash": digest,
                    "ledger_backend": "etcd-raft", "committed_at_claim": 100}
                matches, pins = [], {}
                for validator_id in ("validator1", "validator2"):
                    with oqs.Signature(SIG_ALG) as signer:
                        public = signer.generate_keypair()
                        secret = signer.export_secret_key()
                    receipt = {"validator_id": validator_id, "validator_sig_alg": SIG_ALG,
                        "ledger_backend": "etcd-raft", "issued_at_claim": 101,
                        "watermark_id": claim["watermark_id"], "sequence": 1,
                        "entry_hash": digest, "previous_hash": GENESIS,
                        "claim_hash": hashlib.sha256(claim_json.encode()).hexdigest(),
                        "recipient_signature_hash": hashlib.sha256(bytes.fromhex(recipient_sig)).hexdigest()}
                    with oqs.Signature(SIG_ALG, secret_key=secret) as signer:
                        receipt_sig = signer.sign(canonical_json(receipt)).hex()
                    public_hex = public.hex()
                    pins[validator_id] = {"sig_alg": SIG_ALG, "public_key": public_hex}
                    matches.append({"claim": claim, "entry": entry,
                        "recipient_identity": recipient,
                        "receipt": {"receipt": receipt, "receipt_signature_hex": receipt_sig,
                            "validator_public_key": public_hex, "validator_sig_alg": SIG_ALG},
                        "proof": [entry]})
                trust_path = root / "trust.json"
                trust_path.write_text(json.dumps(pins), encoding="utf-8")
                with patch.object(config, "QUORUM_REQUIRED", 2):
                    bundle = make_bundle(claim["watermark_id"], matches, 0.99, "unit test")
                    ok, errors = verify_bundle(bundle, identity_db, str(trust_path))
                    self.assertTrue(ok, errors)
                    bundle_path = root / "evidence.json"
                    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
                    output = StringIO()
                    with patch.object(config, "QUORUM_REQUIRED", 2), redirect_stdout(output):
                        self.assertEqual(evidence_main([str(bundle_path), "--identity-db", identity_db,
                                                       "--validator-trust", str(trust_path)]), 0)
                    self.assertIn("Evidence verified", output.getvalue())
                    output = StringIO()
                    with patch.object(config, "QUORUM_REQUIRED", 2), redirect_stdout(output):
                        self.assertEqual(evidence_main([str(bundle_path), "--identity-db", identity_db,
                            "--validator-trust", str(trust_path), "--required-quorum", "3"]), 1)
                    self.assertIn("3 required", output.getvalue())
                    tampered = json.loads(json.dumps(bundle))
                    tampered["validator_evidence"][0]["receipt"]["entry_hash"] = "0" * 64
                    ok, _ = verify_bundle(tampered, identity_db, str(trust_path))
                    self.assertFalse(ok)
                    downgraded = json.loads(json.dumps(bundle))
                    downgraded["required_quorum"] = 1
                    downgraded["validator_evidence"] = downgraded["validator_evidence"][:1]
                    ok, errors = verify_bundle(downgraded, identity_db, str(trust_path))
                    self.assertFalse(ok)
                    self.assertTrue(any("2 required" in error for error in errors))
                    ok, _ = verify_bundle(downgraded, identity_db, str(trust_path), required_quorum=1)
                    self.assertFalse(ok)
                    malformed_variants = []
                    bad_claim = json.loads(json.dumps(bundle))
                    bad_claim["claim"] = "not-an-object"
                    malformed_variants.append(bad_claim)
                    bad_identity = json.loads(json.dumps(bundle))
                    bad_identity["recipient_public_identity"] = None
                    malformed_variants.append(bad_identity)
                    bad_entry = json.loads(json.dumps(bundle))
                    bad_entry["validator_evidence"][0]["entry"] = None
                    malformed_variants.append(bad_entry)
                    bad_evidence_list = json.loads(json.dumps(bundle))
                    bad_evidence_list["validator_evidence"] = {}
                    malformed_variants.append(bad_evidence_list)
                    for malformed in malformed_variants:
                        ok, errors = verify_bundle(malformed, identity_db, str(trust_path))
                        self.assertFalse(ok)
                        self.assertTrue(errors)
            finally:
                config.KEYS_DIR = previous


if __name__ == "__main__":
    unittest.main()
