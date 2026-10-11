"""ML-DSA validator receipts, legacy Ed25519 compatibility, and key rotation."""

import json
import os
import sys
import tempfile
import oqs

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.quorum_client import _validate_receipt
from validator.attestation import (
    VALIDATOR_SIG_ALG,
    ValidatorSigningKey,
    canonical_json,
    load_or_create_key,
    make_receipt,
    public_key_hex,
    verify_receipt,
)
import config


def _entry():
    return {
        "id": 7,
        "watermark_id": "test-watermark",
        "committed_at": 1234567890,
        "entry_hash": "a" * 64,
        "prev_hash": "b" * 64,
        "record_json": '{"recipient_id":"recipient"}',
        "signature_hex": "01020304",
    }


def main() -> None:
    with oqs.Signature(VALIDATOR_SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    key = ValidatorSigningKey(VALIDATOR_SIG_ALG, secret_key, public_key)
    result = make_receipt(key, "validator-test", _entry())
    assert result["validator_public_key"] == public_key_hex(key)
    assert result["validator_sig_alg"] == VALIDATOR_SIG_ALG
    assert verify_receipt(result["receipt"], result["receipt_signature_hex"],
                          result["validator_public_key"], result["validator_sig_alg"])
    altered = dict(result["receipt"], watermark_id="another-watermark")
    assert not verify_receipt(altered, result["receipt_signature_hex"],
                              result["validator_public_key"], VALIDATOR_SIG_ALG)
    assert not verify_receipt(result["receipt"], result["receipt_signature_hex"],
                              "00" * 32, VALIDATOR_SIG_ALG)

    config.VALIDATOR_TRUSTED_KEYS = {"validator-test": result["validator_public_key"]}
    config.REQUIRE_TRUSTED_VALIDATORS = True
    original_trusted_roster = config.trusted_validator_keys
    config.trusted_validator_keys = lambda: config.VALIDATOR_TRUSTED_KEYS
    response = {
        "validator_id": "validator-test",
        "validator_public_key": result["validator_public_key"],
        "validator_sig_alg": result["validator_sig_alg"],
        "receipt": result["receipt"],
        "receipt_signature_hex": result["receipt_signature_hex"],
        "entry_hash": _entry()["entry_hash"],
        "signature_hex": _entry()["signature_hex"],
        "record": {"recipient_id": "recipient"},
    }
    assert _validate_receipt(response, _entry()["watermark_id"], _entry()["entry_hash"])[0]
    assert config.validator_key_is_trusted(
        "validator-test", result["validator_public_key"], VALIDATOR_SIG_ALG)
    config.trusted_validator_keys = lambda: {
        "validator-test": {
            "sig_alg": VALIDATOR_SIG_ALG,
            "public_key": "11" * len(public_key),
            "previous": [{"sig_alg": VALIDATOR_SIG_ALG,
                          "public_key": result["validator_public_key"]}],
        }
    }
    assert config.validator_key_is_trusted(
        "validator-test", result["validator_public_key"], VALIDATOR_SIG_ALG)
    assert not config.validator_key_is_trusted(
        "validator-test", result["validator_public_key"], "Ed25519")
    config.trusted_validator_keys = lambda: config.VALIDATOR_TRUSTED_KEYS
    response["validator_public_key"] = "00" * 32
    assert not _validate_receipt(response, _entry()["watermark_id"], _entry()["entry_hash"])[0]
    config.trusted_validator_keys = original_trusted_roster

    # Old Ed25519 receipts with no algorithm field remain verifiable when
    # checked against the previous pinned trust roster.
    legacy_key = Ed25519PrivateKey.generate()
    legacy_public = legacy_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    legacy_receipt = {"validator_id": "validator-legacy", "watermark_id": "old-event"}
    legacy_signature = legacy_key.sign(canonical_json(legacy_receipt))
    assert verify_receipt(legacy_receipt, legacy_signature.hex(), legacy_public.hex())
    assert not verify_receipt(legacy_receipt, legacy_signature.hex(), legacy_public.hex(), VALIDATOR_SIG_ALG)

    # Existing raw Ed25519 key files rotate atomically to ML-DSA-65 at boot.
    with tempfile.TemporaryDirectory() as temp_dir:
        key_path = os.path.join(temp_dir, "validator-key.json")
        legacy_secret = legacy_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(key_path, "w", encoding="utf-8") as f:
            json.dump({"private_key_hex": legacy_secret.hex()}, f)
        migrated = load_or_create_key(key_path)
        with open(key_path, encoding="utf-8") as f:
            saved = json.load(f)
        assert migrated.sig_alg == VALIDATOR_SIG_ALG
        assert saved["sig_alg"] == VALIDATOR_SIG_ALG
        assert saved["public_key_hex"] == migrated.public_key.hex()

    print("Validator receipt checks passed: ML-DSA verifies, tampering/wrong keys fail, and legacy Ed25519 evidence remains verifiable.")


if __name__ == "__main__":
    main()
