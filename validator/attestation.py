"""ML-DSA validator signing keys and signed commit receipts.

Legacy Ed25519 receipts remain verifiable when their algorithm is absent
from older records. Legacy validator key files are rotated to ML-DSA-65
on startup; the new public-key fingerprint must then be pinned again.
"""

from dataclasses import dataclass
import hashlib
import json
import os
import tempfile
import time

import oqs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


VALIDATOR_SIG_ALG = "ML-DSA-65"
LEGACY_SIG_ALG = "Ed25519"


@dataclass(frozen=True)
class ValidatorSigningKey:
    sig_alg: str
    secret_key: bytes
    public_key: bytes


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _generate_key() -> ValidatorSigningKey:
    with oqs.Signature(VALIDATOR_SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return ValidatorSigningKey(VALIDATOR_SIG_ALG, secret_key, public_key)


def _write_key(path: str, key: ValidatorSigningKey) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".validator-key-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({
                "sig_alg": key.sig_alg,
                "private_key_hex": key.secret_key.hex(),
                "public_key_hex": key.public_key.hex(),
            }, f)
            f.flush()
            os.fsync(f.fileno())
        try:
            os.chmod(temp_path, 0o600)
        except OSError:
            pass
        os.replace(temp_path, path)
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def load_or_create_key(path: str) -> ValidatorSigningKey:
    """Load the current ML-DSA key, or rotate a legacy Ed25519 key once."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if data.get("sig_alg") == VALIDATOR_SIG_ALG:
            secret_key = bytes.fromhex(data["private_key_hex"])
            public_key = bytes.fromhex(data["public_key_hex"])
            return ValidatorSigningKey(VALIDATOR_SIG_ALG, secret_key, public_key)
        if data.get("sig_alg") not in (None, LEGACY_SIG_ALG):
            raise ValueError(f"Unsupported validator signing algorithm: {data.get('sig_alg')}")

        # Earlier builds stored a raw Ed25519 private key. Replace it with a
        # fresh ML-DSA key; old receipts retain their public keys and remain
        # verifiable with the old pinned trust-roster backup.
        key = _generate_key()
        _write_key(path, key)
        print(f"Rotated legacy Ed25519 validator key to {VALIDATOR_SIG_ALG}; repin its new fingerprint.")
        return key

    key = _generate_key()
    _write_key(path, key)
    return key


def public_key_hex(key: ValidatorSigningKey) -> str:
    return key.public_key.hex()


def sign_attestation(key: ValidatorSigningKey, statement: dict) -> str:
    """Sign a canonical operational statement with this validator's key."""
    message = canonical_json(statement)
    with oqs.Signature(key.sig_alg, secret_key=key.secret_key) as signer:
        return signer.sign(message).hex()


def verify_attestation(statement: dict, signature_hex: str, public_key_hex_value: str,
                       sig_alg: str = VALIDATOR_SIG_ALG) -> bool:
    try:
        message = canonical_json(statement)
        signature, public_key = bytes.fromhex(signature_hex), bytes.fromhex(public_key_hex_value)
        if sig_alg == LEGACY_SIG_ALG:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        if sig_alg == VALIDATOR_SIG_ALG:
            with oqs.Signature(sig_alg) as verifier:
                return bool(verifier.verify(message, signature, public_key))
        return False
    except Exception:
        return False


def make_receipt(key: ValidatorSigningKey, validator_id: str, entry: dict,
                 machine_attestation: dict | None = None,
                 person_auth_verification: dict | None = None) -> dict:
    receipt = {
        "validator_id": validator_id,
        "validator_sig_alg": key.sig_alg,
        "ledger_backend": entry.get("ledger_backend", "local-sqlite"),
        "receipt_issued_at": int(time.time()),
        "watermark_id": entry["watermark_id"],
        "sequence": entry["id"],
        "committed_at": entry["committed_at"],
        "entry_hash": entry["entry_hash"],
        "prev_hash": entry["prev_hash"],
        "record_hash": hashlib.sha256(entry["record_json"].encode("utf-8")).hexdigest(),
        "signature_hash": hashlib.sha256(bytes.fromhex(entry["signature_hex"])).hexdigest(),
    }
    if machine_attestation is not None:
        # Covered by this validator's receipt signature so evidence can show
        # which external TPM-verifier decision was checked before the commit.
        receipt["machine_attestation"] = machine_attestation
    if person_auth_verification is not None:
        receipt["person_auth_verification"] = person_auth_verification
    with oqs.Signature(key.sig_alg, secret_key=key.secret_key) as signer:
        signature = signer.sign(canonical_json(receipt))
    return {
        "receipt": receipt,
        "receipt_signature_hex": signature.hex(),
        "validator_public_key": public_key_hex(key),
        "validator_sig_alg": key.sig_alg,
    }


def verify_receipt(receipt: dict, signature_hex: str, public_key_hex_value: str,
                   sig_alg: str | None = None) -> bool:
    """Verify ML-DSA receipts and legacy Ed25519 receipts over canonical JSON."""
    try:
        algorithm = sig_alg or receipt.get("validator_sig_alg")
        public_key = bytes.fromhex(public_key_hex_value)
        signature = bytes.fromhex(signature_hex)
        if algorithm is None:
            # Legacy receipt/key pairs predate the algorithm field.
            algorithm = LEGACY_SIG_ALG if len(public_key) == 32 else VALIDATOR_SIG_ALG
        message = canonical_json(receipt)
        if algorithm == LEGACY_SIG_ALG:
            Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
            return True
        if algorithm == VALIDATOR_SIG_ALG:
            with oqs.Signature(algorithm) as verifier:
                return bool(verifier.verify(message, signature, public_key))
        return False
    except Exception:
        return False
