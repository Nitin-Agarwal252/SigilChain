"""Passphrase protection, key rotation, history, and revocation checks."""

import json
import os
import tempfile
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
with tempfile.TemporaryDirectory(prefix="sigilchain-key-test-", dir=ROOT.parent.parent) as temp:
    os.environ["SIGILCHAIN_KEYS_DIR"] = str(Path(temp) / "keys")
    os.environ["SIGILCHAIN_IDENTITY_DB"] = str(Path(temp) / "identity.db")
    from crypto.keys import (generate_identity, register_identity, load_identity,
                             lookup_identity, rotate_identity, revoke_identity,
                             protect_local_identity)

    secret = "test-passphrase-long-enough"
    first_public = generate_identity("lifecycle-test", passphrase=secret)
    register_identity(first_public)
    key_path = Path(temp) / "keys" / "lifecycle-test.json"
    assert json.loads(key_path.read_text(encoding="utf-8"))["format"] == "sigilchain-encrypted-private-key-v1"
    assert load_identity("lifecycle-test", passphrase=secret)["key_version"] == 1
    try:
        load_identity("lifecycle-test", passphrase="wrong-passphrase-value")
        raise AssertionError("wrong passphrase unexpectedly unlocked key")
    except ValueError:
        pass

    second_public = rotate_identity("lifecycle-test", passphrase=secret)
    assert second_public["key_version"] == 2
    assert load_identity("lifecycle-test", passphrase=secret)["key_version"] == 2
    history = lookup_identity("lifecycle-test", key_version=1, allow_revoked=True)
    assert history["sig_public"] == first_public["sig_public"]
    assert history["revoked_at"] is not None
    assert lookup_identity("lifecycle-test")["sig_public"] == second_public["sig_public"]

    revoke_identity("lifecycle-test")
    try:
        lookup_identity("lifecycle-test")
        raise AssertionError("revoked identity unexpectedly remained active")
    except PermissionError:
        pass

    legacy_public = generate_identity("legacy-test")
    register_identity(legacy_public)
    assert protect_local_identity("legacy-test", passphrase=secret) is True
    assert protect_local_identity("legacy-test", passphrase=secret) is False
    assert load_identity("legacy-test", passphrase=secret)["sig_public"] == legacy_public["sig_public"]

print("Key lifecycle checks passed: encrypted storage, legacy-key protection, wrong-passphrase rejection, rotation history, and revocation.")
