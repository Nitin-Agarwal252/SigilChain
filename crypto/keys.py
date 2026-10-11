"""
SigilChain — Part 1: Identity & Key Enrollment.

Each recipient runs this once, locally, to generate:
  - an ML-KEM keypair (for receiving wrapped content keys, Part 2)
  - an ML-DSA keypair (for signing decryption events, Part 4)

Private keys are written ONLY to a local file (never transmitted).
Public keys get registered into a shared SQLite "identity registry" that
the validator nodes (Part 5) read from to verify signatures and encrypt
envelopes against.

The API used here is exercised by tests/test_part1_keys.py against the
liboqs-python runtime. Keep that round-trip test as the guard when updating
the native liboqs version.
"""

import json
import getpass
import os
import re
import sqlite3
import sys
import tempfile
import time
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEM_ALG = "ML-KEM-768"    # NIST security level ~3, matches AES-256 strength
SIG_ALG = "ML-DSA-65"     # NIST security level ~3, paired balance with the KEM

KEYS_DIR = os.environ.get("SIGILCHAIN_KEYS_DIR", "local_keys")
REGISTRY_DB = os.environ.get("SIGILCHAIN_IDENTITY_DB", "identity_registry.db")


def _keys_path(recipient_id: str, key_version: int | None = None) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", recipient_id):
        raise ValueError("Recipient IDs must be 1-64 characters using letters, digits, dot, underscore, or hyphen.")
    suffix = f".v{key_version}" if key_version is not None and key_version > 1 else ""
    return os.path.join(KEYS_DIR, f"{recipient_id}{suffix}.json")


def generate_identity(recipient_id: str, passphrase: str | None = None) -> dict:
    """
    Generate a fresh ML-KEM + ML-DSA keypair pair for `recipient_id`.
    Private keys are saved ONLY to local_keys/<recipient_id>.json.
    Returns the public half (safe to publish to the registry).
    """
    os.makedirs(KEYS_DIR, exist_ok=True)

    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_public = kem.generate_keypair()
        kem_secret = kem.export_secret_key()

    with oqs.Signature(SIG_ALG) as sig:
        sig_public = sig.generate_keypair()
        sig_secret = sig.export_secret_key()

    private_record = {
        "recipient_id": recipient_id,
        "key_version": 1,
        "kem_alg": KEM_ALG,
        "sig_alg": SIG_ALG,
        "kem_public": kem_public.hex(),
        "kem_secret": kem_secret.hex(),
        "sig_public": sig_public.hex(),
        "sig_secret": sig_secret.hex(),
    }

    path = _keys_path(recipient_id)
    if os.path.exists(path):
        raise FileExistsError(f"Local key file already exists for '{recipient_id}'; use rotate or inspect the existing identity.")
    passphrase = passphrase or os.environ.get("SIGILCHAIN_KEY_PASSPHRASE")
    if passphrase is not None and len(passphrase) < 12:
        raise ValueError("Passphrase must contain at least 12 characters.")
    stored_record = _protect_private_record(private_record, passphrase) if passphrase else private_record
    _write_private_record(path, stored_record)
    # local-only private key file — not committed, not transmitted
    print(f"[{recipient_id}] identity generated, private keys saved to {path}")

    return {
        "recipient_id": recipient_id,
        "kem_alg": KEM_ALG,
        "sig_alg": SIG_ALG,
        "kem_public": kem_public.hex(),
        "sig_public": sig_public.hex(),
        "key_version": 1,
    }


def _protect_private_record(record: dict, passphrase: str) -> dict:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))
    aad = f"sigilchain-private-key-v1:{record['recipient_id']}".encode("utf-8")
    plaintext = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        "format": "sigilchain-encrypted-private-key-v1",
        "recipient_id": record["recipient_id"],
        "key_version": record.get("key_version", 1),
        "kem_alg": record["kem_alg"],
        "sig_alg": record["sig_alg"],
        "kem_public": record["kem_public"],
        "sig_public": record["sig_public"],
        "kdf": "scrypt-n16384-r8-p1",
        "salt": salt.hex(),
        "nonce": nonce.hex(),
        "encrypted_private": AESGCM(key).encrypt(nonce, plaintext, aad).hex(),
    }


def _write_private_record(path: str, record: dict) -> None:
    parent = os.path.dirname(path) or "."
    os.makedirs(parent, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".sigilchain-key-", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(record, f)
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


def protect_local_identity(recipient_id: str, passphrase: str | None = None) -> bool:
    """Encrypt an active plaintext key file without rotating its key."""
    identity = lookup_identity(recipient_id)
    path = _keys_path(recipient_id, identity["key_version"])
    with open(path, encoding="utf-8") as f:
        record = json.load(f)
    if record.get("format") == "sigilchain-encrypted-private-key-v1":
        return False
    if (record.get("recipient_id") != recipient_id
            or record.get("key_version", 1) != identity["key_version"]
            or record.get("sig_public") != identity["sig_public"]
            or record.get("kem_public") != identity["kem_public"]):
        raise ValueError("Local private key does not match the active registered identity.")
    passphrase = passphrase or os.environ.get("SIGILCHAIN_KEY_PASSPHRASE")
    if passphrase is None or len(passphrase) < 12:
        raise ValueError("Passphrase must contain at least 12 characters.")
    _write_private_record(path, _protect_private_record(record, passphrase))
    return True


def load_identity(recipient_id: str, passphrase: str | None = None,
                  key_version: int | None = None) -> dict:
    """Load a local private identity, optionally selecting a historical key version."""
    try:
        current = lookup_identity(recipient_id, key_version=key_version,
                                  allow_revoked=key_version is not None)
        path = _keys_path(recipient_id, current["key_version"])
    except (KeyError, sqlite3.Error):
        path = _keys_path(recipient_id)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"No local identity for '{recipient_id}' — run generate_identity() first."
        )
    with open(path, encoding="utf-8") as f:
        record = json.load(f)
    if record.get("format") != "sigilchain-encrypted-private-key-v1":
        return record
    passphrase = passphrase or os.environ.get("SIGILCHAIN_KEY_PASSPHRASE")
    if passphrase is None:
        if not sys.stdin.isatty():
            raise ValueError("Encrypted private key requires SIGILCHAIN_KEY_PASSPHRASE or an interactive prompt.")
        passphrase = getpass.getpass(f"Passphrase for {recipient_id}: ")
    try:
        key = Scrypt(salt=bytes.fromhex(record["salt"]), length=32, n=2**14, r=8, p=1).derive(
            passphrase.encode("utf-8")
        )
        aad = f"sigilchain-private-key-v1:{recipient_id}".encode("utf-8")
        plaintext = AESGCM(key).decrypt(
            bytes.fromhex(record["nonce"]), bytes.fromhex(record["encrypted_private"]), aad
        )
        return json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Could not unlock the private identity; check the passphrase and key file.") from exc


def init_registry(db_path: str = REGISTRY_DB) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS identities (
            recipient_id TEXT PRIMARY KEY,
            kem_alg TEXT NOT NULL,
            sig_alg TEXT NOT NULL,
            kem_public TEXT NOT NULL,
            sig_public TEXT NOT NULL,
            key_version INTEGER NOT NULL DEFAULT 1,
            revoked_at INTEGER
        )
    """)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(identities)")}
    if "key_version" not in columns:
        conn.execute("ALTER TABLE identities ADD COLUMN key_version INTEGER NOT NULL DEFAULT 1")
    if "revoked_at" not in columns:
        conn.execute("ALTER TABLE identities ADD COLUMN revoked_at INTEGER")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS identity_history (
            recipient_id TEXT NOT NULL,
            key_version INTEGER NOT NULL,
            kem_alg TEXT NOT NULL,
            sig_alg TEXT NOT NULL,
            kem_public TEXT NOT NULL,
            sig_public TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            revoked_at INTEGER,
            PRIMARY KEY (recipient_id, key_version)
        )
    """)
    conn.execute("""
        INSERT OR IGNORE INTO identity_history
        (recipient_id, key_version, kem_alg, sig_alg, kem_public, sig_public, created_at, revoked_at)
        SELECT recipient_id, key_version, kem_alg, sig_alg, kem_public, sig_public, ?, revoked_at
        FROM identities
    """, (int(time.time()),))
    conn.commit()
    conn.close()


def register_identity(public_record: dict, db_path: str = REGISTRY_DB) -> int:
    """Register the first public key for an identity; never replace it silently."""
    init_registry(db_path)
    conn = sqlite3.connect(db_path)
    existing = conn.execute(
        "SELECT kem_public, sig_public, key_version, revoked_at FROM identities WHERE recipient_id = ?",
        (public_record["recipient_id"],),
    ).fetchone()
    if existing:
        if existing[3] is None and existing[0] == public_record["kem_public"] and existing[1] == public_record["sig_public"]:
            conn.close()
            return existing[2]
        conn.close()
        raise ValueError("Identity already has keys; use rotate_identity() instead of replacing them.")
    now = int(time.time())
    conn.execute(
        """INSERT INTO identities
           (recipient_id, kem_alg, sig_alg, kem_public, sig_public, key_version)
           VALUES (?, ?, ?, ?, ?, 1)""",
        (public_record["recipient_id"], public_record["kem_alg"], public_record["sig_alg"],
         public_record["kem_public"], public_record["sig_public"]),
    )
    conn.execute(
        """INSERT INTO identity_history
           (recipient_id, key_version, kem_alg, sig_alg, kem_public, sig_public, created_at)
           VALUES (?, 1, ?, ?, ?, ?, ?)""",
        (public_record["recipient_id"], public_record["kem_alg"], public_record["sig_alg"],
         public_record["kem_public"], public_record["sig_public"], now),
    )
    conn.commit()
    conn.close()
    return 1


def lookup_identity(recipient_id: str, db_path: str = REGISTRY_DB,
                    key_version: int | None = None, allow_revoked: bool = False) -> dict:
    """Look up a recipient's PUBLIC keys from the registry (used by sender in Part 2,
    and by validator nodes in Part 5 to verify signatures)."""
    conn = sqlite3.connect(db_path)
    if key_version is not None:
        init_registry(db_path)
        row = conn.execute(
            "SELECT recipient_id, kem_alg, sig_alg, kem_public, sig_public, key_version, revoked_at "
            "FROM identity_history WHERE recipient_id = ? AND key_version = ?",
            (recipient_id, key_version),
        ).fetchone()
    else:
        init_registry(db_path)
        row = conn.execute(
            "SELECT recipient_id, kem_alg, sig_alg, kem_public, sig_public, key_version, revoked_at "
            "FROM identities WHERE recipient_id = ?",
            (recipient_id,),
        ).fetchone()
    conn.close()
    if row is None:
        raise KeyError(f"No registered identity for '{recipient_id}'")
    if row[6] is not None and not allow_revoked:
        raise PermissionError(f"Identity '{recipient_id}' key is revoked")
    return {
        "recipient_id": row[0],
        "kem_alg": row[1],
        "sig_alg": row[2],
        "kem_public": row[3],
        "sig_public": row[4],
        "key_version": row[5],
        "revoked_at": row[6],
    }


def rotate_identity(recipient_id: str, passphrase: str | None = None,
                    db_path: str = REGISTRY_DB) -> dict:
    """Replace the active key version while retaining old public keys for audits."""
    current = lookup_identity(recipient_id, db_path=db_path, allow_revoked=True)
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_public = kem.generate_keypair()
        kem_secret = kem.export_secret_key()
    with oqs.Signature(SIG_ALG) as sig:
        sig_public = sig.generate_keypair()
        sig_secret = sig.export_secret_key()
    version = current["key_version"] + 1
    private_record = {
        "recipient_id": recipient_id, "key_version": version,
        "kem_alg": KEM_ALG, "sig_alg": SIG_ALG,
        "kem_public": kem_public.hex(), "kem_secret": kem_secret.hex(),
        "sig_public": sig_public.hex(), "sig_secret": sig_secret.hex(),
    }
    passphrase = passphrase or os.environ.get("SIGILCHAIN_KEY_PASSPHRASE")
    if passphrase is not None and len(passphrase) < 12:
        raise ValueError("Passphrase must contain at least 12 characters.")
    stored = _protect_private_record(private_record, passphrase) if passphrase else private_record
    now = int(time.time())
    new_key_path = _keys_path(recipient_id, version)
    _write_private_record(new_key_path, stored)
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute("UPDATE identity_history SET revoked_at = ? WHERE recipient_id = ? AND key_version = ?",
                     (now, recipient_id, current["key_version"]))
        conn.execute(
            "INSERT INTO identity_history (recipient_id,key_version,kem_alg,sig_alg,kem_public,sig_public,created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (recipient_id, version, KEM_ALG, SIG_ALG, kem_public.hex(), sig_public.hex(), now),
        )
        conn.execute(
            "UPDATE identities SET kem_alg=?,sig_alg=?,kem_public=?,sig_public=?,key_version=?,revoked_at=NULL "
            "WHERE recipient_id=?",
            (KEM_ALG, SIG_ALG, kem_public.hex(), sig_public.hex(), version, recipient_id),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        if os.path.exists(new_key_path):
            os.remove(new_key_path)
        raise
    finally:
        conn.close()
    return {k: v for k, v in private_record.items() if k not in {"kem_secret", "sig_secret"}}


def revoke_identity(recipient_id: str, db_path: str = REGISTRY_DB) -> None:
    """Revoke the active public key; historical public keys remain queryable for audits."""
    init_registry(db_path)
    now = int(time.time())
    conn = sqlite3.connect(db_path)
    cursor = conn.execute("UPDATE identities SET revoked_at = ? WHERE recipient_id = ? AND revoked_at IS NULL",
                          (now, recipient_id))
    if cursor.rowcount == 0:
        conn.close()
        raise KeyError(f"No active identity for '{recipient_id}'")
    conn.execute("UPDATE identity_history SET revoked_at = ? WHERE recipient_id = ? "
                 "AND key_version = (SELECT key_version FROM identities WHERE recipient_id = ?)",
                 (now, recipient_id, recipient_id))
    conn.commit()
    conn.close()
