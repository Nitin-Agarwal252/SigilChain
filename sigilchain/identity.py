"""Recipient identity and local passphrase-protected PQC key lifecycle."""
from __future__ import annotations

import getpass
import json
import os
import re
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from . import config

KEM_ALG = "ML-KEM-768"
SIG_ALG = "ML-DSA-65"
_KEY_FORMAT = "sigilchain-private-key-v1"


def _validate_id(recipient_id: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", recipient_id):
        raise ValueError("Recipient ID must be 1-64 safe filename characters.")


def _private_path(recipient_id: str, version: int = 1) -> Path:
    _validate_id(recipient_id)
    suffix = f".v{version}" if version > 1 else ""
    return Path(config.KEYS_DIR) / f"{recipient_id}{suffix}.json"


def _connect(db_path: str | None = None) -> sqlite3.Connection:
    path = db_path or config.IDENTITY_DB
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute("""CREATE TABLE IF NOT EXISTS identities (
        recipient_id TEXT NOT NULL, key_version INTEGER NOT NULL,
        kem_alg TEXT NOT NULL, sig_alg TEXT NOT NULL,
        kem_public TEXT NOT NULL, sig_public TEXT NOT NULL,
        created_at INTEGER NOT NULL, revoked_at INTEGER,
        PRIMARY KEY(recipient_id,key_version))""")
    conn.commit()
    return conn


def _protect(record: dict[str, Any], passphrase: str) -> dict[str, Any]:
    if len(passphrase) < 12:
        raise ValueError("Passphrase must be at least 12 characters.")
    salt, nonce = os.urandom(16), os.urandom(12)
    key = Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode())
    aad = f"{_KEY_FORMAT}:{record['recipient_id']}:{record['key_version']}".encode()
    plain = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    return {
        "format": _KEY_FORMAT, "recipient_id": record["recipient_id"],
        "key_version": record["key_version"], "kem_alg": record["kem_alg"],
        "sig_alg": record["sig_alg"], "kem_public": record["kem_public"],
        "sig_public": record["sig_public"], "salt": salt.hex(), "nonce": nonce.hex(),
        "ciphertext": AESGCM(key).encrypt(nonce, plain, aad).hex(),
    }


def _write_private(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(data, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary_path, 0o600)
        # A hard link publishes the complete key file and refuses to replace
        # a destination created by another enrollment or rotation process.
        os.link(temporary_path, path)
        temporary_path.unlink()
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _new_key_record(recipient_id: str, version: int) -> tuple[dict[str, Any], dict[str, Any]]:
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        kem_public = kem.generate_keypair()
        kem_secret = kem.export_secret_key()
    with oqs.Signature(SIG_ALG) as sig:
        sig_public = sig.generate_keypair()
        sig_secret = sig.export_secret_key()
    private = {
        "recipient_id": recipient_id, "key_version": version,
        "kem_alg": KEM_ALG, "sig_alg": SIG_ALG,
        "kem_public": kem_public.hex(), "kem_secret": kem_secret.hex(),
        "sig_public": sig_public.hex(), "sig_secret": sig_secret.hex(),
    }
    public = {key: private[key] for key in
              ("recipient_id", "key_version", "kem_alg", "sig_alg", "kem_public", "sig_public")}
    return private, public


def register_public(public: dict[str, Any], db_path: str | None = None) -> None:
    expected_fields = {"recipient_id", "key_version", "kem_alg", "sig_alg", "kem_public", "sig_public"}
    if not isinstance(public, dict) or set(public) != expected_fields:
        raise ValueError("Public identity must contain exactly the six supported public fields.")
    try:
        _validate_id(public["recipient_id"])
    except (TypeError, ValueError) as exc:
        raise ValueError("Public identity has an invalid recipient ID.") from exc
    if type(public["key_version"]) is not int or public["key_version"] < 1:
        raise ValueError("Public identity key version must be a positive integer.")
    if public["kem_alg"] != KEM_ALG or public["sig_alg"] != SIG_ALG:
        raise ValueError("Public identity must use ML-KEM-768 and ML-DSA-65.")
    with oqs.KeyEncapsulation(KEM_ALG) as kem, oqs.Signature(SIG_ALG) as signature:
        expected_lengths = {
            "kem_public": kem.details["length_public_key"],
            "sig_public": signature.details["length_public_key"],
        }
    for field, expected_length in expected_lengths.items():
        value = public[field]
        if (not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value)
                or len(value) != expected_length * 2):
            raise ValueError(f"Public identity {field} must be {expected_length} bytes of lowercase hexadecimal data.")
    conn = _connect(db_path)
    try:
        conn.execute("INSERT INTO identities VALUES (?,?,?,?,?,?,strftime('%s','now'),NULL)",
                     (public["recipient_id"], public["key_version"], public["kem_alg"], public["sig_alg"],
                      public["kem_public"], public["sig_public"]))
        conn.commit()
    finally:
        conn.close()


def enroll(recipient_id: str, passphrase: str | None = None, db_path: str | None = None) -> dict[str, Any]:
    _validate_id(recipient_id)
    current = lookup_identity(recipient_id, db_path=db_path, allow_revoked=True)
    if current:
        raise ValueError(f"Identity {recipient_id!r} already exists; rotate it instead.")
    passphrase = passphrase or getpass.getpass("Private key passphrase (12+ characters): ")
    private, public = _new_key_record(recipient_id, 1)
    path = _private_path(recipient_id)
    if path.exists():
        raise FileExistsError(f"Refusing to overwrite existing key file {path}.")
    _write_private(path, _protect(private, passphrase))
    try:
        register_public(public, db_path)
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return public


def lookup_identity(recipient_id: str, db_path: str | None = None,
                    key_version: int | None = None, allow_revoked: bool = False) -> dict[str, Any] | None:
    conn = _connect(db_path)
    try:
        if key_version is None:
            row = conn.execute("SELECT recipient_id,key_version,kem_alg,sig_alg,kem_public,sig_public,revoked_at "
                               "FROM identities WHERE recipient_id=? ORDER BY key_version DESC LIMIT 1",
                               (recipient_id,)).fetchone()
        else:
            row = conn.execute("SELECT recipient_id,key_version,kem_alg,sig_alg,kem_public,sig_public,revoked_at "
                               "FROM identities WHERE recipient_id=? AND key_version=?",
                               (recipient_id, key_version)).fetchone()
    finally:
        conn.close()
    if not row or (row[6] is not None and not allow_revoked):
        return None
    return dict(zip(("recipient_id", "key_version", "kem_alg", "sig_alg", "kem_public", "sig_public", "revoked_at"), row))


def load_private(recipient_id: str, passphrase: str | None = None, key_version: int | None = None) -> dict[str, Any]:
    identity = lookup_identity(recipient_id, key_version=key_version, allow_revoked=True)
    version = key_version or (identity["key_version"] if identity else 1)
    path = _private_path(recipient_id, version)
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("format") != _KEY_FORMAT:
        raise ValueError("Unprotected/unknown private key file format; enroll again or protect the key.")
    passphrase = passphrase or getpass.getpass(f"Passphrase for {recipient_id}: ")
    key = Scrypt(salt=bytes.fromhex(data["salt"]), length=32, n=2**15, r=8, p=1).derive(passphrase.encode())
    aad = f"{_KEY_FORMAT}:{recipient_id}:{version}".encode()
    try:
        return json.loads(AESGCM(key).decrypt(bytes.fromhex(data["nonce"]), bytes.fromhex(data["ciphertext"]), aad))
    except Exception as exc:
        raise ValueError("Private key could not be unlocked; check the passphrase and key file.") from exc


def rotate(recipient_id: str, passphrase: str | None = None, db_path: str | None = None) -> dict[str, Any]:
    current = lookup_identity(recipient_id, db_path=db_path, allow_revoked=True)
    if not current:
        raise KeyError(f"Unknown identity {recipient_id!r}")
    new_pass = passphrase or getpass.getpass("New private key passphrase: ")
    version = current["key_version"] + 1
    private, public = _new_key_record(recipient_id, version)
    path = _private_path(recipient_id, version)
    _write_private(path, _protect(private, new_pass))
    try:
        conn = _connect(db_path)
        try:
            conn.execute("UPDATE identities SET revoked_at=strftime('%s','now') WHERE recipient_id=? AND key_version=?",
                         (recipient_id, current["key_version"]))
            register_sql = "INSERT INTO identities VALUES (?,?,?,?,?,?,strftime('%s','now'),NULL)"
            conn.execute(register_sql, (recipient_id, version, KEM_ALG, SIG_ALG, public["kem_public"], public["sig_public"]))
            conn.commit()
        finally:
            conn.close()
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return public


def revoke(recipient_id: str, db_path: str | None = None) -> None:
    conn = _connect(db_path)
    try:
        result = conn.execute("UPDATE identities SET revoked_at=strftime('%s','now') "
                              "WHERE recipient_id=? AND key_version=(SELECT MAX(key_version) FROM identities WHERE recipient_id=?) "
                              "AND revoked_at IS NULL", (recipient_id, recipient_id))
        if result.rowcount != 1:
            raise KeyError(f"No active key for {recipient_id!r}")
        conn.commit()
    finally:
        conn.close()
