"""Hybrid one-to-many document encryption using AES-GCM and ML-KEM."""
from __future__ import annotations

import os
import re
from typing import Any

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import KEM_ALG, SIG_ALG

_PACKAGE_FIELDS = {"format", "document_nonce", "document_ciphertext", "envelopes"}
_ENVELOPE_FIELDS = {"key_version", "kem_alg", "kem_ciphertext", "wrap_nonce", "wrapped_key"}
_SAFE_RECIPIENT_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


def _wrap_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"sigilchain-v1/content-key-wrap/ML-KEM-768").derive(shared_secret)


def _decode_hex(value: Any, name: str, exact_bytes: int | None = None,
                minimum_bytes: int | None = None) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value):
        raise ValueError(f"Encrypted package has malformed {name}.")
    decoded = bytes.fromhex(value)
    if exact_bytes is not None and len(decoded) != exact_bytes:
        raise ValueError(f"Encrypted package has an invalid {name} length.")
    if minimum_bytes is not None and len(decoded) < minimum_bytes:
        raise ValueError(f"Encrypted package has an invalid {name} length.")
    return decoded


def encrypt_pdf(pdf_bytes: bytes, recipients: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(recipients, dict) or not recipients:
        raise ValueError("At least one active recipient is required.")
    with oqs.KeyEncapsulation(KEM_ALG) as kem, oqs.Signature(SIG_ALG) as signature:
        kem_public_length = kem.details["length_public_key"]
        sig_public_length = signature.details["length_public_key"]
    for recipient_id, identity in recipients.items():
        if not isinstance(recipient_id, str) or not _SAFE_RECIPIENT_ID.fullmatch(recipient_id):
            raise ValueError("Recipient map contains an invalid recipient ID.")
        if not isinstance(identity, dict) or identity.get("recipient_id") != recipient_id:
            raise ValueError(f"Recipient identity does not match {recipient_id!r}.")
        if type(identity.get("key_version")) is not int or identity["key_version"] < 1:
            raise ValueError(f"Recipient {recipient_id!r} has an invalid key version.")
        if identity.get("kem_alg") != KEM_ALG or identity.get("sig_alg") != SIG_ALG:
            raise ValueError(f"Recipient {recipient_id!r} does not use the supported PQC algorithms.")
        for field, expected_length in (("kem_public", kem_public_length), ("sig_public", sig_public_length)):
            value = identity.get(field)
            if (not isinstance(value, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", value)
                    or len(value) != expected_length * 2):
                raise ValueError(f"Recipient {recipient_id!r} has malformed {field} material.")
    content_key = AESGCM.generate_key(bit_length=256)
    document_nonce = os.urandom(12)
    encrypted_document = AESGCM(content_key).encrypt(document_nonce, pdf_bytes, b"sigilchain-v1/document")
    envelopes = {}
    for recipient_id, identity in recipients.items():
        if identity["kem_alg"] != KEM_ALG:
            raise ValueError(f"Unsupported recipient KEM: {identity['kem_alg']}")
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(bytes.fromhex(identity["kem_public"]))
        wrap_nonce = os.urandom(12)
        wrapped = AESGCM(_wrap_key(shared_secret)).encrypt(wrap_nonce, content_key,
                                                          f"recipient:{recipient_id}".encode())
        envelopes[recipient_id] = {"key_version": identity["key_version"],
            "kem_alg": KEM_ALG, "kem_ciphertext": kem_ciphertext.hex(),
            "wrap_nonce": wrap_nonce.hex(), "wrapped_key": wrapped.hex()}
    return {"format": "sigilchain-package-v1", "document_nonce": document_nonce.hex(),
            "document_ciphertext": encrypted_document.hex(), "envelopes": envelopes}


def decrypt_pdf(package: dict[str, Any], recipient_id: str, private: dict[str, Any]) -> bytes:
    if not isinstance(package, dict) or set(package) != _PACKAGE_FIELDS or package.get("format") != "sigilchain-package-v1":
        raise ValueError("Unsupported or malformed encrypted package.")
    if not isinstance(recipient_id, str) or not _SAFE_RECIPIENT_ID.fullmatch(recipient_id):
        raise ValueError("Invalid recipient ID.")
    envelopes = package["envelopes"]
    if not isinstance(envelopes, dict):
        raise ValueError("Encrypted package recipient envelopes must be an object.")
    document_nonce = _decode_hex(package["document_nonce"], "document nonce", exact_bytes=12)
    document_ciphertext = _decode_hex(package["document_ciphertext"], "document ciphertext", minimum_bytes=16)
    envelope = envelopes.get(recipient_id)
    if envelope is None:
        raise PermissionError(f"Recipient {recipient_id!r} has no key envelope in this package.")
    if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_FIELDS:
        raise ValueError("Encrypted package recipient envelope is malformed.")
    if type(envelope["key_version"]) is not int or envelope["key_version"] < 1:
        raise ValueError("Encrypted package recipient key version is malformed.")
    if envelope["kem_alg"] != KEM_ALG:
        raise ValueError("Encrypted package uses an unsupported recipient KEM.")
    if not isinstance(private, dict):
        raise ValueError("Recipient private key record is malformed.")
    if type(private.get("key_version")) is not int or private["key_version"] < 1 or private.get("kem_alg") != KEM_ALG:
        raise ValueError("Recipient private key record is malformed.")
    if envelope["key_version"] != private.get("key_version") or envelope["kem_alg"] != private.get("kem_alg"):
        raise PermissionError("The local private key does not match this recipient envelope.")
    try:
        with oqs.KeyEncapsulation(KEM_ALG, secret_key=bytes.fromhex(private["kem_secret"])) as kem:
            kem_ciphertext = _decode_hex(envelope["kem_ciphertext"], "KEM ciphertext",
                                         exact_bytes=kem.details["length_ciphertext"])
            shared_secret = kem.decap_secret(kem_ciphertext)
        wrap_nonce = _decode_hex(envelope["wrap_nonce"], "key-wrap nonce", exact_bytes=12)
        wrapped_key = _decode_hex(envelope["wrapped_key"], "wrapped content key", exact_bytes=48)
        content_key = AESGCM(_wrap_key(shared_secret)).decrypt(
            wrap_nonce, wrapped_key, f"recipient:{recipient_id}".encode())
        return AESGCM(content_key).decrypt(document_nonce, document_ciphertext,
                                           b"sigilchain-v1/document")
    except Exception as exc:
        raise ValueError("Decryption failed: package is damaged or the private key is incorrect.") from exc
