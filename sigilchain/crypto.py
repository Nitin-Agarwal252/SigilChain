"""Hybrid one-to-many document encryption using AES-GCM and ML-KEM."""
from __future__ import annotations

import os
from typing import Any

import oqs
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import KEM_ALG


def _wrap_key(shared_secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"sigilchain-v1/content-key-wrap/ML-KEM-768").derive(shared_secret)


def encrypt_pdf(pdf_bytes: bytes, recipients: dict[str, dict[str, Any]]) -> dict[str, Any]:
    if not recipients:
        raise ValueError("At least one active recipient is required.")
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
    if package.get("format") != "sigilchain-package-v1":
        raise ValueError("Unsupported or malformed encrypted package.")
    envelope = package.get("envelopes", {}).get(recipient_id)
    if envelope is None:
        raise PermissionError(f"Recipient {recipient_id!r} has no key envelope in this package.")
    if envelope.get("key_version") != private.get("key_version") or envelope.get("kem_alg") != private.get("kem_alg"):
        raise PermissionError("The local private key does not match this recipient envelope.")
    try:
        with oqs.KeyEncapsulation(KEM_ALG, secret_key=bytes.fromhex(private["kem_secret"])) as kem:
            shared_secret = kem.decap_secret(bytes.fromhex(envelope["kem_ciphertext"]))
        content_key = AESGCM(_wrap_key(shared_secret)).decrypt(
            bytes.fromhex(envelope["wrap_nonce"]), bytes.fromhex(envelope["wrapped_key"]),
            f"recipient:{recipient_id}".encode())
        return AESGCM(content_key).decrypt(bytes.fromhex(package["document_nonce"]),
            bytes.fromhex(package["document_ciphertext"]), b"sigilchain-v1/document")
    except Exception as exc:
        raise ValueError("Decryption failed: package is damaged or the private key is incorrect.") from exc
