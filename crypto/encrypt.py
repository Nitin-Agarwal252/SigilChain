"""Hybrid document encryption and authenticated SigilChain package format.

ML-KEM-768 remains a key encapsulation mechanism; AES-256-GCM encrypts the
document bytes. Version 2 binds package metadata and recipient envelopes with
AEAD associated data, hashes the plaintext, and can carry a sender ML-DSA
signature over the complete package manifest. The signature is verified
against the sender's registered public key by the caller.
"""

import hashlib
import json
import os
import uuid

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from crypto.sign import sign_record, verify_record

HKDF_INFO = b"sigilchain/v2/ml-kem-768/content-key-wrap"
PACKAGE_VERSION = 2
CRYPTO_SUITE = "ML-KEM-768+HKDF-SHA256+AES-256-GCM+ML-DSA-65"


def canonical_json(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hkdf_derive(shared_secret: bytes, info: bytes = HKDF_INFO, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(shared_secret)


def _package_aad(context: dict) -> bytes:
    return canonical_json(context)


def _wrap_context(package_id: str, recipient_id: str, identity: dict) -> dict:
    return {
        "package_version": PACKAGE_VERSION,
        "package_id": package_id,
        "recipient_id": recipient_id,
        "recipient_key_version": int(identity.get("key_version", 1)),
        "kem_alg": identity["kem_alg"],
        "kem_public_sha256": hashlib.sha256(bytes.fromhex(identity["kem_public"])).hexdigest(),
        "crypto_suite": CRYPTO_SUITE,
    }


def _wrap_info(package_id: str, recipient_id: str, identity: dict) -> bytes:
    return HKDF_INFO + b"\0" + canonical_json(_wrap_context(package_id, recipient_id, identity))


def _wrap_aad(package_id: str, recipient_id: str, identity: dict) -> bytes:
    return canonical_json(_wrap_context(package_id, recipient_id, identity))


def package_signing_bytes(package: dict) -> bytes:
    """Canonical bytes covered by a sender's signature (signature excluded)."""
    unsigned = {key: value for key, value in package.items() if key != "sender_signature_hex"}
    return canonical_json(unsigned)


def verify_package_signature(package: dict, sender_identity: dict | None) -> bool:
    """Verify the v2 sender signature against a separately resolved registry key."""
    if package.get("package_version") != PACKAGE_VERSION:
        return False
    sender = package.get("sender")
    signature_hex = package.get("sender_signature_hex")
    if not sender or not signature_hex or not sender_identity:
        return False
    if (sender_identity.get("recipient_id") != sender.get("recipient_id")
            or sender_identity.get("key_version") != sender.get("key_version")
            or sender_identity.get("sig_alg") != sender.get("sig_alg")):
        return False
    try:
        return verify_record(package_signing_bytes(package), bytes.fromhex(signature_hex),
                             sender_identity["sig_alg"], bytes.fromhex(sender_identity["sig_public"]))
    except (KeyError, TypeError, ValueError):
        return False


def encrypt_document(document_bytes: bytes, recipients: dict, *, sender_id: str | None = None,
                     sender_identity: dict | None = None, package_id: str | None = None,
                     parent_transfer_event_id: str | None = None,
                     parent_acceptance_event_id: str | None = None) -> dict:
    """Encrypt a document once and wrap its content key for every recipient.

    ``sender_identity`` is a locally loaded private identity. When supplied,
    it must belong to ``sender_id`` and signs the full package manifest.
    """
    if not document_bytes:
        raise ValueError("Cannot encrypt an empty document")
    if not recipients:
        raise ValueError("At least one recipient is required")
    if (sender_identity is None) != (sender_id is None):
        raise ValueError("sender_id and sender_identity must be supplied together")
    if sender_identity is None:
        raise ValueError("Version 2 packages require a locally held sender identity to sign the manifest")
    if sender_identity and sender_identity.get("recipient_id") != sender_id:
        raise ValueError("sender identity does not match sender_id")

    package_id = package_id or uuid.uuid4().hex
    recipient_meta = {
        rid: {"kem_alg": identity["kem_alg"], "key_version": int(identity.get("key_version", 1)),
              "kem_public_sha256": hashlib.sha256(bytes.fromhex(identity["kem_public"])).hexdigest()}
        for rid, identity in sorted(recipients.items())
    }
    sender = {"recipient_id": sender_id,
              "key_version": int(sender_identity.get("key_version", 1)),
              "sig_alg": sender_identity["sig_alg"]}
    context = {
        "package_version": PACKAGE_VERSION,
        "crypto_suite": CRYPTO_SUITE,
        "package_id": package_id,
        "document_sha256": hashlib.sha256(document_bytes).hexdigest(),
        "recipients": recipient_meta,
        "sender": sender,
        "lineage": {"parent_transfer_event_id": parent_transfer_event_id,
                    "parent_acceptance_event_id": parent_acceptance_event_id},
    }

    content_key = AESGCM.generate_key(bit_length=256)
    doc_nonce = os.urandom(12)
    doc_ciphertext = AESGCM(content_key).encrypt(doc_nonce, document_bytes, _package_aad(context))

    envelopes = {}
    for recipient_id, identity in recipients.items():
        kem_alg = identity["kem_alg"]
        with oqs.KeyEncapsulation(kem_alg) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(bytes.fromhex(identity["kem_public"]))
        wrap_key = hkdf_derive(shared_secret, info=_wrap_info(package_id, recipient_id, identity))
        wrap_nonce = os.urandom(12)
        wrapped_key = AESGCM(wrap_key).encrypt(
            wrap_nonce, content_key, _wrap_aad(package_id, recipient_id, identity)
        )
        envelopes[recipient_id] = {
            "kem_alg": kem_alg,
            "recipient_key_version": int(identity.get("key_version", 1)),
            "kem_ciphertext": kem_ciphertext.hex(),
            "wrap_nonce": wrap_nonce.hex(),
            "wrapped_key": wrapped_key.hex(),
        }

    package = {
        "package_version": PACKAGE_VERSION,
        "crypto_suite": CRYPTO_SUITE,
        "package_id": package_id,
        "document_sha256": context["document_sha256"],
        "lineage": context["lineage"],
        "sender": sender,
        "recipients": recipient_meta,
        "doc_nonce": doc_nonce.hex(),
        "doc_ciphertext": doc_ciphertext.hex(),
        "envelopes": envelopes,
    }
    package["sender_signature_hex"] = sign_record(
        package_signing_bytes(package), sender_identity["sig_alg"],
        bytes.fromhex(sender_identity["sig_secret"]),
    ).hex()
    return package


def package_context(package: dict) -> dict:
    return {
        "package_version": package["package_version"],
        "crypto_suite": package["crypto_suite"],
        "package_id": package["package_id"],
        "document_sha256": package["document_sha256"],
        "recipients": package["recipients"],
        "sender": package.get("sender"),
        "lineage": package.get("lineage", {"parent_transfer_event_id": None}),
    }
