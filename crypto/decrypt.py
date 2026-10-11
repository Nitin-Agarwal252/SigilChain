"""Package verification, key unwrap, and document decryption."""

import hashlib

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.encrypt import (
    CRYPTO_SUITE, PACKAGE_VERSION, _package_aad, _wrap_aad, _wrap_info, hkdf_derive,
    package_context, verify_package_signature,
)


def decrypt_document(package: dict, recipient_id: str, recipient_private: dict,
                     sender_identity: dict | None = None) -> bytes:
    """Decrypt a v1 legacy package or a signed, authenticated v2 package.

    For v2, the caller must resolve the sender's public key independently
    (normally from the identity registry) and pass it as ``sender_identity``.
    """
    envelope = package.get("envelopes", {}).get(recipient_id)
    if envelope is None:
        raise KeyError(f"No envelope for '{recipient_id}' in this package — not an intended recipient.")

    version = package.get("package_version", 1)
    if version == PACKAGE_VERSION:
        if package.get("crypto_suite") != CRYPTO_SUITE:
            raise ValueError("Unsupported package cryptographic suite")
        if not verify_package_signature(package, sender_identity):
            raise ValueError("Package sender signature is missing or invalid; verify the sender identity and package integrity.")
        if set(package.get("recipients", {})) != set(package.get("envelopes", {})):
            raise ValueError("Package manifest recipient list does not match its key envelopes")
        recipient_meta = package.get("recipients", {}).get(recipient_id)
        if (not recipient_meta
                or recipient_meta.get("kem_alg") != recipient_private.get("kem_alg")
                or recipient_meta.get("key_version") != recipient_private.get("key_version", 1)
                or envelope.get("recipient_key_version") != recipient_private.get("key_version", 1)
                or recipient_meta.get("kem_public_sha256") != hashlib.sha256(
                    bytes.fromhex(recipient_private["kem_public"])
                ).hexdigest()):
            raise ValueError("Package recipient key metadata does not match this private identity")
        context = package_context(package)
        wrap_aad = _wrap_aad(package["package_id"], recipient_id, {
            "kem_alg": recipient_private["kem_alg"],
            "kem_public": recipient_private["kem_public"],
            "key_version": recipient_private.get("key_version", 1),
        })
    elif version == 1:
        # Read-only compatibility for pre-v2 packages. Newly created packages
        # are authenticated v2 and reject missing or invalid sender signatures.
        context = None
        wrap_aad = None
    else:
        raise ValueError(f"Unsupported SigilChain package version: {version}")

    kem_alg = envelope.get("kem_alg", recipient_private["kem_alg"])
    if kem_alg != recipient_private["kem_alg"]:
        raise ValueError("Envelope KEM algorithm does not match this identity")
    kem_secret = bytes.fromhex(recipient_private["kem_secret"])
    with oqs.KeyEncapsulation(kem_alg, secret_key=kem_secret) as kem:
        shared_secret = kem.decap_secret(bytes.fromhex(envelope["kem_ciphertext"]))

    wrap_key = (hkdf_derive(shared_secret, info=_wrap_info(package["package_id"], recipient_id, {
        "kem_alg": recipient_private["kem_alg"],
        "kem_public": recipient_private["kem_public"],
        "key_version": recipient_private.get("key_version", 1),
    })) if version == PACKAGE_VERSION else hkdf_derive(shared_secret))
    if version == PACKAGE_VERSION:
        content_key = AESGCM(wrap_key).decrypt(
            bytes.fromhex(envelope["wrap_nonce"]), bytes.fromhex(envelope["wrapped_key"]), wrap_aad
        )
        pdf_bytes = AESGCM(content_key).decrypt(
            bytes.fromhex(package["doc_nonce"]), bytes.fromhex(package["doc_ciphertext"]),
            _package_aad(context),
        )
        if hashlib.sha256(pdf_bytes).hexdigest() != package.get("document_sha256"):
            raise ValueError("Decrypted document hash does not match the signed package manifest")
        return pdf_bytes

    content_key = AESGCM(wrap_key).decrypt(
        bytes.fromhex(envelope["wrap_nonce"]), bytes.fromhex(envelope["wrapped_key"]), None
    )
    return AESGCM(content_key).decrypt(
        bytes.fromhex(package["doc_nonce"]), bytes.fromhex(package["doc_ciphertext"]), None
    )
