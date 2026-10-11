"""
SigilChain — Part 3 (crypto half): Decrypt (recipient side).

The mechanical inverse of Part 2: decapsulate this recipient's envelope to
recover the shared secret, re-derive the same wrapping key via HKDF, unwrap
the AES content key, then decrypt the document.

The watermark-embedding half of Part 3 (watermark/dct_watermark.py +
watermark/payload.py, already proven) plugs in right after
decrypt_document() returns the plaintext PDF bytes — that's the join point
between this module and the watermark core.
"""

import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.encrypt import hkdf_derive


def decrypt_document(package: dict, recipient_id: str, recipient_private: dict) -> bytes:
    """
    package: the dict returned by encrypt_document()
    recipient_private: the dict returned by crypto.keys.load_identity()
                        (must be THIS recipient's own private identity)
    """
    envelope = package["envelopes"].get(recipient_id)
    if envelope is None:
        raise KeyError(f"No envelope for '{recipient_id}' in this package — not an intended recipient.")

    kem_alg = recipient_private["kem_alg"]
    kem_secret = bytes.fromhex(recipient_private["kem_secret"])
    kem_ciphertext = bytes.fromhex(envelope["kem_ciphertext"])

    with oqs.KeyEncapsulation(kem_alg, secret_key=kem_secret) as kem:
        shared_secret = kem.decap_secret(kem_ciphertext)

    wrap_key = hkdf_derive(shared_secret)
    wrap_nonce = bytes.fromhex(envelope["wrap_nonce"])
    wrapped_key = bytes.fromhex(envelope["wrapped_key"])
    content_key = AESGCM(wrap_key).decrypt(wrap_nonce, wrapped_key, associated_data=None)

    doc_nonce = bytes.fromhex(package["doc_nonce"])
    doc_ciphertext = bytes.fromhex(package["doc_ciphertext"])
    pdf_bytes = AESGCM(content_key).decrypt(doc_nonce, doc_ciphertext, associated_data=None)

    return pdf_bytes
