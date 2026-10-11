"""
SigilChain — Part 2: Encrypt & Distribute (sender side).

Hybrid encryption: the document is encrypted ONCE with a random AES-256
content key. That content key is then wrapped separately for each
recipient using their ML-KEM public key — so the heavy document ciphertext
is shared, but only the intended recipient can unwrap the key.

Package format (all binary fields hex-encoded for easy JSON/SQLite storage):
{
  "doc_nonce": "...",
  "doc_ciphertext": "...",      # AES-GCM ciphertext, tag included (cryptography lib appends it)
  "envelopes": {
    "<recipient_id>": {
      "kem_ciphertext": "...",  # what the recipient decapsulates
      "wrap_nonce": "...",
      "wrapped_key": "..."      # the AES content key, wrapped for this recipient
    },
    ...
  }
}
"""

import os
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

HKDF_INFO = b"sigilchain-content-key-wrap"


def hkdf_derive(shared_secret: bytes, info: bytes = HKDF_INFO, length: int = 32) -> bytes:
    """
    A KEM's shared secret isn't automatically a usable AES key — HKDF turns
    it into one. `info` domain-separates this specific use so the same
    shared secret can't accidentally be reused as a key elsewhere.
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(shared_secret)


def encrypt_document(pdf_bytes: bytes, recipients: dict) -> dict:
    """
    recipients: {recipient_id: identity_dict} where identity_dict has at
    least "kem_alg" and "kem_public" (hex) — the public record shape
    crypto.keys.lookup_identity() returns.
    """
    content_key = AESGCM.generate_key(bit_length=256)
    aesgcm = AESGCM(content_key)
    doc_nonce = os.urandom(12)
    doc_ciphertext = aesgcm.encrypt(doc_nonce, pdf_bytes, associated_data=None)

    envelopes = {}
    for recipient_id, identity in recipients.items():
        kem_alg = identity["kem_alg"]
        kem_public = bytes.fromhex(identity["kem_public"])

        with oqs.KeyEncapsulation(kem_alg) as kem:
            kem_ciphertext, shared_secret = kem.encap_secret(kem_public)

        wrap_key = hkdf_derive(shared_secret)
        wrap_nonce = os.urandom(12)
        wrapped_key = AESGCM(wrap_key).encrypt(wrap_nonce, content_key, associated_data=None)

        envelopes[recipient_id] = {
            "kem_ciphertext": kem_ciphertext.hex(),
            "wrap_nonce": wrap_nonce.hex(),
            "wrapped_key": wrapped_key.hex(),
        }

    return {
        "doc_nonce": doc_nonce.hex(),
        "doc_ciphertext": doc_ciphertext.hex(),
        "envelopes": envelopes,
    }
