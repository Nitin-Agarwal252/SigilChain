"""
SigilChain — Part 4: Sign & Submit the Decryption Record.

Immediately after Part 3 decrypts and watermarks a document, the agent
builds a small record describing the event and signs it with the
recipient's own ML-DSA private key. This binds the record to the
recipient's registered signing key. In the honest agent flow, the record
is created after decryption and watermarking. A signature alone proves
that the key signed the record; it does not independently prove that
decryption happened or that the human recipient distributed the file.

Deterministic serialization matters here: whatever bytes get signed must
be exactly reproducible later when a validator (or the trace console)
re-hashes the record to check the signature. Sorted-key, no-whitespace
JSON guarantees that — any other order or spacing would produce different
bytes and silently break verification, even though the *content* is
identical.
"""

import hashlib
import json
import time

import oqs


def build_record(doc_id: str, recipient_id: str, watermark_id: str,
                  marked_pdf_bytes: bytes, timestamp: int | None = None,
                  key_version: int = 1) -> bytes:
    """
    Build the deterministic byte string that gets signed. Returns raw bytes,
    not a dict — the caller signs exactly this, and a verifier must
    reconstruct exactly this same byte string to check the signature.
    """
    if timestamp is None:
        timestamp = int(time.time())
    record = {
        "doc_id": doc_id,
        "recipient_id": recipient_id,
        "key_version": key_version,
        "watermark_id": watermark_id,
        "timestamp": timestamp,
        "content_hash": hashlib.sha256(marked_pdf_bytes).hexdigest(),
    }
    return serialize_record(record)


def serialize_record(record: dict) -> bytes:
    """
    The single source of truth for turning a record dict into the exact
    bytes that get signed/verified. build_record uses this internally;
    the trace console (Part 6) calls it directly on a record dict fetched
    back from a validator node's /verify response, to independently
    reconstruct the same bytes and check the signature itself -- rather
    than just trusting whatever the node says.

    sort_keys + no extra whitespace: the same record always serializes to
    the exact same bytes, on any machine, at any time.
    """
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def parse_record(record_bytes: bytes) -> dict:
    """Inverse of build_record's JSON encoding, for reading a record back
    (e.g. in the trace console, after fetching it from a validator)."""
    return json.loads(record_bytes.decode("utf-8"))


def sign_record(record_bytes: bytes, sig_alg: str, sig_secret: bytes) -> bytes:
    """Sign with the recipient's own ML-DSA private key. This never touches
    the network — the secret key stays wherever the caller loaded it from
    (crypto.keys.load_identity's local file)."""
    with oqs.Signature(sig_alg, secret_key=sig_secret) as signer:
        return signer.sign(record_bytes)


def verify_record(record_bytes: bytes, signature: bytes, sig_alg: str, sig_public: bytes) -> bool:
    """Verify with the recipient's PUBLIC key only — this is what a
    validator node or the trace console does; neither ever needs or sees
    the private key."""
    with oqs.Signature(sig_alg) as verifier:
        return verifier.verify(record_bytes, signature, sig_public)
