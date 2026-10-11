"""
SigilChain — watermark payload packing.

DESIGN CHANGE from the first version: the watermark no longer encodes
recipient_id/timestamp directly. Instead it embeds a single random
watermark_id, and the *ledger record* (crypto/sign.py's build_record,
Part 4) is what actually carries recipient_id, doc_id, and timestamp --
keyed by that same watermark_id.

Why: the original design packed recipient_id as a uint16 number, but the
identity/crypto layer (Part 1 onward) uses string recipient IDs like
"nitin". Trying to keep both in sync would mean encoding strings into the
image itself, wasting embedding capacity on data that's already stored
(signed, even) in the ledger. Simpler and more robust: the image only has
to prove "this exact session happened" via watermark_id; the ledger
answers "who, and when."

Flow: agent generates a random watermark_id, embeds it (Part 3), builds
and signs a record containing it (Part 4), submits to the ledger (Part 5).
Trace console extracts the same watermark_id from a leaked image, looks
it up on the ledger, and gets recipient_id/timestamp/doc_id back --
signed, not guessed.

NOTE on error correction: unchanged from before -- this still relies on
dct_watermark's majority-vote redundancy. See that module's notes on
optionally layering `reedsolo` on top once it's installed locally.
"""

import os

try:
    from reedsolo import RSCodec
    RS_AVAILABLE = True
except ImportError:
    RS_AVAILABLE = False

# 12 bytes = 96 bits. Generous collision space for a demo/hackathon scale
# (far more sessions than will ever realistically be embedded), while
# staying small enough to keep embedding fast and robust.
WATERMARK_ID_SIZE = 12

# Reed-Solomon parity bytes: can correct up to RS_PARITY_BYTES // 2 byte
# errors anywhere in the encoded payload. This is a SECOND, independent
# error-correction layer on top of dct_watermark's majority-vote
# redundancy -- majority voting recovered the payload in the included
# synthetic JPEG experiment through its tested quality 30 case, so this mainly
# helps with the harder cases: localized burst damage (a crease, a glare
# spot) that majority voting's spread-across-the-page approach reduces
# but doesn't eliminate.
RS_PARITY_BYTES = 8

# The actual number of bytes embedded in the image once RS is applied.
# Both the embedding side (agent/cli.py) and extraction side
# (trace_console/app.py) must agree on this exact number -- it's not
# something to compute conditionally at runtime, since sender and
# verifier are different processes that never coordinate directly.
ENCODED_SIZE = WATERMARK_ID_SIZE + RS_PARITY_BYTES if RS_AVAILABLE else WATERMARK_ID_SIZE


def generate_watermark_id() -> bytes:
    """A fresh random ID for one decryption session. This is what gets
    embedded in the image AND used as the ledger's lookup key -- the two
    join on this value."""
    return os.urandom(WATERMARK_ID_SIZE)


def pack_for_embedding(watermark_id: bytes) -> bytes:
    """
    Reed-Solomon encode the watermark_id for embedding, if reedsolo is
    installed. Falls back to embedding it raw (relying solely on
    dct_watermark's majority-vote redundancy) if not -- so this module
    still works in environments without reedsolo, just with one fewer
    layer of error correction.
    """
    if not RS_AVAILABLE:
        return watermark_id
    rsc = RSCodec(RS_PARITY_BYTES)
    return bytes(rsc.encode(watermark_id))


def unpack_from_embedding(encoded: bytes) -> bytes:
    """
    Inverse of pack_for_embedding: RS-decode (correcting up to
    RS_PARITY_BYTES // 2 byte errors) back to the original watermark_id.
    Raises reedsolo.ReedSolomonError if the data is too corrupted to
    correct -- callers should treat that as "extraction failed", not
    crash the whole console.
    """
    if not RS_AVAILABLE:
        return encoded
    rsc = RSCodec(RS_PARITY_BYTES)
    decoded, _, _ = rsc.decode(bytearray(encoded))
    return bytes(decoded)


def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    if len(bits) % 8 != 0:
        raise ValueError("bit list length must be a multiple of 8")
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i + 8]:
            byte = (byte << 1) | (b & 1)
        out.append(byte)
    return bytes(out)
