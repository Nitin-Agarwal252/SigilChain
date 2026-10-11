"""
Part 2 + Part 3 (crypto half) + Part 4 end-to-end check.

1. Encrypt a fake document for two recipients (Part 2).
2. Decrypt it as each recipient using their own private key (Part 3).
3. Confirm both recover the exact original plaintext.
4. Build, sign, and verify a decryption record for one recipient (Part 4).
5. Confirm a tampered record correctly FAILS verification.

Run: python tests/test_part2_encrypt.py
"""

import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.keys import generate_identity, register_identity, lookup_identity, load_identity
from crypto.encrypt import encrypt_document
from crypto.decrypt import decrypt_document
from crypto.sign import build_record, sign_record, verify_record, parse_record


def ensure_identity(recipient_id: str) -> dict:
    """Reuse an identity from Part 1's test if it already exists locally,
    otherwise generate a fresh one."""
    try:
        load_identity(recipient_id)
    except FileNotFoundError:
        pub = generate_identity(recipient_id)
        register_identity(pub)
    return lookup_identity(recipient_id)


def main():
    print("=== Ensuring identities exist (reusing Part 1's if present) ===")
    ashish_pub = ensure_identity("ashish")
    nitin_pub = ensure_identity("nitin")

    fake_pdf = b"%PDF-1.4 CLASSIFIED BRIEFING -- PS 26237 -- test content " * 80
    print(f"\nTest document: {len(fake_pdf)} bytes")

    print("\n=== Part 2: Encrypting for 2 recipients ===")
    package = encrypt_document(fake_pdf, {"nitin": nitin_pub, "ashish": ashish_pub})
    print(f"doc_ciphertext: {len(package['doc_ciphertext']) // 2} bytes")
    print(f"Envelopes built for: {list(package['envelopes'].keys())}")

    print("\n=== Part 3 (crypto half): Decrypting as each recipient ===")
    nitin_private = load_identity("nitin")
    ashish_private = load_identity("ashish")

    decrypted_nitin = decrypt_document(package, "nitin", nitin_private)
    decrypted_ashish = decrypt_document(package, "ashish", ashish_private)

    nitin_ok = decrypted_nitin == fake_pdf
    ashish_ok = decrypted_ashish == fake_pdf
    print(f"Nitin's decrypted copy matches original:  {nitin_ok}")
    print(f"Ashish's decrypted copy matches original: {ashish_ok}")

    # A recipient who was never sent an envelope should be rejected cleanly
    print("\n=== Part 3: Confirming a non-recipient is correctly rejected ===")
    try:
        decrypt_document(package, "someone-else", nitin_private)
        print("PROBLEM: non-recipient decryption did not raise an error")
        rejection_ok = False
    except KeyError as e:
        print(f"Correctly rejected: {e}")
        rejection_ok = True

    print("\n=== Part 4: Sign + verify a decryption record (Nitin) ===")
    record_bytes = build_record(
        doc_id="briefing-001",
        recipient_id="nitin",
        watermark_id="wm-3f9a21",
        marked_pdf_bytes=decrypted_nitin,
    )
    print(f"Record (deterministic bytes): {parse_record(record_bytes)}")

    signature = sign_record(record_bytes, nitin_private["sig_alg"], bytes.fromhex(nitin_private["sig_secret"]))
    sig_public_bytes = bytes.fromhex(nitin_pub["sig_public"])

    valid = verify_record(record_bytes, signature, nitin_pub["sig_alg"], sig_public_bytes)
    print(f"Signature valid on real record:      {valid}  (expect True)")

    tampered_bytes = record_bytes.replace(b'"nitin"', b'"ashish"')
    tampered_valid = verify_record(tampered_bytes, signature, nitin_pub["sig_alg"], sig_public_bytes)
    print(f"Signature valid on tampered record:  {tampered_valid}  (expect False)")

    print("\n=== RESULT ===")
    all_ok = nitin_ok and ashish_ok and rejection_ok and valid and not tampered_valid
    if all_ok:
        print("Parts 2, 3 (crypto), and 4 all working: encrypt/distribute, "
              "per-recipient decrypt, and sign/verify all check out.")
    else:
        print("Something above didn't match expectations \u2014 paste this full output back for debugging.")


if __name__ == "__main__":
    main()
