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
import copy
import hashlib
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.keys import generate_identity, register_identity, lookup_identity, load_identity
from crypto.encrypt import encrypt_document, canonical_json
from crypto.decrypt import decrypt_document
from crypto.sign import build_record, sign_record, verify_record, parse_record
from crypto.transfer import (build_transfer_record, build_acceptance_record,
                             acceptance_event_id, sign_transfer, new_transfer_id)


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
    nitin_private = load_identity("nitin")
    package = encrypt_document(fake_pdf, {"nitin": nitin_pub, "ashish": ashish_pub},
                               sender_id="nitin", sender_identity=nitin_private)
    print(f"doc_ciphertext: {len(package['doc_ciphertext']) // 2} bytes")
    print(f"Envelopes built for: {list(package['envelopes'].keys())}")

    print("\n=== Part 3 (crypto half): Decrypting as each recipient ===")
    nitin_private = load_identity("nitin")
    ashish_private = load_identity("ashish")

    decrypted_nitin = decrypt_document(package, "nitin", nitin_private, nitin_pub)
    decrypted_ashish = decrypt_document(package, "ashish", ashish_private, nitin_pub)

    nitin_ok = decrypted_nitin == fake_pdf
    ashish_ok = decrypted_ashish == fake_pdf
    print(f"Nitin's decrypted copy matches original:  {nitin_ok}")
    print(f"Ashish's decrypted copy matches original: {ashish_ok}")

    print("\n=== Package v2 manifest and tamper checks ===")
    package_version_ok = package.get("package_version") == 2 and bool(package.get("sender_signature_hex"))
    tampered_package = copy.deepcopy(package)
    tampered_package["recipients"]["ashish"]["key_version"] += 1
    try:
        decrypt_document(tampered_package, "nitin", nitin_private, nitin_pub)
        manifest_tamper_rejected = False
    except ValueError:
        manifest_tamper_rejected = True
    tampered_ciphertext = copy.deepcopy(package)
    ciphertext = bytes.fromhex(tampered_ciphertext["doc_ciphertext"])
    tampered_ciphertext["doc_ciphertext"] = (ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])).hex()
    try:
        decrypt_document(tampered_ciphertext, "nitin", nitin_private, nitin_pub)
        ciphertext_tamper_rejected = False
    except ValueError:
        ciphertext_tamper_rejected = True
    print(f"Versioned sender-signed manifest present: {package_version_ok}")
    print(f"Manifest edit rejected: {manifest_tamper_rejected}")
    print(f"Ciphertext edit rejected: {ciphertext_tamper_rejected}")

    transfer_id = new_transfer_id()
    transfer_package = encrypt_document(
        fake_pdf, {"ashish": ashish_pub}, sender_id="nitin",
        sender_identity=nitin_private, parent_transfer_event_id=transfer_id,
    )
    transfer_record = build_transfer_record(
        transfer_id=transfer_id, document_id="briefing-001", sender=nitin_private,
        recipient=ashish_pub, source_package_id=package["package_id"],
        source_package_sha256=hashlib.sha256(canonical_json(package)).hexdigest(),
        source_document_sha256=hashlib.sha256(fake_pdf).hexdigest(),
        target_package=transfer_package,
        parent_transfer_event_id=None,
    )
    transfer_signature = sign_transfer(transfer_record, nitin_private)
    transfer_valid = verify_record(transfer_record, transfer_signature, nitin_pub["sig_alg"],
                                   bytes.fromhex(nitin_pub["sig_public"]))
    print(f"Signed transfer event verifies for {parse_record(transfer_record)['from_id']} -> "
          f"{parse_record(transfer_record)['to_id']}: {transfer_valid}")

    print("\n=== Recipient acceptance and branched handoff checks ===")
    target_hash = hashlib.sha256(canonical_json(transfer_package)).hexdigest()
    acceptance_id = acceptance_event_id(transfer_id, "ashish", transfer_package["package_id"], target_hash)
    ashish_private = load_identity("ashish")
    acceptance_bytes = build_acceptance_record(
        acceptance_id=acceptance_id, transfer_id=transfer_id,
        document_id="briefing-001", recipient=ashish_private,
        package_id=transfer_package["package_id"], package_sha256=target_hash,
        document_sha256=hashlib.sha256(fake_pdf).hexdigest(),
    )
    acceptance_signature = sign_transfer(acceptance_bytes, ashish_private)
    acceptance_valid = verify_record(acceptance_bytes, acceptance_signature, ashish_pub["sig_alg"],
                                     bytes.fromhex(ashish_pub["sig_public"]))
    branched_package = encrypt_document(
        fake_pdf, {"nitin": nitin_pub}, sender_id="ashish", sender_identity=ashish_private,
        parent_transfer_event_id=transfer_id,
        parent_acceptance_event_id=acceptance_id,
    )
    branch_record = build_transfer_record(
        transfer_id=new_transfer_id(), document_id="briefing-001", sender=ashish_private,
        recipient=nitin_pub, source_package_id=transfer_package["package_id"],
        source_package_sha256=target_hash,
        source_document_sha256=hashlib.sha256(fake_pdf).hexdigest(),
        target_package=branched_package, parent_transfer_event_id=transfer_id,
        parent_acceptance_event_id=acceptance_id,
    )
    branch_fields = parse_record(branch_record)
    branch_valid = verify_record(branch_record, sign_transfer(branch_record, ashish_private),
                                  ashish_pub["sig_alg"], bytes.fromhex(ashish_pub["sig_public"]))
    print(f"Recipient acceptance signature verifies: {acceptance_valid}")
    print(f"Child transfer links to accepted parent: {branch_valid and branch_fields['parent_acceptance_event_id'] == acceptance_id}")

    # A recipient who was never sent an envelope should be rejected cleanly
    print("\n=== Part 3: Confirming a non-recipient is correctly rejected ===")
    try:
        decrypt_document(package, "someone-else", nitin_private, nitin_pub)
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
    all_ok = (nitin_ok and ashish_ok and rejection_ok and valid and not tampered_valid
              and package_version_ok and manifest_tamper_rejected and ciphertext_tamper_rejected)
    all_ok = all_ok and transfer_valid
    all_ok = all_ok and acceptance_valid and branch_valid
    if all_ok:
        print("Parts 2, 3 (crypto), and 4 all working: encrypt/distribute, "
              "per-recipient decrypt, and sign/verify all check out.")
    else:
        print("Something above didn't match expectations \u2014 paste this full output back for debugging.")


if __name__ == "__main__":
    main()
