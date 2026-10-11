"""
Part 1 end-to-end check: generate two identities (Ashish, Nitin), register
their public keys, then prove the crypto actually round-trips:
  - KEM: encapsulate against a public key, decapsulate with the matching
    secret key, confirm both sides agree on the shared secret.
  - Signature: sign a message with a secret key, verify with the matching
    public key, confirm a tampered message correctly FAILS verification.

Run: python tests/test_part1_keys.py
"""

import os
import sys
import oqs

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from crypto.keys import generate_identity, register_identity, lookup_identity


def main():
    print("=== Generating identities ===")
    ashish_pub = generate_identity("ashish")
    nitin_pub = generate_identity("nitin")

    print("\n=== Registering public keys ===")
    register_identity(ashish_pub)
    register_identity(nitin_pub)

    print("\n=== Looking up from registry ===")
    fetched = lookup_identity("nitin")
    assert fetched["kem_public"] == nitin_pub["kem_public"]
    assert fetched["sig_public"] == nitin_pub["sig_public"]
    print("Registry round-trip OK — fetched keys match what was generated.")

    # --- KEM round trip: sender encapsulates against Nitin's public key,
    # Nitin decapsulates with his own secret key, both must agree.
    print("\n=== KEM encap/decap round trip ===")
    from crypto.keys import load_identity
    nitin_private = load_identity("nitin")

    kem_public_bytes = bytes.fromhex(fetched["kem_public"])
    kem_secret_bytes = bytes.fromhex(nitin_private["kem_secret"])

    with oqs.KeyEncapsulation(fetched["kem_alg"]) as sender_kem:
        ciphertext, sender_shared_secret = sender_kem.encap_secret(kem_public_bytes)

    with oqs.KeyEncapsulation(fetched["kem_alg"], secret_key=kem_secret_bytes) as recipient_kem:
        recipient_shared_secret = recipient_kem.decap_secret(ciphertext)

    if sender_shared_secret == recipient_shared_secret:
        print("KEM OK — sender and recipient derived the identical shared secret.")
    else:
        print("KEM MISMATCH — shared secrets do NOT match. Something's wrong.")

    # --- Signature round trip
    print("\n=== Signature sign/verify round trip ===")
    message = b"decryption-record:doc123:nitin:1732300800"

    sig_secret_bytes = bytes.fromhex(nitin_private["sig_secret"])
    sig_public_bytes = bytes.fromhex(fetched["sig_public"])

    with oqs.Signature(fetched["sig_alg"], secret_key=sig_secret_bytes) as signer:
        signature = signer.sign(message)

    with oqs.Signature(fetched["sig_alg"]) as verifier:
        valid = verifier.verify(message, signature, sig_public_bytes)
        tampered_valid = verifier.verify(message + b"TAMPERED", signature, sig_public_bytes)

    print(f"Signature valid on original message: {valid}  (expect True)")
    print(f"Signature valid on tampered message:  {tampered_valid}  (expect False)")

    print("\n=== RESULT ===")
    if sender_shared_secret == recipient_shared_secret and valid and not tampered_valid:
        print("Part 1 fully working: identity generation, registry, KEM, and signatures all correct.")
    else:
        print("Something above didn't match expectations — paste this full output back for debugging.")


if __name__ == "__main__":
    main()
