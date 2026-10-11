"""
SigilChain — CLI agent.

This is where every part built so far actually connects into the two
commands a real user runs:

    sigilchain encrypt --pdf briefing.pdf --recipients nitin,ashish --out package.json
    sigilchain decrypt --package package.json --as nitin --doc-id briefing-001

`encrypt` is the sender's one-time step (Part 2). `decrypt` is what a
recipient runs to open their copy -- and is where Parts 3, 4, and 5 chain
together automatically: decrypt -> watermark every page -> sign a record
-> submit to the validator quorum, all in one command.
"""

import argparse
import getpass
import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
from crypto.keys import (load_identity, lookup_identity, generate_identity,
                         register_identity, rotate_identity, revoke_identity,
                         protect_local_identity)
from crypto.encrypt import encrypt_document
from crypto.decrypt import decrypt_document
from crypto.normalize_document import normalize_to_pdf
from crypto.sign import build_record, sign_record
from watermark.pdf_utils import pdf_to_grayscale_images, images_to_pdf
if config.WATERMARK_TRANSFORM == "dwt-dct":
    from watermark.dwt_dct_watermark import embed_bits
else:
    from watermark.dct_watermark import embed_bits
from watermark.payload import generate_watermark_id, bytes_to_bits, pack_for_embedding, RS_AVAILABLE
from agent.quorum_client import submit_to_quorum, lookup_identity_remote

DEFAULT_NODES = config.NODE_URLS

# Parameters used by the synthetic DCT experiment in tests/test_dct_watermark.py.
# Its results are limited to those simulated inputs and do not guarantee
# recovery from arbitrary screenshots, crops, or photographs.
EMBED_DELTA = config.EMBED_DELTA
EMBED_REPEAT = config.EMBED_REPEAT


def cmd_encrypt(args):
    pdf_bytes = normalize_to_pdf(args.input_file)

    # Bulk recipient list: --recipients-file (one ID per line) scales to
    # 10, 100, or more recipients without a giant comma-separated string.
    # Blank lines and lines starting with # are skipped, so the same file
    # can double as a commented roster.
    recipient_ids = []
    if args.recipients_file:
        with open(args.recipients_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    recipient_ids.append(line)
    if args.recipients:
        recipient_ids.extend(r.strip() for r in args.recipients.split(","))
    recipient_ids = list(dict.fromkeys(recipient_ids))  # de-dupe, keep order

    if not recipient_ids:
        print("No recipients given -- use --recipients or --recipients-file.")
        return

    nodes = args.nodes.split(",") if args.nodes else DEFAULT_NODES
    recipients = {}
    print(f"Resolving {len(recipient_ids)} recipient(s)"
          f"{' via validator nodes (remote lookup)' if args.remote_identities else ' from the local registry'}...")
    for rid in recipient_ids:
        try:
            recipients[rid] = (lookup_identity_remote(nodes, rid) if args.remote_identities
                                else lookup_identity(rid))
        except KeyError as e:
            print(f"  SKIPPING '{rid}': {e}")

    if not recipients:
        print("No recipients could be resolved -- nothing to encrypt for.")
        return

    print(f"Encrypting normalized PDF from {args.input_file} ({len(pdf_bytes)} bytes) for {len(recipients)} recipient(s): "
          f"{list(recipients.keys())}")
    package = encrypt_document(pdf_bytes, recipients)

    with open(args.out, "w") as f:
        json.dump(package, f, indent=2)
    print(f"Wrote encrypted package to {args.out} "
          f"({os.path.getsize(args.out) / 1024:.1f} KB for {len(recipients)} recipient(s))")


def _confirmed_passphrase(prompt: str) -> str:
    first = getpass.getpass(prompt)
    second = getpass.getpass("Repeat passphrase: ")
    if len(first) < 12:
        raise ValueError("Use a passphrase with at least 12 characters.")
    if first != second:
        raise ValueError("Passphrases did not match.")
    return first


def cmd_enroll(args):
    try:
        lookup_identity(args.as_recipient)
    except KeyError:
        pass
    else:
        raise ValueError(f"Identity '{args.as_recipient}' is already registered; use rotate instead.")
    passphrase = _confirmed_passphrase("New identity passphrase: ")
    public = generate_identity(args.as_recipient, passphrase=passphrase)
    version = register_identity(public)
    print(f"Enrolled {args.as_recipient} key version {version}; private key is passphrase-encrypted locally.")


def cmd_rotate(args):
    passphrase = _confirmed_passphrase("New identity passphrase: ")
    public = rotate_identity(args.as_recipient, passphrase=passphrase)
    print(f"Rotated {args.as_recipient} to key version {public['key_version']}.")


def cmd_revoke(args):
    revoke_identity(args.as_recipient)
    print(f"Revoked active identity key for {args.as_recipient}.")


def cmd_protect_key(args):
    passphrase = _confirmed_passphrase("New identity passphrase: ")
    changed = protect_local_identity(args.as_recipient, passphrase=passphrase)
    print("Encrypted the existing local private key." if changed
          else "The local private key is already passphrase-encrypted.")


def cmd_decrypt(args):
    with open(args.package) as f:
        package = json.load(f)

    recipient_private = load_identity(args.as_recipient)
    print(f"Decrypting as '{args.as_recipient}'...")
    pdf_bytes = decrypt_document(package, args.as_recipient, recipient_private)
    print(f"Decrypted: {len(pdf_bytes)} bytes")

    print("Rasterizing pages...")
    pages = pdf_to_grayscale_images(pdf_bytes)
    print(f"{len(pages)} page(s)")

    watermark_id = generate_watermark_id()
    encoded_payload = pack_for_embedding(watermark_id)
    bits = bytes_to_bits(encoded_payload)
    print(f"Session watermark_id: {watermark_id.hex()}")
    print(f"Reed-Solomon error correction: {'enabled' if RS_AVAILABLE else 'NOT AVAILABLE (embedding raw -- install reedsolo for a second redundancy layer)'}")
    print(f"Watermark transform: {config.WATERMARK_TRANSFORM} (delta={EMBED_DELTA}, repeat={EMBED_REPEAT})")

    print("Embedding watermark into every page...")
    marked_pages = []
    for i, page in enumerate(pages):
        marked = embed_bits(page.astype(float), bits, delta=EMBED_DELTA, repeat=EMBED_REPEAT)
        marked_pages.append(marked.clip(0, 255).astype("uint8"))
        print(f"  page {i + 1}/{len(pages)} marked")

    marked_pdf_bytes = images_to_pdf(marked_pages)

    print("\nBuilding and signing the decryption record...")
    record_bytes = build_record(
        doc_id=args.doc_id,
        recipient_id=args.as_recipient,
        watermark_id=watermark_id.hex(),
        marked_pdf_bytes=marked_pdf_bytes,
        key_version=recipient_private.get("key_version", 1),
    )
    signature = sign_record(record_bytes, recipient_private["sig_alg"],
                             bytes.fromhex(recipient_private["sig_secret"]))

    nodes = args.nodes.split(",") if args.nodes else DEFAULT_NODES
    print(f"Submitting to validator quorum: {nodes}")
    result = submit_to_quorum(nodes, watermark_id.hex(), record_bytes, signature,
                               args.as_recipient, required=config.QUORUM_REQUIRED)

    print(f"\nCommitted: {result['committed']}")
    backends = sorted({item.get("ledger_backend") for item in result["accepted_by"]
                       if item.get("ledger_backend")})
    if backends:
        print(f"Ledger backend(s): {', '.join(backends)}")
    print(f"Accepted by: {[a['url'] for a in result['accepted_by']]}")
    if result["rejected_by"]:
        print(f"Rejected by: {result['rejected_by']}")
    if result["unreachable"]:
        print(f"Unreachable: {result['unreachable']}")

    if result["committed"]:
        # Do not release the marked plaintext until the event has reached
        # the configured quorum. Write atomically so an interrupted write
        # cannot leave a partial PDF at the final path.
        os.makedirs(args.out_dir, exist_ok=True)
        out_path = os.path.join(args.out_dir, f"{args.doc_id}_{args.as_recipient}.pdf")
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="wb", delete=False,
                                             dir=args.out_dir, prefix=".sigilchain-") as f:
                temp_path = f.name
                f.write(marked_pdf_bytes)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp_path, out_path)
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        print(f"Wrote marked PDF to {out_path}")
        print(f"\nDone. watermark_id = {watermark_id.hex()}")
        print("Keep this ID (or the marked PDF, which carries it invisibly) "
              "-- the trace console looks up exactly this.")
    else:
        print("\nWARNING: record was not committed by enough nodes. "
              "The marked PDF was not released. Check that enough validator nodes are running.")


def main():
    parser = argparse.ArgumentParser(prog="sigilchain")
    sub = parser.add_subparsers(dest="command", required=True)

    p_enroll = sub.add_parser("enroll", help="Generate a passphrase-protected identity and register its public keys")
    p_enroll.add_argument("--as", dest="as_recipient", required=True, help="Identity name to enroll")
    p_enroll.set_defaults(func=cmd_enroll)

    p_rotate = sub.add_parser("rotate", help="Rotate an identity's keys and preserve prior public keys for audits")
    p_rotate.add_argument("--as", dest="as_recipient", required=True, help="Identity name to rotate")
    p_rotate.set_defaults(func=cmd_rotate)

    p_revoke = sub.add_parser("revoke", help="Revoke the active identity key in the local registry")
    p_revoke.add_argument("--as", dest="as_recipient", required=True, help="Identity name to revoke")
    p_revoke.set_defaults(func=cmd_revoke)

    p_protect = sub.add_parser("protect-key", help="Encrypt an existing plaintext identity file without rotating it")
    p_protect.add_argument("--as", dest="as_recipient", required=True, help="Identity name to protect")
    p_protect.set_defaults(func=cmd_protect_key)

    p_enc = sub.add_parser("encrypt", help="Sender: normalize a supported source file to PDF, then encrypt it")
    p_enc.add_argument("--input", "--pdf", dest="input_file", required=True,
                       help="Source PDF, office document, text/HTML/CSV, or raster image (legacy --pdf alias supported)")
    p_enc.add_argument("--recipients", default=None,
                        help="Comma-separated recipient IDs, e.g. nitin,ashish")
    p_enc.add_argument("--recipients-file", default=None,
                        help="Path to a text file, one recipient ID per line -- for bulk sends (10s-100s of recipients)")
    p_enc.add_argument("--remote-identities", action="store_true",
                        help="Resolve recipients' public keys via the validator nodes' network "
                             "/identity endpoint instead of the local registry file -- needed when "
                             "recipients are on different machines")
    p_enc.add_argument("--nodes", default=None,
                        help="Comma-separated validator node URLs, used only with --remote-identities "
                             "(default: localhost:8001-8003)")
    p_enc.add_argument("--out", default="package.json", help="Where to write the encrypted package")
    p_enc.set_defaults(func=cmd_encrypt)

    p_dec = sub.add_parser("decrypt", help="Recipient: decrypt, watermark, sign, and submit to the ledger")
    p_dec.add_argument("--package", required=True, help="Path to the encrypted package JSON")
    p_dec.add_argument("--as", dest="as_recipient", required=True, help="Which recipient identity to decrypt as")
    p_dec.add_argument("--doc-id", required=True, help="A short identifier for this document")
    p_dec.add_argument("--out-dir", default="decrypted", help="Where to save the watermarked PDF")
    p_dec.add_argument("--nodes", default=None,
                        help="Comma-separated validator node URLs (default: localhost:8001-8003)")
    p_dec.set_defaults(func=cmd_decrypt)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
