"""SigilChain local recipient/sender command line interface."""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from . import config
from .agent import decrypt_and_mark
from .crypto import encrypt_pdf
from .documents import normalize
from .identity import enroll, lookup_identity, register_public, revoke, rotate
from .quorum import lookup_remote


def _passphrase(label: str) -> str:
    first = getpass.getpass(label)
    repeat = getpass.getpass("Repeat passphrase: ")
    if first != repeat:
        raise ValueError("Passphrases did not match.")
    if len(first) < 12:
        raise ValueError("Passphrases must be at least 12 characters.")
    return first


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sigilchain")
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("enroll", help="Create a recipient's PQC keys")
    p.add_argument("--as", dest="recipient", required=True)
    p = commands.add_parser("rotate", help="Rotate recipient keys")
    p.add_argument("--as", dest="recipient", required=True)
    p = commands.add_parser("revoke", help="Revoke recipient's active key")
    p.add_argument("--as", dest="recipient", required=True)
    p = commands.add_parser("export-public", help="Write a public identity record")
    p.add_argument("--as", dest="recipient", required=True)
    p.add_argument("--out", required=True)
    p = commands.add_parser("import-public", help="Register a public identity record")
    p.add_argument("--file", required=True)
    p = commands.add_parser("encrypt", help="Normalize and encrypt once for recipients")
    p.add_argument("--input", required=True)
    p.add_argument("--recipients", required=True, help="Comma-separated recipient IDs")
    p.add_argument("--out", required=True)
    p.add_argument("--remote-identities", action="store_true")
    p = commands.add_parser("decrypt", help="Decrypt, watermark, sign, and submit before release")
    p.add_argument("--package", required=True)
    p.add_argument("--as", dest="recipient", required=True)
    p.add_argument("--doc-id", required=True)
    p.add_argument("--out-dir", default="decrypted")
    args = parser.parse_args(argv)
    try:
        if args.command == "enroll":
            public = enroll(args.recipient, _passphrase("New identity passphrase: "))
            print(f"Enrolled {args.recipient}, key version {public['key_version']}.")
        elif args.command == "rotate":
            public = rotate(args.recipient, _passphrase("New key passphrase: "))
            print(f"Rotated {args.recipient} to key version {public['key_version']}.")
        elif args.command == "revoke":
            revoke(args.recipient)
            print(f"Revoked active identity key for {args.recipient}.")
        elif args.command == "export-public":
            public = lookup_identity(args.recipient)
            if not public:
                raise KeyError(f"Unknown active identity {args.recipient!r}")
            Path(args.out).write_text(json.dumps(public, indent=2), encoding="utf-8")
            print(f"Wrote public identity to {args.out}; it contains no private key material.")
        elif args.command == "import-public":
            public = json.loads(Path(args.file).read_text(encoding="utf-8"))
            if public.get("kem_alg") != "ML-KEM-768" or public.get("sig_alg") != "ML-DSA-65":
                raise ValueError("Public identity must use ML-KEM-768 and ML-DSA-65.")
            register_public(public)
            print(f"Registered public identity {public['recipient_id']} version {public['key_version']}.")
        elif args.command == "encrypt":
            pdf = normalize(args.input)
            recipients = {}
            for recipient in dict.fromkeys(x.strip() for x in args.recipients.split(",") if x.strip()):
                identity = lookup_remote(config.NODE_URLS, recipient) if args.remote_identities else lookup_identity(recipient)
                if not identity:
                    print(f"Skipping unknown or revoked identity {recipient!r}.", file=sys.stderr)
                    continue
                recipients[recipient] = identity
            if not recipients:
                raise ValueError("No active recipient identities resolved.")
            package = encrypt_pdf(pdf, recipients)
            Path(args.out).write_text(json.dumps(package, separators=(",", ":")), encoding="utf-8")
            print(f"Encrypted canonical PDF for {len(recipients)} recipient(s) to {args.out}.")
            print(f"Original source remains at {Path(args.input).resolve()}; retain it separately if needed.")
        elif args.command == "decrypt":
            package = json.loads(Path(args.package).read_text(encoding="utf-8"))
            result = decrypt_and_mark(package, args.recipient, args.doc_id, args.out_dir)
            print(f"Committed watermark session {result['watermark_id']} to {len(result['quorum']['accepted_by'])} pinned validators.")
            print(f"Wrote rasterized watermarked PDF: {result['output_path']}")
            print("The event signature binds the claim to the recipient key; it does not prove human presence or physical leak distribution.")
        return 0
    except Exception as exc:
        print(f"SigilChain error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
