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
import hashlib
import json
import os
import sys
import tempfile
import time

def _paint(message: str, code: str) -> str:
    """Add restrained terminal color without polluting redirected output."""
    if os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty():
        return message
    return f"\033[{code}m{message}\033[0m"


def _status(label: str, message: str, code: str = "36") -> None:
    print(f"{_paint(label, code)} {message}")


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import config
from crypto.keys import (load_identity, lookup_identity, generate_identity,
                         register_identity, rotate_identity, revoke_identity,
                         protect_local_identity)
from crypto.encrypt import encrypt_document, canonical_json
from crypto.decrypt import decrypt_document
from crypto.normalize_document import normalize_to_pdf
from crypto.sign import build_record, sign_record, serialize_record, verify_record
from crypto.transfer import (build_transfer_record, build_acceptance_record,
                             acceptance_event_id, sign_transfer, new_transfer_id)
from security.runtime_assurance import (person_auth_claims, person_auth_watermark_id)
from watermark.pdf_utils import pdf_to_grayscale_images, images_to_pdf
if config.WATERMARK_TRANSFORM == "dwt-dct":
    from watermark.dwt_dct_watermark import embed_bits
else:
    from watermark.dct_watermark import embed_bits
from watermark.payload import generate_watermark_id, bytes_to_bits, pack_for_embedding, RS_AVAILABLE
from agent.quorum_client import submit_to_quorum, lookup_identity_remote, check_watermark

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
    sender_private = load_identity(args.sender)
    package = encrypt_document(pdf_bytes, recipients, sender_id=args.sender,
                               sender_identity=sender_private)

    _atomic_json_write(args.out, package)
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
    try:
        version = register_identity(public)
    except PermissionError as exc:
        print(f"Identity key is staged locally but not enrolled: {exc}")
        return
    print(f"Enrolled {args.as_recipient} key version {version}; private key is passphrase-encrypted locally.")


def cmd_rotate(args):
    passphrase = _confirmed_passphrase("New identity passphrase: ")
    try:
        public = rotate_identity(args.as_recipient, passphrase=passphrase)
    except PermissionError as exc:
        print(f"Rotation key is staged locally but not activated: {exc}")
        return
    print(f"Rotated {args.as_recipient} to key version {public['key_version']}.")


def cmd_revoke(args):
    try:
        revoke_identity(args.as_recipient)
    except PermissionError as exc:
        print(f"Identity was not revoked: {exc}")
        return
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
    auth_token = os.environ.get("SIGILCHAIN_OIDC_ID_TOKEN")
    person_auth = None
    if os.environ.get("SIGILCHAIN_REQUIRE_PERSON_AUTH", "0").strip().lower() in {"1", "true", "yes", "on"}:
        if not auth_token:
            raise ValueError("Person authentication is required; set SIGILCHAIN_OIDC_ID_TOKEN to a fresh OIDC ID token.")
        person_auth = person_auth_claims(auth_token, args.as_recipient)
        person_auth["session_id"] = person_auth_watermark_id(person_auth["issuer"], person_auth["jti"])
    sender_identity = None
    if package.get("package_version") == 2:
        sender = package.get("sender") or {}
        if not sender.get("recipient_id"):
            raise ValueError("Signed package is missing its sender identity")
        sender_identity = lookup_identity(sender["recipient_id"],
                                          key_version=sender.get("key_version", 1),
                                          allow_revoked=True)
    _status("[1/5] DECRYPT", f"Opening the package for '{args.as_recipient}' with their local private key.")
    pdf_bytes = decrypt_document(package, args.as_recipient, recipient_private, sender_identity)
    _status("OK", f"Document decrypted ({len(pdf_bytes)} bytes).", "32")

    parent_transfer_id = (package.get("lineage") or {}).get("parent_transfer_event_id")
    acceptance_id = None
    nodes = args.nodes.split(",") if args.nodes else DEFAULT_NODES
    if parent_transfer_id:
        _status("[2/5] ACCEPT", "Checking the incoming offer and signing acceptance for this exact package.")
        parent_record = _require_committed_parent_transfer(
            nodes, parent_transfer_id, holder_id=args.as_recipient, document_id=args.doc_id,
            package_id=package.get("package_id"),
            package_sha256=hashlib.sha256(canonical_json(package)).hexdigest(),
            document_sha256=hashlib.sha256(pdf_bytes).hexdigest(),
        )
        acceptance_id = _ensure_committed_acceptance(
            nodes, parent_record, recipient_private, document_id=args.doc_id,
            package=package, document_bytes=pdf_bytes,
        )
        _status("OK", f"Recipient acceptance committed: {acceptance_id}", "32")

    _status("[3/5] WATERMARK", "Converting PDF pages to images so each page can carry this session's hidden mark.")
    pages = pdf_to_grayscale_images(pdf_bytes)
    print(f"  {len(pages)} page(s) to mark")

    watermark_id = (bytes.fromhex(person_auth["session_id"]) if person_auth
                    else generate_watermark_id())
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

    _status("[4/5] SIGN", "Binding the document, recipient, watermark, and transfer references into the session claim.")
    record_bytes = build_record(
        doc_id=args.doc_id,
        recipient_id=args.as_recipient,
        watermark_id=watermark_id.hex(),
        marked_pdf_bytes=marked_pdf_bytes,
        key_version=recipient_private.get("key_version", 1),
        package_id=package.get("package_id"),
        transfer_event_id=(package.get("lineage") or {}).get("parent_transfer_event_id"),
        handoff_acceptance_event_id=acceptance_id,
        person_auth=person_auth,
    )
    signature = sign_record(record_bytes, recipient_private["sig_alg"],
                             bytes.fromhex(recipient_private["sig_secret"]))

    _status("[5/5] RECORD", f"Submitting the signed session claim; {config.QUORUM_REQUIRED} validator receipts are required.")
    result = submit_to_quorum(nodes, watermark_id.hex(), record_bytes, signature,
                               args.as_recipient, required=config.QUORUM_REQUIRED,
                               auth_token=auth_token if person_auth else None)

    print(f"\n{_paint('COMMITTED' if result['committed'] else 'NOT COMMITTED', '32' if result['committed'] else '31')}: {result['committed']}")
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
        _status("RELEASED", f"Marked PDF written after quorum commit: {out_path}", "32")
        _status("SESSION ID", watermark_id.hex(), "35")
        print("Keep this ID (or the marked PDF, which carries it invisibly) "
              "-- the trace console looks up exactly this.")
    else:
        print("\nWARNING: record was not committed by enough nodes. "
              "The marked PDF was not released. Check that enough validator nodes are running.")


def _atomic_json_write(path: str, value: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", delete=False,
                                         dir=parent, prefix=".sigilchain-transfer-", suffix=".tmp") as f:
            temp_path = f.name
            json.dump(value, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


def _require_committed_parent_transfer(nodes: list[str], event_id: str, *, holder_id: str,
                                       document_id: str, package_id: str,
                                       package_sha256: str, document_sha256: str) -> dict:
    """Reject a new hop unless its incoming package matches a verified prior quorum event."""
    views = check_watermark(nodes, event_id)
    groups = {}
    for view in views:
        if not (view.get("found") and view.get("chain_valid") and view.get("validator_trusted")
                and view.get("validator_id")):
            continue
        record = view.get("record") or {}
        if record.get("event_type") != "document_transfer" or record.get("event_id") != event_id:
            continue
        try:
            record_bytes = serialize_record(record)
            signature = bytes.fromhex(view["signature_hex"])
            signer = lookup_identity(record["from_id"], key_version=record["from_key_version"],
                                     allow_revoked=True)
            if not verify_record(record_bytes, signature, signer["sig_alg"],
                                 bytes.fromhex(signer["sig_public"])):
                continue
        except (KeyError, TypeError, ValueError):
            continue
        key = (record_bytes.hex(), view["signature_hex"])
        groups.setdefault(key, {"record": record, "validators": set()})["validators"].add(view["validator_id"])
    for group in groups.values():
        record = group["record"]
        if len(group["validators"]) < config.QUORUM_REQUIRED:
            continue
        matches_package = (
            record.get("to_id") == holder_id
            and record.get("doc_id") == document_id
            and record.get("target_package_id") == package_id
            and record.get("target_package_sha256") == package_sha256
            and record.get("target_document_sha256") == document_sha256
        )
        if matches_package:
            return record
    raise ValueError("Incoming package does not match a sender-signed transfer event committed by a trusted validator quorum.")


def _ensure_committed_acceptance(nodes: list[str], transfer_record: dict, recipient_private: dict,
                                 *, document_id: str, package: dict,
                                 document_bytes: bytes) -> str:
    """Commit or reuse a recipient-signed acceptance for this exact package."""
    package_hash = hashlib.sha256(canonical_json(package)).hexdigest()
    transfer_id = transfer_record["event_id"]
    recipient_id = recipient_private["recipient_id"]
    event_id = acceptance_event_id(transfer_id, recipient_id, package["package_id"], package_hash)

    views = check_watermark(nodes, event_id)
    groups = {}
    found_any = False
    for view in views:
        found_any = found_any or bool(view.get("found"))
        if not (view.get("found") and view.get("chain_valid") and view.get("validator_trusted")
                and view.get("validator_id")):
            continue
        record = view.get("record") or {}
        try:
            identity = lookup_identity(record["recipient_id"],
                                       key_version=record["key_version"], allow_revoked=True)
            record_bytes = serialize_record(record)
            signature = bytes.fromhex(view["signature_hex"])
            if (record.get("event_type") != "handoff_acceptance"
                    or record.get("event_id") != event_id
                    or not verify_record(record_bytes, signature, identity["sig_alg"],
                                         bytes.fromhex(identity["sig_public"]))):
                continue
        except (KeyError, TypeError, ValueError):
            continue
        key = (record_bytes.hex(), view["signature_hex"])
        groups.setdefault(key, {"record": record, "validators": set()})["validators"].add(view["validator_id"])

    expected = {
        "transfer_event_id": transfer_id,
        "doc_id": document_id,
        "recipient_id": recipient_id,
        "package_id": package["package_id"],
        "package_sha256": package_hash,
        "document_sha256": hashlib.sha256(document_bytes).hexdigest(),
    }
    for group in groups.values():
        record = group["record"]
        if len(group["validators"]) >= config.QUORUM_REQUIRED:
            if all(record.get(key) == value for key, value in expected.items()):
                return event_id
            raise ValueError("A different acceptance record occupies this package's acceptance ID.")
    if found_any:
        raise ValueError("An acceptance record exists but could not be verified by a trusted validator quorum.")

    record_bytes = build_acceptance_record(
        acceptance_id=event_id, transfer_id=transfer_id, document_id=document_id,
        recipient=recipient_private, package_id=package["package_id"],
        package_sha256=package_hash,
        document_sha256=hashlib.sha256(document_bytes).hexdigest(),
    )
    signature = sign_transfer(record_bytes, recipient_private)
    result = submit_to_quorum(nodes, event_id, record_bytes, signature, recipient_id,
                              required=config.QUORUM_REQUIRED)
    if not result["committed"]:
        raise RuntimeError("Recipient acceptance did not reach the configured validator quorum.")
    return event_id


def _commit_marked_holder_copy(*, nodes: list[str], document_id: str, recipient_id: str,
                               recipient_private: dict, package: dict, document_bytes: bytes,
                               acceptance_id: str, out_dir: str) -> str:
    """Give an onward-forwarding holder their own marked, quorum-recorded PDF."""
    print(f"Creating a recipient-specific marked copy for {recipient_id}...")
    pages = pdf_to_grayscale_images(document_bytes)
    watermark_id = generate_watermark_id()
    bits = bytes_to_bits(pack_for_embedding(watermark_id))
    marked_pages = []
    for index, page in enumerate(pages):
        marked = embed_bits(page.astype(float), bits, delta=EMBED_DELTA, repeat=EMBED_REPEAT)
        marked_pages.append(marked.clip(0, 255).astype("uint8"))
        print(f"  holder page {index + 1}/{len(pages)} marked")
    marked_pdf = images_to_pdf(marked_pages)
    record_bytes = build_record(
        doc_id=document_id, recipient_id=recipient_id, watermark_id=watermark_id.hex(),
        marked_pdf_bytes=marked_pdf, key_version=recipient_private.get("key_version", 1),
        package_id=package.get("package_id"),
        transfer_event_id=(package.get("lineage") or {}).get("parent_transfer_event_id"),
        handoff_acceptance_event_id=acceptance_id,
    )
    signature = sign_record(record_bytes, recipient_private["sig_alg"],
                            bytes.fromhex(recipient_private["sig_secret"]))
    result = submit_to_quorum(nodes, watermark_id.hex(), record_bytes, signature,
                              recipient_id, required=config.QUORUM_REQUIRED)
    if not result["committed"]:
        raise RuntimeError("Holder's marked session did not reach validator quorum; no marked PDF was released.")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"{document_id}_{recipient_id}_{watermark_id.hex()[:12]}.pdf")
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", delete=False, dir=out_dir,
                                         prefix=".sigilchain-holder-") as output:
            temp_path = output.name
            output.write(marked_pdf)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp_path, out_path)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)
    print(f"Holder session committed: {watermark_id.hex()}")
    print(f"Wrote this recipient's marked copy to {out_path}")
    return watermark_id.hex()


def cmd_transfer(args):
    """Re-encrypt for the next holder and commit signed handoff before release."""
    sender_private = load_identity(args.from_id)
    recipient = lookup_identity(args.to_id)
    source_package = None
    source_package_id = None
    source_package_hash = None
    parent_transfer_id = None
    parent_acceptance_id = None
    nodes = args.nodes.split(",") if args.nodes else DEFAULT_NODES

    if args.package:
        with open(args.package, encoding="utf-8") as f:
            source_package = json.load(f)
        source_package_id = source_package.get("package_id")
        source_package_hash = hashlib.sha256(canonical_json(source_package)).hexdigest()
        sender_meta = source_package.get("sender") or {}
        sender_registry = None
        if source_package.get("package_version") == 2:
            sender_registry = lookup_identity(sender_meta.get("recipient_id", ""),
                                              key_version=sender_meta.get("key_version", 1),
                                              allow_revoked=True)
        holder_version = (source_package.get("recipients", {}).get(args.from_id, {})
                          .get("key_version") if source_package.get("package_version") == 2 else None)
        holder_private = (load_identity(args.from_id, key_version=holder_version)
                          if holder_version is not None else sender_private)
        document_bytes = decrypt_document(source_package, args.from_id, holder_private, sender_registry)
        parent_transfer_id = (source_package.get("lineage") or {}).get("parent_transfer_event_id")
        if parent_transfer_id:
            parent_record = _require_committed_parent_transfer(
                nodes, parent_transfer_id, holder_id=args.from_id, document_id=args.doc_id,
                package_id=source_package_id, package_sha256=source_package_hash,
                document_sha256=hashlib.sha256(document_bytes).hexdigest(),
            )
            parent_acceptance_id = _ensure_committed_acceptance(
                nodes, parent_record, sender_private, document_id=args.doc_id,
                package=source_package, document_bytes=document_bytes,
            )
            session_dir = (args.session_out_dir or
                           os.path.join(os.path.dirname(os.path.abspath(args.out)), "decrypted"))
            _commit_marked_holder_copy(
                nodes=nodes, document_id=args.doc_id, recipient_id=args.from_id,
                recipient_private=sender_private, package=source_package,
                document_bytes=document_bytes, acceptance_id=parent_acceptance_id,
                out_dir=session_dir,
            )
    else:
        document_bytes = normalize_to_pdf(args.input_file)

    transfer_id = new_transfer_id()
    target_package = encrypt_document(
        document_bytes, {args.to_id: recipient}, sender_id=args.from_id,
        sender_identity=sender_private, parent_transfer_event_id=transfer_id,
        parent_acceptance_event_id=parent_acceptance_id,
    )
    record_bytes = build_transfer_record(
        transfer_id=transfer_id, document_id=args.doc_id,
        sender=sender_private, recipient=recipient,
        source_package_id=source_package_id,
        source_package_sha256=source_package_hash,
        source_document_sha256=hashlib.sha256(document_bytes).hexdigest(),
        target_package=target_package,
        parent_transfer_event_id=parent_transfer_id,
        parent_acceptance_event_id=parent_acceptance_id,
    )
    signature = sign_transfer(record_bytes, sender_private)
    _status("[TRANSFER]", f"Recording signed offer {args.from_id} -> {args.to_id}; package release waits for quorum.")
    result = submit_to_quorum(nodes, transfer_id, record_bytes, signature,
                              args.from_id, required=config.QUORUM_REQUIRED)
    print(f"{_paint('COMMITTED' if result['committed'] else 'NOT COMMITTED', '32' if result['committed'] else '31')}: {result['committed']}")
    print(f"Accepted by: {[entry['url'] for entry in result['accepted_by']]}")
    if not result["committed"]:
        raise RuntimeError("Handoff did not reach the configured validator quorum; target package was not released.")
    _atomic_json_write(args.out, target_package)
    _status("RELEASED", f"Recipient package written after quorum commit: {args.out}", "32")
    print(f"Transfer event ID: {transfer_id}")
    if parent_acceptance_id:
        print(f"Incoming package acceptance: {parent_acceptance_id}")
    _status("WHAT THIS MEANS", "The receiver's acceptance is recorded when they decrypt or forward the package.", "36")
    _status("LIMIT", "Key signatures do not prove human identity, physical delivery, or who leaked the file.", "33")


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
    p_enc.add_argument("--sender", required=True,
                        help="Enrolled local identity that signs the package manifest")
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

    p_transfer = sub.add_parser(
        "transfer", help="Create a signed, quorum-committed handoff package for the next recipient"
    )
    transfer_source = p_transfer.add_mutually_exclusive_group(required=True)
    transfer_source.add_argument("--input", dest="input_file",
                                 help="Initial source document; the sender creates the first recipient package")
    transfer_source.add_argument("--package", help="Existing package; current holder decrypts and re-encrypts it")
    p_transfer.add_argument("--from", dest="from_id", required=True, help="Current holder's enrolled identity")
    p_transfer.add_argument("--to", dest="to_id", required=True, help="Next recipient's enrolled identity")
    p_transfer.add_argument("--doc-id", required=True, help="Stable document identifier used in the transfer trail")
    p_transfer.add_argument("--out", default="transfer-package.json", help="Path for the next recipient's package")
    p_transfer.add_argument("--session-out-dir", default=None,
                            help="Directory for this holder's marked copy (default: decrypted beside --out)")
    p_transfer.add_argument("--nodes", default=None,
                            help="Comma-separated validator node URLs (default: localhost:8001-8003)")
    p_transfer.set_defaults(func=cmd_transfer)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
