"""Create and verify 2-of-3 (or configured threshold) governance approvals.

Example offline workflow:
  python scripts/governance_cli.py keygen --id admin-a --out governance/admin-a.key.json
  python scripts/governance_cli.py roster --keys governance/admin-a.pub.json governance/admin-b.pub.json governance/admin-c.pub.json --threshold 2 --out governance/roster.json
  python scripts/governance_cli.py approve --action change.json --key governance/admin-a.key.json --out approval-a.json
  python scripts/governance_cli.py merge --action change.json --approvals approval-a.json approval-b.json --out approvals.json
  python scripts/governance_cli.py verify --action change.json --approvals approvals.json --roster governance/roster.json

The private signing keys should be stored on separate machines/accounts. This
tool prepares and verifies approvals; application of an approved change must
also be committed and enforced by the validator quorum before it can be
described as administrator change control.
"""

import argparse
import getpass
import hashlib
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import oqs
import config
from agent.quorum_client import submit_governance_change
from validator import ledger
from crypto.keys import (_apply_rotation_record, _protect_private_record,
                         _write_private_record, register_identity,
                         revoke_identity)
from crypto.governance import (GOVERNANCE_SIG_ALG, action_id, make_action, make_approval_bundle,
                               sign_action, validate_roster, verify_approval_bundle,
                               write_json_atomic)


def _read_json(path: str) -> dict:
    with open(path, encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _write_json(path: str, value: dict) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         delete=False, dir=parent,
                                         prefix=".sigilchain-governance-") as stream:
            temp_path = stream.name
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)


def _read_signing_key(path: str) -> tuple[str, bytes]:
    stored = _read_json(path)
    if stored.get("format") != "sigilchain-encrypted-private-key-v1":
        raise ValueError("Governance private key is not passphrase protected")
    signer_id = stored.get("recipient_id")
    passphrase = getpass.getpass(f"Passphrase for governance key {signer_id}: ")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from crypto.governance import canonical_json

    try:
        key = Scrypt(salt=bytes.fromhex(stored["salt"]), length=32,
                     n=2**14, r=8, p=1).derive(passphrase.encode("utf-8"))
        aad = f"sigilchain-private-key-v1:{signer_id}".encode("utf-8")
        private = json.loads(AESGCM(key).decrypt(
            bytes.fromhex(stored["nonce"]), bytes.fromhex(stored["encrypted_private"]), aad
        ).decode("utf-8"))
    except Exception as exc:
        raise ValueError("Could not unlock governance key; check its passphrase and file.") from exc
    secret_key = bytes.fromhex(private["sig_secret"])
    return signer_id, secret_key


def cmd_keygen(args) -> None:
    if os.path.exists(args.out):
        raise FileExistsError(f"Refusing to replace existing key file: {args.out}")
    first = getpass.getpass("New governance key passphrase (12+ characters): ")
    second = getpass.getpass("Repeat passphrase: ")
    if len(first) < 12 or first != second:
        raise ValueError("Passphrases must match and contain at least 12 characters")
    with oqs.Signature(GOVERNANCE_SIG_ALG) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    record = {"recipient_id": args.id, "key_version": 1,
              "sig_alg": GOVERNANCE_SIG_ALG, "sig_public": public_key.hex(),
              "sig_secret": secret_key.hex()}
    _write_private_record(args.out, _protect_private_record(record, first))
    public_path = args.out[:-9] + ".pub.json" if args.out.endswith(".key.json") else args.out + ".pub.json"
    _write_json(public_path, {"id": args.id, "sig_alg": GOVERNANCE_SIG_ALG,
                              "public_key": public_key.hex()})
    print(f"Created protected private governance key: {args.out}")
    print(f"Public key for the governance roster: {public_path}")


def cmd_roster(args) -> None:
    members = [_read_json(path) for path in args.keys]
    roster = {"schema": "sigilchain-governance-roster-v1",
              "sig_alg": GOVERNANCE_SIG_ALG, "threshold": args.threshold,
              "members": sorted(members, key=lambda item: item.get("id", ""))}
    validate_roster(roster)
    _write_json(args.out, roster)
    print(f"Wrote {args.threshold}-of-{len(members)} governance roster to {args.out}")


def cmd_install_roster(args) -> None:
    """Install the immutable governance trust anchor in the shared trust volume."""
    roster = _read_json(args.roster)
    validate_roster(roster)
    if os.path.exists(args.target):
        existing = _read_json(args.target)
        if existing == roster:
            print(f"Governance roster already installed at {args.target}")
            return
        raise FileExistsError(f"Refusing to replace existing governance roster: {args.target}")
    _write_json(args.target, roster)
    with open(args.target, "rb") as stream:
        fingerprint = hashlib.sha256(stream.read()).hexdigest()
    print(f"Installed governance roster at {args.target}")
    print(f"Set SIGILCHAIN_GOVERNANCE_ROSTER_SHA256 to this exact file hash: {fingerprint}")


def cmd_approve(args) -> None:
    action = _read_json(args.action)
    signer_id, secret_key = _read_signing_key(args.key)
    approval = sign_action(action, signer_id, secret_key)
    bundle = make_approval_bundle(action, [approval])
    _write_json(args.out, bundle)
    print(f"Signed action {action_id(action)} as {signer_id}; approval written to {args.out}")


def cmd_merge(args) -> None:
    action = _read_json(args.action)
    action_digest = action_id(action)
    approvals = []
    seen = set()
    for path in args.approvals:
        bundle = _read_json(path)
        if bundle.get("action_id") != action_digest:
            raise ValueError(f"Approval {path} is for a different action")
        for approval in bundle.get("approvals", []):
            signer_id = approval.get("signer_id")
            if signer_id in seen:
                raise ValueError(f"Duplicate approval from {signer_id!r}")
            seen.add(signer_id)
            approvals.append(approval)
    _write_json(args.out, make_approval_bundle(action, approvals))
    print(f"Combined {len(approvals)} distinct approvals for action {action_digest}")


def cmd_verify(args) -> None:
    action = _read_json(args.action)
    bundle = _read_json(args.approvals)
    roster = _read_json(args.roster)
    result = verify_approval_bundle(action, bundle, roster)
    print(f"Valid {len(result['valid_signers'])}-of-{result['threshold']} approval: {result['action_id']}")
    print("Approvers: " + ", ".join(result["valid_signers"]))


def cmd_snapshot(args) -> None:
    """Capture the current working copies as an explicitly approved baseline."""
    from crypto.keys import init_registry
    init_registry(args.registry)
    ledger.init_db(args.ledger)
    conn = __import__("sqlite3").connect(args.registry)
    identity_rows = conn.execute(
        "SELECT recipient_id,kem_alg,sig_alg,kem_public,sig_public,key_version,revoked_at "
        "FROM identities ORDER BY recipient_id"
    ).fetchall()
    history_rows = conn.execute(
        "SELECT recipient_id,key_version,kem_alg,sig_alg,kem_public,sig_public,created_at,revoked_at "
        "FROM identity_history ORDER BY recipient_id,key_version"
    ).fetchall()
    conn.close()
    identities = [dict(zip(("recipient_id", "kem_alg", "sig_alg", "kem_public", "sig_public", "key_version", "revoked_at"), row))
                  for row in identity_rows]
    history = [dict(zip(("recipient_id", "key_version", "kem_alg", "sig_alg", "kem_public", "sig_public", "created_at", "revoked_at"), row))
               for row in history_rows]
    trust = _read_json(args.trust)
    action = make_action("identity.snapshot", {
        "base_head": ledger.chain_head(args.ledger),
        "snapshot": {"schema": "sigilchain-state-snapshot-v1",
                     "identities": identities, "history": history,
                     "validator_trust_roster": trust},
    })
    _write_json(args.out, action)
    print(f"Captured {len(identities)} identities and {len(trust)} validator keys at the current ledger head.")
    print(f"Snapshot proposal: {args.out}\nAction ID: {action_id(action)}")


def cmd_apply(args) -> None:
    action = _read_json(args.action)
    bundle = _read_json(args.approvals)
    roster = _read_json(args.roster)
    result = verify_approval_bundle(action, bundle, roster)
    os.environ["SIGILCHAIN_REQUIRE_GOVERNANCE_APPROVALS"] = "1"
    os.environ["SIGILCHAIN_GOVERNANCE_ROSTER"] = os.path.abspath(args.roster)
    os.environ["SIGILCHAIN_VALIDATOR_TRUST_FILE"] = os.path.abspath(args.trust)
    details = action["details"]
    ledger.init_db(args.ledger)
    existing_entries = ledger.list_entries(args.ledger)
    has_snapshot = any(
        json.loads(entry["record_json"]).get("event_type") == "governance_change"
        and json.loads(entry["record_json"]).get("action", {}).get("action") == "identity.snapshot"
        for entry in existing_entries
    )
    if action["action"] != "identity.snapshot" and not has_snapshot:
        raise RuntimeError("Create and commit an approved baseline first: governance_cli.py snapshot --out governance/state-snapshot.json")
    commit = submit_governance_change(
        args.nodes.split(",") if args.nodes else config.NODE_URLS,
        action, bundle, required=args.quorum,
    )
    if not commit["committed"]:
        raise RuntimeError(
            "Governance event did not reach the configured validator quorum; state was not applied. "
            f"Accepted={len(commit['accepted_by'])}, rejected={commit['rejected_by']}, "
            f"unreachable={commit['unreachable']}"
        )
    print(f"Governance change committed by validator quorum: {action_id(action)}")
    os.environ["SIGILCHAIN_GOVERNANCE_APPLY_CONTEXT"] = action_id(action)
    if action["action"] == "identity.enroll":
        register_identity(details["identity"], db_path=args.registry, approval_bundle=bundle)
        summary = f"enrolled {details['identity']['recipient_id']}"
    elif action["action"] == "identity.rotate":
        _apply_rotation_record(details["identity"], db_path=args.registry,
                               approval_bundle=bundle)
        summary = f"rotated {details['identity']['recipient_id']}"
    elif action["action"] == "identity.revoke":
        revoke_identity(details["recipient_id"], db_path=args.registry,
                        approval_bundle=bundle)
        summary = f"revoked {details['recipient_id']}"
    elif action["action"] == "identity.snapshot":
        summary = "committed the approved state baseline"
    elif action["action"] == "validator.trust_roster":
        target = details["path"]
        current = {}
        try:
            current = _read_json(target)
        except FileNotFoundError:
            pass
        current_digest = (hashlib.sha256(json.dumps(
            current, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest() if current else None)
        new_roster = details["validators"]
        new_digest = hashlib.sha256(json.dumps(
            new_roster, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")).hexdigest()
        if current_digest == new_digest:
            summary = f"validator trust roster at {target} was already applied"
        elif current_digest != details.get("previous_roster_sha256"):
            raise RuntimeError("Validator trust roster changed since this proposal was approved; create a new proposal.")
        else:
            write_json_atomic(target, new_roster)
            summary = f"updated validator trust roster at {target}"
    else:
        raise ValueError(f"This build cannot apply governance action {action['action']!r}")
    from validator import governance_state
    refreshed_entries = ledger.list_entries(args.ledger)
    replay = governance_state.rebuild(refreshed_entries, roster, args.registry,
                                      os.environ.get("SIGILCHAIN_VALIDATOR_TRUST_FILE", "validator_trust.json"))
    print(f"Applied {summary} after {len(result['valid_signers'])}-of-{result['threshold']} approval verification.")
    print(f"Reconciled working state from the committed ledger: {replay}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="Create a passphrase-protected ML-DSA-65 governance key")
    keygen.add_argument("--id", required=True)
    keygen.add_argument("--out", required=True)
    keygen.set_defaults(func=cmd_keygen)
    roster = sub.add_parser("roster", help="Build a threshold roster from public governance keys")
    roster.add_argument("--keys", nargs="+", required=True)
    roster.add_argument("--threshold", type=int, default=2)
    roster.add_argument("--out", required=True)
    roster.set_defaults(func=cmd_roster)
    install = sub.add_parser("install-roster", help="Install the initial governance roster in the shared trust volume")
    install.add_argument("--roster", required=True)
    install.add_argument("--target", default=os.environ.get(
        "SIGILCHAIN_GOVERNANCE_ROSTER", "/app/data/trust/governance_roster.json"))
    install.set_defaults(func=cmd_install_roster)
    approve = sub.add_parser("approve", help="Sign one exact JSON action with a governance key")
    approve.add_argument("--action", required=True)
    approve.add_argument("--key", required=True)
    approve.add_argument("--out", required=True)
    approve.set_defaults(func=cmd_approve)
    merge = sub.add_parser("merge", help="Combine distinct signatures for the same action")
    merge.add_argument("--action", required=True)
    merge.add_argument("--approvals", nargs="+", required=True)
    merge.add_argument("--out", required=True)
    merge.set_defaults(func=cmd_merge)
    verify = sub.add_parser("verify", help="Verify an approval threshold against the pinned roster")
    verify.add_argument("--action", required=True)
    verify.add_argument("--approvals", required=True)
    verify.add_argument("--roster", required=True)
    verify.set_defaults(func=cmd_verify)
    apply = sub.add_parser("apply", help="Apply an approved identity registry change")
    apply.add_argument("--action", required=True)
    apply.add_argument("--approvals", required=True)
    apply.add_argument("--roster", required=True)
    apply.add_argument("--registry", default=os.environ.get("SIGILCHAIN_IDENTITY_DB", "identity_registry.db"))
    apply.add_argument("--trust", default=os.environ.get("SIGILCHAIN_VALIDATOR_TRUST_FILE", "validator_trust.json"))
    apply.add_argument("--ledger", default=os.environ.get("SIGILCHAIN_LEDGER_DB", "node_ledger.db"))
    apply.add_argument("--nodes", default=None, help="Comma-separated validator URLs")
    apply.add_argument("--quorum", type=int, default=config.QUORUM_REQUIRED)
    apply.set_defaults(func=cmd_apply)
    snapshot = sub.add_parser("snapshot", help="Create the threshold-approved baseline needed for state replay")
    snapshot.add_argument("--registry", default=os.environ.get("SIGILCHAIN_IDENTITY_DB", "identity_registry.db"))
    snapshot.add_argument("--trust", default=os.environ.get("SIGILCHAIN_VALIDATOR_TRUST_FILE", "validator_trust.json"))
    snapshot.add_argument("--ledger", default=os.environ.get("SIGILCHAIN_LEDGER_DB", "node_ledger.db"))
    snapshot.add_argument("--out", required=True)
    snapshot.set_defaults(func=cmd_snapshot)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
