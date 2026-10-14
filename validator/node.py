"""
SigilChain — Part 5b: Validator Node (FastAPI).

Each API node independently validates recipient-signed events and signs
receipts. In Compose mode the nodes read/write one etcd/Raft ordered log;
each API acknowledges only after the shared log committed the event. The
agent separately requires distinct validator receipts before releasing a
marked PDF. Without SIGILCHAIN_ETCD_ENDPOINTS, local SQLite remains a
single-process development fallback, not shared consensus.

Run one instance per node, each with its own port and DB file:

    set SIGILCHAIN_LEDGER_DB=node1.db
    uvicorn validator.node:app --port 8001

    set SIGILCHAIN_LEDGER_DB=node2.db
    uvicorn validator.node:app --port 8002

    set SIGILCHAIN_LEDGER_DB=node3.db
    uvicorn validator.node:app --port 8003

(On macOS/Linux use `export` instead of `set`.) For the recommended
multi-node consensus mode, start the Compose cluster instead of launching
standalone local-SQLite nodes.
"""

import hashlib
import json
import os
import re
import sys
import time

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

from crypto.keys import init_registry, lookup_identity
from crypto.sign import verify_record
from crypto.transfer import acceptance_event_id
from crypto.governance import (canonical_json as canonical_governance_json,
                               governance_required, verify_governance_event)
from validator import ledger, consensus
from validator import governance_state
from validator.attestation import load_or_create_key, make_receipt, public_key_hex, sign_attestation
from security.runtime_assurance import (validate_assurance_configuration,
                                        verify_person_auth, verify_tpm_host_attestation)
import config

DB_PATH = config.LEDGER_DB
ledger.init_db(DB_PATH)
VALIDATOR_KEY = load_or_create_key(config.VALIDATOR_KEY_PATH)
VALIDATOR_PUBLIC_KEY = public_key_hex(VALIDATOR_KEY)
print(f"Validator {config.VALIDATOR_ID} signing-key fingerprint: "
      f"{hashlib.sha256(bytes.fromhex(VALIDATOR_PUBLIC_KEY)).hexdigest()}")

if not config.API_KEY:
    print(
        "\n*** WARNING: SIGILCHAIN_API_KEY is not set -- this node is answering every "
        "request from anyone who can reach it, with no credential check at all. "
        "Fine for local development; set SIGILCHAIN_API_KEY before this touches any "
        "network you don't fully trust. ***\n",
        file=sys.stderr,
    )

_api_key_header = APIKeyHeader(name=config.API_KEY_HEADER, auto_error=False)


def require_api_key(provided: str | None = Security(_api_key_header)) -> None:
    """Applied to every route below via the app-level `dependencies=` list,
    so nothing can be accidentally left unprotected by forgetting to
    decorate a new endpoint individually. A no-op when API_KEY isn't
    configured (see the startup warning above)."""
    if not config.API_KEY:
        return
    if provided != config.API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid API key")


app = FastAPI(title="SigilChain Validator Node", dependencies=[Depends(require_api_key)])
GOVERNANCE_STATE_READY = not governance_required()


@app.on_event("startup")
def restore_governed_state() -> None:
    """Fail closed on invalid governance history and restore committed state."""
    global GOVERNANCE_STATE_READY
    validate_assurance_configuration()
    init_registry(config.IDENTITY_REGISTRY_DB)
    entries = ledger.list_entries(DB_PATH)
    intact, detail = ledger.verify_chain_integrity(DB_PATH)
    if not intact:
        raise RuntimeError(f"Refusing to serve: committed ledger integrity failed: {detail}")
    try:
        verify_tpm_host_attestation(
            config.VALIDATOR_ID,
            hashlib.sha256(f"startup:{config.VALIDATOR_ID}:{int(time.time())}".encode()).hexdigest(),
        )
    except (PermissionError, ValueError) as exc:
        raise RuntimeError(f"Refusing to serve: TPM host attestation failed: {exc}") from exc
    try:
        governed = any(json.loads(entry["record_json"]).get("event_type") == "governance_change"
                       for entry in entries)
    except (KeyError, TypeError, ValueError) as exc:
        raise RuntimeError("Refusing to serve: a ledger entry is not valid JSON") from exc
    if not governed:
        return
    if not governance_required():
        raise RuntimeError(
            "Refusing to serve: committed governance history exists but governance enforcement is disabled"
        )
    roster = config.governance_roster()
    if not roster:
        raise RuntimeError("Refusing to serve: governance events exist but the pinned governance roster is unavailable")
    try:
        summary = governance_state.rebuild(entries, roster, config.IDENTITY_REGISTRY_DB,
                                           config.VALIDATOR_TRUST_FILE)
    except (ValueError, PermissionError, TypeError) as exc:
        # A signed baseline is an explicit one-time operation. Keep the node
        # available so authorized administrators can submit that baseline, but
        # reject ordinary governance changes until it is committed.
        if "no approved identity.snapshot baseline" in str(exc):
            GOVERNANCE_STATE_READY = False
            print("Governance state needs an approved snapshot baseline; ordinary governed changes are paused.")
            return
        raise RuntimeError(f"Refusing to serve: governance state replay failed: {exc}") from exc
    GOVERNANCE_STATE_READY = bool(summary.get("snapshot"))
    print(f"Governance state restored from ledger: {summary}")


def _stored_event_signature_valid(entry: dict, signer_id: str, key_version: int) -> tuple[dict, bool]:
    """Recheck a parent event's canonical bytes and registered historical signer key."""
    try:
        record = json.loads(entry["record_json"])
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        identity = lookup_identity(signer_id, key_version=key_version, allow_revoked=True)
        valid = (
            entry.get("watermark_id") == record.get("event_id")
            and canonical == entry["record_json"].encode("utf-8")
            and verify_record(canonical, bytes.fromhex(entry["signature_hex"]),
                              identity["sig_alg"], bytes.fromhex(identity["sig_public"]))
        )
        return record, valid
    except (KeyError, TypeError, ValueError):
        return {}, False


class SubmitRequest(BaseModel):
    watermark_id: str
    record_hex: str
    signature_hex: str
    recipient_id: str
    auth_token: str | None = None


class SubmitResponse(BaseModel):
    accepted: bool
    entry_hash: str | None = None
    reason: str | None = None
    receipt: dict | None = None
    receipt_signature_hex: str | None = None
    validator_id: str | None = None
    validator_public_key: str | None = None
    validator_sig_alg: str | None = None
    ledger_backend: str = "local-sqlite"
    record: dict | None = None
    signature_hex: str | None = None


def _accepted_response(entry: dict, machine_attestation: dict | None = None,
                       person_auth_verification: dict | None = None) -> SubmitResponse:
    attestation = ledger.get_validator_receipt(DB_PATH, entry["watermark_id"])
    if attestation is None:
        generated = make_receipt(VALIDATOR_KEY, config.VALIDATOR_ID, entry,
                                 machine_attestation=machine_attestation,
                                 person_auth_verification=person_auth_verification)
        attestation = ledger.save_validator_receipt(
            DB_PATH, entry["watermark_id"], config.VALIDATOR_ID,
            generated["receipt"], generated["receipt_signature_hex"],
            generated["validator_public_key"],
        )
    return SubmitResponse(
        accepted=True,
        entry_hash=entry["entry_hash"],
        receipt=attestation["receipt"],
        receipt_signature_hex=attestation["receipt_signature_hex"],
        validator_id=attestation["validator_id"],
        validator_public_key=attestation["validator_public_key"],
        validator_sig_alg=attestation["receipt"].get("validator_sig_alg", "Ed25519"),
        ledger_backend=attestation["receipt"].get("ledger_backend", "local-sqlite"),
        record=json.loads(entry["record_json"]),
        signature_hex=entry["signature_hex"],
    )


def _refresh_governed_state() -> None:
    """Check the log and repair registry/trust-file drift before an API read/write."""
    global GOVERNANCE_STATE_READY
    if not governance_required():
        return
    entries = ledger.list_entries(DB_PATH)
    intact, detail = ledger.verify_chain_integrity(DB_PATH)
    if not intact:
        raise RuntimeError(f"committed ledger integrity failed: {detail}")
    has_governance = False
    for entry in entries:
        try:
            has_governance |= json.loads(entry["record_json"]).get("event_type") == "governance_change"
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("ledger contains malformed event JSON") from exc
    if not has_governance:
        GOVERNANCE_STATE_READY = False
        return
    roster = config.governance_roster()
    if not roster:
        raise RuntimeError("governance roster is unavailable")
    try:
        summary = governance_state.rebuild(entries, roster, config.IDENTITY_REGISTRY_DB,
                                           config.VALIDATOR_TRUST_FILE)
        GOVERNANCE_STATE_READY = bool(summary.get("snapshot"))
    except ValueError as exc:
        if "no approved identity.snapshot baseline" in str(exc):
            GOVERNANCE_STATE_READY = False
            return
        raise


def _require_governed_state() -> None:
    """Fail closed on sensitive reads if the committed baseline is absent or drifted."""
    if not governance_required():
        return
    try:
        _refresh_governed_state()
    except (RuntimeError, ValueError, PermissionError, TypeError) as exc:
        raise HTTPException(status_code=503, detail=f"governed state check failed: {exc}") from exc
    if not GOVERNANCE_STATE_READY:
        raise HTTPException(status_code=503, detail="governance baseline has not been committed")


@app.post("/submit", response_model=SubmitResponse)
def submit(req: SubmitRequest) -> SubmitResponse:
    global GOVERNANCE_STATE_READY
    try:
        record_bytes = bytes.fromhex(req.record_hex)
        signature = bytes.fromhex(req.signature_hex)
        record = json.loads(record_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return SubmitResponse(accepted=False, reason="record or signature is not valid hex-encoded JSON/bytes")
    if not isinstance(record, dict):
        return SubmitResponse(accepted=False, reason="signed record must be a JSON object")

    governance_event = req.recipient_id == "__governance__"
    if governance_event and not governance_required():
        return SubmitResponse(accepted=False, reason="governance events require the governance policy and roster pin to be enabled")
    if governance_required():
        try:
            _refresh_governed_state()
        except (RuntimeError, ValueError, PermissionError, TypeError) as exc:
            raise HTTPException(status_code=503, detail=f"governed state check failed: {exc}") from exc
        if not GOVERNANCE_STATE_READY and not governance_event:
            return SubmitResponse(accepted=False, reason="governance baseline is required before recipient events are accepted")
    identity = None
    if governance_event:
        canonical_record = canonical_governance_json(record)
        if canonical_record != record_bytes:
            return SubmitResponse(accepted=False, reason="governance event is not canonical JSON")
        if signature:
            return SubmitResponse(accepted=False, reason="governance events use embedded threshold signatures")
        try:
            result = verify_governance_event(record, config.governance_roster())
        except (KeyError, ValueError, PermissionError, TypeError) as exc:
            return SubmitResponse(accepted=False, reason=f"governance approvals invalid: {exc}")
        if req.watermark_id != record.get("event_id"):
            return SubmitResponse(accepted=False, reason="governance event ID does not match ledger key")
        action = record["action"]
        details = action["details"]
        action_type = action["action"]
        if not GOVERNANCE_STATE_READY and action_type != "identity.snapshot":
            return SubmitResponse(accepted=False, reason="an approved identity.snapshot baseline is required before governed changes")
        if action_type == "identity.snapshot":
            try:
                governance_state.validate_snapshot(details)
            except ValueError as exc:
                return SubmitResponse(accepted=False, reason=f"governance snapshot is invalid: {exc}")
            already_committed = ledger.find_by_watermark_id(DB_PATH, req.watermark_id)
            if not (already_committed and already_committed["record_json"].encode("utf-8") == record_bytes
                    and already_committed["signature_hex"] == signature.hex()):
                base_head = details.get("base_head")
                current_head = ledger.chain_head(DB_PATH)
                if (not isinstance(base_head, dict)
                        or base_head.get("sequence") != current_head["sequence"]
                        or base_head.get("entry_hash") != current_head["entry_hash"]):
                    return SubmitResponse(accepted=False, reason="snapshot proposal is stale; capture a new baseline from the current log head")
        elif action_type == "identity.enroll":
            proposed = details.get("identity", {})
            try:
                governance_state.validate_identity(proposed)
            except ValueError as exc:
                return SubmitResponse(accepted=False, reason=f"enrollment identity is invalid: {exc}")
            try:
                existing = lookup_identity(proposed.get("recipient_id", ""), allow_revoked=True)
            except KeyError:
                pass
            except PermissionError:
                return SubmitResponse(accepted=False, reason="enrollment identity exists in revoked state; rotate or restore explicitly")
            else:
                if (existing.get("kem_public") != proposed.get("kem_public")
                        or existing.get("sig_public") != proposed.get("sig_public")
                        or existing.get("key_version") != proposed.get("key_version")
                        or existing.get("revoked_at") is not None):
                    return SubmitResponse(accepted=False, reason="enrollment identity is already registered")
            if (proposed.get("key_version") != 1
                    or proposed.get("kem_alg") != "ML-KEM-768"
                    or proposed.get("sig_alg") != "ML-DSA-65"
                    or not proposed.get("kem_public") or not proposed.get("sig_public")):
                return SubmitResponse(accepted=False, reason="enrollment action contains invalid public identity fields")
        elif action_type == "identity.rotate":
            proposed = details.get("identity", {})
            try:
                governance_state.validate_identity(proposed)
            except ValueError as exc:
                return SubmitResponse(accepted=False, reason=f"rotation identity is invalid: {exc}")
            try:
                current = lookup_identity(proposed.get("recipient_id", ""), allow_revoked=True)
            except KeyError:
                return SubmitResponse(accepted=False, reason="rotation identity is not registered")
            already_applied = (
                proposed.get("key_version") == current["key_version"]
                and proposed.get("kem_public") == current["kem_public"]
                and proposed.get("sig_public") == current["sig_public"]
                and current.get("revoked_at") is None
                and details.get("previous_key_version") == current["key_version"] - 1
            )
            if (not already_applied and (details.get("previous_key_version") != current["key_version"]
                    or proposed.get("key_version") != current["key_version"] + 1)
                    or proposed.get("kem_alg") != "ML-KEM-768"
                    or proposed.get("sig_alg") != "ML-DSA-65"):
                return SubmitResponse(accepted=False, reason="rotation proposal is stale or has unsupported algorithms")
        elif action_type == "identity.revoke":
            try:
                current = lookup_identity(details.get("recipient_id", ""), allow_revoked=True)
            except KeyError:
                return SubmitResponse(accepted=False, reason="revoke target is not active")
            if details.get("key_version") != current["key_version"]:
                return SubmitResponse(accepted=False, reason="revoke proposal is stale")
        elif action_type == "validator.trust_roster":
            try:
                with open(config.VALIDATOR_TRUST_FILE, encoding="utf-8") as trust_file:
                    current_roster = json.load(trust_file)
            except (OSError, json.JSONDecodeError):
                current_roster = {}
            current_digest = (hashlib.sha256(json.dumps(
                current_roster, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")).hexdigest() if current_roster else None)
            new_roster = details.get("validators")
            try:
                governance_state.validate_validator_trust_roster(new_roster)
            except ValueError as exc:
                return SubmitResponse(accepted=False, reason=f"validator trust-roster proposal is invalid: {exc}")
            if len(new_roster) < config.QUORUM_REQUIRED:
                return SubmitResponse(accepted=False, reason="proposed validator roster is too small")
            new_digest = (hashlib.sha256(json.dumps(
                new_roster, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")).hexdigest())
            if (details.get("previous_roster_sha256") != current_digest
                    and current_digest != new_digest):
                return SubmitResponse(accepted=False, reason="validator trust-roster proposal is stale")
        else:
            return SubmitResponse(accepted=False, reason=f"unsupported governance action {action_type!r}")
        sig_public = b""
        sig_alg = "governance-threshold"
    else:
        try:
            identity = lookup_identity(req.recipient_id)
        except KeyError:
            return SubmitResponse(accepted=False, reason=f"unknown recipient_id '{req.recipient_id}'")
        except PermissionError:
            return SubmitResponse(accepted=False, reason=f"recipient identity '{req.recipient_id}' is revoked")

    # Handoffs share the ordered event log with decryption-session records.
    # The path/actor/recipient key versions are signed, and validators check
    # the sender is active and the package targets the currently registered
    # recipient key before committing the event.
    if governance_event:
        pass  # Threshold signatures and event structure were checked above.
    elif record.get("event_type") == "document_transfer":
        canonical_record = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if canonical_record != record_bytes:
            return SubmitResponse(accepted=False, reason="transfer record is not canonical JSON")
        if record.get("event_id") != req.watermark_id:
            return SubmitResponse(accepted=False, reason="event_id does not match ledger lookup key")
        if not re.fullmatch(r"[0-9a-f]{32}", req.watermark_id):
            return SubmitResponse(accepted=False, reason="transfer event id must be 32 lowercase hex characters")
        if record.get("from_id") != req.recipient_id:
            return SubmitResponse(accepted=False, reason="from_id does not match authenticated signer")
        if record.get("from_key_version") != identity["key_version"]:
            return SubmitResponse(accepted=False, reason="transfer was not signed by the active sender key version")
        if record.get("from_sig_alg") != identity["sig_alg"]:
            return SubmitResponse(accepted=False, reason="transfer signer algorithm does not match registered identity")
        try:
            target = lookup_identity(record["to_id"])
        except (KeyError, PermissionError):
            return SubmitResponse(accepted=False, reason="transfer target identity is unknown or revoked")
        if (record.get("to_key_version") != target["key_version"]
                or record.get("to_kem_public_sha256") != hashlib.sha256(bytes.fromhex(target["kem_public"])).hexdigest()
                or record.get("to_sig_public_sha256") != hashlib.sha256(bytes.fromhex(target["sig_public"])).hexdigest()):
            return SubmitResponse(accepted=False, reason="transfer target key does not match the active registered identity")
        parent_id = record.get("parent_transfer_event_id")
        if parent_id is not None and not re.fullmatch(r"[0-9a-f]{32}", str(parent_id)):
            return SubmitResponse(accepted=False, reason="parent transfer event id is malformed")
        parent_acceptance_id = record.get("parent_acceptance_event_id")
        if parent_id is None and parent_acceptance_id is not None:
            return SubmitResponse(accepted=False, reason="root transfer cannot reference a prior acceptance")
        if parent_id is not None:
            if not isinstance(parent_acceptance_id, str) or not re.fullmatch(r"[0-9a-f]{32}", parent_acceptance_id):
                return SubmitResponse(accepted=False, reason="forwarded transfer must reference the holder's acceptance event")
            prior_transfer = ledger.get_by_watermark_id(DB_PATH, parent_id)
            acceptance_entry = ledger.get_by_watermark_id(DB_PATH, parent_acceptance_id)
            if prior_transfer is None or acceptance_entry is None:
                return SubmitResponse(accepted=False, reason="parent transfer or holder acceptance is not committed")
            try:
                prior_untrusted_record = json.loads(prior_transfer["record_json"])
                prior_record, prior_signature_ok = _stored_event_signature_valid(
                    prior_transfer, prior_untrusted_record["from_id"],
                    prior_untrusted_record["from_key_version"],
                )
                acceptance_record = json.loads(acceptance_entry["record_json"])
                acceptance_canonical = json.dumps(acceptance_record, sort_keys=True,
                                                  separators=(",", ":")).encode("utf-8")
                acceptance_identity = lookup_identity(
                    acceptance_record["recipient_id"], key_version=acceptance_record["key_version"],
                    allow_revoked=True,
                )
                acceptance_signature_ok = (acceptance_entry.get("watermark_id") == acceptance_record.get("event_id")
                    and acceptance_canonical == acceptance_entry["record_json"].encode("utf-8")
                    and verify_record(
                    acceptance_canonical,
                    bytes.fromhex(acceptance_entry["signature_hex"]),
                    acceptance_identity["sig_alg"], bytes.fromhex(acceptance_identity["sig_public"]),
                ))
            except (KeyError, TypeError, ValueError):
                acceptance_signature_ok = False
                prior_signature_ok = False
                acceptance_record = {}
                prior_record = {}
            if (prior_record.get("event_type") != "document_transfer"
                    or prior_record.get("event_id") != parent_id
                    or acceptance_record.get("event_type") != "handoff_acceptance"
                    or acceptance_record.get("event_id") != parent_acceptance_id
                    or acceptance_record.get("transfer_event_id") != parent_id
                    or acceptance_record.get("recipient_id") != req.recipient_id
                    or acceptance_record.get("doc_id") != record.get("doc_id")
                    or acceptance_record.get("package_id") != record.get("source_package_id")
                    or acceptance_record.get("package_sha256") != record.get("source_package_sha256")
                    or acceptance_record.get("document_sha256") != record.get("source_document_sha256")
                    or acceptance_event_id(
                        parent_id, req.recipient_id, acceptance_record.get("package_id", ""),
                        acceptance_record.get("package_sha256", ""),
                    ) != parent_acceptance_id
                    or prior_record.get("to_id") != req.recipient_id
                    or not prior_signature_ok
                    or not acceptance_signature_ok):
                return SubmitResponse(accepted=False, reason="forwarded transfer does not match a valid holder-signed acceptance")
        if not all(record.get(field) for field in ("doc_id", "target_package_id", "target_package_sha256",
                                                   "source_document_sha256", "target_document_sha256")):
            return SubmitResponse(accepted=False, reason="transfer record is missing required document/package fields")
        if (not re.fullmatch(r"[0-9a-f]{32}", str(record["target_package_id"]))
                or not re.fullmatch(r"[0-9a-f]{64}", str(record["target_package_sha256"]))
                or not re.fullmatch(r"[0-9a-f]{64}", str(record["source_document_sha256"]))
                or not re.fullmatch(r"[0-9a-f]{64}", str(record["target_document_sha256"]))):
            return SubmitResponse(accepted=False, reason="transfer package or document hash is malformed")
        if record["source_document_sha256"] != record["target_document_sha256"]:
            return SubmitResponse(accepted=False, reason="transfer target package changes the document content hash")
        sig_public = bytes.fromhex(identity["sig_public"])
        sig_alg = identity["sig_alg"]
    elif record.get("event_type") == "handoff_acceptance":
        canonical_record = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
        if canonical_record != record_bytes:
            return SubmitResponse(accepted=False, reason="acceptance record is not canonical JSON")
        if record.get("event_id") != req.watermark_id or not re.fullmatch(r"[0-9a-f]{32}", req.watermark_id):
            return SubmitResponse(accepted=False, reason="acceptance event id does not match ledger lookup key")
        if (record.get("recipient_id") != req.recipient_id
                or record.get("key_version") != identity["key_version"]):
            return SubmitResponse(accepted=False, reason="acceptance was not signed by the active recipient key")
        transfer_id = record.get("transfer_event_id")
        if not isinstance(transfer_id, str) or not re.fullmatch(r"[0-9a-f]{32}", transfer_id):
            return SubmitResponse(accepted=False, reason="acceptance transfer event ID is malformed")
        transfer_entry = ledger.get_by_watermark_id(DB_PATH, transfer_id)
        if transfer_entry is None:
            return SubmitResponse(accepted=False, reason="accepted transfer is not committed")
        try:
            transfer_untrusted_record = json.loads(transfer_entry["record_json"])
            transfer_record, transfer_signature_ok = _stored_event_signature_valid(
                transfer_entry, transfer_untrusted_record["from_id"],
                transfer_untrusted_record["from_key_version"],
            )
        except (KeyError, TypeError, ValueError):
            transfer_record = {}
            transfer_signature_ok = False
        expected_package_hash = transfer_record.get("target_package_sha256")
        if (transfer_record.get("event_type") != "document_transfer"
                or transfer_record.get("event_id") != transfer_id
                or transfer_record.get("to_id") != req.recipient_id
                or transfer_record.get("doc_id") != record.get("doc_id")
                or transfer_record.get("target_package_id") != record.get("package_id")
                or expected_package_hash != record.get("package_sha256")
                or transfer_record.get("target_document_sha256") != record.get("document_sha256")
                or not transfer_signature_ok):
            return SubmitResponse(accepted=False, reason="acceptance does not match the committed transfer package")
        if (not re.fullmatch(r"[0-9a-f]{32}", str(record.get("package_id", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("package_sha256", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("document_sha256", "")))):
            return SubmitResponse(accepted=False, reason="acceptance package or document hash is malformed")
        if acceptance_event_id(transfer_id, req.recipient_id, record["package_id"],
                               record["package_sha256"]) != req.watermark_id:
            return SubmitResponse(accepted=False, reason="acceptance event ID is not bound to this recipient and package")
        sig_public = bytes.fromhex(identity["sig_public"])
        sig_alg = identity["sig_alg"]
    else:
        # Existing decryption-session records keep their original schema.
        if record.get("watermark_id") != req.watermark_id:
            return SubmitResponse(accepted=False, reason="watermark_id does not match signed record")
        if record.get("recipient_id") != req.recipient_id:
            return SubmitResponse(accepted=False, reason="recipient_id does not match signed record")
        if record.get("key_version", 1) != identity["key_version"]:
            return SubmitResponse(accepted=False, reason="record was not signed by the active recipient key version")
        sig_public = bytes.fromhex(identity["sig_public"])
        sig_alg = identity["sig_alg"]

    valid = True if governance_event else verify_record(record_bytes, signature, sig_alg, sig_public)
    if not valid:
        return SubmitResponse(accepted=False, reason="signature verification failed")

    person_auth_verification = None
    if (os.environ.get("SIGILCHAIN_REQUIRE_PERSON_AUTH", "0").strip().lower()
            in {"1", "true", "yes", "on"}
            and record.get("event_type") == "decryption_session"):
        try:
            expected_auth = {**(record.get("person_auth") or {}),
                             "watermark_id": req.watermark_id}
            person_auth_verification = verify_person_auth(
                req.auth_token or "", expected_auth, req.recipient_id)
            person_auth_verification["verified_at"] = int(time.time())
        except (KeyError, TypeError, ValueError, PermissionError) as exc:
            return SubmitResponse(accepted=False, reason=f"person authentication failed: {exc}")

    try:
        prior = ledger.find_by_watermark_id(DB_PATH, req.watermark_id)
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    if prior is not None:
        same_event = (
            prior["record_json"].encode("utf-8") == record_bytes
            and prior["signature_hex"] == signature.hex()
        )
        if same_event:
            return _accepted_response(prior)
        return SubmitResponse(accepted=False, reason="watermark_id is already committed to another event")

    try:
        machine_attestation = verify_tpm_host_attestation(
            config.VALIDATOR_ID,
            hashlib.sha256(req.watermark_id.encode("utf-8") + record_bytes).hexdigest(),
        )
        ledger.append_entry(DB_PATH, req.watermark_id, record_bytes, signature)
    except consensus.ConsensusConflict as exc:
        return SubmitResponse(accepted=False, reason=str(exc))
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    except PermissionError as exc:
        raise HTTPException(status_code=503, detail=f"TPM host attestation failed: {exc}") from exc
    committed = ledger.get_by_watermark_id(DB_PATH, req.watermark_id)
    if governance_event:
        try:
            summary = governance_state.rebuild(
                ledger.list_entries(DB_PATH), config.governance_roster(),
                config.IDENTITY_REGISTRY_DB, config.VALIDATOR_TRUST_FILE,
            )
            GOVERNANCE_STATE_READY = bool(summary.get("snapshot"))
        except (ValueError, PermissionError, TypeError, RuntimeError) as exc:
            GOVERNANCE_STATE_READY = False
            raise HTTPException(status_code=500, detail=f"governance event committed but state replay failed: {exc}") from exc
    return _accepted_response(committed, machine_attestation=machine_attestation,
                              person_auth_verification=person_auth_verification)


class VerifyResponse(BaseModel):
    found: bool
    record: dict | None = None
    signature_hex: str | None = None
    entry_hash: str | None = None
    prev_hash: str | None = None
    committed_at: int | None = None
    validator_id: str | None = None
    validator_public_key: str | None = None
    validator_sig_alg: str | None = None
    receipt: dict | None = None
    receipt_signature_hex: str | None = None
    ledger_backend: str = "local-sqlite"


@app.get("/verify/{watermark_id}", response_model=VerifyResponse)
def verify(watermark_id: str) -> VerifyResponse:
    """What the trace console (Part 6) calls after extracting a watermark
    ID from a leaked image. Includes signature_hex specifically so the
    console can independently re-verify the signature itself -- not just
    trust this response."""
    _require_governed_state()
    try:
        entry = ledger.get_by_watermark_id(DB_PATH, watermark_id)
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    if entry is None:
        return VerifyResponse(found=False)
    attestation = ledger.get_validator_receipt(DB_PATH, watermark_id)
    return VerifyResponse(
        found=True,
        record=json.loads(entry["record_json"]),
        signature_hex=entry["signature_hex"],
        entry_hash=entry["entry_hash"],
        prev_hash=entry["prev_hash"],
        committed_at=entry["committed_at"],
        validator_id=attestation["validator_id"] if attestation else None,
        validator_public_key=attestation["validator_public_key"] if attestation else None,
        validator_sig_alg=(attestation["receipt"].get("validator_sig_alg", "Ed25519")
                           if attestation else None),
        receipt=attestation["receipt"] if attestation else None,
        receipt_signature_hex=attestation["receipt_signature_hex"] if attestation else None,
        ledger_backend=(attestation["receipt"].get("ledger_backend", "local-sqlite")
                        if attestation else ("etcd-raft" if consensus.enabled() else "local-sqlite")),
    )


@app.get("/transfer-children/{parent_transfer_event_id}")
def transfer_children(parent_transfer_event_id: str) -> dict:
    """List IDs of direct outgoing transfer branches; clients verify each event independently."""
    _require_governed_state()
    if not re.fullmatch(r"[0-9a-f]{32}", parent_transfer_event_id):
        raise HTTPException(status_code=400, detail="malformed transfer event ID")
    try:
        children = ledger.list_transfer_children(DB_PATH, parent_transfer_event_id)
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    return {"parent_transfer_event_id": parent_transfer_event_id, "children": children}


@app.get("/node-info")
def node_info() -> dict:
    return {
        "validator_id": config.VALIDATOR_ID,
        "validator_public_key": VALIDATOR_PUBLIC_KEY,
        "validator_sig_alg": VALIDATOR_KEY.sig_alg,
        "fingerprint": hashlib.sha256(bytes.fromhex(VALIDATOR_PUBLIC_KEY)).hexdigest(),
        "ledger_backend": "etcd-raft" if consensus.enabled() else "local-sqlite",
        "consensus_failure_model": "crash-fault majority; not Byzantine fault tolerant" if consensus.enabled() else None,
        "governance_state_ready": GOVERNANCE_STATE_READY,
    }


@app.get("/chain-proof/{watermark_id}")
def chain_proof(watermark_id: str) -> dict:
    """Return the ledger prefix needed for a client-side hash-chain check."""
    _require_governed_state()
    try:
        entries = ledger.get_chain_proof(DB_PATH, watermark_id)
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    return {"found": entries is not None, "entries": entries or []}


@app.get("/chain-integrity")
def chain_integrity() -> dict:
    """Live proof-of-tamper-evidence endpoint -- hit this on any node at
    any time to confirm its ledger hasn't been altered since genesis."""
    try:
        ok, detail = ledger.verify_chain_integrity(DB_PATH)
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    return {"intact": ok, "detail": detail}


@app.get("/chain-state")
def chain_state() -> dict:
    """Expose a quorum-checkable current head for externally held checkpoints."""
    try:
        ok, detail = ledger.verify_chain_integrity(DB_PATH)
        head = ledger.chain_head(DB_PATH)
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    statement = {"schema": "sigilchain-chain-head-v1",
                 "validator_id": config.VALIDATOR_ID,
                 "validator_sig_alg": VALIDATOR_KEY.sig_alg,
                 "head": head, "intact": ok, "issued_at": int(time.time())}
    return {"intact": ok, "detail": detail, "head": head,
            "attestation": {"statement": statement,
                            "signature_hex": sign_attestation(VALIDATOR_KEY, statement),
                            "validator_public_key": VALIDATOR_PUBLIC_KEY}}


@app.get("/chain-suffix/{sequence}")
def chain_suffix(sequence: int) -> dict:
    """Return entries after a held checkpoint sequence for client-side verification."""
    if sequence < 0:
        raise HTTPException(status_code=400, detail="sequence must be non-negative")
    try:
        head = ledger.chain_head(DB_PATH)
        if sequence > head["sequence"]:
            raise HTTPException(status_code=409, detail="checkpoint is ahead of the current ledger")
        entries = [entry for entry in ledger.list_entries(DB_PATH) if int(entry["id"]) > sequence]
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    return {"head": head, "entries": entries}


class IdentityResponse(BaseModel):
    found: bool
    recipient_id: str | None = None
    kem_alg: str | None = None
    sig_alg: str | None = None
    kem_public: str | None = None
    sig_public: str | None = None
    key_version: int | None = None


@app.get("/identity/{recipient_id}", response_model=IdentityResponse)
def get_identity(recipient_id: str) -> IdentityResponse:
    """
    Scaling piece: at demo scale, every recipient's machine can share one
    local identity_registry.db file. That stops working once real
    recipients are on separate machines -- 10 or 100 people can't all
    read the same local SQLite file. This endpoint makes the validator
    nodes (already the one piece of infrastructure everyone talks to)
    double as a shared identity directory too: a sender or recipient on
    any machine can resolve someone else's public keys over the network
    instead of needing local file access to the registry.

    Only public keys are ever exposed here -- same as the local registry,
    private keys never leave the machine that generated them.
    """
    _require_governed_state()
    try:
        identity = lookup_identity(recipient_id)
    except KeyError:
        return IdentityResponse(found=False)
    except PermissionError:
        return IdentityResponse(found=False)
    return IdentityResponse(found=True, **identity)
