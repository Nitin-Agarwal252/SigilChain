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
import sys

from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security.api_key import APIKeyHeader
from pydantic import BaseModel

from crypto.keys import lookup_identity
from crypto.sign import verify_record
from validator import ledger, consensus
from validator.attestation import load_or_create_key, make_receipt, public_key_hex
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


class SubmitRequest(BaseModel):
    watermark_id: str
    record_hex: str
    signature_hex: str
    recipient_id: str


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


def _accepted_response(entry: dict) -> SubmitResponse:
    attestation = ledger.get_validator_receipt(DB_PATH, entry["watermark_id"])
    if attestation is None:
        generated = make_receipt(VALIDATOR_KEY, config.VALIDATOR_ID, entry)
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
    )


@app.post("/submit", response_model=SubmitResponse)
def submit(req: SubmitRequest) -> SubmitResponse:
    try:
        identity = lookup_identity(req.recipient_id)
    except KeyError:
        return SubmitResponse(accepted=False, reason=f"unknown recipient_id '{req.recipient_id}'")
    except PermissionError:
        return SubmitResponse(accepted=False, reason=f"recipient identity '{req.recipient_id}' is revoked")

    try:
        record_bytes = bytes.fromhex(req.record_hex)
        signature = bytes.fromhex(req.signature_hex)
        record = json.loads(record_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return SubmitResponse(accepted=False, reason="record or signature is not valid hex-encoded JSON/bytes")
    if not isinstance(record, dict):
        return SubmitResponse(accepted=False, reason="signed record must be a JSON object")

    # The database lookup key and submitter identity must be covered by the
    # exact bytes the recipient signed. Otherwise an attacker could index a
    # valid signed event under a different watermark ID or recipient.
    if record.get("watermark_id") != req.watermark_id:
        return SubmitResponse(accepted=False, reason="watermark_id does not match signed record")
    if record.get("recipient_id") != req.recipient_id:
        return SubmitResponse(accepted=False, reason="recipient_id does not match signed record")
    if record.get("key_version", 1) != identity["key_version"]:
        return SubmitResponse(accepted=False, reason="record was not signed by the active recipient key version")

    sig_public = bytes.fromhex(identity["sig_public"])

    valid = verify_record(record_bytes, signature, identity["sig_alg"], sig_public)
    if not valid:
        return SubmitResponse(accepted=False, reason="signature verification failed")

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
        ledger.append_entry(DB_PATH, req.watermark_id, record_bytes, signature)
    except consensus.ConsensusConflict as exc:
        return SubmitResponse(accepted=False, reason=str(exc))
    except consensus.ConsensusUnavailable as exc:
        raise HTTPException(status_code=503, detail=f"consensus quorum unavailable: {exc}") from exc
    committed = ledger.get_by_watermark_id(DB_PATH, req.watermark_id)
    return _accepted_response(committed)


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


@app.get("/node-info")
def node_info() -> dict:
    return {
        "validator_id": config.VALIDATOR_ID,
        "validator_public_key": VALIDATOR_PUBLIC_KEY,
        "validator_sig_alg": VALIDATOR_KEY.sig_alg,
        "fingerprint": hashlib.sha256(bytes.fromhex(VALIDATOR_PUBLIC_KEY)).hexdigest(),
        "ledger_backend": "etcd-raft" if consensus.enabled() else "local-sqlite",
        "consensus_failure_model": "crash-fault majority; not Byzantine fault tolerant" if consensus.enabled() else None,
    }


@app.get("/chain-proof/{watermark_id}")
def chain_proof(watermark_id: str) -> dict:
    """Return the ledger prefix needed for a client-side hash-chain check."""
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
    try:
        identity = lookup_identity(recipient_id)
    except KeyError:
        return IdentityResponse(found=False)
    except PermissionError:
        return IdentityResponse(found=False)
    return IdentityResponse(found=True, **identity)
