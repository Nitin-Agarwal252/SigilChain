"""Validator HTTP service: verify a signed claim, commit it, issue receipts."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path
from typing import Literal

import oqs
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, StrictInt, StrictStr
from starlette.responses import JSONResponse

from . import config, ledger
from .events import is_well_formed_claim, verify_claim
from .identity import SIG_ALG, lookup_identity

MAX_SUBMIT_REQUEST_BYTES = 16 * 1024


class SubmitBodySizeLimitMiddleware:
    """Bound submit JSON before FastAPI buffers or parses it."""
    def __init__(self, app, max_bytes: int = MAX_SUBMIT_REQUEST_BYTES):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if (scope["type"] != "http" or scope["method"] != "POST"
                or scope["path"] != "/submit"):
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                content_length = int(raw_length.decode("ascii"))
            except (UnicodeDecodeError, ValueError):
                response = JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
                await response(scope, receive, send)
                return
            if content_length < 0:
                response = JSONResponse(status_code=400, content={"detail": "Invalid Content-Length."})
                await response(scope, receive, send)
                return
            if content_length > self.max_bytes:
                response = JSONResponse(status_code=413, content={"detail": "Submission request is too large."})
                await response(scope, receive, send)
                return

        chunks = []
        total = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            total += len(chunk)
            if total > self.max_bytes:
                response = JSONResponse(status_code=413, content={"detail": "Submission request is too large."})
                await response(scope, receive, send)
                return
            chunks.append(chunk)
            if not message.get("more_body", False):
                break

        body = b"".join(chunks)
        body_pending = True

        async def replay_receive():
            nonlocal body_pending
            if body_pending:
                body_pending = False
                return {"type": "http.request", "body": body, "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_receive, send)


app = FastAPI(title="SigilChain Validator", version="1")
app.add_middleware(SubmitBodySizeLimitMiddleware)


def _check_signing_keypair(private_key: bytes, public_key: bytes) -> None:
    """Fail startup if persisted PQ signing material is corrupt or mismatched."""
    challenge = b"SigilChain validator signing-key self-check v1"
    try:
        with oqs.Signature(SIG_ALG, secret_key=private_key) as signer:
            signature = signer.sign(challenge)
        with oqs.Signature(SIG_ALG) as verifier:
            if not verifier.verify(challenge, signature, public_key):
                raise RuntimeError("Validator signing key pair does not match")
    except RuntimeError:
        raise
    except Exception as exc:
        raise RuntimeError("Validator signing key material is invalid") from exc


def _persist_signing_key(path: Path, private_key: bytes, public_key: bytes) -> None:
    """Publish the key file atomically with owner-only permissions on POSIX."""
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump({"sig_alg": SIG_ALG, "private_key_hex": private_key.hex(),
                       "public_key_hex": public_key.hex()}, handle)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name != "nt":
            os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        if os.name != "nt":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def _auth(value: str | None = Header(default=None, alias=config.API_KEY_HEADER)) -> None:
    if config.API_KEY and value != config.API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")


def _load_signing_key() -> tuple[bytes, bytes]:
    path = Path(config.VALIDATOR_KEY_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        value = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(value, dict)
                or set(value) != {"sig_alg", "private_key_hex", "public_key_hex"}
                or value.get("sig_alg") != SIG_ALG
                or not isinstance(value.get("private_key_hex"), str)
                or not isinstance(value.get("public_key_hex"), str)):
            raise RuntimeError("Invalid validator signing key file schema or algorithm")
        try:
            private, public = bytes.fromhex(value["private_key_hex"]), bytes.fromhex(value["public_key_hex"])
        except ValueError as exc:
            raise RuntimeError("Validator signing key file contains invalid hexadecimal") from exc
        _check_signing_keypair(private, public)
        return private, public
    with oqs.Signature(SIG_ALG) as signer:
        public = signer.generate_keypair()
        private = signer.export_secret_key()
    _persist_signing_key(path, private, public)
    _check_signing_keypair(private, public)
    return private, public


VALIDATOR_SECRET, VALIDATOR_PUBLIC = _load_signing_key()


class StrictRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class DecryptionClaimRequest(StrictRequestModel):
    """Bounded v1 claim shape; semantic checks remain in events.py."""
    claim_schema: Literal["sigilchain-decrypt-claim-v1"] = Field(alias="schema")
    document_id: StrictStr = Field(min_length=1, max_length=64)
    recipient_id: StrictStr = Field(min_length=1, max_length=64)
    key_version: StrictInt = Field(ge=1)
    watermark_id: StrictStr = Field(min_length=24, max_length=24)
    timestamp_claim: StrictInt = Field(ge=1)
    marked_file_sha256: StrictStr = Field(min_length=64, max_length=64)

class SubmitRequest(StrictRequestModel):
    watermark_id: StrictStr = Field(min_length=24, max_length=24)
    claim: DecryptionClaimRequest
    # ML-DSA-65 signatures are 3309 bytes (6618 hexadecimal characters).
    signature_hex: StrictStr = Field(min_length=6618, max_length=6618)


def _sign_receipt(entry: dict) -> dict:
    payload = {"validator_id": config.VALIDATOR_ID, "validator_sig_alg": SIG_ALG,
        "ledger_backend": entry["ledger_backend"], "issued_at_claim": int(time.time()),
        "watermark_id": entry["watermark_id"], "sequence": entry["sequence"],
        "entry_hash": entry["entry_hash"], "previous_hash": entry["previous_hash"],
        "claim_hash": hashlib.sha256(entry["claim_json"].encode()).hexdigest(),
        "recipient_signature_hash": hashlib.sha256(bytes.fromhex(entry["signature_hex"])).hexdigest()}
    with oqs.Signature(SIG_ALG, secret_key=VALIDATOR_SECRET) as signer:
        signature = signer.sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    return {"receipt": payload, "receipt_signature_hex": signature.hex(),
            "validator_public_key": VALIDATOR_PUBLIC.hex(), "validator_sig_alg": SIG_ALG}


@app.get("/health")
def health(_: None = Depends(_auth)) -> dict:
    return {"ok": True, "validator_id": config.VALIDATOR_ID,
            "ledger_backend": "etcd-raft" if config.ETCD_ENDPOINTS else "local-sqlite"}


@app.get("/node-info")
def node_info(_: None = Depends(_auth)) -> dict:
    return {"validator_id": config.VALIDATOR_ID, "validator_sig_alg": SIG_ALG,
            "validator_public_key": VALIDATOR_PUBLIC.hex(),
            "fingerprint": hashlib.sha256(VALIDATOR_PUBLIC).hexdigest(),
            "ledger_backend": "etcd-raft" if config.ETCD_ENDPOINTS else "local-sqlite",
            "consensus_model": "Raft crash-fault; not Byzantine" if config.ETCD_ENDPOINTS else "single-process development"}


@app.get("/identity/{recipient_id}")
def identity(recipient_id: str, key_version: int | None = Query(default=None),
             _: None = Depends(_auth)) -> dict:
    value = lookup_identity(recipient_id, key_version=key_version,
                            allow_revoked=key_version is not None)
    return {"found": value is not None, "identity": value}


@app.post("/submit")
def submit(request: SubmitRequest, _: None = Depends(_auth)) -> dict:
    # Use an ordinary mapping for canonical signing and persistence. The
    # semantic validator below also enforces safe IDs and lowercase hex.
    claim = request.claim.model_dump(by_alias=True)
    if not is_well_formed_claim(claim):
        raise HTTPException(400, "Malformed decryption claim.")
    if claim.get("watermark_id") != request.watermark_id:
        raise HTTPException(400, "Watermark does not match the signed claim")
    public = lookup_identity(claim.get("recipient_id", ""), key_version=claim.get("key_version"))
    if not public or public["sig_alg"] != SIG_ALG:
        raise HTTPException(403, "Recipient key version is not registered")
    if not verify_claim(claim, request.signature_hex, public["sig_public"], public["sig_alg"]):
        raise HTTPException(403, "Recipient event signature is invalid")
    try:
        entry = ledger.append_event(request.watermark_id, claim, request.signature_hex)
        receipt = ledger.save_receipt(request.watermark_id, config.VALIDATOR_ID, _sign_receipt(entry))
        return {"accepted": True, "entry": entry, **receipt}
    except ledger.LedgerUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc


@app.get("/verify/{watermark_id}")
def verify(watermark_id: str, _: None = Depends(_auth)) -> dict:
    try:
        entry = ledger.get_event(watermark_id)
        proof = ledger.get_chain_proof(watermark_id) or []
        receipt = ledger.get_receipt(watermark_id, config.VALIDATOR_ID)
        return {"found": entry is not None, "entry": entry, "proof": proof,
                "chain_valid": ledger.verify_chain(proof, watermark_id) if proof else False,
                "receipt_evidence": receipt, "validator_id": config.VALIDATOR_ID}
    except ledger.LedgerUnavailable as exc:
        raise HTTPException(503, str(exc)) from exc
