"""Canonical recipient-signed decryption event claims."""
from __future__ import annotations

import hashlib
import json
import re
import time
from typing import Any

import oqs

from .identity import SIG_ALG


def canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def build_claim(document_id: str, recipient_id: str, key_version: int,
                watermark_id: str, marked_pdf: bytes, timestamp: int | None = None) -> dict[str, Any]:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", document_id):
        raise ValueError("Document IDs must be 1-64 letters, digits, dot, underscore, or hyphen.")
    if not re.fullmatch(r"[0-9a-f]{24}", watermark_id):
        raise ValueError("Watermark IDs must be 24 lowercase hexadecimal characters.")
    return {"schema": "sigilchain-decrypt-claim-v1", "document_id": document_id,
            "recipient_id": recipient_id, "key_version": key_version,
            "watermark_id": watermark_id, "timestamp_claim": int(timestamp or time.time()),
            "marked_file_sha256": hashlib.sha256(marked_pdf).hexdigest()}


def sign_claim(claim: dict[str, Any], private_key_hex: str) -> str:
    with oqs.Signature(SIG_ALG, secret_key=bytes.fromhex(private_key_hex)) as signer:
        return signer.sign(canonical_json(claim)).hex()


def verify_claim(claim: dict[str, Any], signature_hex: str,
                 public_key_hex: str, sig_alg: str = SIG_ALG) -> bool:
    if sig_alg != SIG_ALG:
        return False
    try:
        # Keep the signed v1 record deliberately narrow.  In addition to
        # verifying its signature, reject malformed or ambiguous values before
        # they reach the ledger or an evidence renderer.
        if not isinstance(claim, dict) or set(claim) != {
            "schema", "document_id", "recipient_id", "key_version",
            "watermark_id", "timestamp_claim", "marked_file_sha256",
        }:
            return False
        if claim["schema"] != "sigilchain-decrypt-claim-v1":
            return False
        if not isinstance(claim["document_id"], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", claim["document_id"]
        ):
            return False
        if not isinstance(claim["recipient_id"], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", claim["recipient_id"]
        ):
            return False
        if type(claim["key_version"]) is not int or claim["key_version"] < 1:
            return False
        if type(claim["timestamp_claim"]) is not int or claim["timestamp_claim"] < 1:
            return False
        if not isinstance(claim["watermark_id"], str) or not re.fullmatch(
            r"[0-9a-f]{24}", claim["watermark_id"]
        ):
            return False
        if not isinstance(claim["marked_file_sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", claim["marked_file_sha256"]
        ):
            return False
        if not isinstance(signature_hex, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", signature_hex):
            return False
        if not isinstance(public_key_hex, str) or not re.fullmatch(r"(?:[0-9a-f]{2})+", public_key_hex):
            return False
        with oqs.Signature(SIG_ALG) as verifier:
            return bool(verifier.verify(canonical_json(claim), bytes.fromhex(signature_hex),
                                        bytes.fromhex(public_key_hex)))
    except Exception:
        return False
