"""Signed document handoff events used by the ordered validator ledger."""

import hashlib
import time
import uuid

from crypto.encrypt import canonical_json
from crypto.sign import sign_record


def build_transfer_record(*, transfer_id: str, document_id: str, sender: dict,
                          recipient: dict, source_package_id: str | None,
                          source_package_sha256: str | None,
                          source_document_sha256: str,
                          target_package: dict, parent_transfer_event_id: str | None,
                          parent_acceptance_event_id: str | None = None,
                          timestamp: int | None = None) -> bytes:
    """Create a canonical, sender-signed outgoing-handoff event."""
    if timestamp is None:
        timestamp = int(time.time())
    record = {
        "event_type": "document_transfer",
        "event_id": transfer_id,
        "doc_id": document_id,
        "from_id": sender["recipient_id"],
        "from_key_version": int(sender.get("key_version", 1)),
        "from_sig_alg": sender["sig_alg"],
        "to_id": recipient["recipient_id"],
        "to_key_version": int(recipient.get("key_version", 1)),
        "to_kem_public_sha256": hashlib.sha256(bytes.fromhex(recipient["kem_public"])).hexdigest(),
        "to_sig_public_sha256": hashlib.sha256(bytes.fromhex(recipient["sig_public"])).hexdigest(),
        "source_package_id": source_package_id,
        "source_package_sha256": source_package_sha256,
        "source_document_sha256": source_document_sha256,
        "target_document_sha256": target_package["document_sha256"],
        "target_package_id": target_package["package_id"],
        "target_package_sha256": hashlib.sha256(canonical_json(target_package)).hexdigest(),
        "parent_transfer_event_id": parent_transfer_event_id,
        "parent_acceptance_event_id": parent_acceptance_event_id,
        "timestamp": timestamp,
    }
    return canonical_json(record)


def acceptance_event_id(transfer_id: str, recipient_id: str, package_id: str,
                        package_sha256: str) -> str:
    """Stable lookup ID for one recipient's acceptance of one exact package."""
    material = "\0".join(("sigilchain/handoff-acceptance/v1", transfer_id,
                           recipient_id, package_id, package_sha256)).encode("utf-8")
    return hashlib.sha256(material).hexdigest()[:32]


def build_acceptance_record(*, acceptance_id: str, transfer_id: str, document_id: str,
                            recipient: dict, package_id: str, package_sha256: str,
                            document_sha256: str, timestamp: int | None = None) -> bytes:
    """Create a recipient-key-signed acknowledgment for the exact received package."""
    if timestamp is None:
        timestamp = int(time.time())
    return canonical_json({
        "event_type": "handoff_acceptance",
        "event_id": acceptance_id,
        "transfer_event_id": transfer_id,
        "doc_id": document_id,
        "recipient_id": recipient["recipient_id"],
        "key_version": int(recipient.get("key_version", 1)),
        "package_id": package_id,
        "package_sha256": package_sha256,
        "document_sha256": document_sha256,
        "timestamp": timestamp,
    })


def sign_transfer(record_bytes: bytes, sender_private: dict) -> bytes:
    return sign_record(record_bytes, sender_private["sig_alg"], bytes.fromhex(sender_private["sig_secret"]))


def new_transfer_id() -> str:
    return uuid.uuid4().hex
