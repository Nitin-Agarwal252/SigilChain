"""Decrypt, watermark, sign, commit, then release one recipient's marked PDF."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from . import config
from .crypto import decrypt_pdf
from .events import build_claim, sign_claim
from .identity import load_private
from .quorum import submit_to_quorum
from .watermark import new_watermark_id, watermark_pdf


def decrypt_and_mark(package: dict[str, Any], recipient_id: str, document_id: str,
                     output_dir: str, private: dict[str, Any] | None = None,
                     nodes: list[str] | None = None, pins: dict[str, Any] | None = None,
                     required: int | None = None) -> dict[str, Any]:
    private = private or load_private(recipient_id)
    original_pdf = decrypt_pdf(package, recipient_id, private)
    watermark_id = new_watermark_id()
    marked_pdf = watermark_pdf(original_pdf, watermark_id)
    claim = build_claim(document_id, recipient_id, private["key_version"],
                        watermark_id.hex(), marked_pdf)
    signature_hex = sign_claim(claim, private["sig_secret"])
    result = submit_to_quorum(nodes or config.NODE_URLS, claim, signature_hex,
                              required or config.QUORUM_REQUIRED, pins)
    if not result["committed"]:
        raise RuntimeError("Decryption event did not receive enough valid pinned validator receipts; marked plaintext was not released.")
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / f"{document_id}_{recipient_id}.pdf"
    fd, temporary = tempfile.mkstemp(prefix=".sigilchain-", suffix=".pdf", dir=directory)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(marked_pdf)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return {"output_path": str(destination), "watermark_id": watermark_id.hex(),
            "claim": claim, "signature_hex": signature_hex, "quorum": result}
