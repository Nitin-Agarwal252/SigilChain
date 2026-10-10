"""Trace helpers for page images and canonical PDFs."""
from __future__ import annotations

from io import BytesIO

import numpy as np
import pymupdf
from PIL import Image, ImageSequence

from . import config
from .evidence import make_bundle
from .quorum import check_watermark
from .watermark import extract_page


def image_pages(data: bytes, filename: str) -> list[np.ndarray]:
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if suffix == "pdf":
        with pymupdf.open(stream=data, filetype="pdf") as pdf:
            pages = []
            for page in pdf:
                pix = page.get_pixmap(dpi=config.PDF_DPI, colorspace=pymupdf.csGRAY)
                pages.append(np.asarray(Image.open(BytesIO(pix.tobytes("png"))).convert("L")))
            return pages
    with Image.open(BytesIO(data)) as image:
        return [np.asarray(frame.convert("L")) for frame in ImageSequence.Iterator(image)]


def trace_page(page: np.ndarray, nodes: list[str] | None = None,
               threshold: float = 0.72) -> dict:
    try:
        watermark_id, confidence = extract_page(page)
    except Exception as exc:
        return {"status": "extraction_failed", "error": str(exc)}
    if confidence < threshold:
        return {"status": "inconclusive", "watermark_id": watermark_id.hex(), "confidence": confidence}
    matches = check_watermark(nodes or config.NODE_URLS, watermark_id.hex())
    if not matches:
        return {"status": "unverified", "watermark_id": watermark_id.hex(), "confidence": confidence,
                "reason": "No configured quorum of valid pinned validator receipts and chain proofs."}
    return {"status": "verified", "watermark_id": watermark_id.hex(), "confidence": confidence,
            "bundle": make_bundle(watermark_id.hex(), matches, confidence, "uploaded page")}
