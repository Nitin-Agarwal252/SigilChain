"""Trace helpers for page images and canonical PDFs."""
from __future__ import annotations

import math
from numbers import Real
from io import BytesIO

import numpy as np
import pymupdf
from PIL import Image, ImageSequence

from . import config
from .evidence import make_bundle
from .geometric import correct_photo
from .quorum import check_watermark
from .watermark import extract_page

MAX_TRACE_UPLOAD_BYTES = 50 * 1024 * 1024
MAX_TRACE_PAGES = 100
MAX_TRACE_TOTAL_PIXELS = 120_000_000
TRACE_IMAGE_TYPES = {"pdf", "png", "jpg", "jpeg", "bmp", "tif", "tiff", "webp"}


class TraceInputError(ValueError):
    """Uploaded trace input is malformed or exceeds safety limits."""


def _check_dimensions(width: float, height: float, dpi: int, total_pixels: int) -> int:
    pixel_width = max(1, math.ceil(width * dpi / 72))
    pixel_height = max(1, math.ceil(height * dpi / 72))
    pixels = pixel_width * pixel_height
    if total_pixels + pixels > MAX_TRACE_TOTAL_PIXELS:
        raise TraceInputError("Upload exceeds the total trace rasterization pixel limit.")
    return pixels


def image_pages(data: bytes, filename: str) -> list[np.ndarray]:
    suffix = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if not isinstance(data, bytes) or not data:
        raise TraceInputError("Upload is empty or not a byte string.")
    if len(data) > MAX_TRACE_UPLOAD_BYTES:
        raise TraceInputError("Upload exceeds the maximum trace file size.")
    if suffix not in TRACE_IMAGE_TYPES:
        raise TraceInputError("Unsupported trace file type.")
    dpi = config.PDF_DPI
    if type(dpi) is not int or dpi < 1:
        raise TraceInputError("Trace rasterization DPI must be a positive integer.")
    try:
        if suffix == "pdf":
            with pymupdf.open(stream=data, filetype="pdf") as pdf:
                if not pdf.page_count or pdf.page_count > MAX_TRACE_PAGES:
                    raise TraceInputError(f"PDF must contain between 1 and {MAX_TRACE_PAGES} pages.")
                pages, total_pixels = [], 0
                for page in pdf:
                    pixels = _check_dimensions(page.rect.width, page.rect.height, dpi, total_pixels)
                    total_pixels += pixels
                    pix = page.get_pixmap(dpi=dpi, colorspace=pymupdf.csGRAY)
                    pages.append(np.asarray(Image.open(BytesIO(pix.tobytes("png"))).convert("L")))
                return pages
        with Image.open(BytesIO(data)) as image:
            if image.n_frames < 1 or image.n_frames > MAX_TRACE_PAGES:
                raise TraceInputError(f"Image must contain between 1 and {MAX_TRACE_PAGES} frames.")
            pages, total_pixels = [], 0
            for frame in ImageSequence.Iterator(image):
                pixels = _check_dimensions(frame.width, frame.height, 72, total_pixels)
                total_pixels += pixels
                pages.append(np.asarray(frame.convert("L")))
            return pages
    except TraceInputError:
        raise
    except Exception as exc:
        raise TraceInputError(f"Could not read trace upload: {exc}") from exc


def trace_page(page: np.ndarray, nodes: list[str] | None = None,
               threshold: float = 0.72, photo_capture: bool = False) -> dict:
    if isinstance(threshold, bool) or not isinstance(threshold, Real) or not math.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("Watermark confidence threshold must be a finite number between 0 and 1.")
    try:
        recovery_path = "original image"
        if photo_capture:
            corrected = correct_photo(page)
            if corrected is None:
                return {"status": "inconclusive", "reason":
                        "Could not find a page boundary for photo correction. Try a clearer, more front-facing capture or turn photo correction off."}
            page, alignment_confidence = corrected
            if alignment_confidence < threshold:
                return {"status": "inconclusive", "confidence": alignment_confidence,
                        "reason": "Photo alignment confidence was too low to trust watermark recovery."}
            recovery_path = "experimental photo perspective and grid correction"
        watermark_id, confidence = extract_page(page)
    except Exception:
        return {"status": "inconclusive", "reason":
                "Could not decode a valid watermark payload. The image may be too damaged or misaligned; do not attribute this copy."}
    if confidence < threshold:
        return {"status": "inconclusive", "watermark_id": watermark_id.hex(), "confidence": confidence,
                "recovery_path": recovery_path}
    matches = check_watermark(config.NODE_URLS if nodes is None else nodes, watermark_id.hex())
    if not matches:
        return {"status": "unverified", "watermark_id": watermark_id.hex(), "confidence": confidence,
                "recovery_path": recovery_path,
                "reason": "No configured quorum of valid pinned validator receipts and chain proofs."}
    return {"status": "verified", "watermark_id": watermark_id.hex(), "confidence": confidence,
            "recovery_path": recovery_path,
            "bundle": make_bundle(watermark_id.hex(), matches, confidence, recovery_path)}
