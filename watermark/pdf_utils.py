"""
SigilChain — PDF <-> page-image conversion (Part 3's PDF I/O half).

The DCT watermark core (dct_watermark.py) operates on grayscale image
arrays, not PDF files directly -- a PDF is a mix of vector text, fonts,
and embedded objects, not pixels, so there's nothing to embed DCT
coefficients into until it's rasterized. This module is the bridge:
rasterize each page to a grayscale array for embedding/extraction, then
reassemble marked pages back into a single PDF.

Uses the modern `import pymupdf` name, not the deprecated `import fitz`
(same library, PyMuPDF renamed its import in recent versions).
"""

import io

import numpy as np
import pymupdf
from PIL import Image

DEFAULT_DPI = 150


def pdf_to_grayscale_images(pdf_bytes: bytes, dpi: int = DEFAULT_DPI) -> list[np.ndarray]:
    """Rasterize every page of a PDF to a grayscale numpy array, at the
    given DPI. 150 DPI matches what the watermark core was tuned and
    tested against (see tests/test_dct_watermark.py's synthetic page)."""
    doc = pymupdf.open(stream=pdf_bytes, filetype="pdf")
    zoom = dpi / 72.0  # PDF's native unit is 72 DPI
    matrix = pymupdf.Matrix(zoom, zoom)

    images = []
    for page in doc:
        pix = page.get_pixmap(matrix=matrix, colorspace=pymupdf.csGRAY)
        arr = np.frombuffer(pix.samples, dtype=np.uint8).reshape(pix.height, pix.width)
        images.append(arr.copy())
    doc.close()
    return images


def images_to_pdf(images: list[np.ndarray], dpi: int = DEFAULT_DPI) -> bytes:
    """Reassemble a list of grayscale page images (post-watermarking) back
    into a single PDF, one page per image, each sized to match the
    original page dimensions at the given DPI."""
    doc = pymupdf.open()
    for arr in images:
        img = Image.fromarray(arr.astype(np.uint8), mode="L")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        png_bytes = buf.getvalue()

        h, w = arr.shape
        width_pt = w * 72.0 / dpi
        height_pt = h * 72.0 / dpi
        page = doc.new_page(width=width_pt, height=height_pt)
        page.insert_image(pymupdf.Rect(0, 0, width_pt, height_pt), stream=png_bytes)

    out = doc.tobytes()
    doc.close()
    return out
