"""Invisible PDF watermarking: required Reed-Solomon plus repeated DCT carriers."""
from __future__ import annotations

import os
from io import BytesIO

import numpy as np
import pymupdf
from PIL import Image
from reedsolo import RSCodec
from scipy.fft import dct, idct

from . import config

ID_BYTES = 12
RS_PARITY = 8
CODEC = RSCodec(RS_PARITY)
BLOCK = 8
COEF_A, COEF_B = (3, 1), (1, 3)


def new_watermark_id() -> bytes:
    return os.urandom(ID_BYTES)


def to_bits(watermark_id: bytes) -> list[int]:
    if len(watermark_id) != ID_BYTES:
        raise ValueError("Watermark IDs must be exactly 12 bytes.")
    coded = bytes(CODEC.encode(watermark_id))
    return [(byte >> bit) & 1 for byte in coded for bit in range(7, -1, -1)]


def from_bits(bits: list[int]) -> bytes:
    expected = (ID_BYTES + RS_PARITY) * 8
    if len(bits) != expected:
        raise ValueError(f"Expected {expected} bits, got {len(bits)}.")
    raw = bytearray()
    for i in range(0, len(bits), 8):
        value = 0
        for bit in bits[i:i + 8]:
            value = (value << 1) | (bit & 1)
        raw.append(value)
    decoded, _, _ = CODEC.decode(raw)
    return bytes(decoded)


def _haar_ll(gray: np.ndarray) -> tuple[np.ndarray, tuple[int, int]]:
    h, w = gray.shape
    padded = np.pad(gray.astype(np.float64), ((0, h % 2), (0, w % 2)), mode="edge")
    a, b = padded[0::2, 0::2], padded[0::2, 1::2]
    c, d = padded[1::2, 0::2], padded[1::2, 1::2]
    return (a + b + c + d) / 4.0, (h, w)


def _haar_inverse(ll: np.ndarray, original: np.ndarray, shape: tuple[int, int]) -> np.ndarray:
    h, w = shape
    padded = np.pad(original.astype(np.float64), ((0, h % 2), (0, w % 2)), mode="edge")
    a, b = padded[0::2, 0::2], padded[0::2, 1::2]
    c, d = padded[1::2, 0::2], padded[1::2, 1::2]
    lh, hl, hh = (a - b + c - d) / 4, (a + b - c - d) / 4, (a - b - c + d) / 4
    restored = np.empty_like(padded)
    restored[0::2, 0::2] = ll + lh + hl + hh
    restored[0::2, 1::2] = ll - lh + hl - hh
    restored[1::2, 0::2] = ll + lh - hl - hh
    restored[1::2, 1::2] = ll - lh - hl + hh
    return restored[:h, :w]


def _dct2(block: np.ndarray) -> np.ndarray:
    return dct(dct(block.astype(np.float64), axis=0, norm="ortho"), axis=1, norm="ortho")


def _idct2(block: np.ndarray) -> np.ndarray:
    return idct(idct(block, axis=1, norm="ortho"), axis=0, norm="ortho")


def _carrier_indices(shape: tuple[int, int], bit_count: int, repeat: int) -> list[list[tuple[int, int]]]:
    h, w = shape
    positions = [(y, x) for y in range(0, h - BLOCK + 1, BLOCK)
                 for x in range(0, w - BLOCK + 1, BLOCK)]
    count = bit_count * repeat
    if len(positions) < count:
        raise ValueError(f"Page too small for watermark: need {count} blocks, have {len(positions)}.")
    chosen = [positions[i * len(positions) // count] for i in range(count)]
    groups = [[] for _ in range(bit_count)]
    for index, pos in enumerate(chosen):
        groups[index % bit_count].append(pos)
    return groups


def _embed(gray: np.ndarray, bits: list[int], delta: float, repeat: int) -> np.ndarray:
    out = gray.astype(np.float64).copy()
    groups = _carrier_indices(out.shape, len(bits), repeat)
    for bit, positions in zip(bits, groups):
        for y, x in positions:
            coeff = _dct2(out[y:y + BLOCK, x:x + BLOCK])
            a, b = coeff[COEF_A], coeff[COEF_B]
            if bit and a - b < delta:
                middle = (a + b) / 2
                coeff[COEF_A], coeff[COEF_B] = middle + delta / 2, middle - delta / 2
            elif not bit and b - a < delta:
                middle = (a + b) / 2
                coeff[COEF_A], coeff[COEF_B] = middle - delta / 2, middle + delta / 2
            out[y:y + BLOCK, x:x + BLOCK] = _idct2(coeff)
    return np.clip(out, 0, 255)


def _extract(gray: np.ndarray, bit_count: int, repeat: int) -> tuple[list[int], float]:
    groups = _carrier_indices(gray.shape, bit_count, repeat)
    bits, confidence = [], []
    for positions in groups:
        votes = []
        for y, x in positions:
            coeff = _dct2(gray[y:y + BLOCK, x:x + BLOCK])
            votes.append(int(coeff[COEF_A] > coeff[COEF_B]))
        ones = sum(votes)
        bits.append(int(ones >= len(votes) / 2))
        confidence.append(max(ones, len(votes) - ones) / len(votes))
    return bits, float(np.mean(confidence))


def embed_page(gray: np.ndarray, watermark_id: bytes) -> np.ndarray:
    bits = to_bits(watermark_id)
    if config.WATERMARK_TRANSFORM == "dwt-dct":
        ll, shape = _haar_ll(gray)
        return np.clip(_haar_inverse(_embed(ll, bits, config.EMBED_DELTA, config.EMBED_REPEAT), gray, shape), 0, 255)
    return _embed(gray, bits, config.EMBED_DELTA, config.EMBED_REPEAT)


def extract_page(gray: np.ndarray) -> tuple[bytes, float]:
    bit_count = (ID_BYTES + RS_PARITY) * 8
    if config.WATERMARK_TRANSFORM == "dwt-dct":
        target, _ = _haar_ll(gray)
    else:
        target = gray
    bits, confidence = _extract(target, bit_count, config.EMBED_REPEAT)
    return from_bits(bits), confidence


def pdf_pages(pdf_bytes: bytes) -> list[np.ndarray]:
    with pymupdf.open(stream=pdf_bytes, filetype="pdf") as pdf:
        return [np.asarray(Image.open(BytesIO(page.get_pixmap(dpi=config.PDF_DPI, colorspace=pymupdf.csGRAY).tobytes("png"))).convert("L"))
                for page in pdf]


def pages_to_pdf(pages: list[np.ndarray], dpi: int | None = None) -> bytes:
    if not pages:
        raise ValueError("Cannot create an empty marked PDF.")
    dpi = dpi or config.PDF_DPI
    images = [Image.fromarray(np.asarray(page, dtype=np.uint8), mode="L") for page in pages]
    output = BytesIO()
    images[0].save(output, format="PDF", save_all=True, append_images=images[1:], resolution=dpi)
    return output.getvalue()


def watermark_pdf(pdf_bytes: bytes, watermark_id: bytes) -> bytes:
    marked = [embed_page(page, watermark_id) for page in pdf_pages(pdf_bytes)]
    return pages_to_pdf(marked)
