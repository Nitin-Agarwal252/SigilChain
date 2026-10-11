"""One-level Haar DWT + block-DCT watermarking option.

The DCT payload is embedded in the low-low (LL) wavelet subband. This
keeps the existing spread assignment/error-correction format while moving
the carriers to a lower spatial scale. Select it consistently for both
embedding and extraction with SIGILCHAIN_WATERMARK_TRANSFORM=dwt-dct.
"""

import numpy as np

from watermark.dct_watermark import (
    embed_bits as _embed_dct,
    extract_bits as _extract_dct,
    extract_bits_with_confidence as _extract_dct_confident,
    capacity as _dct_capacity,
)


def _forward(gray: np.ndarray) -> tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray, tuple[int, int]]:
    image = np.asarray(gray, dtype=np.float64)
    height, width = image.shape
    padded = np.pad(image, ((0, height % 2), (0, width % 2)), mode="edge")
    a = padded[0::2, 0::2]
    b = padded[0::2, 1::2]
    c = padded[1::2, 0::2]
    d = padded[1::2, 1::2]
    # Orthonormal Haar subbands, scaled so the LL range remains in pixel units.
    ll = (a + b + c + d) / 4.0
    lh = (a - b + c - d) / 4.0
    hl = (a + b - c - d) / 4.0
    hh = (a - b - c + d) / 4.0
    return ll, lh, hl, hh, (height, width)


def _inverse(ll: np.ndarray, lh: np.ndarray, hl: np.ndarray, hh: np.ndarray,
             shape: tuple[int, int]) -> np.ndarray:
    image = np.empty((ll.shape[0] * 2, ll.shape[1] * 2), dtype=np.float64)
    image[0::2, 0::2] = ll + lh + hl + hh
    image[0::2, 1::2] = ll - lh + hl - hh
    image[1::2, 0::2] = ll + lh - hl - hh
    image[1::2, 1::2] = ll - lh - hl + hh
    return image[:shape[0], :shape[1]]


def embed_bits(gray: np.ndarray, bits: list[int], delta: float = 60.0,
               repeat: int = 40) -> np.ndarray:
    """Embed bits in DCT coefficient pairs inside the Haar LL subband."""
    ll, lh, hl, hh, shape = _forward(gray)
    marked_ll = _embed_dct(ll, bits, delta=delta, repeat=repeat)
    return np.clip(_inverse(marked_ll, lh, hl, hh, shape), 0, 255)


def extract_bits(gray: np.ndarray, num_bits: int, repeat: int = 40) -> list[int]:
    """Extract the payload from the Haar LL subband."""
    ll, _, _, _, _ = _forward(gray)
    return _extract_dct(ll, num_bits, repeat=repeat)


def extract_bits_with_confidence(gray: np.ndarray, num_bits: int,
                                 repeat: int = 40) -> tuple[list[int], float]:
    """Extract bits and return the DCT carrier-agreement heuristic."""
    ll, _, _, _, _ = _forward(gray)
    return _extract_dct_confident(ll, num_bits, repeat=repeat)


def capacity(shape: tuple[int, int]) -> int:
    """Report the number of available 8x8 DCT carriers in the LL subband."""
    return _dct_capacity(((shape[0] + 1) // 2, (shape[1] + 1) // 2))
