"""
SigilChain — DCT-domain watermark core.

Embeds a bit payload into a grayscale image by comparing two mid-frequency
DCT coefficients within each 8x8 block (Koch-Zhao style coefficient-pair
watermarking). Mid-frequency coefficients are chosen deliberately: the DC
term (0,0) carries too much visual energy to touch without visible
artifacts, and high-frequency terms are exactly what JPEG quantization
destroys first. Mid-band survives moderate recompression while staying
imperceptible.

Each payload bit is repeated across many blocks (spread-spectrum style);
extraction uses majority voting across the repeats, which is what gives
this robustness against localized corruption (compression noise, minor
cropping, screenshot artifacts) without yet requiring a separate
error-correcting code on top.
"""

import numpy as np
from scipy.fft import dct, idct

# Mid-frequency coefficient pair used for embedding. Chosen to be close in
# frequency (so JPEG's per-frequency quantization affects them similarly)
# but not adjacent to the DC term or the highest frequencies.
COEF_A = (3, 1)
COEF_B = (1, 3)

BLOCK_SIZE = 8


def _block_dct(block: np.ndarray) -> np.ndarray:
    return dct(dct(block.astype(np.float64), axis=0, norm="ortho"), axis=1, norm="ortho")


def _block_idct(coeffs: np.ndarray) -> np.ndarray:
    return idct(idct(coeffs, axis=1, norm="ortho"), axis=0, norm="ortho")


def _iter_blocks(shape, block_size=BLOCK_SIZE):
    h, w = shape
    for by in range(0, h - block_size + 1, block_size):
        for bx in range(0, w - block_size + 1, block_size):
            yield by, bx


def capacity(image_shape, block_size=BLOCK_SIZE) -> int:
    """Number of 8x8 blocks available in an image of this shape."""
    h, w = image_shape[:2]
    return (h // block_size) * (w // block_size)


def _spread_assignment(avail: int, num_bits: int, repeat: int) -> list[list[int]]:
    """
    Choose `num_bits * repeat` block indices out of `avail`, evenly spaced
    across the whole range (stride selection), then assign them round-robin
    to bits. This ensures every bit's repeats are spread across the entire
    page rather than clustered in one region — critical for surviving a
    crop, crease, or glare spot that only damages part of a photographed
    page. Returns a list (one entry per bit) of block-index lists.
    """
    blocks_needed = num_bits * repeat
    if blocks_needed > avail:
        raise ValueError(
            f"Image too small: need {blocks_needed} blocks for {num_bits} bits "
            f"x {repeat} repeats, only {avail} available. Shrink `repeat`, "
            f"shorten the payload, or use a larger image."
        )
    stride = avail // blocks_needed
    picked = [i * stride for i in range(blocks_needed)]

    assignment = [[] for _ in range(num_bits)]
    for i, block_idx in enumerate(picked):
        assignment[i % num_bits].append(block_idx)
    return assignment


def embed_bits(gray: np.ndarray, bits: list[int], delta: float = 12.0, repeat: int = 40) -> np.ndarray:
    """
    Embed `bits` (a list of 0/1) into a grayscale image, each bit repeated
    `repeat` times across blocks spread evenly across the whole page.

    delta: minimum enforced gap between the two chosen coefficients.
           Larger = more robust to compression, but more visible distortion.
    repeat: how many blocks carry each bit. Larger = more robust to
            localized corruption, but requires a bigger image / more capacity.
    """
    gray = gray.astype(np.float64).copy()
    block_positions = list(_iter_blocks(gray.shape))
    avail = len(block_positions)
    assignment = _spread_assignment(avail, len(bits), repeat)

    for bit, block_indices in zip(bits, assignment):
        for block_idx in block_indices:
            by, bx = block_positions[block_idx]
            block = gray[by:by + BLOCK_SIZE, bx:bx + BLOCK_SIZE]
            coeffs = _block_dct(block)

            a = coeffs[COEF_A]
            b = coeffs[COEF_B]

            if bit == 1:
                # enforce a > b + delta
                if a - b < delta:
                    mid = (a + b) / 2
                    coeffs[COEF_A] = mid + delta / 2
                    coeffs[COEF_B] = mid - delta / 2
            else:
                # enforce b > a + delta  (i.e. a < b - delta)
                if b - a < delta:
                    mid = (a + b) / 2
                    coeffs[COEF_A] = mid - delta / 2
                    coeffs[COEF_B] = mid + delta / 2

            gray[by:by + BLOCK_SIZE, bx:bx + BLOCK_SIZE] = _block_idct(coeffs)

    return np.clip(gray, 0, 255)


def extract_bits(gray: np.ndarray, num_bits: int, repeat: int = 40) -> list[int]:
    """
    Extract `num_bits` bits from a grayscale image using majority voting
    across each bit's `repeat` carrier blocks. Must use the identical
    spread assignment embed_bits used, or extraction reads the wrong
    blocks entirely.
    """
    gray = gray.astype(np.float64)
    block_positions = list(_iter_blocks(gray.shape))
    avail = len(block_positions)
    assignment = _spread_assignment(avail, num_bits, repeat)

    bits = []
    for block_indices in assignment:
        votes = []
        for block_idx in block_indices:
            by, bx = block_positions[block_idx]
            block = gray[by:by + BLOCK_SIZE, bx:bx + BLOCK_SIZE]
            coeffs = _block_dct(block)
            votes.append(1 if coeffs[COEF_A] > coeffs[COEF_B] else 0)
        bit = 1 if sum(votes) >= len(votes) / 2 else 0
        bits.append(bit)
    return bits


def bit_error_rate(original_bits: list[int], recovered_bits: list[int]) -> float:
    n = min(len(original_bits), len(recovered_bits))
    if n == 0:
        return 1.0
    errors = sum(1 for i in range(n) if original_bits[i] != recovered_bits[i])
    return errors / n


def extract_bits_with_confidence(gray: np.ndarray, num_bits: int, repeat: int = 40) -> tuple[list[int], float]:
    """
    Same as extract_bits, but also returns an average confidence score:
    for each bit, what fraction of its `repeat` carrier blocks agreed with
    the majority. 1.0 = perfect unanimous agreement across every bit,
    0.5 = pure noise. Used by geometric_correction's fine-alignment search
    to find the pixel offset that best restores block alignment, without
    needing to already know the correct answer.
    """
    gray = gray.astype(np.float64)
    block_positions = list(_iter_blocks(gray.shape))
    avail = len(block_positions)
    assignment = _spread_assignment(avail, num_bits, repeat)

    bits = []
    confidences = []
    for block_indices in assignment:
        votes = []
        for block_idx in block_indices:
            by, bx = block_positions[block_idx]
            block = gray[by:by + BLOCK_SIZE, bx:bx + BLOCK_SIZE]
            coeffs = _block_dct(block)
            votes.append(1 if coeffs[COEF_A] > coeffs[COEF_B] else 0)
        ones = sum(votes)
        bit = 1 if ones >= len(votes) / 2 else 0
        bits.append(bit)
        confidences.append(max(ones, len(votes) - ones) / len(votes))
    return bits, (sum(confidences) / len(confidences) if confidences else 0.0)
