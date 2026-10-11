"""Haar DWT + DCT hybrid watermark round-trip experiment."""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np

from tests.test_dct_watermark import make_synthetic_document, jpeg_round_trip
from watermark.dct_watermark import bit_error_rate
from watermark.dwt_dct_watermark import embed_bits, extract_bits
from watermark.payload import generate_watermark_id, bytes_to_bits, bits_to_bytes


def main() -> None:
    image = make_synthetic_document()
    watermark_id = generate_watermark_id()
    bits = bytes_to_bits(watermark_id)
    marked = np.clip(embed_bits(image.astype(np.float64), bits, delta=60.0, repeat=40), 0, 255).astype(np.uint8)
    distortion = float(np.mean(np.abs(marked.astype(np.float64) - image.astype(np.float64))))
    assert distortion < 1.5, f"Mean absolute pixel distortion is too high: {distortion:.3f}"

    results = {}
    for quality in (95, 75, 50, 30, 20, 15):
        compressed = jpeg_round_trip(marked, quality).astype(np.float64)
        extracted = extract_bits(compressed, len(bits), repeat=40)
        results[quality] = bit_error_rate(bits, extracted)
        assert bits_to_bytes(extracted) == watermark_id, f"DWT-DCT extraction failed at JPEG q={quality}"

    print(f"DWT-DCT synthetic test passed; mean absolute pixel change={distortion:.3f}/255.")
    print("JPEG bit error rates:", results)


if __name__ == "__main__":
    main()
