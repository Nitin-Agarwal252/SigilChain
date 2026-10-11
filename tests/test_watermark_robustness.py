"""Conservative DCT watermark round-trip checks on synthetic page-like pixels."""

from __future__ import annotations

import unittest

import cv2
import numpy as np

from watermark.dct_watermark import embed_bits, extract_bits


def synthetic_page(height: int = 1200, width: int = 1000) -> np.ndarray:
    """Create text-like structure and light noise without using a real page."""
    image = np.full((height, width), 250, dtype=np.uint8)
    cv2.putText(image, "SIGILCHAIN SYNTHETIC TEST", (60, 80), cv2.FONT_HERSHEY_SIMPLEX, 1.0, 20, 2, cv2.LINE_AA)
    for y in range(140, height - 60, 38):
        cv2.line(image, (60, y), (width - 80 - (y % 120), y), 70, 1, cv2.LINE_AA)
    rng = np.random.default_rng(17)
    noise = rng.normal(0, 1.0, image.shape)
    return np.clip(image.astype(np.float32) + noise, 0, 255).astype(np.uint8)


class WatermarkRobustnessTests(unittest.TestCase):
    payload = [int(bit) for bit in "1011001010010110"]
    repeat = 20

    def _embed(self) -> np.ndarray:
        source = synthetic_page()
        marked = embed_bits(source.astype(np.float64), self.payload, delta=110.0, repeat=self.repeat)
        return np.clip(marked, 0, 255).astype(np.uint8)

    def test_payload_survives_lossless_png_round_trip(self):
        marked = self._embed()
        ok, encoded = cv2.imencode(".png", marked)
        self.assertTrue(ok)
        decoded = cv2.imdecode(encoded, cv2.IMREAD_GRAYSCALE)
        self.assertEqual(extract_bits(decoded, len(self.payload), repeat=self.repeat), self.payload)

    def test_payload_survives_moderate_jpeg_recompression(self):
        marked = self._embed()
        ok, encoded = cv2.imencode(".jpg", marked, [cv2.IMWRITE_JPEG_QUALITY, 92])
        self.assertTrue(ok)
        decoded = cv2.imdecode(encoded, cv2.IMREAD_GRAYSCALE)
        self.assertEqual(extract_bits(decoded, len(self.payload), repeat=self.repeat), self.payload)


if __name__ == "__main__":
    unittest.main()
