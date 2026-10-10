"""Upload parsing and resource limits for the trace pipeline."""
from __future__ import annotations

import io
import unittest
from unittest.mock import patch

import pymupdf
from PIL import Image

from sigilchain.trace import TraceInputError, image_pages, trace_page


class TraceInputTests(unittest.TestCase):
    def test_rejects_empty_oversized_and_unsupported_inputs(self):
        with self.assertRaises(TraceInputError):
            image_pages(b"", "leak.pdf")
        with patch("sigilchain.trace.MAX_TRACE_UPLOAD_BYTES", 2):
            with self.assertRaises(TraceInputError):
                image_pages(b"123", "leak.pdf")
        with self.assertRaises(TraceInputError):
            image_pages(b"not an image", "leak.exe")

    def test_rejects_pdf_page_count_before_rendering(self):
        with pymupdf.open() as document:
            document.new_page()
            document.new_page()
            pdf = document.tobytes()
        with patch("sigilchain.trace.MAX_TRACE_PAGES", 1):
            with self.assertRaises(TraceInputError):
                image_pages(pdf, "leak.pdf")

    def test_rejects_image_exceeding_total_pixel_budget(self):
        output = io.BytesIO()
        Image.new("RGB", (12, 12), "white").save(output, format="PNG")
        with patch("sigilchain.trace.MAX_TRACE_TOTAL_PIXELS", 100):
            with self.assertRaises(TraceInputError):
                image_pages(output.getvalue(), "leak.png")

    def test_rejects_invalid_confidence_thresholds(self):
        for threshold in (-0.01, 1.01, float("nan"), float("inf"), True, "0.72"):
            with self.subTest(threshold=threshold):
                with self.assertRaises(ValueError):
                    trace_page(None, threshold=threshold)

    def test_explicit_empty_validator_list_does_not_use_defaults(self):
        import numpy as np

        with patch("sigilchain.trace.extract_page", return_value=(b"a" * 12, 0.99)), \
                patch("sigilchain.trace.check_watermark", return_value=[]) as check:
            result = trace_page(np.zeros((8, 8), dtype=np.uint8), nodes=[])
        self.assertEqual(result["status"], "unverified")
        check.assert_called_once_with([], (b"a" * 12).hex())


if __name__ == "__main__":
    unittest.main()
