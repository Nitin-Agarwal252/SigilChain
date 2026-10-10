"""Upload parsing and resource limits for the trace pipeline."""
from __future__ import annotations

import io
import unittest
from unittest.mock import patch

import pymupdf
from PIL import Image

from sigilchain.trace import TraceInputError, image_pages


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


if __name__ == "__main__":
    unittest.main()
