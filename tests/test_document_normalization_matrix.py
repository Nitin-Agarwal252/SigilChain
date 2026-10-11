"""Synthetic-input normalization coverage for the supported input matrix."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

import pymupdf as fitz
from PIL import Image

from crypto.normalize_document import (
    DocumentNormalizationError,
    IMAGE_FORMATS,
    OFFICE_FORMATS,
    normalize_to_pdf,
)


class DocumentNormalizationMatrixTests(unittest.TestCase):
    def test_pdf_is_validated_and_preserved(self):
        document = fitz.open()
        document.new_page()
        source_bytes = document.tobytes()
        document.close()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.pdf"
            source.write_bytes(source_bytes)
            self.assertEqual(normalize_to_pdf(source), source_bytes)

    def test_common_raster_formats_become_one_page_pdf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for extension, save_format in (("png", "PNG"), ("jpg", "JPEG"), ("tiff", "TIFF"), ("webp", "WEBP")):
                with self.subTest(extension=extension):
                    source = root / f"fixture.{extension}"
                    Image.new("RGB", (80, 60), "white").save(source, format=save_format)
                    result = normalize_to_pdf(source)
                    with fitz.open(stream=result, filetype="pdf") as normalized:
                        self.assertEqual(normalized.page_count, 1)

    @unittest.skipUnless(shutil.which("soffice") or shutil.which("libreoffice"), "LibreOffice is required")
    def test_text_and_csv_convert_when_libreoffice_is_available(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {
                "brief.txt": "Synthetic normalization fixture",
                "brief.md": "# Synthetic normalization fixture",
                "brief.html": "<!doctype html><p>Synthetic normalization fixture</p>",
                "brief.csv": "name,value\nfixture,1\n",
            }
            for name, content in cases.items():
                with self.subTest(name=name):
                    source = root / name
                    source.write_text(content, encoding="utf-8")
                    result = normalize_to_pdf(source)
                    with fitz.open(stream=result, filetype="pdf") as normalized:
                        self.assertGreaterEqual(normalized.page_count, 1)

    def test_unsupported_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "fixture.bin"
            source.write_bytes(b"synthetic")
            with self.assertRaisesRegex(DocumentNormalizationError, "Unsupported source format"):
                normalize_to_pdf(source)

    def test_declared_format_sets_match_normalizer_allowlist(self):
        self.assertIn(".png", IMAGE_FORMATS)
        self.assertIn(".docx", OFFICE_FORMATS)
        self.assertIn(".pdf", {".pdf", *IMAGE_FORMATS, *OFFICE_FORMATS})


if __name__ == "__main__":
    unittest.main()
