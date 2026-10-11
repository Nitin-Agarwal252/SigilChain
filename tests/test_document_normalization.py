import tempfile
import unittest
import shutil
from pathlib import Path

import pymupdf as fitz
from PIL import Image

from crypto.normalize_document import DocumentNormalizationError, normalize_to_pdf


class DocumentNormalizationTests(unittest.TestCase):
    def test_pdf_is_validated_and_preserved(self):
        doc = fitz.open()
        doc.new_page()
        original = doc.tobytes()
        doc.close()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.pdf"
            path.write_bytes(original)
            self.assertEqual(normalize_to_pdf(path), original)

    def test_png_is_converted_to_one_page_pdf(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scan.png"
            Image.new("RGB", (32, 24), "white").save(path)
            result = normalize_to_pdf(path)
            with fitz.open(stream=result, filetype="pdf") as document:
                self.assertEqual(document.page_count, 1)

    def test_unknown_extension_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret.bin"
            path.write_bytes(b"data")
            with self.assertRaisesRegex(DocumentNormalizationError, "Unsupported source format"):
                normalize_to_pdf(path)

    @unittest.skipUnless(shutil.which("soffice") or shutil.which("libreoffice"),
                         "LibreOffice is installed in the application image")
    def test_text_uses_office_conversion_filter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "briefing.txt"
            path.write_text("SigilChain normalization test", encoding="utf-8")
            result = normalize_to_pdf(path)
            with fitz.open(stream=result, filetype="pdf") as document:
                self.assertEqual(document.page_count, 1)
                self.assertIn("SigilChain", document[0].get_text())


if __name__ == "__main__":
    unittest.main()
