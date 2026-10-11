"""Convert supported source documents into a validated canonical PDF.

Text and office documents use LibreOffice's headless import/export filters;
raster images use Pillow. The supported extension list is intentionally
explicit: binary formats without a safe converter are rejected clearly.
"""

import html
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import pymupdf as fitz
from PIL import Image, ImageSequence

OFFICE_FORMATS = {
    ".doc", ".docx", ".odt", ".rtf", ".txt", ".md", ".html", ".htm",
    ".csv", ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".odp",
}
IMAGE_FORMATS = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}
SUPPORTED_FORMATS = {".pdf", *OFFICE_FORMATS, *IMAGE_FORMATS}


class DocumentNormalizationError(ValueError):
    pass


def _validate_pdf(data: bytes, source: str) -> bytes:
    try:
        with fitz.open(stream=data, filetype="pdf") as document:
            if document.page_count < 1:
                raise DocumentNormalizationError(f"{source} contains no pages")
    except DocumentNormalizationError:
        raise
    except Exception as exc:
        raise DocumentNormalizationError(f"{source} did not produce a readable PDF: {exc}") from exc
    if not data.startswith(b"%PDF-"):
        raise DocumentNormalizationError(f"{source} is not a valid PDF file")
    return data


def _images_to_pdf(path: Path) -> bytes:
    try:
        with Image.open(path) as source:
            frames = [frame.convert("RGB") for frame in ImageSequence.Iterator(source)]
            if not frames:
                raise DocumentNormalizationError("Image has no frames")
            from io import BytesIO
            output = BytesIO()
            frames[0].save(output, format="PDF", save_all=True, append_images=frames[1:])
            return _validate_pdf(output.getvalue(), path.name)
    except DocumentNormalizationError:
        raise
    except Exception as exc:
        raise DocumentNormalizationError(f"Could not convert image {path.name}: {exc}") from exc


def _office_to_pdf(path: Path, timeout: int) -> bytes:
    soffice = shutil.which("soffice") or shutil.which("libreoffice")
    if not soffice:
        raise DocumentNormalizationError(
            f"Converting {path.suffix} requires LibreOffice (soffice); install it or use a supported PDF/image input."
        )
    with tempfile.TemporaryDirectory(prefix="sigilchain-convert-") as work:
        work_path = Path(work)
        source = path
        # LibreOffice does not import Markdown as a first-class format. Render
        # it as escaped preformatted text so layout cannot interpret raw HTML.
        if path.suffix.lower() == ".md":
            source = work_path / "source.html"
            source.write_text("<!doctype html><meta charset='utf-8'><pre>" +
                              html.escape(path.read_text(encoding="utf-8", errors="replace")) +
                              "</pre>", encoding="utf-8")
        out_dir = work_path / "out"
        out_dir.mkdir()
        profile = (work_path / "profile").as_uri()
        command = [soffice, "--headless", f"-env:UserInstallation={profile}",
                   "--convert-to", "pdf", "--outdir", str(out_dir), str(source)]
        try:
            result = subprocess.run(command, capture_output=True, text=True,
                                     timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise DocumentNormalizationError(f"LibreOffice timed out converting {path.name}") from exc
        pdf_path = out_dir / f"{source.stem}.pdf"
        if result.returncode != 0 or not pdf_path.is_file():
            detail = (result.stderr or result.stdout).strip() or "no conversion output"
            raise DocumentNormalizationError(f"LibreOffice could not convert {path.name}: {detail}")
        return _validate_pdf(pdf_path.read_bytes(), path.name)


def normalize_to_pdf(input_path: str | os.PathLike, timeout: int = 90) -> bytes:
    """Return validated PDF bytes from a supported input file."""
    path = Path(input_path)
    if not path.is_file():
        raise DocumentNormalizationError(f"Input file does not exist: {path}")
    extension = path.suffix.lower()
    if extension not in SUPPORTED_FORMATS:
        supported = ", ".join(sorted(ext.lstrip(".") for ext in SUPPORTED_FORMATS))
        raise DocumentNormalizationError(
            f"Unsupported source format '{extension or '(no extension)'}'. Supported formats: {supported}."
        )
    if extension == ".pdf":
        return _validate_pdf(path.read_bytes(), path.name)
    if extension in IMAGE_FORMATS:
        return _images_to_pdf(path)
    return _office_to_pdf(path, timeout)
