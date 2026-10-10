"""Normalize supported source documents to validated canonical PDF bytes."""
from __future__ import annotations

import html
import shutil
import subprocess
import tempfile
from pathlib import Path

import pymupdf
from PIL import Image, ImageSequence

OFFICE = {".doc", ".docx", ".odt", ".rtf", ".txt", ".md", ".html", ".htm",
          ".csv", ".xls", ".xlsx", ".ods", ".ppt", ".pptx", ".odp"}
IMAGES = {".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp"}
SUPPORTED = OFFICE | IMAGES | {".pdf"}


class DocumentError(ValueError):
    pass


def _validate(data: bytes, name: str) -> bytes:
    try:
        with pymupdf.open(stream=data, filetype="pdf") as pdf:
            if pdf.page_count < 1:
                raise DocumentError(f"{name} contains no pages.")
    except DocumentError:
        raise
    except Exception as exc:
        raise DocumentError(f"{name} did not produce a readable PDF: {exc}") from exc
    if not data.startswith(b"%PDF-"):
        raise DocumentError(f"{name} is not a valid PDF.")
    return data


def _image_pdf(path: Path) -> bytes:
    try:
        with Image.open(path) as image:
            pages = [frame.convert("RGB") for frame in ImageSequence.Iterator(image)]
            if not pages:
                raise DocumentError("Image input has no frames.")
            from io import BytesIO
            output = BytesIO()
            pages[0].save(output, format="PDF", save_all=True, append_images=pages[1:])
            return _validate(output.getvalue(), path.name)
    except DocumentError:
        raise
    except Exception as exc:
        raise DocumentError(f"Could not convert image {path.name}: {exc}") from exc


def _office_pdf(path: Path, timeout: int = 90) -> bytes:
    converter = shutil.which("soffice") or shutil.which("libreoffice")
    if not converter:
        raise DocumentError(f"{path.suffix} conversion requires LibreOffice (soffice).")
    with tempfile.TemporaryDirectory(prefix="sigilchain-lo-") as work:
        root = Path(work)
        source = path
        if path.suffix.lower() == ".md":
            source = root / "markdown.html"
            source.write_text("<!doctype html><meta charset='utf-8'><pre>" +
                              html.escape(path.read_text(encoding="utf-8", errors="replace")) +
                              "</pre>", encoding="utf-8")
        out = root / "out"
        out.mkdir()
        profile = (root / "profile").as_uri()
        try:
            result = subprocess.run([converter, "--headless", f"-env:UserInstallation={profile}",
                "--convert-to", "pdf", "--outdir", str(out), str(source)],
                capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired as exc:
            raise DocumentError(f"LibreOffice timed out converting {path.name}.") from exc
        produced = out / f"{source.stem}.pdf"
        if result.returncode or not produced.is_file():
            raise DocumentError(f"LibreOffice failed to convert {path.name}: {(result.stderr or result.stdout).strip()}")
        return _validate(produced.read_bytes(), path.name)


def normalize(input_path: str | Path, timeout: int = 90) -> bytes:
    path = Path(input_path)
    if not path.is_file():
        raise DocumentError(f"Input file does not exist: {path}")
    ext = path.suffix.lower()
    if ext not in SUPPORTED:
        raise DocumentError(f"Unsupported input type {ext or '(no extension)'}. Supported: {', '.join(sorted(SUPPORTED))}")
    if ext == ".pdf":
        return _validate(path.read_bytes(), path.name)
    if ext in IMAGES:
        return _image_pdf(path)
    return _office_pdf(path, timeout)
