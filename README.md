# SigilChain

SigilChain is a prototype for encrypting documents for named recipients and
linking a recovered watermark to a signed decryption-session record. It is an
applied demonstration, not proof of who physically distributed a leaked file.

## Demo flow

1. Normalize a supported source document to a canonical PDF.
2. Encrypt the document once with AES-256-GCM and wrap its key separately for
   each recipient with ML-KEM-768.
3. A recipient decrypts with their locally protected key. The agent generates a
   fresh session watermark, embeds it on each page, builds an event claim, and
   signs that claim using the recipient's ML-DSA-65 key.
4. Three validator services use a shared three-member etcd/Raft log and return
   signed receipts. The configured receipt threshold is two of three.
5. The trace console extracts a watermark from a PDF or page image, verifies
   the corresponding event and proofs against pinned trust keys, and can export
   a JSON evidence bundle.

The recipient signature proves that the registered key signed the event claim.
The agent creates that claim after decryption in its intended flow, but the
signature alone does not independently prove the decryption happened. A
watermark match links a copy to the recorded session; it does not establish who
physically shared it. Identity depends on trusted enrollment and key custody.

## Cryptography and storage

- Document encryption: AES-256-GCM.
- Per-recipient key encapsulation: ML-KEM-768.
- Recipient event signatures: ML-DSA-65.
- Validator receipts: ML-DSA-65.
- Watermark: DCT by default, Reed–Solomon error correction, with optional
  one-level Haar DWT + DCT mode for evaluation.
- Local identity and validator state may use SQLite. The replicated ordered
  log is etcd/Raft, not SQLite. Raft tolerates a crashed/unavailable member; it
  is not Byzantine consensus. Three containers on one Docker host share a
  failure domain.

## Input and output formats

The normalizer accepts PDF, common Word/Writer, spreadsheet and presentation
formats, text, Markdown, HTML, CSV, and common raster images. Office/text
conversion uses LibreOffice; images use Pillow. Unsupported formats are
rejected. Pages are rasterized during watermarking and reassembled as a PDF, so
the output may not preserve searchable text or the exact original layout.
Keep the original source file separately. The output is not a watermarked
DOCX/spreadsheet.

Watermark robustness results are limited to the tests that were run. Synthetic
JPEG or aligned-damage tests do not establish reliable recovery from arbitrary
camera photographs, crops, perspective, or glare.

## Run locally with Docker Compose

From this directory:

```powershell
docker compose up --build -d
docker compose ps
```

The local console is served at `http://localhost:8501`. Run `demo.ps1` for the
staged offline flow. On first setup, compare validator fingerprints through a
trusted channel. Without an independent fingerprint source, label key pinning
as local demo setup rather than independent validator identity verification.

## Tests

With the project dependencies installed, run:

```powershell
python -m unittest discover -s tests -v
```

Automatic unittest discovery covers key lifecycle, document normalization,
watermark recovery, and the optional Raft integration checks. Some files named
`test_part*.py` are standalone scripts and are not run by unittest discovery.
Run them only in an isolated test environment. Raft integration tests append
synthetic ledger entries, so they are skipped unless
`SIGILCHAIN_TEST_ETCD_ENDPOINTS` points to a disposable cluster; never point
that variable at the live demo ledger.

## Air-gapped deployment

Build and export the images using `scripts/export_airgap_bundle.ps1`. Transfer
the resulting `dist/airgap` folder to the isolated Docker host and run
`import_airgap_bundle.ps1` there. Then run `demo.ps1` from the project root or
from inside `dist/airgap` for the staged end-to-end flow. The script reuses the
bundle's prebuilt images with `--no-build --pull never`; it does not rebuild or
download anything. It intentionally excludes recipient private keys, local
databases, and other persistent state from the image archive. Recipient keys
and demo files remain in the bundle's local `cli-data` folder. A successful
local Docker run alone does not prove deployment on a disconnected machine.

## Repository hygiene

Local keys, validator trust files, SQLite databases, encrypted demo packages,
decrypted documents, and air-gap image archives are excluded by `.gitignore`.
Generated demo media is not part of the source tree. Never commit passphrases
or private keys.
