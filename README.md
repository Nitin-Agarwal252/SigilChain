# SigilChain

SigilChain is a prototype for encrypting documents for named recipients and
linking a recovered watermark to a signed decryption-session record. It is an
applied demonstration, not proof of who physically distributed a leaked file.

## Demo flow

1. Normalize a supported source document to a canonical PDF.
2. Create a recipient package using ML-KEM-768 encapsulation, HKDF-SHA256,
   and AES-256-GCM. The sender signs the versioned package manifest with
   ML-DSA-65; the signature binds the document hash, recipient key versions,
   and encrypted key envelopes.
3. For each onward handoff, the current holder decrypts locally and creates a
   fresh package for the next recipient. Their ML-DSA-65-signed handoff record
   binds package and document hashes and is committed through the validator
   quorum before the next package is released.
4. The final recipient decrypts with their locally protected key. The agent
   creates a fresh session watermark, embeds it on every page, and submits a
   recipient-key-signed session claim to the validators. The marked PDF is
   released only after quorum commit.
5. Three validator services use a shared three-member etcd/Raft log and return
   signed receipts. The configured receipt threshold is two of three. The trace
   console extracts a watermark from the marked PDF or page image, verifies
   the session, validator proofs, and available handoff chain, then exports a
   JSON evidence bundle.

Run `demo.ps1` to show the complete A → B → C path with the default identities
`nitin`, `ashish`, and `rahul_demo`. The final trace should show both signed,
quorum-committed handoffs. Every sender and the final decryptor needs the
matching local private key and passphrase. Choose a fresh recipient ID if an
old private-key passphrase has been lost.

The recipient signature proves that the registered key signed the event claim.
The agent creates that claim after decryption in its intended flow, but the
signature alone does not independently prove the decryption happened. A
watermark match links a copy to the recorded session; it does not establish who
physically shared it. Identity depends on trusted enrollment and key custody.

## Cryptography and storage

- Document encryption: AES-256-GCM.
- Per-recipient key encapsulation: ML-KEM-768.
- Package-manifest, recipient event, and transfer-event signatures: ML-DSA-65.
- Package v2 binds document and key-wrap metadata as AES-GCM associated data,
  derives recipient-specific wrap keys with HKDF-SHA256, checks the plaintext
  SHA-256 after decrypt, and rejects unsigned or altered v2 manifests. Legacy
  v1 packages remain readable for compatibility but lack these v2 checks.
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

### Logged transfer path

The existing stack's `cli` service can create a first handoff from a source
document and continue a chain from a received package. Replace the IDs and
paths with enrolled identities and your document:

```powershell
docker compose --profile tools run --rm cli python agent/cli.py transfer `
  --input /data/source.pdf --from alice --to bob --doc-id case-001 `
  --out /data/package-for-bob.json

docker compose --profile tools run --rm cli python agent/cli.py transfer `
  --package /data/package-for-bob.json --from bob --to carol `
  --doc-id case-001 --out /data/package-for-carol.json

docker compose --profile tools run --rm cli python agent/cli.py decrypt `
  --package /data/package-for-carol.json --as carol --doc-id case-001
```

Each `--from` identity must have its private key on the machine running the
command; the `--to` identity needs only its registered public key. The handoff
event is signed by the sending key and records the destination key version and
package/document hashes. It is evidence of a signed, committed handoff claim,
not proof that a person physically received the file. The receiver's later
signed decryption session establishes a separate event.

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
