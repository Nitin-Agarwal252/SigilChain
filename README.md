# SigilChain

SigilChain is an offline-oriented prototype for distributing one encrypted
document to multiple recipients and returning a uniquely marked PDF after each
recipient decryption. A random per-session watermark joins the marked copy to a
recipient-key-signed event claim and validator evidence.

**Attribution boundary:** this records that a registered signing key signed an
event claim and that validators committed it. It does not independently prove
that a human decrypted the file, who physically distributed a leak, or when an
event occurred according to a trusted clock.

The original input stays at its source path. The encrypted content is a
canonical PDF. Decryption produces a **rasterized, watermarked PDF**, not a
watermarked DOCX, spreadsheet, or the original editable file. Retain the
original separately when needed.

## Quick start

1. Build images on a connected staging machine with `docker compose --profile tools build`.
2. Start the validators and trace console with `docker compose --profile local-ui up -d`.
3. Pin validator fingerprints out of band with `python scripts/pin_validators.py`.
4. Enroll each recipient: `python -m sigilchain.cli enroll --as alice`.
5. Encrypt: `python -m sigilchain.cli encrypt --input ./source.docx --recipients alice,bob --out ./package.json`.
6. On the recipient's device, decrypt: `python -m sigilchain.cli decrypt --package ./package.json --as alice --doc-id memo-001`.
7. Upload the marked PDF or a page image to `http://127.0.0.1:8501` and download the JSON evidence bundle.

In Docker, the recipient CLI is available with `docker compose --profile tools run --rm cli python -m sigilchain.cli ...`; mount or copy the recipient's own `local_keys` and source/package files under `./cli-data`. Never put private keys, passphrases, databases, packages, or demo content in Git.

## Security model and operational limits

- ML-KEM-768 (FIPS 203) wraps the AES content key; ML-DSA-65 (FIPS 204) signs recipient event claims and validator receipts.
- AES-256-GCM encrypts the canonical PDF once. Each authorized recipient gets a separate KEM envelope.
- Three etcd members use Raft ordering. A write needs two members; the system also requires two distinct signed validator receipts. Raft tolerates crash/unavailable members, not Byzantine behavior.
- The Compose demo runs all members on one Docker host. It is a shared failure domain and does not meet a strong “no single administrator can alter anything” guarantee against a host administrator. For stronger deployment, separate validators and protect signing keys on independent hosts/hardware.
- The trace console requires pinned validator keys and a configured quorum. Missing keys, invalid signatures, broken proofs, or insufficient receipts are inconclusive/fail closed.
- Watermarks use repeated DCT carriers and Reed–Solomon coding. The optional Haar DWT + DCT mode is experimental. Photo correction is experimental; no camera-capture resistance is claimed without tests on that exact transformation.

## Offline transfer

Build/export on a connected staging machine, then transfer the bundle:

```powershell
.\scripts\export_airgap_bundle.ps1
# copy dist\airgap to the isolated host
.
```

On the isolated Docker host, from the transferred directory:

```powershell
.\import_airgap_bundle.ps1
```

Import verifies the image archive checksum, loads prebuilt images, and starts
Compose with `--no-build --pull never`. The image build/export phase itself
requires dependencies/images to be available on the staging machine.

## Verification

See [BUILD_STATUS.md](BUILD_STATUS.md) for implementation and test status. The
portable evidence verifier is `python -m sigilchain.evidence path\bundle.json`
and requires a trusted identity registry and pinned validator roster for a
meaningful offline identity check.
