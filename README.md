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

1. Set a fresh API key of at least 32 bytes in the shell used for every Compose command. In PowerShell:

   ```powershell
   $env:SIGILCHAIN_API_KEY = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
   ```

   Keep this secret out of Git and share it only with authorized offline clients.
2. Build images on a connected staging machine: `docker compose --profile tools build`.
3. Start validators and console: `docker compose --profile local-ui up -d --no-build --pull never`.
4. Pin validator fingerprints after out-of-band checks: `docker compose --profile tools run --rm cli python scripts/pin_validators.py --out /data/trust/validator_trust.json`.
5. Enroll each recipient: `docker compose --profile tools run --rm cli python -m sigilchain.cli enroll --as alice`.
6. Put source files under `./cli-data`, then encrypt: `docker compose --profile tools run --rm cli python -m sigilchain.cli encrypt --input /data/source.docx --recipients alice,bob --out /data/package.json`.
7. Decrypt as the recipient: `docker compose --profile tools run --rm cli python -m sigilchain.cli decrypt --package /data/package.json --as alice --doc-id memo-001`.
8. Upload the marked PDF or a page image to `http://127.0.0.1:8501` and download its JSON evidence bundle.

The recipient CLI stores local private keys under `./cli-data/local_keys`; keep
that directory on the recipient's device. Never put private keys, passphrases,
databases, packages, or personal demo content in Git.

For larger recipient groups, create `./cli-data/recipients.txt` with one recipient
ID per line (blank lines and lines beginning with `#` are ignored), then pass
`--recipients-file /data/recipients.txt` instead of `--recipients`. You can
combine both options; duplicate IDs are removed while preserving their order.
When resolving public keys from validator nodes, add `--remote-identities` and,
if needed, `--nodes http://validator1:8001,http://validator2:8002,http://validator3:8003`.

The trace console accepts files up to 50 MiB and processes at most 100 pages or
frames and 120 million grayscale raster pixels per document to limit memory use.

## Security model and operational limits

- ML-KEM-768 (FIPS 203) wraps the AES content key; ML-DSA-65 (FIPS 204) signs recipient event claims and validator receipts.
- AES-256-GCM encrypts the canonical PDF once. Each authorized recipient gets a separate KEM envelope.
- Three etcd members use Raft ordering. A write needs two members; the system also requires two distinct signed validator receipts. Raft tolerates crash/unavailable members, not Byzantine behavior.
- The Compose demo runs all members on one Docker host. It is a shared failure domain and does not meet a strong “no single administrator can alter anything” guarantee against a host administrator. For stronger deployment, separate validators and protect signing keys on independent hosts/hardware.
- The trace console requires pinned validator keys and a configured quorum. Missing keys, invalid signatures, broken proofs, or insufficient receipts are inconclusive/fail closed.
- Validator APIs require the same operator-managed 32-byte-minimum `SIGILCHAIN_API_KEY` across clients and validator containers; missing configuration fails closed. The key is shared through the offline environment, not a cloud KMS.
- For rotation, set the new `SIGILCHAIN_API_KEY` and temporarily set the old value as `SIGILCHAIN_API_KEY_PREVIOUS` for validators and clients, then recreate the Compose services. Once all clients use the new key, remove `SIGILCHAIN_API_KEY_PREVIOUS` and recreate services again. If configured, the previous key must also be at least 32 bytes.
- Watermarks use repeated DCT carriers and Reed–Solomon coding. The optional Haar DWT + DCT mode is experimental. Photo correction is experimental; no camera-capture resistance is claimed without tests on that exact transformation.

## Offline transfer

Build/export on a connected staging machine, then transfer the bundle:

```powershell
.\scripts\export_airgap_bundle.ps1
# copy dist\airgap to the isolated host
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
meaningful offline identity check. For the Compose network, run it in the CLI
container with `--identity-db /data/shared/identity_registry.db` and
`--validator-trust /data/trust/validator_trust.json`. Operators can require a
higher receipt count with `--required-quorum 3`; this setting can raise but
cannot lower the verifier's local minimum.
