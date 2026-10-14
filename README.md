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
   fresh package for the next recipient. The sender signs the offer with
   ML-DSA-65. Before forwarding, the current holder also signs an acceptance
   for the exact incoming package and receives their own marked, quorum-recorded
   PDF; these events are committed through the validator quorum before the next
   package is released. One acceptance can anchor multiple outgoing branches,
   such as B → C and B → D.
4. The final recipient decrypts with their locally protected key. The agent
   creates a fresh session watermark, embeds it on every page, and submits a
   recipient-key-signed session claim to the validators. The marked PDF is
   released only after quorum commit.
5. Three validator services use a shared three-member etcd/Raft log and return
   signed receipts. The configured receipt threshold is two of three. The trace
   console extracts a watermark from the marked PDF or page image, verifies
   the session, validator proofs, and handoff acceptances, then exports a JSON
   evidence bundle. It can also show quorum-verified outgoing branches from
   the recipient's session.

Run `scripts/export_airgap_bundle.ps1` after source changes to rebuild the
container images, then run `demo.ps1` to show the colored, narrated flow. It
checks validator trust, enrolls the default path (`nitin` → `ashish` →
`rahul_demo`) plus the `deepa_demo` branch recipient, creates a 2-of-3
governance roster and approved state baseline, commits the two transfer
branches, decrypts both leaf packages, seals and verifies a ledger checkpoint,
and opens the trace console with an Ashish-session page image ready to upload.
The governance setup is included by default for a fresh demo; `-SkipGovernance`
omits that stage. If governance has already been committed to the persistent
stack, keep its roster hash and do not disable enforcement. The demo stores its
local governance keys under `dist/airgap/cli-data/governance`; for real
independent approvals, keep approver keys on separate machines and bring only
the signed approval files to the service host. A same-host run demonstrates the
workflow, not independent administrator control.

On a fresh installation, use fresh IDs or the defaults and select the optional combined watermark transform:

```powershell
.\scripts\export_airgap_bundle.ps1
.\demo.ps1 -InputFile '.\ISRO -Hackathon.pdf' -Recipients @('nitin_run2','ashish_run2','rahul_run2') -DecryptAs 'rahul_run2' -BranchRecipient 'deepa_run2'
```

For example, add `-WatermarkTransform 'dwt-dct'` to that command to use the optional combined transform.
The output explains each stage with color-coded messages; passphrase input is
hidden. The final trace upload is Ashish's marked session and should display
the committed branches. It does not prove who physically distributed the
file. OIDC and TPM integrations are described separately because they require
an identity provider and an independent TPM quote verifier, respectively.
Every sender, branch recipient, and decryptor needs the matching local private
key and passphrase. A forgotten private-key passphrase cannot be recovered. On
a stack where governance was already enabled, use already enrolled IDs or
complete an approved `identity.enroll` change first; the demo refuses to bypass
governance to enroll a new recipient. For a clean fresh-ID repeat, use a fresh
installation with fresh persistent volumes.

The recipient signature proves that the registered key signed the event claim.
The agent creates that claim after decryption in its intended flow, but the
signature alone does not independently prove the decryption happened. A
watermark match links a copy to the recorded session; it does not establish who
physically shared it. Identity depends on trusted enrollment and key custody.
The official CLI records an acceptance only after successful decryption, and
the recipient's registered key signs an acknowledgment bound to that exact
package. The signature itself proves the key signed the claim; it does not
independently prove decryption. It helps reconstruct branches and event order,
but does not prove the human personally opened the file or identify the person
who leaked it. A leak from B's watermarked session can be associated with B's
key; later B → C and B → D offers appear as separate branches and do not
overwrite that association.
This depends on the leaked copy being the marked PDF produced by the official
decrypt/forward flow; a plaintext copy made outside that flow has no SigilChain
watermark to recover.

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
command; the `--to` identity needs only its registered public key. The sender
signs the handoff offer and the receiving key signs an acceptance after the
exact package is decrypted. A subsequent transfer must reference the accepted
parent package, so branches remain distinct. Acceptance is key-level evidence;
it does not prove human identity, physical delivery, or who distributed a leak.

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

## Administrator change approvals (prototype)

High impact identity operations can be put behind a threshold of separate
ML-DSA-65 governance keys. The default stays off, so the existing demo setup
continues to run as before. With the gate enabled, start the validators with
`SIGILCHAIN_REQUIRE_GOVERNANCE_APPROVALS=1` and configure their
`SIGILCHAIN_GOVERNANCE_ROSTER` to the same roster. Governance enforcement now
requires its exact file hash in `SIGILCHAIN_GOVERNANCE_ROSTER_SHA256`; provision
that expected hash through deployment configuration controlled outside the
validator host. The official `apply` command submits each approved change to
the validator quorum before applying it locally.

Create distinct governance keys on the approvers' separate machines/accounts;
never copy a private governance key to the service host:

```powershell
python scripts/governance_cli.py keygen --id admin-a --out governance/admin-a.key.json
python scripts/governance_cli.py keygen --id admin-b --out governance/admin-b.key.json
python scripts/governance_cli.py keygen --id admin-c --out governance/admin-c.key.json
python scripts/governance_cli.py roster --keys governance/admin-a.pub.json governance/admin-b.pub.json governance/admin-c.pub.json --threshold 2 --out governance/roster.json
```

Copy the public roster into the Compose trust volume, then place the printed
SHA-256 in deployment configuration before restarting validators:

```powershell
Copy-Item governance\roster.json .\cli-data\governance_roster.json
docker compose --profile tools run --rm cli python scripts/governance_cli.py install-roster --roster /data/governance_roster.json
$env:SIGILCHAIN_GOVERNANCE_ROSTER_SHA256 = "<hash printed by install-roster>"
$env:SIGILCHAIN_REQUIRE_GOVERNANCE_APPROVALS = "1"
docker compose up -d --force-recreate validator1 validator2 validator3
```

Approver private keys stay on their separate machines. The approvals and
proposal files can be transferred without transferring those private keys.
For first-time genesis setup, enroll the demo recipients and pin the validator
keys while governance mode is off, then enable it, restart validators, and
capture/approve/apply the baseline snapshot above. The approved snapshot is the
point where the new threshold policy begins; it is not retroactive proof of
how the initial registry was created.

For a proposed identity change, each approver runs `approve` on the same
proposal file, then an operator combines and applies the approvals:

```powershell
python scripts/governance_cli.py approve --action governance-proposals\ACTION.json --key governance/admin-a.key.json --out approvals\admin-a.json
python scripts/governance_cli.py approve --action governance-proposals\ACTION.json --key governance/admin-b.key.json --out approvals\admin-b.json
python scripts/governance_cli.py merge --action governance-proposals\ACTION.json --approvals approvals\admin-a.json approvals\admin-b.json --out approvals\combined.json
python scripts/governance_cli.py apply --action governance-proposals\ACTION.json --approvals approvals\combined.json --roster governance/roster.json
```

Before governed changes, create and commit one threshold-approved state
snapshot. It captures the existing public identities, key history, and pinned
validator keys at the current ledger head:

```powershell
python scripts/governance_cli.py snapshot --out governance/state-snapshot.json
python scripts/governance_cli.py approve --action governance/state-snapshot.json --key governance/admin-a.key.json --out approvals/admin-a.json
python scripts/governance_cli.py approve --action governance/state-snapshot.json --key governance/admin-b.key.json --out approvals/admin-b.json
python scripts/governance_cli.py merge --action governance/state-snapshot.json --approvals approvals/admin-a.json approvals/admin-b.json --out approvals/snapshot.json
python scripts/governance_cli.py apply --action governance/state-snapshot.json --approvals approvals/snapshot.json --roster governance/roster.json
```

After that, validators validate the full hash chain and threshold signatures
at startup, then rebuild the identity registry and validator trust file from
the latest approved snapshot plus later committed governance events. Ordinary
governed mutations are refused until a baseline exists. Direct edits to those
working files are repaired from the log on restart. Keep the governance roster
and its expected hash under control separate from the app host; otherwise a
host administrator can replace both the roster and the code and bypass this
prototype control. Once a governance event exists in the ledger, validators
refuse to start if governance enforcement is switched off.

To make a portable checkpoint that can reveal a later rollback, capture a
head agreed by the validator quorum, have the governance key holders approve
it, seal it, and store the sealed JSON away from the SigilChain host:

```powershell
python scripts/checkpoint_cli.py capture --out governance/checkpoint-action.json
python scripts/governance_cli.py approve --action governance/checkpoint-action.json --key governance/admin-a.key.json --out approvals/checkpoint-a.json
python scripts/governance_cli.py approve --action governance/checkpoint-action.json --key governance/admin-b.key.json --out approvals/checkpoint-b.json
python scripts/governance_cli.py merge --action governance/checkpoint-action.json --approvals approvals/checkpoint-a.json approvals/checkpoint-b.json --out approvals/checkpoint.json
python scripts/checkpoint_cli.py seal --action governance/checkpoint-action.json --approvals approvals/checkpoint.json --roster governance/roster.json --out checkpoint.json
```

On a later check, run `python scripts/checkpoint_cli.py verify --checkpoint
checkpoint.json --roster governance/roster.json`. It confirms the held checkpoint
is still an ancestor of the head returned by a validator quorum. This detects
rollback behind that checkpoint; it does not detect a compromise that happened
before the checkpoint was kept elsewhere, and it is not TPM boot attestation.

Optional OIDC person-authentication and independent TPM-verifier enforcement
are documented in [SECURITY-IMPLEMENTATION-NOTES.md](SECURITY-IMPLEMENTATION-NOTES.md).
The default local/offline demo leaves both controls disabled. TPM mode requires
a separately deployed verifier that validates real TPM quotes against a
trusted hardware/boot profile; the repository contains the fail-closed client
and signed evidence integration, not that verifier service.

## Repository hygiene

Local keys, validator trust files, SQLite databases, encrypted demo packages,
decrypted documents, and air-gap image archives are excluded by `.gitignore`.
Generated demo media is not part of the source tree. Never commit passphrases
or private keys.
