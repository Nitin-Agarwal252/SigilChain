# SigilChain build status

This file tracks what is implemented and what has actually been verified. A
feature is not marked verified until its check has been run successfully.

## Component map

| Component | Location | Responsibility |
|---|---|---|
| Recipient keys and identity registry | `sigilchain/identity.py` | Local passphrase-protected ML-KEM-768 and ML-DSA-65 keys; public identity records; key lifecycle. |
| Document normalization and hybrid encryption | `sigilchain/documents.py`, `sigilchain/crypto.py` | Convert supported inputs to validated PDF, encrypt once with AES-256-GCM, wrap content key per recipient with ML-KEM-768. |
| Decrypt, watermark, and claim | `sigilchain/agent.py`, `sigilchain/watermark.py` | Decrypt for recipient, rasterize, embed session watermark, sign canonical claim, submit before release. |
| Validator and shared ledger | `sigilchain/validator.py`, `sigilchain/ledger.py` | Verify recipient signatures, commit ordered records through etcd/Raft, issue ML-DSA validator receipts. |
| Trace and evidence | `sigilchain/trace.py`, `sigilchain/evidence.py` | Extract marks from pages/images, verify quorum evidence and build portable JSON evidence bundle. |
| Offline deployment | `docker-compose.yml`, `Dockerfile`, `scripts/` | Three validators, three-member etcd cluster, local console, and export/import image bundle. |

## Acceptance checklist

- [x] Normalize PDF, Office, text/HTML/CSV/Markdown, and raster images; reject unsupported inputs and retain the source separately.
- [x] Enroll identities with passphrase-protected private keys; rotate and revoke keys.
- [x] Encrypt a canonical PDF once with AES-256-GCM and envelope the content key separately using ML-KEM-768.
- [x] Require Reed–Solomon coding and DCT watermarking during decrypt; keep optional Haar DWT + DCT experimental.
- [x] Sign a deterministic event claim with the recipient's ML-DSA-65 key; document what that signature does and does not prove.
- [x] Commit to three-member etcd/Raft ordering and require 2-of-3 distinct ML-DSA validator receipts; independently verify hash-chain proofs and pinned keys.
- [x] Trace PDF and image uploads page by page; export JSON evidence; fail closed on malformed, tampered, untrusted, or sub-quorum evidence.
- [x] Start an imported bundle offline without package/image pulls; bind the local console to loopback by default.
- [ ] Run service, end-to-end, and full air-gap checks and record actual results below.

## Completed

- Confirmed the new path `C:\sigilproj2` is separate from the read-only reference project.
- Created the component map and acceptance checklist from the supplied SIH brief and reference interfaces.

## Incomplete

- Service-level, end-to-end, and full air-gap acceptance checks remain.

## Verified

- Python syntax compilation, Docker Compose configuration validation, and whitespace checks pass.
- Docker images build for both app and CLI targets using matching liboqs 0.16.0 and liboqs-python 0.16.0.1.
- Container unit acceptance suite passes: 13 tests covering ML-KEM/ML-DSA flows, identity/key lifecycle, file normalization, DCT/DWT-DCT watermark round trips, JPEG recompression, evidence tampering, hash-chain tampering, and fail-closed ledger outages.

## Known limitations

- Any successful match attributes a leaked copy to a signed session claim; it does not prove who physically distributed the copy or provide a trusted timestamp.
- etcd/Raft is crash-fault consensus. Three containers on one Docker host share a failure domain.
- Watermark robustness claims will be limited to transformations actually exercised in the tests.
