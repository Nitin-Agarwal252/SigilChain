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
- [x] Run unit and service-outage checks, plus an end-to-end encrypt/decrypt/watermark/quorum/trace/evidence round trip.
- [ ] Validate transfer/import on a separate physically isolated host with pulls disabled.

## Completed

- Confirmed the new path `C:\sigilproj2` is separate from the read-only reference project.
- Created the component map and acceptance checklist from the supplied SIH brief and reference interfaces.

## Incomplete

- Full air-gap transfer/import validation remains.

## Verified

- Python syntax compilation, Docker Compose configuration validation, and whitespace checks pass.
- Docker images build for both app and CLI targets using matching liboqs 0.16.0 and liboqs-python 0.16.0.1.
- Container unit acceptance suite passes: 23 tests covering ML-KEM/ML-DSA flows, identity/key lifecycle, file normalization, DCT/DWT-DCT watermark round trips, JPEG recompression, trace upload limits and threshold validation, malformed validator claims, evidence tampering, hash-chain tampering, and fail-closed ledger outages.
- Container end-to-end acceptance test passes against the live Compose validators and etcd cluster: enroll identity, encrypt, decrypt, mark, collect quorum receipts, extract watermark, and verify portable evidence bundle.
- Evidence verification uses the greater of local policy, bundle-declared quorum, and any explicit operator override; a bundle cannot lower the verifier's local minimum. Regression test passes for both metadata and explicit-argument downgrade attempts.
- Validator submission and watermark lookup also enforce at least the local configured quorum; zero or invalid quorum requests fail closed.
- Recipient-signed v1 claims require an exact schema, valid recipient/document identifiers, positive integer key version and timestamp, a 12-byte hexadecimal watermark ID, a SHA-256 file digest, and well-formed hexadecimal signature/key material; both claim construction and verification reject malformed values. Regression and end-to-end suites pass.
- The offline evidence CLI accepts an operator-specified required receipt quorum; it can raise, but cannot lower, local policy.
- Public identity registration accepts only the exact public-field schema, supported PQC algorithms, safe recipient IDs, positive key versions, and correctly sized library-reported ML-KEM/ML-DSA public keys; malformed imports are rejected before registry writes.
- Encrypted-package decryption validates the v1 package/envelope schemas, recipient, nonce and ciphertext encodings, and PQC ciphertext size before decapsulation; malformed package structures fail with controlled errors.
- Document encryption validates each recipient identity's ID, key version, algorithm identifiers, and library-sized ML-KEM/ML-DSA public keys before encapsulating the content key.
- Trace uploads reject unsupported, empty, or over-50-MiB files and cap processing at 100 pages/frames and 120 million raster pixels per document before rendering; malformed inputs return clear errors.
- Trace confidence thresholds must be finite and within [0, 1]; passing an explicit empty validator list no longer falls back to configured nodes.
- Validator submission rejects malformed claim schemas before identity-registry lookup, returning HTTP 400 without touching the registry.
- Validator HTTP requests constrain watermark IDs and ML-DSA-65 signature hex fields to expected lengths before application-level claim validation.
- Validator submission parses v1 claims with a strict bounded model: exact schema literal, strict strings/integers, capped field lengths, and no unknown fields; semantic safe-ID and lowercase-hex checks still run before registry lookup.
- Validator HTTP request objects reject unknown top-level fields as well as unknown claim fields.
- Validator request models use Pydantic 2's explicit strict-model configuration and alias-aware serialization.
- Validator `/submit` requests with declared bodies over 16 KiB are rejected by middleware before JSON/model parsing; malformed or negative `Content-Length` values are rejected as bad requests.
- Malformed evidence structures (wrong top-level, claim, identity, evidence-list, and ledger-entry types) fail closed with verification errors rather than crashing the verifier.
- Same-host offline-import simulation passes: exported all required images, rejected a modified README before image loading, then loaded the clean archive and started Compose with `--no-build --pull never`; validator health returned 200 using the etcd-Raft backend.

## Known limitations

- Any successful match attributes a leaked copy to a signed session claim; it does not prove who physically distributed the copy or provide a trusted timestamp.
- etcd/Raft is crash-fault consensus. Three containers on one Docker host share a failure domain.
- Watermark robustness claims will be limited to transformations actually exercised in the tests.
- SHA-256 bundle checks detect accidental or uncoordinated file changes; the bundle manifest is not signed, so it does not authenticate the exporter against an attacker who can replace both files and checksums.
- The offline import was tested on the connected development host, not on a separate physically isolated machine.
