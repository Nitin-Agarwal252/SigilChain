# Security controls: implementation status and remaining work

## Implemented in the current source changes

- A transfer offer is sender-signed and commits the source/target package and
  document hashes.
- On an incoming transfer, the recipient's key signs an acceptance bound to
  that exact package. The validator checks the acceptance against the prior
  committed offer and verifies the recipient signature.
- A holder forwarding a received package gets a separate marked PDF and a
  signed, quorum-committed decryption-session record. The forwarded package
  remains bound to the accepted parent, and branches such as B → C and B → D
  are separate transfer events.
- The trace console verifies each offer and acceptance and can display the
  downstream branch tree. The offline evidence verifier checks the acceptance
  signatures, validator receipts, ledger proofs, and parent links.

The official CLI emits an acceptance only after successful decryption, and the
acceptance is bound to the exact package. The signature itself proves only that
the enrolled key signed that claim; it cannot independently prove decryption or
that the named human personally used the key. A recovered watermark associates
a marked copy with a signed session; it does not identify the physical distributor.

## Administrator approvals and state recovery: prototype controls added

The current Compose stack places all three validators, their keys, and the
shared etcd/Raft service on one host. Raft protects ordering when members crash;
it does not protect against an administrator who controls the host, application,
trust files, and storage. An opt-in application-level gate now supports
separate, passphrase-protected ML-DSA-65 governance keys and threshold approval
for identity enrollment, rotation, revocation, and validator trust-roster
updates through the official CLI/bootstrap script. Proposals bind signatures
to canonical action bytes; stale validator-roster changes are refused. The
default is off, so the regular demo flow remains unchanged.

Approved changes are now submitted to the validator quorum as signed
`governance_change` events before the official CLI/bootstrap applies them. Each
validator verifies the threshold against its configured governance roster and
commits the event in the same ordered log as transfer and decryption records.
If the quorum does not commit, the official path refuses to apply the change.

An approved `identity.snapshot` event establishes the initial state baseline.
Validators then validate the entire ledger and threshold signatures at startup,
replay the latest snapshot plus subsequent identity and trust-roster events, and
replace drifted SQLite and trust JSON working copies. Ordinary governed changes
are paused until a baseline exists. Direct edits to the working copies are
therefore repaired at restart, and the official CLI requires a committed event
before it mutates its local copy.

`scripts/checkpoint_cli.py` captures a chain head agreed by a validator quorum.
Two or more governance-key holders can approve and seal that checkpoint. A
later `verify` checks the checkpoint signatures and verifies that the live
chain returned by a validator quorum extends the externally retained head.
Keep the sealed checkpoint on a separate machine or offline medium to detect
rollback behind it.

These controls still do not stop a privileged operator who can replace the
application, control two validator processes, and change all deployment
configuration. The governance roster should be independently stored and its
SHA-256 supplied via `SIGILCHAIN_GOVERNANCE_ROSTER_SHA256` by deployment
configuration outside the validator host. If that hash is stored only in a
local `.env` on the same host, it is not an independent trust anchor. A local
checkpoint is also ineffective if the host operator can replace it; the
checkpoint must be held elsewhere. This is a prototype control, not a claim of
tamper-proof operation against a fully privileged host administrator.

`scripts/governance_cli.py` creates governance keys and rosters, creates a
baseline snapshot, signs and merges proposals, verifies thresholds, and applies
approved changes. Set `SIGILCHAIN_REQUIRE_GOVERNANCE_APPROVALS=1` on validators
and clients to turn on the gate. Keep governance private keys off the service
host. A disconnected offline checkpoint can be created/sealed/verified using
`scripts/checkpoint_cli.py` and the same independent governance signers.
The gate requires a pinned `SIGILCHAIN_GOVERNANCE_ROSTER_SHA256`; after any
governance event is committed, validators refuse startup if enforcement is
disabled. This protects against an accidental or unilateral configuration
toggle while the committed log is retained.

## Optional TPM host attestation integration

The validator now has an opt-in fail-closed integration with an independent
TPM verifier. With `SIGILCHAIN_REQUIRE_TPM_ATTESTATION=1`, each validator checks
an HTTPS verifier at startup and before accepting a new event. The request
contains a cryptographically random 256-bit nonce, validator ID, configured
host/profile IDs, and a digest binding the challenge to the operation. The
verifier must return a signed `sigilchain-tpm-attestation-v1` statement whose
nonce, host, validator, profile, operation, freshness, approval, and quote
digest all match. A validator receipt then includes the verifier statement,
verifier signature, and verifier public key, covered by the validator's own
receipt signature. Bad, stale, missing, or unreachable attestation fails
closed.

Configure validators with `SIGILCHAIN_TPM_VERIFIER_URL` (HTTPS),
`SIGILCHAIN_TPM_VERIFIER_PUBLIC_KEY` (pinned Ed25519 public key in hex),
`SIGILCHAIN_TPM_HOST_ID`, and `SIGILCHAIN_TPM_PROFILE_ID`. The verifier is a
separate trust domain and must itself validate an actual TPM 2.0 quote,
measured-boot/event-log evidence, reference measurements, and quote freshness
before signing approval. This repository implements the verifier client and
receipt/evidence path; it does not ship the TPM quote collector/verifier or
hardware-specific reference profiles. Thus this integration is not a claim
that TPM hardware attestation is operational until that external verifier is
deployed and provisioned. A host-local self-check is not an independent
attestation. Hardware-backed, non-exportable validator signing keys remain a
separate production hardening task.

The base demo network is internal-only and cannot reach an external verifier.
An optional `docker-compose.assurance.yml` override attaches validators to an
externally created network named `sigilchain-tpm-verifier`. This network must
actually route to a verifier on a separate machine; attaching another
container on the same host does not create an independent trust domain.

```powershell
docker network create sigilchain-tpm-verifier
docker compose -f docker-compose.yml -f docker-compose.assurance.yml up -d
```

Configure the route and HTTPS verifier URL first. Creating the network alone
does not make a remote verifier reachable.

To independently verify exported TPM evidence, pass the verifier's pinned
public key to the offline verifier:

```powershell
python trace_console/verify_evidence.py evidence.json --tpm-verifier-key <PINNED_ED25519_PUBLIC_KEY_HEX>
```

## Optional person authentication through OIDC

With `SIGILCHAIN_REQUIRE_PERSON_AUTH=1`, the CLI requires a fresh signed OIDC
ID token in `SIGILCHAIN_OIDC_ID_TOKEN`. Each validator validates its RS256
signature using the configured JWKS, issuer, audience, expiry/not-before and
authentication freshness, and requires the configured recipient-mapping claim
(default `sigilchain_recipient_id`) to equal the CLI recipient. It also requires
`sub`, `jti`, `nonce`, and `auth_time`. The recipient-signed session contains
the issuer/subject, recipient mapping, one-use token ID, nonce, auth time, and
token digest; the raw token is sent to validators for verification but is not
written to the event or evidence bundle. The watermark/session ID is derived
from issuer plus `jti`, so replaying that token cannot create a second distinct
session for the same identity.

Set `SIGILCHAIN_OIDC_ISSUER`, `SIGILCHAIN_OIDC_AUDIENCE`, and either
`SIGILCHAIN_OIDC_JWKS_FILE` or an HTTPS `SIGILCHAIN_OIDC_JWKS_URL`. The identity
provider must issue an RS256 token with the listed claims and map the proven
account to the SigilChain recipient ID. A token acquisition/login UI is not
included: the operator obtains a fresh token from the configured identity
provider and supplies it to the CLI environment. In the offline Docker demo,
provision the JWKS file in the shared trust volume and supply the token through
the tools container environment. Do not pass tokens over an untrusted network.

The console and JSON evidence label this as OIDC-authenticated account subject,
not proof of which human physically used the endpoint. Person-level attribution
still depends on the identity provider's proofing, MFA policy, account custody,
and endpoint integrity. Shared accounts, stolen tokens, or a compromised
endpoint weaken that claim. These opt-in modes default off and do not change the
existing offline demo flow.

## Verification limits for this checkout

These optional controls require rebuilding the app/CLI images and regenerating
the air-gap bundle before use; editing source alone does not update the bundled
images. They remain disabled by default. The external TPM verifier and the
identity-provider token issuance flow must be provisioned separately.
