# Enrollment and evidence design — Phase 2 draft

This is a design for review, not an implemented protocol or trust guarantee.
No enrollment, attestation keys, challenge service or verifier exists yet.
The current inventory-v1 contract remains unchanged and unverified.

## Separate input from decisions

`evidence-submission-draft.schema.json` describes untrusted input, version
`0.1-draft`. It carries an opaque challenge ID, a 32-byte hex nonce, an opaque
service-scoped enrollment ID and optional quote/measurement material. Missing
material is explicitly null. `origin` is a client assertion, never authenticated
provenance. Synthetic submissions must never enter a future production trust path.

The proposed quote encoding is hex-encoded TPMS_ATTEST and TPMT_SIGNATURE,
without a TPM2B size prefix on the attestation. This is a wire-format proposal;
compatibility with real tooling output must be tested before freezing it.
Each encoded quote/signature is bounded to 8 KiB. SHA-256 PCR indices are 0–23;
logs are optional hex-encoded bytes bounded to 1 MiB each. Oversized legitimate
logs require an explicit future protocol revision; never silently truncate them.
No real quote parser or PCR/log replay is implemented.

The separate `verification-result-draft.schema.json` belongs only to the future
server. It reports policy version, outcome, reason codes and independent checks
for key provenance, signature, freshness, measurements and policy. ACCEPTED
requires every check VERIFIED; any FAILED check requires REJECTED. Unavailable
checks remain INDETERMINATE unless an explicit mandatory policy rejects them.
Passing this schema cannot authenticate a server or prove it ran those checks.

Both schemas reject additional fields. Fixtures are explicitly synthetic,
including the test constructing an ACCEPTED result. A one-byte placeholder quote
can pass structural validation but is not a TPM quote. A future decoder must
reject it. Semantic checks, including duplicate PCR indices with different
values, matching PCR selection/digest, and algorithm restrictions, belong to the
future verifier. Transport input must use the existing duplicate-key rejection
and 8 MiB envelope limit before decoding; schemas alone do not bound JSON bytes.

## Enrollment trust and lifecycle

Default future enrollment is operator-approved in the independent laboratory.
Use a new service-scoped AK; do not reuse a key from another service. Associate
an opaque enrollment ID with the public AK and a documented trust class:
physical TPM, virtual TPM or provenance unproven. Inventory hints cannot select
that class. Missing provenance prevents hardware-backed acceptance.

Before implementing enrollment, validate EK certificate chains against an
explicit reviewed manufacturer trust store where certificates are available,
and test credential activation linking the AK to the enrolled TPM. A self-signed
AK or a valid quote signature alone is insufficient. Manufacturer trust, firmware
assumptions, enrollment authorization and relay attacks remain separate concerns.
Do not fall back to trusting an unsigned client declaration when a certificate
or activation operation is unavailable.

Keep EK certificates and other permanent identifiers out of routine submissions,
audit logs and public reports. Store enrollment material under restricted access
separately from evaluations. Proposed laboratory retention: raw submissions at
most 24 hours, minimal evaluation metadata 30 days, active enrollment material
until revocation plus 30 days. These are proposed limits; automated deletion and
access controls must be implemented and tested before server operation.

Revocation is operator-controlled and takes effect for outstanding challenges.
AK rotation creates a new enrollment after proof and authorization; never silently
trust a replacement key. Keep policy versions immutable. Legitimate system
updates require a reviewed new baseline/policy, not relaxed signature or freshness
checks. Recovery must not require clearing the TPM or deleting unrelated keys.

## Challenge and session binding

Proposed default: generate 32 random bytes on the server, expire after 120 seconds,
and bind the challenge to authenticated session, enrollment, policy version and
requested PCR selection. Define and test canonical TPM qualifying-data binding
before implementation. Use authenticated TLS and endpoint authorization; possession
of an opaque enrollment ID is not authentication.

Atomically reserve a challenge for one submission before expensive verification.
A consumed, expired or concurrently reserved challenge cannot be accepted again.
Infrastructure failure requires a fresh challenge, not reopening the original.
Never compare only a client-provided nonce field: check signed qualifying data.
Freshness does not establish that the game runs on the quoted machine; relay and
post-quote changes remain unresolved.

## Phase 3 entry criteria

Review this design; select verified library/tool versions; obtain real quote
samples with consent; validate encoding and provenance; implement independent
signature, nonce and PCR/log consistency checks; test atomic challenge handling,
revocation, retention, authorization and denial-of-service limits. A fixture-only
verifier does not satisfy these criteria. No game or Vanguard integration follows
from meeting the experimental policy.
