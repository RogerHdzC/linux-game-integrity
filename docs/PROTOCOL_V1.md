# Implemented protocol: HTTP v1

This document describes executable behavior, not the historical `0.1-draft`
evidence/result schemas. The stable inventory-v1 contract is unchanged and always
reports INDETERMINATE. Historical laboratory reports retain their original phase
numbers; the new implementation roadmap begins again with consolidation Phase 1.

The authoritative request validators are `apps/verifier-api/src/input.ts` and the
service's enrollment/challenge validators. Server response types are in
`apps/verifier-api/src/responses.ts`; HTTP contract tests exercise the serialized
forms. See the [API reference](../apps/verifier-api/README.md) for fields, size
limits, encodings, status codes and reproducible local commands. Draft schemas
are not accepted as interchangeable API v1 requests.

## State and trust boundaries

1. An administrator registers an RSA-2048 public key. Registration establishes
   UNPROVEN key storage, not TPM provenance or EK/AK enrollment.
2. An authenticated lab client requests a challenge. A transaction locks issuance,
   checks the rate limit and enrollment, and stores a random nonce with a fixed
   policy version and expiration. The policy supplies the 120-second lifetime.
3. Strict input validation rejects client verification results and unknown fields.
   A conditional committed UPDATE reserves one unexpired challenge once. Missing,
   expired and already consumed identifiers return 409.
4. The decoder checks the supported TPM structures. Node/OpenSSL verifies the
   exact attestation bytes against the registered key. Only a valid signature can
   make the signed nonce and PCR digest comparisons VERIFIED. This proves no key
   provenance, log coverage or approved system configuration.
5. A second transaction locks the enrollment, rechecks revocation and persists
   minimal server-generated results. A revocation committed before this lock is
   observed. A later revocation does not retroactively rewrite historical results.
6. A crash or storage failure after reservation consumes the challenge even when
   no evaluation is persisted. The client must request a new challenge.

## Meaning of checks

| Check | Implemented meaning |
|---|---|
| signature | Registered public key verifies the exact quote bytes |
| freshness | Authenticated signed nonce and submitted nonce match the stored challenge |
| pcrBinding | Authenticated quote digest matches the supplied selected PCR values |
| keyProvenance | UNAVAILABLE until cryptographic enrollment; FAILED for revoked registration |
| measurements | UNAVAILABLE: boot/IMA reconstruction and coverage are unimplemented |
| policy | UNAVAILABLE: no approved baseline; FAILED for a retired challenge policy |

Signature failure leaves freshness/PCR binding NOT_CHECKED, except an independently
detected submitted nonce mismatch remains FAILED. Raw decoder comparisons are
internal calculations, not authenticated verification results.

The pure policy engine requires exactly all six mandatory checks VERIFIED for
ACCEPTED. This case is tested with synthetic inputs only. The HTTP service cannot
currently establish all six checks. HTTP 201 indicates creation, not acceptance.
REJECTED signals a failed check; otherwise incomplete verification is INDETERMINATE.
Neither future experimental acceptance nor a valid quote would demonstrate cheat
absence, an uncompromised administrator or Vanguard compatibility.

## Deferred work

EK trust stores, credential activation, hardware/virtual provenance, log replay,
reviewed baselines, per-client identity, TLS/external deployment and independent
security review remain future work. No new cryptographic mechanism or hardware
operation is introduced by consolidation.
