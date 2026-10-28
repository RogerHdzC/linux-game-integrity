# Phase 3 results — real quote verification, limited trust

Executed 2026-10-27. Phase 3 is **partial**, with a functional local verifier and
real TPM evidence. Key provenance, measured-boot/IMA log reconstruction and an
approved security baseline remain pending. This is not an ACCEPTED platform or
Vanguard compatibility result.

## Implemented and exercised

- NestJS API with separate client/admin bearer authentication, bounded strict JSON
  parsing, unproven-key registration and revocation.
- PostgreSQL 16 persistence, transactional migration, 32-byte random challenges,
  120-second expiry and atomic consumption before quote processing.
- A versioned policy and independent server checks. Errors, missing evidence and
  unknown trust properties cannot turn into acceptance.
- Bounded TPMS_ATTEST / TPMT_SIGNATURE decoding and RSA-2048 RSASSA/SHA-256
  verification using Node/OpenSSL. Signed nonce and selected-PCR digest comparison.
- Minimal evaluation audit rows; no raw evidence storage. Startup/hourly retention
  cleanup and generic error responses without request/database content.
- A separate operator-only TPM helper, with private Ansible orchestration and
  service-health checks. The Rust inventory agent remains read-only and unchanged.

## Real hardware experiment

The native Debian 12 laboratory used its existing TPM 2.0 and tpm2-tools 5.4.
An explicitly authorized temporary restricted signing key was created under the
NULL hierarchy through `/dev/tpmrm0`. No persistent handle, EK provisioning,
credential activation, hierarchy-auth change or TPM clear was performed.
The public key was registered as **UNPROVEN**, not as a manufacturer-backed AK.

The API issued a fresh challenge, the lab TPM quoted SHA-256 PCRs 0,2,4,7,10,
and the verifier checked the returned real bytes. The initial signing template
failed with TPM error 0x2D6; setting its symmetric parameter to `null` corrected
the signing-only template. Failed attempts are retained privately as failures.
They were not counted as successful attestations.

| Real-evidence check | Observed outcome |
|---|---|
| Exact quote signature against registered RSA public key | VERIFIED |
| Signed qualifying data against server-issued nonce | VERIFIED |
| Hash of supplied PCR values against signed PCR digest | VERIFIED |
| Complete evaluation | INDETERMINATE |
| Replay of consumed challenge | HTTP 409 |
| Old quote submitted against a new challenge | REJECTED |
| Mutated real signature, checked directly | Signature verification false |
| Modified PCR value, checked directly | PCR digest comparison false |
| Key provenance / measurement coverage / trusted baseline | UNAVAILABLE |

This demonstrates signature and freshness properties relative to the registered
key. The server cannot prove that key belongs to a physical TPM, that the quoted
machine runs a particular game, or that measurements cover all relevant behavior.
PCR digest consistency is not event-log replay or approval of the measured state.

Health comparisons around successful preparation, quote collection and cleanup
passed. The experiment's context/output directory was removed through Ansible;
no global flush command was used. Raw evidence, public keys, session identifiers
and host-specific logs remain private and excluded from Git. No verifier service
or database was deployed onto the native host and no reboot was needed.

## IMA policy diagnosis

The running kernel's configuration declares `CONFIG_IMA_READ_POLICY` and
`CONFIG_IMA_WRITE_POLICY` unset, `CONFIG_IMA_ARCH_POLICY=y`,
`CONFIG_IMA_APPRAISE=y`, and default template `ima-sig`. No IMA-specific boot
parameters were observed. The disabled read-policy option explains why root
cannot read back the policy through securityfs; it is not solved by another sudo
invocation. The option controls policy readback according to the
[Linux 6.1 IMA Kconfig](https://github.com/torvalds/linux/blob/v6.1/security/integrity/ima/Kconfig).
These configuration observations do not independently prove the active coverage.
No kernel, boot parameters or IMA policy were changed.

## Automated checks and dependencies

- 15 Jest tests passed: cryptographic negatives using explicitly synthetic
  software-signed fixtures, strict input/authentication, expiration, replay,
  eight concurrent submissions with one winner, revocation, restart persistence,
  missing evidence, database outage, failure after reservation, retention and
  transaction rollback. Integration tests used real isolated PostgreSQL 16.15.
- 18 Rust and 22 Python regression tests passed, along with rustfmt and Clippy.
- TypeScript strict compilation and Prettier checks passed. The lab quote helper
  compiled with Python. The standalone loopback server started, rejected an
  unauthenticated request with 401, and stopped cleanly.
- Gitleaks and a scan for private infrastructure references passed on the public
  source tree; raw lab files were excluded.
- Runtime npm audit returned zero vulnerabilities. The development dependency tree
  reports five low-severity entries from one deepmerge/Jest advisory, documented
  in the [verifier README](../apps/verifier-api/README.md); it is not a zero-findings
  audit. The unrelated high-severity multer advisory was removed by a pinned
  patched override and the suite reran successfully.
- GitHub Actions adds an isolated PostgreSQL job and runtime/development audit
  gates. Remote CI execution is recorded separately from these local results.

## Remaining Phase 3 acceptance gates

1. Review and implement EK/AK provenance and credential activation with a vetted
   trust store and revocation lifecycle. Never upgrade UNPROVEN based on a flag.
2. Reconstruct measured boot and IMA PCRs from bounded real logs; resolve policy
   coverage through a suitable laboratory kernel/configuration and review.
3. Approve versioned security baselines and legitimate-update handling. An arbitrary
   snapshot from the test host is not automatically a trusted baseline.
4. Complete independent parser/security review, broader algorithms/platforms,
   multi-user authorization, TLS deployment and service resource controls before
   any external operation. Existing TPM firmware warnings remain a residual risk.

Native Ubuntu/Fedora Phase 2 coverage remains pending. These limitations prevent
claiming the overall MVP or Phase 3 complete, despite real quote verification.
