# Requirements and acceptance criteria

## Current iteration

| ID | Requirement | Acceptance evidence |
|---|---|---|
| F0-1 | Inspect existing workspace and tools before edits | Initial findings in RESULTS_PHASE_0_1 |
| F0-2 | Document actors, assets, trust boundaries and risks | THREAT_MODEL and LIMITATIONS |
| F1-1 | Read distribution/version and kernel from real Linux | Live report plus CLI integration test |
| F1-2 | Observe Secure Boot, TPM, modules and measurement interfaces when exposed | Live missing-capability output plus explicitly synthetic parser tests |
| F1-3 | Preserve errors and unknown values without implicit secure defaults | Permission, missing, corrupt, oversized and contract consistency tests |
| F1-4 | Version and validate JSON; never accept client trust claims | Strict schema and negative contract tests |
| F1-5 | Keep agent read-only and unprivileged | Source review: file reads/metadata, no shell/network/device commands; ordinary-user execution |
| F1-6 | Separate fixtures from real data | Synthetic fixture markers, Source origin and local reports directory |
| F1-7 | Reproducible build/test commands | Pinned toolchain/dependencies, README and CI |
| F1-8 | Public repository, suitable license, contribution guidance | GitHub visibility, LICENSE, NOTICE, CONTRIBUTING and SECURITY |
| F1-9 | Document lab needs and avoid premature hardware claims | LAB, COMPATIBILITY and results |
| F1-10 | Stop before remote attestation pending user review | No verifier or remote protocol implementation |

Nonfunctional requirements: typed Rust output; bounded reads and collection sizes;
no raw secrets or permanent device identifiers; no automatic elevation; English
communication/documentation; normalized errors; no destructive host operations.
Runtime latency/resource targets need measurement on representative hardware,
not a claim based on unit-test speed.

## Future requirements — not accepted in this iteration

A NestJS/TypeScript verifier will issue unpredictable one-use challenges, track
expiry and concurrency in PostgreSQL, validate signatures and AK provenance,
check measurement consistency and apply versioned policy independently. Policies
must distinguish mandatory and informational checks, known/revoked baselines,
legitimate updates, and ACCEPTED/REJECTED/INDETERMINATE explanations.

Required negative cases: invalid signature, wrong/reused/expired nonce, inconsistent
measurements, malformed/incomplete evidence, unsupported kernel, missing TPM,
verification errors, unauthenticated requests, oversized inputs, concurrent replay,
database migration failures and secret-free audit logs. No error may accept.
Hardware success requires real evidence and independent verification, not fixtures.
