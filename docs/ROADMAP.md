# Implementation roadmap: attestation and Linux kernel observation

This continuation roadmap supersedes the original scheduling and restarts phase
numbering. Earlier results remain historical evidence, not completion of the new
enrollment, reconstruction or trusted-policy phases. Only consolidation Phase 1
is implemented in this iteration. The original eight-week estimate is deferred
until laboratory preparation and provenance research establish realistic scope.

## Delivery rules

Commit and push small, reviewable increments after relevant local checks. Check
GitHub Actions after every push and fix failures before dependent work. Each
functional change includes regression tests and documentation. Review public diffs
for secrets and infrastructure information; raw evidence and host-specific Ansible
remain private. Record implemented, tested and pending work at each boundary.

## Phases and gates

| Phase | Scope | Completion gate / current status |
|---|---|---|
| 1 — Consolidate | Review verifier, contracts, transactions and TPM decoder; correct findings, expand negative tests, document dependencies | Implemented and locally tested; publication/CI evidence in the consolidation report |
| 2 — Isolated laboratories | Prepare the dedicated disposable Ubuntu 24.04 LTS physical machine, baseline, exact versions and console/reinstallation recovery | Pending; recoverable laboratory with explicit physical/virtual evidence classification |
| 3 — Key provenance | Reviewed versioned EK trust store, certificates, credential activation, rotation and revocation | Pending; real enrollment and substitution/activation negatives; unsupported evidence stays UNPROVEN |
| 4 — Boot/IMA reconstruction | Bounded parsers, PCR reconstruction, consistency and collection-race handling; inspectable IMA policy without initial appraisal enforcement | Pending; real reconstruction and tampering tests, with separate coverage/content approval |
| 5 — Trust policies | Immutable reviewed baselines, revocation, legitimate updates and recovery | Pending; real acceptance only with every mandatory check, with precise limited claims |
| 6 — eBPF observation | Dedicated test workload/cgroup, privileged loader separated from agent, bounded events and explicit losses; no content, arguments or personal paths | Pending; expected events, detectable losses, overhead/privacy review and disposable-machine validation |
| 7 — Custom module decision | Compare demonstrated gaps against eBPF/LSM and existing interfaces; independent review | Pending; retain eBPF if no justified gap; otherwise separately approve minimal observation-only module, private signing keys and recovery tests |
| 8 — Compatibility/hardening | Native Ubuntu/Fedora, per-client authentication, admin authorization, TLS, limits, migration/backup/retention recovery | Pending; explicit supported configurations and operational boundaries before external access |
| 9 — Adversarial review | Replay/revocation races, malformed evidence, sensor failure/saturation/lifecycle, repeatable performance and independent security review | Pending; material findings resolved or block release, residual risks explicit |
| 10 — Research MVP | Reproducible setup, evidence matrix, feasibility report and reviewed release | Pending; another engineer can reproduce the supported experiments and their limits |

The user's dedicated disposable Ubuntu machine replaces the earlier mandatory VM
proposal. A VM is optional, and virtual evidence never establishes physical TPM
trust. Phase 2 must establish console access and tested recovery before future
kernel experiments. Existing shared laboratory machines remain limited to already
reviewed operations. No provisioning or host operation was performed in Phase 1.

A custom `.ko` is a conditional research decision, not an approved implementation.
No sensor, module or accepted experimental policy would imply cheat absence or
Vanguard compatibility. Existing firmware keys, TPM ownership and unrelated keys
must be preserved. Missing hardware/reviews remain open gates, never synthetic
substitutes. Future persistent infrastructure changes belong in private Ansible.

## Historical plan (retained for interpreting prior reports)

The original eight-week outline is an estimate, not a commitment that hardware
attestation or universal distribution support can be completed in that period.

| Phase / indicative period | Work | Completion gate |
|---|---|---|
| 0 / week 1 | Requirements, environment inspection, threat model, initial risks | Reviewed scope and explicit assumptions |
| 1 / week 2 | Read-only Rust inventory, JSON contract, tests, reproducible commands | Real Linux output, passing tests, documented unavailable capabilities |
| 2 / weeks 3–4 | Review current results; native Ubuntu/Fedora capability matrix; refine evidence request/result contracts | User review, physical-lab access, privacy and enrollment design |
| 3 / weeks 5–6 | NestJS verifier, PostgreSQL, one-use challenges, versioned policy, real quote verification where testable | Signature + provenance + freshness + PCR/log consistency tests; persistent atomic challenge state; real hardware evidence |
| 4 / week 7 | Adversarial protocol tests and independent security review | Invalid/replayed/inconsistent/expired evidence never accepted; documented residual risks |
| 5 / week 8 | Reproducibility, latency/resource measurements, feasibility report and external proposal | Recorded real and synthetic results, no unsupported compatibility claims |

Phases 0/1 are delivered. Phase 2 adds native Debian validation and draft
submission/result contracts plus enrollment/privacy design. Native Ubuntu/Fedora
coverage and independent design review remain pending; Phase 2 is partial.
The user authorized Phase 3. A local NestJS/PostgreSQL verifier now verifies real
quote signatures, signed nonces and PCR digest consistency; one-use challenges
and revocation are tested. Provenance, log reconstruction and trusted baselines
remain missing, so Phase 3 is partial. See RESULTS_PHASE_3.md.

Dependencies: native Linux lab; accessible TPM 2.0; verified TSS tooling/library
versions; supported PCR banks and log templates; attestation-key enrollment and
revocation policy; secure transport/authentication; transaction design; trusted
baselines; update/recovery strategy; privacy review.

Open risks include privileged compromise, relay attacks, measurement coverage,
mutable runtime memory, virtual TPM rollback, device fingerprinting and false
rejections during legitimate updates. See the threat model's risk register.

A later external proposal should report which properties were actually demonstrated,
which remain assumptions, and why the results do not imply official Vanguard
integration or Riot acceptance. Support across every distribution is an aspiration,
not a current compatibility claim.
