# Roadmap and review gates

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
Review is required before implementing remote attestation. A functional
fixture-only verifier would not complete Phase 3.

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
