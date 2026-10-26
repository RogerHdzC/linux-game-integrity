# Threat model — experimental inventory and future attestation

Version 0.1, 2026-10-25. Scope: independent lab; no interaction with Riot services,
Vanguard or game processes. The current implementation collects observations;
it does not establish a trusted platform or prevent cheating.

## Assets and trust boundaries

Assets: accurate interpretation of evidence, future signing keys and challenge
state, versioned policy, reproducible source/builds, lab availability and device
privacy. The user's files, firmware and TPM state must remain untouched.

Boundaries: firmware/hardware → kernel → userspace agent → JSON consumer. Future
boundaries add transport → verifier → policy/database. All data crossing from a
client is untrusted, even when a schema validates it. The current stdout consumer
has no authenticated binding to a device or execution.

## Actors

| Actor | Capabilities | Current protection and residual risk |
|---|---|---|
| Unprivileged user | Replace own agent/output, submit arbitrary JSON, replay reports | Strict format and honest labels; cannot authenticate any client report |
| Administrator/root | Modify userspace, mount namespaces, files, policy and agent; manipulate observations | No root-resistant guarantee; all inventory remains unverified |
| Compromised kernel | Forge procfs/sysfs, suppress modules, lie about controls, stall reads | Outside current trust boundary; no local detector can establish kernel honesty |
| Physical attacker | Change boot media/firmware, attach devices, exploit DMA or hardware | No physical resistance demonstrated; future TPM/boot controls have separate assumptions |
| Malicious hypervisor/host | Emulate guest hardware, roll back snapshots, control virtual TPM and guest memory | VM/WSL results do not establish host integrity or physical TPM provenance |
| Network attacker (future) | Replay, alter, relay or flood attestation exchanges | No network surface today; future authenticated transport, freshness and resource limits required |
| Dependency/build attacker | Compromise sources, dependencies, CI actions or releases | Locked dependencies, pinned CI actions, review and scans reduce exposure, do not prove supply-chain integrity |

## Attack surfaces and mitigations in this phase

- Filesystem parser inputs: bounded reads, UTF-8 validation, conservative parsing,
  explicit errors, no shell execution. `os-release` is parsed as data.
- Misleading success: missing/error observations retain null values. Cryptographic
  fields are false and result is always INDETERMINATE. Extra fields and client
  acceptance claims fail contract validation.
- Resource exhaustion: 1 MiB content reads, 4096 entries per enumeration/module
  list, 8 MiB validator input. A compromised kernel can still block reads or
  fabricate data. File-type checks are best effort, not protection from root
  racing path resolution or changing the kernel.
- Accidental disclosure: no hostname, machine-id, usernames, IP/MAC addresses,
  serials, EK/AK, kernel addresses or raw event logs. Reports remain local.
- Privilege misuse: no elevation, filesystem writes, TPM commands or configuration
  changes by the agent. Opening system files can still update access metadata
  or create audit events under the host's filesystem/security settings.

## Unresolved threats and risk register

| ID | Risk | Severity | Required research or control |
|---|---|---|---|
| R1 | Root/kernel can fabricate inventory | Critical | Hardware-backed evidence, explicit root of trust and independent verification |
| R2 | Valid signature from an untrusted AK accepted as hardware trust | Critical | AK enrollment/provenance, credential activation strategy, manufacturer trust policy |
| R3 | Replay, snapshot rollback or relay/cuckoo attack | High | Unpredictable one-use challenges, atomic consumption, expiry, session/device binding; relay remains separate research |
| R4 | Measurements do not cover runtime memory, peripherals or all executable state | Critical | Coverage analysis, threat-specific controls; no claim of cheat absence |
| R5 | Valid old measurements used after a state change (TOCTOU) | High | Define temporal guarantees; ongoing measurement alone is not complete runtime protection |
| R6 | Legitimate kernel/package updates cause false rejections | High | Versioned baselines, signed policy updates, revocation, rollback and review workflow |
| R7 | Hardware keys/logs fingerprint users | High | Minimize data, separate enrollment identifiers, retention limits and review |
| R8 | Virtual TPM trusted as physical hardware | High | Separate trust classes and documented hypervisor assumptions |
| R9 | Malicious or unavailable dependency/advisory service | Medium | Pin versions, fail closed on audit errors, independently review releases |
| R10 | Incomplete local observation confused with verified integrity | High | Explicit evidence levels, negative tests and documentation |

## Assumptions and acceptance

For ordinary inventory operation, the kernel and standard system interfaces are
assumed to function and return finite reads. This is an operational assumption,
not a security conclusion. The lab owner authorizes local observation only.

Phase acceptance requires real Linux output, valid schema, negative tests,
explicit missing capabilities, no automatic elevation, and documented limitations.
Hardware-backed acceptance is not available. Independent review is still needed
before relying on future security claims.
