# Phase 2 results — native Debian and draft evidence contracts

Native observations: 2026-10-26. Local verification and documentation completed
2026-10-27. These are bounded observations of one laboratory configuration,
not current continuous monitoring or a hardware integrity guarantee.

## Delivered scope

A static Rust inventory binary was deployed through a dedicated private Ansible
playbook. Separate ordinary-user and privileged runs passed the unchanged
inventory-v1 schema. The public repository adds draft submission/result schemas,
synthetic negative tests and an enrollment/privacy design. No verifier or remote
attestation endpoint was implemented.

The deployed agent source is commit
`fd477c10e76499e9a31edd674d55554c6e4f59a5`, built with Rust 1.84.1,
locked dependencies and target `x86_64-unknown-linux-musl`. Its SHA-256 is
`1cffc801b84c66f5b74a9f3f0153449509f40fc2b382f86f398344915044509a`.
The local and deployed checksums matched. ELF inspection showed static PIE
without a dynamic interpreter. Phase 2 changes do not modify agent runtime code;
the artifact deliberately retains its original source commit. A checksum is not
a signed supply-chain attestation.

## Live observations

| Check | Observed result | Interpretation |
|---|---|---|
| Platform | Native Debian 12.15, kernel 6.1.0-54-amd64, x86-64 | One tested environment; physical context supplied by lab operation |
| Secure Boot | Enabled through OS interfaces | OS-declared; boot-chain verification not performed |
| Lockdown / module enforcement | integrity / enabled | OS-declared controls |
| Kernel taint / loaded modules | 0 / 188 entries | Inventory only; no independent module signature validation |
| TPM discovery | TPM 2.0, device and resource-manager interfaces | Presence alone is not provenance |
| Ordinary IMA / boot-log probes | Permission denied | Preserved in the normal inventory |
| Privileged IMA / boot-log probes | ASCII/binary IMA logs and boot log readable | One-byte agent probes; no replay or content validation |
| IMA policy | Permission denied even with sudo | Coverage remains unknown |
| IMA counters | 191 measurements, 0 violations | Counters do not prove comprehensive measurement or appraisal |
| TPM capability commands | PCR allocation and algorithms returned successfully | Separate privileged tooling, outside the agent |
| PCR banks / values | SHA-1 and SHA-256 banks; SHA-256 PCRs 0, 2, 4, 7, 10 read successfully | Five 32-byte values checked for format; unsigned collected measurements |
| Inventory result | INDETERMINATE in both executions | All cryptographic/server-verification flags remain false |

`tpm2-tools 5.4-1`, TSS libraries `3.2.1-3` and `tpm-udev 0.6` were installed.
The transaction preview identified 12 new packages and no upgrades/removals.
Distribution udev rules changed TPM device ownership and modes to 0660. No users
were added to TPM groups and no manual permission changes were made. No Rust
compiler, background agent or attestation service was installed on the lab host.

The filtered boot journal still reports a TPM CRB ACPI command/response buffer
size mismatch and disabled hardware RNG. Capability and selected PCR commands
succeeded despite those warnings. This does not validate other TPM operations,
randomness, quote reliability or firmware correctness; those remain unresolved.

## Operational and automated validation

- Ansible syntax check passed. Initial apply: 20 successful tasks, 4 changed,
  zero failed/unreachable. Second apply: 20 successful tasks, **0 changed**, zero
  failed/unreachable. Private report refreshes are excluded from change counts;
  the idempotence claim concerns managed-host configuration.
- Service snapshots before/after matched: 20 running containers, 13 with healthy
  checks, zero failed systemd units. Existing stopped containers were preserved.
  Containers without checks were observed running, not proven application-healthy.
- No reboot, instance draining, TPM reset/key creation, firmware change or IMA
  policy change was performed. Applications were not restarted by this procedure.
- Rust: 6 unit and 12 integration tests passed; formatting and Clippy passed.
- Python: 22 tests passed, including 9 new draft-contract tests. These are
  structural/consistency tests, not signature or replay-protection tests.
- Both saved native inventories passed schema validation. The static binary also
  passed local live-output contract tests. GitHub Actions now includes this
  portable build/check; remote execution must be checked separately.
- Dependency audit queried 16 locked versions; that query returned no advisories.
- Gitleaks 8.24.2 found no leaks in the reviewed public source tree. A separate
  scan found no known private infrastructure paths, hostnames or login references.

Raw inventories, PCR values and infrastructure-specific execution logs remain
private, in an ignored directory with mode 0700 and report files mode 0600.
Public findings omit host addresses, login accounts and raw measurement logs.
See [lab procedure](LAB.md) for reproduction and [test plan](TEST_PLAN.md).

## Remaining gates

Phase 2 is **partial**: native Ubuntu and Fedora validation and independent
review of the enrollment/privacy design remain pending. The unreadable IMA policy
prevents a coverage claim. There is no AK provenance validation, real quote,
signature verification, nonce binding, PCR/log replay or server policy decision.
The TPM firmware warning is a residual risk for later experiments.

Phase 3 requires review of these results and the [enrollment design](ENROLLMENT_DESIGN.md)
before implementing remote attestation. Nothing here demonstrates cheat absence,
Riot acceptance, Vanguard integration or League of Legends compatibility.
