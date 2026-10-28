# Test plan

## Executed in the first iteration

| Test area | Cases and expected outcome | Observed result |
|---|---|---|
| Rust unit tests | os-release quotes, precedence within file, missing version, malformed input and no shell expansion; SecureBoot framing/boolean; module parsing and address omission; Lockdown active mode; read-size boundary | 6 passed |
| Rust integration tests | Synthetic capabilities remain unverified; absent/denied interfaces; fallback only on missing os-release; corrupt/oversized input; empty lists; WSL hint; multiple TPM versions and invalid names; CLI rejects options and emits live JSON | 10 passed |
| Contract tests | Labeled synthetic fixture and live binary match schema; acceptance/verified flags, extra fields, wrong/missing types, inconsistent observations, excessive sizes, duplicate keys and invalid JSON fail | 9 passed |
| Dependency-audit tests | Empty findings, advisory reporting, incomplete/paginated/error responses and both ecosystems | 4 passed |
| Live inventory | Ordinary-user WSL execution produces JSON; missing hardware remains unknown; result INDETERMINATE | Passed; see COMPATIBILITY |
| Secret scan | Gitleaks 8.24.2 on all 35 files prepared for publication | No leaks found |
| Formatting / static analysis / build | rustfmt, Clippy with warnings denied, locked Cargo build | Passed |
| Dependency audit | Query all 16 locked external Rust/Python versions; fail if advisories or unavailable/incomplete response | No known advisories returned by the executed OSV query |

See README for exact commands. Rust tests live in `apps/agent/src/lib.rs` and
`apps/agent/tests/inventory.rs`; Python tests live in `tests/contracts/`.
`tests/fixtures/` is exclusively synthetic. `reports/inventory-wsl.json` is local
live output excluded from publication. GitHub Actions runs quality checks and
Gitleaks independently; a local test pass is not a claim that remote CI ran.

The read-only claim is supported by source review and ordinary-user operation:
no write APIs, subprocesses, network calls, mount changes or TPM commands in the
agent. A syscall trace or independently reviewed sandbox profile has not been
produced, and hostile-kernel behavior is not tested.

## Protocol and hardware acceptance targets

| Scenario | Required future result |
|---|---|
| Real valid evidence meeting an experimental policy | ACCEPTED only after all independent checks |
| Invalid signature, wrong nonce, replayed nonce | REJECTED |
| Expired nonce or concurrent duplicate submission | REJECTED with atomic single consumption |
| Measurements inconsistent with signed PCR digest | REJECTED |
| Incomplete evidence | INDETERMINATE |
| TPM unavailable | INDETERMINATE or REJECTED under explicit policy |
| Unsupported/revoked kernel | REJECTED or explicit review |
| Verification error or unavailable dependency | Never ACCEPTED |
| Legitimate update | Evaluate against the authorized updated policy |
| Oversized/malformed request, unauthorized endpoint access | Reject without expensive verification or data leakage |
| Migration failure or persistence outage | No acceptance; maintain state consistency |
| Audit records | No secrets or unnecessary permanent identifiers |

The Phase 3 executed subset below updates these original targets; unlisted
acceptance gates remain pending. Hardware claims require the native lab. No synthetic cryptographic fixture has been presented as a real quote.
Latency/resource benchmarks, physical TPM/IMA validation, Fedora testing and
independent security review remain pending.

## Phase 2 validation (2026-10-26/27)

Rust now has 6 unit and 12 integration tests: the two added synthetic cases cover
an unreadable IMA policy alongside readable logs, and a missing boot log alongside
a malformed TPM version. Python now has 22 tests, including 9 draft-schema tests
for synthetic labeling, client/server separation, missing fields, versions,
nonce/binary encoding and bounds, PCR limits, and acceptance/failure consistency.
Trailing newlines in hex inputs are rejected. All passed in the local run.

The portable musl artifact passed local contract tests. Both native Debian reports
(ordinary and explicitly privileged execution) passed inventory-v1 validation.
Ansible reapplication reported zero host changes; service snapshots matched.
TPM capability and selected PCR-read commands succeeded. These hardware reads do
not fulfill the future signature, replay, nonce, enrollment or policy tests above.
See [Phase 2 results](RESULTS_PHASE_2.md) for exact observations and limits.

## Phase 3 executed subset

15 Jest tests passed against isolated PostgreSQL 16.15. They cover API access,
input limits/duplicate keys, migration transaction rollback, nonce expiry/replay,
eight concurrent submissions, revocation, restart persistence, missing evidence,
storage failure before and after reservation, retention, synthetic signature/PCR
negatives and policy nonacceptance with missing checks. Separately, real hardware
quote signature, signed nonce and PCR digest were verified; replay and stale
challenge binding were rejected. Real signature/PCR mutations failed checks.

These results do not complete the full future table: provenance, real event-log
reconstruction, baselines/legitimate updates, external TLS/multi-user deployment
and independent review remain pending. See RESULTS_PHASE_3.md.
