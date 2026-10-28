# Consolidation Phase 1 results

Executed 2026-10-28. This is Phase 1 of the continuation roadmap, not the original
inventory phase. The implemented changes consolidate the existing verifier. No
native host was contacted, no hardware quote was collected, and no kernel, TPM,
firmware or infrastructure configuration was changed. Historical real-hardware
results remain in [the earlier Phase 3 report](RESULTS_PHASE_3.md).

## Review findings and corrections

| Area | Finding / result |
|---|---|
| Policy boundary | Empty or incomplete objects could produce ACCEPTED in direct calls. Require exactly six own mandatory VERIFIED checks; malformed/missing/extra fields cannot accept. Explicit mandatory FAILED rejects. The HTTP service already constructed all six fields; no API acceptance bypass was demonstrated. |
| Result semantics | Failed signatures could coexist with VERIFIED nonce/PCR comparisons. Those unauthenticated comparisons now stay NOT_CHECKED; independent envelope nonce mismatch still fails. |
| Contracts | Implemented HTTP v1 input validation and typed responses are documented separately from historical 0.1-draft schemas. Inventory-v1 is unchanged. |
| TPM decoder | Added entry-point hex/size validation to prevent silent Buffer truncation outside HTTP validation. Expanded synthetic truncation, selection, algorithm, length and trailing-byte tests. |
| Transactions | Conditional committed reservation, final enrollment lock and transactional migration retained. Tests confirm replay exclusion, concurrent rate limits, revocation during verification and consumed challenges after storage failure. |
| Lifecycle | Startup previously queried the migration table without requiring a returned row. It now requires version 1 and closes initialized resources on failure. Startup/shutdown and failure paths are tested. |
| HTTP parsing | Invalid UTF-8 is rejected instead of silently replaced. A raw-byte regression exercises the wire behavior. |
| Test isolation | Each API suite creates/drops its own random PostgreSQL schema. Repeated runs do not inherit earlier records or issuance counters. |

The policy PCR array is frozen at runtime, and challenge lifetime comes from the
same policy constant as the documented 120-second TTL. No external dependency or
database migration was introduced.

## Observed verification

| Check | Observed result |
|---|---|
| Rust format and Clippy with warnings denied | Passed |
| Cargo tests, locked dependencies | 18 passed: 6 unit and 12 integration |
| Python contracts and audit tests | 22 passed |
| Strict TypeScript build and Prettier | Passed |
| Jest/Supertest with real local PostgreSQL 16.15 | 25 passed; repeated isolated runs passed |
| Concurrent identical submissions | Exactly one created evaluation; seven HTTP 409 responses |
| Concurrent issuance after resetting only suite-owned records | Exactly 60 created challenges; one HTTP 429 |
| Revocation while final evaluation waits on a locked row | REJECTED, keyProvenance FAILED |
| Valid synthetic quote evaluation | INDETERMINATE; provenance, coverage and baseline unavailable |
| Public-source secret and private-infrastructure pattern scan | No findings in executed scans; this is not proof that disclosure is impossible |
| OSV dependency query | 16 pinned Rust/Python versions queried; no advisories returned |
| Runtime npm audit | Zero findings returned |
| Full npm audit | Five low-severity development dependency entries; one underlying advisory, described below |

All new quote fixtures are software-signed synthetic TPM-shaped structures. Real
PostgreSQL transactions do not turn synthetic quote evidence into hardware proof.
These results do not establish trusted-platform acceptance, absence of cheats,
complete parser assurance or Vanguard compatibility. Independent security review
remains pending.

## Reproduce

Use the pinned Rust toolchain and lockfiles. Follow the root README to create a
Python virtual environment and install `tests/requirements.txt`. Follow the
[verifier setup](../apps/verifier-api/README.md) for Node and a disposable local
PostgreSQL database. Set `LGI_TEST_DATABASE_URL` to that database; its role must
be able to create schemas. Never point tests at a production database.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
.venv/bin/python -m unittest discover -s tests/contracts -v
npm ci --ignore-scripts
npm run format:check
npm test
npm test
.venv/bin/python scripts/audit_dependencies.py
npm audit --omit=dev --audit-level=low
npm audit --audit-level=moderate
git diff --check
```

`npm test` includes strict compilation and requires the database environment
variable. Repeating it checks isolation. The executed local environment used
Node 22.15.1 and PostgreSQL 16.15. The tests close application listeners and pools
and drop only their generated schema. An interrupted process may leave its test
schema; inspect and remove only that identified schema in the disposable database.
The temporary local database server was used solely for this verification.

For publication, scan the complete tracked tree plus new intended files using
Gitleaks 8.24.2 with redaction, and inspect diffs for private infrastructure data.
Exclude ignored reports, local databases, build output and node_modules from the
publication set. No keys or raw hardware evidence belong in commits.

## Dependency advisory and remediation

The audit returned [GHSA-gcqx-w48m-w2h4](https://github.com/advisories/GHSA-gcqx-w48m-w2h4)
for `deepmerge` 4.3.1 through Jest configuration dependencies. Five low-severity
entries describe that dependency chain, not five independent advisories. The
installed runtime dependency graph is unaffected by this finding. Only trusted
repository test configuration is loaded; this limits exposure but does not repair
the dependency. Untrusted changes still require review before running tests.

The current audit proposes a breaking downgrade to Jest 25.1.0 for full remediation.
That is not applied automatically. Maintainers must review an upstream compatible
fix or a replacement, update the lockfile, run the entire suite and audit again
before closing the finding. CI continues to fail on any runtime advisory at low
severity and development advisories at moderate or higher. The low-severity
exception remains open; a passing gate is not a zero-findings audit.

## Incremental publication

Each functional increment passed relevant local checks and a public-data scan
before publication. All three jobs (quality, verifier and secrets) passed for:

| Commit | Change | CI |
|---|---|---|
| `2086dbb` | Complete mandatory policy checks and immutable PCR selection | [Passed](https://github.com/RogerHdzC/linux-game-integrity/actions/runs/40705630536) |
| `de39f99` | Authenticated verification labels and implemented HTTP v1 contracts | [Passed](https://github.com/RogerHdzC/linux-game-integrity/actions/runs/40706102600) |
| `5aa344d` | Lifecycle/parser corrections and adversarial transaction regressions | [Passed](https://github.com/RogerHdzC/linux-game-integrity/actions/runs/40706848324) |

The report and roadmap are published as a separate documentation increment. Its
run is listed in [GitHub Actions](https://github.com/RogerHdzC/linux-game-integrity/actions).

## Phase boundary

The consolidation software work and its functional CI checks are complete. The
new Phase 2 remains pending: prepare the user's disposable physical Ubuntu machine
and verify recovery before experiments. No VM is required under the revised lab
choice. Enrollment/provenance, log reconstruction, trusted baselines, eBPF/custom
module decisions, external operation and independent review remain later gates.
No live API path produces ACCEPTED in this implementation.
