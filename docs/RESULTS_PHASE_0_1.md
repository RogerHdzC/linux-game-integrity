# Phase 0/1 results

Date: 2026-10-25 (America/Mexico_City). Scope: first inventory iteration only.

## Initial inspection

The workspace contained no application code, README, project instructions or
usable Git history. The user supplied the project requirements.
Observed tools: Rust/Cargo 1.84.1, rustfmt, Clippy, Git, Node.js/npm, Python and Docker
CLI. No prior application architecture or CI existed to reuse.

The environment identified itself as Ubuntu 24.04.5 LTS, with os-release version
ID 24.04 and kernel `5.15.167.4-microsoft-standard-WSL2`. Python 3.14.2 was used
for contract tests. No deployment or host configuration change was needed.

## Delivered

- A compiled Rust library and CLI for read-only Linux inventory.
- A strict versioned JSON Schema, standalone format validator, normalized errors
  and explicit unverified evidence/result fields.
- Synthetic fixtures, parser/collector/CLI integration tests and negative contract tests.
- Threat model, requirements, architecture, privacy, limits, lab plan, test plan,
  compatibility matrix and roadmap.
- English community guidance, Apache-2.0 license and attribution notice.
- GitHub Actions configuration for formatting, Clippy, build, tests, contract
  validation, OSV dependency audit and Gitleaks secret scanning.

## Observed validation

Commands were executed from the repository root. A temporary Cargo home and
Python virtual environment were used because the session restricts writes outside
the workspace; these do not change repository instructions or runtime behavior.

```text
cargo fmt --all -- --check                              passed
cargo clippy --workspace --all-targets --locked -- -D warnings  passed
cargo build --workspace --locked                        passed
cargo test --workspace --locked                         16 passed
python -m unittest discover -s tests/contracts -v        13 passed
python scripts/validate_inventory.py reports/inventory-wsl.json  passed
python scripts/audit_dependencies.py                    16 versions, no advisories returned
```

After fetching dependencies, Rust checks also passed with `--offline`. The
contract tests execute the real local binary in addition to synthetic inputs.
These checks do not validate physical TPM signatures, PCR replay or a server.
Gitleaks 8.24.2 scanned all 35 publication files (about 130 KB) and found no
secrets. Its release archive was checked against the published SHA-256 checksum.
The implementation was published to the public repository. The original GitHub
Actions validation completed successfully: both `quality` and `secrets` passed.
This included the locked build, formatting, Clippy, Rust tests, contract/integration
tests, live runner inventory validation, dependency audit and history secret scan.
Current checks are available on the repository's Actions page.

## Live observations and limits

The local JSON contains `origin: live`, `trust: os-declared-unverified` and
`result: INDETERMINATE`. It records Ubuntu/kernel information, an empty module
list, module loading not disabled and kernel taint zero. SecureBoot, TPM,
signature-enforcement, Lockdown and IMA/boot-log interfaces were not exposed.
No missing capability was converted to false or a positive security conclusion.

The complete report stays in ignored `reports/`. The public summary omits
machine/user identifiers. All fixture inputs are separately marked synthetic.
No game, Vanguard component or Riot endpoint was used.

## Remaining work and review boundary

The overall MVP is **not complete**. Remote attestation, AK provenance, signatures,
nonce/replay handling, PCR/log validation, a policy engine, API access control,
PostgreSQL/migrations and persistence are not implemented. Hardware-dependent
checks require a native lab; none have been simulated as successful validation.

Review this iteration before beginning the next implementation phase. Recommended
next work: review the threat model and contract, collect a baseline on a native
Ubuntu lab host, then design enrollment, evidence and server-result contracts.
WSL development can continue without migrating the whole workspace.
