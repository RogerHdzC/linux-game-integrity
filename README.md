# Linux Game Integrity

Open research into which Linux platform integrity properties can be verified,
and what those guarantees would mean for competitive gaming. The long-term aim
is to contribute technical evidence toward potential Riot Vanguard support on
Linux and League of Legends compatibility across distributions.

**Status: Phase 2, native Debian laboratory validation and contract design.**
This repository contains a read-only Rust inventory agent, a stable inventory
JSON contract, separate draft evidence/result contracts, automated tests and a
threat model. It does not make League of Legends run on Linux, integrate with Vanguard, or verify
attestations. This is an independent project, without affiliation with or approval
from Riot Games.

## Implemented capabilities

- Distribution and version from `os-release`; kernel release from procfs.
- Observed UEFI SecureBoot value, when readable.
- TPM class discovery, declared major version and device-node existence.
- Loaded modules, declared module signature enforcement, module-loading lock,
  Kernel Lockdown mode and kernel taint value.
- Readability probes for IMA interfaces and the TPM0 boot event log.
- JSON with explicit sources, unknown values and errors.

All results are **OS-declared and unverified**. The local result is always
`INDETERMINATE`. A valid contract establishes JSON format, not authenticity.

## Requirements and installation

Linux; Rust/Cargo through rustup; a C compiler/linker for building; Python 3.14
with `venv` for contract tests. Python is not required by the compiled agent.
Rust is pinned in `rust-toolchain.toml`, Rust dependencies in `Cargo.lock`, and
Python test dependencies in `tests/requirements.txt`.

```bash
git clone https://github.com/RogerHdzC/linux-game-integrity.git
cd linux-game-integrity
rustup toolchain install 1.84.1 --profile minimal --component clippy --component rustfmt
cargo build --workspace --locked
python3 -m venv .venv
.venv/bin/python -m pip install -r tests/requirements.txt
```

Installation downloads dependencies. At runtime, the agent uses no network,
subprocesses, `sudo`, mounts or TPM commands. It does not change firmware,
Secure Boot, kernel modules or kernel policies.

## Run

```bash
mkdir -p reports
umask 077
cargo run --locked -p lgi-agent -- > reports/inventory.json
.venv/bin/python scripts/validate_inventory.py reports/inventory.json
```

The shell redirection saves the report; the agent only writes to stdout.
`reports/` is excluded from Git for privacy. Run without elevated privileges.
A failed read preserves `permission_denied`, `not_found` or another error with
`value: null`. Do not rerun as root merely to hide these limitations. `--help`
and `--version` are the only options.

Exit code 0: report emitted, including when capabilities are unavailable.
1: output failure. 2: invalid arguments or non-Linux platform. An exit code is
**not** a trust decision.

## Test

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --locked
.venv/bin/python -m unittest discover -s tests/contracts -v
.venv/bin/python scripts/audit_dependencies.py
```

The OSV dependency audit requires network access and sends only dependency names
and versions. GitHub Actions also runs Gitleaks secret scanning. CI does not
publish live inventories as artifacts. A failed OSV query fails the check.

## Layout and documentation

```text
apps/agent/                         Rust CLI and library
packages/attestation-contracts/     JSON Schema v1 and specification
tests/fixtures/                     Explicitly synthetic data
tests/contracts/                    Contract, integration and negative tests
scripts/                           Validation and dependency audit
docs/                              Threat model, design, limits and results
```

- [Threat model](docs/THREAT_MODEL.md) and [requirements](docs/REQUIREMENTS.md).
- [Architecture](docs/ARCHITECTURE.md) and [contract](packages/attestation-contracts/README.md).
- [Privacy](docs/PRIVACY.md) and [limitations](docs/LIMITATIONS.md).
- [Test plan](docs/TEST_PLAN.md), [results](docs/RESULTS_PHASE_0_1.md)
  and [compatibility matrix](docs/COMPATIBILITY.md).
- [Lab requirements](docs/LAB.md), [roadmap](docs/ROADMAP.md)
  and [technical references](docs/REFERENCES.md).

WSL2 remains suitable for development. A native Debian laboratory now supports
firmware-interface and TPM command checks; Ubuntu/Fedora native coverage remains
pending. See [Phase 2 results](docs/RESULTS_PHASE_2.md) and the
[enrollment design](docs/ENROLLMENT_DESIGN.md).
Inventory and attestation research do not require a graphical desktop. Missing
interfaces in WSL do not establish the Windows host's firmware or TPM state.

## Contribute and license

Contributions are welcome: detection improvements, negative tests, security
reviews and reproducible results from other distributions. Read
[CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Do not submit
credentials or unreviewed inventories.

[Apache-2.0](LICENSE) was selected to support broad collaboration and reuse,
including an explicit contributor patent grant under the license's terms.
Contributions use the same license. It does not grant rights to Riot software
or trademarks, or imply Riot's acceptance.

Remote attestation, NestJS, PostgreSQL and policy enforcement remain future work
**after review of this iteration**. Phase 2 does not implement enrollment or quotes.
