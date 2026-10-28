# Lab environment

## Development environment

WSL2 is sufficient for Rust development, parsers, contracts and negative tests.
There is no need to migrate the whole project now. The current environment
exposes real Linux interfaces but not the firmware/TPM/IMA interfaces needed for
hardware-backed validation. A successful test here does not validate host Windows.

## Proposed baseline for the physical lab

This is a practical project baseline, not a measured minimum or a game requirement:

- A dedicated x86-64 machine that can boot native Ubuntu Server 24.04 LTS.
- At least 2 CPU cores, 4 GiB RAM and 20 GiB available disk space for the agent,
  toolchains and basic experiments; 8 GiB RAM and 40 GiB are preferable when the
  future backend/database and logs share the machine.
- UEFI firmware and a TPM 2.0 exposed to Linux. Firmware TPM or discrete TPM must
  have its trust assumptions recorded; neither is accepted automatically.
- Ability to inspect Secure Boot, signed boot components, kernel module-signing
  support, Lockdown and IMA configuration. Later enabling or changing these is
  a separate, reviewed lab task with recovery planning, never an agent action.
- Ordinary user account for the inventory; administrative access held separately
  by the lab owner for any explicitly approved setup.
- Network access to obtain toolchains/dependencies; the inventory itself is offline.

**No graphical interface or GPU is required** for inventory, TPM, IMA or remote
attestation research. Game execution is outside this phase; its requirements
must be assessed separately if an authorized compatibility path becomes available.
Ubuntu publishes its own installation requirements
([Ubuntu Server requirements](https://ubuntu.com/server/docs/reference/installation/system-requirements/));
the capacities above are our suggested development allocation, not vendor minima.

Keep source in Git and clone it onto the lab host. Do not migrate credentials
into the repository. Capture a local inventory before proposing host changes.
Fedora testing comes later and should record its exact release/kernel.

## Virtual lab

A VM or software TPM can help test serialization and cryptographic protocol code
later. Label results virtual/synthetic as appropriate. They do not replace a
physical TPM, native boot-chain measurements or a hostile-hypervisor analysis.
No virtual-TPM setup is installed by this iteration.

## Permissions

EFI variables, IMA policy/logs, Lockdown and TPM interfaces may require permissions
or may not be mounted. The agent records the failure and continues. Do not mount
securityfs, alter ACLs, load modules, change Secure Boot, clear a TPM or create keys
automatically. Lab configuration changes require a separate, explicitly reviewed task.

## Phase 2: native collection procedure

A native Debian 12 laboratory is now tested; WSL remains the build environment.
Ubuntu/Fedora hardware coverage remains pending. The inventory agent is unchanged.
Privileged diagnostics are a separately authorized laboratory procedure, not an
agent feature. Infrastructure-specific automation and raw results remain private.

Build a portable artifact on the development machine, after running the README
quality checks:

```bash
rustup target add x86_64-unknown-linux-musl --toolchain 1.84.1
cargo build --release --locked --target x86_64-unknown-linux-musl
file target/x86_64-unknown-linux-musl/release/lgi-agent
readelf -l target/x86_64-unknown-linux-musl/release/lgi-agent
sha256sum target/x86_64-unknown-linux-musl/release/lgi-agent
git rev-parse HEAD
```

The ELF must have no `INTERP` program header. Record the agent source commit,
Rust version, target and SHA-256 together; a checksum is not a provenance signature.
Deploy that artifact using narrowly scoped configuration management, verify its
checksum at the destination and retain a versioned path. Do not install a build
toolchain on the laboratory server or rebuild during deployment.

On Debian 12 the tested package set is `tpm2-tools=5.4-1`, TSS libraries
`3.2.1-3` and `tpm-udev=0.6`. Preview the transaction before applying it: install
only missing dependencies, no broad upgrades or removals. The udev package may
change device ownership/modes; record those effects. Do not add users to TPM
groups, change device permissions manually, reset the TPM or enable a daemon.
Do not use this version pin on another distribution without checking its packages.

Capture running-container state and available healthchecks, plus failed systemd
units, before installation, immediately after it, and after diagnostics. Stop if
health regresses. These snapshots do not replace application end-to-end tests.
Repeat the configuration apply: no managed-host changes should be required.

Run the binary as the ordinary lab user, with an external timeout, redirecting
stdout using `umask 077`. Run a separate privileged comparison only when explicitly
authorized. Label files `inventory-ordinary.json` and `inventory-privileged.json`;
never replace the ordinary result with the privileged one. Validate each with
`scripts/validate_inventory.py` on the development machine.

The separate authorized TPM diagnostics use the documented resource-manager TCTI:

```bash
sudo timeout 20 tpm2_getcap -T device:/dev/tpmrm0 pcrs
sudo timeout 20 tpm2_getcap -T device:/dev/tpmrm0 algorithms
sudo timeout 20 tpm2_pcrread -T device:/dev/tpmrm0 sha256:0,2,4,7,10
```

References: [capability query](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_getcap.1/)
and [PCR read](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_pcrread.1/).
Keep outputs private. A successful command is a collected observation, not an
independent signature/provenance check. The inventory's `commandAccess` remains
`not-tested` because these commands run outside the agent.

Inspect only a bounded, filtered kernel journal for TPM/IMA/Lockdown warnings.
Do not collect full event logs or read EK/AK material in this phase. No reboot,
firmware change, IMA policy change or enrollment is needed for this procedure.
Rollback removes only the newly deployed laboratory artifact and manifest;
package removal must first account for dependencies and any shared use.
