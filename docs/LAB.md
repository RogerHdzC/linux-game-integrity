# Lab environment

## Keep WSL for this iteration

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
