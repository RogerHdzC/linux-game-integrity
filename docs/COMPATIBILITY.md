# Compatibility matrix

WSL observations from 2026-10-25; native Debian observations from 2026-10-26. The live row describes the execution environment
visible to the agent, including WSL and sandbox restrictions. It is not a
statement about physical host hardware or compatibility with a game.

| Environment | Inventory | SecureBoot variable | TPM interfaces | IMA / boot log | Status |
|---|---|---|---|---|---|
| Ubuntu 24.04, 5.15.167.4-microsoft-standard-WSL2 | Distribution/kernel read; empty loaded-module list | Not exposed | Class/nodes not exposed | Not exposed | Live local execution passed schema |
| Synthetic Ubuntu-like fixture, 6.8.0-synthetic | Parser/collector inputs exercised | Synthetic enabled value | Synthetic TPM 2.0 declaration | Synthetic readable interfaces, not real logs | Tests only; no hardware claim |
| Native Debian 12.15, 6.1.0-54-amd64 (ordinary user) | Distribution/kernel/modules read; static agent runs | Enabled, OS-declared | TPM 2.0 interfaces detected; commands outside agent | Permission denied for IMA/boot-log probes | Live output passed inventory-v1 |
| Same native Debian environment (explicit privileged comparison) | Same inventory fields readable | Enabled, OS-declared | Separate tools successfully read capabilities and selected PCRs | IMA logs and boot log probe readable; IMA policy denied | Live output passed inventory-v1; no quote verification |
| Native Ubuntu Server 24.04 LTS | Not yet tested | Unknown | Unknown | Unknown | Physical lab needed |
| Fedora | Not yet tested | Unknown | Unknown | Unknown | Later distribution validation |
| VM with virtual TPM | Not yet tested | Unknown | Unknown | Unknown | Future protocol lab, different trust class |

The real WSL run observed `modulesDisabled: false` and `kernelTaint: 0`.
The signature-enforcement and Lockdown interfaces were unavailable. These values
remain OS-declared; taint zero is not evidence of a trustworthy kernel.

Record exact distribution, kernel, agent commit, commands, interface errors and
physical/virtual context for each new row. Do not infer support for all kernels
or distributions from one successful build. Prefer reviewed summaries over raw
inventories in public contributions.

See [Phase 2 results](RESULTS_PHASE_2.md) for package versions, evidence levels,
permission differences and unresolved TPM firmware warnings. No PCR/log replay
or physical-key provenance validation has been performed.
