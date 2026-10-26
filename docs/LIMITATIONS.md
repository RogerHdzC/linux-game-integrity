# Limitations and interpretation

## Evidence levels

| Level | Meaning | Current implementation |
|---|---|---|
| OS-declared | A local interface returned a value | Implemented, unverified |
| Collected measurements | Actual PCR values or event-log entries collected with context | Not implemented; readability probes are not measurements |
| Cryptographically backed | Evidence signed under a defined key and format | Not implemented |
| Server verified | Independent checks of signature, provenance, freshness and measurement consistency | Not implemented |
| Security conclusion | Policy-specific claim within explicit assumptions | No acceptance decision or cheat-free conclusion |

A schema-valid report is not cryptographic evidence. A hostile client can produce
one. The inventory is not an atomic snapshot, and values can change between reads.

## Secure Boot, modules and Lockdown

The SecureBoot variable is an OS-exposed observation. It does not establish the
trustworthiness of firmware, certificate databases, revocation state, the agent
or current runtime memory. The agent does not check SetupMode or reconstruct the
boot chain. The documented efivarfs layout includes four attribute bytes before
the payload ([kernel documentation](https://docs.kernel.org/filesystems/efivarfs.html)).

Module signature checking occurs in the kernel; the reported enforcement flag
and module list are not independent signature validation. A built-in component
is not listed in `/proc/modules`. Lockdown modes restrict operations but are
not a proof that the kernel has never been compromised. See the
[module signing documentation](https://docs.kernel.org/admin-guide/module-signing.html).

## TPM

A sysfs class entry, version string or device node does not establish TPM command
access, manufacturer provenance, key enrollment or trust in the caller. TPM 1.2
is recorded distinctly from TPM 2.0. No commands, PCR reads, keys or quotes are
used in this iteration.

A future quote may bind selected PCR state to a challenge under an attestation
key. Checking the signature, qualifying data and PCR digest still requires a
separate decision about key provenance and allowed measurements. See
[tpm2_checkquote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/).

## IMA and runtime coverage

An accessible log does not prove IMA policy coverage, completeness, appraisal or
replay consistency with a TPM quote. Different templates encode different event
fields ([IMA templates](https://docs.kernel.org/security/IMA-templates.html)).
Coverage must be analyzed against the configured policy; a measured file is not
proof of all subsequent in-memory execution. JIT code, mutable process memory,
peripherals, DMA, privileged attacks and post-measurement changes require separate
analysis. No cheat-free guarantee follows from IMA.

## Virtualization, WSL and portability

WSL2 runs a Linux kernel in a managed VM
([Microsoft architecture comparison](https://learn.microsoft.com/en-us/windows/wsl/compare-versions)).
In this tested execution environment, EFI, TPM and securityfs interfaces were not
exposed. This says nothing definitive about the Windows host's physical TPM or
Secure Boot. Sandboxing can further restrict visibility.

A virtual TPM can support protocol experiments but does not establish a physical
root of trust independent of its host. Host-controlled snapshots and rollback
need explicit treatment. `environmentHint: unknown` does not establish bare metal.

Only the listed WSL environment has been tested live. Ubuntu bare metal, Fedora,
other kernels/architectures and physical TPM behavior remain unvalidated. The
fixed boot-log probe currently targets TPM0; nonzero TPMs are enumerated for
version/node observations but their boot logs are not dynamically discovered.

## Operational limits

Reads are size bounded, not time bounded. A hostile or malfunctioning kernel can
stall them. File-type checks do not prevent a privileged actor from racing path
resolution. UTF-8 and conservative field parsing can reject unusual declarations;
errors remain explicit rather than becoming secure defaults.

No remote protocol, replay protection, API authorization, database, migrations,
cryptographic verification, policy engine or game integration exists yet.
