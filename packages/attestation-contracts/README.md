# Inventory contract v1

The normative definition is `inventory-v1.schema.json`, JSON Schema 2020-12.
`scripts/validate_inventory.py` also limits reports to 8 MiB and rejects duplicate
keys. All objects reject extra properties. Incompatible changes require a new
`schemaVersion` and migration tests.

| Field | Rule and meaning |
|---|---|
| schemaVersion / kind | Constants `1` / `linux-inventory` |
| origin | `live` for local reads, `synthetic` for fixtures; not proof of origin |
| trust | Constant `os-declared-unverified` |
| agentVersion | Agent version, at most 64 characters |
| platform | Observations described below |
| evidence | Four `false` constants: no collected measurements, quote, cryptographic backing or server verification |
| result | Only `INDETERMINATE` |
| limitations | 1–32 explanations, up to 1024 characters each |

Every observation includes `status`, `source`, `value` and `error`:

| status | value | error |
|---|---|---|
| observed | Specific non-null type | null |
| unavailable | null | not_found |
| error | null | permission_denied, invalid_data, too_large or io |

`source` identifies the queried interface, up to 512 characters. Raw exception
messages are not included. `unavailable` does not prove missing hardware.
`observed` means a successful read, not trust in its contents.

## Platform observations

- `distribution`: os-release `id` and nullable `versionId`; rolling distributions
  may omit VERSION_ID. `/etc/os-release` takes precedence, with fallback to
  `/usr/lib/os-release` only when absent. Files are never merged.
- `kernelRelease`: `/proc/sys/kernel/osrelease`, at most 256 bytes in the agent.
  The schema allows 256 characters; the agent applies the stricter byte limit.
- `environmentHint`: `wsl` when the kernel name contains microsoft; otherwise
  `unknown`. No automatic bare-metal claim is made.
- `secureBoot`: `enabled`/`disabled` from a UEFI variable with four attribute bytes
  and one boolean byte. Certificates, SetupMode and the boot chain are not checked.
- `tpm.classDevices`: `tpmN` names enumerated from sysfs. An empty list means
  successful enumeration with no entries; null means error/unavailable interface.
- `tpm.majorVersions`: 1 or 2 as declared by `tpm_version_major`; each observation
  retains its source path. `deviceNodes` only checks existence through metadata;
  devices are not opened and command access is not tested.
  `commandAccess` remains `not-tested`.
- `loadedModules`: up to 4096 entries with name, size in bytes, reference count
  (including the kernel's -1 value), and Live/Loading/Unloading state. Addresses,
  dependencies, paths and signatures are omitted. Built-in kernel components
  are not listed.
- `moduleSignatureEnforcement`: declared `sig_enforce` parameter.
- `modulesDisabled`: declared `modules_disabled` value, not verification of
  signatures on already loaded modules.
- `lockdown`: active none/integrity/confidentiality mode; not inferred from Secure Boot.
- `kernelTaint`: kernel-reported unsigned integer; zero does not prove security.
- `measurementInterfaces`: probe at most one byte, discarded, from ASCII/binary
  IMA logs, IMA policy and the TPM0 boot log. `true` only means the read succeeded;
  empty files are readable too. No measurements are collected.

Content reads are capped at 1 MiB and reject oversized data instead of silently
truncating it. Sysfs enumeration is limited to 4096 entries. There is no hard
read deadline against a kernel that stalls an operation.

## Separation from the future verifier

The client cannot submit `quoteVerified`, `nonceVerified` or `ACCEPTED` in this
format. A future phase will define separate request and server-result contracts.
The server must independently verify signatures, AK provenance, nonce, PCRs and
policy. Neither this schema nor its validator implements those checks. An
attacker can still produce schema-valid JSON containing false observations.

## Phase 2 design drafts

The separate `evidence-submission-draft.schema.json` and
`verification-result-draft.schema.json` use version `0.1-draft`. They do not
change inventory-v1, add an endpoint or implement cryptographic verification.
The request rejects client-provided decisions. The result describes a future
server response and requires all checks VERIFIED for ACCEPTED.

See [enrollment and protocol design](../../docs/ENROLLMENT_DESIGN.md) for field
encodings, bounds, trust boundaries and unimplemented semantic checks. Fixtures
are synthetic; even a schema-valid quote may contain meaningless bytes. Do not
use schema validation as an attestation verifier.
