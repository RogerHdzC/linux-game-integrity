# Privacy

## Collected data and purpose

The agent reports distribution/version, kernel release, selected security-control
observations, loaded module names/sizes/reference counts/states, TPM interface
presence/version, interface paths and normalized error codes. These support
capability comparison and explain why a future attestation may be unavailable.

It omits hostname, usernames, machine-id, IP/MAC addresses, hardware serials,
EK/AK material, memory addresses, raw IMA events and boot logs. Readability probes
read at most one byte and discard it. Error messages do not echo arbitrary file
contents or operating-system exception text.

Distribution, kernel and uncommon module combinations can still fingerprint a
machine. Minimization reduces that risk; it does not make the inventory anonymous.

## Transport, storage and retention

The agent has no network client and no persistent storage. Reports go to stdout;
users choose whether to redirect them to a local file. `reports/` is ignored by
Git. Use `umask 077`. No automatic deletion is performed: users control retention
and should delete local reports when an experiment no longer needs them.

Do not attach raw reports to issues without reviewing them. Publish capability
summaries instead. CI validates ephemeral runner output but does not upload it
as an artifact. CI logs retain test results according to repository settings.

The separate development audit sends public dependency names/versions to OSV.
It never sends inventory data. GitHub hosts public source and CI results.

## Future design requirements

Before adding a server, define consent, authentication, retention/deletion,
access controls, audit minimization and an enrollment strategy that avoids
unnecessary permanent device identifiers. EK certificates and persistent AKs can
link sessions; raw measurement logs may reveal file paths and installed software.
Phase 3 implements laboratory retention as described below; a complete privacy
guarantee and externally reviewed enrollment design remain unestablished.

## Phase 2 laboratory handling

The separate privileged diagnostics collect selected PCR values and bounded
TPM-related kernel messages into private controller reports, never public CI
artifacts. Report directories use mode 0700 and files 0600. Keep execution
privilege labels separate from the stable inventory contract. Raw reports can
contain infrastructure details and must not be committed or attached to issues.
Delete them when review no longer needs them; no automatic purge is installed.
Publish only reviewed capability summaries. The proposed future enrollment and
server retention defaults are in [ENROLLMENT_DESIGN.md](ENROLLMENT_DESIGN.md).

## Phase 3 local service

The API persists unproven public keys, opaque enrollment/challenge/evaluation IDs,
nonces, timestamps, policy versions and check/reason codes. It does not persist
raw quotes, PCR values or incoming request bodies. The single client uses a
shared laboratory credential; this is not anonymous or multi-user operation.
Startup/hourly cleanup deletes old evaluations and expired challenge state after
30 days, then revoked enrollments after 30 days when references are gone.
Active public keys remain until revocation; keys can correlate sessions.

Native experiments retain real quote/public-key reports only in private local
storage. Temporary context files are removed after collection through scoped
Ansible cleanup. Source-control exclusion does not encrypt files; restrict access
and remove reports when no longer needed. See the verifier README for setup,
retention ordering and access limitations.
