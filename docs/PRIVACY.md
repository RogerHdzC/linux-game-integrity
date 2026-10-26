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
No server retention policy or privacy guarantee is implemented in this phase.
