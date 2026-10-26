# Technical references

Primary sources consulted for this iteration on 2026-10-25. Documentation may
track newer versions than the tested WSL kernel; only the interfaces exercised
locally or in labeled fixtures have been validated here.

- [os-release specification](https://www.freedesktop.org/software/systemd/man/latest/os-release.html): precedence, quoting, missing version and parsing as data.
- [Linux efivarfs](https://docs.kernel.org/filesystems/efivarfs.html): four attribute bytes before UEFI variable data; read-only handling.
- [Kernel module signing](https://docs.kernel.org/admin-guide/module-signing.html): enforcement and signature-validation scope.
- [IMA templates](https://docs.kernel.org/security/IMA-templates.html): measurement event fields and templates; no full-log collection in this phase.
- [tpm2_checkquote](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_checkquote.1/): future signature, qualification and PCR validation, not an implemented feature.
- [WSL version comparison](https://learn.microsoft.com/en-us/windows/wsl/compare-versions): WSL2's managed-VM boundary.
- [Ubuntu Server requirements](https://ubuntu.com/server/docs/reference/installation/system-requirements/): installation context, distinct from our proposed lab allocation.
- [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/): dependency advisory queries, response ordering and pagination.
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0): repository licensing terms; LICENSE contains the official text.

No cited source establishes that this architecture prevents cheating or is
accepted by Riot. Those are not conclusions of this iteration.
