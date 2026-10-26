# Project instructions

- Use English for documentation, comments, CLI messages and communication.
- Work incrementally; read README and docs before changing architecture.
- Phases 0 and 1 cover read-only local inventory. Do not start remote attestation
  until the user has reviewed this iteration.
- Do not modify, disable, intercept or bypass Vanguard; do not inject into or
  manipulate game processes. Use an independent lab.
- Do not change host firmware, Secure Boot, modules, TPM, mounts or policies.
  Document privilege requirements; never elevate the agent automatically.
- Distinguish declared data, measurements, cryptographic evidence and server
  verification. Never turn missing data or errors into acceptance.
- Clearly label fixtures as synthetic. Keep live reports locally in `reports/`
  unless their publication has been explicitly reviewed.
- Do not commit secrets, permanent identifiers or raw IMA logs.
- Run formatting, Clippy, Cargo tests and contract tests after functional changes.
  Record only results actually observed.
- Justify and pin dependencies; keep code, contract and documentation aligned.
  Seek independent review before drawing security conclusions.
- Current CI: GitHub Actions. This does not authorize deployments.
