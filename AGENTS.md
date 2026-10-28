# Project instructions

- Use English for documentation, comments, CLI messages and communication.
- Work incrementally; read README and docs before changing architecture.
- Follow the current phase boundary in docs/ROADMAP.md. Historical Phases 0–3
  reports use the earlier numbering. The current authorized increment is
  consolidation Phase 1; later laboratory, enrollment and kernel work requires
  its own authorization.
- Commit and push reviewable increments after relevant checks and public-data
  review; check GitHub Actions before proceeding with dependent changes.
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
