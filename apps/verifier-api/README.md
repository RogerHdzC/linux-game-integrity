# Experimental verifier — implemented HTTP v1

A local NestJS API, PostgreSQL challenge state and bounded TPM quote verification.
It is a laboratory service with **one client principal**. It is not deployed on
the native lab host or exposed publicly. No game integration is implemented.

## Dependencies

Node 22.15.1, NestJS 11.2.8 (CommonJS-compatible), TypeScript 5.9.3, PostgreSQL 16,
`pg` for explicit parameterized SQL/transactions, Express for bounded raw-body
parsing, and Node/OpenSSL for RSA signature verification. Jest/Supertest test the
API; pinned Prettier checks the new TypeScript/JavaScript formatting. All package versions and transitive resolutions are locked. Prisma is omitted:
three small tables and explicit reservation transactions do not require an ORM.
`multer` is overridden to patched 2.5.0 although this service has no upload routes.

The known low-severity deepmerge advisory GHSA-gcqx-w48m-w2h4 affects the Jest
configuration dependency, not runtime dependencies. No patched release was
available at implementation time. Only trusted repository test configuration is
loaded. CI audits runtime dependencies at low severity and development dependencies
at moderate severity; this exception is documented, not a clean-audit claim.

## Local setup

Use a disposable database. Docker Compose is optional; a separately provisioned
PostgreSQL 16 instance also works. Run commands from the repository root:

```bash
npm ci --ignore-scripts
npm run build
export LGI_POSTGRES_PASSWORD="$(openssl rand -hex 24)"
docker compose -f infra/docker-compose.yml up -d --wait
export DATABASE_URL="postgresql://lgi_lab:${LGI_POSTGRES_PASSWORD}@127.0.0.1:55432/lgi_lab"
npm run migrate
export LGI_CLIENT_TOKEN="$(openssl rand -hex 32)"
export LGI_ADMIN_TOKEN="$(openssl rand -hex 32)"
npm start
```

The API binds **127.0.0.1:3000**. Use an authenticated SSH tunnel for remote lab
access. Public deployment requires TLS, multi-user authorization, stronger rate
limits and operational review. Never expose this HTTP listener through a public
reverse proxy as-is. Tokens are environment inputs, never included in reports.
Distinct tokens must contain at least 32 bytes. Both are lab-wide credentials;
per-device identity and credential rotation without restart are future work.

`npm run migrate` applies the transactional, advisory-lock-protected initial
schema. Run `LGI_TEST_DATABASE_URL="$DATABASE_URL" npm test` only against a
disposable test database. Tests create synthetic enrollments/evaluations and modify
test rows; they require PostgreSQL and fail instead of silently skipping it.

Stop with Ctrl-C. Stop Compose using `docker compose -f infra/docker-compose.yml
stop`; the database volume is retained. Removing a volume is a separate data-loss
operation. Configuration changes on shared hosts belong in private Ansible.

## Version 1 API

All requests use JSON and `Authorization: Bearer <token>`. Admin registration and
revocation require the separate admin token. Unknown fields, duplicate JSON keys,
invalid encodings, excessive nesting (>32) and bodies over 64 KiB are rejected.
Compressed request bodies are not supported. Values are never interpolated into SQL.

| Method / path | Required body | Behavior |
|---|---|---|
| POST /v1/enrollments | `publicKey`: RSA-2048 SPKI PEM | Admin registers an **UNPROVEN** key; returns opaque enrollmentId |
| POST /v1/enrollments/:id/revoke | `{}` | Admin revokes enrollment; outstanding challenges cannot establish acceptance |
| POST /v1/challenges | `enrollmentId` | Returns challengeId, nonce (32-byte lowercase hex), policyVersion, PCR selection and expiresAt |
| POST /v1/evaluations | `schemaVersion: 1`, `challengeId`, `nonce`, `quote` | Consumes challenge and persists a server-generated evaluation |

A quote is null for missing evidence, or an object containing `attest`, `signature`
and `pcrs`. `attest` is hex TPMS_ATTEST without a TPM2B prefix; `signature` is hex
TPMT_SIGNATURE with RSASSA/SHA-256. Both have an 8 KiB decoded bound. `pcrs` contains
exactly five `{index, digest}` objects for SHA-256 indices 0,2,4,7,10, each digest
32-byte lowercase hex; indices must be unique. Other banks, signatures, key sizes
and selections are rejected explicitly. Real tpm2-tools 5.4 output was tested.
The Phase 2 draft schemas remain historical designs, not these route contracts.
This API uses equivalent strict runtime validation in `src/input.ts`, typed
server responses in `src/responses.ts`, and HTTP contract regression tests.
See [implemented protocol](../../docs/PROTOCOL_V1.md) for the trust boundaries.

Responses include schemaVersion, evaluationId, challengeId, policyVersion, result,
checks and reason codes. HTTP 201 means a resource/result was created, **not** that
integrity was accepted. Invalid/replayed/expired challenges return 409; invalid
input 400, authentication 401, unavailable enrollment 404, excess body 413,
non-JSON 415, issuance rate limit 429, and storage/internal failure 503.

## Verification and state semantics

Policy `lab-tpm-sha256-v1` fixes SHA-256 PCRs 0,2,4,7,10 and a 120-second TTL.
The server stores nonce, principal, enrollment and immutable policy version.
A conditional PostgreSQL UPDATE atomically consumes an unexpired challenge
**before** decoding/verifying a quote. A crash or failure after reservation burns
the challenge; retry requires a new challenge. Issuance is limited to 60/minute
for the single client with a database advisory lock. Token possession is the
current authentication boundary. No client result or trust flag is accepted.

The decoder checks magic/type, lengths, supported algorithms, selection and trailing
bytes. Node crypto verifies the exact signed bytes. The server compares signed
qualifying data to its stored nonce and hashes supplied PCR values in selection
order to check the quote's digest. Revocation is checked again under a database
lock before persisting a result. Invalid signature/nonce/PCR binding rejects.
When the signature fails, matching nonce/PCR bytes cannot become VERIFIED; their
checks remain NOT_CHECKED (an already detected envelope nonce mismatch stays FAILED).

There is **no production acceptance path**: key provenance, measurement coverage
and the trusted baseline remain unavailable. A valid quote therefore returns
INDETERMINATE. PCR digest binding is distinct from IMA/boot-log replay and policy
coverage, which are not implemented. The pure policy engine's ACCEPTED case is
covered only by explicitly synthetic unit tests with all six mandatory checks marked
verified. Missing, inherited, extra or malformed checks cannot enable acceptance;
an explicit mandatory failure produces REJECTED. The PCR selection is immutable.

## Privacy and retention

Raw quote bytes, PCR values and incoming bodies are not persisted or logged by
the API. PostgreSQL stores public keys as UNPROVEN enrollments, challenge state,
minimal checks/reasons and timestamps. Public keys can correlate devices; restrict
database access. Startup and hourly maintenance delete evaluations older than
30 days, then old expired challenges, then revoked enrollments older than 30 days
when no retained challenge references them. Active keys remain until revocation.
No access logging or request-body error logging is enabled. Storage failures
return generic errors without database details or supplied evidence.

## Real laboratory evidence

`scripts/lab/quote.py` is an explicitly authorized operator tool, separate from the
Rust inventory agent. Its `prepare` operation creates a temporary restricted
RSA signing key under the NULL hierarchy using the kernel resource-manager TCTI.
Its `quote` operation signs the server nonce and writes private evidence. It does
not provision an EK, activate credentials, persist handles or change ownership.
The operator must delete the experiment directory after collecting the result;
never use global flush/TPM clear commands. The private Ansible workflow performs
that scoped cleanup and compares service-health snapshots around operations.

See [Phase 3 results](../../docs/RESULTS_PHASE_3.md) for executed tests and blockers.
