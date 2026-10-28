const request = require("supertest");
const { Pool } = require("pg");
const { randomBytes } = require("node:crypto");
const { createApp } = require("../../../dist/apps/verifier-api/src/main");
const { migrate } = require("../../../dist/apps/verifier-api/src/migrate");
const { synthetic, publicKey } = require("./synthetic");
// This suite REQUIRES a disposable PostgreSQL database: it never silently skips.
let pool, app, service, enrollment;
const client = randomBytes(32).toString("hex"),
  admin = randomBytes(32).toString("hex");
const post = (path, body, token = client) =>
  request(app.getHttpServer())
    .post("/v1/" + path)
    .set("Authorization", "Bearer " + token)
    .send(body);
beforeAll(async () => {
  if (!process.env.LGI_TEST_DATABASE_URL)
    throw new Error(
      "LGI_TEST_DATABASE_URL must name an isolated test database",
    );
  pool = new Pool({
    connectionString: process.env.LGI_TEST_DATABASE_URL,
    max: 5,
  });
  await migrate(pool);
  await migrate(pool);
  ({ app, service } = await createApp(pool, client, admin));
  const r = await post("enrollments", { publicKey }, admin);
  expect(r.status).toBe(201);
  enrollment = r.body.enrollmentId;
});
afterAll(async () => {
  if (app) await app.close();
  if (pool) await pool.end();
});
async function challenge() {
  const r = await post("challenges", { enrollmentId: enrollment });
  expect(r.status).toBe(201);
  return r.body;
}
function submission(c) {
  return {
    schemaVersion: 1,
    challengeId: c.challengeId,
    nonce: c.nonce,
    quote: synthetic(c.nonce),
  };
}
test("auth and strict JSON boundaries", async () => {
  expect((await post("challenges", {}, "wrong")).status).toBe(401);
  expect((await post("enrollments", { publicKey })).status).toBe(401);
  expect(
    (await post("challenges", { enrollmentId: enrollment, result: "ACCEPTED" }))
      .status,
  ).toBe(400);
  const duplicate = await request(app.getHttpServer())
    .post("/v1/challenges")
    .set("Authorization", "Bearer " + client)
    .set("Content-Type", "application/json")
    .send('{"enrollmentId":"x","enrollmentId":"y"}');
  expect(duplicate.status).toBe(400);
  expect(
    (await post("challenges", { padding: "x".repeat(65536) })).status,
  ).toBe(413);
});
test("valid synthetic quote checks crypto but cannot establish hardware trust", async () => {
  const c = await challenge(),
    r = await post("evaluations", submission(c));
  expect(r.status).toBe(201);
  expect(r.body.result).toBe("INDETERMINATE");
  expect(r.body.checks).toMatchObject({
    signature: "VERIFIED",
    freshness: "VERIFIED",
    pcrBinding: "VERIFIED",
    keyProvenance: "UNAVAILABLE",
    measurements: "UNAVAILABLE",
  });
  const stored = await pool.query("SELECT * FROM lgi_evaluations WHERE id=$1", [
    r.body.evaluationId,
  ]);
  expect(stored.rows[0].result).toBe("INDETERMINATE");
  expect(stored.rows[0].public_key).toBeUndefined();
  expect((await post("evaluations", submission(c))).status).toBe(409);
});
test("concurrent replay has exactly one winner", async () => {
  const c = await challenge(),
    body = submission(c);
  const results = await Promise.all(
    Array.from({ length: 8 }, () => post("evaluations", body)),
  );
  expect(results.filter((r) => r.status === 201)).toHaveLength(1);
  expect(results.filter((r) => r.status === 409)).toHaveLength(7);
});
test("expired, wrong nonce, invalid signature and inconsistent PCRs never accept", async () => {
  const expired = await challenge();
  await pool.query(
    "UPDATE lgi_challenges SET expires_at=now()-interval '1 second' WHERE id=$1",
    [expired.challengeId],
  );
  expect((await post("evaluations", submission(expired))).status).toBe(409);
  for (const mutate of [
    (b) => (b.nonce = "00".repeat(32)),
    (b) => (b.quote.attest = "00"),
    (b) => (b.quote.pcrs[0].digest = "11".repeat(32)),
  ]) {
    const c = await challenge(),
      body = submission(c);
    mutate(body);
    const r = await post("evaluations", body);
    expect(r.body.result).toBe("REJECTED");
  }
});
test("missing quote remains indeterminate and client acceptance is rejected", async () => {
  const c = await challenge(),
    body = { ...submission(c), quote: null };
  expect(
    (await post("evaluations", { ...body, result: "ACCEPTED" })).status,
  ).toBe(400);
  expect((await post("evaluations", body)).body.result).toBe("INDETERMINATE");
});
test("revocation invalidates outstanding challenges", async () => {
  const e = await post("enrollments", { publicKey }, admin);
  const c = (await post("challenges", { enrollmentId: e.body.enrollmentId }))
    .body;
  expect(
    (await post("enrollments/" + e.body.enrollmentId + "/revoke", {}, admin))
      .status,
  ).toBe(201);
  expect((await post("evaluations", submission(c))).body.result).toBe(
    "REJECTED",
  );
  expect(
    (await post("challenges", { enrollmentId: e.body.enrollmentId })).status,
  ).toBe(404);
});
test("state persists across application restart", async () => {
  const c = await challenge();
  await post("evaluations", submission(c));
  await app.close();
  ({ app, service } = await createApp(pool, client, admin));
  expect((await post("evaluations", submission(c))).status).toBe(409);
});
test("database failure yields service unavailable and not acceptance", async () => {
  const broken = new Pool({
    connectionString: "postgres://127.0.0.1:1/unavailable",
    connectionTimeoutMillis: 100,
  });
  const other = await createApp(broken, client, admin);
  const r = await request(other.app.getHttpServer())
    .post("/v1/challenges")
    .set("Authorization", "Bearer " + client)
    .send({ enrollmentId: enrollment });
  expect(r.status).toBe(503);
  await other.app.close();
  await broken.end();
});
test("retention removes expired records without storing raw evidence", async () => {
  const c = await challenge();
  await post("evaluations", submission(c));
  await pool.query(
    "UPDATE lgi_evaluations SET created_at=now()-interval '31 days' WHERE challenge_id=$1",
    [c.challengeId],
  );
  await pool.query(
    "UPDATE lgi_challenges SET expires_at=now()-interval '31 days' WHERE id=$1",
    [c.challengeId],
  );
  await service.cleanup();
  expect(
    (
      await pool.query("SELECT id FROM lgi_challenges WHERE id=$1", [
        c.challengeId,
      ])
    ).rowCount,
  ).toBe(0);
});
test("a storage failure after reservation cannot reopen the challenge", async () => {
  const { Verifier } = require("../../../dist/apps/verifier-api/src/service");
  const c = await challenge();
  const failed = new Verifier({
    query: pool.query.bind(pool),
    connect: async () => {
      throw new Error("synthetic storage outage");
    },
  });
  await expect(failed.evaluate(submission(c))).rejects.toThrow(
    "synthetic storage outage",
  );
  expect((await post("evaluations", submission(c))).status).toBe(409);
});
test("migration failure rolls back all schema statements", async () => {
  const isolated = await pool.connect();
  const failing = {
    connect: async () => ({
      query: async (sql, ...args) => {
        if (sql.includes("CREATE TABLE IF NOT EXISTS lgi_migrations")) {
          await isolated.query(
            "CREATE TABLE lgi_synthetic_rollback (id integer)",
          );
          return isolated.query("SELECT nonexistent_lgi_migration_function()");
        }
        return isolated.query(sql, ...args);
      },
      release: () => {},
    }),
  };
  try {
    await expect(migrate(failing)).rejects.toThrow();
    expect(
      (
        await isolated.query(
          "SELECT to_regclass('lgi_synthetic_rollback') AS name",
        )
      ).rows[0].name,
    ).toBeNull();
  } finally {
    isolated.release();
  }
});

test("invalid signatures cannot authenticate nonce or PCR comparisons", async () => {
  const c = await challenge(),
    body = submission(c);
  body.quote.signature =
    body.quote.signature.slice(0, -2) +
    (body.quote.signature.endsWith("ff") ? "00" : "ff");
  const r = await post("evaluations", body);
  expect(r.status).toBe(201);
  expect(r.body.result).toBe("REJECTED");
  expect(r.body.checks).toMatchObject({
    signature: "FAILED",
    freshness: "NOT_CHECKED",
    pcrBinding: "NOT_CHECKED",
  });
  expect(r.body.reasons).toContain("INVALID_SIGNATURE");
});
test("HTTP v1 response contracts are server-generated and distinct from drafts", async () => {
  const c = await challenge();
  expect(Object.keys(c).sort()).toEqual(
    [
      "schemaVersion",
      "challengeId",
      "nonce",
      "policyVersion",
      "pcrBank",
      "pcrs",
      "expiresAt",
    ].sort(),
  );
  expect(c.schemaVersion).toBe(1);
  expect(c.nonce).toMatch(/^[a-f0-9]{64}$/);
  expect(c.pcrs).toEqual([0, 2, 4, 7, 10]);
  expect(Number.isFinite(Date.parse(c.expiresAt))).toBe(true);
  const body = submission(c);
  for (const extra of [
    { checks: { signature: "VERIFIED" } },
    { keyProvenance: "TRUSTED" },
    { result: "ACCEPTED" },
  ])
    expect((await post("evaluations", { ...body, ...extra })).status).toBe(400);
  const r = await post("evaluations", body);
  expect(Object.keys(r.body).sort()).toEqual(
    [
      "schemaVersion",
      "evaluationId",
      "challengeId",
      "policyVersion",
      "result",
      "checks",
      "reasons",
    ].sort(),
  );
  expect(Object.keys(r.body.checks).sort()).toEqual(
    [
      "keyProvenance",
      "signature",
      "freshness",
      "pcrBinding",
      "measurements",
      "policy",
    ].sort(),
  );
  expect(r.body).toMatchObject({
    schemaVersion: 1,
    challengeId: c.challengeId,
    policyVersion: c.policyVersion,
    result: "INDETERMINATE",
  });
});
