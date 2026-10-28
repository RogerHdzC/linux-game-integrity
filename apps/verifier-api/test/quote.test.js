const { checkQuote } = require("../../../dist/apps/verifier-api/src/quote");
const { decide } = require("../../../dist/packages/policy-engine");
const { parseJson } = require("../../../dist/apps/verifier-api/src/input");
const { synthetic, publicKey } = require("./synthetic");

test("synthetic signature, signed nonce and PCR digest are checked independently", () => {
  const q = synthetic("ab".repeat(32));
  expect(checkQuote(q, publicKey, "ab".repeat(32))).toEqual({
    signature: true,
    nonce: true,
    pcrBinding: true,
  });
  expect(checkQuote(q, publicKey, "cd".repeat(32)).nonce).toBe(false);
  const bad = {
    ...q,
    signature:
      q.signature.slice(0, -2) + (q.signature.endsWith("ff") ? "00" : "ff"),
  };
  expect(checkQuote(bad, publicKey, "ab".repeat(32)).signature).toBe(false);
  q.pcrs[0].digest = "11".repeat(32);
  expect(checkQuote(q, publicKey, "ab".repeat(32)).pcrBinding).toBe(false);
});
test("truncation, trailing bytes, wrong selection and duplicate PCRs fail", () => {
  const q = synthetic("ab".repeat(32));
  for (const attest of ["00", q.attest + "00", q.attest.slice(0, -2)])
    expect(() =>
      checkQuote({ ...q, attest }, publicKey, "ab".repeat(32)),
    ).toThrow();
  q.pcrs[0].index = 2;
  expect(() => checkQuote(q, publicKey, "ab".repeat(32))).toThrow();
});
test("policy never accepts an unavailable or failed check", () => {
  const checks = {
    keyProvenance: "VERIFIED",
    signature: "VERIFIED",
    freshness: "VERIFIED",
    pcrBinding: "VERIFIED",
    measurements: "VERIFIED",
    policy: "VERIFIED",
  };
  expect(decide(checks)).toBe("ACCEPTED"); // Pure synthetic policy unit test only.
  for (const key of Object.keys(checks)) {
    expect(decide({ ...checks, [key]: "UNAVAILABLE" })).toBe("INDETERMINATE");
    expect(decide({ ...checks, [key]: "FAILED" })).toBe("REJECTED");
  }
});
test("duplicate decoded keys and excessive nesting are rejected", () => {
  for (const text of [
    '{"a":1,"a":2}',
    '{"a":1,"\\u0061":2}',
    "[".repeat(33) + "0" + "]".repeat(33),
  ])
    expect(() => parseJson(text)).toThrow();
  expect(parseJson('{"x":[{"a":1},{"a":2}]}')).toEqual({
    x: [{ a: 1 }, { a: 2 }],
  });
});

test("policy rejects incomplete, inherited or malformed synthetic trust claims", () => {
  const complete = Object.fromEntries(
    [
      "keyProvenance",
      "signature",
      "freshness",
      "pcrBinding",
      "measurements",
      "policy",
    ].map((key) => [key, "VERIFIED"]),
  );
  for (const value of [
    null,
    undefined,
    [],
    "VERIFIED",
    {},
    { signature: "VERIFIED" },
    Object.create(complete),
    { ...complete, result: "ACCEPTED" },
  ])
    expect(decide(value)).toBe("INDETERMINATE");
  for (const key of Object.keys(complete)) {
    const missing = { ...complete };
    delete missing[key];
    expect(decide(missing)).toBe("INDETERMINATE");
    for (const value of [true, null, "UNKNOWN", "NOT_CHECKED"])
      expect(decide({ ...complete, [key]: value })).toBe("INDETERMINATE");
  }
  expect(decide({ signature: "FAILED" })).toBe("REJECTED");
  const { POLICY } = require("../../../dist/packages/policy-engine");
  expect(Object.isFrozen(POLICY.pcrs)).toBe(true);
  expect(() => POLICY.pcrs.push(11)).toThrow();
});

test("every truncated synthetic TPM structure and trailing signature byte fails", () => {
  const nonce = "ab".repeat(32),
    q = synthetic(nonce);
  for (const field of ["attest", "signature"]) {
    for (let end = 0; end < q[field].length; end += 2)
      expect(() =>
        checkQuote({ ...q, [field]: q[field].slice(0, end) }, publicKey, nonce),
      ).toThrow();
    for (const value of [
      q[field] + "00",
      q[field] + "zz",
      q[field] + "a",
      "00".repeat(8193),
    ])
      expect(() =>
        checkQuote({ ...q, [field]: value }, publicKey, nonce),
      ).toThrow();
  }
  expect(() => checkQuote(q, publicKey, nonce + "zz")).toThrow();
  expect(() =>
    checkQuote(
      { ...q, pcrs: q.pcrs.map((p) => ({ ...p, digest: p.digest + "zz" })) },
      publicKey,
      nonce,
    ),
  ).toThrow();
});
test("unsupported synthetic algorithms, selections and declared lengths fail", () => {
  const nonce = "ab".repeat(32),
    q = synthetic(nonce);
  // Offsets below are specific to synthetic.js: empty signer and 32-byte nonce.
  const mutations = [
    ["attest", 0, 0],
    ["attest", 5, 0],
    ["attest", 6, 255],
    ["attest", 58, 2],
    ["attest", 70, 2],
    ["attest", 72, 4],
    ["attest", 73, 2],
    ["attest", 74, 0],
    ["attest", 77, 255],
    ["signature", 1, 0x16],
    ["signature", 3, 4],
    ["signature", 4, 255],
  ];
  for (const [field, offset, value] of mutations) {
    const bytes = Buffer.from(q[field], "hex");
    bytes[offset] = value;
    expect(() =>
      checkQuote({ ...q, [field]: bytes.toString("hex") }, publicKey, nonce),
    ).toThrow();
  }
});
