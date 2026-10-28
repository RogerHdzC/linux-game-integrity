export type Check = "VERIFIED" | "FAILED" | "UNAVAILABLE" | "NOT_CHECKED";
export type Outcome = "ACCEPTED" | "REJECTED" | "INDETERMINATE";
export const POLICY = Object.freeze({
  version: "lab-tpm-sha256-v1",
  pcrs: [0, 2, 4, 7, 10] as readonly number[],
  ttlSeconds: 120,
});
export interface Checks {
  keyProvenance: Check;
  signature: Check;
  freshness: Check;
  pcrBinding: Check;
  measurements: Check;
  policy: Check;
}
export function decide(checks: Checks): Outcome {
  const values = Object.values(checks);
  if (values.includes("FAILED")) return "REJECTED";
  return values.every((v) => v === "VERIFIED") ? "ACCEPTED" : "INDETERMINATE";
}
