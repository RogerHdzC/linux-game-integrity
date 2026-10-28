export type Check = "VERIFIED" | "FAILED" | "UNAVAILABLE" | "NOT_CHECKED";
export type Outcome = "ACCEPTED" | "REJECTED" | "INDETERMINATE";
export const POLICY = Object.freeze({
  version: "lab-tpm-sha256-v1",
  pcrs: Object.freeze([0, 2, 4, 7, 10]),
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
const mandatory = [
  "keyProvenance",
  "signature",
  "freshness",
  "pcrBinding",
  "measurements",
  "policy",
] as const;
export function decide(checks: unknown): Outcome {
  if (!checks || typeof checks !== "object" || Array.isArray(checks))
    return "INDETERMINATE";
  const fields = checks as Record<string, unknown>;
  const own = (key: string) =>
    Object.prototype.hasOwnProperty.call(fields, key);
  // An explicit mandatory failure remains a rejection even if other data is missing.
  if (mandatory.some((key) => own(key) && fields[key] === "FAILED"))
    return "REJECTED";
  if (Reflect.ownKeys(fields).length !== mandatory.length)
    return "INDETERMINATE";
  return mandatory.every((key) => own(key) && fields[key] === "VERIFIED")
    ? "ACCEPTED"
    : "INDETERMINATE";
}
