import { BadRequestException } from "@nestjs/common";
import { QuoteInput } from "./quote";
export const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function object(
  value: unknown,
  fields: string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new BadRequestException("INVALID_INPUT");
  const data = value as Record<string, unknown>;
  if (Object.keys(data).sort().join(",") !== [...fields].sort().join(","))
    throw new BadRequestException("INVALID_FIELDS");
  return data;
}
export function identifier(value: unknown): string {
  if (typeof value !== "string" || value.length !== 36 || !uuid.test(value))
    throw new BadRequestException("INVALID_ID");
  return value;
}
function hex(value: unknown, max: number, exact?: number): string {
  if (
    typeof value !== "string" ||
    value.length > max ||
    (exact !== undefined && value.length !== exact) ||
    !/^(?:[0-9a-f]{2})+(?![\s\S])/.test(value)
  )
    throw new BadRequestException("INVALID_HEX");
  return value;
}
export function evidence(value: unknown): {
  challengeId: string;
  nonce: string;
  quote: QuoteInput | null;
} {
  const data = object(value, [
    "schemaVersion",
    "challengeId",
    "nonce",
    "quote",
  ]);
  if (data.schemaVersion !== 1)
    throw new BadRequestException("INVALID_VERSION");
  const challengeId = identifier(data.challengeId),
    nonce = hex(data.nonce, 64, 64);
  if (data.quote === null) return { challengeId, nonce, quote: null };
  const q = object(data.quote, ["attest", "signature", "pcrs"]);
  if (!Array.isArray(q.pcrs) || q.pcrs.length !== 5)
    throw new BadRequestException("INVALID_PCRS");
  const seen = new Set<number>();
  const pcrs = q.pcrs.map((p: unknown) => {
    const v = object(p, ["index", "digest"]);
    if (
      !Number.isInteger(v.index) ||
      typeof v.index !== "number" ||
      v.index < 0 ||
      v.index > 23 ||
      seen.has(v.index)
    )
      throw new BadRequestException("INVALID_PCRS");
    seen.add(v.index);
    return { index: v.index, digest: hex(v.digest, 64, 64) };
  });
  return {
    challengeId,
    nonce,
    quote: {
      attest: hex(q.attest, 16384),
      signature: hex(q.signature, 16384),
      pcrs,
    },
  };
}
/** JSON.parse validates syntax; a second token walk rejects duplicate keys and excessive depth. */
export function parseJson(text: string): unknown {
  const result: unknown = JSON.parse(text);
  const stack: (Set<string> | null)[] = [];
  const tokens = /"(?:\\.|[^"\\])*"|[{}\[\]]/g;
  for (const match of text.matchAll(tokens)) {
    const token = match[0];
    if (token === "{" || token === "[") {
      stack.push(token === "{" ? new Set<string>() : null);
      if (stack.length > 32) throw new Error("JSON_DEPTH");
    } else if (token === "}" || token === "]") stack.pop();
    else if (/^\s*:/.test(text.slice((match.index ?? 0) + token.length))) {
      const keys = stack[stack.length - 1],
        key = JSON.parse(token) as string;
      if (!keys || keys.has(key)) throw new Error("DUPLICATE_KEY");
      keys.add(key);
    }
  }
  return result;
}
