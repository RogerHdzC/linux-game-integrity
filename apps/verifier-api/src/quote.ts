import { createHash, createPublicKey, constants, verify } from "node:crypto";
import { POLICY } from "../../../packages/policy-engine";

/** Bounded TPM wire decoder; crypto is performed by Node/OpenSSL, not this parser. */
class Reader {
  private offset = 0;
  constructor(private readonly bytes: Buffer) {}
  take(n: number): Buffer {
    if (n < 0 || this.offset + n > this.bytes.length)
      throw new Error("TRUNCATED_TPM_DATA");
    const value = this.bytes.subarray(this.offset, this.offset + n);
    this.offset += n;
    return value;
  }
  u8(): number {
    return this.take(1).readUInt8();
  }
  u16(): number {
    return this.take(2).readUInt16BE();
  }
  u32(): number {
    return this.take(4).readUInt32BE();
  }
  sized(): Buffer {
    return this.take(this.u16());
  }
  end(): void {
    if (this.offset !== this.bytes.length) throw new Error("TRAILING_TPM_DATA");
  }
}
export interface QuoteInput {
  attest: string;
  signature: string;
  pcrs: { index: number; digest: string }[];
}
export interface QuoteChecks {
  signature: boolean;
  nonce: boolean;
  pcrBinding: boolean;
}
export function checkQuote(
  input: QuoteInput,
  pem: string,
  nonce: string,
): QuoteChecks {
  const message = Buffer.from(input.attest, "hex");
  const r = new Reader(message);
  if (r.u32() !== 0xff544347 || r.u16() !== 0x8018)
    throw new Error("NOT_A_TPM_QUOTE");
  r.sized(); // qualifiedSigner: provenance is deliberately NOT inferred from this field.
  const extraData = r.sized();
  r.take(8);
  r.u32();
  r.u32(); // clock, resetCount, restartCount
  if (r.u8() > 1) throw new Error("INVALID_CLOCK_INFO");
  r.take(8); // firmwareVersion
  if (r.u32() !== 1 || r.u16() !== 0x000b || r.u8() !== 3)
    throw new Error("UNSUPPORTED_PCR_SELECTION");
  const selection = r.take(3);
  const selected = Array.from({ length: 24 }, (_, i) => i).filter(
    (i) => (selection[i >> 3] & (1 << i % 8)) !== 0,
  );
  if (selected.join(",") !== POLICY.pcrs.join(","))
    throw new Error("WRONG_PCR_SELECTION");
  const digest = r.sized();
  r.end();
  if (digest.length !== 32) throw new Error("INVALID_PCR_DIGEST");
  const s = new Reader(Buffer.from(input.signature, "hex"));
  if (s.u16() !== 0x0014 || s.u16() !== 0x000b)
    throw new Error("UNSUPPORTED_SIGNATURE");
  const signature = s.sized();
  s.end();
  const key = createPublicKey(pem);
  if (
    key.asymmetricKeyType !== "rsa" ||
    key.asymmetricKeyDetails?.modulusLength !== 2048
  )
    throw new Error("UNSUPPORTED_KEY");
  if (signature.length !== 256) throw new Error("INVALID_SIGNATURE_SIZE");
  const ordered = [...input.pcrs].sort((a, b) => a.index - b.index);
  if (ordered.map((p) => p.index).join(",") !== POLICY.pcrs.join(","))
    throw new Error("WRONG_PCR_VALUES");
  const calculated = createHash("sha256")
    .update(Buffer.concat(ordered.map((p) => Buffer.from(p.digest, "hex"))))
    .digest();
  return {
    signature: verify(
      "sha256",
      message,
      { key, padding: constants.RSA_PKCS1_PADDING },
      signature,
    ),
    nonce: extraData.equals(Buffer.from(nonce, "hex")),
    pcrBinding: calculated.equals(digest),
  };
}
