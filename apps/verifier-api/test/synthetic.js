const { generateKeyPairSync, sign, createHash } = require("node:crypto");
// Synthetic TPM-shaped bytes signed with a software key, NEVER hardware evidence.
const keys = generateKeyPairSync("rsa", { modulusLength: 2048 });
const publicKey = keys.publicKey.export({ type: "spki", format: "pem" });
function u16(n) {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n);
  return b;
}
function u32(n) {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(n);
  return b;
}
function sized(b) {
  return Buffer.concat([u16(b.length), b]);
}
function synthetic(nonce) {
  const pcrs = [0, 2, 4, 7, 10].map((index) => ({
    index,
    digest: "00".repeat(32),
  }));
  const digest = createHash("sha256").update(Buffer.alloc(160)).digest();
  const attest = Buffer.concat([
    u32(0xff544347),
    u16(0x8018),
    sized(Buffer.alloc(0)),
    sized(Buffer.from(nonce, "hex")),
    Buffer.alloc(16),
    Buffer.from([1]),
    Buffer.alloc(8),
    u32(1),
    u16(0xb),
    Buffer.from([3, 0x95, 4, 0]),
    sized(digest),
  ]);
  const signature = Buffer.concat([
    u16(0x14),
    u16(0xb),
    sized(sign("sha256", attest, keys.privateKey)),
  ]);
  return {
    attest: attest.toString("hex"),
    signature: signature.toString("hex"),
    pcrs,
  };
}
module.exports = { synthetic, publicKey };
