import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { FlattenedSign, base64url, compactVerify, importJWK } from "jose";
import { decodeReceipt, loadKeysFromJson, VerificationError, verifyReceipt } from "./verifier.js";

const vectors = JSON.parse(readFileSync(process.argv[2], "utf8"));
const receipt = vectors.should_verify[0].receipt;
const keys = loadKeysFromJson(vectors.public_keys);
const options = { now: new Date("2026-12-31T00:00:00.000Z"), expectedWorkspaceId: "ws_test" };
const header = { alg: "EdDSA", kid: "test-key/v1", typ: "allowly-receipt+jws" };
const publicJwk = { kty: "OKP", crv: "Ed25519", x: vectors.public_keys.keys[0].public_key };
const privateKey = await importJWK({ ...publicJwk, d: base64url.encode(new Uint8Array(32)) }, "EdDSA");
const publicKey = await importJWK(publicJwk, "EdDSA");
const compact = [receipt.protected, receipt.payload, receipt.signature].join(".");
assert.deepEqual(JSON.parse(new TextDecoder().decode((await compactVerify(compact, publicKey,
  { algorithms: ["EdDSA"] })).payload)), decodeReceipt(receipt));
const evidence = decodeReceipt(receipt);
evidence.context.unicode = "café\n東京";
const stock = await new FlattenedSign(new TextEncoder().encode(JSON.stringify(evidence, null, 2)))
  .setProtectedHeader(header).sign(privateKey);
assert.deepEqual(await verifyReceipt({ ...stock }, keys, options), evidence);

const badHeaders = [
  ...["none", "HS256", "RS256", "Ed25519"].map(alg => ({ ...header, alg })),
  { ...header, typ: "JWT" }, { ...header, kid: "" }, { alg: "EdDSA", typ: header.typ },
  { ...header, jku: "https://attacker.invalid/keys" }, { ...header, jwk: {} },
  { ...header, crit: ["b64"] }, { ...header, b64: false },
];
for (const value of badHeaders) {
  await assert.rejects(verifyReceipt({ ...receipt, protected: base64url.encode(JSON.stringify(value)) }, keys, options), VerificationError);
}
for (const [field, raw] of [
  ["protected", '{"alg":"EdDSA","alg":"EdDSA","kid":"test-key/v1","typ":"allowly-receipt+jws"}'],
  ["protected", '{"alg":"EdDSA","\\u0061lg":"EdDSA","kid":"test-key/v1","typ":"allowly-receipt+jws"}'],
  ["protected", new Uint8Array([239, 187, 191, ...new TextEncoder().encode(JSON.stringify(header))])],
  ["payload", new Uint8Array([255])], ["payload", ""],
  ["payload", '{"schema_version":"5","schema_version":"5"}'],
  ["payload", '{"context":{"amount":1.0}}'], ["payload", '{"context":{"amount":1e0}}'],
] as const) {
  assert.throws(() => decodeReceipt({ ...receipt, [field]: base64url.encode(raw) }), VerificationError);
}
for (const wire of [{ ...receipt, header: {} }, { ...receipt, signatures: [] }, decodeReceipt(receipt)]) {
  await assert.rejects(verifyReceipt(wire, keys, options), VerificationError);
}
await assert.rejects(verifyReceipt({ ...receipt,
  protected: base64url.encode(JSON.stringify({ ...header, kid: "test-key/v2" })) }, keys, options), VerificationError);
console.log("Stock jose interoperability and strict JWS framing pass.");
