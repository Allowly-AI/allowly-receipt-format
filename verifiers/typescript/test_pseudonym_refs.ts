/**
 * hmac-v1 pseudonym reference tests (spec Appendix A).
 *
 * Constants are the spec's Appendix A.3 published vectors — identical to the
 * Python test_pseudonym_refs.py, so the two reference helpers are pinned to the
 * same cross-language expected bytes.
 *
 * Usage: node --experimental-strip-types test_pseudonym_refs.ts
 *    or after build: node dist/test_pseudonym_refs.js
 */
import assert from "node:assert/strict";
import { createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { matchesRef, VerificationError, verifyReceipt } from "./verifier.js";

const KEY = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
const RECORD_REF =
  "hmac-v1:ecfc67ffb7bac447c05df24d1a25d75ebe7e765320d0fb1b4d22be332341599e";
const FULL_TUPLE_REF =
  "hmac-v1:c5fa890e042ea330013bd07bcc47c3312136373493fe87a490907b0e93c5727a";

let failures = 0;
function check(name: string, cond: boolean): void {
  if (cond) {
    console.log(`  OK    ${name}`);
  } else {
    console.log(`  FAIL  ${name}`);
    failures++;
  }
}

// A.3 published record vector
check("matches_published_record_vector", matchesRef(KEY, "record", "MRN-48291", RECORD_REF));

// A.3 published full_tuple vector (five components joined by 0x1F)
const fullTuple = ["MRN-48291", "baseline_arm_1", "demographics", "demographics", "2"].join("\x1f");
check("matches_published_full_tuple_vector", matchesRef(KEY, "full_tuple", fullTuple, FULL_TUPLE_REF));

// Mismatches and non-canonical references return false (never throw)
for (const [fieldName, value, ref] of [
  ["record", "MRN-48292", RECORD_REF],
  ["actor", "MRN-48291", RECORD_REF],
  ["record", "MRN-48291", RECORD_REF.toUpperCase()],
  ["record", "MRN-48291", RECORD_REF.slice(0, -1)],
  ["record", "MRN-48291", "sha256:" + RECORD_REF.slice("hmac-v1:".length)],
] as const) {
  check(`mismatch_returns_false [${fieldName}/${value.slice(0, 9)}]`, !matchesRef(KEY, fieldName, value, ref));
}

// Value is NOT Unicode-normalized: composed U+00E9 matches, decomposed e+U+0301 does not.
const composed = "José";
const decomposed = "José";
const JOSE_REF = "hmac-v1:76eca5c20d6d5d1c60f48bcd8b891f757e21a030e92f3cac90bc2462997f43ab";
check("composed_value_matches", matchesRef(KEY, "actor", composed, JOSE_REF));
check("decomposed_value_does_not_match", !matchesRef(KEY, "actor", decomposed, JOSE_REF));

// Weak key and unknown field are rejected loudly
function throws(fn: () => void, needle: string): boolean {
  try {
    fn();
    return false;
  } catch (e) {
    return e instanceof Error && e.message.includes(needle);
  }
}
check("rejects_weak_key", throws(() => matchesRef(new Uint8Array(8), "record", "MRN-48291", RECORD_REF), "128 bits"));
check("rejects_unknown_field", throws(() => matchesRef(KEY, "unknown", "MRN-48291", RECORD_REF), "field name"));

// Independent Appendix A.2 oracle: feed each framing component separately to
// Node, rather than copying the verifier's Buffer.concat construction.
function reference(key: Uint8Array, field: string, value: string): string {
  return "hmac-v1:" + createHmac("sha256", key)
    .update(Buffer.from(field, "ascii"))
    .update(new Uint8Array([0]))
    .update(Buffer.from(value, "utf8"))
    .digest("hex");
}

const fields = ["project", "record", "actor", "full_tuple"] as const;
const values = ["", " MRN-48291 ", "mrn-48291", "José", "Jose\u0301", "项目🙂", "a\u0000b"];
const ephemeralKey = new Uint8Array(randomBytes(32));
for (const length of [16, 32, 64]) {
  const key = new Uint8Array(randomBytes(length));
  for (const field of fields) {
    for (const value of values) {
      const ref = reference(key, field, value);
      assert.equal(matchesRef(key, field, value, ref), true, `${length}-byte ${field}: ${JSON.stringify(value)}`);
      assert.equal(matchesRef(ephemeralKey, field, value, ref), false, "independent keys do not match");
      assert.equal(matchesRef(key, field, value + "x", ref), false, "values are exact");
      for (const other of fields.filter((name) => name !== field)) {
        assert.equal(matchesRef(key, other, value, ref), false, `${field}/${other} separation`);
      }
    }
  }
}

// A.2 full_tuple uses four literal 0x1F bytes; missing components are empty.
for (const components of [
  ["MRN-48291", "baseline_arm_1", "demographics", "demographics", "2"],
  ["记录🙂", "", "instrument", "", ""],
  ["", "", "", "", ""],
]) {
  const framed = Buffer.from(components.flatMap((part, index) =>
    [...(index === 0 ? [] : [0x1f]), ...Buffer.from(part, "utf8")]));
  const ref = "hmac-v1:" + createHmac("sha256", ephemeralKey)
    .update(Buffer.from("full_tuple", "ascii")).update(new Uint8Array([0]))
    .update(framed).digest("hex");
  assert.equal(matchesRef(ephemeralKey, "full_tuple", components.join("\x1f"), ref), true);
  assert.equal(matchesRef(ephemeralKey, "project", components.join("\x1f"), ref), false);
  assert.equal(matchesRef(ephemeralKey, "full_tuple", components.join("|"), ref), false);
}

const boundaryValue = "boundary José🙂";
const validRef = reference(ephemeralKey, "record", boundaryValue);
for (const key of [null, undefined, "0123456789abcdef", Array(32).fill(1),
  new Uint16Array(16), new ArrayBuffer(32), new DataView(new ArrayBuffer(32))]) {
  assert.throws(() => matchesRef(key as unknown as Uint8Array, "record", boundaryValue, validRef), TypeError);
}
for (const length of [0, 8, 15]) {
  assert.throws(() => matchesRef(new Uint8Array(randomBytes(length)), "record", boundaryValue, validRef), RangeError);
}
for (const field of ["", "Record", "unknown", "record\u0000", "prоject", null, undefined, 0,
  new String("record"), [], Symbol("record")]) {
  assert.throws(() => matchesRef(ephemeralKey, field as unknown as string, boundaryValue, validRef), RangeError);
}
for (const value of [null, undefined, 0, false, [], {}, new String(boundaryValue)]) {
  assert.throws(() => matchesRef(ephemeralKey, "record", value as unknown as string, validRef), TypeError);
}
for (const value of ["\ud800", "\udc00", "a\ud800b", "\udc00\ud800"]) {
  assert.throws(() => matchesRef(ephemeralKey, "record", value, validRef), RangeError);
}
for (const ref of [null, undefined, 0, false, {}, [], Buffer.from(validRef), new String(validRef)]) {
  assert.equal(matchesRef(ephemeralKey, "record", boundaryValue, ref as unknown as string), false);
}
for (const ref of ["", "prefix" + validRef, validRef + "suffix", validRef + "\n", validRef + "\r",
  validRef + "\u0000", validRef.slice(0, -1), validRef + "0", validRef.toUpperCase(),
  validRef.replace("hmac-v1:", "hmac-v2:"), validRef.replace("h", "\u0168")]) {
  assert.equal(matchesRef(ephemeralKey, "record", boundaryValue, ref), false, `noncanonical ${JSON.stringify(ref)}`);
}

// name is public exception metadata. Exercise the constructor and a real
// verification failure with an ephemeral signing key and hand-written bytes.
const diagnostic = new VerificationError("test diagnostic");
assert.equal(diagnostic.name, "VerificationError");
assert.equal(diagnostic.message, "test diagnostic");
assert.equal(diagnostic instanceof Error, true);
const canonicalReceipt = '{"action":"test","agent_id":"agent","alg":"Ed25519",' +
  '"authorization_id":"auth","context":{},"decision":"allow","engine_version":"test",' +
  '"issued_at":"2026-09-30T00:00:00.000Z","key_id":"ephemeral",' +
  '"reason":"test","receipt_id":"receipt","resource":null,"schema_version":"4",' +
  '"user_id":"user","workspace_id":"workspace"}';
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const signature = sign(null, Buffer.from(canonicalReceipt, "utf8"), privateKey);
const receipt = { ...JSON.parse(canonicalReceipt), signature: signature.toString("base64url") };
const keys = [{ keyId: "ephemeral", alg: "Ed25519" as const,
  publicKeyBytes: new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
  activeFrom: new Date("2026-09-01T00:00:00.000Z"), activeUntil: null }];
const opts = { now: new Date("2026-10-01T00:00:00.000Z"), expectedWorkspaceId: "workspace" };
await verifyReceipt(receipt, keys, opts);
const changedSignature = Buffer.from(signature);
changedSignature[0] ^= 1;
await assert.rejects(verifyReceipt({ ...receipt, signature: changedSignature.toString("base64url") }, keys, opts),
  (error: unknown) => error instanceof VerificationError && error.name === "VerificationError");

if (failures) {
  console.log(`\n${failures} failure(s)`);
  process.exit(1);
}
console.log("\nhmac-v1 pseudonym reference vectors pass.");
