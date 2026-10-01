import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import jcsCanonicalize from "canonicalize";
import { fingerprintJson, SealJsonError } from "./browser/sealJson.js";
import {
  SEAL_MAX_DEPTH,
  SEAL_MAX_UTF8_BYTES,
  SEAL_PROFILE,
  SealInputError,
  hashSealJson,
  hashSealValue,
  loadKeysFromJson,
  verifySealJson,
  verifySealValue,
} from "./verifier.js";

type JsonRecord = Record<string, any>;

function generatedJson(generator: JsonRecord): string {
  if (generator.kind === "string_value_total_utf8_bytes") {
    const prefix = '{"v":"';
    const suffix = '"}';
    return prefix + "a".repeat(generator.utf8_bytes - prefix.length - suffix.length) + suffix;
  }
  if (generator.kind === "nested_arrays") {
    return "[".repeat(generator.depth - 1) + "0" + "]".repeat(generator.depth - 1);
  }
  throw new Error(`unknown generator: ${JSON.stringify(generator)}`);
}

function vectorInput(testCase: JsonRecord): string | Uint8Array {
  if (testCase.raw_json !== undefined) return testCase.raw_json;
  if (testCase.raw_utf8_base64 !== undefined) {
    return new Uint8Array(Buffer.from(testCase.raw_utf8_base64, "base64url"));
  }
  return generatedJson(testCase.generator);
}

// Expected record bytes come from Appendix B / ECMAScript string escaping,
// never from a verifier helper. Node crypto supplies the independent digest.
const digestBytes = (canonical: string) => createHash("sha256").update(canonical, "utf8").digest("hex");
const sealError = (code: string) => (error: unknown) => error instanceof SealInputError
  && error.name === "SealInputError" && error.code === code;

function checkSealBoundaries(): void {
  for (const [raw, canonical] of [
    ["null", "null"], ["true", "true"], ["false", "false"], ["[]", "[]"], ["{}", "{}"],
    ['"text"', '"text"'], ["-0", "0"], ["1.0", "1"], ["1E+0", "1"],
    ["9007199254740991", "9007199254740991"], ["-9007199254740991", "-9007199254740991"],
    ["5e-324", "5e-324"], ["1.25", "1.25"],
    ['{"b":false,"a":[null,true]}', '{"a":[null,true],"b":false}'],
    [String.raw`{"v":"\b\f\n\r\t\u0000\"\\/"}`, String.raw`{"v":"\b\f\n\r\t\u0000\"\\/"}`],
    ['{"a":"a","b":"a"}', '{"a":"a","b":"a"}'],
    [String.raw`{"a\"b":1,"a\\b":2}`, String.raw`{"a\"b":1,"a\\b":2}`],
    ['{"__proto__" \t\r\n:1}', '{"__proto__":1}'],
  ]) {
    const expected = digestBytes(canonical);
    assert.equal(hashSealJson(raw), expected, `raw accepted boundary: ${raw}`);
    assert.equal(hashSealJson(new TextEncoder().encode(raw)), expected, "UTF-8 byte boundary");
    assert.equal(hashSealValue(JSON.parse(raw)), expected, `parsed accepted boundary: ${raw}`);
  }
  assert.equal(hashSealValue(Object.assign(Object.create(null), { v: null })), digestBytes('{"v":null}'),
    "null-prototype JSON objects are accepted");

  // Empty containers at level 32 are valid. A scalar inside 32 containers is
  // at level 33, including when every parent is an object (Appendix B.1.3).
  for (const raw of ["[".repeat(32) + "]".repeat(32), '{"v":'.repeat(31) + "{}" + "}".repeat(31)]) {
    assert.equal(hashSealJson(raw), digestBytes(raw), "empty container at exactly depth 32");
    assert.equal(hashSealValue(JSON.parse(raw)), digestBytes(raw), "parsed depth 32");
  }
  for (const raw of ["[".repeat(32) + "0" + "]".repeat(32), '{"v":'.repeat(32) + "0" + "}".repeat(32)]) {
    assert.throws(() => hashSealJson(raw), sealError("depth_limit"), "raw scalar at depth 33");
    assert.throws(() => hashSealValue(JSON.parse(raw)), sealError("depth_limit"), "parsed scalar at depth 33");
  }
  for (const raw of [
    "[" + new Array(40).fill("[]").join(",") + "]",
    "{" + Array.from({ length: 40 }, (_, i) => `"k${String(i).padStart(2, "0")}":{}`).join(",") + "}",
  ]) assert.equal(hashSealJson(raw), digestBytes(raw), "closed siblings do not accumulate depth");
  for (const value of ["[".repeat(64), "{".repeat(64), '\\"' + "[".repeat(64), '"' + "{".repeat(64)]) {
    const raw = JSON.stringify(value);
    assert.equal(hashSealJson(raw), digestBytes(raw), "escaped punctuation is string data");
  }
  for (const prefix of [String.raw`{"":"ok","deep":`, String.raw`{"escape":"\\","deep":`, String.raw`{"escape":"\"","deep":`]) {
    const raw = prefix + "[".repeat(5000) + "null" + "]".repeat(5000) + "}";
    assert.throws(() => hashSealJson(raw), sealError("depth_limit"), "bound depth after string escapes before parsing");
  }

  const limit = 1_048_576; // Appendix B.1.2, independent of the exported constant.
  const padded = " ".repeat(limit - 4) + "null";
  assert.equal(hashSealJson(padded), digestBytes("null"), "raw input at exactly 1 MiB");
  assert.throws(() => hashSealJson(" " + padded), sealError("size_limit"), "raw limit applies before whitespace removal");
  const exactString = "a".repeat(limit - 2);
  assert.equal(hashSealValue(exactString), digestBytes('"' + exactString + '"'), "parsed canonical bytes at exactly 1 MiB");
  assert.throws(() => hashSealValue(exactString + "a"), sealError("size_limit"), "parsed canonical bytes one over limit");
  const multibyte = '"' + "😀".repeat((limit - 4) / 4) + 'aa"';
  assert.equal(Buffer.byteLength(multibyte, "utf8"), limit);
  assert.equal(hashSealJson(multibyte), digestBytes(multibyte), "size counts UTF-8 bytes");
  assert.throws(() => hashSealJson(multibyte.slice(0, -1) + 'a"'), sealError("size_limit"), "UTF-8 one byte over limit");
  // 61,681 safe integers produce 1,048,578 canonical bytes. Their shorter
  // exponent spellings fit under the raw limit but must fail the second limit.
  const expanded = "[" + new Array(61_681).fill("1e15").join(",") + "]";
  assert.ok(Buffer.byteLength(expanded, "utf8") < limit);
  assert.equal(1 + 61_681 * 17, limit + 2);
  assert.throws(() => hashSealJson(expanded), sealError("size_limit"), "canonical size is bounded after number expansion");

  for (const raw of [
    String.raw`{"\"b":1,"\u0022b":1}`,
    String.raw`{"a\"b":1,"a\u0022b":1}`,
    String.raw`{"a\\b":1,"a\u005cb":1}`,
    '{"a" \t\r\n:1,"\\u0061" \t\r\n:1}',
  ]) assert.throws(() => hashSealJson(raw), sealError("duplicate_key"), "decoded duplicate keys with escapes or whitespace");
  for (const raw of ["", "[", '["unfinished', String.raw`{"bad\q":1}`, '{"a":1,}', '["a":1]', "null false"]) {
    assert.throws(() => hashSealJson(raw), sealError("invalid_json"), "malformed JSON has a domain error");
  }
  for (const raw of ["\ud800", "x\udc00", '"\ud800"']) {
    assert.throws(() => hashSealJson(raw), sealError("invalid_unicode"), "raw UTF-16 must be well formed before parsing");
  }
  for (const value of [null, 0, {}, [0x7b, 0x7d], new String("{}")]) {
    assert.throws(() => hashSealJson(value as never), sealError("invalid_type"), "only text and Uint8Array are raw input");
  }
  assert.throws(() => hashSealValue(new Proxy({}, {})), sealError("unsupported_value"),
    "a proxy must not escape the structured-clone boundary");
}

async function checkSealVerification(): Promise<void> {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicBytes = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url");
  const keys = [{ keyId: "ephemeral-seal/v1", alg: "Ed25519" as const, publicKeyBytes: publicBytes,
    activeFrom: new Date("2026-01-01T00:00:00.000Z"), activeUntil: null }];
  const opts = { expectedWorkspaceId: "ws_seal_test", now: new Date("2026-10-01T00:00:00.000Z"),
    trustedKeyFingerprints: new Set(["sha256:" + createHash("sha256").update(publicBytes).digest("hex")]) };
  const digest = digestBytes("null");
  const signed = (changes: JsonRecord = {}) => {
    const payload = {
      schema_version: "4", receipt_id: "rcp_seal_ephemeral", workspace_id: opts.expectedWorkspaceId,
      issued_at: "2026-09-30T00:00:00.000Z", decision: "allow", reason: "authorization_granted_action_active",
      user_id: "allowly:seal", agent_id: "allowly.seal", action: "record.seal", resource: null,
      context: { seal_profile: "allowly.seal.jcs-sha256.v1", record_sha256: digest },
      authorization_id: "auth_seal_current", engine_version: "2026-09-30.1", alg: "Ed25519", key_id: keys[0].keyId,
      ...changes,
    };
    // These signing fixtures contain no control characters or non-integer
    // numbers. Independent JCS therefore agrees with wire-4 §4.2 for them.
    return { ...payload, signature: sign(null, Buffer.from(jcsCanonicalize(payload)!, "utf8"), privateKey).toString("base64url") };
  };
  const success = { signatureVerified: true, recordMatches: true, failureReason: null };
  const failure = (failureReason: string, signatureVerified = true) => ({ signatureVerified, recordMatches: false, failureReason });
  const valid = signed();
  assert.deepEqual(await verifySealJson("null", valid, keys, opts), success, "fresh signed raw positive control");
  assert.deepEqual(await verifySealValue(null, valid, keys, opts), success, "fresh signed parsed positive control");
  assert.deepEqual(await verifySealValue(false, valid, keys, opts), failure("record_mismatch"), "parsed record mismatch");
  assert.deepEqual(await verifySealValue(undefined, valid, keys, opts), failure("invalid_record"), "parsed unsupported record");
  assert.deepEqual(await verifySealValue(new Proxy({}, {}), valid, keys, opts), failure("invalid_record"), "parsed clone failure");
  assert.deepEqual(await verifySealJson("{", valid, keys, opts), failure("invalid_record"), "raw invalid record");
  for (const authorization_id of ["auth_seal_current", "auth_seal_renewed"]) {
    assert.deepEqual(await verifySealValue(null, signed({ authorization_id }), keys, opts), success,
      "SEAL must not bind a particular authorization id");
  }
  for (const [changes, reason] of [
    [{ action: "record.update" }, "not_seal_receipt"], [{ decision: "deny" }, "not_seal_receipt"],
    [{ agent_id: "other" }, "seal_identity_mismatch"], [{ user_id: "other" }, "seal_identity_mismatch"],
    [{ context: { seal_profile: "other", record_sha256: digest } }, "seal_profile_mismatch"],
  ] as Array<[JsonRecord, string]>) {
    const receipt = signed(changes);
    assert.deepEqual(await verifySealJson("null", receipt, keys, opts), failure(reason), reason);
    assert.deepEqual(await verifySealValue(null, receipt, keys, opts), failure(reason), `parsed ${reason}`);
  }
  for (const record_sha256 of ["0" + digest, digest + "z", digest.toUpperCase(), "a".repeat(63), [digest], null, 42]) {
    const receipt = signed({ context: { seal_profile: "allowly.seal.jcs-sha256.v1", record_sha256 } });
    assert.deepEqual(await verifySealJson("null", receipt, keys, opts), failure("invalid_record_digest"), "strict digest syntax and type");
    assert.deepEqual(await verifySealValue(null, receipt, keys, opts), failure("invalid_record_digest"), "parsed strict digest guard");
  }
  for (const expectedWorkspaceId of [undefined, null, 42, "", "other_workspace"]) {
    const options = { ...opts, expectedWorkspaceId } as never;
    assert.deepEqual(await verifySealJson("null", valid, keys, options), failure("receipt_verification_failed", false), "expected workspace is required");
    assert.deepEqual(await verifySealValue(null, valid, keys, options), failure("receipt_verification_failed", false), "parsed workspace binding");
  }
  assert.deepEqual(await verifySealValue(null, signed({ workspace_id: "" }), keys, { ...opts, expectedWorkspaceId: "" }),
    failure("receipt_verification_failed", false), "an empty workspace cannot be its own trust anchor");
  const tampered = { ...valid, reason: "changed_after_signing" };
  assert.deepEqual(await verifySealValue(null, tampered, keys, opts), failure("receipt_verification_failed", false), "parsed base signature failure");
  assert.deepEqual(await verifySealValue(null, valid, keys, { ...opts, trustedKeyFingerprints: new Set() }),
    failure("receipt_verification_failed", false), "caller key pins fail closed");

  // User-provided records and trust sets can throw their own errors. Preserve
  // those errors; they are not SealInputError / VerificationError failures.
  const recordError = new Error("record boundary sentinel");
  const throwingRecord = new Proxy({}, { ownKeys() { throw recordError; } });
  await assert.rejects(() => verifySealValue(throwingRecord, valid, keys, opts), error => error === recordError);
  const trustError = new Error("trust boundary sentinel");
  const throwingTrust = new Set<string>();
  throwingTrust.has = () => { throw trustError; };
  await assert.rejects(() => verifySealJson("null", valid, keys, { ...opts, trustedKeyFingerprints: throwingTrust }),
    error => error === trustError);
}

async function main(profilePath: string, verificationPath: string): Promise<void> {
  const profile = JSON.parse(readFileSync(profilePath, "utf8"));
  const verification = JSON.parse(readFileSync(verificationPath, "utf8"));

  if (profile.profile !== SEAL_PROFILE) throw new Error("profile identifier mismatch");
  if (
    profile.limits.max_utf8_bytes !== SEAL_MAX_UTF8_BYTES
    || profile.limits.max_depth !== SEAL_MAX_DEPTH
  ) throw new Error("profile limits mismatch");

  for (const testCase of [...profile.should_hash, ...profile.generated_should_hash]) {
    if (hashSealJson(vectorInput(testCase)) !== testCase.record_sha256) {
      throw new Error(`${testCase.name}: digest mismatch`);
    }
    const browser = await fingerprintJson(vectorInput(testCase) as string);
    assert.equal(browser.recordSha256, testCase.record_sha256, testCase.name);
    if (testCase.canonical_json !== undefined) {
      assert.equal(browser.canonical, testCase.canonical_json, testCase.name);
    }
  }
  for (const testCase of profile.equivalent) {
    for (const raw of testCase.raw_jsons) {
      assert.deepEqual(await fingerprintJson(raw), {
        canonical: testCase.canonical_json,
        recordSha256: testCase.record_sha256,
      }, testCase.name);
    }
    const digests = new Set(testCase.raw_jsons.map(hashSealJson));
    if (digests.size !== 1 || !digests.has(testCase.record_sha256)) {
      throw new Error(`${testCase.name}: inputs were not equivalent`);
    }
  }
  for (const testCase of profile.should_differ) {
    const browser = await Promise.all(testCase.raw_jsons.map(fingerprintJson));
    assert.equal(new Set(browser.map(result => result.recordSha256)).size, testCase.raw_jsons.length, testCase.name);
    const digests = new Set(testCase.raw_jsons.map(hashSealJson));
    if (digests.size !== testCase.raw_jsons.length) {
      throw new Error(`${testCase.name}: distinct inputs collided`);
    }
  }
  for (const testCase of profile.should_reject) {
    await assert.rejects(() => fingerprintJson(vectorInput(testCase) as string), SealJsonError, testCase.name);
    try {
      hashSealJson(vectorInput(testCase));
      throw new Error(`${testCase.name}: should have been rejected`);
    } catch (error) {
      if (!(error instanceof SealInputError) || error.code !== testCase.expected_code) {
        throw new Error(`${testCase.name}: unexpected error ${String(error)}`);
      }
    }
  }

  for (const testCase of profile.should_hash) {
    if (hashSealValue(JSON.parse(testCase.raw_json)) !== testCase.record_sha256) {
      throw new Error(`${testCase.name}: parsed boundary mismatch`);
    }
  }

  // Check depth before a recursive parser can overflow. Brackets, braces and
  // escaped quotes inside strings are data, not nesting (spec Appendix B.1).
  for (const raw of [
    "[".repeat(5000) + "null" + "]".repeat(5000),
    '{"v":'.repeat(5000) + "null" + "}".repeat(5000),
  ]) assert.throws(() => hashSealJson(raw),
    (error: unknown) => error instanceof SealInputError && error.code === "depth_limit",
    "raw depth must be bounded before parsing");
  for (const value of ['[{]}', '"[{]}', '\\"[{]}']) {
    const raw = JSON.stringify(value);
    assert.equal(hashSealJson(raw), hashSealValue(value), "string punctuation cannot change depth");
  }

  for (const value of [undefined, 1n, () => null, Symbol("non-json"), new Date(),
    new Map(), new Set(), new Uint8Array([1]), { [Symbol("key")]: null },
    Object.defineProperty({}, "hidden", { value: null }),
    Object.defineProperty({}, "getter", { enumerable: true, get: () => null }),
    Object.defineProperty([1], "0", { enumerable: true, get: () => 1 }),
  ]) assert.throws(() => hashSealValue(value),
    (error: unknown) => error instanceof SealInputError && error.code === "unsupported_value",
    "parsed-value hashing must not silently normalize non-JSON data");
  for (const value of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY]) {
    assert.throws(() => hashSealValue(value),
      (error: unknown) => error instanceof SealInputError && error.code === "number_overflow");
  }
  for (const value of [Number.MAX_SAFE_INTEGER + 1, Number.MIN_SAFE_INTEGER - 1]) {
    assert.throws(() => hashSealValue(value),
      (error: unknown) => error instanceof SealInputError && error.code === "unsafe_integer");
  }
  for (const value of ["\ud800", { ["\ud800"]: null }]) {
    assert.throws(() => hashSealValue(value),
      (error: unknown) => error instanceof SealInputError && error.code === "invalid_unicode");
  }

  const assertInvalidArray = (value: unknown[], label: string) => assert.throws(
    () => hashSealValue(value),
    (error: unknown) => error instanceof SealInputError
      && error.code === "unsupported_value"
      && error.message === "record arrays must be dense without extra properties",
    label,
  );
  const trailingHole = [1];
  trailingHole.length = 2;
  assertInvalidArray(trailingHole, "parsed arrays must not contain trailing holes");
  const replacedIndex = [1];
  replacedIndex.length = 2;
  Object.defineProperty(replacedIndex, "extra", { enumerable: true, value: 2 });
  assertInvalidArray(replacedIndex, "parsed array keys must match their indices");

  const keys = loadKeysFromJson(verification.public_keys);
  for (const testCase of [...verification.should_verify, ...verification.should_reject]) {
    const result = await verifySealJson(testCase.raw_json, testCase.receipt, keys, {
      expectedWorkspaceId: verification.expected_workspace_id,
      trustedKeyFingerprints: new Set(verification.trusted_key_fingerprints),
      now: new Date(verification.now),
    });
    const expected = testCase.expected;
    if (
      result.signatureVerified !== expected.signature_verified
      || result.recordMatches !== expected.record_matches
      || result.failureReason !== expected.failure_reason
    ) throw new Error(`${testCase.name}: verification result mismatch`);
  }

  const matching = verification.should_verify[0];
  const missingWorkspace = await verifySealJson(
    matching.raw_json,
    matching.receipt,
    keys,
    undefined as never,
  );
  if (
    missingWorkspace.signatureVerified
    || missingWorkspace.recordMatches
    || missingWorkspace.failureReason !== "receipt_verification_failed"
  ) throw new Error("missing expected workspace must fail closed");

  checkSealBoundaries();
  await checkSealVerification();
  console.log("SEAL TypeScript vectors passed");
}

const [profilePath, verificationPath] = process.argv.slice(2);
if (!profilePath || !verificationPath) {
  throw new Error("usage: test_seal.js PROFILE_VECTORS VERIFICATION_VECTORS");
}
await main(profilePath, verificationPath);
