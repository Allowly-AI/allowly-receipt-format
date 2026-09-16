import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
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

  console.log("SEAL TypeScript vectors passed");
}

const [profilePath, verificationPath] = process.argv.slice(2);
if (!profilePath || !verificationPath) {
  throw new Error("usage: test_seal.js PROFILE_VECTORS VERIFICATION_VECTORS");
}
await main(profilePath, verificationPath);
