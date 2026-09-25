import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  POLICY_EVALUATION_ENGINE_VERSION,
  POLICY_EVALUATION_ENGINE_VERSIONS,
  POLICY_EVALUATION_PROFILE,
  VerificationError,
  loadKeysFromJson,
  publicKeyFingerprint,
  verifyPolicyEvaluation,
} from "./verifier.js";

type JsonObject = Record<string, any>;

function alteredSignature(signature: string): string {
  return (signature.startsWith("A") ? "B" : "A") + signature.slice(1);
}

async function main(vectorsPath: string): Promise<void> {
  const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as JsonObject;
  assert.equal(vectors.profile, POLICY_EVALUATION_PROFILE);
  assert.equal(
    POLICY_EVALUATION_ENGINE_VERSION,
    POLICY_EVALUATION_ENGINE_VERSIONS.at(-1),
  );
  assert.deepEqual(
    vectors.supported_action_engine_versions,
    POLICY_EVALUATION_ENGINE_VERSIONS,
  );
  assert.deepEqual(
    vectors.supported_authorization_engine_versions,
    POLICY_EVALUATION_ENGINE_VERSIONS,
  );

  const keys = loadKeysFromJson(vectors.public_keys);
  const trustedKeyFingerprints = new Set<string>(vectors.trusted_key_fingerprints);
  assert.ok(trustedKeyFingerprints.size > 0, "policy vectors must pin at least one key");
  for (const fingerprint of trustedKeyFingerprints) {
    assert.ok(keys.some((key) => publicKeyFingerprint(key) === fingerprint));
  }
  const opts = {
    expectedWorkspaceId: vectors.expected_workspace_id as string,
    trustedKeyFingerprints,
    now: new Date(vectors.verification_now as string),
  };

  const seenStatuses = new Set<string>();
  const seenDiagnostics = new Set<string>();
  for (const testCase of vectors.verification_cases as JsonObject[]) {
    const actual = await verifyPolicyEvaluation(
      testCase.receipt,
      testCase.authorization_receipts,
      keys,
      opts,
    );
    assert.deepEqual(actual, testCase.expected, testCase.name);
    seenStatuses.add(actual.status);
    seenDiagnostics.add(actual.diagnostic);
  }
  assert.deepEqual(seenStatuses, new Set(["matched", "mismatch", "not_checked"]));
  for (const diagnostic of [
    "matched",
    "policy_evaluation_mismatch",
    "policy_evaluation_not_recorded",
    "unsupported_engine_version",
    "authorization_receipt_not_found",
    "conflicting_authorization_receipts",
    "unsupported_authorization_snapshot",
    "authorization_subject_mismatch",
    "authorization_action_not_found",
    "authorization_action_ambiguous",
    "unsupported_policy",
  ]) {
    assert.ok(seenDiagnostics.has(diagnostic), `missing shared vector for ${diagnostic}`);
  }

  for (const testCase of vectors.validation_error_cases as JsonObject[]) {
    await assert.rejects(
      verifyPolicyEvaluation(
        testCase.receipt,
        testCase.authorization_receipts,
        keys,
        opts,
      ),
      (error: unknown) => error instanceof VerificationError
        && error.message.includes(testCase.expected_error),
      testCase.name,
    );
  }

  const operatorCoverage = new Set<string>();
  for (const testCase of vectors.runtime_cases as JsonObject[]) {
    for (const key of ["deny_when", "escalate_when", "confirm_when"]) {
      for (const condition of testCase.constraints[key] ?? []) {
        for (const operator of Object.keys(condition)) {
          if (operator !== "field") operatorCoverage.add(operator);
        }
      }
    }
  }
  assert.deepEqual(operatorCoverage, new Set([
    "eq", "neq", "lt", "lte", "gt", "gte", "in", "nin",
    "contains_any", "contains_none", "empty", "exists",
  ]), "shared vectors must cover every profile operator");

  const matchedCase = (vectors.verification_cases as JsonObject[]).find(
    (testCase) => testCase.expected.status === "matched",
  );
  assert.ok(matchedCase, "shared vectors need a matched case");

  const badActionReceipt = structuredClone(matchedCase.receipt);
  badActionReceipt.signature = alteredSignature(badActionReceipt.signature);
  await assert.rejects(
    verifyPolicyEvaluation(
      badActionReceipt,
      matchedCase.authorization_receipts,
      keys,
      opts,
    ),
    (error: unknown) => error instanceof VerificationError
      && error.message === "signature verification failed",
    "an invalid action signature must be a verification error",
  );

  const badCandidate = structuredClone(matchedCase.authorization_receipts[0]);
  badCandidate.signature = alteredSignature(badCandidate.signature);
  await assert.rejects(
    verifyPolicyEvaluation(
      matchedCase.receipt,
      [...matchedCase.authorization_receipts, badCandidate],
      keys,
      opts,
    ),
    VerificationError,
    "every supplied authorization receipt must authenticate",
  );

  await assert.rejects(
    verifyPolicyEvaluation(
      matchedCase.receipt,
      matchedCase.authorization_receipts,
      keys,
      { ...opts, trustedKeyFingerprints: new Set() },
    ),
    (error: unknown) => error instanceof VerificationError
      && error.message.includes("at least one"),
    "an empty caller trust set must fail closed",
  );

  await assert.rejects(
    verifyPolicyEvaluation(
      matchedCase.authorization_receipts[0],
      [],
      keys,
      opts,
    ),
    (error: unknown) => error instanceof VerificationError
      && error.message === "policy evaluation requires an action receipt",
    "the primary receipt must be an action receipt",
  );

  // The promise reaches its first signature-verification await only after all
  // inputs are snapshotted. Later caller mutation must not alter the replay.
  const mutableReceipt = structuredClone(matchedCase.receipt);
  const mutableCandidates = structuredClone(matchedCase.authorization_receipts);
  const mutableKeys = structuredClone(keys);
  const replay = verifyPolicyEvaluation(
    mutableReceipt,
    mutableCandidates,
    mutableKeys,
    opts,
  );
  queueMicrotask(() => {
    mutableReceipt.policy_eval = { matched_condition: null, field_value: null };
    mutableCandidates[0].context.actions[0].constraints = {};
    mutableKeys[0].publicKeyBytes.fill(0);
  });
  assert.deepEqual(await replay, matchedCase.expected, "replay must use the authenticated snapshots");

  const sharedKeyBytes = new Uint8Array(new SharedArrayBuffer(keys[0].publicKeyBytes.length));
  sharedKeyBytes.set(keys[0].publicKeyBytes);
  await assert.rejects(
    verifyPolicyEvaluation(
      matchedCase.receipt,
      matchedCase.authorization_receipts,
      [{ ...keys[0], publicKeyBytes: sharedKeyBytes }, ...keys.slice(1)],
      opts,
    ),
    (error: unknown) => error instanceof VerificationError
      && error.message.includes("SharedArrayBuffer"),
    "shared key bytes cannot provide an immutable verification snapshot",
  );

  console.log("Policy evaluation TypeScript vectors passed");
}

const vectorsPath = process.argv[2];
if (!vectorsPath) throw new Error("usage: test_policy_evaluation.js PROFILE_VECTORS");
await main(vectorsPath);
