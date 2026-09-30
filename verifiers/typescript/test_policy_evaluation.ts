import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import {
  POLICY_EVALUATION_ENGINE_VERSION,
  POLICY_EVALUATION_ENGINE_VERSIONS,
  POLICY_EVALUATION_PROFILE,
  VerificationError,
  canonicalize,
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

  // Independent signing keys let each valid signed snapshot reach replay.
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const replayKey = {
    keyId: "replay-boundary-key", alg: "Ed25519" as const,
    publicKeyBytes: new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
    activeFrom: new Date("0001-01-01T00:00:00.000Z"), activeUntil: null,
  };
  const signReceipt = (receipt: JsonObject): JsonObject => {
    const { signature, ...payload } = receipt;
    payload.key_id = replayKey.keyId;
    return { ...payload, signature: signBytes(null, canonicalize(payload), privateKey).toString("base64url") };
  };
  const replayOptions = { ...opts, trustedKeyFingerprints: new Set([publicKeyFingerprint(replayKey)]) };
  const signedAction = signReceipt(matchedCase.receipt);
  const signedCreation = signReceipt(matchedCase.authorization_receipts[0]);
  for (const unrelated of [
    signReceipt({ ...signedCreation, authorization_id: "another-authorization" }),
    signReceipt({ ...signedCreation, event: "authorization.revoke", decision: "authorization_revoked" }),
  ]) {
    assert.deepEqual(
      await verifyPolicyEvaluation(signedAction, [unrelated, signedCreation], [replayKey], replayOptions),
      matchedCase.expected,
      "other authorizations and revoke events cannot compete with the exact creation snapshot",
    );
    assert.deepEqual(
      await verifyPolicyEvaluation(signedAction, [unrelated], [replayKey], replayOptions),
      { ...matchedCase.expected, authorization_receipt_id: null, status: "not_checked",
        diagnostic: "authorization_receipt_not_found", calculated_evaluation: null },
    );
  }
  assert.deepEqual(
    await verifyPolicyEvaluation(signedAction, [signReceipt({ ...signedCreation,
      issued_at: signedAction.issued_at })], [replayKey], replayOptions),
    matchedCase.expected,
    "a creation snapshot at the action's exact timestamp is supported",
  );
  assert.deepEqual(
    await verifyPolicyEvaluation(signedAction, [signReceipt({ ...signedCreation,
      agent_id: "another-agent" })], [replayKey], replayOptions),
    { ...matchedCase.expected, status: "not_checked", diagnostic: "authorization_subject_mismatch",
      calculated_evaluation: null },
  );

  for (const actions of [
    [{ name: "", constraints: {} }],
    [{ name: 1, constraints: {} }],
    [{ name: signedAction.action, constraints: null }],
    [signedCreation.context.actions[0], { name: "other", constraints: {} }, { name: "other", constraints: {} }],
  ]) {
    assert.deepEqual(
      await verifyPolicyEvaluation(signedAction, [signReceipt({ ...signedCreation,
        context: { ...signedCreation.context, actions } })], [replayKey], replayOptions),
      { ...matchedCase.expected, status: "not_checked", diagnostic: "unsupported_authorization_snapshot",
        calculated_evaluation: null },
      "a valid signature cannot make malformed action entries or duplicate unrelated names supported",
    );
  }

  // Fields added after evaluation are removed only by the engines that add them.
  for (const engine of POLICY_EVALUATION_ENGINE_VERSIONS) {
    for (const field of ["client_timestamp", "client_timestamp_source", "execution", "identity_verification"]) {
      const missing = engine !== "2026-09-16.1";
      const evaluation = { matched_condition: { field, op: "exists", value: missing ? false : true },
        field_value: missing ? null : "recorded-after-evaluation" };
      const action = signReceipt({ ...signedAction, engine_version: engine,
        context: { [field]: "recorded-after-evaluation" }, policy_eval: evaluation });
      const creation = signReceipt({ ...signedCreation, engine_version: engine,
        context: { actions: [{ name: action.action,
          constraints: { confirm_when: [{ field, exists: missing ? false : true }] } }] } });
      assert.deepEqual(
        await verifyPolicyEvaluation(action, [creation], [replayKey], replayOptions),
        { ...matchedCase.expected, engine_version: engine, recorded_evaluation: evaluation,
          calculated_evaluation: evaluation },
        `${engine} must ${missing ? "remove" : "preserve"} ${field} during conditional replay`,
      );
    }
  }

  const executeCase = (vectors.verification_cases as JsonObject[]).find(
    (testCase) => testCase.name === "current_engine_with_current_snapshot",
  );
  assert.ok(executeCase, "shared vectors need a current executable snapshot");
  const grant = executeCase.authorization_receipts[0].context.actions[0].executable_operations[0];
  const invalidGrants: unknown[] = [null, {}, "not-an-array", [null],
    Array.from({ length: 101 }, () => grant),
    [{ ...grant, unexpected: "extra" }],
    [{ ...grant, enabled_executable_id: "" }],
    [{ ...grant, enabled_executable_id: 1 }],
    [{ ...grant, enabled_executable_id: ["not-a-string"] }],
    [{ ...grant, definition_fingerprint: "sha256:bad" }],
    [{ ...grant, minimum_evidence_mode: "unsupported" }],
  ];
  for (const field of Object.keys(grant)) {
    const missingField = { ...grant };
    delete missingField[field];
    invalidGrants.push([missingField]);
  }
  for (const [grants, supported] of [
    [[], true], [[{ ...grant, minimum_evidence_mode: "receipt" }], true],
    [[{ ...grant, minimum_evidence_mode: "witnessed" }], true],
    [Array.from({ length: 100 }, () => grant), true],
    ...invalidGrants.map((grants) => [grants, false]),
  ] as const) {
    const creation = signReceipt({ ...executeCase.authorization_receipts[0],
      context: { actions: [{ ...executeCase.authorization_receipts[0].context.actions[0],
        executable_operations: grants }] } });
    assert.deepEqual(
      await verifyPolicyEvaluation(signReceipt(executeCase.receipt), [creation], [replayKey], replayOptions),
      supported ? executeCase.expected : { ...executeCase.expected, status: "not_checked",
        diagnostic: "unsupported_authorization_snapshot", calculated_evaluation: null },
      `executable snapshot support must be ${supported}; entries: ${Array.isArray(grants) ? grants.length : typeof grants}`,
    );
  }

  for (const [receipt, candidates, publicKeys, expectedError] of [
    [matchedCase.receipt, null, keys, "authorizationReceipts must be an array"],
    [matchedCase.receipt, {}, keys, "authorizationReceipts must be an array"],
    [matchedCase.receipt, matchedCase.authorization_receipts, null, "publicKeys must be an array"],
    [matchedCase.receipt, matchedCase.authorization_receipts, {}, "publicKeys must be an array"],
  ] as const) {
    await assert.rejects(
      verifyPolicyEvaluation(receipt as never, candidates as never, publicKeys as never, opts),
      (error: unknown) => error instanceof VerificationError && error.message === expectedError,
    );
  }

  for (const [options, expectedError] of [
    [null, "expectedWorkspaceId must be a non-empty string"],
    [0, "expectedWorkspaceId must be a non-empty string"],
    [{ ...opts, expectedWorkspaceId: undefined }, "expectedWorkspaceId must be a non-empty string"],
    [{ ...opts, expectedWorkspaceId: null }, "expectedWorkspaceId must be a non-empty string"],
    [{ ...opts, expectedWorkspaceId: 1 }, "expectedWorkspaceId must be a non-empty string"],
    [{ ...opts, expectedWorkspaceId: "" }, "expectedWorkspaceId must be a non-empty string"],
    [{ ...opts, trustedKeyFingerprints: {
      has: 1,
      size: 1,
      *[Symbol.iterator]() { yield [...trustedKeyFingerprints][0]; },
    } }, "trustedKeyFingerprints must be a non-empty set"],
    [{ ...opts, trustedKeyFingerprints: null }, "trustedKeyFingerprints must be a non-empty set"],
    [{ ...opts, trustedKeyFingerprints: "not-a-set" }, "trustedKeyFingerprints must be a non-empty set"],
    [{ ...opts, trustedKeyFingerprints: {} }, "trustedKeyFingerprints must be a non-empty set"],
    [{ ...opts, trustedKeyFingerprints: { has: 1, size: 1 } }, "trustedKeyFingerprints must be a non-empty set"],
    [{ ...opts, trustedKeyFingerprints: { has() { return true; }, size: "1" } }, "trustedKeyFingerprints must be a non-empty set"],
    [{ ...opts, trustedKeyFingerprints: { has() { return true; }, size: 1 } }, "trustedKeyFingerprints must be a non-empty set"],
    [{ ...opts, now: "not-a-date" }, "now must be a valid Date"],
    [{ ...opts, now: new Date(Number.NaN) }, "now must be a valid Date"],
  ] as const) {
    await assert.rejects(
      verifyPolicyEvaluation(matchedCase.receipt, matchedCase.authorization_receipts, keys, options as never),
      (error: unknown) => error instanceof VerificationError && error.message === expectedError,
    );
  }
  const pinned = [...trustedKeyFingerprints][0];
  for (const malformed of [null, 1, `extra${pinned}`, `${pinned}extra`, pinned.toUpperCase()]) {
    await assert.rejects(
      verifyPolicyEvaluation(matchedCase.receipt, matchedCase.authorization_receipts, keys, {
        ...opts,
        trustedKeyFingerprints: new Set([pinned, malformed]) as never,
      }),
      (error: unknown) => error instanceof VerificationError
        && error.message === "trustedKeyFingerprints must contain at least one sha256:<64 lowercase hex> fingerprint",
      "one valid pin must not hide a malformed second pin",
    );
  }

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
  const mutableOptions = structuredClone(opts);
  const replay = verifyPolicyEvaluation(
    mutableReceipt,
    mutableCandidates,
    mutableKeys,
    mutableOptions,
  );
  queueMicrotask(() => {
    mutableReceipt.policy_eval = { matched_condition: null, field_value: null };
    mutableCandidates[0].context.actions[0].constraints = {};
    mutableKeys[0].publicKeyBytes.fill(0);
    mutableOptions.now.setUTCFullYear(1900);
    mutableOptions.trustedKeyFingerprints.clear();
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
