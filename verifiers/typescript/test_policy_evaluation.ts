import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign as signBytes } from "node:crypto";
import jcsCanonicalize from "canonicalize";
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
    // This generated corpus has no control characters; JCS and wire 4 agree.
    // Do not sign with the verifier's own possibly-mutated canonicalizer.
    return { ...payload, signature: signBytes(null,
      Buffer.from(jcsCanonicalize(payload)!), privateKey).toString("base64url") };
  };
  const replayOptions = { ...opts, trustedKeyFingerprints: new Set([publicKeyFingerprint(replayKey)]) };
  const signedAction = signReceipt(matchedCase.receipt);
  const signedCreation = signReceipt(matchedCase.authorization_receipts[0]);

  // Profile §§4–6: hand-written truth tables distinguish match, no-match and
  // uncomparable inputs. The latter still records the evaluated condition.
  const operatorCases: Array<[string, unknown, unknown, boolean | null, unknown]> = [
    ["eq", true, true, true, true], ["eq", true, false, false, null],
    ["eq", true, 1, null, true], ["eq", 1, "1", null, 1],
    ["eq", null, null, true, null], ["eq", "a", "b", false, null],
    ["neq", true, false, true, true], ["neq", true, true, false, null],
    ["neq", null, null, false, null], ["neq", false, 0, null, false],
    ["lt", 9, 10, true, 9], ["lt", 10, 10, false, null], ["lt", 11, 10, false, null],
    ["lte", 9, 10, true, 9], ["lte", 10, 10, true, 10], ["lte", 11, 10, false, null],
    ["gt", 9, 10, false, null], ["gt", 10, 10, false, null], ["gt", 11, 10, true, 11],
    ["gte", 9, 10, false, null], ["gte", 10, 10, true, 10], ["gte", 11, 10, true, 11],
    ["lt", true, 10, null, true], ["gte", "10", 10, null, "10"],
    ["lt", "10", 10, null, "10"], ["gt", true, 10, null, true],
    ["lt", [10], 10, null, null],
    ["eq", {}, null, null, null], ["eq", [], "x", null, null],
    ["eq", null, "x", null, null], ["eq", "x", null, null, "x"],
    ["in", true, [1, true], true, true], ["in", false, [1, true], false, null],
    ["in", true, [false, true], true, true], ["nin", true, [false, true], false, null],
    ["in", true, [1], null, true], ["in", null, [null], true, null],
    ["nin", true, [1, false], true, true], ["nin", true, [true], false, null],
    ["nin", true, [1], null, true], ["nin", null, [null], false, null],
    ["contains_any", [true], [1], false, null],
    ["contains_any", [1, true], [true, 1], true, 1],
    ["contains_any", [true, 1], [1, true], true, true],
    ["contains_any", [], [null], false, null],
    ["contains_any", [null], [null], true, null],
    ["contains_any", "a", ["a"], null, "a"],
    ["contains_any", [{}], [null], null, null],
    ["contains_any", [false], [true], false, null],
    ["contains_any", [1], [2], false, null],
    ["contains_any", ["1"], [1], false, null],
    ["contains_any", ["a", {}], ["b"], null, null],
    ["contains_none", [], [null], true, null],
    ["contains_none", [true], [1], true, null],
    ["contains_none", [1, true], [true], false, null],
    ["contains_none", [null], [null], false, null],
    ["contains_none", {}, [null], null, null],
    ["contains_none", "a", ["a"], null, null],
    ["contains_none", ["a", {}], ["a"], null, null],
    ["empty", [], true, true, null], ["empty", [null], true, false, null],
    ["empty", [], false, false, null], ["empty", [null], false, true, null],
    ["empty", "", true, null, null],
    ["empty", "not-an-array", true, null, null], ["empty", {}, true, null, null],
    ["exists", null, true, true, null], ["exists", null, false, false, null],
    ["exists", false, true, true, false],
  ];
  for (const [op, actual, value, matches, fieldValue] of operatorCases) {
    const evaluation = matches === false ? { matched_condition: null, field_value: null }
      : { matched_condition: { field: "sample", op, value }, field_value: fieldValue };
    const action = signReceipt({ ...signedAction, context: { sample: actual }, policy_eval: evaluation });
    const creation = signReceipt({ ...signedCreation,
      context: { actions: [{ name: action.action, constraints: { deny_when: [{ field: "sample", [op]: value }] } }] } });
    assert.deepEqual(await verifyPolicyEvaluation(action, [creation], [replayKey], replayOptions),
      { ...matchedCase.expected, recorded_evaluation: evaluation, calculated_evaluation: evaluation },
      `${op}: ${JSON.stringify(actual)} against ${JSON.stringify(value)}`);
  }

  const expectReplay = async (
    name: string,
    constraints: JsonObject,
    context: JsonObject,
    recorded: JsonObject,
    calculated: JsonObject | null,
    status = "matched",
    diagnostic = status === "matched" ? "matched" : "policy_evaluation_mismatch",
  ): Promise<void> => {
    const action = signReceipt({ ...signedAction, context, policy_eval: recorded });
    const creation = signReceipt({ ...signedCreation,
      context: { actions: [{ name: action.action, constraints }] } });
    assert.deepEqual(
      await verifyPolicyEvaluation(action, [creation], [replayKey], replayOptions),
      { ...matchedCase.expected, status, diagnostic,
        recorded_evaluation: recorded, calculated_evaluation: calculated },
      name,
    );
  };
  const matchingCondition = { field: "tier", eq: "blocked" };
  const matchingEvaluation = { matched_condition: { field: "tier", op: "eq", value: "blocked" },
    field_value: "blocked" };
  const noMatchEvaluation = { matched_condition: null, field_value: null };

  // Profile §4 counts all lists before §5 chooses the first match.
  for (const [deny, escalate, confirm] of [[10, 0, 0], [4, 3, 3], [0, 5, 5], [0, 0, 10]]) {
    const constraints = {
      deny_when: Array.from({ length: deny }, () => matchingCondition),
      escalate_when: Array.from({ length: escalate }, () => matchingCondition),
      confirm_when: Array.from({ length: confirm }, () => matchingCondition),
    };
    await expectReplay(`exactly ten conditions are supported: ${deny}/${escalate}/${confirm}`,
      constraints, { tier: "blocked" }, matchingEvaluation, matchingEvaluation);
  }
  for (const [deny, escalate, confirm] of [[11, 0, 0], [4, 3, 4], [1, 5, 5], [0, 0, 11]]) {
    await expectReplay(`eleven conditions are unsupported: ${deny}/${escalate}/${confirm}`, {
      deny_when: Array.from({ length: deny }, () => matchingCondition),
      escalate_when: Array.from({ length: escalate }, () => matchingCondition),
      confirm_when: Array.from({ length: confirm }, () => matchingCondition),
    }, { tier: "blocked" }, matchingEvaluation, null, "not_checked", "unsupported_policy");
  }
  for (const key of ["deny_when", "escalate_when", "confirm_when"]) {
    for (const malformedList of [false, 1, "", "condition", {}, { length: 0 }]) {
      await expectReplay(`${key} must be null or an array: ${JSON.stringify(malformedList)}`,
        { [key]: malformedList }, {}, noMatchEvaluation, null, "not_checked", "unsupported_policy");
    }
    await expectReplay(`${key} may be null beside valid conditions`, {
      deny_when: [matchingCondition], escalate_when: [matchingCondition], confirm_when: [matchingCondition],
      [key]: null,
    }, { tier: "blocked" }, matchingEvaluation, matchingEvaluation);
    for (const invalid of [{ field: "tier", unknown: "blocked" }, { field: "tier", in: ["blocked", {}] }]) {
      await expectReplay(`an early ${key} match cannot hide its later malformed condition`,
        { [key]: [matchingCondition, invalid] }, { tier: "blocked" }, matchingEvaluation,
        null, "not_checked", "unsupported_policy");
      if (key !== "deny_when") {
        await expectReplay(`an early deny cannot hide malformed ${key}`,
          { deny_when: [matchingCondition], [key]: [invalid] }, { tier: "blocked" },
          matchingEvaluation, null, "not_checked", "unsupported_policy");
      }
    }
  }

  // Profile §5.6 calculates no result, even if a signed receipt records one.
  for (const constraints of [{}, { deny_when: [] }, { escalate_when: [], confirm_when: [] },
    { deny_when: null, escalate_when: null, confirm_when: null },
    { deny_when: [], escalate_when: null, confirm_when: [] }, { max_per_day: 1 }]) {
    await expectReplay(`no conditions produce no calculated object: ${JSON.stringify(constraints)}`,
      constraints, {}, noMatchEvaluation, null, "mismatch");
  }
  for (const key of ["escalate_when", "confirm_when"]) {
    const firstMissing = { matched_condition: { field: "absent", op: "eq", value: 1 }, field_value: null };
    await expectReplay(`${key} returns its first missing field before a later match`,
      { [key]: [{ field: "absent", eq: 1 }, matchingCondition] }, { tier: "blocked" },
      firstMissing, firstMissing);
  }

  // Profile §4 requires an own field member. An inherited string must not turn
  // a signed object with missing/extra members into a supported condition.
  const inheritedFieldDescriptor = Object.getOwnPropertyDescriptor(Object.prototype, "field");
  try {
    Object.defineProperty(Object.prototype, "field", { value: "tier", configurable: true });
    for (const condition of [{ eq: "blocked" }, { eq: "blocked", gte: 1 },
      { eq: "blocked", unexpected: 1 }]) {
      await expectReplay(`an inherited field cannot repair condition members: ${JSON.stringify(condition)}`,
        { deny_when: [condition] }, { tier: "blocked" }, matchingEvaluation,
        null, "not_checked", "unsupported_policy");
    }
  } finally {
    if (inheritedFieldDescriptor) Object.defineProperty(Object.prototype, "field", inheritedFieldDescriptor);
    else delete (Object.prototype as JsonObject).field;
  }

  // Profile §7 compares every byte/value, rather than just serialized length.
  const stringEvaluation = { matched_condition: { field: "sample", op: "eq", value: "alpha" },
    field_value: "alpha" };
  await expectReplay("a different field value of the same byte length is a mismatch",
    { deny_when: [{ field: "sample", eq: "alpha" }] }, { sample: "alpha" },
    { ...stringEvaluation, field_value: "bravo" }, stringEvaluation, "mismatch");
  const membershipEvaluation = { matched_condition: { field: "sample", op: "in", value: ["a", "b"] },
    field_value: "a" };
  await expectReplay("recorded policy-value array order is part of the comparison",
    { deny_when: [{ field: "sample", in: ["a", "b"] }] }, { sample: "a" },
    { ...membershipEvaluation, matched_condition: { field: "sample", op: "in", value: ["b", "a"] } },
    membershipEvaluation, "mismatch");
  await expectReplay("object member order does not change the complete evaluation",
    { deny_when: [{ field: "sample", eq: "alpha" }] }, { sample: "alpha" },
    { field_value: "alpha", matched_condition: { value: "alpha", op: "eq", field: "sample" } },
    stringEvaluation);

  // Malformed policy is not replayable, even with an authentic signature.
  const invalidConditions: unknown[] = [null, [], "condition", {},
    { field: "", eq: 1 }, { field: 1, eq: 1 }, { field: null, eq: 1 },
    { field: "sample" }, { eq: 1 }, { field: "sample", unknown: 1 },
    { field: "sample", eq: 1, neq: 2 }, { field: "sample", eq: 1, extra: null }];
  for (const op of ["exists", "empty"]) {
    for (const value of [null, 0, 1, "true", [], {}]) invalidConditions.push({ field: "sample", [op]: value });
  }
  for (const op of ["in", "nin", "contains_any", "contains_none"]) {
    for (const value of [null, true, 1, "a", [], {}, [{}], [1, {}]]) invalidConditions.push({ field: "sample", [op]: value });
  }
  for (const op of ["lt", "lte", "gt", "gte"]) {
    for (const value of [null, true, "1", [], {}]) invalidConditions.push({ field: "sample", [op]: value });
  }
  for (const op of ["eq", "neq"]) {
    for (const value of [[], {}]) invalidConditions.push({ field: "sample", [op]: value });
  }
  for (const condition of invalidConditions) {
    const creation = signReceipt({ ...signedCreation,
      context: { actions: [{ name: signedAction.action, constraints: { deny_when: [condition] } }] } });
    assert.deepEqual(await verifyPolicyEvaluation(signedAction, [creation], [replayKey], replayOptions),
      { ...matchedCase.expected, status: "not_checked", diagnostic: "unsupported_policy", calculated_evaluation: null },
      `malformed condition: ${JSON.stringify(condition)}`);
  }
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
  assert.deepEqual(
    await verifyPolicyEvaluation(signReceipt({ ...signedAction, authorization_id: "" }),
      [signReceipt({ ...signedCreation, authorization_id: "" })], [replayKey], replayOptions),
    { ...matchedCase.expected, authorization_receipt_id: null, status: "not_checked",
      diagnostic: "authorization_receipt_not_found", calculated_evaluation: null },
    "an empty authorization ID never selects a matching creation snapshot",
  );

  for (const actions of [undefined, null, false, 1, "not-an-array", {}, [],
    [null], [[]], ["entry"], [{}],
    [{ name: signedAction.action, constraints: false }],
    [{ name: signedAction.action, constraints: 1 }],
    [{ name: signedAction.action, constraints: "policy" }],
    [{ name: signedAction.action, constraints: [] }]]) {
    const context = actions === undefined ? {} : { actions };
    assert.deepEqual(
      await verifyPolicyEvaluation(signedAction, [signReceipt({ ...signedCreation, context })],
        [replayKey], replayOptions),
      { ...matchedCase.expected, status: "not_checked", diagnostic: "unsupported_authorization_snapshot",
        calculated_evaluation: null },
      `an authenticated malformed actions snapshot is unsupported: ${JSON.stringify(actions)}`,
    );
  }
  assert.deepEqual(
    await verifyPolicyEvaluation(signedAction, [signReceipt({ ...signedCreation, context: { actions: [
      { name: "first-other-action", constraints: {} }, signedCreation.context.actions[0],
      { name: "second-other-action", constraints: {} },
    ] } })], [replayKey], replayOptions),
    matchedCase.expected,
    "several different unrelated actions do not change the selected policy",
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
    [Object.fromEntries(Object.entries(grant).map(([key, value]) =>
      [key === "provider_id" ? "unexpected_provider" : key, value]))],
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
    [{ ...opts, now: null }, "now must be a valid Date"],
    [{ ...opts, now: new Date(Number.NaN) }, "now must be a valid Date"],
  ] as const) {
    await assert.rejects(
      verifyPolicyEvaluation(matchedCase.receipt, matchedCase.authorization_receipts, keys, options as never),
      (error: unknown) => error instanceof VerificationError && error.message === expectedError,
    );
  }
  const pinned = [...trustedKeyFingerprints][0];
  for (const malformed of [null, 1, `extra${pinned}`, `${pinned}extra`, pinned.toUpperCase(),
    { toString: () => pinned }]) {
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

  const callableOptions = Object.assign(() => undefined, replayOptions);
  const callablePins = Object.assign(function* () { yield publicKeyFingerprint(replayKey); }, {
    has: () => true, size: 1,
    *[Symbol.iterator]() { yield publicKeyFingerprint(replayKey); },
  });
  for (const [options, message] of [
    [callableOptions, "expectedWorkspaceId must be a non-empty string"],
    [{ ...replayOptions, trustedKeyFingerprints: callablePins }, "trustedKeyFingerprints must be a non-empty set"],
    [{ ...replayOptions, trustedKeyFingerprints: {
      has: () => true, size: "1",
      *[Symbol.iterator]() { yield publicKeyFingerprint(replayKey); },
    } }, "trustedKeyFingerprints must be a non-empty set"],
  ] as const) {
    await assert.rejects(
      verifyPolicyEvaluation(signedAction, [signedCreation], [replayKey], options as never),
      (error: unknown) => error instanceof VerificationError && error.message === message,
    );
  }
  const { now: _now, ...withoutNow } = replayOptions;
  assert.deepEqual(await verifyPolicyEvaluation(signedAction, [signedCreation], [replayKey], withoutNow),
    matchedCase.expected, "the public replay API uses its default clock when now is omitted");
  for (const publicKeys of [[{ ...replayKey, extra: () => undefined }], [null],
    [{ ...replayKey, publicKeyBytes: undefined }]]) {
    await assert.rejects(
      verifyPolicyEvaluation(signedAction, [signedCreation], publicKeys as never, replayOptions),
      VerificationError,
      "uncloneable or malformed selected keys produce a verification error",
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
  await assert.rejects(
    verifyPolicyEvaluation(signedAction, [signedCreation],
      [replayKey, { ...replayKey, publicKeyBytes: sharedKeyBytes }], replayOptions),
    (error: unknown) => error instanceof VerificationError && error.message.includes("SharedArrayBuffer"),
    "an ordinary first key cannot hide shared memory in a later key",
  );
  const sharedBufferDescriptor = Object.getOwnPropertyDescriptor(globalThis, "SharedArrayBuffer")!;
  try {
    Object.defineProperty(globalThis, "SharedArrayBuffer", { ...sharedBufferDescriptor, value: undefined });
    assert.deepEqual(await verifyPolicyEvaluation(signedAction, [signedCreation], [replayKey], replayOptions),
      matchedCase.expected, "ordinary keys remain usable when SharedArrayBuffer is unavailable");
  } finally {
    Object.defineProperty(globalThis, "SharedArrayBuffer", sharedBufferDescriptor);
  }

  console.log("Policy evaluation TypeScript vectors passed");
}

const vectorsPath = process.argv[2];
if (!vectorsPath) throw new Error("usage: test_policy_evaluation.js PROFILE_VECTORS");
await main(vectorsPath);
