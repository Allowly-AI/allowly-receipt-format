/**
 * Run the TypeScript verifier against all test vectors.
 *
 * Usage: node --experimental-strip-types test_vectors.ts ../../test-vectors.json
 *   or after build: node dist/test_vectors.js ../../test-vectors.json
 */
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as signBytes, webcrypto } from "node:crypto";
import { mock } from "node:test";
import jcsCanonicalize from "canonicalize";
import {
  VerificationError,
  canonicalize,
  checkpointMerkleRoot,
  loadKeysFromJson,
  publicKeyFingerprint,
  verifyCheckpoint,
  verifyReceipt,
} from "./verifier.js";

// Hand-written expected canonical form for the spec §4.3 reference example.
// Deliberately NOT produced by the reference canonicalizer: if canonicalization
// regresses, generated vectors would regress with it and tests would still pass.
const GOLDEN_PAYLOAD = {
  schema_version: "4",
  receipt_id: "rcp_01HXZ2B3QW4N5M6P7R8S9T0V1W",
  workspace_id: "ws_01HXA1B2C3D4E5F6G7H8J9K0L1",
  issued_at: "2026-04-21T14:32:17.482Z",
  decision: "allow",
  reason: "authorization_granted_action_active",
  user_id: "emp_8821",
  agent_id: "referral_outreach",
  action: "outreach.send",
  resource: "edge:emp_8821:conn_9f2a",
  context: {
    session_id: "sess_7f2",
    origin: "chat",
    initiated_by: "user",
    control: "line\n\t\u0000",
    types: [7, true, null],
    "😀_key": "emoji",
    "｡_key": "bmp",
  },
  authorization_id: "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
  engine_version: "2026-04-17.1",
  alg: "Ed25519",
  key_id: "projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",
};
const GOLDEN_CANONICAL =
  '{"action":"outreach.send","agent_id":"referral_outreach",' +
  '"alg":"Ed25519",' +
  '"authorization_id":"auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",' +
  '"context":{"control":"line\\u000a\\u0009\\u0000","initiated_by":"user",' +
  '"origin":"chat","session_id":"sess_7f2","types":[7,true,null],' +
  '"😀_key":"emoji","｡_key":"bmp"},' +
  '"decision":"allow","engine_version":"2026-04-17.1",' +
  '"issued_at":"2026-04-21T14:32:17.482Z",' +
  '"key_id":"projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",' +
  '"reason":"authorization_granted_action_active",' +
  '"receipt_id":"rcp_01HXZ2B3QW4N5M6P7R8S9T0V1W",' +
  '"resource":"edge:emp_8821:conn_9f2a","schema_version":"4","user_id":"emp_8821",' +
  '"workspace_id":"ws_01HXA1B2C3D4E5F6G7H8J9K0L1"}';

async function main(vectorsPath: string): Promise<number> {
  const raw = readFileSync(vectorsPath, "utf-8");
  const vectors = JSON.parse(raw);

  const keys = loadKeysFromJson(vectors.public_keys);
  // All vectors use issued_at in 2026; pin "now" for deterministic timestamp checks.
  const now = new Date("2026-12-31T00:00:00Z");

  let failures = 0;

  try {
    await verifyReceipt(vectors.should_verify[0].receipt, keys, { now: new Date(Number.NaN) });
    console.log("  FAIL  invalid_now: invalid clock was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError && e.message.includes("now must be a valid Date")) {
      console.log(`  OK    invalid_now (${e.message})`);
    } else {
      console.log(`  FAIL  invalid_now: unexpected error: ${e}`);
      failures++;
    }
  }

  console.log("Testing own-property receipt validation...");
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const inheritedFields = structuredClone(vectors.should_verify[0].receipt);
  inheritedFields.key_id = "prototype-key";
  inheritedFields.signature = signBytes(null, Buffer.from("{}"), privateKey).toString("base64url");
  const publicKeyDer = publicKey.export({ type: "spki", format: "der" });
  const boundaryKey = {
    keyId: "boundary-key",
    alg: "Ed25519" as const,
    publicKeyBytes: new Uint8Array(publicKeyDer.subarray(-32)),
    activeFrom: new Date("0001-01-01T00:00:00.000Z"),
    activeUntil: null,
  };

  // These generated fixtures have no control characters, so RFC 8785 gives
  // the same bytes as wire 4. Sign independently of the code being mutated.
  // A malformed field must be rejected even when its signature is authentic.
  const signBoundaryReceipt = (receipt: Record<string, unknown>) => {
    const { signature, ...payload } = receipt;
    payload.key_id = boundaryKey.keyId;
    return { ...payload, signature: signBytes(null,
      Buffer.from(jcsCanonicalize(payload)!), privateKey).toString("base64url") };
  };
  const baseline = vectors.should_verify[0].receipt;
  await verifyReceipt(signBoundaryReceipt(baseline), [boundaryKey], { now });
  const rejectSigned = async (receipt: Record<string, unknown>, label: string) => {
    await assert.rejects(verifyReceipt(signBoundaryReceipt(receipt), [boundaryKey], { now }),
      VerificationError, label);
  };
  for (const field of ["receipt_id", "workspace_id", "reason", "user_id", "agent_id", "engine_version"]) {
    for (const value of [null, false, 1, [], {}]) {
      await rejectSigned({ ...baseline, [field]: value }, `${field} must be a string`);
    }
  }
  for (const field of ["resource", "authorization_id"]) {
    for (const value of [false, 1, [], {}]) {
      await rejectSigned({ ...baseline, [field]: value }, `${field} must be string or null`);
    }
    await verifyReceipt(signBoundaryReceipt({ ...baseline, [field]: null }), [boundaryKey], { now });
  }
  for (const context of [null, false, 1, "context", []]) {
    await rejectSigned({ ...baseline, context }, "context must be an object");
  }
  for (const fields of [
    { schema_version: "5" }, { alg: "RSA" }, { action: null }, { action: 1 },
    { action: [] }, { decision: "unknown" }, { unknown_field: null },
    { event: "authorization.create" },
  ]) await rejectSigned({ ...baseline, ...fields }, "signed invalid receipt shape");
  for (const field of Object.keys(baseline).filter(field => field !== "signature" && field !== "key_id")) {
    const missing = { ...baseline };
    delete missing[field];
    await rejectSigned(missing, `signed receipt missing ${field}`);
  }
  for (const policy_eval of [
    null, [], "evaluation", { matched_condition: null }, { field_value: null },
    { matched_condition: null, field_value: null, extra: true },
    { matched_condition: [], field_value: null },
    { matched_condition: { field: 1, op: "eq", value: null }, field_value: null },
    { matched_condition: { field: "v", op: 1, value: null }, field_value: null },
    { matched_condition: { field: "v", op: "eq", value: {} }, field_value: null },
    { matched_condition: { field: "v", op: "eq", value: [{}] }, field_value: null },
    { matched_condition: { field: "v", op: "eq", value: null, extra: true }, field_value: null },
    { matched_condition: null, field_value: [] }, { matched_condition: null, field_value: {} },
  ]) await rejectSigned({ ...baseline, policy_eval }, "signed malformed policy evaluation");
  for (const field of ["field", "op", "value"]) {
    const condition: Record<string, unknown> = { field: "v", op: "eq", value: null };
    delete condition[field];
    await rejectSigned({ ...baseline, policy_eval: { matched_condition: condition, field_value: null } },
      `signed policy condition missing ${field}`);
  }
  for (const field_value of [null, true, false, 0, -1, "scalar"]) {
    await verifyReceipt(signBoundaryReceipt({ ...baseline,
      policy_eval: { matched_condition: null, field_value } }), [boundaryKey], { now });
  }

  // A membership value may be empty or contain any mix of JSON scalars. Every
  // item must be a scalar; one valid item cannot hide an object or nested array.
  for (const value of [[], [null, false, true, 0, -1, ""]]) {
    await verifyReceipt(signBoundaryReceipt({ ...baseline,
      policy_eval: { matched_condition: { field: "v", op: "in", value }, field_value: null },
    }), [boundaryKey], { now });
  }
  for (const value of [[null, {}], [false, []], [1, {}], ["valid", []], [{}, true]]) {
    await rejectSigned({ ...baseline,
      policy_eval: { matched_condition: { field: "v", op: "in", value }, field_value: null },
    }, "every policy condition array item must be a scalar");
  }

  const { action: omittedAction, ...eventBaseline } = baseline;
  await verifyReceipt(signBoundaryReceipt({ ...eventBaseline,
    event: "authorization.create", decision: "authorization_granted", resource: null,
  }), [boundaryKey], { now });
  await rejectSigned({ ...eventBaseline,
    event: ["authorization.create"], decision: "authorization_granted", resource: null,
  }, "an event array must not be coerced into an allowed event name");

  const signedBoundary = signBoundaryReceipt(baseline);
  await assert.rejects(verifyReceipt(signedBoundary, new Set([boundaryKey]) as never, { now }),
    VerificationError, "publicKeys must be an array even when an iterable contains the right key");
  // Spec §7 step 2 rejects wrong-length signatures before cryptographic work.
  // Counting calls catches a skipped schema guard even if Ed25519 later rejects
  // the same bytes. No error text is used as the detection oracle.
  const signatureVerification = mock.method(webcrypto.subtle, "verify");
  try {
    for (const length of [0, 1, 63, 65]) {
      await assert.rejects(verifyReceipt({ ...signedBoundary,
        signature: Buffer.alloc(length).toString("base64url"),
      }, [boundaryKey], { now }), VerificationError);
    }
    assert.equal(signatureVerification.mock.callCount(), 0,
      "invalid signature lengths must fail the schema check before Ed25519 verification");
  } finally {
    signatureVerification.mock.restore();
  }
  // A caller can supply malformed key objects directly, bypassing the key
  // document loader. Sign the numeric selector independently so crypto cannot
  // conceal a missing receipt key_id type check.
  const { signature: omittedSignature, ...numericSelectorPayload } = { ...baseline, key_id: 7 };
  const numericSelectorReceipt = { ...numericSelectorPayload,
    signature: signBytes(null, Buffer.from(jcsCanonicalize(numericSelectorPayload)!), privateKey)
      .toString("base64url"),
  };
  await assert.rejects(verifyReceipt(numericSelectorReceipt,
    [{ ...boundaryKey, keyId: 7 as never }], { now }), VerificationError,
  "an authentic receipt must still use a string key_id");

  // Sparse arrays can have as many enumerable keys as their length by adding
  // an extra property. They must not become the signed empty array when cloned
  // and serialized. The accepted control fixes the signature over [] first.
  const emptyArrayReceipt = signBoundaryReceipt({ ...baseline, context: { values: [] } });
  await verifyReceipt(emptyArrayReceipt, [boundaryKey], { now });
  const balancedSparseArray: unknown[] = new Array(1);
  Object.defineProperty(balancedSparseArray, "extra", { enumerable: true, value: null });
  const sparseReceipt = { ...emptyArrayReceipt, context: { values: balancedSparseArray } };
  await assert.rejects(verifyReceipt(sparseReceipt, [boundaryKey], { now }), VerificationError,
    "a sparse array plus an extra key must not reuse an empty-array signature");

  const nullPrototypeContext = Object.assign(Object.create(null), {
    empty: Object.create(null), values: [null, false, [], {}],
  });
  await verifyReceipt(signBoundaryReceipt({ ...baseline, context: nullPrototypeContext }),
    [boundaryKey], { now });
  const localMetadataReceipt = signBoundaryReceipt({ ...baseline, context: {} }) as Record<string, unknown>;
  let localMetadataReads = 0;
  Object.defineProperty(localMetadataReceipt.context as object, "local_metadata", {
    enumerable: false,
    get() { localMetadataReads++; throw new Error("local metadata must not be read"); },
  });
  await verifyReceipt(localMetadataReceipt, [boundaryKey], { now });
  assert.equal(localMetadataReads, 0, "non-enumerable metadata is outside the JSON payload");

  const checkpointCase = vectors.checkpoint_cases[0];
  const checkpoint = checkpointCase.checkpoint;
  await verifyReceipt(signBoundaryReceipt(checkpoint), [boundaryKey], { now });
  for (const fields of [
    { period_start: "2026-04-21T00:00:00.001Z" },
    { period_end: checkpoint.context.period_start },
    { period_end: "2026-04-23T00:00:00.000Z" },
    { receipt_count: -1 }, { receipt_count: "2" },
    { merkle_root: "sha256:" + "A".repeat(64) },
    { merkle_root: "sha256:" + "0".repeat(63) },
    { previous_checkpoint_id: null }, { previous_merkle_root: null },
    { previous_checkpoint_id: 1 }, { previous_merkle_root: "sha256:bad" },
    { unknown_field: null },
  ]) await rejectSigned({ ...checkpoint, context: { ...checkpoint.context, ...fields } },
    "signed checkpoint context must obey the daily commitment schema");
  for (const field of Object.keys(checkpoint.context)) {
    const context = { ...checkpoint.context };
    delete context[field];
    await rejectSigned({ ...checkpoint, context }, `checkpoint context missing ${field}`);
  }
  await rejectSigned({ ...checkpoint, issued_at: checkpoint.context.period_start },
    "checkpoint cannot be issued before its period ends");
  await rejectSigned({ ...checkpoint, authorization_id: "not-null" },
    "checkpoint authorization must be null");
  await rejectSigned({ ...checkpoint, resource: "not-null" }, "checkpoint resource must be null");
  const checkpointOptions = { expectedWorkspaceId: checkpoint.workspace_id, now };
  const checkpointKeys = [...keys, boundaryKey];
  await verifyCheckpoint(signBoundaryReceipt(checkpoint), checkpointCase.receipts, checkpointKeys, checkpointOptions);
  for (const fields of [
    { receipt_count: checkpointCase.receipts.length + 1 },
    { merkle_root: "sha256:" + "0".repeat(64) },
  ]) await assert.rejects(verifyCheckpoint(signBoundaryReceipt({ ...checkpoint,
    context: { ...checkpoint.context, ...fields } }), checkpointCase.receipts, checkpointKeys, checkpointOptions),
    VerificationError, "authentic checkpoint must commit the supplied member set");
  assert.equal(checkpointCase.receipts.length, 2, "the fixed checkpoint fixture has two members");
  for (const [issued_at, accepted] of [
    [checkpoint.context.period_start, true], [checkpoint.context.period_end, false],
    [new Date(Date.parse(checkpoint.context.period_start) - 1).toISOString(), false],
  ]) {
    const members = [...checkpointCase.receipts];
    members[0] = signBoundaryReceipt({ ...members[0], issued_at });
    // Independent two-leaf commitment keeps the signatures, count and root
    // correct. Only the member's period membership can cause rejection.
    const leaves = members.map(member => createHash("sha256").update(Buffer.from([0]))
      .update(jcsCanonicalize(member)!).digest()).sort(Buffer.compare);
    const merkle_root = "sha256:" + createHash("sha256").update(Buffer.from([1]))
      .update(leaves[0]).update(leaves[1]).digest("hex");
    const verification = verifyCheckpoint(signBoundaryReceipt({ ...checkpoint,
      context: { ...checkpoint.context, merkle_root } }), members, checkpointKeys, checkpointOptions);
    if (accepted) await verification;
    else await assert.rejects(verification, VerificationError,
      "the checkpoint period includes its start but excludes its end");
  }

  // Pin both sides of the reference verifier's five-minute clock allowance.
  const issuedAt = Date.parse(vectors.should_verify[0].receipt.issued_at);
  for (const ahead of [0, 1, 299_999, 300_000]) {
    await verifyReceipt(vectors.should_verify[0].receipt, keys, {
      now: new Date(issuedAt - ahead),
    });
  }
  await assert.rejects(
    verifyReceipt(vectors.should_verify[0].receipt, keys, {
      now: new Date(issuedAt - 300_001),
    }),
    (error: unknown) => error instanceof VerificationError
      && error.message.startsWith("receipt issued in the future:"),
  );

  // A valid signature must not hide an invalid lifecycle resource.
  for (const [event, decision] of [
    ["authorization.create", "authorization_granted"],
    ["authorization.revoke", "authorization_revoked"],
  ]) {
    const payload = {
      ...structuredClone(vectors.should_verify[0].receipt),
      key_id: boundaryKey.keyId,
      event, decision, resource: "not-null",
    };
    delete payload.signature;
    delete payload.action;
    const receipt = {
      ...payload,
      signature: signBytes(null, canonicalize(payload), privateKey).toString("base64url"),
    };
    await assert.rejects(
      verifyReceipt(receipt, [boundaryKey], { now }),
      (error: unknown) => error instanceof VerificationError
        && error.message === `authorization lifecycle receipt with event=${JSON.stringify(event)} must have null resource`,
    );
  }

  // Duplicate IDs and duplicate bytes are independent key-document failures.
  const independentKey = {
    ...vectors.public_keys.keys[0],
    public_key: Buffer.from(boundaryKey.publicKeyBytes).toString("base64url"),
  };
  delete independentKey.public_key_fingerprint;
  assert.throws(
    () => loadKeysFromJson({
      ...vectors.public_keys,
      keys: [vectors.public_keys.keys[0], independentKey],
    }),
    (error: unknown) => error instanceof VerificationError
      && error.message === `duplicate key_id in keys document: ${JSON.stringify(independentKey.key_id)}`,
  );
  const duplicateBytes = { ...vectors.public_keys.keys[0], key_id: "same-bytes-new-id" };
  assert.throws(
    () => loadKeysFromJson({
      ...vectors.public_keys,
      keys: [vectors.public_keys.keys[0], duplicateBytes],
    }),
    (error: unknown) => error instanceof VerificationError
      && error.message === 'duplicate public key in keys document: "same-bytes-new-id"',
  );

  // Merkle commitments are sets, including empty, odd-sized and reordered sets.
  const members = vectors.should_verify.slice(0, 3).map((vector: { receipt: Record<string, unknown> }) => vector.receipt);
  const root = await checkpointMerkleRoot(members);
  // Independent SHA-256 calculation with the spec's 00/01 domains and odd leaf.
  assert.equal(root, "sha256:e529bb04362039e95713a85de5341c1bb1e544c35024a13248785b1880f6f71c");
  assert.equal(await checkpointMerkleRoot([...members].reverse()), root);
  assert.equal(await checkpointMerkleRoot([]), "sha256:dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986");
  await assert.rejects(
    checkpointMerkleRoot([members[0], members[0]]),
    (error: unknown) => error instanceof VerificationError
      && error.message.startsWith("duplicate checkpoint member receipt_id:"),
  );
  for (const member of [null, "not-a-receipt", { receipt_id: 1 }]) {
    await assert.rejects(
      checkpointMerkleRoot([member as never]),
      (error: unknown) => error instanceof VerificationError
        && error.message === "checkpoint member must be a receipt object with receipt_id",
    );
  }

  assert.equal(new TextDecoder().decode(canonicalize({ v: '"\\\b\f\r' })), String.raw`{"v":"\"\\\u0008\u000c\u000d"}`);
  const canonicalScalarCases: Array<[unknown, string]> = [
    [null, "null"], [false, "false"], [true, "true"], [0, "0"], [-0, "0"],
    [Number.MAX_SAFE_INTEGER, "9007199254740991"],
    [Number.MIN_SAFE_INTEGER, "-9007199254740991"],
    [[], "[]"], [{}, "{}"], [Object.create(null), "{}"],
    [{ empty: [], nested: Object.create(null), value: null },
      '{"empty":[],"nested":{},"value":null}'],
    [{ "2": "two", "10": "ten", "1": "one" }, '{"1":"one","10":"ten","2":"two"}'],
    ["/😀é", '"/😀é"'],
  ];
  for (const [value, expected] of canonicalScalarCases) {
    assert.deepEqual(canonicalize(value), new TextEncoder().encode(expected),
      "canonical bytes must preserve empty values, scalars and UTF-8");
  }
  assert.deepEqual(canonicalize(String.fromCharCode(...Array.from({ length: 32 }, (_, i) => i))),
    new TextEncoder().encode(String.raw`"\u0000\u0001\u0002\u0003\u0004\u0005\u0006\u0007\u0008\u0009\u000a\u000b\u000c\u000d\u000e\u000f\u0010\u0011\u0012\u0013\u0014\u0015\u0016\u0017\u0018\u0019\u001a\u001b\u001c\u001d\u001e\u001f"`),
    "wire 4 uses a lowercase four-digit escape for every control character");
  assert.throws(() => canonicalize(balancedSparseArray), VerificationError,
    "key count alone cannot prove that an array is dense");

  // Enumerable accessors are reachable JavaScript inputs, but are not JSON
  // data. Rejection must not execute a getter while making the snapshot.
  for (const value of [{}, [null]]) {
    let getterReads = 0;
    Object.defineProperty(value, Array.isArray(value) ? "0" : "claim", {
      enumerable: true,
      get() { getterReads++; return true; },
    });
    assert.throws(() => canonicalize(value), VerificationError);
    assert.equal(getterReads, 0, "an invalid input getter must never run");
  }
  const snapshotReceipt = signBoundaryReceipt({ ...baseline, context: { claim: false } }) as Record<string, unknown>;
  const snapshotVerification = verifyReceipt(snapshotReceipt, [boundaryKey], { now });
  queueMicrotask(() => { (snapshotReceipt.context as { claim: boolean }).claim = true; });
  await snapshotVerification;
  assert.deepEqual(snapshotReceipt.context, { claim: true }, "the caller changed its input after verification began");

  assert.doesNotThrow(() => canonicalize(new Array(49_999).fill(null)));
  assert.throws(
    () => canonicalize(new Array(50_000).fill(null)),
    (error: unknown) => error instanceof VerificationError
      && error.message === "payload exceeds max node count 50000",
  );
  let nested: unknown = null;
  for (let depth = 1; depth < 32; depth++) nested = [nested];
  assert.doesNotThrow(() => canonicalize(nested));
  assert.throws(
    () => canonicalize([nested]),
    (error: unknown) => error instanceof VerificationError
      && error.message === "payload nesting exceeds max depth 32",
  );
  assert.throws(
    () => canonicalize({ ["\ud800"]: null }),
    (error: unknown) => error instanceof VerificationError
      && error.message === "string contains an unpaired Unicode surrogate",
  );
  try {
    await verifyReceipt(Object.create(inheritedFields), [{
      keyId: "prototype-key",
      alg: "Ed25519",
      publicKeyBytes: new Uint8Array(publicKeyDer.subarray(-32)),
      activeFrom: new Date("0001-01-01T00:00:00.000Z"),
      activeUntil: null,
    }], { now });
    console.log("  FAIL  prototype_only_receipt: signature over {} was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError) {
      console.log(`  OK    prototype_only_receipt (${e.message})`);
    } else {
      console.log(`  FAIL  prototype_only_receipt: unexpected error: ${e}`);
      failures++;
    }
  }
  const inheritedContext = structuredClone(vectors.should_verify[0].receipt);
  inheritedContext.context = Object.create({ unsigned_claim: true });
  try {
    await verifyReceipt(inheritedContext, keys, { now });
    console.log("  FAIL  prototype_context: inherited context claim was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError && e.message.includes("plain JSON object")) {
      console.log(`  OK    prototype_context (${e.message})`);
    } else {
      console.log(`  FAIL  prototype_context: unexpected error: ${e}`);
      failures++;
    }
  }
  const proxyContext = structuredClone(vectors.should_verify[0].receipt);
  proxyContext.context = new Proxy(proxyContext.context, {});
  try {
    await verifyReceipt(proxyContext, keys, { now });
    console.log("  FAIL  proxy_context: nested Proxy was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError && e.message.includes("structured-cloneable JSON data")) {
      console.log(`  OK    proxy_context (${e.message})`);
    } else {
      console.log(`  FAIL  proxy_context: unexpected error: ${e}`);
      failures++;
    }
  }
  try {
    canonicalize({ sparse: new Array(1) });
    console.log("  FAIL  sparse_array: sparse array was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError && e.message.includes("dense JSON arrays")) {
      console.log(`  OK    sparse_array (${e.message})`);
    } else {
      console.log(`  FAIL  sparse_array: unexpected error: ${e}`);
      failures++;
    }
  }

  console.log("Testing golden canonical bytes (spec §4.3)...");
  const got = new TextDecoder().decode(canonicalize(GOLDEN_PAYLOAD));
  if (got === GOLDEN_CANONICAL) {
    console.log("  OK    golden_canonical_form");
  } else {
    console.log(`  FAIL  golden_canonical_form:\n    expected: ${GOLDEN_CANONICAL}\n    got:      ${got}`);
    failures++;
  }

  // A sort comparator must be consistent for the keys it receives, including
  // self comparisons (ECMA-262 SortIndexedProperties). Otherwise canonical
  // bytes depend on the engine's permitted comparison sequence. Default
  // STRING sorting remains valid; no comparator or sorting method is required.
  {
    const payload = { "｡": 7, z: 6, "😀": 5, a: 4, "": 3, "é": 2, aa: 1 };
    const nativeSort = Array.prototype.sort;
    const orderedKeys = nativeSort.call(Object.keys(payload)) as string[];
    Array.prototype.sort = function (this: unknown[], compare?: (a: unknown, b: unknown) => number) {
      const keyOf = (value: unknown): unknown => Array.isArray(value) ? value[0] : value;
      if (compare && this.length === orderedKeys.length
        && this.every(value => orderedKeys.includes(keyOf(value) as string))) {
        for (const left of this) {
          // Both signs of numeric zero mean equality for a valid comparator.
          assert.equal(compare(left, left) + 0, 0, "canonical key sort must compare a key equal to itself");
          for (const right of this) {
            const expected = Math.sign(orderedKeys.indexOf(keyOf(left) as string)
              - orderedKeys.indexOf(keyOf(right) as string));
            const forward: number = Math.sign(compare(left, right)) + 0;
            assert.equal(forward, expected, "canonical key sort must follow native UTF-16 STRING order");
            assert.ok(forward === -Math.sign(compare(right, left)),
              "canonical key sort must reverse sign when its arguments are reversed");
          }
        }
      }
      return nativeSort.call(this, compare);
    } as typeof Array.prototype.sort;
    try {
      assert.deepEqual(canonicalize(payload),
        new TextEncoder().encode('{"":3,"a":4,"aa":1,"z":6,"é":2,"😀":5,"｡":7}'));
    } finally {
      Array.prototype.sort = nativeSort;
    }
  }

  console.log("\nTesting keys-document hardening...");
  const dupDoc = { ...vectors.public_keys, keys: [...vectors.public_keys.keys, ...vectors.public_keys.keys] };
  const badKeyDoc = (field: "active_from" | "active_until", value: unknown) => {
    const doc = structuredClone(vectors.public_keys);
    doc.keys[0][field] = value;
    return doc;
  };
  const missingActiveUntil = structuredClone(vectors.public_keys);
  delete missingActiveUntil.keys[0].active_until;
  const missingWorkspace = structuredClone(vectors.public_keys);
  delete missingWorkspace.workspace_id;
  const emptyWorkspace = structuredClone(vectors.public_keys);
  emptyWorkspace.workspace_id = "";
  const wrongAlg = structuredClone(vectors.public_keys);
  wrongAlg.keys[0].alg = "RSA";
  const wrongFingerprint = structuredClone(vectors.public_keys);
  wrongFingerprint.keys[0].public_key_fingerprint = "sha256:" + "0".repeat(64);
  const invalidKeyDocs = [
    ["duplicate_keys", dupDoc],
    ["missing_keys_array", {}],
    ["missing_workspace_id", missingWorkspace],
    ["empty_workspace_id", emptyWorkspace],
    ["wrong_algorithm", wrongAlg],
    ["wrong_public_key_fingerprint", wrongFingerprint],
    ["active_from_missing_millis", badKeyDoc("active_from", "2026-01-01T00:00:00Z")],
    ["active_from_microseconds", badKeyDoc("active_from", "2026-01-01T00:00:00.123456Z")],
    ["active_from_nanoseconds", badKeyDoc("active_from", "2026-01-01T00:00:00.123456789Z")],
    ["active_from_offset", badKeyDoc("active_from", "2026-01-01T00:00:00.000+00:00")],
    ["active_until_empty", badKeyDoc("active_until", "")],
    ["active_until_zero", badKeyDoc("active_until", 0)],
    ["active_until_false", badKeyDoc("active_until", false)],
    ["active_until_missing", missingActiveUntil],
  ] as const;
  for (const [name, doc] of invalidKeyDocs) {
    try {
      loadKeysFromJson(doc as never);
      console.log(`  FAIL  ${name}: should have been rejected`);
      failures++;
    } catch (e) {
      if (e instanceof VerificationError) {
        console.log(`  OK    ${name} (${e.message})`);
      } else {
        console.log(`  FAIL  ${name}: unexpected error type: ${e}`);
        failures++;
      }
    }
  }
  for (const invalid of [null, false, 1, "entry"]) {
    assert.throws(() => loadKeysFromJson({ ...vectors.public_keys, keys: [invalid] }), VerificationError,
      "malformed key entries must raise the documented verification error");
  }
  for (const field of ["key_id", "alg", "public_key", "active_from"]) {
    for (const value of [null, false, 1, [], {}]) {
      assert.throws(() => loadKeysFromJson({ ...vectors.public_keys,
        keys: [{ ...vectors.public_keys.keys[0], [field]: value }] }), VerificationError,
        `key ${field} must be a string`);
    }
    const missing = { ...vectors.public_keys.keys[0] };
    delete missing[field];
    assert.throws(() => loadKeysFromJson({ ...vectors.public_keys, keys: [missing] }), VerificationError,
      `key entry requires ${field}`);
  }
  for (const length of [0, 31, 33]) {
    const entry = { ...vectors.public_keys.keys[0], public_key: Buffer.alloc(length).toString("base64url") };
    delete entry.public_key_fingerprint;
    assert.throws(() => loadKeysFromJson({ ...vectors.public_keys,
      keys: [entry] }),
      VerificationError, "Ed25519 public keys must contain exactly 32 bytes");
  }
  const noncanonicalPublicKey = structuredClone(vectors.public_keys);
  noncanonicalPublicKey.keys[0].public_key =
    "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2il";
  try {
    loadKeysFromJson(noncanonicalPublicKey);
    console.log("  FAIL  noncanonical_public_key: should have been rejected");
    failures++;
  } catch (e) {
    const expected =
      'non-canonical base64url: "O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2il"';
    if (e instanceof VerificationError && e.message === expected) {
      console.log(`  OK    noncanonical_public_key (${e.message})`);
    } else {
      console.log(`  FAIL  noncanonical_public_key: unexpected error: ${e}`);
      failures++;
    }
  }
  if (keys[0].activeFrom.getUTCFullYear() === 1) {
    console.log("  OK    active_from_year_0001");
  } else {
    console.log(`  FAIL  active_from_year_0001: got ${keys[0].activeFrom.toISOString()}`);
    failures++;
  }
  if (vectors.public_keys.keys[0].public_key_fingerprint === publicKeyFingerprint(keys[0])) {
    console.log("  OK    public_key_fingerprint");
  } else {
    console.log("  FAIL  public_key_fingerprint: fixed vector does not match decoded key");
    failures++;
  }
  try {
    await verifyReceipt(vectors.should_verify[0].receipt, [
      { ...keys[0], alg: "RSA" as never },
      ...keys.slice(1),
    ], { now });
    console.log("  FAIL  public_key_algorithm: non-Ed25519 key object was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError && e.message.includes("public key alg")) {
      console.log(`  OK    public_key_algorithm (${e.message})`);
    } else {
      console.log(`  FAIL  public_key_algorithm: unexpected error: ${e}`);
      failures++;
    }
  }
  try {
    await verifyReceipt(vectors.should_verify[0].receipt, [
      new Proxy(keys[0], {}),
      ...keys.slice(1),
    ], { now });
    console.log("  FAIL  public_key_proxy: proxied key was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError && e.message.includes("publicKeys must be structured-cloneable")) {
      console.log(`  OK    public_key_proxy (${e.message})`);
    } else {
      console.log(`  FAIL  public_key_proxy: unexpected error: ${e}`);
      failures++;
    }
  }
  try {
    await verifyReceipt(vectors.should_verify[0].receipt, [
      { ...keys[0], activeFrom: new Date(Number.NaN) },
      ...keys.slice(1),
    ], { now });
    console.log("  FAIL  public_key_invalid_date: invalid key date was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError && e.message.includes("activeFrom must be a valid Date")) {
      console.log(`  OK    public_key_invalid_date (${e.message})`);
    } else {
      console.log(`  FAIL  public_key_invalid_date: unexpected error: ${e}`);
      failures++;
    }
  }
  const rotatedReceipt = vectors.should_verify.find(
    (v: { name: string }) => v.name === "action_rotated_key",
  ).receipt;
  try {
    await verifyReceipt(rotatedReceipt, keys, {
      now,
      trustedKeyFingerprints: new Set([publicKeyFingerprint(keys[0])]),
    });
    console.log("  FAIL  selected_key_fingerprint_pin: untrusted rotation key was accepted");
    failures++;
  } catch (e) {
    if (e instanceof VerificationError && e.message.includes("fingerprint is not trusted")) {
      console.log(`  OK    selected_key_fingerprint_pin (${e.message})`);
    } else {
      console.log(`  FAIL  selected_key_fingerprint_pin: unexpected error: ${e}`);
      failures++;
    }
  }
  try {
    await verifyReceipt(rotatedReceipt, keys, {
      now,
      trustedKeyFingerprints: new Set(keys.map(publicKeyFingerprint)),
    });
    console.log("  OK    selected_key_fingerprint_rotation");
  } catch (e) {
    console.log(`  FAIL  selected_key_fingerprint_rotation: ${e}`);
    failures++;
  }

  console.log(`\nTesting ${vectors.should_verify.length} should_verify vectors...`);
  for (const v of vectors.should_verify) {
    try {
      await verifyReceipt(v.receipt, keys, { now });
      console.log(`  OK    ${v.name}`);
    } catch (e) {
      if (e instanceof VerificationError) {
        console.log(`  FAIL  ${v.name}: unexpected rejection: ${e.message}`);
      } else {
        console.log(`  FAIL  ${v.name}: unexpected error: ${e}`);
      }
      failures++;
    }
  }

  console.log(`\nTesting ${vectors.should_reject.length} should_reject vectors...`);
  for (const v of vectors.should_verify) {
    if (v.receipt.event !== "confirmation.resolve") continue;
    await assert.rejects(
      verifyReceipt(v.receipt, keys, { now, expectedWorkspaceId: "ws_other" }),
      /workspace_id mismatch/,
      "confirmation receipts must bind to the caller's trusted workspace",
    );
  }
  for (const v of vectors.should_reject) {
    try {
      await verifyReceipt(v.receipt, keys, { now });
      console.log(`  FAIL  ${v.name}: should have been rejected`);
      failures++;
    } catch (e) {
      if (!(e instanceof VerificationError)) {
        console.log(`  FAIL  ${v.name}: unexpected error type: ${e}`);
        failures++;
        continue;
      }
      const expected: string = v.expected_reason;
      if (e.message.toLowerCase().includes(expected.toLowerCase())) {
        console.log(`  OK    ${v.name} (${e.message})`);
      } else {
        console.log(`  FAIL  ${v.name}: wrong reason`);
        console.log(`        expected: ${expected}`);
        console.log(`        got:      ${e.message}`);
        failures++;
      }
    }
  }

  console.log(`\nTesting ${vectors.checkpoint_cases.length} checkpoint vectors...`);
  for (const checkpointCase of vectors.checkpoint_cases) {
    try {
      const root = await checkpointMerkleRoot(checkpointCase.receipts);
      if (root !== checkpointCase.expected_merkle_root) {
        throw new VerificationError(
          `cross-language root mismatch: expected ${checkpointCase.expected_merkle_root}, got ${root}`,
        );
      }
      await verifyCheckpoint(
        checkpointCase.checkpoint,
        checkpointCase.receipts,
        keys,
        {
          expectedWorkspaceId: vectors.public_keys.workspace_id,
          previousCheckpoint: checkpointCase.previous_checkpoint,
          now,
          trustedKeyFingerprints: new Set(keys.map(publicKeyFingerprint)),
        },
      );
      try {
        await verifyCheckpoint(
          checkpointCase.checkpoint,
          checkpointCase.receipts,
          keys,
          {
            expectedWorkspaceId: vectors.public_keys.workspace_id,
            now,
            trustedKeyFingerprints: new Set(["sha256:" + "0".repeat(64)]),
          },
        );
        throw new VerificationError("checkpoint accepted an untrusted signing key");
      } catch (e) {
        if (!(e instanceof VerificationError) || !e.message.includes("fingerprint is not trusted")) {
          throw e;
        }
      }
      try {
        await verifyCheckpoint(
          checkpointCase.checkpoint,
          checkpointCase.receipts.slice(0, -1),
          keys,
          { expectedWorkspaceId: vectors.public_keys.workspace_id, now },
        );
        throw new VerificationError("checkpoint accepted an omitted member");
      } catch (e) {
        if (!(e instanceof VerificationError) || !e.message.includes("receipt_count mismatch")) {
          throw e;
        }
      }
      const sharedKeyBytes = new Uint8Array(
        new SharedArrayBuffer(keys[0].publicKeyBytes.length),
      );
      sharedKeyBytes.set(keys[0].publicKeyBytes);
      try {
        await verifyCheckpoint(checkpointCase.checkpoint, checkpointCase.receipts, [
          { ...keys[0], publicKeyBytes: sharedKeyBytes },
          ...keys.slice(1),
        ], {
          expectedWorkspaceId: vectors.public_keys.workspace_id,
          now,
        });
        throw new VerificationError("checkpoint accepted shared key bytes");
      } catch (e) {
        if (!(e instanceof VerificationError) || !e.message.includes("SharedArrayBuffer")) {
          throw e;
        }
      }
      const mutableCheckpoint = structuredClone(checkpointCase.checkpoint);
      const incompleteMembers = checkpointCase.receipts.slice(0, -1);
      const incompleteRoot = await checkpointMerkleRoot(incompleteMembers);
      queueMicrotask(() => {
        mutableCheckpoint.context.receipt_count = incompleteMembers.length;
        mutableCheckpoint.context.merkle_root = incompleteRoot;
      });
      try {
        await verifyCheckpoint(mutableCheckpoint, incompleteMembers, keys, {
          expectedWorkspaceId: vectors.public_keys.workspace_id,
          now,
        });
        throw new VerificationError("checkpoint accepted inputs mutated during verification");
      } catch (e) {
        if (!(e instanceof VerificationError) || !e.message.includes("receipt_count mismatch")) {
          throw e;
        }
      }
      console.log(`  OK    ${checkpointCase.name}`);
    } catch (e) {
      console.log(`  FAIL  ${checkpointCase.name}: ${e}`);
      failures++;
    }
  }

  console.log("\nTesting checkpoint/key boundary contracts...");
  {
    const verificationError = (error: unknown) => error instanceof VerificationError
      && error.name === "VerificationError";
    // These fresh signed fixtures are control-free. JCS and Node crypto are
    // independent of the verifier; the 00/01/02 domains come from spec §3.7.1.
    const leaf = (receipt: Record<string, unknown>) => createHash("sha256")
      .update(Buffer.from([0])).update(jcsCanonicalize(receipt)!).digest();
    const independentRoot = (receipts: Array<Record<string, unknown>>) => {
      let hashes = receipts.map(leaf).sort(Buffer.compare);
      if (!hashes.length) return "sha256:" + createHash("sha256").update(Buffer.from([2])).digest("hex");
      while (hashes.length > 1) {
        hashes = Array.from({ length: Math.ceil(hashes.length / 2) }, (_, index) =>
          createHash("sha256").update(Buffer.from([1])).update(hashes[index * 2])
            .update(hashes[Math.min(index * 2 + 1, hashes.length - 1)]).digest());
      }
      return "sha256:" + hashes[0].toString("hex");
    };
    const emptyRoot = "sha256:dbc1b4c900ffe48d575b5da5c638040125f65db0fe3e24494b76ea986457d986";
    assert.equal(independentRoot([]), emptyRoot);
    const start = "2026-04-21T00:00:00.000Z";
    const end = "2026-04-22T00:00:00.000Z";
    const emptyContext = {
      period_start: start, period_end: end, receipt_count: 0, merkle_root: emptyRoot,
      previous_checkpoint_id: null, previous_merkle_root: null,
    };
    const emptyCheckpoint = signBoundaryReceipt({ ...checkpoint, receipt_id: "boundary-empty-day",
      issued_at: end, context: emptyContext });
    const options = { expectedWorkspaceId: vectors.public_keys.workspace_id, now };
    const members = Array.from({ length: 17 }, (_, index) => signBoundaryReceipt({ ...baseline,
      receipt_id: `boundary-member-${index}`, issued_at: start, context: { index } }));
    for (const count of [0, 1, 3, 7, 17]) {
      const receipts = members.slice(0, count);
      const merkle_root = independentRoot(receipts);
      const signed = signBoundaryReceipt({ ...emptyCheckpoint,
        receipt_id: `boundary-count-${count}`, context: { ...emptyContext, receipt_count: count, merkle_root } });
      await verifyReceipt(signed, [boundaryKey], { now });
      await verifyCheckpoint(signed, receipts, [boundaryKey], options);
      assert.equal(await checkpointMerkleRoot(receipts), merkle_root, `independent ${count}-leaf root`);
      assert.equal(await checkpointMerkleRoot([...receipts].reverse()), merkle_root, "member order cannot change a set commitment");
    }
    // At most 257 distinct leaves guarantee a shared first byte. Comparing the
    // entire digest is required even when that first byte ties; both orders
    // must yield the independently computed two-leaf commitment.
    const prefixes = new Map<number, Record<string, unknown>>();
    let tied: Array<Record<string, unknown>> | undefined;
    for (let index = 0; index < 257 && tied === undefined; index++) {
      const receipt = signBoundaryReceipt({ ...baseline,
        receipt_id: `boundary-prefix-${index}`, issued_at: start, context: {} });
      const digest = leaf(receipt);
      const previous = prefixes.get(digest[0]);
      if (previous && !leaf(previous).equals(digest)) tied = [previous, receipt];
      else prefixes.set(digest[0], receipt);
    }
    assert.ok(tied, "find two distinct digest suffixes sharing a first byte");
    for (const receipts of [tied, [...tied].reverse()]) {
      assert.equal(await checkpointMerkleRoot(receipts), independentRoot(receipts),
        "Merkle sorting must compare digest suffixes when the first byte ties");
    }
    await assert.rejects(checkpointMerkleRoot([members[0], members[0]]), verificationError,
      "duplicate member ids are rejected independently of the root");

    for (const receipt_count of [0, 1, Number.MAX_SAFE_INTEGER - 1, Number.MAX_SAFE_INTEGER]) {
      await verifyReceipt(signBoundaryReceipt({ ...emptyCheckpoint,
        context: { ...emptyContext, receipt_count } }), [boundaryKey], { now });
    }
    for (const receipt_count of [-1, 0.5, Number.MAX_SAFE_INTEGER + 1, null, false, "0"]) {
      await assert.rejects(verifyReceipt(signBoundaryReceipt({ ...emptyCheckpoint,
        context: { ...emptyContext, receipt_count } }), [boundaryKey], { now }), verificationError);
    }
    for (const field of ["merkle_root", "previous_merkle_root"]) {
      for (const value of ["prefix" + emptyRoot, emptyRoot + "suffix", [emptyRoot], null, 1, false]) {
        const context = { ...emptyContext, previous_checkpoint_id: "prior", previous_merkle_root: emptyRoot,
          [field]: value };
        await assert.rejects(verifyReceipt(signBoundaryReceipt({ ...emptyCheckpoint, context }),
          [boundaryKey], { now }), verificationError, `${field} must have the exact string profile`);
      }
    }
    for (const day of ["0001-01-01", "0099-12-31", "2000-02-28", "2000-02-29", "9999-12-30"]) {
      const period_start = day + "T00:00:00.000Z";
      const period_end = new Date(Date.parse(period_start) + 86_400_000).toISOString();
      const signed = signBoundaryReceipt({ ...emptyCheckpoint, issued_at: period_end,
        context: { ...emptyContext, period_start, period_end } });
      await verifyCheckpoint(signed, [], [boundaryKey], { ...options, now: new Date(period_end) });
    }
    for (const context of [
      { ...emptyContext, period_start: "2026-04-21T12:00:00.000Z", period_end: "2026-04-22T12:00:00.000Z" },
      { ...emptyContext, period_end: "2026-04-23T00:00:00.000Z" },
      { ...emptyContext, period_start: end, period_end: start },
      { ...emptyContext, period_start: start, period_end: start },
    ]) {
      await assert.rejects(verifyReceipt(signBoundaryReceipt({ ...emptyCheckpoint,
        issued_at: "2026-04-24T00:00:00.000Z", context }), [boundaryKey], { now }), verificationError);
    }
    await assert.rejects(verifyReceipt(signBoundaryReceipt({ ...emptyCheckpoint,
      issued_at: new Date(Date.parse(end) - 1).toISOString() }), [boundaryKey], { now }), verificationError,
    "checkpoint issue time includes the exact end but excludes the preceding millisecond");
    for (const field of ["period_start", "period_end"]) {
      await assert.rejects(verifyReceipt(signBoundaryReceipt({ ...emptyCheckpoint,
        context: { ...emptyContext, [field]: { toString: null } } }), [boundaryKey], { now }), verificationError,
      "a JSON object in a timestamp field must raise VerificationError without implicit coercion");
    }

    const prior: Record<string, unknown> & { signature: string } = signBoundaryReceipt({ ...emptyCheckpoint, receipt_id: "boundary-prior",
      issued_at: start, context: { ...emptyContext,
        period_start: "2026-04-20T00:00:00.000Z", period_end: start } });
    const linked = signBoundaryReceipt({ ...emptyCheckpoint, receipt_id: "boundary-linked",
      context: { ...emptyContext, receipt_count: members.length, merkle_root: independentRoot(members),
        previous_checkpoint_id: prior.receipt_id, previous_merkle_root: emptyRoot } });
    await verifyCheckpoint(prior, [], [boundaryKey], options);
    await verifyCheckpoint(linked, members, [boundaryKey], { ...options, previousCheckpoint: prior });
    await verifyCheckpoint(linked, members, [boundaryKey], options);
    for (const fields of [{ receipt_id: "other-prior" },
      { context: { ...(prior.context as Record<string, unknown>), merkle_root: "sha256:" + "0".repeat(64) } },
      { issued_at: end, context: emptyContext }]) {
      const invalidPrior = signBoundaryReceipt({ ...prior, ...fields });
      await verifyReceipt(invalidPrior, [boundaryKey], { now });
      await assert.rejects(verifyCheckpoint(linked, members, [boundaryKey],
        { ...options, previousCheckpoint: invalidPrior }), verificationError,
      "a supplied prior checkpoint must have the signed id/root and a non-overlapping period");
    }
    const wrongSignature = Buffer.from(prior.signature, "base64url");
    wrongSignature[0] ^= 1;
    await assert.rejects(verifyCheckpoint(linked, members, [boundaryKey], { ...options,
      previousCheckpoint: { ...prior, signature: wrongSignature.toString("base64url") } }), verificationError,
    "a supplied prior checkpoint signature must verify");
    const actionAsCheckpoint: Record<string, unknown> = { ...emptyCheckpoint, action: "files.read", decision: "allow" };
    delete actionAsCheckpoint.event;
    const signedAction = signBoundaryReceipt(actionAsCheckpoint);
    await verifyReceipt(signedAction, [boundaryKey], { now });
    await assert.rejects(verifyCheckpoint(signedAction, [], [boundaryKey], options), verificationError,
      "an action with checkpoint-shaped context cannot serve as a checkpoint");
    const actionAsPrior = signBoundaryReceipt({ ...actionAsCheckpoint, receipt_id: prior.receipt_id,
      issued_at: start, context: prior.context });
    await verifyReceipt(actionAsPrior, [boundaryKey], { now });
    await assert.rejects(verifyCheckpoint(linked, members, [boundaryKey],
      { ...options, previousCheckpoint: actionAsPrior }), verificationError,
    "an authentic action with matching linkage cannot serve as the prior checkpoint");
    const nestedCheckpoint = signBoundaryReceipt({ ...emptyCheckpoint,
      context: { ...emptyContext, receipt_count: 1, merkle_root: independentRoot([prior]) } });
    await verifyReceipt(nestedCheckpoint, [boundaryKey], { now });
    await assert.rejects(verifyCheckpoint(nestedCheckpoint, [prior], [boundaryKey], options), verificationError,
      "a valid earlier checkpoint inside the current period cannot be a member");
    for (const context of [null, [], 1, "context", { ...emptyContext, period_start: null },
      { ...emptyContext, previous_checkpoint_id: false, previous_merkle_root: emptyRoot }]) {
      const invalidPrior = signBoundaryReceipt({ ...prior, context });
      await assert.rejects(verifyCheckpoint(linked, members, [boundaryKey],
        { ...options, previousCheckpoint: invalidPrior }), verificationError,
      "prior schema validation cannot be hidden by an unauthentic fixture");
    }
    await verifyCheckpoint(emptyCheckpoint, [], [boundaryKey], { expectedWorkspaceId: options.expectedWorkspaceId });
    for (const invalidNow of [null, 0, "2026-04-22T00:00:00.000Z", new Date(Number.NaN)]) {
      await assert.rejects(verifyCheckpoint(emptyCheckpoint, [], [boundaryKey],
        { ...options, now: invalidNow as never }), verificationError, "a supplied clock must be a valid Date");
    }
    const mutableNow = new Date(end);
    const withClockSnapshot = verifyCheckpoint(linked, members, [boundaryKey],
      { ...options, now: mutableNow, previousCheckpoint: prior });
    queueMicrotask(() => mutableNow.setTime(Date.parse(start) - 300_001));
    await withClockSnapshot;
    await assert.rejects(verifyCheckpoint(emptyCheckpoint, [], [new Proxy(boundaryKey, {})], options), verificationError,
      "uncloneable public keys must raise VerificationError");
    for (const invalidKey of [null, undefined, 1, false, "key", { ...boundaryKey, publicKeyBytes: undefined }]) {
      await assert.rejects(verifyCheckpoint(emptyCheckpoint, [], [invalidKey as never, boundaryKey], options),
        verificationError, "invalid public-key entries must raise VerificationError before key selection");
    }
    const sharedArrayDescriptor = Object.getOwnPropertyDescriptor(globalThis, "SharedArrayBuffer")!;
    try {
      Object.defineProperty(globalThis, "SharedArrayBuffer", { ...sharedArrayDescriptor, value: undefined });
      await verifyCheckpoint(emptyCheckpoint, [], [boundaryKey], options);
    } finally {
      Object.defineProperty(globalThis, "SharedArrayBuffer", sharedArrayDescriptor);
    }

    const rotationPair = generateKeyPairSync("ed25519");
    const rotationKey = { ...boundaryKey, keyId: "checkpoint-rotation",
      publicKeyBytes: new Uint8Array(rotationPair.publicKey.export({ type: "spki", format: "der" }).subarray(-32)) };
    const signRotation = (receipt: Record<string, unknown>) => {
      const { signature, ...payload } = receipt;
      payload.key_id = rotationKey.keyId;
      return { ...payload, signature: signBytes(null, Buffer.from(jcsCanonicalize(payload)!),
        rotationPair.privateKey).toString("base64url") };
    };
    const trusted = new Set([boundaryKey, rotationKey].map(key =>
      "sha256:" + createHash("sha256").update(key.publicKeyBytes).digest("hex")));
    const currentPin = new Set(["sha256:" + createHash("sha256").update(boundaryKey.publicKeyBytes).digest("hex")]);
    const rotatedMember = signRotation(members[0]);
    const rotatingCheckpoint = signBoundaryReceipt({ ...emptyCheckpoint, context: { ...emptyContext,
      receipt_count: 1, merkle_root: independentRoot([rotatedMember]) } });
    const rotatedPrior = signRotation(prior);
    for (const [current, receipts, previousCheckpoint] of [
      [rotatingCheckpoint, [rotatedMember], undefined], [linked, members, rotatedPrior],
    ] as const) {
      await verifyCheckpoint(current, [...receipts], [boundaryKey, rotationKey],
        { ...options, previousCheckpoint, trustedKeyFingerprints: trusted });
      await assert.rejects(verifyCheckpoint(current, [...receipts], [boundaryKey, rotationKey],
        { ...options, previousCheckpoint, trustedKeyFingerprints: currentPin }), verificationError,
      "trusted fingerprints apply to members and prior checkpoints as well as the current checkpoint");
    }

    const entry = { key_id: boundaryKey.keyId, alg: "Ed25519", public_key: Buffer.from(boundaryKey.publicKeyBytes).toString("base64url"),
      active_from: "0001-01-01T00:00:00.000Z", active_until: null,
      public_key_fingerprint: "sha256:" + createHash("sha256").update(boundaryKey.publicKeyBytes).digest("hex") };
    const keyDoc = { workspace_id: options.expectedWorkspaceId, keys: [entry] };
    const loaded = loadKeysFromJson(keyDoc);
    assert.deepEqual(loaded[0].publicKeyBytes, boundaryKey.publicKeyBytes);
    assert.equal(publicKeyFingerprint(loaded[0]), entry.public_key_fingerprint);
    await verifyReceipt(signBoundaryReceipt(baseline), loaded, { now });
    for (const doc of [null, undefined, false, 1, "doc", { ...keyDoc, workspace_id: 1 },
      Object.assign(Object.create({ workspace_id: keyDoc.workspace_id }), { keys: keyDoc.keys }),
      Object.assign(() => undefined, keyDoc)]) {
      assert.throws(() => loadKeysFromJson(doc as never), verificationError,
        "key documents require an object with an own string workspace id");
    }
    for (const key of [Object.assign(() => undefined, entry),
      Object.assign(Object.create({ active_until: null }), { ...entry, active_until: undefined })]) {
      if (typeof key !== "function") delete key.active_until;
      assert.throws(() => loadKeysFromJson({ ...keyDoc, keys: [key] } as never), verificationError,
        "key entries require an object and an own active_until field");
    }
    for (const fingerprint of [null, false, 1, [], {}, entry.public_key_fingerprint.toUpperCase()]) {
      assert.throws(() => loadKeysFromJson({ ...keyDoc, keys: [{ ...entry, public_key_fingerprint: fingerprint }] } as never),
        verificationError, "advertised fingerprints must match the independently computed raw-key hash");
    }
    for (const active_from of ["0001-01-01T00:00:00.000Z", "0099-12-31T23:59:59.999Z", "9999-12-31T23:59:59.999Z"]) {
      const parsed = loadKeysFromJson({ ...keyDoc, keys: [{ ...entry, active_from }] });
      assert.equal(parsed[0].activeFrom.toISOString(), active_from);
    }
    for (const field of ["active_from", "active_until"] as const) {
      for (const value of ["0000-01-01T00:00:00.000Z", "2026-02-29T00:00:00.000Z",
        "2026-04-21T24:00:00.000Z", "prefix" + start, start + "suffix", [start]]) {
        assert.throws(() => loadKeysFromJson({ ...keyDoc, keys: [{ ...entry, [field]: value }] } as never), verificationError);
      }
    }
    const signedMember = members[0];
    for (const publicKeyBytes of [undefined, [], Array.from(boundaryKey.publicKeyBytes),
      new Uint8Array(31), new Uint8Array(33), new Uint16Array(32)]) {
      await assert.rejects(verifyReceipt(signedMember, [{ ...boundaryKey, publicKeyBytes: publicKeyBytes as never }], { now }),
        verificationError, "selected keys must have exactly 32 raw Uint8Array bytes");
    }
    for (const activeUntil of [undefined, start, new Date(Number.NaN)]) {
      await assert.rejects(verifyReceipt(signedMember, [{ ...boundaryKey, activeUntil: activeUntil as never }], { now }),
        verificationError, "selected key retirement dates must be a valid Date or null");
    }
    for (const issued_at of [start, new Date(Date.parse(start) + 1).toISOString(), new Date(Date.parse(end) - 1).toISOString()]) {
      await verifyReceipt(signBoundaryReceipt({ ...signedMember, issued_at }), [{ ...boundaryKey,
        activeFrom: new Date(start), activeUntil: new Date(end) }], { now });
    }
    for (const issued_at of [new Date(Date.parse(start) - 1).toISOString(), end]) {
      await assert.rejects(verifyReceipt(signBoundaryReceipt({ ...signedMember, issued_at }), [{ ...boundaryKey,
        activeFrom: new Date(start), activeUntil: new Date(end) }], { now }), verificationError,
      "selected key validity is half-open at the exact millisecond boundaries");
    }
  }
  console.log("  OK    checkpoint/key boundary contracts");

  console.log();
  if (failures) {
    console.log(`${failures} failure(s)`);
    return 1;
  }
  console.log("All vectors pass.");
  return 0;
}

const vectorsPath = process.argv[2];
if (!vectorsPath) {
  console.error("usage: node test_vectors.ts <path-to-test-vectors.json>");
  process.exit(2);
}

main(vectorsPath).then((code) => process.exit(code));
