/**
 * Run the TypeScript verifier against all test vectors.
 *
 * Usage: node --experimental-strip-types test_vectors.ts ../../test-vectors.json
 *   or after build: node dist/test_vectors.js ../../test-vectors.json
 */
import { readFileSync } from "node:fs";
import { generateKeyPairSync, sign as signBytes } from "node:crypto";
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
