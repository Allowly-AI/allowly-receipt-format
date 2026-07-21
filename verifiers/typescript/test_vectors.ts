/**
 * Run the TypeScript verifier against all test vectors.
 *
 * Usage: node --experimental-strip-types test_vectors.ts ../../test-vectors.json
 *   or after build: node dist/test_vectors.js ../../test-vectors.json
 */
import { readFileSync } from "node:fs";
import { canonicalize, verifyReceipt, loadKeysFromJson, VerificationError } from "./verifier.js";

// Hand-written expected canonical form for the spec §4.3 reference example.
// Deliberately NOT produced by the reference canonicalizer: if canonicalization
// regresses, generated vectors would regress with it and tests would still pass.
const GOLDEN_PAYLOAD = {
  version: "1.1",
  receipt_id: "rcp_01HXZ2B3QW4N5M6P7R8S9T0V1W",
  workspace_id: "ws_01HXA1B2C3D4E5F6G7H8J9K0L1",
  issued_at: "2026-04-21T14:32:17.482Z",
  decision: "allow",
  reason: "authorization_granted_action_active",
  user_id: "emp_8821",
  agent_id: "referral_outreach",
  action: "outreach.send",
  resource: "edge:emp_8821:conn_9f2a",
  context: { session_id: "sess_7f2", origin: "chat", initiated_by: "user" },
  authorization_id: "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
  engine_version: "2026-04-17.1",
  alg: "Ed25519",
  key_id: "projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",
};
const GOLDEN_CANONICAL =
  '{"action":"outreach.send","agent_id":"referral_outreach",' +
  '"alg":"Ed25519",' +
  '"authorization_id":"auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",' +
  '"context":{"initiated_by":"user","origin":"chat","session_id":"sess_7f2"},' +
  '"decision":"allow","engine_version":"2026-04-17.1",' +
  '"issued_at":"2026-04-21T14:32:17.482Z",' +
  '"key_id":"projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",' +
  '"reason":"authorization_granted_action_active",' +
  '"receipt_id":"rcp_01HXZ2B3QW4N5M6P7R8S9T0V1W",' +
  '"resource":"edge:emp_8821:conn_9f2a","user_id":"emp_8821","version":"1.1",' +
  '"workspace_id":"ws_01HXA1B2C3D4E5F6G7H8J9K0L1"}';

async function main(vectorsPath: string): Promise<number> {
  const raw = readFileSync(vectorsPath, "utf-8");
  const vectors = JSON.parse(raw);

  const keys = loadKeysFromJson(vectors.public_keys);
  // All vectors use issued_at in 2026; pin "now" for deterministic timestamp checks.
  const now = new Date("2026-12-31T00:00:00Z");

  let failures = 0;

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
  for (const [name, doc] of [["duplicate_keys", dupDoc], ["missing_keys_array", {}]] as const) {
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
