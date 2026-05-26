/**
 * Run the TypeScript verifier against all test vectors.
 *
 * Usage: node --experimental-strip-types test_vectors.ts ../../test-vectors.json
 *   or after build: node dist/test_vectors.js ../../test-vectors.json
 */
import { readFileSync } from "node:fs";
import { verifyReceipt, loadKeysFromJson, VerificationError } from "./verifier.js";

async function main(vectorsPath: string): Promise<number> {
  const raw = readFileSync(vectorsPath, "utf-8");
  const vectors = JSON.parse(raw);

  const keys = loadKeysFromJson(vectors.public_keys);
  // All vectors use issued_at in 2026; pin "now" for deterministic timestamp checks.
  const now = new Date("2026-12-31T00:00:00Z");

  let failures = 0;

  console.log(`Testing ${vectors.should_verify.length} should_verify vectors...`);
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
