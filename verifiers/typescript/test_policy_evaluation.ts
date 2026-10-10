import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { decodeReceipt, loadKeysFromJson, verifyReceipt, VerificationError } from "./verifier.js";

const vectors = JSON.parse(readFileSync(process.argv[2], "utf8"));
const keys = loadKeysFromJson(vectors.public_keys);
const options = { now: new Date(vectors.verification_now),
  expectedWorkspaceId: vectors.expected_workspace_id,
  trustedKeyFingerprints: new Set<string>(vectors.trusted_key_fingerprints) };
for (const value of vectors.signature_cases) {
  await verifyReceipt(value.receipt, keys, options);
}
for (const value of vectors.tampered_cases) {
  await assert.rejects(verifyReceipt(value.receipt, keys, options),
    (error: unknown) => error instanceof VerificationError && error.message.includes("signature verification failed"), value.name);
}
const separation = decodeReceipt(vectors.signature_cases.find((value: { name: string }) => value.name === "opa_allow_final_deny").receipt);
assert.equal(separation.decision, "deny");
assert.ok(separation.policy_eval);
assert.equal(separation.policy_eval.result.decision, "allow");
// This package authenticates recorded OPA evidence. Native OPA replay has its own CLI.
const exports = await import("./verifier.js");
assert.equal("verifyPolicyEvaluation" in exports, false);
console.log("Wire-5 OPA evidence signature vectors passed");
