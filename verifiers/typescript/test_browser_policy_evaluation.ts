import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

const vectors = JSON.parse(readFileSync(process.argv[2], "utf8"));
const output = mkdtempSync(join(tmpdir(), "allowly-browser-wire5-"));
try {
  const verifierOutput = join(output, "verifier.mjs");
  const generator = fileURLToPath(new URL("../scripts/build-browser.py", import.meta.url));
  const build = spawnSync("python3", [generator, verifierOutput, join(output, "sealJson.mjs")], { encoding: "utf8" });
  assert.equal(build.status, 0, `${build.stdout}\n${build.stderr}`);
  const verifier = await import(pathToFileURL(verifierOutput).href);
  const keys = await verifier.loadKeysFromJson(vectors.public_keys);
  const options = { now: new Date(vectors.verification_now), expectedWorkspaceId: vectors.expected_workspace_id,
    trustedKeyFingerprints: new Set(vectors.trusted_key_fingerprints) };
  for (const value of vectors.signature_cases) await verifier.verifyReceipt(value.receipt, keys, options);
  for (const value of vectors.tampered_cases) {
    await assert.rejects(verifier.verifyReceipt(value.receipt, keys, options), /signature verification failed/, value.name);
  }
  assert.equal("verifyPolicyEvaluation" in verifier, false);
  const receiptVectors = JSON.parse(readFileSync(new URL("../../../test-vectors.json", import.meta.url), "utf8"));
  const receiptKeys = await verifier.loadKeysFromJson(receiptVectors.public_keys);
  for (const value of receiptVectors.checkpoint_cases) {
    await verifier.verifyCheckpoint(value.checkpoint, value.receipts, receiptKeys, {
      expectedWorkspaceId: receiptVectors.public_keys.workspace_id,
      previousCheckpoint: value.previous_checkpoint,
      now: new Date("2026-12-31T00:00:00.000Z"),
    });
  }
} finally {
  rmSync(output, { recursive: true, force: true });
}
console.log("Generated browser wire-5 OPA evidence signature vectors passed");
