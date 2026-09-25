import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

type JsonObject = Record<string, any>;

async function main(vectorsPath: string): Promise<void> {
  const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as JsonObject;
  const outputDirectory = mkdtempSync(join(tmpdir(), "allowly-browser-policy-"));
  const verifierOutput = join(outputDirectory, "verifier.mjs");
  const sealOutput = join(outputDirectory, "sealJson.mjs");
  const declarationOutput = join(outputDirectory, "sealJson.d.ts");
  const generator = fileURLToPath(new URL("../scripts/build-browser.py", import.meta.url));
  try {
    const build = spawnSync(
      "python3",
      [generator, verifierOutput, sealOutput, declarationOutput],
      { encoding: "utf8" },
    );
    assert.equal(build.status, 0, `${build.stdout}\n${build.stderr}`);

    const browserVerifier = await import(pathToFileURL(verifierOutput).href) as JsonObject;
    assert.equal(typeof browserVerifier.verifyPolicyEvaluation, "function");
    const keys = await browserVerifier.loadKeysFromJson(vectors.public_keys);
    const opts = {
      expectedWorkspaceId: vectors.expected_workspace_id,
      trustedKeyFingerprints: new Set(vectors.trusted_key_fingerprints),
      now: new Date(vectors.verification_now),
    };

    // A normal non-isolated offline page may not expose SharedArrayBuffer at
    // all. Replay must still work with ordinary ArrayBuffer-backed key bytes.
    const sharedArrayBufferDescriptor = Object.getOwnPropertyDescriptor(
      globalThis,
      "SharedArrayBuffer",
    );
    Object.defineProperty(globalThis, "SharedArrayBuffer", {
      configurable: true,
      value: undefined,
      writable: true,
    });
    try {
      for (const testCase of vectors.verification_cases as JsonObject[]) {
        const actual = await browserVerifier.verifyPolicyEvaluation(
          testCase.receipt,
          testCase.authorization_receipts,
          keys,
          opts,
        );
        assert.deepEqual(actual, testCase.expected, testCase.name);
      }
      for (const testCase of vectors.validation_error_cases as JsonObject[]) {
        await assert.rejects(
          browserVerifier.verifyPolicyEvaluation(
            testCase.receipt,
            testCase.authorization_receipts,
            keys,
            opts,
          ),
          (error: unknown) => error instanceof Error
            && error.name === "VerificationError"
            && error.message.includes(testCase.expected_error),
          testCase.name,
        );
      }
    } finally {
      if (sharedArrayBufferDescriptor === undefined) {
        delete (globalThis as JsonObject).SharedArrayBuffer;
      } else {
        Object.defineProperty(globalThis, "SharedArrayBuffer", sharedArrayBufferDescriptor);
      }
    }
  } finally {
    rmSync(outputDirectory, { recursive: true, force: true });
  }

  console.log("Generated browser policy evaluation vectors passed");
}

const vectorsPath = process.argv[2];
if (!vectorsPath) throw new Error("usage: test_browser_policy_evaluation.js PROFILE_VECTORS");
await main(vectorsPath);
