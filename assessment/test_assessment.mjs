import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { verifyAssessment } from './verify.mjs';
import { verifyReceipt, loadKeysFromJson } from '../verifiers/typescript/dist/verifier.js';

const cases = JSON.parse(readFileSync(new URL('./evidence-vectors.json', import.meta.url), 'utf8')).cases;
for (const test of cases) {
  const call = () => verifyAssessment(test.signed_assessment, test.keys, test.source_snapshot, test.policy_definition, test.mapping_snapshot, { expectedWorkspaceId: test.workspace_id, expectedProjectId: test.project_id, trustedKeyFingerprints: test.fingerprints });
  if (test.valid) {
    const result = await call();
    assert.equal(result.assessment_id, 'asm_fictional', test.name);
    assert.equal(result.mode, 'observe', test.name);
    assert.equal(result.intervention, 'none', test.name);
  } else {
    await assert.rejects(call, undefined, test.name);
  }
}
await assert.rejects(() => verifyReceipt(cases[0].signed_assessment, loadKeysFromJson(cases[0].keys), { expectedWorkspaceId: cases[0].workspace_id, trustedKeyFingerprints: cases[0].fingerprints }));
console.log(`${cases.length} assessment vectors passed; receipt-domain rejection passed`);
