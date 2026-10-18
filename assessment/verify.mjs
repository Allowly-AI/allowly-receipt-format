// Source-distributed Observe verifier. Existing wire-5 package exports stay unchanged.
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { canonicalize, loadKeysFromJson, publicKeyFingerprint } from '../verifiers/typescript/dist/verifier.js';
import { assert, object, exact, equal, evidenceContext, validatePolicyDefinition } from './evidence.mjs';

const fields = 'schema_version assessment_id workspace_id job_id project_id agent_id action issued_at policy_ref mapping_version mapping_sha256 reviewer_version engine_version source source_sha256 request_sha256 facts missing_information context policy_eval assessment_status application_reported_execution mode intervention'.split(' ');
const hex = /^[0-9a-f]{64}$/;
const text = new TextDecoder('utf-8', { fatal: true });
const digest = async value => Buffer.from(await webcrypto.subtle.digest('SHA-256', canonicalize(value))).toString('hex');
function timestamp(value) {
  assert(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value), 'invalid timestamp');
  const milliseconds = Date.parse(value);
  assert(Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value, 'invalid timestamp');
  return milliseconds;
}
function b64(value) {
  assert(typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value), 'invalid base64url');
  const bytes = Buffer.from(value, 'base64url');
  assert(bytes.toString('base64url') === value, 'noncanonical base64url');
  return bytes;
}
function json(value) {
  const raw = b64(value), parsed = JSON.parse(text.decode(raw));
  assert(raw.equals(Buffer.from(canonicalize(parsed))), 'noncanonical or duplicate JSON');
  return parsed;
}
export async function validatePayload(payload, source, definition, mapping) {
  exact(payload, fields);
  for (const field of ['assessment_id', 'workspace_id', 'job_id', 'project_id', 'agent_id', 'action', 'reviewer_version', 'mapping_version']) assert(typeof payload[field] === 'string' && Array.from(payload[field]).length > 0 && Array.from(payload[field]).length <= 512, 'invalid identifier');
  assert(payload.schema_version === 'allowly.assessment.v1', 'unsupported assessment');
  assert(payload.mode === 'observe' && payload.intervention === 'none', 'invalid Observe mode');
  assert(['sent', 'accepted', 'failed', 'unknown'].includes(payload.application_reported_execution), 'invalid reported execution');
  assert(timestamp(payload.issued_at) <= Date.now() + 300000, 'future assessment');
  for (const field of ['source_sha256', 'request_sha256', 'mapping_sha256']) assert(typeof payload[field] === 'string' && hex.test(payload[field]), 'invalid digest');
  assert(typeof payload.engine_version === 'string' && /^sha256:[0-9a-f]{64}$/.test(payload.engine_version), 'invalid engine digest');
  const ref = payload.policy_ref;
  exact(ref, ['policy_id', 'policy_version', 'definition_sha256']);
  assert(typeof ref.policy_id === 'string' && ref.policy_id.length > 0 && Number.isSafeInteger(ref.policy_version) && ref.policy_version > 0 && typeof ref.definition_sha256 === 'string' && hex.test(ref.definition_sha256), 'invalid policy reference');
  validatePolicyDefinition(definition);
  assert(await digest(definition) === ref.definition_sha256 && definition.agent_id === payload.agent_id, 'policy binding mismatch');
  const selected = definition.actions.filter(entry => entry.policy.action === payload.action);
  assert(selected.length === 1, 'selected action missing');
  const entry = selected[0], policy = entry.policy;
  assert(Object.hasOwn(entry, 'evidence') && equal(entry.guards, {}) && equal(entry.executable_operations, []) && [policy, ...policy.rules].every(choice => ['allow', 'deny'].includes(choice.decision)), 'unsupported Observe policy');
  assert(await digest(mapping) === payload.mapping_sha256 && mapping.mapping_version === payload.mapping_version, 'mapping binding mismatch');
  exact(source, ['project_id', 'trace_id', 'observation_id', 'observed_at', 'captured_at', 'content']);
  const {content, ...metadata} = source;
  assert(equal(payload.source, metadata) && source.project_id === payload.project_id, 'source binding mismatch');
  for (const field of ['project_id', 'trace_id', 'observation_id']) assert(typeof source[field] === 'string' && Array.from(source[field]).length > 0 && Array.from(source[field]).length <= 512, 'invalid source id');
  assert(timestamp(source.observed_at) <= timestamp(source.captured_at) + 300000 && timestamp(source.captured_at) <= Date.now() + 300000, 'invalid source time');
  assert(canonicalize(source).length <= 65536 && await digest(source) === payload.source_sha256, 'source digest or size mismatch');
  const context = evidenceContext(policy.fields, entry.evidence, content, payload.facts, payload.missing_information, mapping);
  assert(equal(payload.context, context), 'incorrect derived context');
  const requestFields = ['job_id', 'project_id', 'agent_id', 'action', 'policy_ref', 'mapping_version', 'reviewer_version', 'source_sha256', 'facts', 'missing_information', 'application_reported_execution', 'mapping_sha256'];
  const request = {...Object.fromEntries(requestFields.map(name => [name, payload[name]])), source_snapshot: source, mapping_snapshot: mapping};
  assert(canonicalize(request).length <= 65536 && await digest(request) === payload.request_sha256, 'request commitment mismatch');
  if (payload.missing_information.length) {
    assert(payload.policy_eval === null && payload.assessment_status === 'insufficient_evidence', 'missing evidence cannot become a result');
  } else {
    const evaluation = payload.policy_eval;
    exact(evaluation, ['input_sha256', 'result']);
    assert(evaluation.input_sha256 === await digest({policy, action: payload.action, context}), 'OPA input commitment mismatch');
    const result = evaluation.result;
    exact(result, ['profile', 'status', 'decision', 'target', 'matched_rule_id', 'evaluated_fields']);
    assert(result.profile === 'allowly.basic.v1' && result.status === 'ok' && ['allow', 'deny'].includes(result.decision) && result.target === null, 'invalid OPA result');
    assert(result.matched_rule_id === null || typeof result.matched_rule_id === 'string' && Array.from(result.matched_rule_id).length > 0 && Array.from(result.matched_rule_id).length <= 128, 'invalid matched rule');
    const rules = policy.rules.filter(rule => rule.id === result.matched_rule_id);
    assert(result.matched_rule_id === null || rules.length === 1, 'unknown matched rule');
    const choice = rules[0] ?? policy;
    const expectedFields = Object.fromEntries((choice.conditions ?? []).map(condition => [condition.field, context[condition.field]]));
    assert(result.decision === choice.decision && equal(result.evaluated_fields, expectedFields), 'inconsistent OPA explanation');
    assert(payload.assessment_status === (result.decision === 'deny' ? 'violation_detected' : 'no_violation_found'), 'result/status mismatch');
  }
  return payload;
}

export async function verifyAssessment(envelope, keysDocument, sourceSnapshot, policyDefinition, mappingSnapshot, { expectedWorkspaceId, expectedProjectId, trustedKeyFingerprints }) {
  exact(envelope, ['protected', 'payload', 'signature']);
  assert(canonicalize(envelope).length <= 350000, 'assessment too large');
  const header = json(envelope.protected), payload = json(envelope.payload);
  exact(header, ['alg', 'kid', 'typ']);
  assert(header.alg === 'EdDSA' && header.typ === 'allowly-assessment+jws' && typeof header.kid === 'string' && header.kid.length > 0, 'invalid assessment JWS header');
  assert(typeof expectedWorkspaceId === 'string' && expectedWorkspaceId.length > 0 && typeof expectedProjectId === 'string' && expectedProjectId.length > 0, 'caller trust context required');
  assert(payload.workspace_id === expectedWorkspaceId && keysDocument.workspace_id === expectedWorkspaceId && payload.project_id === expectedProjectId, 'workspace/project mismatch');
  assert(Array.isArray(trustedKeyFingerprints) && trustedKeyFingerprints.length > 0 && trustedKeyFingerprints.every(value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value)), 'caller trusted fingerprints required');
  const key = loadKeysFromJson(keysDocument).find(key => key.keyId === header.kid);
  assert(key && trustedKeyFingerprints.includes(publicKeyFingerprint(key)), 'untrusted assessment key');
  const issued = timestamp(payload.issued_at);
  assert(issued >= key.activeFrom.getTime() && (!key.activeUntil || issued < key.activeUntil.getTime()), 'key outside active window');
  const signature = b64(envelope.signature);
  assert(signature.length === 64, 'invalid signature length');
  const publicKey = await webcrypto.subtle.importKey('raw', key.publicKeyBytes, 'Ed25519', false, ['verify']);
  assert(await webcrypto.subtle.verify('Ed25519', publicKey, signature, new TextEncoder().encode(envelope.protected + '.' + envelope.payload)), 'signature mismatch');
  return validatePayload(payload, sourceSnapshot, policyDefinition, mappingSnapshot);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [bundlePath, keysPath, workspaceId, projectId, ...fingerprints] = process.argv.slice(2);
  try {
    const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
    const keys = JSON.parse(readFileSync(keysPath, 'utf8'));
    const payload = await verifyAssessment(bundle.signed_assessment, keys, bundle.source_snapshot, bundle.policy_definition, bundle.mapping_snapshot, { expectedWorkspaceId: workspaceId, expectedProjectId: projectId, trustedKeyFingerprints: fingerprints });
    console.log(`Verified recorded assessment ${payload.assessment_id}: ${payload.assessment_status}`);
  } catch {
    console.error('Assessment verification failed');
    process.exitCode = 1;
  }
}
