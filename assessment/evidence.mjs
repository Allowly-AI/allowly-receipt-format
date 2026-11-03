// Pure policy evidence validation. No source provider or rule evaluator.
import { canonicalize } from '../verifiers/typescript/dist/verifier.js';

export const assert = (condition, message) => { if (!condition) throw new Error(message); };
export const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export const equal = (left, right) => Buffer.from(canonicalize(left)).equals(Buffer.from(canonicalize(right)));
export const exact = (value, keys) => assert(object(value) && equal(Object.keys(value).sort(), [...keys].sort()), 'unexpected fields');
const text = (value, limit) => typeof value === 'string' && Array.from(value).length > 0 && Array.from(value).length <= limit && !value.includes('\0');
const kinds = ['string', 'integer', 'boolean', 'null', 'list'];
function names(value, minimum, maximum, limit = 64) {
  assert(Array.isArray(value) && value.length >= minimum && value.length <= maximum && value.every(name => text(name, limit)) && new Set(value).size === value.length, 'invalid unique evidence names');
}
function typed(value, kind) {
  if (kind === 'string') return typeof value === 'string' && !value.includes('\0');
  if (kind === 'integer') return Number.isSafeInteger(value);
  if (kind === 'boolean') return typeof value === 'boolean';
  if (kind === 'null') return value === null;
  return kind === 'list' && Array.isArray(value) && value.length <= 64 && value.every(item => typed(item, item === null ? 'null' : typeof item === 'number' ? 'integer' : typeof item));
}
function fieldsValid(fields) {
  assert(object(fields) && Object.keys(fields).length <= 64 && Object.entries(fields).every(([name, kind]) => text(name, 128) && kinds.includes(kind)), 'invalid policy fields');
}
export function validateEvidence(fields, evidence) {
  fieldsValid(fields);
  assert(object(evidence) && Object.keys(evidence).length > 0 && equal(Object.keys(evidence).sort(), Object.keys(fields).sort()), 'evidence must cover fields exactly');
  for (const [name, item] of Object.entries(evidence)) {
    assert(object(item), 'invalid evidence requirement');
    const keys = Object.keys(item).sort().join(',');
    if (keys === 'instruction,sources') {
      names(item.sources, 1, 8);
      assert(text(item.instruction, 2048) && item.instruction.trim().length > 0, 'invalid instruction');
    } else if (keys === 'empty_sources,source,transform') {
      assert(fields[name] === 'string' && item.transform === 'email_domain' && text(item.source, 64), 'invalid transform');
      names(item.empty_sources, 0, 8);
      assert(!item.empty_sources.includes(item.source), 'source cannot be empty source');
    } else if (keys === 'all_of') {
      names(item.all_of, 1, 16, 128);
      assert(fields[name] === 'boolean' && item.all_of.every(dependency => Object.hasOwn(fields, dependency) && fields[dependency] === 'boolean' && object(evidence[dependency]) && !Object.hasOwn(evidence[dependency], 'all_of')), 'all_of requires direct booleans');
    } else throw new Error('unsupported evidence requirement');
  }
  canonicalize(evidence);
}
const pointer = value => text(value, 256) && value.startsWith('/') && !/~(?![01])/.test(value);
export function validateMapping(mapping) {
  exact(mapping, ['observation_name', 'sources', 'execution_pointer', 'mapping_version']);
  assert(text(mapping.observation_name, 128) && text(mapping.mapping_version, 128) && pointer(mapping.execution_pointer), 'invalid mapping');
  assert(object(mapping.sources) && Object.keys(mapping.sources).length >= 1 && Object.keys(mapping.sources).length <= 32 && Object.entries(mapping.sources).every(([name, path]) => text(name, 64) && pointer(path)), 'invalid mapping sources');
  canonicalize(mapping);
}
const atom = "[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+";
const label = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
const mailbox = new RegExp(`^(${atom}(?:\\.${atom})*)@(${label}(?:\\.${label})+)$`);
export function domainValue(content, requirement) {
  assert(object(content) && object(requirement), 'invalid domain extraction input');
  exact(requirement, ['source', 'transform', 'empty_sources']);
  assert(requirement.transform === 'email_domain' && text(requirement.source, 64), 'invalid domain extraction input');
  names(requirement.empty_sources, 0, 8);
  assert(!requirement.empty_sources.includes(requirement.source), 'source cannot be empty source');
  const source = content[requirement.source];
  if (typeof source !== 'string' || source.length > 254 || requirement.empty_sources.some(name => !Object.hasOwn(content, name) || content[name] !== '')) return null;
  const match = mailbox.exec(source);
  return !match || match[0] !== source || match[1].length > 64 || match[2].length > 253 ? null : match[2].toLowerCase();
}
export function evidenceContext(fields, evidence, content, facts, missing, mapping) {
  validateEvidence(fields, evidence);
  assert(object(content) && Object.keys(content).length <= 32 && Object.entries(content).every(([name, value]) => text(name, 64) && typeof value === 'string' && !value.includes('\0')), 'invalid source content');
  validateMapping(mapping);
  const direct = Object.fromEntries(Object.entries(evidence).filter(([, item]) => !Object.hasOwn(item, 'all_of')));
  const sources = Object.values(direct).flatMap(item => item.sources ?? [item.source, ...item.empty_sources]);
  assert(sources.every(name => Object.hasOwn(mapping.sources, name)) && Object.keys(content).every(name => Object.hasOwn(mapping.sources, name)), 'mapping does not cover evidence');
  exact(facts, Object.keys(direct));
  const absent = Object.keys(direct).filter(name => facts[name] === null);
  assert(Array.isArray(missing) && missing.every(name => typeof name === 'string') && new Set(missing).size === missing.length && equal([...missing].sort(), absent.sort()), 'missing evidence mismatch');
  for (const [name, item] of Object.entries(direct)) {
    const fact = facts[name];
    if (fact === null) continue;
    exact(fact, ['value', 'citations']);
    if (Object.hasOwn(item, 'sources')) assert(item.sources.every(source => Object.hasOwn(content, source)), 'required extraction source unavailable');
    assert(typed(fact.value, fields[name]) && Array.isArray(fact.citations) && fact.citations.length >= 1 && fact.citations.length <= 8, 'invalid typed fact');
    for (const citation of fact.citations) {
      exact(citation, ['field', 'start', 'end', 'quote']);
      assert(typeof citation.field === 'string' && (item.sources ?? [item.source]).includes(citation.field) && Object.hasOwn(content, citation.field), 'unsupported citation source');
      const characters = Array.from(content[citation.field]);
      assert(Number.isSafeInteger(citation.start) && Number.isSafeInteger(citation.end) && citation.start >= 0 && citation.start < citation.end && citation.end <= characters.length && text(citation.quote, 8192) && characters.slice(citation.start, citation.end).join('') === citation.quote, 'unsupported evidence span');
    }
    if (Object.hasOwn(item, 'transform')) {
      const source = content[item.source];
      assert(fact.value === domainValue(content, item) && fact.citations.length === 1 && equal(fact.citations[0], {field: item.source, start: 0, end: Array.from(source).length, quote: source}), 'deterministic fact mismatch');
    }
  }
  canonicalize(facts);
  if (absent.length) return {};
  const context = Object.fromEntries(Object.entries(facts).map(([name, fact]) => [name, fact.value]));
  for (const [name, item] of Object.entries(evidence)) if (Object.hasOwn(item, 'all_of')) Object.defineProperty(context, name, {value: item.all_of.every(dependency => context[dependency]), enumerable: true});
  return context;
}
export function validatePolicyDefinition(definition) {
  exact(definition, ['profile', 'agent_id', 'actions', 'default_expiry_days']);
  assert(definition.profile === 'allowly.policy.v1' && text(definition.agent_id, 128) && (definition.default_expiry_days === null || Number.isSafeInteger(definition.default_expiry_days) && definition.default_expiry_days >= 1 && definition.default_expiry_days <= 3650), 'invalid definition');
  assert(Array.isArray(definition.actions) && definition.actions.length >= 1 && definition.actions.length <= 32, 'invalid actions');
  const actionNames = new Set(), grantsSeen = new Set();
  for (const entry of definition.actions) {
    exact(entry, Object.hasOwn(entry, 'evidence') ? ['policy', 'guards', 'executable_operations', 'evidence'] : ['policy', 'guards', 'executable_operations']);
    const policy = entry.policy;
    exact(policy, ['profile', 'action', 'decision', 'target', 'fields', 'rules']);
    assert(policy.profile === 'allowly.basic.v1' && text(policy.action, 64) && !['allow', 'deny', 'confirm', 'escalate'].includes(policy.action) && !actionNames.has(policy.action), 'invalid action policy');
    actionNames.add(policy.action);
    fieldsValid(policy.fields);
    if (Object.hasOwn(entry, 'evidence')) validateEvidence(policy.fields, entry.evidence);
    assert(Array.isArray(policy.rules) && policy.rules.length <= 32, 'invalid rules');
    for (const choice of [policy, ...policy.rules]) {
      assert(object(choice) && ['allow', 'deny', 'confirm', 'escalate'].includes(choice.decision), 'invalid decision');
      assert(['allow', 'deny'].includes(choice.decision) ? choice.target === null : choice.decision === 'confirm' ? choice.target === 'agent_owner' : text(choice.target, 135) && choice.target.startsWith('member:') && choice.target.slice(7).trim(), 'invalid target');
    }
    const ids = new Set();
    for (const rule of policy.rules) {
      exact(rule, ['id', 'decision', 'target', 'conditions']);
      assert(text(rule.id, 128) && !ids.has(rule.id) && Array.isArray(rule.conditions) && rule.conditions.length >= 1 && rule.conditions.length <= 10, 'invalid rule'); ids.add(rule.id);
      for (const condition of rule.conditions) {
        exact(condition, ['field', 'op', 'value']);
        assert(typeof condition.field === 'string' && Object.hasOwn(policy.fields, condition.field), 'unknown condition field');
        const kind = policy.fields[condition.field], op = condition.op, value = condition.value;
        assert(['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'not_in', 'exists', 'contains_any', 'contains_none', 'empty'].includes(op), 'unknown condition operator');
        const valid = op === 'exists' ? typeof value === 'boolean' : op === 'empty' ? kind === 'list' && typeof value === 'boolean' : ['contains_any', 'contains_none'].includes(op) ? kind === 'list' && typed(value, 'list') && value.length > 0 : ['in', 'not_in'].includes(op) ? kind !== 'list' && Array.isArray(value) && value.length <= 64 && value.every(item => typed(item, kind)) : kind !== 'list' && typed(value, kind) && (!['gt', 'gte', 'lt', 'lte'].includes(op) || kind === 'integer');
        assert(valid, 'invalid condition value');
      }
    }
    assert(object(entry.guards) && Object.keys(entry.guards).every(name => ['resource_pattern', 'allowed_initiators', 'max_per_day'].includes(name)), 'invalid guards');
    if (Object.hasOwn(entry.guards, 'resource_pattern')) assert(text(entry.guards.resource_pattern, 256), 'invalid resource guard');
    if (Object.hasOwn(entry.guards, 'allowed_initiators')) names(entry.guards.allowed_initiators, 1, 128, 128);
    if (Object.hasOwn(entry.guards, 'max_per_day')) assert(Number.isSafeInteger(entry.guards.max_per_day) && entry.guards.max_per_day > 0, 'invalid count guard');
    assert(Array.isArray(entry.executable_operations) && entry.executable_operations.length <= 100, 'invalid grants');
    for (const grant of entry.executable_operations) {
      exact(grant, ['enabled_executable_id', 'provider_id', 'operation_id', 'catalog_revision', 'definition_fingerprint', 'minimum_evidence_mode']);
      assert(['enabled_executable_id', 'provider_id', 'operation_id', 'catalog_revision'].every(name => text(grant[name], 128)) && typeof grant.definition_fingerprint === 'string' && /^sha256:[0-9a-f]{64}$/.test(grant.definition_fingerprint) && ['receipt', 'witnessed'].includes(grant.minimum_evidence_mode), 'invalid executable grant');
      const identity = JSON.stringify([grant.enabled_executable_id, grant.operation_id]); assert(!grantsSeen.has(identity), 'duplicate executable grant'); grantsSeen.add(identity);
    }
  }
  assert(canonicalize(definition).length <= 65536, 'definition too large');
}
