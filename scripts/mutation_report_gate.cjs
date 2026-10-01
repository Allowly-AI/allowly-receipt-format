#!/usr/bin/env node
"use strict";

// Read-only gate: node scripts/mutation_report_gate.cjs <Stryker JSON report>.
// Only schema 1.0 and the exact checked-out verifier.ts are supported.
const fs = require("node:fs");
const path = require("node:path");
const { createHash } = require("node:crypto");
const ts = require("../verifiers/typescript/node_modules/typescript");
const REPO_ROOT = path.resolve(__dirname, "..");
const SOURCE_PATH = path.join(REPO_ROOT, "verifiers/typescript/verifier.ts");
const TIMEOUT_PROOF_PATH = path.join(__dirname, "mutation_timeout_proofs.json");
// Exact ordered inputs of the reviewed runtime proof. The context hash binds
// these names and their contents; no report/manifest/CLI path list is accepted.
const TIMEOUT_CONTEXT_PATHS = Object.freeze([
  "verifiers/typescript/verifier.ts",
  "verifiers/typescript/test_vectors.ts",
  "verifiers/typescript/test_policy_evaluation.ts",
  "verifiers/typescript/test_pseudonym_refs.ts",
  "verifiers/typescript/test_seal.ts",
  "test-vectors.json",
  "vectors/policy/profile-v1.json",
  "vectors/seal/profile-v1.json",
  "vectors/seal/verification-v1.json",
  "verifiers/typescript/package.json",
  "verifiers/typescript/package-lock.json",
  "verifiers/typescript/tsconfig.json",
  "verifiers/typescript/scripts/copy-seal-vectors.mjs",
  "verifiers/typescript/stryker.conf.cjs",
]);
const STATUSES = ["Killed", "Survived", "Timeout", "NoCoverage", "RuntimeError", "CompileError", "Ignored", "Pending"];

// Reviewed verifier.ts at 4cdf6d6: replace only the 64 direct sole plain
// VerificationError message literals with this marker, then hash ALL bytes.
// Any other source edit invalidates both exemption proofs; never auto-refresh.
const MESSAGE_MARKER = '"__ALLOWLY_COSMETIC_ERROR_MESSAGE__"';
const VERIFIER_EVIDENCE_SHA256 = "943300d14b6968aa0fc0112ae3433560c65bb69c5d541db037ad896ebbfbe469";
const hash = (text) => createHash("sha256").update(text).digest("hex");
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
function requireThat(condition, message) {
  if (!condition) throw new Error(message);
}
function onlyKeys(value, allowed, label) {
  requireThat(object(value), `${label} must be an object`);
  requireThat(Object.keys(value).every((key) => allowed.includes(key)), `${label} has unknown fields`);
}
function walk(node, visit) {
  visit(node);
  ts.forEachChild(node, (child) => walk(child, visit));
}
function parse(source) {
  requireThat(typeof source === "string" && source.length > 0, "Trusted verifier source is missing or empty");
  const ast = ts.createSourceFile("verifier.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  requireThat(ast.parseDiagnostics.length === 0, "Verifier source has syntax errors");
  return ast;
}
function evidence(ast) {
  const cosmeticRanges = new Set();
  const messages = [];
  walk(ast, (node) => {
    const start = node.getStart(ast);
    const key = `${start}:${node.end}`;
    if (cosmeticMessage(node)) {
      cosmeticRanges.add(key);
      messages.push({ start, end: node.end });
    }
  });
  let normalized = ast.text;
  for (const { start, end } of messages.sort((a, b) => b.start - a.start)) {
    normalized = normalized.slice(0, start) + MESSAGE_MARKER + normalized.slice(end);
  }
  const normalizedSourceSha256 = hash(normalized);
  const compare = ast.statements.find((node) => ts.isFunctionDeclaration(node) && node.name?.text === "compareBytes");
  const expression = compare?.body?.statements.at(-1)?.expression;
  const comparisonRange = expression ? `${expression.getStart(ast)}:${expression.end}` : null;
  return { cosmeticRanges, comparisonRange, normalizedSourceSha256,
    trusted: normalizedSourceSha256 === VERIFIER_EVIDENCE_SHA256 };
}
function offset(position, ast) {
  onlyKeys(position, ["line", "column"], "Mutation position");
  const starts = ast.getLineStarts();
  requireThat(Number.isSafeInteger(position.line) && position.line >= 1 && position.line <= starts.length
    && Number.isSafeInteger(position.column) && position.column >= 1, "Invalid mutation position");
  const begin = starts[position.line - 1];
  let end = starts[position.line] ?? ast.text.length;
  while (end > begin && /[\r\n\u2028\u2029]/.test(ast.text[end - 1])) end--;
  requireThat(position.column - 1 <= end - begin, "Mutation column is outside its source line");
  return begin + position.column - 1;
}
function validateMutant(mutant, ast, ids) {
  onlyKeys(mutant, ["id", "mutatorName", "replacement", "status", "location", "statusReason", "testsCompleted", "killedBy", "coveredBy", "duration", "static", "description"], "Mutant");
  requireThat(typeof mutant.id === "string" && mutant.id.length > 0 && !ids.has(mutant.id), "Missing or duplicate mutant ID");
  ids.add(mutant.id);
  requireThat(typeof mutant.mutatorName === "string" && mutant.mutatorName.length > 0 && typeof mutant.replacement === "string", `Mutant ${mutant.id} lacks mutation evidence`);
  requireThat(STATUSES.includes(mutant.status), `Mutant ${mutant.id} has unknown status: ${mutant.status}`);
  onlyKeys(mutant.location, ["start", "end"], "Mutation location");
  const start = offset(mutant.location.start, ast);
  const end = offset(mutant.location.end, ast);
  requireThat(start < end, `Mutant ${mutant.id} has an empty or reversed range`);
  requireThat(mutant.replacement !== ast.text.slice(start, end), `Mutant ${mutant.id} does not change the source`);
  for (const key of ["statusReason", "description"]) if (key in mutant) requireThat(typeof mutant[key] === "string", `Invalid ${key}`);
  for (const key of ["testsCompleted", "duration"]) if (key in mutant) requireThat(Number.isFinite(mutant[key]) && mutant[key] >= 0, `Invalid ${key}`);
  for (const key of ["killedBy", "coveredBy"]) if (key in mutant) requireThat(Array.isArray(mutant[key]) && mutant[key].every((id) => typeof id === "string"), `Invalid ${key}`);
  if ("static" in mutant) requireThat(typeof mutant.static === "boolean", "Invalid static flag");
  return { start, end };
}
function plainLiteral(node) {
  return ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node);
}
function cosmeticMessage(node) {
  const constructor = node.parent;
  return plainLiteral(node) && constructor && ts.isNewExpression(constructor)
    && ts.isIdentifier(constructor.expression) && constructor.expression.text === "VerificationError"
    && constructor.arguments?.length === 1 && constructor.arguments[0] === node
    && ts.isThrowStatement(constructor.parent) && constructor.parent.expression === constructor;
}
function literalReplacement(replacement) {
  const ast = ts.createSourceFile("replacement.ts", replacement, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const statement = ast.statements[0];
  return ast.parseDiagnostics.length === 0 && ast.statements.length === 1 && statement
    && ts.isExpressionStatement(statement) && plainLiteral(statement.expression)
    && statement.expression.getStart(ast) === 0 && statement.expression.end === replacement.length;
}
function exemption(mutant, range, ast, proof) {
  if (!proof.trusted) return null;
  const rangeKey = `${range.start}:${range.end}`;
  if (mutant.mutatorName === "StringLiteral" && proof.cosmeticRanges.has(rangeKey) && literalReplacement(mutant.replacement)) {
    return { classification: "cosmetic", reason: "Only the direct sole plain-text argument of throw new VerificationError changes; exception class and control flow remain unchanged." };
  }
  if (mutant.mutatorName === "ArithmeticOperator"
    && rangeKey === proof.comparisonRange && ast.text.slice(range.start, range.end) === "left.length - right.length"
    && mutant.replacement === "left.length + right.length") {
    return { classification: "equivalent", reason: "Pinned compareBytes/sha256/checkpointMerkleRoot and sole level.sort(compareBytes) reference: inputs are 32-byte SHA-256 digests. The final return is reached only for equal bytes; 0 -> 64 can only reorder identical digests, leaving Merkle bytes/root unchanged." };
  }
  return null;
}

function timeoutKey(mutant) {
  const { start, end } = mutant.location;
  return JSON.stringify([mutant.mutatorName, start.line, start.column, end.line, end.column, mutant.replacement]);
}
// Pure proof validation for synthetic fixtures. Production callers must obtain
// both the manifest and current fingerprint from the fixed live files below.
function verifiedTimeouts(manifest, verificationContextSha256, ast) {
  const entries = new Map();
  if (manifest === null) return entries;
  onlyKeys(manifest, ["verificationContextSha256", "verifierSourceSha256", "entries"], "Timeout proof manifest");
  requireThat([manifest.verificationContextSha256, manifest.verifierSourceSha256].every((value) =>
    typeof value === "string" && /^[0-9a-f]{64}$/.test(value)), "Invalid timeout proof fingerprints");
  requireThat(Array.isArray(manifest.entries), "Timeout proofs must be individually recorded entries");
  if (manifest.verificationContextSha256 !== verificationContextSha256 || manifest.verifierSourceSha256 !== hash(ast.text)) return entries;
  for (const entry of manifest.entries) {
    onlyKeys(entry, ["mutatorName", "location", "replacement", "reason"], "Timeout proof entry");
    requireThat(typeof entry.reason === "string" && entry.reason.trim().length > 0, "Timeout proof lacks an individual reason");
    validateMutant({ id: "proof", mutatorName: entry.mutatorName, location: entry.location,
      replacement: entry.replacement, status: "Timeout" }, ast, new Set());
    const key = timeoutKey(entry);
    requireThat(!entries.has(key), "Duplicate timeout proof entry");
    entries.set(key, entry.reason);
  }
  return entries;
}
function liveTimeoutEvidence() {
  let manifest;
  try {
    manifest = JSON.parse(fs.readFileSync(TIMEOUT_PROOF_PATH, "utf8"));
  } catch (error) {
    if (error.code === "ENOENT") return { manifest: null, verificationContextSha256: null };
    throw error;
  }
  const verificationContextSha256 = hash(JSON.stringify(TIMEOUT_CONTEXT_PATHS.map((name) =>
    [name, fs.readFileSync(path.join(REPO_ROOT, name), "utf8")])));
  return { manifest, verificationContextSha256 };
}

function classifyReport(report, trustedSource, timeoutEvidence = { manifest: null, verificationContextSha256: null }) {
  onlyKeys(report, ["schemaVersion", "files", "thresholds", "testFiles", "projectRoot", "config", "framework", "system", "performance"], "Report");
  requireThat(report.schemaVersion === "1.0", "Unsupported report schema; expected 1.0");
  onlyKeys(report.thresholds, ["high", "low", "break"], "Report thresholds");
  const thresholds = [report.thresholds.high, report.thresholds.low];
  if ("break" in report.thresholds) thresholds.push(report.thresholds.break);
  requireThat(thresholds.every((n) => Number.isSafeInteger(n) && n >= 0 && n <= 100), "Invalid report thresholds");
  for (const key of ["testFiles", "config", "framework", "system", "performance"]) if (key in report) requireThat(object(report[key]), `Invalid report ${key}`);
  if ("projectRoot" in report) requireThat(typeof report.projectRoot === "string", "Invalid report projectRoot");
  onlyKeys(report.files, ["verifier.ts"], "Report files");
  requireThat(Object.keys(report.files).length === 1, "Report must contain only verifier.ts");
  const file = report.files["verifier.ts"];
  onlyKeys(file, ["language", "source", "mutants"], "Verifier report");
  requireThat(file.language === "typescript", "Expected TypeScript report");
  requireThat(typeof file.source === "string" && file.source.length > 0 && file.source === trustedSource, "Report source does not exactly match checked-out verifier.ts");
  requireThat(Array.isArray(file.mutants) && file.mutants.length > 0, "Report has no mutants");
  const ast = parse(trustedSource);
  const proof = evidence(ast);
  const timeouts = verifiedTimeouts(timeoutEvidence.manifest, timeoutEvidence.verificationContextSha256, ast);
  const counts = Object.fromEntries(STATUSES.map((status) => [status, 0]));
  Object.assign(counts, { cosmetic: 0, equivalent: 0, unclassifiedSurvived: 0 });
  const exclusions = [];
  const detectedFaults = [];
  const blockers = [];
  const ids = new Set();
  for (const mutant of file.mutants) {
    const range = validateMutant(mutant, ast, ids);
    counts[mutant.status]++;
    if (mutant.status === "Killed") continue;
    const record = { id: mutant.id, location: mutant.location, mutatorName: mutant.mutatorName, status: mutant.status };
    const timeoutReason = mutant.status === "Timeout" ? timeouts.get(timeoutKey(mutant)) : null;
    if (timeoutReason) {
      detectedFaults.push({ ...record, reason: timeoutReason });
      continue;
    }
    // Unproven/resource timeouts never become cosmetic/equivalent successes.
    const allowed = mutant.status === "Survived" ? exemption(mutant, range, ast, proof) : null;
    if (allowed) {
      counts[allowed.classification]++;
      exclusions.push({ ...record, ...allowed });
    } else {
      if (mutant.status === "Survived") counts.unclassifiedSurvived++;
      blockers.push({ ...record, reason: mutant.status === "Survived" ? "No individually proven cosmetic/equivalent exemption" : `${mutant.status} is unresolved and blocks the gate` });
    }
  }
  counts.detectedTimeout = detectedFaults.length;
  return { pass: blockers.length === 0, file: "verifier.ts", sourceSha256: hash(trustedSource),
    normalizedSourceSha256: proof.normalizedSourceSha256, evidenceSourceMatched: proof.trusted,
    total: file.mutants.length, counts, exclusions, detectedFaults, blockers };
}

if (require.main === module) {
  try {
    requireThat(process.argv.length === 3, "Usage: node scripts/mutation_report_gate.cjs <Stryker JSON report>");
    const source = fs.readFileSync(SOURCE_PATH, "utf8");
    const result = classifyReport(JSON.parse(fs.readFileSync(process.argv[2], "utf8")), source, liveTimeoutEvidence());
    console.log(JSON.stringify(result, null, 2));
    process.exitCode = result.pass ? 0 : 1;
  } catch (error) {
    console.error(`Mutation report gate refused: ${error.message}`);
    process.exitCode = 2;
  }
}
module.exports = { classifyReport, TIMEOUT_CONTEXT_PATHS };
