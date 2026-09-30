"use strict";

// Synthetic reports only. No verifier code or mutation runner is executed.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const ts = require("../verifiers/typescript/node_modules/typescript");
const { classifyReport } = require("./mutation_report_gate.cjs");
const source = fs.readFileSync(path.join(__dirname, "../verifiers/typescript/verifier.ts"), "utf8");
const MESSAGE = '"receipt must be an object"';
const ORIGINAL_RETURN = "left.length - right.length";
let nextId = 0;

function mutant(text = MESSAGE, changes = {}, original = source) {
  const start = original.indexOf(text);
  assert.notEqual(start, -1, `Fixture source lacks ${text}`);
  const ast = ts.createSourceFile("verifier.ts", original, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const position = (offset) => {
    const { line, character } = ast.getLineAndCharacterOfPosition(offset);
    return { line: line + 1, column: character + 1 };
  };
  return { id: String(nextId++), mutatorName: "StringLiteral", replacement: '""', status: "Survived",
    location: { start: position(start), end: position(start + text.length) }, ...changes };
}
function report(mutants, original = source) {
  return { schemaVersion: "1.0", thresholds: { high: 100, low: 100 }, files: {
    "verifier.ts": { language: "typescript", source: original, mutants },
  } };
}
const equivalent = (original = source) => mutant(ORIGINAL_RETURN,
  { mutatorName: "ArithmeticOperator", replacement: "left.length + right.length" }, original);
const classify = (mutants, original = source) => classifyReport(report(mutants, original), original);

test("plain direct VerificationError text is cosmetic; ID/location/reason are recorded", () => {
  const m = mutant();
  const result = classify([m]);
  assert.equal(result.pass, true);
  assert.equal(result.counts.Survived, 1);
  assert.equal(result.counts.cosmetic, 1);
  assert.equal(result.counts.unclassifiedSurvived, 0);
  assert.deepEqual(result.exclusions[0], { id: m.id, location: m.location, mutatorName: "StringLiteral", status: "Survived",
    classification: "cosmetic", reason: "Only the direct sole plain-text argument of throw new VerificationError changes; exception class and control flow remain unchanged." });
});

test("the exact proven Merkle comparison is equivalent, with its equal-content proof", () => {
  const m = equivalent();
  const result = classify([m]);
  assert.equal(result.pass, true);
  assert.equal(result.counts.equivalent, 1);
  assert.equal(result.counts.cosmetic, 0);
  assert.equal(result.exclusions[0].id, m.id);
  assert.deepEqual(result.exclusions[0].location, m.location);
  assert.match(result.exclusions[0].reason, /only for equal bytes.*identical digests.*Merkle bytes\/root unchanged/);
});

test("a plain non-interpolated template changes text only; its timeout still blocks", () => {
  const changed = source.replace(MESSAGE, '`receipt must be an object`');
  const m = mutant('`receipt must be an object`', { replacement: '``' }, changed);
  assert.equal(classify([m], changed).pass, true);
  assert.equal(classify([{ ...m, status: "Timeout" }], changed).pass, false);
});

test("the actual Stryker 1.0 report shape accepts a validated break threshold without relaxing the gate", () => {
  const mutants = [mutant(MESSAGE, { status: "Killed" }), mutant(), equivalent()]
    .map((m) => ({ ...m, statusReason: "fixture result", testsCompleted: 1, killedBy: m.status === "Killed" ? ["0"] : [] }));
  const realShape = { files: report(mutants).files, schemaVersion: "1.0", thresholds: { break: 100, high: 80, low: 60 },
    testFiles: {}, projectRoot: ".", config: {}, framework: { name: "StrykerJS", version: "10.0.0" } };
  const result = classifyReport(realShape, source);
  assert.equal(result.pass, true);
  assert.equal(result.total, 3);
  assert.equal(result.counts.Killed, 1);
  assert.equal(result.counts.cosmetic, 1);
  assert.equal(result.counts.equivalent, 1);
  for (const value of [-1, 101, NaN, Infinity, "100", null, undefined, 1.5]) {
    assert.throws(() => classifyReport({ ...realShape, thresholds: { ...realShape.thresholds, break: value } }, source), /Invalid report thresholds/);
  }
  const behavioral = { ...realShape, thresholds: { ...realShape.thresholds, break: 0 }, files: report([mutant('"not_checked"')]).files };
  assert.equal(classifyReport(behavioral, source).pass, false);
});

test("semantic status, diagnostic, operator, profile, and regex mutations block", () => {
  for (const text of ['"not_checked"', '"unsupported_authorization_snapshot"', '"eq"',
    '"allowly-conditional-evaluation-v1"', '"receipt_verification_failed"', '/^[A-Za-z0-9_-]*$/']) {
    const result = classify([mutant(text)]);
    assert.equal(result.pass, false, text);
    assert.equal(result.counts.unclassifiedSurvived, 1, text);
    assert.equal(result.exclusions.length, 0, text);
  }
});

test("removed guards and renamed exception constructors cannot become cosmetic", () => {
  for (const m of [
    mutant("!B64URL_RE.test(s)", { mutatorName: "ConditionalExpression", replacement: "false" }),
    mutant(`throw new VerificationError(${MESSAGE});`, { replacement: `throw new Error(${MESSAGE});` }),
    mutant(MESSAGE, { mutatorName: "UnknownMutation" }),
    mutant(MESSAGE, { mutatorName: "BlockStatement" }),
  ]) {
    assert.equal(classify([m]).pass, false);
  }
});

test("replacement injection, interpolation, and nonliteral argument changes block", () => {
  for (const replacement of ['"", undefined', 'makeMessage()', '`message ${run()}`',
    '"message"; throw new Error("different");', '"message" /* added code */']) {
    assert.equal(classify([mutant(MESSAGE, { replacement })]).pass, false, replacement);
  }
  const template = '`non-canonical base64url: ${JSON.stringify(s)}`';
  assert.equal(classify([mutant(template, { replacement: '``' })]).pass, false);
});

test("a literal within another argument expression or a multi-argument constructor blocks", () => {
  for (const argument of [`${MESSAGE} + "suffix"`, `${MESSAGE}, { cause: "detail" }`]) {
    const changed = source.replace(`VerificationError(${MESSAGE})`, `VerificationError(${argument})`);
    assert.equal(classify([mutant(MESSAGE, {}, changed)], changed).pass, false);
  }
});

test("changed VerificationError semantics, shadowing, or base Error binding blocks", () => {
  for (const changed of [
    source.replace("super(message);", 'super(message === "" ? "accepted" : message);'),
    source + '\nfunction shadow(VerificationError: any) { throw new VerificationError("test"); }\n',
    source + '\nclass Error { constructor(message: string) {} }\n',
  ]) assert.equal(classify([mutant(MESSAGE, {}, changed)], changed).pass, false);
});

test("new message observers, crypto writes, and unrelated meaningful code invalidate BOTH exemptions", () => {
  for (const changed of [
    source.replace("if (error instanceof VerificationError) {", 'if (error instanceof VerificationError && error.message === "") {'),
    source + '\nglobalThis.crypto.subtle.digest = async () => new ArrayBuffer(1);\n',
    source.replace("const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;", "const MAX_FUTURE_SKEW_MS = 6 * 60 * 1000;"),
    source.replace('this.name = "VerificationError";', 'this.name = "ChangedError";'),
  ]) {
    const result = classify([mutant(MESSAGE, {}, changed), equivalent(changed)], changed);
    assert.equal(result.pass, false);
    assert.equal(result.evidenceSourceMatched, false);
    assert.equal(result.counts.cosmetic, 0);
    assert.equal(result.counts.equivalent, 0);
    assert.equal(result.counts.unclassifiedSurvived, 2);
    assert.equal(result.exclusions.length, 0);
  }
});

test("only direct sole plain error message text is normalized; edited text preserves both proofs", () => {
  const changedMessage = '"new plain error message"';
  const changed = source.replace(MESSAGE, changedMessage);
  const result = classify([mutant(changedMessage, {}, changed), equivalent(changed)], changed);
  const baseline = classify([mutant(), equivalent()]);
  assert.equal(result.pass, true);
  assert.equal(result.evidenceSourceMatched, true);
  assert.equal(result.normalizedSourceSha256, "943300d14b6968aa0fc0112ae3433560c65bb69c5d541db037ad896ebbfbe469");
  assert.equal(result.normalizedSourceSha256, baseline.normalizedSourceSha256);
  assert.notEqual(result.sourceSha256, baseline.sourceSha256);
  assert.equal(result.counts.cosmetic, 1);
  assert.equal(result.counts.equivalent, 1);
});

test("other compareBytes mutations and an inexact replacement remain behavioral survivors", () => {
  assert.equal(classify([mutant("left[i] - right[i]", { mutatorName: "ArithmeticOperator", replacement: "left[i] + right[i]" })]).pass, false);
  assert.equal(classify([{ ...equivalent(), replacement: "left.length * right.length" }]).pass, false);
  assert.equal(classify([{ ...equivalent(), mutatorName: "UnknownMutation" }]).pass, false);
});

test("changed caller, extra references, variable-length input, hash function, or crypto import invalidates proof", () => {
  for (const changed of [
    source.replace("level.sort(compareBytes);", "level.reverse(); level.sort(compareBytes);"),
    source + "\nfunction extra(a: Uint8Array, b: Uint8Array) { return compareBytes(a, b); }\n",
    source.replace("return sha256(new Uint8Array([0x00]), canonicalize(receipt));", "return canonicalize(receipt);"),
    source.replace('digest("SHA-256", input)', 'digest("SHA-512", input)'),
    source.replace('from "node:crypto"', 'from "custom-crypto"'),
    source + "\nconst extraDigest = sha256;\n",
    source.replace("i < left.length", "i < right.length"),
  ]) assert.equal(classify([equivalent(changed)], changed).pass, false);
});

test("killed, raw survived, timeout, cosmetic, equivalent, and unresolved statuses stay separate", () => {
  const mutants = [mutant(MESSAGE, { status: "Killed" }), mutant(), equivalent(), mutant(MESSAGE, { status: "Timeout" }),
    ...["NoCoverage", "RuntimeError", "CompileError", "Ignored", "Pending"].map((status) => mutant(MESSAGE, { status }))];
  const result = classify(mutants);
  assert.equal(result.pass, false);
  assert.equal(result.total, 9);
  assert.deepEqual(result.counts, { Killed: 1, Survived: 2, Timeout: 1, NoCoverage: 1, RuntimeError: 1,
    CompileError: 1, Ignored: 1, Pending: 1, cosmetic: 1, equivalent: 1, unclassifiedSurvived: 0 });
  assert.equal(result.blockers.length, 6);
  assert.deepEqual(result.blockers.map((m) => m.id), mutants.slice(3).map((m) => m.id));
  for (const m of result.blockers) {
    assert.deepEqual(m.location, mutants.find((input) => input.id === m.id).location);
    assert.match(m.reason, /unresolved and blocks/);
  }
  assert.equal(classify([{ ...equivalent(), status: "Timeout" }]).pass, false);
});

test("unknown statuses/schema and missing, empty, wrong-target, or forged source/report fail closed", () => {
  const valid = report([mutant()]);
  for (const invalid of [null, {}, { ...valid, schemaVersion: "2.0" }, { ...valid, thresholds: {} },
    { ...valid, files: {} }, report([]), report([mutant()], source + "\n// forged\n"),
    { ...valid, files: { "other.ts": valid.files["verifier.ts"] } },
    { ...valid, unexpectedSchemaField: true }, report([{ ...mutant(), status: "Success" }]),
    report([{ ...mutant(), replacement: undefined }]),
    { ...valid, files: { "verifier.ts": { ...valid.files["verifier.ts"], source: undefined } } },
  ]) assert.throws(() => classifyReport(invalid, source));
  assert.throws(() => classifyReport(valid, undefined));
  assert.throws(() => classifyReport(valid, ""));
  const syntaxError = source + "\nfunction unfinished(\n";
  assert.throws(() => classifyReport(report([mutant()], syntaxError), syntaxError), /syntax errors/);
});

test("duplicate IDs, malformed locations, and no-op replacements cannot pass", () => {
  const m = mutant();
  assert.throws(() => classify([m, { ...m }]), /duplicate/);
  for (const location of [undefined, { start: { line: 0, column: 1 }, end: m.location.end },
    { start: { line: 1, column: 1000000 }, end: m.location.end },
    { start: m.location.end, end: m.location.start }, { start: m.location.start, end: m.location.start }]) {
    assert.throws(() => classify([{ ...m, location }]));
  }
  assert.throws(() => classify([{ ...m, replacement: MESSAGE }]), /does not change/);
});

test("CLI returns 0 only for resolved reports; unresolved, missing, or invalid JSON fail", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "allowly-report-gate-"));
  const script = path.join(__dirname, "mutation_report_gate.cjs");
  const run = (filename) => spawnSync(process.execPath, [script, path.join(directory, filename)], { encoding: "utf8" });
  try {
    fs.writeFileSync(path.join(directory, "pass.json"), JSON.stringify(report([mutant(), equivalent()])));
    fs.writeFileSync(path.join(directory, "blocked.json"), JSON.stringify(report([mutant(MESSAGE, { status: "Timeout" })])));
    fs.writeFileSync(path.join(directory, "invalid.json"), "not JSON");
    const pass = run("pass.json");
    assert.equal(pass.status, 0, pass.stderr);
    assert.equal(JSON.parse(pass.stdout).pass, true);
    const blocked = run("blocked.json");
    assert.equal(blocked.status, 1, blocked.stderr);
    assert.equal(JSON.parse(blocked.stdout).counts.Timeout, 1);
    assert.equal(run("missing.json").status, 2);
    assert.equal(run("invalid.json").status, 2);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});
