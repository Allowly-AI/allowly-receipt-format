"use strict";

// Synthetic reports only. No verifier code or mutation runner is executed.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");
const test = require("node:test");
const ts = require("../verifiers/typescript/node_modules/typescript");
const { classifyReport, TIMEOUT_CONTEXT_PATHS, LOSSLESS_EVIDENCE_PATHS } = require("./mutation_report_gate.cjs");
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
const comparatorSurvivor = (original = source) => mutant(ORIGINAL_RETURN,
  { mutatorName: "ArithmeticOperator", replacement: "left.length + right.length" }, original);
const killed = (original = source) => mutant(ORIGINAL_RETURN,
  { status: "Killed", mutatorName: "ArithmeticOperator", replacement: `left.length + right.length + ${nextId}` }, original);
const classify = (mutants, original = source) => classifyReport(report(mutants, original), original);

// Independent synthetic identities copied from the reviewed immutable report.
// No runtime ledger/report can add classifier policy.
const EXACT_FIXTURES = [
  [115,22,"StringLiteral","\"=\"","\"\"","equivalent"],
  [115,33,"ArithmeticOperator","(4 - (s.length % 4)) % 4","(4 - s.length % 4) * 4","equivalent"],
  [115,34,"ArithmeticOperator","4 - (s.length % 4)","4 + s.length % 4","equivalent"],
  [134,42,"StringLiteral","\"payload\"","\"\"","cosmetic"],
  [149,3,"CallExpression","validateTree(snapshot, checkCanonicalNumbers);",";","equivalent"],
  [165,19,"EqualityOperator","i < left.length","i <= left.length","equivalent"],
  [202,65,"BooleanLiteral","true","false","equivalent"],
  [220,11,"ConditionalExpression","checkCanonicalNumbers && !Number.isInteger(value)","false","equivalent"],
  [220,62,"BlockStatement","{\n        throw new VerificationError(\"receipts must not contain non-integer numbers\");\n      }","{}","equivalent"],
  [263,47,"StringLiteral","\"number\"","\"\"","equivalent"],
  [263,57,"StringLiteral","\"string\"","\"\"","equivalent"],
  [264,35,"StringLiteral","`unsupported type in payload: ${typeof value}`","``","cosmetic"],
  [280,7,"ConditionalExpression","typeof v === \"object\"","true","equivalent"],
  [290,31,"StringLiteral","`unsupported type in payload: ${typeof v}`","``","cosmetic"],
  [340,11,"BlockStatement","{\n    throw new VerificationError(\"now must be a valid Date\");\n  }","{}","equivalent"],
  [399,41,"MethodExpression","[...expectedDecisions].sort()","[...expectedDecisions]","cosmetic"],
  [399,41,"ArrayDeclaration","[...expectedDecisions]","[]","cosmetic"],
  [431,11,"StringLiteral","`got an action receipt with action=${JSON.stringify(action)}`","``","cosmetic"],
  [437,11,"StringLiteral","`got ${JSON.stringify(r.decision)}`","``","cosmetic"],
  [444,33,"StringLiteral","`unsupported signature alg: ${JSON.stringify(r.alg)}`","``","cosmetic"],
  [476,5,"BooleanLiteral","false","true","equivalent"],
  [764,7,"ConditionalExpression","!isPlainJsonObject(context)","false","equivalent"],
  [764,36,"BlockStatement","{\n    return { constraints: null, diagnostic: \"unsupported_authorization_snapshot\" };\n  }","{}","equivalent"],
  [765,12,"ObjectLiteral","{ constraints: null, diagnostic: \"unsupported_authorization_snapshot\" }","{}","equivalent"],
  [765,45,"StringLiteral","\"unsupported_authorization_snapshot\"","\"\"","equivalent"],
  [795,26,"MethodExpression","parsedActions\n    .filter((entry) => entry.name !== action)","parsedActions","equivalent"],
  [796,24,"ConditionalExpression","entry.name !== action","true","equivalent"],
  [823,5,"StringLiteral","\"deny\"","\"\"","equivalent"],
  [827,5,"StringLiteral","\"confirm\"","\"\"","equivalent"],
  [835,5,"StringLiteral","\"escalate\"","\"\"","equivalent"],
  [836,5,"StringLiteral","\"escalate_condition_matched\"","\"\"","equivalent"],
  [843,5,"StringLiteral","\"confirm\"","\"\"","equivalent"],
  [844,5,"StringLiteral","\"confirm_condition_matched\"","\"\"","equivalent"],
  [853,13,"StringLiteral","\"none\"","\"\"","equivalent"],
  [854,15,"StringLiteral","\"policy_conditions_not_matched\"","\"\"","equivalent"],
  [899,15,"LogicalOperator","missingKind ?? kind","missingKind && kind","equivalent"],
  [900,17,"StringLiteral","\"context_field_missing\"","\"\"","equivalent"],
  [970,9,"ConditionalExpression","!Array.isArray(expected)","false","equivalent"],
  [989,7,"ConditionalExpression","op === \"empty\"","true","equivalent"],
  [990,35,"ConditionalExpression","typeof expected !== \"boolean\"","false","equivalent"],
  [993,10,"BooleanLiteral","false","true","equivalent"],
  [1025,10,"ConditionalExpression","typeof value === \"number\"","true","equivalent"],
  [1037,7,"ConditionalExpression","left === null || right === null","false","equivalent"],
  [1037,7,"LogicalOperator","left === null || right === null","left === null && right === null","equivalent"],
  [1037,7,"ConditionalExpression","left === null","false","equivalent"],
  [1037,24,"ConditionalExpression","right === null","false","equivalent"],
  [1061,7,"ConditionalExpression","calculated === null","false","equivalent"],
  [1064,10,"ConditionalExpression","left.length === right.length","true","equivalent"],
  [1123,7,"StringLiteral","`record exceeds the ${SEAL_MAX_UTF8_BYTES}-byte SEAL limit`","``","cosmetic"],
  [1143,46,"StringLiteral","\"record must be valid JSON\"","\"\"","cosmetic"],
  [1150,37,"ArrayDeclaration","[]","[\"Stryker was here\"]","equivalent"],
  [1153,10,"EqualityOperator","index < text.length","index <= text.length","equivalent"],
  [1163,12,"EqualityOperator","index < text.length","index <= text.length","equivalent"],
  [1170,9,"ConditionalExpression","index >= text.length","false","equivalent"],
  [1170,9,"EqualityOperator","index >= text.length","index > text.length","equivalent"],
  [1173,12,"ConditionalExpression","next < text.length","true","equivalent"],
  [1173,12,"EqualityOperator","next < text.length","next <= text.length","equivalent"],
  [1179,13,"OptionalChaining","keys?.has","keys.has","equivalent"],
  [1180,53,"StringLiteral","`duplicate decoded object key: ${JSON.stringify(key)}`","``","cosmetic"],
  [1182,9,"OptionalChaining","keys?.add","keys.add","equivalent"],
  [1192,7,"ConditionalExpression","chunks.length === 0","true","equivalent"],
  [1192,7,"ConditionalExpression","chunks.length === 0","false","equivalent"],
  [1192,7,"EqualityOperator","chunks.length === 0","chunks.length !== 0","equivalent"],
  [1309,51,"StringLiteral","\"record contains an unpaired Unicode surrogate\"","\"\"","cosmetic"],
  [1314,46,"StringLiteral","\"rawJson must be a string or Uint8Array\"","\"\"","cosmetic"],
  [1320,46,"StringLiteral","\"record must be well-formed UTF-8\"","\"\"","cosmetic"],
  [1341,11,"StringLiteral","`record nesting exceeds the SEAL max depth ${SEAL_MAX_DEPTH}`","``","cosmetic"],
  [1351,49,"StringLiteral","\"record contains a number outside binary64 range\"","\"\"","cosmetic"],
  [1355,50,"StringLiteral","\"record number underflows binary64 to zero\"","\"\"","cosmetic"],
  [1358,48,"StringLiteral","\"record contains an integer outside ±(2^53-1)\"","\"\"","cosmetic"],
  [1360,7,"ConditionalExpression","value !== 0","true","equivalent"],
  [1363,7,"StringLiteral","\"record number loses significant digits in the RFC 8785 binary64 model\"","\"\"","cosmetic"],
  [1374,19,"BlockStatement","{\n    throw new SealInputError(\"canonicalization_failed\", \"record cannot be canonicalized as RFC 8785\");\n  }","{}","equivalent"],
  [1375,57,"StringLiteral","\"record cannot be canonicalized as RFC 8785\"","\"\"","cosmetic"],
  [1378,57,"StringLiteral","\"record cannot be canonicalized as RFC 8785\"","\"\"","cosmetic"],
  [1384,7,"StringLiteral","`canonical record exceeds the ${SEAL_MAX_UTF8_BYTES}-byte SEAL limit`","``","cosmetic"],
  [1395,19,"BlockStatement","{\n    throw new SealInputError(\"unsupported_value\", \"record must be structured-cloneable JSON data\");\n  }","{}","equivalent"],
  [1396,51,"StringLiteral","\"record must be structured-cloneable JSON data\"","\"\"","cosmetic"],
  [1409,9,"StringLiteral","`record nesting exceeds the SEAL max depth ${SEAL_MAX_DEPTH}`","``","cosmetic"],
  [1415,53,"StringLiteral","\"record contains a non-finite number\"","\"\"","cosmetic"],
  [1418,52,"StringLiteral","\"record contains an integer outside ±(2^53-1)\"","\"\"","cosmetic"],
  [1422,53,"StringLiteral","\"record contains an unpaired Unicode surrogate\"","\"\"","cosmetic"],
  [1433,57,"StringLiteral","\"record must not contain accessors\"","\"\"","cosmetic"],
  [1440,55,"StringLiteral","\"record objects must be plain JSON objects\"","\"\"","cosmetic"],
  [1443,55,"StringLiteral","\"record must not contain symbol keys\"","\"\"","cosmetic"],
  [1447,57,"StringLiteral","\"record must contain enumerable data properties only\"","\"\"","cosmetic"],
  [1450,55,"StringLiteral","\"record contains an unpaired Unicode surrogate\"","\"\"","cosmetic"],
  [1455,53,"StringLiteral","`record contains non-JSON type ${typeof value}`","``","cosmetic"],
  [1463,77,"MethodExpression","extra.sort()","extra","cosmetic"],
  [1467,77,"MethodExpression","missing.sort()","missing","cosmetic"],
  [1476,35,"StringLiteral","`${f} must be a string`","``","cosmetic"],
  [1482,35,"StringLiteral","`${f} must be string or null`","``","cosmetic"],
  [1496,35,"StringLiteral","`${f} must be a string`","``","cosmetic"],
  [1512,7,"StringLiteral","`signature must decode to 64 bytes (Ed25519), got ${sigBytes.length}`","``","cosmetic"],
  [1526,6,"ConditionalExpression","typeof value === \"number\"","true","equivalent"],
  [1546,81,"MethodExpression","extra.sort()","extra","cosmetic"],
  [1549,77,"MethodExpression","missing.sort()","missing","cosmetic"],
  [1554,7,"ConditionalExpression","typeof value !== \"object\"","false","equivalent"],
  [1562,9,"ConditionalExpression","typeof matched !== \"object\" || Array.isArray(matched)","false","equivalent"],
  [1562,9,"LogicalOperator","typeof matched !== \"object\" || Array.isArray(matched)","typeof matched !== \"object\" && Array.isArray(matched)","equivalent"],
  [1562,9,"ConditionalExpression","typeof matched !== \"object\"","false","equivalent"],
  [1562,64,"BlockStatement","{\n      throw new VerificationError(\"policy_eval.matched_condition must be an object or null\");\n    }","{}","equivalent"],
  [1596,7,"ConditionalExpression","typeof value !== \"object\" || value === null || Array.isArray(value)","false","equivalent"],
  [1596,7,"LogicalOperator","typeof value !== \"object\" || value === null || Array.isArray(value)","(typeof value !== \"object\" || value === null) && Array.isArray(value)","equivalent"],
  [1596,7,"ConditionalExpression","typeof value !== \"object\" || value === null","false","equivalent"],
  [1596,7,"LogicalOperator","typeof value !== \"object\" || value === null","typeof value !== \"object\" && value === null","equivalent"],
  [1596,7,"ConditionalExpression","typeof value !== \"object\"","false","equivalent"],
  [1596,36,"ConditionalExpression","value === null","false","equivalent"],
  [1596,76,"BlockStatement","{\n    throw new VerificationError(\"receipt.checkpoint context must be an object\");\n  }","{}","equivalent"],
  [1600,54,"StringLiteral","\"receipt.checkpoint context\"","\"\"","cosmetic"],
  [1604,7,"ConditionalExpression","periodEnd <= periodStart","false","equivalent"],
  [1604,7,"EqualityOperator","periodEnd <= periodStart","periodEnd < periodStart","equivalent"],
  [1604,33,"BlockStatement","{\n    throw new VerificationError(\"receipt.checkpoint period_end must be after period_start\");\n  }","{}","equivalent"],
  [1696,9,"StringLiteral","`checkpoint member ${JSON.stringify(receipt.receipt_id)} falls outside checkpoint period`","``","cosmetic"],
  [1708,7,"StringLiteral","`checkpoint merkle_root mismatch: committed ${context.merkle_root}, got ${root}`","``","cosmetic"],
  [1729,20,"Regex","/^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$/","/^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z/","equivalent"],
  [1767,9,"ConditionalExpression","k.activeUntil !== null && k.activeUntil <= k.activeFrom","false","equivalent"],
  [1767,35,"EqualityOperator","k.activeUntil <= k.activeFrom","k.activeUntil < k.activeFrom","equivalent"],
  [1767,66,"BlockStatement","{\n      throw new VerificationError(\"selected public key active window is empty\");\n    }","{}","equivalent"],
  [1781,20,"ConditionalExpression","k.activeUntil === null","true","equivalent"],
  [1892,25,"StringLiteral","\"key must be a Uint8Array\"","\"\"","cosmetic"],
  [1897,7,"ConditionalExpression","typeof fieldName !== \"string\"","false","equivalent"],
  [1901,25,"StringLiteral","\"value must be a string\"","\"\"","cosmetic"],
  [1904,26,"StringLiteral","\"value contains an unpaired Unicode surrogate\"","\"\"","cosmetic"],
  [1911,28,"StringLiteral","\"ascii\"","\"\"","equivalent"],
  [1913,24,"StringLiteral","\"utf-8\"","\"\"","equivalent"],
  [1917,5,"StringLiteral","\"ascii\"","\"\"","equivalent"],
  [1919,32,"StringLiteral","\"ascii\"","\"\"","equivalent"],
  [1922,10,"ConditionalExpression","expected.length === got.length","true","equivalent"],
];
const REFUSED_FIXTURES = [
  [1042,30,"StringLiteral","\"null:\"","\"\""],
  [1044,61,"StringLiteral","\"true\"","\"\""],
  [1044,70,"StringLiteral","\"false\"","\"\""],
  [981,10,"MethodExpression","expected.some((item) => !isStrictPolicyScalar(item))","expected.every(item => !isStrictPolicyScalar(item))"],
  [981,24,"ArrowFunction","(item) => !isStrictPolicyScalar(item)","() => undefined"],
  [1005,7,"MethodExpression","expected.filter(isStrictPolicyScalar)","expected"],
  [1025,10,"LogicalOperator","typeof value === \"number\" && Number.isSafeInteger(value)","typeof value === \"number\" || Number.isSafeInteger(value)"],
  [1036,7,"ConditionalExpression","!isStrictPolicyScalar(left) || !isStrictPolicyScalar(right)","false"],
  [1036,7,"LogicalOperator","!isStrictPolicyScalar(left) || !isStrictPolicyScalar(right)","!isStrictPolicyScalar(left) && !isStrictPolicyScalar(right)"],
  [1042,7,"ConditionalExpression","value === null","false"],
  [1043,7,"ConditionalExpression","typeof value === \"string\"","true"],
  [1043,7,"EqualityOperator","typeof value === \"string\"","typeof value !== \"string\""],
  [1044,7,"ConditionalExpression","typeof value === \"boolean\"","false"],
  [1044,24,"StringLiteral","\"boolean\"","\"\""],
  [243,13,"ConditionalExpression","!(\"value\" in descriptor)","false"],
  [243,39,"BlockStatement","{\n          throw new VerificationError(\"payload must not contain accessor properties\");\n        }","{}"],
  [258,13,"ConditionalExpression","!(\"value\" in descriptor)","false"],
  [258,39,"BlockStatement","{\n          throw new VerificationError(\"payload must not contain accessor properties\");\n        }","{}"],
  [263,16,"ConditionalExpression","value !== null && ![\"boolean\", \"number\", \"string\"].includes(typeof value)","false"],
  [263,91,"BlockStatement","{\n      throw new VerificationError(`unsupported type in payload: ${typeof value}`);\n    }","{}"],
  [283,33,"EqualityOperator","a < b","a <= b"],
  [283,46,"ConditionalExpression","a > b","true"],
  [283,46,"ConditionalExpression","a > b","false"],
  [283,46,"EqualityOperator","a > b","a >= b"],
  [283,46,"EqualityOperator","a > b","a <= b"],
  [362,9,"StringLiteral","`expected ${JSON.stringify(opts.expectedWorkspaceId)}`","``"],
  [1729,20,"Regex","/^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$/","/(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$/"],
  [1825,35,"StringLiteral","`keys[${i}] must be an object`","``"],
  [1829,37,"StringLiteral","`keys[${i}].${field} must be a string`","``"],
  [1833,35,"StringLiteral","`keys[${i}].alg must be \"Ed25519\"`","``"],
  [1835,47,"ConditionalExpression","k.active_until !== null && typeof k.active_until !== \"string\"","false"],
  [1836,35,"StringLiteral","`keys[${i}].active_until must be a string or null`","``"],
  [1848,35,"StringLiteral","`keys[${i}].public_key must decode to 32 bytes, got ${pub.length}`","``"],
  [1862,9,"StringLiteral","`keys[${i}].public_key_fingerprint does not match public_key`","``"],
  [1873,21,"Regex","/^hmac-v1:[0-9a-f]{64}$/","/hmac-v1:[0-9a-f]{64}$/"],
  [1873,21,"Regex","/^hmac-v1:[0-9a-f]{64}$/","/^hmac-v1:[0-9a-f]{64}/"],
];
function exactFixture([line, column, mutatorName, original, replacement]) {
  const ast = ts.createSourceFile("verifier.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
  const start = ast.getPositionOfLineAndCharacter(line - 1, column - 1);
  assert.equal(source.slice(start, start + original.length), original);
  const position = (offset) => {
    const { line, character } = ast.getLineAndCharacterOfPosition(offset);
    return { line: line + 1, column: character + 1 };
  };
  return { id: String(nextId++), mutatorName, replacement, status: "Survived",
    location: { start: position(start), end: position(start + original.length) } };
}

test("every reviewed exact identity is classified with an individual reason and untouched raw status", () => {
  const mutants = EXACT_FIXTURES.map(exactFixture);
  const result = classify(mutants);
  assert.equal(result.pass, false);
  assert.equal(result.score.rawPercent, 0);
  assert.equal(result.score.thresholdPercent, 80);
  assert.equal(result.score.meetsThreshold, false);
  assert.deepEqual(result.blockers, []);
  assert.equal(result.exactEvidenceSourceMatched, true);
  assert.equal(result.losslessEvidenceMatched, true);
  assert.equal(result.total, 129);
  assert.equal(result.counts.Survived, 129);
  assert.equal(result.counts.Killed, 0);
  assert.equal(result.counts.cosmetic, 47);
  assert.equal(result.counts.equivalent, 82);
  assert.equal(result.counts.unclassifiedSurvived, 0);
  for (let index = 0; index < mutants.length; index++) {
    const m = mutants[index], exclusion = result.exclusions[index];
    assert.equal(exclusion.id, m.id);
    assert.deepEqual(exclusion.location, m.location);
    assert.equal(exclusion.mutatorName, m.mutatorName);
    assert.equal(exclusion.status, "Survived");
    assert.equal(exclusion.classification, EXACT_FIXTURES[index][5]);
    assert.equal(exclusion.reason.trim().length > 0, true);
  }
});

test("every exact entry refuses nearby ranges and altered mutators or replacements", () => {
  for (const fixture of EXACT_FIXTURES) {
    const m = exactFixture(fixture);
    for (const changed of [
      { ...m, mutatorName: "UnreviewedMutator" },
      { ...m, replacement: m.replacement + " " },
      { ...m, location: { ...m.location, start: { ...m.location.start, column: m.location.start.column + 1 } } },
    ]) {
      const result = classify([changed]);
      assert.equal(result.pass, false, JSON.stringify(changed));
      assert.equal(result.exclusions.length, 0);
      assert.equal(result.counts.unclassifiedSurvived, 1);
    }
  }
});

test("the raw source pin refuses changed callers, observed private results, guards and public metadata", () => {
  const mutants = EXACT_FIXTURES.map(exactFixture);
  for (const changed of [
    source + "\nfunction extraKey(value: any) { return typedPolicyScalarKey(value); }\n",
    source.replace("level.sort(compareBytes);", "level.sort((a, b) => compareBytes(a.subarray(1), b));"),
    source.replace("checkSchema(ownReceipt);", ";"),
    source.replace("keySnapshots = structuredClone(publicKeys);", "keySnapshots = publicKeys;"),
    source + "\nfunction extraComparison(a: any, b: any) { return policyEvaluationsEqual(a, b); }\n",
    source.replace("?.policyEval ?? null;", "?.kind as any;") ,
    source.replace('const HMAC_REF_FIELDS = new Set(["project", "record", "actor", "full_tuple"]);',
      'const HMAC_REF_FIELDS = new Set(["project", "record", "actor"]);'),
    source.replace('this.name = "SealInputError";', 'this.name = "ChangedSealError";'),
    source.replace('this.name = "VerificationError";', 'this.name = "ChangedVerificationError";'),
    source.replace('return { signatureVerified, recordMatches, failureReason };',
      'return { signatureVerified: true, recordMatches, failureReason };'),
    source.replace('"unsupported_policy"', '"changed_public_diagnostic"'),
  ]) {
    const result = classify(mutants, changed);
    assert.equal(result.pass, false);
    assert.equal(result.exactEvidenceSourceMatched, false);
    assert.equal(result.exclusions.length, 0);
    assert.equal(result.counts.unclassifiedSurvived, 129);
  }
  const textOnly = source.replace(MESSAGE, '"changed plain message"');
  const refused = classify(mutants, textOnly);
  assert.equal(refused.evidenceSourceMatched, true);
  assert.equal(refused.exactEvidenceSourceMatched, false);
  assert.equal(refused.exclusions.length, 0);
  assert.equal(refused.counts.unclassifiedSurvived, 129);
});

test("public name, result and diagnostic mutations and comparator/options entries have no exemption", () => {
  for (const m of [
    mutant('"VerificationError"'),
    mutant('"SealInputError"'),
    mutant('"record_mismatch"'),
    mutant('"unsupported_policy"'),
    mutant('"deny_condition_matched"'),
    mutant('a < b ? -1 : a > b ? 1 : 0', { mutatorName: "ConditionalExpression", replacement: "a < b ? -1 : 1" }),
    mutant('`expected ${JSON.stringify(opts.expectedWorkspaceId)}`', { replacement: '``' }),
  ]) {
    assert.equal(classify([m]).pass, false);
    assert.equal(classify([m]).exclusions.length, 0);
  }
});

test("exact entries never accept non-Survived statuses, resource timeouts or injected proof fields", () => {
  for (const status of ["Killed", "Timeout", "NoCoverage", "RuntimeError", "CompileError", "Ignored", "Pending"]) {
    const mutants = EXACT_FIXTURES.map((fixture) => ({ ...exactFixture(fixture), status,
      statusReason: status === "Timeout" ? "Resource or unexplained timeout" : "fixture" }));
    const result = classify(mutants);
    assert.equal(result.counts[status], 129);
    assert.equal(result.counts.cosmetic, 0);
    assert.equal(result.counts.equivalent, 0);
    assert.equal(result.counts.detectedTimeout, 0);
    assert.deepEqual(result.exclusions, []);
    assert.deepEqual(result.detectedFaults, []);
    assert.equal(result.pass, status === "Killed");
    assert.equal(result.blockers.length, status === "Killed" ? 0 : 129);
  }
  const m = exactFixture(EXACT_FIXTURES[0]);
  assert.throws(() => classify([{ ...m, status: "Equivalent" }]), /unknown status/);
  assert.throws(() => classify([m, { ...m }]), /duplicate/);
  assert.throws(() => classify([{ ...m, equivalentProof: "approved" }]), /unknown fields/);
  assert.throws(() => classifyReport({ ...report([m]), reviewedProofs: [m] }, source), /unknown fields/);
});

test("parser-dependent exact entries bind the fixed installed call chain and lockfile", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "allowly-exact-dependency-gate-"));
  const script = path.join(directory, "scripts/mutation_report_gate.cjs");
  const reportPath = path.join(directory, "report.json");
  const fixture = EXACT_FIXTURES.find(([line, , mutatorName, , replacement]) =>
    line === 1192 && mutatorName === "ConditionalExpression" && replacement === "true");
  const m = exactFixture(fixture);
  const run = (...extra) => spawnSync(process.execPath, [script, reportPath, ...extra], { encoding: "utf8", timeout: 20000 });
  try {
    for (const name of ["scripts/mutation_report_gate.cjs", "verifiers/typescript/verifier.ts", ...LOSSLESS_EVIDENCE_PATHS]) {
      const target = path.join(directory, name);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(__dirname, "..", name), target);
    }
    fs.symlinkSync(fs.realpathSync(path.join(__dirname, "../verifiers/typescript/node_modules/typescript")),
      path.join(directory, "verifiers/typescript/node_modules/typescript"), "dir");
    fs.writeFileSync(reportPath, JSON.stringify(report([m])));
    const accepted = run();
    assert.equal(accepted.status, 1, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).counts.equivalent, 1);
    assert.equal(JSON.parse(accepted.stdout).score.rawPercent, 0);
    for (const name of LOSSLESS_EVIDENCE_PATHS) {
      const target = path.join(directory, name);
      const original = fs.readFileSync(target, "utf8");
      fs.writeFileSync(target, original + "\n");
      const refused = run();
      assert.equal(refused.status, 1, `${name}: ${refused.stderr}`);
      assert.equal(JSON.parse(refused.stdout).losslessEvidenceMatched, false);
      assert.equal(JSON.parse(refused.stdout).counts.unclassifiedSurvived, 1);
      fs.writeFileSync(target, original);
    }
    const missingPath = path.join(directory, LOSSLESS_EVIDENCE_PATHS.at(-1));
    fs.unlinkSync(missingPath);
    assert.equal(run().status, 1);
    assert.equal(run("--proof=approved").status, 2);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test("source-bound counterexamples and unproven candidates remain unresolved survivors", () => {
  for (const fixture of REFUSED_FIXTURES) {
    const result = classify([exactFixture(fixture)]);
    assert.equal(result.pass, false, JSON.stringify(fixture));
    assert.equal(result.counts.Survived, 1);
    assert.equal(result.counts.Killed, 0);
    assert.equal(result.counts.unclassifiedSurvived, 1);
    assert.deepEqual(result.exclusions, []);
  }
});

test("plain direct VerificationError text is cosmetic; ID/location/reason are recorded", () => {
  const m = mutant();
  const result = classify([m]);
  assert.equal(result.pass, false);
  assert.equal(result.score.rawPercent, 0);
  assert.deepEqual(result.blockers, []);
  assert.equal(result.counts.Survived, 1);
  assert.equal(result.counts.cosmetic, 1);
  assert.equal(result.counts.unclassifiedSurvived, 0);
  assert.deepEqual(result.exclusions[0], { id: m.id, location: m.location, mutatorName: "StringLiteral", status: "Survived",
    classification: "cosmetic", reason: "Only the direct sole plain-text argument of throw new VerificationError changes; exception class and control flow remain unchanged." });
});

test("the old Merkle comparator exemption is withdrawn and remains an accepted unresolved gap at 80%", () => {
  const m = comparatorSurvivor();
  const result = classify([killed(), killed(), killed(), killed(), m]);
  assert.equal(result.pass, true);
  assert.equal(result.score.rawPercent, 80);
  assert.equal(result.score.thresholdPercent, 80);
  assert.equal(result.counts.Killed, 4);
  assert.equal(result.counts.equivalent, 0);
  assert.equal(result.counts.cosmetic, 0);
  assert.equal(result.counts.unclassifiedSurvived, 1);
  assert.deepEqual(result.exclusions, []);
  assert.equal(result.unresolvedSurvivors[0].id, m.id);
  assert.deepEqual(result.unresolvedSurvivors[0].location, m.location);
  assert.equal(result.unresolvedSurvivors[0].status, "Survived");
  assert.match(result.unresolvedSurvivors[0].reason, /Unresolved test gap/);
  assert.deepEqual(result.blockers, []);
});

test("the raw 80% floor keeps cosmetic and equivalent survivors in its denominator", () => {
  const cosmetic = mutant();
  const reviewed = exactFixture(EXACT_FIXTURES[0]);
  const result = classify([killed(), killed(), killed(), cosmetic, reviewed]);
  assert.equal(result.score.rawPercent, 60);
  assert.equal(result.score.total, 5);
  assert.equal(result.score.detected, 3);
  assert.equal(result.counts.cosmetic, 1);
  assert.equal(result.counts.equivalent, 1);
  assert.equal(result.score.meetsThreshold, false);
  assert.equal(result.pass, false);
  assert.deepEqual(result.blockers, []);
});

test("a score that rounds to 80% still fails when it is below the floor", () => {
  const base = comparatorSurvivor();
  const mutants = Array.from({ length: 25001 }, (_, index) => ({ ...base,
    id: `boundary-${index}`, replacement: `left.length + right.length + ${index}`,
    status: index < 20000 ? "Killed" : "Survived" }));
  const input = report(mutants);
  input.thresholds.break = 0;
  const result = classifyReport(input, source);
  assert.equal(result.score.rawPercent.toFixed(2), "80.00");
  assert.equal(result.score.rawPercent < 80, true);
  assert.equal(result.score.thresholdPercent, 80);
  assert.equal(result.score.meetsThreshold, false);
  assert.equal(result.pass, false);
  assert.equal(result.unresolvedSurvivors.length, 5001);
  assert.deepEqual(result.blockers, []);
});

test("bad statuses and unproved timeouts block even when the raw score meets 80%", () => {
  for (const status of ["Timeout", "NoCoverage", "RuntimeError", "CompileError", "Ignored", "Pending"]) {
    const bad = mutant(MESSAGE, { status, replacement: JSON.stringify(status) });
    const result = classify([...Array.from({ length: 8 }, () => killed()), comparatorSurvivor(), bad]);
    assert.equal(result.score.rawPercent, 80, status);
    assert.equal(result.score.meetsThreshold, true, status);
    assert.equal(result.pass, false, status);
    assert.equal(result.blockers.length, 1, status);
    assert.equal(result.blockers[0].id, bad.id, status);
    assert.equal(result.counts.detectedTimeout, 0, status);
  }
});

test("a plain non-interpolated template changes text only; its timeout still blocks", () => {
  const changed = source.replace(MESSAGE, '`receipt must be an object`');
  const m = mutant('`receipt must be an object`', { replacement: '``' }, changed);
  assert.equal(classify([m], changed).pass, false);
  assert.equal(classify([m], changed).counts.cosmetic, 1);
  assert.equal(classify([{ ...m, status: "Timeout" }], changed).pass, false);
});

test("the actual Stryker 1.0 report shape accepts a validated break threshold without relaxing the gate", () => {
  const mutants = [...Array.from({ length: 8 }, () => killed()), mutant(), comparatorSurvivor()]
    .map((m) => ({ ...m, statusReason: "fixture result", testsCompleted: 1, killedBy: m.status === "Killed" ? ["0"] : [] }));
  const realShape = { files: report(mutants).files, schemaVersion: "1.0", thresholds: { break: 100, high: 80, low: 60 },
    testFiles: {}, projectRoot: ".", config: {}, framework: { name: "StrykerJS", version: "10.0.0" } };
  const result = classifyReport(realShape, source);
  assert.equal(result.pass, true);
  assert.equal(result.total, 10);
  assert.equal(result.counts.Killed, 8);
  assert.equal(result.score.rawPercent, 80);
  assert.equal(result.score.thresholdPercent, 80);
  assert.equal(result.counts.cosmetic, 1);
  assert.equal(result.counts.equivalent, 0);
  assert.equal(result.counts.unclassifiedSurvived, 1);
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

test("new message observers, crypto writes, and unrelated meaningful code invalidate the message proof", () => {
  for (const changed of [
    source.replace("if (error instanceof VerificationError) {", 'if (error instanceof VerificationError && error.message === "") {'),
    source + '\nglobalThis.crypto.subtle.digest = async () => new ArrayBuffer(1);\n',
    source.replace("const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;", "const MAX_FUTURE_SKEW_MS = 6 * 60 * 1000;"),
    source.replace('this.name = "VerificationError";', 'this.name = "ChangedError";'),
  ]) {
    const result = classify([mutant(MESSAGE, {}, changed), comparatorSurvivor(changed)], changed);
    assert.equal(result.pass, false);
    assert.equal(result.evidenceSourceMatched, false);
    assert.equal(result.counts.cosmetic, 0);
    assert.equal(result.counts.equivalent, 0);
    assert.equal(result.counts.unclassifiedSurvived, 2);
    assert.equal(result.exclusions.length, 0);
  }
});

test("only direct sole plain error message text is normalized; the comparator remains unresolved", () => {
  const changedMessage = '"new plain error message"';
  const changed = source.replace(MESSAGE, changedMessage);
  const result = classify([mutant(changedMessage, {}, changed), comparatorSurvivor(changed)], changed);
  const baseline = classify([mutant(), comparatorSurvivor()]);
  assert.equal(result.pass, false);
  assert.equal(result.evidenceSourceMatched, true);
  assert.equal(result.normalizedSourceSha256, "943300d14b6968aa0fc0112ae3433560c65bb69c5d541db037ad896ebbfbe469");
  assert.equal(result.normalizedSourceSha256, baseline.normalizedSourceSha256);
  assert.notEqual(result.sourceSha256, baseline.sourceSha256);
  assert.equal(result.counts.cosmetic, 1);
  assert.equal(result.counts.equivalent, 0);
  assert.equal(result.counts.unclassifiedSurvived, 1);
  assert.equal(result.unresolvedSurvivors.length, 1);
  assert.equal(result.score.rawPercent, 0);
});

test("other compareBytes mutations and an inexact replacement remain behavioral survivors", () => {
  assert.equal(classify([mutant("left[i] - right[i]", { mutatorName: "ArithmeticOperator", replacement: "left[i] + right[i]" })]).pass, false);
  assert.equal(classify([{ ...comparatorSurvivor(), replacement: "left.length * right.length" }]).pass, false);
  assert.equal(classify([{ ...comparatorSurvivor(), mutatorName: "UnknownMutation" }]).pass, false);
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
  ]) assert.equal(classify([comparatorSurvivor(changed)], changed).pass, false);
});

test("killed, raw survived, timeout, cosmetic, equivalent, and unresolved statuses stay separate", () => {
  const mutants = [killed(), mutant(), comparatorSurvivor(), mutant(MESSAGE, { status: "Timeout", replacement: '"timeout"' }),
    ...["NoCoverage", "RuntimeError", "CompileError", "Ignored", "Pending"].map((status) => mutant(MESSAGE, { status, replacement: JSON.stringify(status) }))];
  const result = classify(mutants);
  assert.equal(result.pass, false);
  assert.equal(result.total, 9);
  assert.deepEqual(result.counts, { Killed: 1, Survived: 2, Timeout: 1, NoCoverage: 1, RuntimeError: 1,
    CompileError: 1, Ignored: 1, Pending: 1, cosmetic: 1, equivalent: 0, unclassifiedSurvived: 1, detectedTimeout: 0 });
  assert.equal(result.unresolvedSurvivors.length, 1);
  assert.equal(result.blockers.length, 6);
  assert.deepEqual(result.blockers.map((m) => m.id), mutants.slice(3).map((m) => m.id));
  for (const m of result.blockers) {
    assert.deepEqual(m.location, mutants.find((input) => input.id === m.id).location);
    assert.match(m.reason, /unresolved and blocks/);
  }
  assert.equal(classify([{ ...comparatorSurvivor(), status: "Timeout" }]).pass, false);
});

// These are fictional proof records over synthetic context; they never write a
// production proof file or modify source/test inputs in the original repo.
const fixtureHash = (text) => createHash("sha256").update(text).digest("hex");
function timeoutEvidence(m) {
  const verificationContextSha256 = fixtureHash("synthetic fixture context");
  return { verificationContextSha256, manifest: {
    verificationContextSha256, verifierSourceSha256: fixtureHash(source),
    entries: [{ mutatorName: m.mutatorName, location: m.location, replacement: m.replacement,
      reason: "Synthetic fixture: independently reproduced infinite loop" }],
  } };
}

test("only an exact independently proven Timeout is a detected fault, never an exclusion", () => {
  const m = mutant("i < left.length", { mutatorName: "ConditionalExpression", replacement: "true", status: "Timeout" });
  const evidence = timeoutEvidence(m);
  const result = classifyReport(report([m]), source, evidence);
  assert.equal(result.pass, true);
  assert.equal(result.counts.Timeout, 1);
  assert.equal(result.counts.detectedTimeout, 1);
  assert.equal(result.counts.Killed, 0);
  assert.equal(result.counts.cosmetic, 0);
  assert.equal(result.counts.equivalent, 0);
  assert.deepEqual(result.exclusions, []);
  assert.deepEqual(result.detectedFaults, [{ id: m.id, location: m.location, mutatorName: m.mutatorName,
    status: "Timeout", reason: evidence.manifest.entries[0].reason }]);
  assert.deepEqual(result.blockers, []);
  for (const status of ["Survived", "NoCoverage", "RuntimeError", "CompileError", "Ignored", "Pending"]) {
    const blocked = classifyReport(report([{ ...m, status }]), source, evidence);
    assert.equal(blocked.pass, false, status);
    assert.equal(blocked.counts.detectedTimeout, 0, status);
  }
});

test("mismatched type/location/replacement/source/context or an unexplained timeout still blocks", () => {
  const m = mutant("i < left.length", { mutatorName: "ConditionalExpression", replacement: "true", status: "Timeout" });
  const evidence = timeoutEvidence(m);
  const otherLocation = mutant("!B64URL_RE.test(s)", { mutatorName: m.mutatorName, replacement: m.replacement, status: "Timeout" }).location;
  for (const entry of [{ ...evidence.manifest.entries[0], mutatorName: "EqualityOperator" },
    { ...evidence.manifest.entries[0], location: otherLocation }, { ...evidence.manifest.entries[0], replacement: "false" }]) {
    const result = classifyReport(report([m]), source, { ...evidence, manifest: { ...evidence.manifest, entries: [entry] } });
    assert.equal(result.pass, false);
    assert.equal(result.counts.detectedTimeout, 0);
  }
  for (const stale of [{ ...evidence, verificationContextSha256: fixtureHash("changed test/fixture/build context") },
    { ...evidence, manifest: { ...evidence.manifest, verifierSourceSha256: fixtureHash("different verifier source") } },
    { ...evidence, manifest: { ...evidence.manifest, entries: [] } }, { manifest: null, verificationContextSha256: null }]) {
    const result = classifyReport(report([m]), source, stale);
    assert.equal(result.pass, false);
    assert.equal(result.counts.Timeout, 1);
    assert.equal(result.counts.detectedTimeout, 0);
    assert.equal(result.blockers[0].id, m.id);
  }
  const changed = source.replace(MESSAGE, '"changed cosmetic text"');
  assert.equal(classifyReport(report([m], changed), changed, evidence).pass, false);
});

test("malformed/omitted proof inputs, empty reasons, or duplicate entries cannot approve a timeout", () => {
  const m = mutant("i < left.length", { mutatorName: "ConditionalExpression", replacement: "true", status: "Timeout" });
  const evidence = timeoutEvidence(m);
  const invalid = [undefined, {}, { ...evidence.manifest, verifierSourceSha256: "bad hash" },
    { ...evidence.manifest, contextPaths: TIMEOUT_CONTEXT_PATHS.slice(0, 1) },
    { ...evidence.manifest, contextPaths: [...TIMEOUT_CONTEXT_PATHS].reverse() },
    { ...evidence.manifest, entries: [{ ...evidence.manifest.entries[0], reason: " " }] },
    { ...evidence.manifest, entries: [evidence.manifest.entries[0], evidence.manifest.entries[0]] },
    { ...evidence.manifest, entries: [{ ...evidence.manifest.entries[0], status: "Timeout" }] },
    { ...evidence.manifest, entries: "all timeouts" }];
  for (const manifest of invalid) assert.throws(() => classifyReport(report([m]), source, { ...evidence, manifest }));
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
  assert.throws(() => classify([m, { ...m, id: "another-id" }]), /Duplicate mutation identity/);
  for (const location of [undefined, { start: { line: 0, column: 1 }, end: m.location.end },
    { start: { line: 1, column: 1000000 }, end: m.location.end },
    { start: m.location.end, end: m.location.start }, { start: m.location.start, end: m.location.start }]) {
    assert.throws(() => classify([{ ...m, location }]));
  }
  assert.throws(() => classify([{ ...m, replacement: MESSAGE }]), /does not change/);
  for (const changes of [{ id: " " }, { mutatorName: " " }, { testsCompleted: 0.5 },
    { testsCompleted: -1 }, { duration: NaN }, { killedBy: [""] }, { coveredBy: ["0", "0"] },
    { static: "false" }]) assert.throws(() => classify([{ ...m, ...changes }]));
});

test("CLI binds timeout proof to every live input and never accepts a missing manifest", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "allowly-timeout-gate-"));
  const m = mutant("i < left.length", { mutatorName: "ConditionalExpression", replacement: "true", status: "Timeout" });
  const script = path.join(directory, "scripts/mutation_report_gate.cjs");
  const proofPath = path.join(directory, "scripts/mutation_timeout_proofs.json");
  const reportPath = path.join(directory, "report.json");
  const run = () => spawnSync(process.execPath, [script, reportPath], { encoding: "utf8" });
  try {
    for (const name of ["scripts/mutation_report_gate.cjs", ...TIMEOUT_CONTEXT_PATHS]) {
      const target = path.join(directory, name);
      fs.mkdirSync(path.dirname(target), { recursive: true });
      fs.copyFileSync(path.join(__dirname, "..", name), target);
    }
    fs.symlinkSync(fs.realpathSync(path.join(__dirname, "../verifiers/typescript/node_modules")),
      path.join(directory, "verifiers/typescript/node_modules"), "dir");
    const manifest = timeoutEvidence(m).manifest;
    manifest.verificationContextSha256 = fixtureHash(JSON.stringify(TIMEOUT_CONTEXT_PATHS.map((name) =>
      [name, fs.readFileSync(path.join(directory, name), "utf8")])));
    fs.writeFileSync(proofPath, JSON.stringify(manifest));
    fs.writeFileSync(reportPath, JSON.stringify(report([m])));
    const accepted = run();
    assert.equal(accepted.status, 0, accepted.stderr);
    assert.equal(JSON.parse(accepted.stdout).counts.detectedTimeout, 1);
    for (const name of TIMEOUT_CONTEXT_PATHS) {
      const target = path.join(directory, name);
      const original = fs.readFileSync(target, "utf8");
      fs.writeFileSync(target, original + "\n");
      if (name === "verifiers/typescript/verifier.ts") fs.writeFileSync(reportPath, JSON.stringify(report([m], original + "\n")));
      const stale = run();
      assert.equal(stale.status, 1, `${name}: ${stale.stderr}`);
      assert.equal(JSON.parse(stale.stdout).counts.detectedTimeout, 0, name);
      fs.writeFileSync(target, original);
      fs.writeFileSync(reportPath, JSON.stringify(report([m])));
    }
    fs.unlinkSync(proofPath);
    const missing = run();
    assert.equal(missing.status, 1, missing.stderr);
    assert.equal(JSON.parse(missing.stdout).counts.detectedTimeout, 0);
  } finally {
    fs.rmSync(directory, { recursive: true });
  }
});

test("CLI returns 0 only at the approved score with no fatal blockers; missing or invalid JSON fail", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "allowly-report-gate-"));
  const script = path.join(__dirname, "mutation_report_gate.cjs");
  const run = (filename) => spawnSync(process.execPath, [script, path.join(directory, filename)], { encoding: "utf8" });
  try {
    fs.writeFileSync(path.join(directory, "pass.json"), JSON.stringify(report([...Array.from({ length: 8 }, () => killed()), mutant(), comparatorSurvivor()])));
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
