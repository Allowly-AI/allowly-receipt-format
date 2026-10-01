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
// Each exact identity below was reviewed at 6fc4443 against the immutable
// report and the independent worker probes. The raw pin includes every local
// caller/validator; it is separate from, and never refreshes, the older pin.
const RAW_VERIFIER_EVIDENCE_SHA256 = "407d7a2d759706b8fb3f005c61983575d58a891d8b4b0d5e1cffae4240b72691";
// Parser-dependent entries additionally bind the installed lossless call chain.
const LOSSLESS_EVIDENCE_PATHS = Object.freeze([
  "verifiers/typescript/package-lock.json",
  "verifiers/typescript/node_modules/lossless-json/package.json",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/package.json",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/index.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/config.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/LosslessNumber.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/numberParsers.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/parse.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/revive.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/reviveDate.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/stringify.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/types.js",
  "verifiers/typescript/node_modules/lossless-json/lib/esm/utils.js"
]);
const LOSSLESS_EVIDENCE_SHA256 = "c303b023e10e35d52db86f397172023a3ec154b4b337217d7ee6c7a29e3204a5";
// [start line, start column, mutator, original slice, exact replacement,
//  classification, individual reason, requires the lossless pin?]
// The original slice fixes the end offset; IDs are never classification inputs.
const REVIEWED_MUTATIONS = Object.freeze([
  [115,22,"StringLiteral","\"=\"","\"\"","equivalent","The only change is omitting trailing '=' padding. For primitive string inputs, Node Buffer.from(base64) accepts unpadded input and decode/re-encode still requires exact canonical base64url. For non-string second-read key-loader values, length/coercion evaluations and the strict comparison against the object are retained; Buffer decoding ignores differences in trailing padding. No validation guard is removed."],
  [115,33,"ArithmeticOperator","(4 - (s.length % 4)) % 4","(4 - s.length % 4) * 4","equivalent","The padding count changes from final modulo 4 to multiplication by 4, but the unchanged inner s.length % 4 keeps the repeat count finite/non-negative whenever the original arithmetic is valid. Only trailing '=' count changes. Node base64 decoding yields the same bytes regardless of that trailing padding, then exact re-encoding is checked. The same property reads and coercions remain."],
  [115,34,"ArithmeticOperator","4 - (s.length % 4)","4 + s.length % 4","equivalent","Replacing subtraction with addition in the padding formula only changes the count of trailing '=' (0-3 for actual strings). The same s.length access and modulo coercion occur, Node's base64 decoder accepts these padded/unpadded forms, and strict canonical re-encoding remains unchanged."],
  [134,42,"StringLiteral","\"payload\"","\"\"","cosmetic","Only the constant snapshot label changes from 'payload' to ''. The same input, structuredClone operation, catch, VerificationError constructor and rejection occur. No interpolation or property read is removed."],
  [149,3,"CallExpression","validateTree(snapshot, checkCanonicalNumbers);",";","equivalent","The pre-clone validateTree remains. It rejects enumerable accessors, unsupported values, nonplain objects, ill-formed strings, non-dense arrays, cycles via the depth bound, and excessive depth/nodes before native structuredClone. Cloning admissible data preserves enumerable JSON values, array items, numeric values, aliases and depth; it drops ignored non-enumerable/symbol data and normalizes an allowed null prototype to another allowed prototype. The post-walk checks no new JSON state under native structuredClone. No user getter is invoked in that admissible domain. This argument assumes the native global, as the implementation does."],
  [165,19,"EqualityOperator","i < left.length","i <= left.length","equivalent","compareBytes is private; its sole call is level.sort(compareBytes) on SHA-256 outputs at verifier.ts:186. Both operands are 32-byte Uint8Arrays. If any byte differs, either loop returns the same first difference. If all 32 bytes tie, the mutant's added i=32 comparison sees undefined === undefined, then both return left.length-right.length = 0. This is an individual domain proof for <=; it does not apply to IDs100/102."],
  [202,65,"BooleanLiteral","true","false","equivalent","Only validateTree's default parameter changes. The two live call sites, both inside snapshotJson at lines 142 and 149, always supply checkCanonicalNumbers explicitly. Its own default stays true for public canonicalize, and verifyReceipt/verifyCheckpoint explicitly request false before later payload canonicalization. No live caller uses validateTree's default."],
  [220,11,"ConditionalExpression","checkCanonicalNumbers && !Number.isInteger(value)","false","equivalent","When checkCanonicalNumbers is false, both number guards are disabled. When true, the unchanged Number.isSafeInteger(value) rejects every non-integer, NaN, infinity and unsafe integer that the removed Number.isInteger guard rejects. Acceptance, canonical bytes and error class stay fixed; the diagnostic for a fractional value can change."],
  [220,62,"BlockStatement","{\n        throw new VerificationError(\"receipts must not contain non-integer numbers\");\n      }","{}","equivalent","Removing the first numeric throw still leaves the immediately following safe-integer throw under the same checkCanonicalNumbers flag. Number.isSafeInteger implies Number.isInteger for native numeric values. No malformed numeric value is newly serialized; fractional-number diagnostic wording can change."],
  [263,47,"StringLiteral","\"number\"","\"\"","equivalent","typeof value === 'number' is handled in the first if arm, so number can never reach this final else-if type list. Removing 'number' from that list is unreachable under the unchanged preceding dispatch and changes no outcome or evaluation of input data."],
  [263,57,"StringLiteral","\"string\"","\"\"","equivalent","All string values enter the earlier typeof value === 'string' branch. The final type-list arm cannot receive a string. Removing 'string' there is a strict dispatch-equivalent edit."],
  [264,35,"StringLiteral","`unsupported type in payload: ${typeof value}`","``","cosmetic","The replacement removes only typeof applied to a local value from a VerificationError message. typeof on that local does not call a getter, valueOf, toJSON or coercion."],
  [280,7,"ConditionalExpression","typeof v === \"object\"","true","equivalent","snapshotJson pre-validation and native clone restrict stringify input to null, boolean, safe integer, scalar string, dense arrays and plain objects. The first five stringify arms return before this condition; only a plain object reaches it. Replacing the object test with true admits no additional reachable value."],
  [290,31,"StringLiteral","`unsupported type in payload: ${typeof v}`","``","cosmetic","This changes only a message containing typeof of the local v. It removes no property read or application callback. In addition, valid JSON cases return in earlier stringify arms and unsupported values are rejected by validateTree before this branch."],
  [340,11,"BlockStatement","{\n    throw new VerificationError(\"now must be a valid Date\");\n  }","{}","equivalent","If Date.prototype.getTime.call(now) throws, nowMs remains undefined. Removing the catch's throw reaches the unchanged !Number.isFinite(nowMs) guard and raises the identical 'now must be a valid Date' VerificationError. If it succeeds, this catch is never entered. Date.prototype.getTime is called with the same value once and no new caller read is introduced."],
  [399,41,"MethodExpression","[...expectedDecisions].sort()","[...expectedDecisions]","cosmetic","Only error formatting changes. expectedDecisions is an unexposed module-owned Set of primitive event decision names; the fresh spread array is used only in JSON.stringify for the error. Removing its default sort does not mutate caller data or invoke caller coercion."],
  [399,41,"ArrayDeclaration","[...expectedDecisions]","[]","cosmetic","The removed spread iterates a module-owned Set initialized with primitive decision names. That Set is not supplied or exposed by a caller. Replacing the fresh diagnostic array with [] changes only the error list; no input accessor or toJSON is removed."],
  [431,11,"StringLiteral","`got an action receipt with action=${JSON.stringify(action)}`","``","cosmetic","action is a primitive string from the receipt snapshot and passes its typeof guard before this template. JSON.stringify on that primitive has no caller getter or toJSON effect. Rejection and its condition are unchanged."],
  [437,11,"StringLiteral","`got ${JSON.stringify(r.decision)}`","``","cosmetic","r.decision is an own data field in the validated receipt snapshot and checkSchema already requires a primitive string. Its JSON.stringify is diagnostic only and cannot invoke caller accessors or toJSON."],
  [444,33,"StringLiteral","`unsupported signature alg: ${JSON.stringify(r.alg)}`","``","cosmetic","r.alg is an own data field of the snapshot and the unchanged checkSchema string guard runs before the algorithm check. The removed JSON.stringify reads a primitive string, not caller-owned accessors."],
  [476,5,"BooleanLiteral","false","true","equivalent","The changed importKey extractable flag affects only whether the local CryptoKey could later be exported. verifyReceipt never exports or returns that key and uses it solely in the same Ed25519 verify call with the same 'verify' usage. Signature outcome, key selection, trust pinning and public API return remain unchanged. Native WebCrypto is the assumed provider; no hidden cleanup or I/O change is claimed."],
  [764,7,"ConditionalExpression","!isPlainJsonObject(context)","false","equivalent","The selected creation context has already passed checkSchema at lines 1486–1492 on the same immutable snapshot. That check rejects non-object, null and array contexts, exactly the predicate tested here. No private replay caller bypasses verifyPolicyEvaluation authentication."],
  [764,36,"BlockStatement","{\n    return { constraints: null, diagnostic: \"unsupported_authorization_snapshot\" };\n  }","{}","equivalent","Removing this return does not affect execution: verifyReceipt/checkSchema already excludes every value that would enter the !isPlainJsonObject(context) branch before this private helper runs on the owned snapshot."],
  [765,12,"ObjectLiteral","{ constraints: null, diagnostic: \"unsupported_authorization_snapshot\" }","{}","equivalent","The changed object literal is inside the context-type rejection branch. Authentication's checkSchema rejects exactly those context values first; supported or unsupported action entries inside an object use different branches."],
  [765,45,"StringLiteral","\"unsupported_authorization_snapshot\"","\"\"","equivalent","This diagnostic is not generally cosmetic. Its particular branch is unreachable after mandatory checkSchema context validation on the immutable authenticated creation receipt, so this exact replacement has no reachable public result."],
  [795,26,"MethodExpression","parsedActions\n    .filter((entry) => entry.name !== action)","parsedActions","equivalent","Before unrelatedNames is built, matchingActions has exactly one selected action; zero or multiple selections already return. Adding that selected name once to the uniqueness check cannot collide with any name whose name !== action, so duplicate-unrelated-name detection is unchanged."],
  [796,24,"ConditionalExpression","entry.name !== action","true","equivalent","The predicate replacement includes the one selected name along with unrelated names. The preceding zero/multiple-match checks guarantee exactly one selected name; it is different from every unrelated name, leaving the equality of Set.size and array length unchanged."],
  [823,5,"StringLiteral","\"deny\"","\"\"","equivalent","Only the private PolicyConditionResult.kind value changes. The deny control-flow check uses reason === deny_condition_matched; verifyPolicyEvaluation projects only .policyEval. All private kind fields are unused outside construction."],
  [827,5,"StringLiteral","\"confirm\"","\"\"","equivalent","missingKind changes from confirm to an empty string, but both are defined values. The missingKind === undefined branch is unchanged, so deny still remembers its first missing field and continues; only the unused private kind differs."],
  [835,5,"StringLiteral","\"escalate\"","\"\"","equivalent","The escalate result's private kind changes. evaluatePolicyConditions returns any non-null escalate result and verifyPolicyEvaluation extracts only policyEval; no path branches on the kind."],
  [836,5,"StringLiteral","\"escalate_condition_matched\"","\"\"","equivalent","The escalate match reason changes, but no caller reads an escalate result's reason. The only reason comparison belongs to the separate denyResult. The public replay extracts only policyEval."],
  [843,5,"StringLiteral","\"confirm\"","\"\"","equivalent","The confirm result's private kind changes; confirm handling only checks null and public replay reads only policyEval."],
  [844,5,"StringLiteral","\"confirm_condition_matched\"","\"\"","equivalent","The confirm result's private match reason changes. No branch reads that reason after the confirm list returns; only policyEval reaches the public result."],
  [853,13,"StringLiteral","\"none\"","\"\"","equivalent","The no-match private kind changes. This object is returned directly from evaluatePolicyConditions and public replay reads only .policyEval; no private caller consumes this kind."],
  [854,15,"StringLiteral","\"policy_conditions_not_matched\"","\"\"","equivalent","The no-match private reason changes. This bottom-of-evaluator result is never used as denyResult and public replay reads only .policyEval, so the only reason-sensitive deny branch is unaffected."],
  [899,15,"LogicalOperator","missingKind ?? kind","missingKind && kind","equivalent","The replacement changes only the private result.kind expression. Missing-list early return/deferred fallback decisions still use missingKind === undefined and reason is unchanged; callers discard kind and read policyEval."],
  [900,17,"StringLiteral","\"context_field_missing\"","\"\"","equivalent","Changing context_field_missing to an empty private reason preserves its inequality to deny_condition_matched, which is the only reason test. Escalate/confirm result reasons are not inspected, and the public result uses only policyEval."],
  [970,9,"ConditionalExpression","!Array.isArray(expected)","false","equivalent","normalizePolicyCondition has already required Array.isArray(expected) for in/nin during complete prevalidation and again when reading each condition. Expected is the owned signed array and cannot change during synchronous calculation, so this second array check always passes."],
  [981,10,"MethodExpression","expected.some((item) => !isStrictPolicyScalar(item))","expected.every(item => !isStrictPolicyScalar(item))","equivalent","All expected contains_any/contains_none items have already passed normalizePolicyCondition's strict scalar validation. The owned array is not exposed to callers and evaluation is synchronous; this later some/every invalid-item check is false in either version."],
  [981,24,"ArrowFunction","(item) => !isStrictPolicyScalar(item)","() => undefined","equivalent","The expected-array invalid-item callback can only inspect scalars already accepted by normalizePolicyCondition. Replacing it with undefined keeps .some false; malformed policy items are rejected by the earlier unchanged validator."],
  [989,7,"ConditionalExpression","op === \"empty\"","true","equivalent","With the original normalizer, only supported operators reach policyConditionMatches. eq/neq, four numeric operators, in/nin and contains_any/contains_none all return before this point; exists is handled by evaluateConditionList before the call. Therefore the only reachable op here is empty and the predicate is already true."],
  [990,35,"ConditionalExpression","typeof expected !== \"boolean\"","false","equivalent","An empty condition's expected value is already a boolean because the unchanged normalizer requires it. Removing this later typeof check does not remove the actual-array check and cannot change a valid or uncomparable empty result."],
  [993,10,"BooleanLiteral","false","true","equivalent","The final fallback is unreachable for every supported normalized operator: all twelve operators are handled by an earlier return or by the caller's exists branch. Unsupported operators fail the original normalizer before this private function runs."],
  [1005,7,"MethodExpression","expected.filter(isStrictPolicyScalar)","expected","equivalent","Complete policy normalization guarantees every expected contains_any item is a strict scalar. Removing the scalar filter preserves the sequence passed to typedPolicyScalarKey, the resulting set, and input-order field projection. No caller can mutate this owned array during synchronous evaluation."],
  [1025,10,"LogicalOperator","typeof value === \"number\" && Number.isSafeInteger(value)","typeof value === \"number\" || Number.isSafeInteger(value)","equivalent","Every numeric value in the action/creation snapshots has passed canonicalize/validateTree before signature authentication. That unchanged wire validator forbids non-integer and unsafe numbers. For any remaining JSON value, typeof number || Number.isSafeInteger and typeof number && Number.isSafeInteger agree; non-numbers make both terms false."],
  [1025,10,"ConditionalExpression","typeof value === \"number\"","true","equivalent","ECMAScript Number.isSafeInteger returns false for every non-number without coercion. Therefore true && Number.isSafeInteger(value) is exactly the original number-type conjunction for all values, even before applying the wire-number invariant."],
  [1036,7,"ConditionalExpression","!isStrictPolicyScalar(left) || !isStrictPolicyScalar(right)","false","equivalent","Expected is a normalized strict scalar. For authenticated JSON actual values, the later null/type branches already reject every non-scalar actual: objects/arrays differ from non-null scalar types, and null-versus-object returns false. Authenticated numbers are safe integers. Removing this preliminary scalar check leaves the same comparison result."],
  [1036,7,"LogicalOperator","!isStrictPolicyScalar(left) || !isStrictPolicyScalar(right)","!isStrictPolicyScalar(left) && !isStrictPolicyScalar(right)","equivalent","Expected is always a normalized strict scalar, so the mutated invalid-left && invalid-right condition is never true. The remaining null/type checks still reject all non-scalar JSON actual values, as in the original; wire validation has already excluded unsafe/fractional numbers."],
  [1037,7,"ConditionalExpression","left === null || right === null","false","equivalent","Both operands have passed the unchanged strict-scalar guard. Of those scalars only null has typeof object. Falling through to typeof equality therefore distinguishes exactly the same both-null, one-null and neither-null cases as the removed special branch."],
  [1037,7,"LogicalOperator","left === null || right === null","left === null && right === null","equivalent","The narrower both-null predicate returns true for two nulls. Exactly-one-null cases fall through to typeof equality and remain false because the other accepted scalar is not an object. Neither-null comparison is unchanged."],
  [1037,7,"ConditionalExpression","left === null","false","equivalent","When left alone is null, the branch now falls through, but typeof null differs from every non-null accepted scalar. Right-null/both-null cases still use the original branch, so typed comparability is unchanged."],
  [1037,24,"ConditionalExpression","right === null","false","equivalent","When right alone is null, the branch now falls through, but typeof null differs from every non-null accepted scalar. Left-null/both-null cases still use the original branch, so typed comparability is unchanged."],
  [1042,7,"ConditionalExpression","value === null","false","equivalent","Null is remapped from null: to integer:null. A safe integer's String form is never null; string keys still start string: and boolean keys boolean:. The mapping remains injective over JSON scalar type/value classes, and these keys never appear in a public policy_eval."],
  [1042,30,"StringLiteral","\"null:\"","\"\"","equivalent","Null is remapped from null: to an empty key. Every non-null scalar key retains a non-empty type prefix, so null remains distinct and the typed-set equality relation is unchanged. Internal keys are not returned."],
  [1043,7,"ConditionalExpression","typeof value === \"string\"","true","equivalent","All non-null scalars are remapped to string:${JSON.stringify(value)}. Valid scalar JSON encodings distinguish quoted strings, boolean literals and safe integer literals; -0 and 0 are equal in both implementations. Null keeps a separate prefix. The mapping preserves typed equality without exposing keys."],
  [1043,7,"EqualityOperator","typeof value === \"string\"","typeof value !== \"string\"","equivalent","Non-string non-null scalars use string:<JSON scalar>, while strings use integer:<raw string>. These prefixes separate the domains; JSON literal encoding distinguishes integers and booleans within the first domain, and String preserves strings within the second. Null retains its own prefix, so the equality relation is unchanged."],
  [1044,7,"ConditionalExpression","typeof value === \"boolean\"","false","equivalent","Booleans fall through to integer:true and integer:false. Safe integer String forms cannot be true/false, string keys retain string: plus a quoted encoding, and null retains null:. The scalar key mapping stays injective."],
  [1044,24,"StringLiteral","\"boolean\"","\"\"","equivalent","No scalar's typeof equals the empty string, so boolean values fall through to integer:true/integer:false. Those keys cannot collide with safe integer decimal forms or other type prefixes; boolean values remain distinct."],
  [1044,61,"StringLiteral","\"true\"","\"\"","equivalent","The true boolean key becomes boolean:, while false remains boolean:false. No other domain uses the boolean: prefix, so true/false and all other scalar classes remain distinct. This private key spelling is not a public diagnostic or recorded value."],
  [1044,70,"StringLiteral","\"false\"","\"\"","equivalent","The false boolean key becomes boolean:, while true remains boolean:true. The two boolean keys stay distinct and no other scalar type uses that prefix. Public output still records actual values, not set keys."],
  [1061,7,"ConditionalExpression","calculated === null","false","equivalent","Calculated null is canonicalized as the four-byte JSON text null after the guard removal. Recorded evaluation has already passed checkPolicyEval and is an object whose canonical bytes start with {. Its bytes cannot equal null, so the later byte comparison still returns false and public mismatch/calculated null are preserved."],
  [1064,10,"ConditionalExpression","left.length === right.length","true","equivalent","Canonicalize returns complete canonical JSON values without trailing bytes. A complete recorded object cannot be a strict byte prefix of another complete canonical JSON object: its closing brace would terminate the outer value. The unchanged every-byte check already rejects either unequal-length case; length equality is redundant for this exact recorded/calculated object domain."],
  [1123,7,"StringLiteral","`record exceeds the ${SEAL_MAX_UTF8_BYTES}-byte SEAL limit`","``","cosmetic","Only this SealInputError human message changes; code size_limit, class/name, throw and every verifySeal result remain unchanged. Interpolation reads only a fixed numeric limit."],
  [1143,46,"StringLiteral","\"record must be valid JSON\"","\"\"","cosmetic","Only this SealInputError human message changes; code invalid_json, class/name, throw and every verifySeal result remain unchanged."],
  [1150,37,"ArrayDeclaration","[]","[\"Stryker was here\"]","equivalent","This changes the initial objectKeys stack, not chunks. Every key in well-formed JSON has an enclosing object whose Set is pushed above the added string; primitives have no object keys. Colon strings outside an object are malformed; a missing .has method is caught locally and strict parsing still rejects them. The temporary stack value never reaches canonical bytes. Candidate is scoped to native JSON operations and the pinned lossless parser.",true],
  [1153,10,"EqualityOperator","index < text.length","index <= text.length","equivalent","At index === text.length the outer scanner executes one extra iteration: text[index] is undefined, neither brace test matches, and index increments. No token, chunk boundary, key Set, or output text changes."],
  [1163,12,"EqualityOperator","index < text.length","index <= text.length","equivalent","At EOF the inner string scanner performs one extra iteration on undefined. It still reaches index >= text.length and breaks without producing a token or changing chunks. For a completed string it still breaks at the same closing quote."],
  [1170,9,"ConditionalExpression","index >= text.length","false","equivalent","A completed token never reaches this EOF condition. For an unfinished token, falling through creates tokenEnd beyond EOF; no colon exists there, no chunk is added, and the trailing original text is returned. The strict parser rejects the same unfinished text. Earlier duplicate detection and number-validation order remain intact."],
  [1170,9,"EqualityOperator","index >= text.length","index > text.length","equivalent","Only index === text.length changes. That is an unfinished string; tokenEnd is beyond EOF, no colon or replacement chunk can be produced, and the unchanged unfinished text reaches the strict parser. Completed-token paths are identical."],
  [1173,12,"ConditionalExpression","next < text.length","true","equivalent","The RHS /\\s/u.test(text[next]) is false at or beyond EOF because undefined converts to the non-whitespace string 'undefined'. Removing the next < length conjunct therefore does not extend whitespace scanning."],
  [1173,12,"EqualityOperator","next < text.length","next <= text.length","equivalent","At next === text.length the added RHS check evaluates /\\s/u.test(undefined) to false, so the <= change produces no loop iteration. Before EOF both bounds agree."],
  [1179,13,"OptionalChaining","keys?.has","keys.has","equivalent","Every object member in valid JSON has a current private Set, so optional and direct .has agree. A missing Set occurs only for colon-string tokens outside any object, which cannot form valid JSON. The added TypeError is caught by the unchanged local catch; strict parsing rejects that same grammar as invalid_json. The pinned parser call chain retains the same number validation and discards its temporary value before native JSON.parse supplies the canonical value.",true],
  [1180,53,"StringLiteral","`duplicate decoded object key: ${JSON.stringify(key)}`","``","cosmetic","Only this SealInputError human message changes; code duplicate_key, class/name, throw and every verifySeal result remain unchanged. Its JSON.stringify argument is an already-decoded primitive string."],
  [1182,9,"OptionalChaining","keys?.add","keys.add","equivalent","For valid object members keys is a Set, so .add and ?.add agree. With no enclosing object, the extra TypeError is caught locally; that colon-string grammar remains invalid in the strict parser. The validation parse is discarded, and native JSON.parse remains the canonical value source.",true],
  [1192,7,"ConditionalExpression","chunks.length === 0","true","equivalent","Returning original text still executes the full manual decoded-key Set scan before this return. The lossless parse validates syntax and every number but its value is discarded; native JSON.parse supplies the actual value. For unique __proto__ keys, the lossless temporary object's setter does not affect any returned record or number token. The pinned parser tests duplicate ownership with Object.prototype.hasOwnProperty.call. Candidate is tied to that implementation; retain namespacing.",true],
  [1192,7,"ConditionalExpression","chunks.length === 0","false","equivalent","When chunks was empty, the changed path appends text.slice(0) and joins one element, returning exactly text. When chunks is nonempty, both versions append the same suffix and join the same array."],
  [1192,7,"EqualityOperator","chunks.length === 0","chunks.length !== 0","equivalent","With no chunks, append-and-join returns the original text. With chunks, the early return removes only key namespacing after the complete independent decoded-duplicate scan. The pinned lossless parser still visits and validates every number; unique unprefixed keys can only alter its discarded temporary object through the legacy __proto__ setter. Native JSON.parse constructs the actual canonicalized value. No temporary property, prototype, or callback escapes to a public result.",true],
  [1309,51,"StringLiteral","\"record contains an unpaired Unicode surrogate\"","\"\"","cosmetic","Only this SealInputError human message changes; code invalid_unicode, class/name, throw and every verifySeal result remain unchanged."],
  [1314,46,"StringLiteral","\"rawJson must be a string or Uint8Array\"","\"\"","cosmetic","Only this SealInputError human message changes; code invalid_type, class/name, throw and every verifySeal result remain unchanged."],
  [1320,46,"StringLiteral","\"record must be well-formed UTF-8\"","\"\"","cosmetic","Only this SealInputError human message changes; code invalid_utf8, class/name, throw and every verifySeal result remain unchanged."],
  [1341,11,"StringLiteral","`record nesting exceeds the SEAL max depth ${SEAL_MAX_DEPTH}`","``","cosmetic","Only this SealInputError human message changes; code depth_limit, class/name, throw and every verifySeal result remain unchanged. Interpolation reads only a fixed numeric limit."],
  [1351,49,"StringLiteral","\"record contains a number outside binary64 range\"","\"\"","cosmetic","Only this SealInputError human message changes; code number_overflow, class/name, throw and every verifySeal result remain unchanged."],
  [1355,50,"StringLiteral","\"record number underflows binary64 to zero\"","\"\"","cosmetic","Only this SealInputError human message changes; code number_underflow, class/name, throw and every verifySeal result remain unchanged."],
  [1358,48,"StringLiteral","\"record contains an integer outside ±(2^53-1)\"","\"\"","cosmetic","Only this SealInputError human message changes; code unsafe_integer, class/name, throw and every verifySeal result remain unchanged."],
  [1360,7,"ConditionalExpression","value !== 0","true","equivalent","Only value === 0 adds a call to isSafeNumber. Nonzero significands that round to zero were already rejected by the underflow guard. For remaining legal zero spellings, integer tokens parse safely and decimal/exponent tokens have empty significant digits, just like String(0), so the pinned isSafeNumber returns true. Extreme zero-exponent shared vectors and root zero spellings pass in the exact probe.",true],
  [1363,7,"StringLiteral","\"record number loses significant digits in the RFC 8785 binary64 model\"","\"\"","cosmetic","Only this SealInputError human message changes; code number_precision, class/name, throw and every verifySeal result remain unchanged."],
  [1374,19,"BlockStatement","{\n    throw new SealInputError(\"canonicalization_failed\", \"record cannot be canonicalized as RFC 8785\");\n  }","{}","equivalent","If jcsCanonicalize throws, assignment never completes and canonical remains undefined. Removing the catch throw therefore reaches the following canonical === undefined guard, which throws the same SealInputError, name, and canonicalization_failed code. Only error stack location changes. This fallback argument does not assume the catch is unreachable."],
  [1375,57,"StringLiteral","\"record cannot be canonicalized as RFC 8785\"","\"\"","cosmetic","Only this SealInputError human message changes; code canonicalization_failed, class/name, throw and every verifySeal result remain unchanged."],
  [1378,57,"StringLiteral","\"record cannot be canonicalized as RFC 8785\"","\"\"","cosmetic","Only this SealInputError human message changes; code canonicalization_failed, class/name, throw and every verifySeal result remain unchanged."],
  [1384,7,"StringLiteral","`canonical record exceeds the ${SEAL_MAX_UTF8_BYTES}-byte SEAL limit`","``","cosmetic","Only this SealInputError human message changes; code size_limit, class/name, throw and every verifySeal result remain unchanged. Interpolation reads only a fixed numeric limit."],
  [1395,19,"BlockStatement","{\n    throw new SealInputError(\"unsupported_value\", \"record must be structured-cloneable JSON data\");\n  }","{}","equivalent","If structuredClone throws, snapshot remains undefined. Removing the catch throw then invokes validateSealTree(undefined), which rejects at root depth 1 with the same SealInputError name and unsupported_value code. The human message and stack differ; digest and verification result behavior do not. No guard removal is proposed."],
  [1396,51,"StringLiteral","\"record must be structured-cloneable JSON data\"","\"\"","cosmetic","Only this SealInputError human message changes; code unsupported_value, class/name, throw and every verifySeal result remain unchanged."],
  [1409,9,"StringLiteral","`record nesting exceeds the SEAL max depth ${SEAL_MAX_DEPTH}`","``","cosmetic","Only this SealInputError human message changes; code depth_limit, class/name, throw and every verifySeal result remain unchanged. Interpolation reads only a fixed numeric limit."],
  [1415,53,"StringLiteral","\"record contains a non-finite number\"","\"\"","cosmetic","Only this SealInputError human message changes; code number_overflow, class/name, throw and every verifySeal result remain unchanged."],
  [1418,52,"StringLiteral","\"record contains an integer outside ±(2^53-1)\"","\"\"","cosmetic","Only this SealInputError human message changes; code unsafe_integer, class/name, throw and every verifySeal result remain unchanged."],
  [1422,53,"StringLiteral","\"record contains an unpaired Unicode surrogate\"","\"\"","cosmetic","Only this SealInputError human message changes; code invalid_unicode, class/name, throw and every verifySeal result remain unchanged."],
  [1433,57,"StringLiteral","\"record must not contain accessors\"","\"\"","cosmetic","Only this SealInputError human message changes; code unsupported_value, class/name, throw and every verifySeal result remain unchanged."],
  [1440,55,"StringLiteral","\"record objects must be plain JSON objects\"","\"\"","cosmetic","Only this SealInputError human message changes; code unsupported_value, class/name, throw and every verifySeal result remain unchanged."],
  [1443,55,"StringLiteral","\"record must not contain symbol keys\"","\"\"","cosmetic","Only this SealInputError human message changes; code unsupported_value, class/name, throw and every verifySeal result remain unchanged."],
  [1447,57,"StringLiteral","\"record must contain enumerable data properties only\"","\"\"","cosmetic","Only this SealInputError human message changes; code unsupported_value, class/name, throw and every verifySeal result remain unchanged."],
  [1450,55,"StringLiteral","\"record contains an unpaired Unicode surrogate\"","\"\"","cosmetic","Only this SealInputError human message changes; code invalid_unicode, class/name, throw and every verifySeal result remain unchanged."],
  [1455,53,"StringLiteral","`record contains non-JSON type ${typeof value}`","``","cosmetic","Only this SealInputError human message changes; code unsupported_value, class/name, throw and every verifySeal result remain unchanged. Interpolation uses only typeof on the local value."],
  [1463,77,"MethodExpression","extra.sort()","extra","cosmetic","extra is a new Object.keys/filter array of primitive strings. Sorting changes only the list embedded in a thrown error. The array is not shared with the input; default string sorting and JSON.stringify introduce no caller callback."],
  [1467,77,"MethodExpression","missing.sort()","missing","cosmetic","missing is a new filtered array of internal REQUIRED_FIELDS strings. Its only consumer in this branch is the error text; sorting does not affect schema decisions or caller objects."],
  [1476,35,"StringLiteral","`${f} must be a string`","``","cosmetic","The removed interpolation uses local f from the internal stringFields array, containing fixed primitive field names. It removes no receipt property read; the typeof guard and throw remain."],
  [1482,35,"StringLiteral","`${f} must be string or null`","``","cosmetic","Only a template containing local f from the fixed ['resource','authorization_id'] array is changed. The input read occurs in the unchanged v assignment and guard, not in this message."],
  [1496,35,"StringLiteral","`${f} must be a string`","``","cosmetic","Only a template containing f from fixed ['alg','key_id','signature'] field names changes. No input property access or callback is removed; guard and throw remain."],
  [1512,7,"StringLiteral","`signature must decode to 64 bytes (Ed25519), got ${sigBytes.length}`","``","cosmetic","The removed message reads sigBytes.length from a fresh locally decoded Uint8Array. That buffer is not caller-owned or exposed before the throw, and length is a built-in integer getter. The signature length guard and rejection remain."],
  [1526,6,"ConditionalExpression","typeof value === \"number\"","true","equivalent","Number.isInteger returns true only for primitive numbers. Earlier OR arms already accept null/string/boolean; for every other value the original typeof guard is false and the mutated Number.isInteger is also false. Native Number.isInteger does not coerce or invoke valueOf. The scalar predicate is exactly unchanged."],
  [1546,81,"MethodExpression","extra.sort()","extra","cosmetic","extra is a fresh Object.keys/filter array, so its members are primitive property-name strings. sort only changes error formatting; it mutates neither the object nor any caller array and cannot call item coercion."],
  [1549,77,"MethodExpression","missing.sort()","missing","cosmetic","missing is a fresh filter result from internal expected field-name arrays. Those names are primitive strings at every live checkExactKeys call. Removing sort changes only diagnostic ordering and no caller effects."],
  [1554,7,"ConditionalExpression","typeof value !== \"object\"","false","equivalent","Null and arrays still fail the unchanged remaining terms. Other admissible JSON primitives cannot have own named matched_condition and field_value properties: booleans/numbers have no own keys, while strings have only character index keys. Unchanged checkExactKeys therefore rejects each with VerificationError. Functions/symbols/undefined are rejected by receipt tree validation first. No value becomes a valid policy object; diagnostic text can change."],
  [1562,9,"ConditionalExpression","typeof matched !== \"object\" || Array.isArray(matched)","false","equivalent","After receipt pre-validation, a non-null matched value is a JSON primitive, dense array or plain object. Removing this guard cannot give primitives the own field/op/value keys required by unchanged checkExactKeys. Dense arrays have only index keys because validateTree rejects named extras; empty arrays lack the required keys. Thus all rejected shapes remain rejected before field-value logic, with a different diagnostic."],
  [1562,9,"LogicalOperator","typeof matched !== \"object\" || Array.isArray(matched)","typeof matched !== \"object\" && Array.isArray(matched)","equivalent","The mutated conjunction cannot be true for native Array.isArray values, so this guard is effectively bypassed. Unchanged receipt density/accessor validation and checkExactKeys still reject all non-object JSON primitives and arrays as in2040. Null stays outside the matched !== null block. No new shape is accepted; diagnostic text can change."],
  [1562,9,"ConditionalExpression","typeof matched !== \"object\"","false","equivalent","Only the primitive-type term is disabled; arrays still trigger the remaining Array.isArray term. Non-null JSON primitives cannot satisfy the own field/op/value check immediately below. Unsupported non-JSON primitives are rejected by validateTree before schema. Accepted conditions and rejection class remain unchanged."],
  [1562,64,"BlockStatement","{\n      throw new VerificationError(\"policy_eval.matched_condition must be an object or null\");\n    }","{}","equivalent","With the throw removed, every non-null primitive or array still fails checkExactKeys: primitives lack the required own fields and prevalidated arrays cannot have the named extras. Plain objects follow the original checks, null still skips this block. No application getter is reached because the receipt is already a validated snapshot. Only the error explanation changes."],
  [1596,7,"ConditionalExpression","typeof value !== \"object\" || value === null || Array.isArray(value)","false","equivalent","Replacing this entire checkpoint-context object guard with false cannot admit invalid contexts: checkSchema at line 1487 rejects non-objects/null/arrays before the sole checkCheckpointContext call at line 409. The point-in-time receipt snapshot remains unchanged between those synchronous checks."],
  [1596,7,"LogicalOperator","typeof value !== \"object\" || value === null || Array.isArray(value)","(typeof value !== \"object\" || value === null) && Array.isArray(value)","equivalent","The mutated outer || to && changes only invalid context cases. The earlier checkSchema object/null/array guard rejects every such case before the sole checkpoint-context call. All values reaching this predicate are validated context objects and all its original/mutated terms are false."],
  [1596,7,"ConditionalExpression","typeof value !== \"object\" || value === null","false","equivalent","Removing the inner non-object-or-null condition leaves the array check, and earlier checkSchema independently rejects non-objects/null/arrays. For every context passed to this private helper the removed inner predicate is already false."],
  [1596,7,"LogicalOperator","typeof value !== \"object\" || value === null","typeof value !== \"object\" && value === null","equivalent","Changing typeof-non-object || null to && affects non-object and null inputs, but neither reaches this private helper because checkSchema rejects them first. Its sole call uses the same immutable receipt snapshot."],
  [1596,7,"ConditionalExpression","typeof value !== \"object\"","false","equivalent","Replacing only typeof value !== object with false cannot alter public acceptance or error class; checkSchema has already enforced context object type at line 1487. Null/array checks remain, and public malformed contexts fail before this call."],
  [1596,36,"ConditionalExpression","value === null","false","equivalent","Removing only the value === null condition has no reachable changed branch: the earlier schema context guard rejects null before line 409. Validated context snapshots are non-null objects."],
  [1596,76,"BlockStatement","{\n    throw new VerificationError(\"receipt.checkpoint context must be an object\");\n  }","{}","equivalent","Deleting this guard's throw body leaves all invalid object-type cases rejected by the earlier checkSchema guard. The private helper has exactly one live call, after that check and with the same snapshot."],
  [1600,54,"StringLiteral","\"receipt.checkpoint context\"","\"\"","cosmetic","Only the constant checkExactKeys label changes. The same context object and fixed expected-key list are checked; this helper uses the label only in VerificationError text. Key reads, rejection, class and public name remain unchanged."],
  [1604,7,"ConditionalExpression","periodEnd <= periodStart","false","equivalent","Removing periodEnd <= periodStart still rejects every equal/reversed period through the independent exact 86,400,000 ms duration check at line 1609. Parsed timestamps are finite real Date instants. The public result and VerificationError class/name stay the same; human message text can differ."],
  [1604,7,"EqualityOperator","periodEnd <= periodStart","periodEnd < periodStart","equivalent","Changing <= to < only changes equality. Equal finite period endpoints have zero duration and fail the mandatory 86,400,000 ms check. Other endpoints follow the same branches. Error wording changes only for equality; no public decision/class/name changes."],
  [1604,33,"BlockStatement","{\n    throw new VerificationError(\"receipt.checkpoint period_end must be after period_start\");\n  }","{}","equivalent","Deleting the order-check throw cannot accept non-increasing endpoints: the next duration predicate rejects zero or negative duration with VerificationError. Finite parsed Date values and exact one-day duration are still enforced."],
  [1696,9,"StringLiteral","`checkpoint member ${JSON.stringify(receipt.receipt_id)} falls outside checkpoint period`","``","cosmetic","Only out-of-period error text changes. receipt is from ownReceipts, which snapshotJson validated and cloned before awaits. The unchanged successful verifyReceipt schema guard requires receipt_id to be a primitive string. JSON.stringify therefore cannot call a getter or toJSON here; interval rejection, VerificationError class and name remain unchanged."],
  [1708,7,"StringLiteral","`checkpoint merkle_root mismatch: committed ${context.merkle_root}, got ${root}`","``","cosmetic","Only root-mismatch error text changes. context comes from the owned checkpoint snapshot and merkle_root has already passed the strict primitive-string root guard. root is a locally computed primitive string. Both interpolations are free of caller callbacks, and comparison/rejection/class/name are unchanged."],
  [1729,20,"Regex","/^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$/","/^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z/","equivalent","The original string type guard remains. With the start-anchored four-digit-year pattern, removing only the end anchor can admit an extra suffix, but every successful native Date must still have d.toISOString() === s. A four-digit-year ISO output ends exactly at the matched Z; any suffix therefore rejects. Non-string inputs follow the identical short-circuit/message path. This proof does not cover the start-anchor mutation, which admits expanded years."],
  [1767,9,"ConditionalExpression","k.activeUntil !== null && k.activeUntil <= k.activeFrom","false","equivalent","The mutated empty-window predicate is false. Earlier guards require finite Date activeFrom/activeUntil. If activeUntil <= activeFrom, every finite issuedAt either precedes activeFrom (line 1770 rejects) or is >= activeFrom >= activeUntil (line 1773 rejects). No receipt can be accepted through the empty window; only human error text can differ."],
  [1767,35,"EqualityOperator","k.activeUntil <= k.activeFrom","k.activeUntil < k.activeFrom","equivalent","Changing activeUntil <= activeFrom to < only affects equal finite endpoints. Any issuedAt is either below activeFrom or at/after activeUntil when those are equal, so one of the following validity guards rejects with VerificationError. Valid nonempty windows are unchanged."],
  [1767,66,"BlockStatement","{\n      throw new VerificationError(\"selected public key active window is empty\");\n    }","{}","equivalent","Deleting the empty-window throw does not remove subsequent activation/retirement checks. Their union rejects every finite issuedAt whenever activeUntil <= activeFrom. Earlier selected-Date guards remain intact. This is result/class/name equivalence, not a proposal to remove the boundary defense."],
  [1781,20,"ConditionalExpression","k.activeUntil === null","true","equivalent","The selected key is an owned structuredClone snapshot; prior finite-Date/window/issued-at checks are complete before this private copy is returned. The sole findKey caller verifyReceipt consumes only publicKeyBytes for fingerprint/import/signature verification and never exposes or reads the returned activeUntil. Replacing only the return-copy null predicate skips a pure native Date read on owned data, changes no caller object, and preserves every public result."],
  [1892,25,"StringLiteral","\"key must be a Uint8Array\"","\"\"","cosmetic","Only the direct plain TypeError message changes; the key type guard, exception class/name and all HMAC results remain unchanged."],
  [1897,7,"ConditionalExpression","typeof fieldName !== \"string\"","false","equivalent","The private HMAC_REF_FIELDS Set contains only four primitive strings. Native Set.has performs no coercion and rejects every non-string, so the remaining membership guard raises the same RangeError without reading input properties."],
  [1901,25,"StringLiteral","\"value must be a string\"","\"\"","cosmetic","Only the direct plain TypeError message changes; the value type guard, exception class/name and every HMAC result remain unchanged."],
  [1904,26,"StringLiteral","\"value contains an unpaired Unicode surrogate\"","\"\"","cosmetic","Only the direct plain RangeError message changes; ill-formed Unicode is still rejected at the same branch with the same class/name."],
  [1911,28,"StringLiteral","\"ascii\"","\"\"","equivalent","The membership guard restricts fieldName to four ASCII primitive strings. Node Buffer.from with an empty encoding selects UTF-8; ASCII and UTF-8 encode each permitted field into identical bytes."],
  [1913,24,"StringLiteral","\"utf-8\"","\"\"","equivalent","The value type and well-formed Unicode guards remain. Node Buffer.from with an empty encoding selects the same UTF-8 encoder as utf-8, preserving every framed value byte and HMAC result."],
  [1917,5,"StringLiteral","\"ascii\"","\"\"","equivalent","This locally constructed expected reference contains only the ASCII hmac-v1 prefix and 64 lowercase SHA-256 hex digits. Node's empty-encoding UTF-8 default yields the same bytes as ascii."],
  [1919,32,"StringLiteral","\"ascii\"","\"\"","equivalent","The preceding unchanged type guard and anchored regex restrict ref to a primitive ASCII string. Node's empty-encoding UTF-8 default yields the same reference bytes as ascii."],
  [1922,10,"ConditionalExpression","expected.length === got.length","true","equivalent","The unchanged anchored regex requires exactly hmac-v1 plus 64 ASCII hex digits. Both fresh local buffers are therefore 72 bytes; removing their always-true length equality does not change timingSafeEqual or any result."],
].map(Object.freeze));
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
function losslessEvidenceMatched() {
  try {
    return hash(JSON.stringify(LOSSLESS_EVIDENCE_PATHS.map((name) =>
      [name, fs.readFileSync(path.join(REPO_ROOT, name), "utf8")]))) === LOSSLESS_EVIDENCE_SHA256;
  } catch (error) {
    if (error.code === "ENOENT") return false;
    throw error;
  }
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
    rawTrusted: hash(ast.text) === RAW_VERIFIER_EVIDENCE_SHA256,
    losslessTrusted: losslessEvidenceMatched(),
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
  if (proof.rawTrusted) {
    for (const [line, column, mutator, original, replacement, classification, reason, lossless] of REVIEWED_MUTATIONS) {
      if (mutant.location.start.line === line && mutant.location.start.column === column
        && mutant.mutatorName === mutator && mutant.replacement === replacement
        && range.end - range.start === original.length && ast.text.slice(range.start, range.end) === original
        && (!lossless || proof.losslessTrusted)) {
        return { classification, reason };
      }
    }
  }
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
    exactEvidenceSourceMatched: proof.rawTrusted, losslessEvidenceMatched: proof.losslessTrusted,
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
module.exports = { classifyReport, TIMEOUT_CONTEXT_PATHS, LOSSLESS_EVIDENCE_PATHS };
