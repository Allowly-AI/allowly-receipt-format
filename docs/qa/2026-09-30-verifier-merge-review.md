# Five-worker verifier integration review

## Policy worker merge

Worker commit: `4bff4dae5ece472353f56c8633a69c964d5d315e`.

Ponytail suggested grouping repeated JSON evidence and removing an unused
generator body from the callable trust-set fixture.

- Keep the self-contained mutation records. Each record includes its exact
  identity, source argument, and observed result for independent review. Group
  references would require readers to reconstruct that evidence. This data is
  an audit record, not runtime code.
- Simplify `callablePins` to an ordinary callable. Its explicit `has`, `size`,
  and `Symbol.iterator` properties remain unchanged, as do every assertion and
  expected result. The removed generator body was never called.

The worker's recorded probe hashes describe its original commit. The integrated
corpus has this small follow-up and must receive new full-gate evidence before
release. Production verifier code, dependencies, and mutation thresholds remain
unchanged.

The second review proposed keeping only summary/unresolved ledger entries and
fewer malformed-list/action fixtures. Reject these cuts. The full ledger is the
stored evidence for each claimed detection or equivalence candidate; temporary
probe files alone are not the committed audit record. The matrices cover
different primitive types, array shapes, absent values, and invalid constraints.
Removing them would narrow the proven input boundaries during a test-quality
repair. All original assertions and the new expected outcomes remain intact.

After the helper simplification, the normal integrated `npm test` command passed.
The unchanged code-diff retry records these rejections through the existing
Ponytail hook; no hook or release gate is bypassed.

## Receipt worker merge

Worker commit: `4f851db05d6a8bb0e202d73a96f3c515e9bfa53b`.

Ponytail suggested moving detailed local probe output into a CI artifact. Reject
that cut for this merge: these probes ran locally, and no durable CI artifact
has replaced the committed evidence. Keep exact mutation identities, hashes,
commands, outcomes, and the source arguments needed to review the proposed
exclusions. Production code and every test assertion remain unchanged.

## SEAL worker merge

The worker could not create its Git index lock in its restricted sandbox. The
integrator staged only the two tested owned files and committed them normally
on `fix/verifier-seal-20260930`: `d3de670`.

Reject the three Ponytail cuts for this merge:

- Keep the local exact-probe evidence. The generated Stryker report does not
  contain these independent before/after commands, observations, or source
  arguments and is not a replacement for this committed record.
- Keep the current/renewed authorization pair as an adjacent positive control
  and changed-input check for the authorization-independent SEAL contract.
- Keep the common rejection tables through both public methods,
  `verifySealJson` and `verifySealValue`. They promise the same result fields
  through different input boundaries; do not assume shared internals are a
  substitute for checking both public contracts.

All tested assertions, expected results, and production source stay unchanged.
Finish the merge through the hook's documented unchanged-diff rejection path.

## Checkpoint and key worker merge

The worker's sandbox also blocked its Git index lock. The integrator committed
only its two owned, tested files on `fix/verifier-checkpoint-20260930`:
`435bf6f`.

Keep the portable key-comparator laws and native default-sort positive control.
Normalize numeric zero in the new assertions so a valid comparator may return
either positive or negative zero. This does not change ordering, antisymmetry,
or self-equality requirements. Every original assertion remains intact.

The integrated tests need fresh full-gate and timeout evidence. In particular,
mutant 100's new timeout is not accepted solely from the worker's observation.

Reject the two Ponytail cuts for this merge. No durable CI artifact replaces
the committed local before/after evidence. Keep the small explicit self-equality
and reversed-sign assertions alongside the expected-order assertion: they make
the distinct comparator laws and failure diagnostics clear. These are bounded
test checks, not production abstractions. The normal combined `npm test` passed
after the zero normalization and its explicit TypeScript number annotation.

## HMAC and proof-rule worker merge

The worker's sandbox blocked its commit lock. The integrator committed only
its four tested owned files on `fix/verifier-proof-hmac-20260930`: `a5a3d91`.
The committed worker ledger describes its original 143 proposed new exact
exclusions; it is historical evidence, not authority for the final gate.

Independent integration review rejects these eleven new equivalent proposals:
`1224, 1225, 1267, 1294, 1316, 1317, 1340, 1343, 1345, 1349, 1351`.
The signed JSON snapshots do not prove that inherited policy lists/arrays are
immutable, authenticated scalars. Such arrays can contain caller-owned getters.
Remove these exact entries and their new acceptance fixtures, add them to the
new refusal fixtures, and adjust only the new synthetic table-count assertions.
Every original gate-test body and assertion stays unchanged. The integrated
new exact table has 132 entries: 47 cosmetic and 85 equivalent.

### Confirmed inherited-policy counterexample

Source SHA256: `407d7a2d759706b8fb3f005c61983575d58a891d8b4b0d5e1cffae4240b72691`.
Immutable report SHA256: `d95ca21a3370ec1ba564481c6af08c66e9b841aa5983f5165f69e197cc4f5ea4`.
Report mutant 1294 replaces the exact source slice at 1025:10–66,
`typeof value === "number" && Number.isSafeInteger(value)`, with
`typeof value === "number" || Number.isSafeInteger(value)`.

The policy worker ran an inline Node module without writing files. It verified
the raw source hash, selected the exact immutable report mutation, and used
installed TypeScript `transpileModule` (ES2022/ESNext) to import correct and
changed modules through separate base64 data URLs. It resolved `canonicalize`
and `lossless-json` to installed file URLs. Fixture shapes came from the first
matched shared policy vector, not from the verifier's output. A fresh Ed25519
key signed independently JCS-canonicalized payloads; no production keys changed.

Signed action overrides: context `{risk: 1}` and recorded evaluation
`{matched_condition: null, field_value: null}`. Signed creation overrides:
context `{actions: [{name: action.action, constraints: {}}]}`. After signing,
the probe set a configurable process-local data property
`Object.prototype.deny_when = [{field: "risk", lt: 0.5}]`, then called each
module's public `verifyPolicyEvaluation` with the vector workspace/clock and
the independently generated key's trusted fingerprint. A `finally` restored
the prior prototype descriptor. Correct source returned `not_checked`,
`unsupported_policy`, and calculated null. The exact changed version returned
`matched`, `matched`, and a calculated no-match evaluation. This disproves
1294's proposed authenticated-numeric-domain proof. The other ten removals are
conservative deferrals, not ten independently reproduced production bugs.

### Older comparator exclusion

The read-only receipt/key cross-check found no further unsound new exclusions
in its scope. It did identify an unproved older exemption, mutant 106: changing
the equal-byte comparator return from zero to 64 violates comparator
self-equality. ECMA-262 makes an inconsistent comparator's entire sort order
implementation-defined, so the old argument about only identical hashes
reordering is insufficient. The integrator requested human review before
changing those existing gate-test expectations, as required by `allowly-qa`.
Do not treat the concern as resolved or publish based on that exemption.

### Final Ponytail decisions

Reject all seven proposed cuts for this bounded repair merge:

- Keep the committed worker evidence. No durable build/CI artifact replaces the
  local exact probes, source arguments, counterexamples, or commands.
- Keep per-trial timeout records. Each is an independent observation with its
  exact command, outcome, signal, elapsed time, and source binding. Compacting
  them is an optional evidence-schema redesign, not a release blocker fix.
- Keep the fixed installed-parser call-chain hash. Lockfile integrity pins an
  installation artifact, not the live installed module bytes on which these six
  proofs depend. The additional hash fails closed on missing/changed modules;
  it does not replace `npm ci`. QA forbids changing dependencies/locks here.
- Keep independent gate and fixture identities copied from the immutable
  report. Sharing one mutable manifest would make the synthetic acceptance
  oracle repeat the classifier's own definitions. The gate takes no runtime
  ledger/report/CLI-supplied exemption authority.
- Keep individual timeout reasons within the existing strict manifest schema.
  Hoisting them requires a new schema and changes existing rejection tests;
  the small ten-entry record is not runtime product complexity.
- Keep distinct changed-caller, guard, private-result, public-metadata and
  public-result refusal fixtures. They express separate safety obligations and
  protect against future proof-normalization shortcuts, not just a generic
  one-byte hash mismatch.
- Keep the real signed positive receipt and changed-signature negative beside
  the constructor checks. Public verification must actually raise the promised
  exception, not merely expose a constructor with that name. The signer is
  independent and uses fresh test-only keys.

Combined `npm test` and all 28 classifier tests passed after the eleven
exclusion deferrals and the ten-entry timeout renewal. Original 21 test bodies
were mechanically compared to base `6fc4443` and are byte-for-byte unchanged.
The integrated verification context matches the frozen timeout corpus:
`aeadc2a678817243c2e07a305d01776e43d3adbe190a8877afceddf6f3548dda`.
Finish through the hook's normal documented unchanged-code-diff retry.

### Additional callback-domain deferrals

The final read-only policy review also defers new proposed exclusions 1342,
1353 and 1354. These replace the private scalar-key strings `null:`, `true`
and `false` with empty strings. An inherited caller-owned policy array can
provide its own `.map` method at verifier line 985, receiving the private
`typedPolicyScalarKey` callback. A custom `.filter` result can expose the same
callback at line 1005. Those methods can inspect its returned strings and
branch or throw. The proposed unobservable-private-result argument therefore
does not establish equivalence across the admitted input domain.

This is a conservative source-based refusal, not a new runtime probe or a
claim of three independently reproduced production bugs. The remaining
scalar/type callback rules preserve the boolean outputs under their unchanged
guards; the review identified no further affected rows. The final new exact
table has 129 entries: 47 cosmetic and 82 equivalent. The worker's original
143 proposals and the previous 132-entry merge remain historical evidence.
The three removed entries now have explicit rejection fixtures. No production
source, runtime test, dependency, lockfile, mutation scope or threshold changes.

## Final integrated native run

The repository-owned full-file TypeScript mutation gate ran on frozen commit
`e1cfcef0f7074dce52c1203f0b50f43c5e0d4246`. It finished on 2026-10-01 at
05:17:23 UTC in 22 minutes and 35 seconds. The initial restricted invocation
could not bind Stryker's local logging port and produced no mutation results;
the unchanged command then ran with approved network/sandbox access:

```text
/private/tmp/allowly-identity-release-mutation-20260930/bin/python -u -c 'import sys; from scripts.mutation_gate import typescript_gate; sys.exit(typescript_gate(["verifiers/typescript/verifier.ts"]))'
```

All 2,441 exact mutants ran without incremental results. The raw breaking
threshold stayed 100, concurrency stayed two, timeout stayed 20,000 ms, and
the production source, installed dependencies, lockfile and Stryker scope
stayed unchanged. The native dry run and full `npm test` passed, including the
generated browser adapter. Every invocation generated fresh ephemeral signing
keys where the new fixtures require them; production keys and published
historical vectors were not rotated or rewritten.

Raw report SHA-256:
`321ec92d98cea87b9c52087a4f315e268f1470148f769a0cee22fa05ffdcf11e`.
The raw report remains at
`/private/tmp/allowly-verifier-integrated.q01xCy/native/verifiers/typescript/reports/mutation/mutation.json`.
Production source SHA-256 remains
`407d7a2d759706b8fb3f005c61983575d58a891d8b4b0d5e1cffae4240b72691`.

An independent read-only comparison confirmed identical IDs and all 2,441
exact identities (location, mutator, replacement), with no duplicates, added
or missing mutations, source differences, or unexpected raw status changes.
All 1,978 previously Killed mutations stayed Killed, all nine previous Timeouts
stayed Timeout, 228 Survived mutations became Killed, and only mutation 100
changed from Survived to Timeout. No previous runtime detection was lost.
Sorted exact-identity inventory SHA-256 is the same in both reports:
`c801a474a2ff0ff5e67b1d7b0a7900cea06f9eb464af370d4785801276cd3f7f`.
Baseline raw report SHA-256:
`d95ca21a3370ec1ba564481c6af08c66e9b841aa5983f5165f69e197cc4f5ea4`.

| Raw outcome | Before this five-worker pass | Final native run |
| --- | ---: | ---: |
| Killed | 1,978 | 2,206 |
| Survived | 454 | 225 |
| Timeout | 9 | 10 |
| NoCoverage / RuntimeError / CompileError / Ignored / Pending | 0 | 0 |
| Raw score | 81.40% | 90.78% |

Both the native runner and strict classifier return exit code 1. This is a
failed release gate, not a successful publication or a bypassed threshold.
The frozen native invocation's earlier classifier counted 54 unresolved cases.
After the three callback-domain deferrals, the final checked-out classifier at
`d00dfba792dedb583d0ea6b6e9fd71350cb0333b` was run directly against that same
raw report. Its runtime verification context still exactly matches the frozen
run and renewed timeout proofs:
`aeadc2a678817243c2e07a305d01776e43d3adbe190a8877afceddf6f3548dda`.
The classifier-only stricter changes did not alter any of those runtime inputs.

The final classification has 85 cosmetic exclusions, 83 claimed-equivalent
exclusions, ten independently reproduced infinite-loop detections and **57
unresolved survivors**. Raw statuses were not rewritten. The ten exact timeout
IDs are 100, 145, 147, 154, 171, 1421, 1437, 1443, 1456 and 1746; the correct
four-suite corpus completed twice, and each exact mutated version stalled twice.
Missing, mismatched or unexplained timeout evidence still blocks release.

| Remaining area | Count | Exact IDs |
| --- | ---: | --- |
| Receipt / input / base64 / tree / options | 14 | 53, 54, 60, 61, 63, 68, 118, 236, 238, 275, 277, 284, 293, 421 |
| Policy | 25 | 581, 582, 583, 584, 585, 588, 590, 740, 791, 820, 1224, 1225, 1257, 1267, 1294, 1316, 1317, 1340, 1342, 1343, 1345, 1349, 1351, 1353, 1354 |
| SEAL | 8 | 1489, 1713, 1716, 1718, 1720, 1739, 1815, 1817 |
| Key loading / clock | 8 | 2295, 2461, 2472, 2479, 2485, 2494, 2512, 2525 |
| HMAC reference | 2 | 2526, 2527 |

These 57 cases lack a detecting test or a sound individual equivalence proof;
they are not 57 confirmed production bugs. The older comparator exemption 106
is an additional unproved release concern, still awaiting the requested human
review before changing its original test expectations. Its currently counted
equivalence must not be used to justify publication.

After the final three deferrals, main's full TypeScript `npm test` and all 28
classifier tests passed again. The original 21 classifier test bodies remain
byte-for-byte identical to base `6fc4443`. The five branch commits remain
available and all five are merged into local main. Nothing was pushed,
published or deployed in this pass; no GitHub release approval was created.

The bounded QA repair rounds are exhausted. Further survivor-test repairs
require a new approved pass with fresh test signatures and frozen evidence;
do not silently start another repair round or weaken existing assertions.
