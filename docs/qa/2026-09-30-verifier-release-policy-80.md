# Verifier release policy: raw 80% floor

The human approved a raw mutation score of at least 80% and asked to continue
the release using the completed verification. No further survivor-test repair
round is required by this policy. This replaces the older gate requirement
that every survivor have an individually proved exemption.

The TypeScript report gate counts only Killed mutants and independently proved
Timeout detections in the numerator. Every raw mutant stays in the denominator,
including reviewed cosmetic and equivalent survivors. The score must meet 80%
before rounding. Stryker's breaking threshold is also 80. Report-supplied
thresholds cannot lower the release floor.

Survived statuses are preserved. Unresolved survivors remain visible as
accepted test gaps when the report meets the floor. NoCoverage, CompileError,
RuntimeError, Ignored, Pending and unproved Timeout statuses still block. The
gate also refuses malformed reports, unknown statuses, duplicate IDs or exact
mutation identities, and a report source that differs from the checked-out
verifier. Ordinary test failures, missing fresh runner reports, and nonzero
runner exits cannot pass. Python mutation policy is unchanged in this pass.

The old comparator-106 equivalence exemption is withdrawn. The replacement
`left.length + right.length` returns 64 on equal 32-byte inputs, including
self-comparison, where the correct comparator returns zero. This violates the
comparator laws, so the earlier portability argument is not sufficient. It is
now an unresolved survivor accepted only under the approved score policy.
Its raw status is not rewritten, and it is not called harmless or equivalent.

## Existing final report under the approved policy

Applying the changed read-only classifier to the existing immutable final
report returned exit zero, with no fatal blockers:

```text
Raw score: (2,206 Killed + 10 proved Timeout detections) / 2,441 = 90.78246620237607%
Required floor: 80%
Raw Survived: 225 (85 reviewed cosmetic, 82 reviewed equivalent, 58 unresolved)
Fatal blockers: 0
```

All 225 survivors remain in the raw denominator. The 58 unresolved test gaps
accepted for this release are the report identities:

```text
53, 54, 60, 61, 63, 68, 106, 118, 236, 238, 275, 277, 284, 293,
421, 581, 582, 583, 584, 585, 588, 590, 740, 791, 820, 1224, 1225,
1257, 1267, 1294, 1316, 1317, 1340, 1342, 1343, 1345, 1349, 1351,
1353, 1354, 1489, 1713, 1716, 1718, 1720, 1739, 1815, 1817, 2295,
2461, 2472, 2479, 2485, 2494, 2512, 2525, 2526, 2527
```

This is accepted test risk, not a claim that these changes are equivalent or
that the verifier has no remaining test gaps. The classifier's
`unresolvedSurvivors` output retains each ID, location, mutator, replacement
and raw Survived status separately from its fatal `blockers` output.

## Reviewed timeout evidence rebind

The completed two-trial evidence in
[`2026-09-30-verifier-integrated-timeouts.json`](./2026-09-30-verifier-integrated-timeouts.json)
remains the record of the original trials. All ten exact mutants compiled and
timed out twice under the recorded 20,000 ms limit; the separate correct copies
passed both trials. Each proof identifies the exact location, mutator,
replacement and infinite-loop cause. The original reasons keep their original
context hash and observations.

This is one explicit reviewed rebind of
[`mutation_timeout_proofs.json`](../../scripts/mutation_timeout_proofs.json),
not an automatic refresh. Read-only comparison against the frozen corpus
`/private/tmp/allowly-verifier-integrated.q01xCy/native` found all 14 context
inputs identical before the policy edit. After the edit, the sole context diff
is:

```diff
   thresholds: {
-    break: 100,
+    break: 80,
   },
```

The breaking threshold decides the runner's final score exit. It does not
change instrumented verifier code, compiler preparation, test inputs, build
or test commands, mutation identities, coverage settings, concurrency, timeout
limits, or loop behavior. The completed trials therefore remain applicable to
these exact loop detections. Only the manifest's context fingerprint changes;
future context changes still invalidate the proof and need separate review.

| Fingerprint | SHA-256 |
|---|---|
| Original 14-input context | `aeadc2a678817243c2e07a305d01776e43d3adbe190a8877afceddf6f3548dda` |
| Reviewed threshold-only context | `1d3b4a921ab17a1bea7ad42be3cde42fef93d94f72ba18b0dd1b67d70346e55a` |
| Original Stryker config | `590a273ca4c770f8ddec0ae3c97d5f4854ee0830b6ab98b417f561ade610d36e` |
| Reviewed Stryker config | `9c24c1ec337dffb8ec0432ba55cdc161ccda0db5e6df7f4ff17e0469c17bf419` |
| Unchanged verifier source | `407d7a2d759706b8fb3f005c61983575d58a891d8b4b0d5e1cffae4240b72691` |
| Existing final native report | `321ec92d98cea87b9c52087a4f315e268f1470148f769a0cee22fa05ffdcf11e` |

## Verification boundary

This policy change reuses the completed native run and ordinary verifier test
results described in
[`2026-09-30-verifier-merge-review.md`](./2026-09-30-verifier-merge-review.md).
No ordinary test suite, mutation run, or timeout probe was repeated. New and
updated synthetic gate fixtures are left to the mandatory GitHub checks; their
presence is not a claim that the changed policy has already passed those checks.
Production verifier source, runtime test assertions, fixtures, dependencies and
lockfiles are unchanged by this policy change.

Applying the new classifier once to the existing immutable native report
returned exit 0: 2,216 detected out of 2,441 total, or 90.78246620237607%,
above the 80% floor. Raw outcomes remain 2,206 Killed, 225 Survived and ten
independently proved Timeout detections. The separate report categories are
85 cosmetic, 82 equivalent and 58 unresolved survivors, including 106; there
are zero fatal blockers. The prior review lists the other 57 exact unresolved
identities. This is policy evaluation of existing results, not a new test run.

The operator explicitly requested no repeated local verification. The release
push uses the existing `ALLOWLY_SKIP_MUTATION_GATE=1` option to reuse this
completed native run. The normal commit review and required GitHub CI/review
remain active; no hook or protected GitHub rule is changed.

## Commit review decisions

Keep the staged code unchanged after reviewing the four Ponytail suggestions:

- Keep the default `identities` set: the existing timeout-manifest validator
  calls `validateMutant` with three arguments; report validation supplies four.
  Removing the default without updating that live caller would break proof
  validation. The two modes are used, not speculative flexibility.
- Keep the short comparator comment. It records the withdrawn equivalence
  argument where exemptions are considered, preventing an unsupported proof
  from being restored without understanding this approved policy decision.
- Keep all six bad-status cases at an exactly passing 80% raw score. The later
  status/timeout tests do not replace that boundary: a zero-score report fails
  for its score even if a fatal-status guard is accidentally removed.
- Keep the threshold assertions beside exact acceptance, rounded-below-floor
  refusal, reviewed identities and validated report thresholds. They state the
  fixed operator policy across distinct boundaries. No production verifier
  assertion or gate boundary check is removed to shorten the release diff.

Finish via the hook's documented unchanged-code-diff retry, not `--no-verify`.
