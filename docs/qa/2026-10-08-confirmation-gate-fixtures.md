# Confirmation release: mutation-gate fixture repair

The 4.3.0 confirmation change added an event-table line, changed the event
diagnostic, and advanced the package metadata. Twelve of the 31 classifier
tests still assumed that the live source, source locations, and dependency lock
were the immutable 4.2.0 proof inputs. Their failures correctly showed that the
old proofs did not apply to the changed checkout.

The repair freezes the reviewed source and lock as byte-exact test data from
commit `6489e63`. Existing historical proof tests run the unchanged production
classifier in a disposable context with those inputs and the installed parser
bytes. All 31 existing assertion sets remain. Separate live-source and real
CLI assertions reject inherited exemptions and historical reports.

No production classifier, proof hash, mutation catalog, timeout proof,
threshold, hook, dependency, lock, or verifier behavior changes in this repair.
Historical source is test data, not an executed verifier. The 80% raw floor and
all fatal-status blockers remain unchanged.

## Verification

- Classifier fixtures: 33/33 pass, including all previously failing cases.
- Native mutation-runner argument/exit regressions: 9/9 pass.
- Current TypeScript verifier build, receipt, policy, browser, HMAC and SEAL
  vectors pass.
- Feature-family contract lint passes all 16 checks.
- The live-source assertion passes in an untouched disposable copy and fails
  when another disposable copy forces normalized-source proof matching to
  `true`. The original source worktree is never mutated.
- Independent read-only review found no removed/weakened assertions or changes
  to production gate policy.

This repairs the classifier-test gate. It is not a new Stryker run, a passed
Python mutation gate, a package publication, a main merge, or a deployment.
The separate Python-version mutation issue still needs resolution before the
confirmation release can pass the full pre-push gate.
