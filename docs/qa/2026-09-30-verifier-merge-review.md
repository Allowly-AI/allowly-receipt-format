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
