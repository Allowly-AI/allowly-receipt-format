# Confirmation release: fresh mutation evidence

The native runner tested committed source `a45266c95568702ce3a00bbaad781b0c77fedd97`
in a disposable clone. Python mutation checking passed. The TypeScript run
completed in 28 minutes and 3 seconds with 2,445 raw mutations:

- 2,208 Killed;
- 227 Survived, retained as unresolved test gaps in the raw denominator;
- ten Timeout, with no other statuses.

Stryker returned zero at its 80% threshold. The combined native gate initially
returned one because the prior timeout manifest belonged to the old source and
context. That refusal was correct. No old proof or survivor exemption was
automatically transferred to this release.

## Fresh timeout trials

Each exact native Timeout was applied separately to disposable copies of the
current committed source. Every copy compiled after the installed Stryker
10.0.0 `disableTypeChecks` preparation, with its default null parser plugins.
Each mutant then timed out in two independent trials, with a 20,000 ms limit
and `SIGKILL` sent only to the owned Node child. Two separate correct copies
passed the four repository-owned Node suites. Node was 24.19.0.

The [trial record](2026-10-08-confirmation-timeouts.json) retains each identity,
raw and prepared source hashes, test commands, exits, signals, and durations.
Runtime stdout/stderr is omitted from this compact record; the complete local
probe record has SHA-256
`3e828b789972df0be98ffcd440c7aac0b7335db163f5eb5f99dee63011d3dd61`.
The exact report and frozen context were checked before every probe and at
completion. A separate read-only review checked all ten loop causes.

These are detected faults, not harmless survivors. The new manifest records
each cause individually. In particular, the backward comparator requires a
matching first byte, and the backward inner JSON scanner has an escaped-string
path; neither claim says all input strings or byte arrays loop.

| Evidence | SHA-256 |
| --- | --- |
| Unprepared verifier | `34f80c55f2e508cf423f2dc83fbe70bbc07ecbc6d48b00730088a871a0f9244f` |
| Native Stryker JSON report | `ef90edb906f0c8556be2309a9bf3136ee315098f94c244a02b0a3b5b31e29452` |
| Ordered 14-input verification context | `9347cb4729244a77553d3484fc35d5b3277d9eda2b673dc795b349dc0186c11b` |

## Gate result and limits

Applying the unchanged production classifier to the preserved fresh report and
newly proved manifest returned zero: `(2,208 + 10) / 2,445`, or
`90.7157464212679%`, with zero fatal blockers. All 227 survivors remain visible
as unresolved gaps; none is excluded from the denominator or called harmless.
The raw 80% floor, fatal-status rules, source binding, classifier pins, runtime
assertions, mutation configuration, dependencies, and hooks were not weakened.

This records a completed native run and separate fresh proof validation, not a
claim that a subsequent pre-push run, GitHub CI, publication, or production
deployment has completed. The normal pre-push and required CI remain active.
