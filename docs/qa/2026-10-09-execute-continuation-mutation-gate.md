# Execute continuation 4.3.1: fresh mutation evidence

The local release preparation tested the current uncommitted feature source.
Receipt wire version remains 4. The TypeScript verifier source has SHA-256
`806acdd02c4e0c53eea84410aa621fba6e7bd23eeaaf6bc25d21d530117e6a53`.
The ordered 14-input test context has SHA-256
`e41a572145a7fde4a1a573abe7571bf10f070a275b5841d6de724f526ac1c9b0`.

## Full TypeScript gate

The full native run measured 2,446 mutants. It resumed only this fresh run's
source-matched partial checkpoint, not a historical release report. The
eight-worker pass produced 28 timeouts. Those timeout entries were omitted
from a separate retry cache and measured again at the normal two-worker
setting. Stryker retained 2,418 already measured outcomes and produced another
full report. No outcome status was manually changed. The 18 resource-related
timeouts became surviving mutants, not detected faults.

The final native report has 2,209 Killed, 227 Survived and ten Timeout, with no
other statuses. The unchanged production classifier accepts the ten freshly
proved loop faults: `(2209 + 10) / 2446`, or **90.71954210956665%**, above the
raw 80% floor. All 227 survivors remain unresolved test gaps in the denominator.
There are no fatal blockers, cosmetic exclusions or equivalent exclusions.

The full runner used `stryker.conf.cjs`, `--reporters json` and
`--timeoutMS 20000`, with concurrency eight and then two for remeasurement.
The exact command, native reports and classifier output remain in
`/private/tmp/allowly-native-release-checks.eiK9eG`.

## Fresh timeout trials

Each exact timeout fault was applied to two independently built copies of the
current files. Every mutation compiled after installed Stryker 10.0.0
`disableTypeChecks` preparation. Each fault then exceeded a 20,000 ms limit in
both trials; `SIGKILL` targeted only the owned Node child. Four independently
built correct copies passed all four repository-owned Node suites. Node was
24.18.1. The [compact trial record](2026-10-09-execute-continuation-timeouts.json)
retains exact identities, raw/prepared hashes, commands, exits and durations.
Its references hash the complete private trial records and the native report.
Historical full-source QA reports were not changed or inherited.

## Python scope and release limits

The Python runner now includes canonical `policy.py` in its critical-source
list, with a regression test. Fresh mutation checking of the exact changed
lines killed all 11 mutants using the complete vector, exception, pseudonym,
SEAL and policy runner. No survivor was exempted. This is a changed-lines
Python result, not a claim about the entire Python mutation corpus.

This evidence does not claim a commit, pre-push run, GitHub CI, registry
publication or production deployment. Those release gates remain active.
