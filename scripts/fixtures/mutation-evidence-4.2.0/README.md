# Historical mutation-proof inputs

These are byte-exact test data copied from verifier release 4.2.0, commit
`6489e63`, before the confirmation-resolution change. They are not an active
verifier, dependency lock, or new production proof.

The gate's existing reviewed identities and source/dependency fingerprints
refer to these bytes. Positive historical proof tests use a disposable context
containing the unchanged production classifier and these inputs. No test runs
this verifier source or installs this lock.

| File | SHA-256 |
| --- | --- |
| `verifier.ts.txt` | `407d7a2d759706b8fb3f005c61983575d58a891d8b4b0d5e1cffae4240b72691` |
| `package-lock.json.txt` | `5c8d37baaa5d0b491dcd87d65f829caa049003fe1d8a39d4a7d7d55956ae777b` |

Separate live-source and CLI tests reject old reports and refuse to transfer
these exemptions to the current verifier. The raw 80% score, fatal-status
rules, exact source binding, and production proof hashes remain unchanged.
New source or dependency proofs still require their own review; never refresh
these fixtures or production pins just to make a test pass.
