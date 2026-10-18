# Observe assessment profile v1

Status: source-distributed Observe contract. This profile does not change receipt
wire 5 or the published receipt-verifier package API. The separate reference
tools live in `assessment/`. They reuse the maintained canonicalizer and key
document parser. They are not authorization receipt parsers.

An assessment records an asynchronous evaluation of copied activity. It never
grants authority, dispatches an action, or resolves a confirmation. The signature
authenticates recorded claims and their bindings. It does not prove source truth,
model accuracy, email delivery, legal agreement, or complete capture of activity.

## Envelope and trust

The original flattened JWS has exactly `protected`, `payload`, and `signature`,
each unpadded canonical base64url. Its canonical protected header has exactly
`alg: EdDSA`, nonempty `kid`, and **`typ: allowly-assessment+jws`**. Receipt JWS
types must fail assessment verification and assessment types must fail receipt
verification. Canonicalization and Ed25519 signature bytes use the existing
receipt-format canonical JSON rules, without adding receipt fields.

The verifier requires a caller-configured workspace ID, Langfuse project ID,
and trusted Ed25519 key fingerprints obtained over an authenticated channel.
Neither a bundled key document nor a payload-selected workspace establishes
trust. The selected key must cover `issued_at`; revoked/expired windows remain
enforced. Header and payload JSON must be canonical, rejecting duplicate fields,
alternate base64 spellings, extra fields, floats and unsafe integers.

## Frozen payload

The payload has exactly:

`schema_version`, `assessment_id`, `workspace_id`, `job_id`, `project_id`,
`agent_id`, `action`, `issued_at`, `policy_ref`, `mapping_version`,
`reviewer_version`, `engine_version`, `source`, `source_sha256`, `request_sha256`,
`facts`, `missing_information`, `context`, `policy_eval`, `assessment_status`,
`application_reported_execution`, `mode`, and `intervention`.

- `schema_version` is `allowly.assessment.v1`; `mode` is `observe` and
  `intervention` is `none`. There is no authorization ID, lifecycle event,
  top-level authorization decision, execution authority, or approval token.
- `policy_ref` has the exact immutable policy ID, positive integer version and
  lowercase 64-hex definition digest. `engine_version` is `sha256:<64 hex>`.
- `issued_at` is a real UTC millisecond timestamp, at most five minutes in the
  future. Source `observed_at` and `captured_at` use the same timestamp profile.
  An observation may precede capture arbitrarily; it may not follow capture by
  more than five minutes. Capture may not be more than five minutes in future.
- `reviewer_version` identifies provider/model and prompt/schema revision.
  `request_sha256` commits the exact canonical internal request; this does not
  make its contents independently true.
- `source` retains `project_id`, `trace_id`, `observation_id`, `observed_at`, and
  `captured_at`. The accompanying `source_snapshot` contains those fields plus
  `content`, a bounded object of at most 32 string values. Its canonical bytes
  must match `source_sha256`. The full source is at most 64 KiB.
- `application_reported_execution` is `sent`, `failed`, or `unknown`. It records
  the application's report, independently of the policy result.

## Supported evidence mapping

The one-action mapping `medical-external-v1` supports two facts:
`contains_medical_information` and `external_recipient`. Each fact is null or
exactly `{value: boolean, citations: [...]}`. A present fact requires 1–8
citations with exactly `field`, `start`, `end`, and `quote`. Offsets are Unicode
code points, not UTF-16 units or UTF-8 bytes. The nonempty quote must equal the
specified slice of a captured source string. A false fact needs evidence too.
Medical citations refer to `body`; external-recipient citations refer to `recipient`.
Null is not false. `missing_information` names precisely the absent facts,
without duplicates. The signature records the reviewer's interpretation of
these passages; a matching quote does not prove the interpretation correct.

With both facts present, `context` has exactly one boolean,
`medical_external_disclosure`, equal to their AND. Existing BasicPolicy rule
conditions still mean OR; this profile does not change that engine behavior.
The runtime loads the exact workspace/agent/action policy edition and evaluates
the derived context with real OPA. This demo accepts allow/deny policy actions
only, with no execution guards or executable grants.

`policy_eval` has the existing `input_sha256` and complete `allowly.basic.v1`
result (`profile`, `status`, `decision`, `target`, `matched_rule_id`,
`evaluated_fields`). A completed `deny` yields `violation_detected`; a completed
`allow` yields `no_violation_found`. Targets are null in this allow/deny profile.
The reference verifier authenticates recorded OPA evidence; independent replay
also requires the retained definition and exact evaluation input.

With missing facts, context is empty, evaluation is null, and status is
`insufficient_evidence`. Unsupported work, failed models/OPA, and unfinished jobs
remain `not_assessed` in the application, with a reason, rather than fabricated
successful evidence. A pending signature does not mean verified.

## Persistence and human judgment

One workspace/job identity binds an immutable request and assessment. A changed
body under that identity fails; retries return the retained result. Signer
retries sign the same frozen payload without rerunning the model. Changed
policy/reviewer/mapping inputs create a new assessment.

Human Agree, Disagree, or Needs investigation judgments are separate append-only
records. They cannot rewrite the signed assessment, policy, reported execution,
or absence of intervention. Capture failures and known coverage gaps remain
visible. The system cannot infer an entirely missing event without independent
expected-source evidence and must not claim a complete history.
