# Observe assessment profile v1

This source-distributed profile records an asynchronous evaluation of copied
activity. It does not grant authority or dispatch actions. The maintained tools
in `assessment/` are separate from ordinary receipt wire 5 and its public API.
The signature authenticates recorded claims and commitments; it does not prove
source truth, model accuracy, execution, legal agreement or complete capture.

## Approved contract revision

On 2026-10-18 the maintainer approved a breaking, unpublished policy/evidence
revision without changing package, HTTP, policy, basic, assessment or receipt
version labels. There are no external clients. New writes use policy-defined
evidence; tools do not retain business-specific compatibility branches. Original
signed assessments and published editions remain immutable. Historical vectors
remain in `assessment/vectors.json`; revised vectors are in
`assessment/evidence-vectors.json`. See `GOVERNANCE.md` for the bounded exception.

## Envelope and trust

The flattened JWS has exactly `protected`, `payload`, and `signature`: original
canonical, unpadded base64url strings. The canonical protected header has exactly
`alg: EdDSA`, a nonempty `kid`, and `typ: allowly-assessment+jws`. Receipt types
must fail assessment verification and assessment types must fail receipt
verification. Canonical JSON and Ed25519 use the maintained receipt primitives.
Duplicate members, floats, unsafe integers and alternate encodings are rejected.

The caller supplies trusted workspace and project IDs and Ed25519 public-key
fingerprints obtained independently. A bundled key document cannot establish its
own trust. Workspace binding, selected fingerprint and key validity at
`issued_at` are mandatory. The verifier has no Langfuse or other provider calls.

The verification bundle contains `signed_assessment`, `source_snapshot`,
`policy_definition`, and `mapping_snapshot`. Only the signed JWS is authority;
any optional decoded display copy is untrusted. Trusted keys remain separate.

## Frozen payload

The payload has exactly:

`schema_version`, `assessment_id`, `workspace_id`, `job_id`, `project_id`,
`agent_id`, `action`, `issued_at`, `policy_ref`, `mapping_version`,
`mapping_sha256`, `reviewer_version`, `engine_version`, `source`,
`source_sha256`, `request_sha256`, `facts`, `missing_information`, `context`,
`policy_eval`, `assessment_status`, `application_reported_execution`, `mode`,
and `intervention`.

`schema_version` remains `allowly.assessment.v1`, `mode` is `observe` and
`intervention` is `none`. There is no execution authority or approval token.
`policy_ref` has exactly a nonempty `policy_id`, positive safe-integer
`policy_version` and lowercase 64-hex `definition_sha256`. The latter hashes the
complete canonical approved definition, including evidence instructions.
`engine_version` remains `sha256:<64 lowercase hex>`.

`source_snapshot` has exactly `project_id`, `trace_id`, `observation_id`,
`observed_at`, `captured_at`, and `content`. IDs are opaque source identifiers.
`source` equals its metadata without content, and its project equals the trusted
project. Content has at most 32 bounded logical names with string values, no
NUL. Its complete canonical snapshot is at most 64 KiB and matches
`source_sha256`. Capturing a source is not authenticating its upstream truth.

Times are real UTC millisecond timestamps. Issue and capture may be at most five
minutes in the future. Observation may precede capture arbitrarily, but cannot
follow it by more than five minutes.

`mapping_version` is an opaque label, never a selector for business logic.
`mapping_sha256` hashes the complete canonical mapping. `reviewer_version`
identifies the extraction implementation/model/prompt. Application-reported
execution is `sent`, `accepted`, `failed`, or `unknown`, independently of the
policy result. `accepted` means reported provider acceptance, not delivery.

## Policy-defined requirements

An action entry optionally has `evidence`, omitted from normalized JSON when
absent. Explicit null is invalid. When present it is nonempty and its keys equal
all `policy.fields` keys. Types come from those existing declarations; evidence
does not introduce a second type schema. Each requirement has exactly one form:

- `{sources: [...], instruction: ...}`: 1–8 unique logical source names and a
  nonblank instruction of 1–2048 code points for AI extraction.
- `{source: ..., transform: "email_domain", empty_sources: [...]}`: a string
  result derived from a single complete plain ASCII mailbox. The required list
  has 0–8 unique logical names other than source; each must be present and empty.
- `{all_of: [...]}`: a boolean derived from 1–16 unique declared direct boolean
  fields. References to derived fields, chains and cycles are invalid.

Logical source names contain 1–64 code points and no NUL. The mailbox transform
accepts a dot-atom local part up to 64 ASCII characters and a DNS domain with at
least two labels, up to 253 characters, within a total 254-character mailbox.
Local atoms use `[A-Za-z0-9!#$%&'*+/=?^_\x60{|}~-]+`. Domain labels contain 1–63
ASCII letters/digits/hyphens with alphanumeric ends. It lowercases only the
domain. Display names, multiple addresses, quoting, comments, groups, whitespace,
Unicode, address literals, malformed labels and unsupported envelope evidence
are unavailable. Subdomains remain distinct. The source adapter supplies strings;
it does not supply hidden internal-domain rules or extract business facts.

Observe requires exact selected agent/action binding, evidence metadata,
allow/deny action and rule decisions, empty guards and no executable grants.
OPA's existing OR conditions and decision precedence remain unchanged. An AND
requirement uses explicit `all_of` and an ordinary rule over the derived field.

## Mapping, typed facts and citations

The exact mapping snapshot has `observation_name` (1–128 code points), `sources`
(1–32 logical-name to JSON-pointer entries), `execution_pointer`, and
`mapping_version` (1–128 code points). Pointers begin `/`, are at most 256 code
points, contain no NUL and use valid RFC 6901 `~0`/`~1` escapes. The mapping covers
every source named by the approved evidence requirements. Captured content keys
must be mapped names. Mapping configuration selects source strings only.

Facts have exactly the direct, non-derived evidence field names. A fact is null
(unavailable) or exactly `{value, citations}`. Values obey their declared strict
`string`, safe `integer`, `boolean`, `null`, or scalar `list` type. Lists have at
most 64 string/integer/boolean/null items; nested lists and objects, floats,
coercion, unsafe integers and NUL are invalid. Present `{value:null,...}` differs
from an unavailable null fact. False and zero are values.

Every present fact has 1–8 citations, each exactly `{field,start,end,quote}`.
Offsets are Unicode code points, with `0 <= start < end <= source length`.
The exact nonempty quote is at most 8192 code points. AI citations use only that
requirement's sources, and every declared source must be captured before its
fact can be present. Deterministic extraction requires exactly one whole-source
citation, all declared empty sources and a recomputed matching domain.
A matching citation authenticates recorded text, not the AI interpretation.

`missing_information` is exactly the unique set of unavailable direct fields.
Any missing direct evidence means empty context, null policy evaluation and
`insufficient_evidence`, including false-plus-missing conjunctions. Otherwise
context equals all direct values plus mechanically derived `all_of` booleans.
Failures and unfinished work remain `not_assessed` application states, not
fabricated successful assessments.

## Commitments and recorded OPA result

Both tools check the complete definition, selected action, all snapshot digests,
required source coverage, typed facts, exact citations and derived context.
They reconstruct the canonical original request from the payload fields
`job_id`, `project_id`, `agent_id`, `action`, `policy_ref`, `mapping_version`,
`reviewer_version`, `source_sha256`, `facts`, `missing_information`,
`application_reported_execution`, `mapping_sha256`, plus bundle
`source_snapshot` and `mapping_snapshot`. It is at most 65,536 bytes and must
match `request_sha256`.

For complete evidence `policy_eval` is exactly `{input_sha256,result}`. The
input digest hashes canonical `{policy: selected_entry.policy, action, context}`,
without an HTTP wrapper. Result has exactly `profile`, `status`, `decision`,
`target`, `matched_rule_id`, and `evaluated_fields`. Profile is
`allowly.basic.v1`, status is `ok`, decision is allow/deny, target is null.
A matched rule must exist and supply the recorded decision; its evaluated fields
equal all its condition fields in context. An action-level result has null rule
ID and empty evaluated fields. Deny means `violation_detected`; allow means
`no_violation_found`. This validates recorded bindings, not independent OPA
replay or the truth of semantic evidence.

## Persistence and human judgment

A workspace/job identity binds one immutable request. Changed content under that
identity fails; retries return the retained assessment. Signing retries sign the
same frozen bytes without re-extraction. New policy/mapping/reviewer inputs
create new assessments. Human judgments are separate append-only records and
cannot rewrite signed claims. Capture failures and known gaps remain visible;
an unobserved event cannot be inferred without independent expected-source data.
