# Allowly conditional evaluation profile v1

Profile identifier: `allowly-conditional-evaluation-v1`

This profile lets a verifier repeat the conditional policy calculation recorded
in an Allowly action receipt. It uses the signed authorization creation receipt
as the rule snapshot and the signed action receipt as the input snapshot.

A `matched` result has a narrow meaning: the saved rules and reconstructed
inputs produce the same complete `policy_eval` object. It does not reproduce the
final Allowly decision. It also does not prove that the customer supplied facts
were true, that an action happened, or that the supplied receipt set is
complete.

## 1. Supported versions

The action receipt's signed `engine_version` selects the evaluator. A verifier
must not apply newer semantics to an unknown engine.

| Action engine | Authorization snapshot engine | Evaluator source |
|---|---|---|
| `2026-09-16.1` | `2026-09-16.1` | `allowly-api/app/services/policy_conditions.py` at commit `1a7b36e2e83d0a8b57914d16bc297d8f8090eb13` |
| `2026-09-24.1` | `2026-09-16.1` or `2026-09-24.1` | The same conditional evaluator; this engine also records identity, customer time, and governed execution evidence after evaluation. |

An unsupported action engine returns `not_checked` with
`unsupported_engine_version`. An unsupported creation snapshot version or
shape returns `not_checked` with `unsupported_authorization_snapshot`.

## 2. Authenticate evidence before replay

The caller must provide a non-empty expected workspace ID and at least one
trusted Ed25519 public-key fingerprint. Bundled keys are not a trust decision.

Before returning any replay status, the verifier must run the normal strict
wire, schema, timestamp, workspace, trusted-key, and signature checks on:

1. the action receipt; and
2. every supplied authorization-receipt candidate.

Malformed receipts, invalid signatures, wrong workspaces, unknown keys, and
untrusted keys are verification errors. They are not `not_checked` results.

After authentication, select creation receipts whose `event` is
`authorization.create` and whose `authorization_id` exactly equals the action
receipt's non-empty `authorization_id`. No match returns
`authorization_receipt_not_found`. Byte-for-byte identical copies of one signed
receipt count once. More than one distinct matching creation receipt returns
`conflicting_authorization_receipts`.

The selected creation receipt must meet all of these rules:

- its `issued_at` is no later than the action receipt's `issued_at`;
- its `user_id` and `agent_id` equal the action receipt values;
- `context.actions` is a non-empty array;
- every action entry has exactly `name` and `constraints`;
- every `name` is a non-empty string and all names are unique; and
- every `constraints` value is an object.

A subject mismatch returns `authorization_subject_mismatch`. A missing action
returns `authorization_action_not_found`. More than one entry for the selected
action returns `authorization_action_ambiguous`. Other unsupported snapshot
shapes return `unsupported_authorization_snapshot`.

## 3. Reconstruct the evaluator input

Copy the action receipt's signed `context`. For engine `2026-09-16.1`, remove
exactly these top-level keys:

- `budget`
- `escalation`
- `session_id`

For engine `2026-09-24.1`, also remove these receipt-only fields, which the API
adds after the conditional policy calculation:

- `client_timestamp`
- `client_timestamp_source`
- `execution`
- `identity_verification`

The API evaluates the customer context before it adds those receipt-only
fields. Preserve every other key, array order, JSON type, explicit `null`, and
the difference between an absent member and a member set to `null`.

Use the selected action entry's signed `constraints`. Other constraint members,
such as state-dependent limits, do not affect this conditional calculation.

## 4. Supported condition language

The supported condition-list members are `deny_when`, `escalate_when`, and
`confirm_when`. A present member is `null` or an array. There may be at most ten
conditions across the three arrays.

Each condition is an object with exactly two members:

```json
{"field": "risk_score", "gte": 80}
```

`field` is a non-empty string. The other member is exactly one supported
operator. The normalized receipt form is:

```json
{"field": "risk_score", "op": "gte", "value": 80}
```

Unknown operators, extra members, invalid value types, empty membership lists,
and other malformed policy shapes return `not_checked` with
`unsupported_policy`.

### 4.1 JSON types

A scalar is a string, integer, boolean, or `null`. Integers use the receipt
format's safe integer range. Booleans and integers are different types, so
`true` does not equal `1`. No operation coerces strings, numbers, or booleans.

### 4.2 Operators

| Operator | Required policy value | Calculation |
|---|---|---|
| `eq` | scalar | The present field has the same JSON scalar type and value. |
| `neq` | scalar | The present field has the same JSON scalar type and a different value. |
| `lt`, `lte`, `gt`, `gte` | integer | The present field is an integer and the named comparison is true. |
| `in`, `nin` | non-empty scalar array | Compare only policy items with the same scalar type as the present field. If there is no comparable item, the field is uncomparable. |
| `contains_any` | non-empty scalar array | The present field is a scalar array and its typed set intersects the policy array's typed set. |
| `contains_none` | non-empty scalar array | The present field is a scalar array and its typed set is disjoint from the policy array's typed set. An empty input array therefore matches. |
| `empty` | boolean | The present field is an array and its empty state equals the policy value. |
| `exists` | boolean | Field presence equals the policy value. A present `null` value exists. |

For every operator except `exists`, an absent or uncomparable field produces a
`context_field_missing` result according to the precedence rules below.

## 5. Evaluation order and missing-field precedence

Conditions inside one list are evaluated in array order and are ORed. The first
match is returned.

1. Evaluate `deny_when` first. A deny match returns immediately. Remember the
   first absent or uncomparable deny field, but continue through later deny
   conditions so a later deny match can win.
2. Evaluate `escalate_when`. Its first match or first absent or uncomparable
   field returns immediately.
3. Evaluate `confirm_when`. Its first match or first absent or uncomparable
   field returns immediately.
4. If neither later list returned, use the remembered deny missing-field result
   as `kind: "confirm"` and `reason: "context_field_missing"`.
5. If conditions exist but none matched and no field was missing or
   uncomparable, return `kind: "none"`, reason
   `policy_conditions_not_matched`, and `policy_eval` equal to
   `{"matched_condition": null, "field_value": null}`.
6. If no conditions exist, the conditional evaluator returns no result.

This deferred deny fallback is part of the profile. A verifier that returns the
first missing deny immediately does not implement either supported engine.

## 6. `field_value` projection

The calculated `policy_eval` is exactly
`{"matched_condition": ..., "field_value": ...}`.

- An absent field records `null`.
- `contains_any` records the first input-array item, in input order, whose type
  and value match a policy item. It records `null` when none matches.
- `contains_none` and `empty` record `null`.
- Other operators record the actual value only when it is a scalar. They record
  `null` for arrays or other values.
- A no-match result records both members as `null`.

## 7. Comparison and result contract

Compare the complete recorded `policy_eval` object with the complete calculated
object using typed JSON equality. Object member order does not matter. Array
order, absent members, explicit `null`, and scalar types do matter.

The Python and TypeScript public functions return these snake-case fields:

```json
{
  "profile": "allowly-conditional-evaluation-v1",
  "engine_version": "2026-09-24.1",
  "receipt_id": "rcp_...",
  "authorization_receipt_id": "rcp_...",
  "status": "matched",
  "diagnostic": "matched",
  "recorded_evaluation": {},
  "calculated_evaluation": {}
}
```

`authorization_receipt_id`, `recorded_evaluation`, and
`calculated_evaluation` may be `null` when evidence is unavailable.

| Status | Diagnostic | Meaning |
|---|---|---|
| `matched` | `matched` | Complete supported evidence produced the recorded object. |
| `mismatch` | `policy_evaluation_mismatch` | Complete supported evidence produced a different object. |
| `not_checked` | `policy_evaluation_not_recorded` | The action receipt has no `policy_eval`. |
| `not_checked` | `unsupported_engine_version` | The action engine is not in the supported table. |
| `not_checked` | `authorization_receipt_not_found` | No exact signed creation snapshot is available. |
| `not_checked` | `conflicting_authorization_receipts` | More than one distinct exact-ID creation snapshot is supplied. |
| `not_checked` | `unsupported_authorization_snapshot` | The snapshot version, time, or shape is unsupported. |
| `not_checked` | `authorization_subject_mismatch` | The signed user or agent differs between the pair. |
| `not_checked` | `authorization_action_not_found` | The snapshot does not contain the action. |
| `not_checked` | `authorization_action_ambiguous` | The action appears more than once. |
| `not_checked` | `unsupported_policy` | The selected policy shape or operator is unsupported. |

The implementation and reviewed cases are shared through
`vectors/policy/profile-v1.json`. The `runtime_cases` section contains pure
evaluator inputs and expected `kind`, `reason`, and `policy_eval`. The
`verification_cases` section contains signed pairs and exact public results.
