# Allowly OPA evaluation and replay profile

This profile defines wire-5 immutable policy references, complete provisional
OPA evidence, and content-addressed engine identity. Ordinary signature
verification and official-OPA policy replay remain separate operations.

## Immutable definition

`definition_sha256` is SHA-256 of the maintained receipt canonicalizer's UTF-8
bytes for the complete stored envelope. It preserves ordered arrays, absent
versus null, integer bounds and Unicode rules. No database serialization or
alternate JSON canonicalizer is used.

The exact `allowly.policy.v1` envelope has `profile`, nonempty `agent_id`,
nonempty ordered `actions`, and required `default_expiry_days` (null or a strict
integer 1..3650). Each action has exactly `policy`, `guards`, and
`executable_operations`. Nested `policy.action` names are unique. The entire
definition is validated, normalized once, stored and hashed; bookkeeping IDs,
timestamps, descriptions and archive status are excluded.

`guards` has only optional `resource_pattern` (nonempty string),
`allowed_initiators` (nonempty unique list of nonempty strings), and
`max_per_day` (positive safe integer). Explicit null guards are invalid.
Resource matching, identity, expiry, approval consumption, budgets and atomic
UTC-day reservations stay outside Rego. An asserted initiator is not human
identity evidence. Preserve the existing atomic budget/counter lineage.

Executable entries have exactly `enabled_executable_id`, `provider_id`,
`operation_id`, `catalog_revision`, `definition_fingerprint`, and
`minimum_evidence_mode`, retaining existing catalog/workspace/fingerprint
checks and full-witness/no-downgrade rules.

## BasicPolicy and provisional output

Each normalized `allowly.basic.v1` BasicPolicy has exactly `profile`, `action`,
`default_decision`, `default_target`, `fields`, and ordered `rules`.
Action names are nonempty, at most 256 Unicode scalar values, and differ from
decision labels. `fields` maps at most 64 nonempty field names (at most 128
Unicode scalar values) to `string`, `integer`, `boolean`, or `null`.
At most 32 ordered rules are allowed. Each has exactly `id`, `decision`,
`target`, and a nonempty `conditions` list of at most 10 entries.
Rule IDs are unique, nonempty and at most 128 Unicode scalar values.

Conditions have exactly `field`, `op`, `value`. Fields must be declared.
Operators are `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, `in`, `not_in`, and `exists`.
Comparisons require values matching the declared scalar type. Ordered
comparisons require integers. Membership uses arrays of at most 64 typed
scalars. `exists` requires a boolean and preserves presence versus explicit
null. The first matching rule wins; otherwise the default applies. Missing
or wrongly typed comparison inputs are invalid rather than default allows.

Authoring validates every rule/default target: allow and deny require null,
confirm requires exactly `agent_owner`, and escalate requires
`member:<nonempty opaque member ID>` (at most 256 Unicode scalar values).
Owner means the existing immutable grant-owner snapshot. Membership is checked
through trusted publication and resolution paths, not asserted API-key input.

The exact original inner input is `{policy, action, context}`. Hash its frozen
canonical bytes before the HTTP `input` wrapper. Retain original input privately
only when replay is wanted; evidence hashes cannot reconstruct it.

Successful output has exactly `profile: allowly.basic.v1`, `status: ok`,
`decision`, `target`, `matched_rule_id`, and `evaluated_fields`. The latter
records compared fields present in the original context; missing exists inputs
are omitted and present null stays null. A default has null rule ID and empty
evaluated fields. All values obey receipt canonicalization bounds.
Undefined/malformed/unavailable or invalid-input outputs do not count as
successful evidence and never authorize execution.

## Full engine manifest

`engine_version` is `sha256:` plus SHA-256 of this exact canonical object:

```text
{
  schema: "allowly.engine.v1",
  policy_profile: "allowly.policy.v1",
  evaluator: {
    profile: "allowly.basic.v1",
    entrypoint: "/v1/data/allowly/basic/result",
    module: {path: "policies/opa/allowly_basic.rego",
             api_id: "ops/opa/evaluator.bundle.tar.gz/policies/opa/allowly_basic.rego",
             sha256: <raw Rego SHA-256>},
    opa: {version: <exact official version>, commit: <build commit>,
          platform: <actual platform>, artifact_sha256: <official artifact SHA-256>},
    bundle: {roots: [""], revision: "allowly.basic.v1", rego_version: 1},
    signed_bundle: {path: "ops/opa/evaluator.bundle.tar.gz",
                    artifact_sha256: <complete gzip bundle SHA-256>,
                    public_key_sha256: <release PEM bytes SHA-256>,
                    key_id: <OPA release signing key ID>,
                    scope: "allowly/evaluator/v1", algorithm: "EdDSA",
                    development: <boolean>}
  },
  runtime: {artifact_sha256: <retained full runtime tar SHA-256>, format: "tar",
            files: [{path: <relative path>, sha256: <raw file SHA-256>}, ...]}
}
```

Objects have exactly the shown keys. Raw hashes are 64 lowercase hex characters.
The runtime artifact covers actual final authority/transaction guard code and
its dependencies. File paths are unique relative paths without traversal; tar
members are regular files and match the full list. A dirty checkout's Git HEAD
or evaluator-only manifest is insufficient. New semantics/platform/artifacts
require a new immutable identity. Retain exact artifacts, never repoint an ID.

The current local replay pin is official OPA 1.21.1, commit
`2a109e54103370d2ef288782ef3cb4c8a37902b2`, platform `darwin/arm64`, binary SHA-256
`a00a6469a0968c47c01137ed0dacaa88148be5d0eaa8524310cd371f3a98a169`, and Rego SHA-256
`76d8e826f88e0e1fc34d274687044609b2c298e562289f502b712e907928b40c`.
These are actual local artifacts, not production or Linux pins.
The retained runtime archive contains this signed bundle and its separate
release trust anchor at `ops/opa/bundle-public.pem`. These hashes bind both to
the receipt's authenticated engine manifest. A development key is clearly
marked; it is not a production signing claim. The evaluator bundle is shared
code, not the customer's immutable policy edition named by `policy_ref`.
The native signed full-root bundle prevents policy/data replacement after readiness.
The runtime OPA listener remains private: full-root ownership does not make
ad-hoc query endpoints an untrusted sandbox.

## Separate replay

The Python `allowly-policy-replay` command authenticates the receipt using
caller-trusted workspace/key fingerprints, then checks manifest identity,
complete definition digest, selected BasicPolicy, original input digest, Rego
and official OPA build, and retained runtime archive. It verifies the archived
bundle and separate trust anchor against the signed manifest, then uses stock
OPA bundle-signature verification with the fixed key ID, scope and EdDSA
algorithm before evaluation. The bundle must contain only `.manifest`,
`.signatures.json` and the exact pinned Rego module; its bundle metadata and
module bytes must match the retained manifest and source. It invokes only official
OPA with fixed `data.allowly.basic.result`, never a Python/TypeScript rule
interpreter or caller-supplied query. No private input or result is logged.

Replay returns `matched` only for the complete provisional result.
Missing inputs/artifacts and unsupported engines return `not_checked`;
commitment or comparison failures return `mismatched`. Signature failures remain
verification failures. CLI exit codes are 0, 4, 3, and 1 respectively.
The JSON report separates `signature_verified`, `policy_replay`,
`transactional_enforcement`, and `witnessed_execution`. The latter two are
`not_checked` by this command.

Replay does not prove input truth, human intent, final approval/budget/day-limit
atomicity, provider execution, or complete receipt history. The retained runtime
artifact authenticates code identity, not a replay of transaction state.
Native enrollment/authentication/rotation/revocation, workspace KMS boundaries,
Ed25519 signing, receipt canonicalization and full TLSNotary witness checks
retain their existing semantics.

## Local regression evidence

`vectors/policy/profile-v1.json` carries deterministic fixture-key signatures
for complete OPA results, missing/null exists evidence, OPA-allow/final-deny and
tampered commitments. Its retained fixture manifest identifies a real local
runtime archive held by the workspace builder. It is test evidence, not a
published production engine. Regeneration does not need a second interpreter.

Run native replay tests with explicit paths in `ALLOWLY_OPA_BINARY`,
`ALLOWLY_OPA_MODULE_FILE`, and `ALLOWLY_OPA_RUNTIME_ARTIFACT`. Without these
artifacts those tests report skipped; portable signature tests still run.
No test mock or signature alone satisfies native replay, non-production
Cloud KMS, Postgres concurrency, or full TLSNotary release gates.
