# OPA policy references and receipt evidence

Status: agreed build contract, 2026-10-09. Wire `5` and verifier `5.0.0`
local staging are approved. This proposal itself does not change the active
receipt specification, runtime emission or verifier packages, and does not
authorize package publication or deployment.

## Baseline and fresh-build scope

This proposal starts from receipt-format commit
`6da0fdc72ebd683e079b5e920fac116548839c75` (wire `4`, Python and TypeScript
verifiers `4.3.1`) and API commit
`6b84c1c386fc9d2f99b36c1103cd71c8ebd3d4ad` (engine `2026-10-09.1`).

[The active specification](../receipt-format.md) and both verifier schema
checks reject unknown top-level fields. Its `policy_eval` also accepts exactly
`matched_condition` and `field_value`. Adding `policy_ref` and changing
`policy_eval` therefore require a new wire version. The earlier wire-4
confirmation-event exception did not permit new signed fields. The approved
local target is wire `5` with verifier major `5.0.0`, derived from that exact
baseline. HTTP `/v1`, engine IDs and SDK versions remain separate version axes.

This is a fresh build. Client, workspace and data migration, backfills,
mixed-version coexistence and backward runtime compatibility are out of scope.
Initialize the new schema in an explicitly selected empty local/test database.
Schema initialization does not authorize resetting an existing database,
deleting customer data or receipts, replacing keys, or changing a deployed
service. Existing artifacts remain outside this rebuild's write scope.

## What versioning already exists

At the API baseline, publication already creates replacement history. Each
publication creates a new `AgentPolicy` row with its own ID. Ordinary workspaces
archive prior policies and replace their grants in one transaction; Enterprise
keeps policies side by side. An authorization copies its rules and pins the
selected row ID. These are version-like editions, so the rebuild does not start
from a system with no versioning.

What is missing is a stable logical policy ID across those editions, an explicit
edition number, and a canonical definition digest. Existing managed SEAL also
repairs its policy row in place, and standard grants can contain inline rules.
The proposed changes make identity and immutability uniform across these paths.
An edition row ID plus digest would already bind exact bytes; the logical ID and
number add stable publication identity and clear edition ordering, not another
cryptographic guarantee.

## One policy identity and one reference

Add one **required, signed, top-level** `policy_ref` to every new-wire receipt:

```text
null
or
{
  "policy_id": <nonempty opaque string>,
  "policy_version": <integer from 1 through 9007199254740991>,
  "definition_sha256": <exactly 64 lowercase hexadecimal characters>
}
```

An object has exactly these three members. Booleans are not versions. Omission,
partial objects, unknown members and malformed digests fail schema validation.
The signed `workspace_id` scopes the reference; do not repeat it inside the
object. A policy ID has meaning only with that workspace and version.

`policy_id` identifies a stable logical policy. A row ID may continue to identify
one internal version record. Reuse `agent_policies` for these records; do not add
a second policy table or storage system. `policy_version` increases under the existing
workspace publication lock, with database uniqueness on
`(workspace_id, logical_policy_id, policy_version)`. Failed transactions need
not produce gap-free numbering. Never reuse a published version or mutate its
logical ID, agent binding, definition or digest. Archive state is separate from
the immutable definition. Concurrent publication must allocate distinct versions
and either commit all authority changes or none.

The fresh schema requires the logical ID, version, full definition and digest on
every policy row. Reuse the existing schema tooling for initialization; no
nullable compatibility fields or data backfill are needed. Keep one authoritative
rule definition. The old `actions`/`requires_*` rule payloads must not become a
second editable source that needs synchronization with the new definition.

`definition_sha256` is SHA-256 of the UTF-8 bytes returned by the maintained
receipt-format canonicalizer for the complete stored policy definition. Use its
existing integer/Unicode/JSON rules; do not introduce another canonicalizer or
hash a database serialization. Preserve ordered arrays. The definition is the
full envelope below, not one selected action. It excludes row IDs, timestamps,
description, archive state and other bookkeeping. Store the same normalized
definition that was validated and hashed, then evaluate that stored edition
without later normalization changes.

Each authorization pins this reference and its exact immutable edition row in
the same workspace. That retained row is the rule snapshot: do not persist a
second editable copy of the full rules on the grant. The grant keeps its own
narrower action/resource scope, expiry, budget/approval lineage and existing
identity provenance. Caches derive rules from the exact edition, never the
current/latest policy. Check and Execute use that granted version.
Missing definitions, digest mismatches and cross-workspace references fail
closed. A malformed or unresolved governed grant is an error, not a null reference.
Archived editions remain available for their grants and replay. Retention or
workspace deletion is a separate, explicitly authorized operation; it is not a
reason to reuse a published version.

## Full authoritative definition and targets

Use one strict full-definition envelope:

```text
{
  "profile": "allowly.policy.v1",
  "agent_id": <nonempty protected agent/item ID>,
  "actions": [
    {
      "policy": <allowly.basic.v1 BasicPolicy>,
      "guards": {
        "resource_pattern": <optional nonempty string>,
        "allowed_initiators": <optional nonempty unique list of nonempty strings>,
        "max_per_day": <optional positive safe integer>
      },
      "executable_operations": [<existing pinned executable descriptor>]
    }
  ],
  "default_expiry_days": null | <strict integer from 1 through 3650>
}
```

The outer profile versions the authoring envelope; nested `allowly.basic.v1`
versions the per-action OPA input/rule contract. They are not competing engine
IDs. Require at least one action and unique nested `policy.action` names. Do not
duplicate that name on the action entry or retain `requires_*`, legacy condition
arrays or separate escalation-target maps as rule authority. Preserve existing
action, policy-size and executable-count bounds. Validate every rule/default
target in the full-definition authoring layer, beyond BasicPolicy's basic
non-null target check:

| Decision | Required target |
| --- | --- |
| `allow`, `deny` | `null` |
| `confirm` | Exactly `agent_owner` |
| `escalate` | `member:<account_user_id>`, with a nonempty member ID |

`agent_owner` means the owner saved in that authorization's existing immutable
provenance at grant creation. It does not mean the current owner at check or
resolution time. One edition may create grants with different snapshotted
owners; this is the deliberate meaning of the rule. The policy reference binds
that rule, while signed grant provenance/source evidence binds the actual owner.
A missing owner cannot be replaced with a caller-supplied or current owner to
approve a confirmation. No duplicate policy identity or owner-snapshot store is
needed. Native/provider binding, proof checks and key revocation remain in the
existing grant identity path; key rotation does not require a policy edition.

An escalation's member ID is fixed in the policy definition. Validate membership
through the trusted control-plane path when publishing, and recheck current
membership on the trusted review-resolution path. A setup/runtime API key plus
a supplied member ID is not proof of membership. An internal mapped reviewer
must match the target; public client-reported approval remains client-reported
evidence, not proof that the named member acted. Missing membership evidence
must not silently become a verified approval.

`guards` may be empty. Its three members are optional, but explicit null values
and unknown members are invalid. Resource matching keeps the existing runtime
`fnmatch` behavior; a restricted action with a missing resource is denied.
`allowed_initiators` checks asserted `context.initiated_by`, not authenticated
human or agent identity. `max_per_day` remains an atomic UTC-day reservation on
the existing counter lineage, outside Rego. Grant budgets likewise remain in
Allowly; this schema does not invent a policy budget cap. A default expiry is
used only when creating a grant; the resulting expiry is saved on that grant.

Keep the existing executable descriptor fields: `enabled_executable_id`,
`provider_id`, `operation_id`, `catalog_revision`, `definition_fingerprint` and
`minimum_evidence_mode`. Preserve workspace/catalog/fingerprint checks, unique
operation binding and full-witness/no-downgrade rules. Authoring validation must
bind `agent_id` to the row and check the entire envelope before publication;
the digest helper's canonical-object check alone is not schema validation.

## Grant and publication rules

Standard grant creation requires an explicit published `policy_id` and
`policy_version`. The server resolves the workspace-scoped version and computes
the digest; the client cannot choose the digest. It also checks current
publication and entitlement state: an archived/superseded version cannot mint
new authority merely because its definition remains stored. The rebuilt API has
no inline standard grant definitions. Callers publish once, then create grants from that
version. This avoids an implicit policy store and new rules for hidden policies,
deduplication or customer allowances. Drafts and previews create no authority.

Keep current entitlements: ordinary publication replaces authority atomically;
Enterprise can retain side-by-side policies. Updating one logical policy creates
a version under that ID; creating a separate policy creates a new ID. A version
number alone does not select a new live version or alter an existing grant.
Predecessor revocation, child revocation, successor creation and publication
commit together. Preserve existing budget and UTC-day counter lineage.

Managed SEAL uses an actual system-owned logical policy and immutable version,
through the same definition/digest service. Its existing exemption from customer
allowances remains explicit. Repair changed managed rules by publishing a new
version and rotating its grants; the current in-place repair pattern must not
rewrite a published definition.

## Which version a receipt names

| Receipt or path | Required `policy_ref` |
| --- | --- |
| Governed action, including a later authority/limit denial | Exact version pinned by the resolved authorization |
| Standard or confirmation-child `authorization.create` | Created grant's pinned version; a child inherits its parent's version |
| `authorization.revoke`, including publication supersession | Revoked grant's version; never its successor's version |
| `confirmation.resolve` or `escalation.resolve` | Original review's source authorization/version, with its existing source receipt link |
| `budget.settle` | Version of the original checked authorization and source decision receipt |
| Managed SEAL evaluation and its grant lifecycle | Actual system-owned pinned version |
| Record-only SEAL with no governed evaluation | `null` |
| Missing-authorization denial | `null` |
| Workspace `receipt.checkpoint` | `null` |

Null means no policy applies or no authorization was resolved. It is not an
unknown-version fallback for governed grants. Keep a non-null reference when a
resolved grant is expired, revoked or superseded. Resolution never consults the
latest policy: a waiting review remains tied to its original version, and a
superseded/revoked grant cannot regain permission through approval. Existing
request commitments, condition fingerprints, parent links and dispatch claims
still bind the exact request and control its use.

Runtime builders populate `policy_ref`, `engine_version` and evaluation evidence
from trusted records only, outside caller context/metadata merges. Reject caller
attempts to supply reserved issuer fields at input boundaries. Copies in caller
context are not authoritative references. Every lookup, including source
receipts and version records, checks the authenticated workspace.

## Provisional evaluation and final decision

Keep top-level `decision` and `reason` for Allowly's final committed result. For
an action where OPA successfully returned a validated result, redefine the
optional signed `policy_eval` as exactly:

```text
{
  "input_sha256": <64 lowercase hexadecimal characters>,
  "result": {
    "profile": "allowly.basic.v1",
    "status": "ok",
    "decision": "allow" | "deny" | "confirm" | "escalate",
    "target": null | <opaque review target>,
    "matched_rule_id": null | <ordered rule identifier>,
    "evaluated_fields": <object of evaluated field names and JSON values>
  }
}
```

The profile defines allowed field types, target requirements, rule identifiers
and missing-field evidence. A default result has no matched rule and empty
evaluated fields. The exact inner OPA input is
`{policy: <validated stored BasicPolicy>, action: <selected action>, context: <effective context>}`.
Hash its canonical bytes before the HTTP `input` wrapper. Freeze/hash at the
client's outbound serialization point, not by rebuilding input after evaluation.
This commitment does not claim to include identity or transaction facts that
were never sent to OPA. Preserve absence versus null. Retain the original input
privately if replay is needed; a hash or partial explanation cannot reconstruct
it. This introduces no automatic logging or retention of private input.

OPA's successful result remains unchanged when Allowly applies identity/grant
fences, exact approval matching/consumption and atomic budget/day reservations.
For example, OPA may record `allow` while the top-level result records
`deny / budget_exceeded`. An approved matching review may also let Allowly turn
a provisional review result into final allow. The policy result alone never
authorizes dispatch. Preserve the existing signed review/source evidence for
those transitions.

Do not emit `policy_eval` on event receipts or when evaluation did not run.
Undefined, invalid, malformed or unavailable OPA results are service failures,
not successful policy results. They cannot produce an allow or a fabricated
successful evaluation block. A non-null `policy_ref` does not by itself claim
that OPA ran.

## Evaluator identity and independent verification

Keep the existing signed `engine_version` as the single identity of one
immutable engine manifest: `sha256:` followed by SHA-256 of the manifest's
maintained canonical JSON bytes. The full manifest has schema
`allowly.engine.v1`, identifies `policy_profile: allowly.policy.v1`, and binds:

- The evaluator profile, fixed entrypoint, module path/API ID and Rego SHA-256.
- The exact official OPA version, build commit, platform and binary/image SHA-256.
- The native full-root bundle configuration (`roots: [""]`, revision and Rego
  version), which prevents HTTP policy/data replacement after readiness.
- A retained runtime artifact's SHA-256 covering final authority/transaction
  guard code. A dirty checkout's unchanged Git HEAD is not such an artifact.

Use one actual platform artifact per manifest. A different platform or runtime
artifact produces a different manifest identity. Retain the exact artifacts for
replay and audit; a mutable URL or unverified version label is insufficient.
Do not add parallel receipt fields for OPA, Rego and engine versions. New engine
semantics require a new manifest identity; never repoint an old identity.
A local evaluator-only artifact manifest is not this complete runtime engine
manifest; its platform-specific development binary pin is not a production pin.
The OPA listener remains private to trusted runtime code. Full-root ownership
blocks management mutation, but does not disable ad-hoc `/v1/query` or make the
listener an untrusted-caller sandbox. Deployment must keep tenant code away from
the listener or add a native endpoint/method allowlist before exposing it.

The ordinary Python, TypeScript and browser verifier validates receipt shape,
workspace/key binding and signature. A separate CLI/container uses pinned
official OPA, the authenticated manifest, a definition matching `policy_ref`
and original inputs matching `input_sha256` to compare the complete provisional
result. Do not maintain a second Rego interpreter in Python or TypeScript.

Report signature verification, policy replay, final transactional enforcement
and witnessed execution separately. Missing inputs/artifacts or unsupported
engines mean replay `not_checked`; comparison failure means `mismatched`.
Replay success does not prove input truth, human intent, reservation concurrency,
provider execution or a complete receipt history. Native enrollment/authentication,
rotation/revocation, workspace KMS boundaries, Ed25519 signing, canonicalization
and full TLSNotary witness verification remain unchanged.

## Adoption gates

1. Implement the agreed full-definition/profile and manifest schemas; test digest stability,
   ordering, missing/null distinctions, invalid versions, workspace mismatch,
   forged reserved fields and immutable child/review/lifecycle references.
2. Update active spec, both signature verifiers and regenerated signed vectors
   before runtime emission. Include tampered reference/input/result/engine
   vectors and OPA-allow/final-deny cases. Update OpenAPI, SDKs, integrations,
   dashboard receipt export/download, browser verification and docs together.
3. Prove real Postgres publication/revocation/approval races and budget/day-limit
   concurrency, atomic rollback and counter lineage. SQLite or mocks alone do
   not satisfy this gate.
4. Sign and independently verify the new receipt with an explicitly authorized
   **non-production Cloud KMS key**. No such key is established by this proposal;
   obtaining one remains a release prerequisite. Fake KMS does not satisfy it.
   Pass native identity and existing full-witness/no-downgrade regressions.
5. Pass affected suites and workspace `python3 ops/contract_lint.py`; release
   receipt/verifiers before runtime and compatible consumers before new emission.
   Package publication, deployment and any destructive reset remain outside
   this local proposal.

Source checks for this proposal used the exact baseline files:
`spec/receipt-format.md`, both `verifier` implementations, `scripts/gen_vectors.py`,
and API `models.py`, `routers/authorizations.py`, `services/policy_publication.py`,
`services/seal.py`, `services/canonical.py` and `services/signing.py`.
