# Allowly Receipt Format Specification

**Version:** 1.0.0-draft.5
**Status:** Draft — public review
**License:** This specification is published under CC-BY 4.0. Reference implementations are Apache 2.0.

---

## 1. Purpose

A *receipt* is a signed, immutable record of a single authorization event — either an authorization decision made by an authorization-check service at the moment an agent or human acted, or an event tied to the authorization itself (creation, revocation, third-party escalation resolution). This document specifies the canonical format, signature scheme, and verification algorithm so that any party holding a receipt and the issuer's public key can verify the receipt offline, without contacting the issuer.

Two kinds of receipts share the same format:

- **Action receipts** record a single authorization decision: *at time T, the issuer decided that action A by agent G on behalf of user U was allowed, denied, required confirmation, or required escalation, under authorization C.* These are produced by the issuer's `/check` endpoint.
- **Event receipts** record events tied to the authorization itself: *at time T, user U authorized agent G with scopes S,* *at time T, that authorization was revoked,* or *at time T, a third-party escalation was approved or rejected.* These are produced when an authorization is created/revoked or when an escalation is resolved.

Both kinds of receipts use the same JSON structure, the same canonicalization, the same signature scheme, and the same verifier. They differ only in the values of a few fields (§3.3). An auditor presented with a dispute typically needs both: event receipts prove *what was authorized and who approved later escalation*, while action receipts prove *what happened under that authorization*.

The goals of this format are, in order:

1. **Third-party verifiability.** An auditor, regulator, or end-user can verify a receipt without trusting the issuer's continued cooperation or uptime.
2. **Tamper evidence.** Any modification to the receipt content after signing is detectable.
3. **Portability.** Receipts remain verifiable if the issuer goes out of business, the customer switches vendors, or the verifier is written in a different language.
4. **Simplicity.** The verification algorithm is short enough to reimplement in any language in under 200 lines.

Non-goals: this spec does not define the *decision logic* that produced the receipt, the *policy language* used to describe permissions, or the *transport* used to deliver receipts. It defines only the signed artifact and how to verify it.

## 2. Terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are to be interpreted as described in RFC 2119 and RFC 8174.

- **Receipt** — a JSON object conforming to §3 plus its signature. Either an action receipt or an event receipt. A receipt always carries a real Ed25519 signature; an in-flight pending state is a transport-layer concept the issuer surfaces separately (§5.3).
- **Action receipt** — a receipt recording a single authorization decision at the moment of an action. See §3.3.
- **Event receipt** — a receipt recording an authorization-related event (creation, revocation, or escalation resolution). See §3.3.
- **Issuer** — the entity that produced and signed the receipt. Identified by `workspace_id`.
- **Subject** — the end-user on whose behalf an agent acted, or who granted the authorization. Identified by `user_id`.
- **Verifier** — any party validating a receipt.
- **Canonical form** — the byte sequence produced by applying the canonicalization rules in §4 to a receipt's payload.

## 3. Receipt structure

A receipt is a JSON object with the following top-level fields. All fields are required except where marked conditional (`scope`/`event`, by receipt kind) or optional (`policy_eval`, §3.6). Unknown fields **MUST NOT** be present in v1 receipts; verifiers **MUST** reject receipts containing unknown top-level fields.

```json
{
  "version": "1.0",
  "receipt_id": "rcp_01HXZ2B3QW4N5M6P7R8S9T0V1W",
  "workspace_id": "ws_01HXA1B2C3D4E5F6G7H8J9K0L1",
  "issued_at": "2026-04-21T14:32:17.482Z",
  "decision": "allow",
  "reason": "authorization_granted_scope_active",
  "user_id": "emp_8821",
  "agent_id": "referral_outreach",
  "scope": "outreach.send",
  "resource": "edge:emp_8821:conn_9f2a",
  "context": {
    "initiated_by": "user",
    "origin": "chat",
    "session_id": "sess_7f2"
  },
  "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
  "policy_version": "2026-04-17.1",
  "signature": {
    "alg": "Ed25519",
    "key_id": "projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",
    "value": "base64url(...)"
  }
}
```

### 3.1 Field definitions

| Field | Type | Required | Notes |
|---|---|---|---|
| `version` | string | yes | MUST be `"1.0"` for receipts conforming to this spec. |
| `receipt_id` | string | yes | ULID. Monotonic within a workspace. |
| `workspace_id` | string | yes | Issuer identifier. Used to look up the verification key. |
| `issued_at` | string | yes | RFC 3339 timestamp, UTC, millisecond precision, Z suffix. |
| `decision` | string | yes | See §3.3 for allowed values by receipt kind. |
| `reason` | string | yes | Machine-readable reason code. Human-readable strings MUST NOT appear here. |
| `user_id` | string | yes | Opaque identifier of the end-user. Customer-defined; issuers and verifiers MUST NOT assume any particular structure. SHOULD NOT contain personally identifiable information (§10.6). |
| `agent_id` | string | yes | Opaque identifier of the agent or acting principal. Customer-defined. For human-initiated actions, this identifies the actor's role (e.g. `controller`, `dba`). |
| `scope` | string \| absent | conditional | Present on action receipts. The scope name being checked (e.g. `email.send`, `contact.enrich`). Format is issuer-defined but conventionally dotted. **MUST be absent on event receipts.** |
| `event` | string \| absent | conditional | Present on event receipts. One of `"authorization.create"`, `"authorization.revoke"`, or `"escalation.resolve"`. **MUST be absent on action receipts.** |
| `resource` | string \| null | yes | An identifier for the target of the action, or `null`. Always `null` for authorization create/revoke receipts. For `escalation.resolve`, this MAY carry the resource the escalation was bound to. Issuers MUST NOT include the resource's contents, only an identifier. |
| `context` | object | yes | An opaque object of additional facts the issuer considered. Contents are issuer-defined. Verifiers MUST preserve the object byte-for-byte during canonicalization. MAY be empty (`{}`). |
| `authorization_id` | string \| null | yes | The authorization record this receipt relates to. For action receipts: the authorization that authorized the decision, or `null` if no authorization matched. For event receipts: the related `authorization_id` (never `null`). |
| `policy_version` | string | yes | Version of the issuer's decision logic at time of issue. Format is issuer-defined. |
| `policy_eval` | object \| absent | optional | Action receipts only; **MUST be absent on event receipts.** Records the outcome of per-scope condition evaluation: which condition (if any) routed the decision, and the evaluated context value. The rules in force are pinned by `authorization_id` (§3.3). See §3.6. |
| `signature` | object | yes | See §5. |

### 3.2 Extensibility

Future versions MAY add fields. Verifiers implementing v1 **MUST** reject any receipt whose `version` field is not exactly `"1.0"`. Verifiers implementing a later version **MUST** refuse to verify v1 receipts using v2 rules; forward compatibility is by version gating, not by best-effort parsing.

**Versioning policy.** The unknown-field rule (§3.1) makes any additive field a breaking change for deployed verifiers. To keep tamper-rejection strict without uncoordinated breakage:

- **While this spec is in draft** (pre-1.0.0 final), the wire `version` stays `"1.0"` and the spec, both reference verifiers, and the test vectors ship in lockstep — every draft regenerates all three together. Draft verifiers are not long-lived deployment artifacts.
- **After 1.0.0 final**, any additive optional field requires a minor wire-version bump (e.g. `"1.1"`). Verifiers declare the set of versions they accept (e.g. `{"1.0", "1.1"}`) and apply the unknown-field rule per accepted version: a `"1.0"` receipt carrying a field defined only in `"1.1"` is rejected.
- Issuers **MUST NOT** emit a field under a `version` value that does not define it.

### 3.3 Receipt kinds

Receipts come in two kinds, distinguished by which of two mutually exclusive fields is present:

**Action receipts** record a single authorization decision at the moment of an action. They are produced by the issuer's decisioning endpoint (conventionally `POST /v1/check`).

- `scope` — present, set to the scope name being checked. Conventionally dotted (`email.send`, `contact.enrich`, `payment.approve`).
- `event` — **MUST be absent.**
- `decision` — one of `"allow"`, `"deny"`, `"confirm"`, `"escalate"`.
- `authorization_id` — the matching authorization, or `null` if no authorization matched.
- `resource` — an identifier for the action's target, or `null`.

**Event receipts** record an authorization-related event. They are produced when an authorization is created/revoked or when a third-party escalation is resolved.

- `event` — present, one of:
  - `"authorization.create"` — the customer recorded that a user approved a set of scopes for an agent.
  - `"authorization.revoke"` — the authorization was revoked (by the user, by the customer, or automatically on expiry).
  - `"escalation.resolve"` — a third-party approver approved or rejected a pending escalation.
- `scope` — **MUST be absent.**
- `decision` — one of:
  - `"authorization_granted"` — paired with `event: "authorization.create"`.
  - `"authorization_revoked"` — paired with `event: "authorization.revoke"`.
  - `"escalation_approved"` — paired with `event: "escalation.resolve"` when the approver approved.
  - `"escalation_rejected"` — paired with `event: "escalation.resolve"` when the approver rejected.
- `authorization_id` — the authorization being created, revoked, or escalated. **MUST NOT** be `null` on an event receipt.
- `resource` — **MUST** be `null` for authorization create/revoke receipts. For `escalation.resolve`, this MAY carry the resource the escalation was bound to.
- `context` — conventionally carries lifecycle metadata: the full scope set at creation, `expires_at`, `requires_confirm_for`, `requires_escalation_for`, the creation source (`csv_upload`, `onboarding_modal`), an optional `csv_hash` or similar integrity identifier, an optional `replaces` field (see below); for revocations a `revoked_by` field (`user`, `admin`, `expired`, `tombstone`); and for escalation resolution an `escalation` object containing the escalation id, scope, approver label, resolution status, and approver identity.

**Authorizations are immutable.** There is no update event. Any change to an authorization — its scopes, per-scope constraints, or verb-routing rules (`requires_confirm_for`, `requires_escalation_for`, conditional routing) — is expressed as revoking the existing authorization and creating a new one, producing one signed `authorization.revoke` receipt and one signed `authorization.create` receipt. Because each `authorization_id` therefore refers to exactly one immutable rule set, the id alone pins the rules in force for every action receipt that references it; no revision counter is needed.

**Lineage convention (non-normative).** When a new authorization supersedes an old one, the creation receipt's `context` MAY carry `replaces: "<authorization_id of the predecessor>"`. This lets auditors walk the succession of rule sets across revoke-and-create boundaries. Verifiers do not validate `replaces`; it is an audit convenience, not a chain-integrity mechanism.

Verifiers **MUST** enforce the following:

- Exactly one of `scope` and `event` is present. Receipts with both fields, or with neither, are rejected.
- If `event` is present, it MUST be one of `"authorization.create"`, `"authorization.revoke"`, or `"escalation.resolve"`. The corresponding `decision` MUST be valid for that event. `authorization_id` MUST NOT be `null`. `resource` MUST be `null` for authorization create/revoke receipts. `policy_eval` MUST be absent.
- If `scope` is present, `decision` MUST be one of `"allow"`, `"deny"`, `"confirm"`, or `"escalate"`. The reserved event-only decisions (`authorization_granted`, `authorization_revoked`, `escalation_approved`, `escalation_rejected`) MUST NOT appear on action receipts. If `policy_eval` is present, it MUST conform to §3.6.

The two-field discriminator design (rather than a single overloaded field) makes the receipt kind explicit at the schema level. A field's presence tells you what kind of receipt it is; pairing rules become trivial to enforce.

### 3.4 Example authorization receipt

```json
{
  "version": "1.0",
  "receipt_id": "rcp_01HXZAUTHORIZATIONCREATE0000000",
  "workspace_id": "ws_01HXA1B2C3D4E5F6G7H8J9K0L1",
  "issued_at": "2026-04-21T14:30:00.000Z",
  "decision": "authorization_granted",
  "reason": "user_approved_via_customer_ui",
  "user_id": "emp_8821",
  "agent_id": "referral_outreach",
  "event": "authorization.create",
  "resource": null,
  "context": {
    "scopes": [
      "contact.enrich",
      {
        "name": "hiring.reject_application",
        "constraints": {
          "confirm_when": [
            { "field": "score_delta", "lt": 5 },
            { "field": "opt_out", "eq": true }
          ],
          "escalate_when": [
            { "field": "score", "exists": false }
          ]
        }
      }
    ],
    "requires_confirm_for": ["outreach.send"],
    "expires_at": "2026-12-31T00:00:00Z",
    "source": "csv_upload_v2",
    "csv_hash": "sha256:abc123..."
  },
  "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
  "policy_version": "2026-04-17.1",
  "signature": {
    "alg": "Ed25519",
    "key_id": "projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",
    "value": "base64url(...)"
  }
}
```

### 3.5 The authorization chain

An auditor can reconstruct the full story of an authorization by querying all receipts with a given `authorization_id`. The chain consists of:

1. Exactly one `authorization.create` receipt (the authorization grant itself).
2. Zero or more action receipts (each check that matched this authorization). The rules in force for every one of them are exactly those recorded in the creation receipt — authorizations are immutable (§3.3), so `authorization_id` alone pins the rule set.
3. Zero or more `escalation.resolve` receipts for third-party escalation decisions under this authorization.
4. At most one `authorization.revoke` receipt (if and when the authorization was revoked).

The chain is self-verifying: every receipt is independently signed, ordered by `issued_at`, and cryptographically tied to the same `authorization_id`. Producing this chain is the primary artifact customers present in disputes.

Rule changes never mutate a chain. Changing scopes, constraints, or verb routing is expressed as revoking the old authorization and creating a new one (§3.3); the new creation receipt MAY carry `replaces` in context, so successive chains form a walkable lineage.

### 3.6 Conditional policy evaluation (`policy_eval`)

Issuers that route action decisions through per-scope conditions (for example: *require confirmation when a score is within 5 points of the rejection threshold*, or *when the subject has opted out of automated processing*) MAY record the evaluation outcome in an optional top-level `policy_eval` object on action receipts. The block gives an auditor a signed answer to *"why did this decision require confirmation?"* The rules that were evaluated are pinned by the receipt's top-level `authorization_id` — authorizations are immutable (§3.3), so the creation receipt for that id is the signed snapshot of the rules in force. The condition language itself remains issuer-defined and out of scope, consistent with the non-goals in §1.

**Issuer convention (non-normative).** An issuer MAY model conditional routing as per-scope constraint attributes such as `confirm_when` and `escalate_when`. A deliberately small shape is recommended: each condition names one context `field` and one operator (`eq`, `neq`, `lt`, `lte`, `gt`, `gte`, `in`, or `exists`), condition lists are ORed, and there is no nesting or expression language. For example, an issuer might store `{ "field": "score_delta", "lt": 5 }` on an authorization, then normalize the matched condition in the action receipt as `{ "field": "score_delta", "op": "lt", "value": 5 }`. The receipt format only standardizes the normalized evidence in `policy_eval`; it does not standardize the authorization API's policy authoring syntax.

```json
{
  "version": "1.0",
  "receipt_id": "rcp_01J0Z7Q4BORDERLINE0CONFIRM",
  "workspace_id": "ws_01HXA1B2C3D4E5F6G7H8J9K0L1",
  "issued_at": "2026-06-09T17:04:09.114Z",
  "decision": "confirm",
  "reason": "confirm_condition_matched",
  "user_id": "cand_55ab2",
  "agent_id": "scout_referrals",
  "scope": "hiring.reject_application",
  "resource": "application:req_2207:cand_55ab2",
  "context": {
    "initiated_by": "agent",
    "score": 68,
    "threshold": 70,
    "score_delta": 2,
    "opt_out": false
  },
  "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
  "policy_version": "2026-06-01.2",
  "policy_eval": {
    "matched_condition": { "field": "score_delta", "op": "lt", "value": 5 },
    "field_value": 2
  },
  "signature": {
    "alg": "Ed25519",
    "key_id": "projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",
    "value": "base64url(...)"
  }
}
```

#### 3.6.1 Members

When `policy_eval` is present, both members MUST be present:

| Member | Type | Notes |
|---|---|---|
| `matched_condition` | object \| null | The single condition that routed the decision, expressed as the triple `{"field": string, "op": string, "value": string \| integer \| boolean \| null \| array}` — exactly those three members, no others. Arrays are for membership-style operators such as `in` and MUST contain only strings, integers, booleans, or nulls. `null` attests that conditions were evaluated and none matched. The set of operator names is issuer-defined; this spec constrains only the shape. |
| `field_value` | string \| integer \| boolean \| null | Snapshot of the evaluated context field at decision time. `null` when `matched_condition` is `null` or when the referenced field was absent from the request context. See §10.7 for snapshot-minimization guidance. |

#### 3.6.2 Rules

- `policy_eval` **MUST NOT** appear on event receipts. Verifiers MUST reject event receipts that carry it.
- Per §4.2 rule 6, non-integer numbers MUST NOT appear anywhere inside `policy_eval`, including inside `matched_condition.value` arrays. Fractional thresholds or values MUST be expressed as scaled integers (e.g. basis points, micros) or strings.
- Issuers **SHOULD** emit `policy_eval` on every action receipt for scopes that carry conditions — including `allow` decisions, where `matched_condition: null` attests *evaluated, nothing fired*. An absence of flags is itself evidence.
- Canonicalization note: the lexicographic key sort places `policy_eval` immediately before `policy_version` in the canonical form.

#### 3.6.3 Fail-closed convention (non-normative)

If a condition references a context field that is absent from the request, issuers are encouraged to fail closed: return `confirm` with `reason: "context_field_missing"`, set `matched_condition` to the unevaluable condition, and set `field_value: null`. The rationale: if the caller cannot demonstrate a fact the policy depends on (e.g. an opt-out flag), the safe decision is human review, and the receipt should record that this is what happened. The format permits but does not mandate this behavior.

#### 3.6.4 What `policy_eval` does not prove

Like `context` (§7.1), the evaluated values originate from the customer's system. `policy_eval` attests that the issuer evaluated the stated condition against the stated value and routed accordingly — not that the value was true in the world.

## 4. Canonical serialization

To produce a byte sequence suitable for signing and verification, a verifier **MUST** canonicalize the receipt payload as follows.

### 4.1 Payload scope

The *payload* is the receipt object with the `signature` field removed. All other top-level fields are included.

### 4.2 Canonicalization rules

The canonical form is the payload serialized as JSON with the following normative rules. These rules are a strict subset of RFC 8785 (JSON Canonicalization Scheme) chosen for implementability.

1. **Encoding.** UTF-8, no BOM.
2. **Whitespace.** No whitespace between tokens. Specifically: no spaces, no tabs, no newlines anywhere outside of string values.
3. **Object keys.** Sorted in lexicographic order by UTF-16 code unit (the default `Array.prototype.sort` order in JavaScript, and Python's `sorted()` on strings). Applied recursively to every object, including nested objects (such as `context`).
4. **Array order.** Preserved as-is. Arrays are ordered data; verifiers **MUST NOT** sort them.
5. **Strings.** Serialized with double quotes. The following characters **MUST** be escaped: `"` as `\"`, `\` as `\\`, and control characters `U+0000` through `U+001F` using `\uXXXX` lowercase-hex form (e.g. `\u000a` for newline). Non-ASCII characters **MUST NOT** be escaped; they appear as their UTF-8 byte sequence.
6. **Numbers.** Integers serialized without a decimal point or exponent. Non-integer numbers **MUST NOT** appear in v1 receipts; if present, verifiers **MUST** reject the receipt.
7. **Booleans and null.** Serialized as `true`, `false`, `null`.
8. **Separators.** `,` between array/object elements, `:` between object keys and values. No surrounding whitespace.

### 4.3 Reference canonical form

The payload for the example in §3 canonicalizes to (linebreaks for display only; the actual canonical form is one line):

```
{"agent_id":"referral_outreach","authorization_id":"auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
"context":{"initiated_by":"user","origin":"chat","session_id":"sess_7f2"},
"decision":"allow","issued_at":"2026-04-21T14:32:17.482Z","policy_version":
"2026-04-17.1","reason":"authorization_granted_scope_active","receipt_id":
"rcp_01HXZ2B3QW4N5M6P7R8S9T0V1W","resource":"edge:emp_8821:conn_9f2a","scope":
"outreach.send","user_id":"emp_8821","version":"1.0","workspace_id":
"ws_01HXA1B2C3D4E5F6G7H8J9K0L1"}
```

Note: `scope` and `event` are mutually exclusive — the canonical form contains exactly one of them, never both. The lexicographic key sort places `event` before `scope`, which matters for canonicalization correctness when generating event receipts vs action receipts.

## 5. Signature

The receipt carries exactly one signature over the canonical payload: an Ed25519 signature from the issuer's published key.

### 5.1 Algorithm

- Algorithm: Ed25519 per RFC 8032.
- Key: an asymmetric key held by the issuer. The public key is published at a well-known URL per §6.
- Input: the canonical payload bytes from §4, passed to Ed25519's sign operation as the message.
- Output: the 64-byte Ed25519 signature, base64url-encoded without padding per RFC 4648 §5.

Verifiers **MUST** use standard RFC 8032 Ed25519 verification over the raw canonical payload bytes. The signer's implementation details — including whether the signer pre-hashes the message before calling its KMS — are outside the scope of this specification. Verifiers do not pre-hash.

### 5.2 Signature object

```json
{
  "alg": "Ed25519",
  "key_id": "string",
  "value": "base64url-nopad-string"
}
```

- `alg` — **MUST** be `"Ed25519"` in v1 receipts.
- `key_id` — an opaque string the issuer uses to identify which key produced the signature. **SHOULD** be the full resource path of the specific key version, so rotations are unambiguous.
- `value` — the base64url-encoded Ed25519 signature bytes. Never empty, never a placeholder. A receipt without a real signature is not a receipt; see §5.3.

### 5.3 Pending state is not part of the receipt format

Issuers commonly sign asynchronously to keep KMS latency off the decisioning hot path. During the gap between decision time and signature completion, no receipt object exists in this format — only an in-flight pending state, which is the issuer's responsibility to expose through its API in a structurally distinct way (typically as a small object carrying `receipt_id`, an estimated ready time, and a URL where the eventual signed receipt can be fetched).

This separation is deliberate. Pending is a transport-layer concern, not a receipt-format concern. Keeping pending out of the signed-receipt schema means:

- Verifiers cannot accidentally accept an unsigned object. The schema check in §7 step 2 rejects anything whose `signature.value` isn't a base64url string of the right length.
- Customers cannot accidentally serialize a pending response as audit evidence. The pending response and the signed receipt have different shapes; passing the wrong one to a verifier or a long-term store fails immediately, not silently.
- The receipt format spec stays focused on a single artifact: the signed receipt.

Issuers **MUST NOT** emit any object claiming to be a v1 receipt with `signature.value` set to a non-signature value (e.g. a placeholder string). Verifiers **MUST** reject any such object on the schema check.

### 5.4 Implementation notes on signing (non-normative)

These notes describe how signers typically produce the Ed25519 signature. They are informative only; none affects the wire format or verification algorithm.

- **Pure-software Ed25519 libraries** (PyNaCl, libsodium, Go's `crypto/ed25519`): pass the raw canonical payload as the message. The library handles RFC 8032 internally.
- **Google Cloud KMS, software-protected keys:** pass the raw canonical payload as `data` to `asymmetricSign`. Pre-hashing returns a 400 error.
- **Google Cloud KMS, HSM-protected keys:** Google's HSM Ed25519 requires a pre-computed SHA-512 digest passed as `digest.sha512`. The signer computes SHA-512 of the canonical payload before calling KMS. This is a quirk of the HSM path; the resulting signature is still a standard RFC 8032 Ed25519 signature and verifies normally.
- **AWS KMS:** Ed25519 is signed in MESSAGE mode (raw payload). Pre-hashing is not required.

In all cases the verifier's behavior is identical: standard Ed25519 verification over the raw canonical payload. If a signer produces signatures that fail standard verification, the bug is in the signer, not the format.

### 5.5 Internal integrity checks (non-normative)

Issuers **MAY** compute internal integrity checks on receipts between decision time and signing time, for example to detect corruption in their own storage layer. A common implementation is an HMAC computed with a service-wide key at decision time and stored alongside the receipt in the operational database.

Such checks are strictly internal to the issuer. They **MUST NOT** appear in the signed payload, the receipt's wire format, exported receipts, or any verifier's validation algorithm. They provide consistency signals for the issuer's own operations (for example: detecting a database row that was rewritten between decision and signing) but provide **no security guarantees** against attackers who have compromised the issuer's infrastructure — such an attacker can recompute the internal check. They are not tamper evidence.

Implementers are cautioned against presenting internal integrity checks to customers or auditors as security features. The only signature that matters for third-party verification is the Ed25519 signature in §5.1.

## 6. Public key distribution

Issuers **MUST** publish the Ed25519 public keys for each workspace at a stable, HTTPS-served URL. The canonical URL pattern is:

```
https://{issuer-domain}/v1/workspaces/{workspace_id}/keys
```

The response is a JSON document:

```json
{
  "workspace_id": "ws_01HXA1B2C3D4E5F6G7H8J9K0L1",
  "keys": [
    {
      "key_id": "projects/allowly-prod/...cryptoKeyVersions/3",
      "alg": "Ed25519",
      "public_key": "base64url-encoded 32-byte Ed25519 public key",
      "active_from": "2026-04-01T00:00:00Z",
      "active_until": null
    },
    {
      "key_id": "projects/allowly-prod/...cryptoKeyVersions/2",
      "alg": "Ed25519",
      "public_key": "...",
      "active_from": "2026-01-15T00:00:00Z",
      "active_until": "2026-04-01T00:00:00Z"
    }
  ]
}
```

Keys **MUST** remain published even after rotation so historical receipts remain verifiable. `active_until` being non-null indicates the key is retired but receipts signed during its active window remain valid.

Verifiers **SHOULD** cache this document; issuers **SHOULD** set `Cache-Control: max-age=3600` or similar.

## 7. Verification algorithm

A verifier given a receipt `R` and the issuer's public keys **MUST** perform all of the following steps in order, and **MUST** reject the receipt if any step fails.

1. **Version check.** Assert `R.version == "1.0"`.
2. **Schema check.** Assert all fields in §3.1 are present with the correct types. Assert no unknown top-level fields are present. Assert `R.signature.value` is a non-empty string that decodes from base64url to exactly 64 bytes — this rejects placeholders, empty strings, and pending markers on shape alone. If `R.policy_eval` is present, assert it conforms to §3.6.1: an object with exactly `matched_condition` (an object with exactly the members `field`, `op`, `value` — or null; `value` may be a scalar or an array of scalars) and `field_value` (string, integer, boolean, or null), and no other members.
3. **Receipt kind and pairing check.** Determine the receipt kind from which discriminator field is present, and enforce the corresponding constraints:
   - Exactly one of `scope` and `event` MUST be present. Reject if both are present, or if neither is present.
   - **If `event` is present** (event receipt):
     - `event` MUST be one of `"authorization.create"`, `"authorization.revoke"`, or `"escalation.resolve"`.
     - If `event == "authorization.create"`: `decision` MUST equal `"authorization_granted"`.
     - If `event == "authorization.revoke"`: `decision` MUST equal `"authorization_revoked"`.
     - If `event == "escalation.resolve"`: `decision` MUST be one of `"escalation_approved"` or `"escalation_rejected"`.
     - `authorization_id` MUST NOT be `null`.
     - `resource` MUST be `null` for authorization create/revoke receipts.
     - `policy_eval` MUST be absent.
   - **If `scope` is present** (action receipt):
     - `decision` MUST be one of `"allow"`, `"deny"`, `"confirm"`, or `"escalate"`.
     - The reserved event-only decisions (`authorization_granted`, `authorization_revoked`, `escalation_approved`, `escalation_rejected`) MUST NOT appear.
4. **Algorithm check.** Assert `R.signature.alg == "Ed25519"`.
5. **Timestamp sanity.** Parse `R.issued_at` as RFC 3339. Assert it is not in the future (allowing a small skew, e.g. 5 minutes) and not absurdly far in the past (spec does not mandate a cutoff; verifier policy).
6. **Canonicalize.** Produce the canonical payload bytes per §4.
7. **Signature verification.**
   - Look up the public key matching `R.signature.key_id` from the published key document.
   - If the key is not found, reject.
   - If the key's active window does not include `R.issued_at`, reject.
   - Verify the Ed25519 signature against the canonical payload bytes per RFC 8032. If verification fails, reject.
8. **Accept.** If all checks pass, the receipt is valid.

A valid action receipt attests that: *at `issued_at`, the issuer identified by `workspace_id` made `decision` about `scope` by `agent_id` on behalf of `user_id`, under `authorization_id`, with policy version `policy_version`.*

A valid event receipt attests that: *at `issued_at`, the issuer identified by `workspace_id` recorded an authorization-related event (`event`) for `authorization_id`, with `user_id` and `agent_id` as the parties, and context detailing the relevant scopes, metadata, or escalation resolution.*

### 7.1 What verification does NOT prove

Verifiers and users of verified receipts **MUST NOT** assume the following:

1. **That the action actually happened.** An action receipt records what the agent *asked about*, not what the agent *did*. An `allow` decision followed by no action still produces a receipt.
2. **That the user's approval was informed.** An `authorization.create` receipt records that the customer told the issuer the user approved. It does not prove the customer's approval UI was clear, the user read it, or the user understood what they approved. The quality of the approval UX is the customer's responsibility, not the receipt's.
3. **That the context is true.** Fields like `initiated_by` and `origin` reflect what the customer's system reported at the time. The issuer does not independently verify them.
4. **That `user_id` corresponds to any particular real-world person.** It is an opaque identifier the customer controls.

These limits are intentional. The receipt attests to what the issuer observed and recorded, not to ground truth about the world.

## 8. Revocation

Receipts are immutable and never revoked. A revocation of an authorization is itself a new event that produces a new `authorization.revoke` receipt. After revocation, subsequent action checks against the same `authorization_id` return `deny` with `reason: "authorization_revoked"`, each producing its own signed action receipt. The complete history — creation, actions, revocation, and any post-revocation denies — is reconstructable via the authorization chain (§3.5).

Authorizations are likewise immutable (§3.3): there is no update event, and a change to scopes, constraints, or verb-routing rules is expressed as revoke + create, never as mutation of an existing authorization.

## 9. Test vectors

Reference test vectors are provided in `test-vectors.json`. Implementations **MUST** pass all vectors in the `should_verify` group and **MUST** reject all vectors in the `should_reject` group with the specified reason.

Vectors include:

*Action receipts that MUST verify:*
- A minimal `allow` action receipt with an empty context.
- A `deny` receipt with `authorization_id: null`.
- A receipt with non-ASCII characters in multiple fields (tests UTF-8 handling).
- A receipt with a rich nested context object (tests canonicalization correctness).
- An `escalate` receipt with escalation context.
- A `confirm` receipt with a `policy_eval` block whose `matched_condition` fired (tests §3.6 schema and the `policy_eval` < `policy_version` canonical sort).
- A `confirm` receipt with a `policy_eval.matched_condition.value` array for an `in` condition.
- An `allow` receipt with `policy_eval.matched_condition: null` and `field_value: null` (conditions evaluated, none matched).
- A `confirm` receipt with `reason: "context_field_missing"`, `matched_condition` set, `field_value: null` (fail-closed convention).

*Event receipts that MUST verify:*
- A `authorization.create` receipt with scopes, expiry, and a `csv_hash` source identifier.
- A `authorization.create` receipt carrying a `replaces` lineage pointer in context (§3.3).
- A `authorization.revoke` receipt with `revoked_by: "user"` in context.
- An `escalation.resolve` receipt with an approved resolution and resource binding.

*Receipts that MUST be rejected:*
- A receipt with a tampered payload (signature fails).
- A receipt with a forged signature (zero bytes).
- A receipt with an unknown `key_id`.
- A receipt with `version: "2.0"` (v1 verifier rejects).
- A receipt with an unknown top-level field.
- A receipt with a required field missing.
- A receipt with `decision: "maybe"` (invalid decision value).
- A receipt with both `scope` and `event` present.
- A receipt with neither `scope` nor `event` present.
- A receipt with `event: "authorization.update"` (unknown event — removed in draft.5).
- A receipt with `event: "authorization.create"` but `decision: "allow"` (pairing violation).
- A receipt with `event: "authorization.revoke"` but `authorization_id: null` (pairing violation).
- A receipt with `event: "authorization.create"` but a non-null `resource` (pairing violation).
- An event receipt carrying a `policy_eval` block (pairing violation).
- An action receipt whose `policy_eval` carries an unknown extra member (schema violation, §3.6.1).
- An action receipt whose `policy_eval.matched_condition` is missing `op` (schema violation, §3.6.1).
- An action receipt with a non-integer number in `policy_eval.field_value` (canonicalization rule 6).
- An action receipt with an event-only decision such as `authorization_granted` (reserved decision misuse).

## 10. Security considerations

### 10.1 Key compromise

If an issuer's Ed25519 private key is compromised, all receipts signed under that key are untrustworthy from the moment of compromise until rotation. Issuers **SHOULD** rotate keys at least annually. Verifiers **SHOULD** consult the key document's `active_until` field when verifying old receipts; a key retired for compromise should have `active_until` set to the compromise time, invalidating all later receipts signed under it.

### 10.2 Canonicalization fragility

Incorrect canonicalization is the most common implementation bug in JSON signing schemes. The specific rules in §4 are chosen to be implementable with standard library functions in most languages (`JSON.stringify` in JavaScript with sorted keys, `json.dumps` in Python with `sort_keys=True`, `separators=(",", ":")`, and `ensure_ascii=False`), but implementers **MUST** verify against the reference test vectors before trusting their implementation.

### 10.3 Replay

The receipt format does not include a replay-protection mechanism beyond `receipt_id` and `issued_at`. Receipts are not bearer tokens — they do not authorize any action and cannot be "replayed" to cause an action. They attest to past decisions. Duplicate receipts (same `receipt_id` appearing twice) indicate a bug, not an attack.

### 10.4 Privacy of receipts

Receipts contain `user_id`, `agent_id`, `scope` (or `event`), and `resource`. These may be sensitive. Issuers and customers **SHOULD** treat receipt exports with the same care as other logs containing user identifiers. The receipt format does not encrypt content; if confidentiality is required, transport- or storage-layer encryption **MUST** be applied separately.

### 10.5 Signing window and issuer SLA

Because signing is often asynchronous, an issuer that goes offline between decision time and signing time produces decisions whose receipts remain in pending state — outside this format — until signing resumes. Issuers **SHOULD** publish and enforce a maximum signing window after which operators are alerted (typical SLA: receipts are signed within 60 seconds of issuance). Customers **SHOULD** treat the issuer's pending response as transient and follow the issuer's documented retrieval mechanism (typically a poll-the-receipt-URL pattern) before treating any artifact as audit evidence. The receipt format itself does not include a pending state — pending is a transport-layer concept the issuer's API surfaces in a structurally distinct response.

### 10.6 PII in identifiers

`user_id` and `agent_id` are opaque strings to the issuer and verifier. Customers choose what they mean. Customers **SHOULD NOT** use identifiers that contain personally identifiable information — raw email addresses, phone numbers, or legal names — for three reasons:

1. **Receipts are long-lived.** A PII-laden `user_id` is embedded in every signed receipt for that user, for as long as receipts are retained. Retention policies that would normally apply to PII (deletion on request, region restrictions) are much harder to enforce against an immutable signed ledger.
2. **Identifiers should be stable across user lifecycle.** Email addresses change when people marry, change companies, or get domains renamed. An ID that changes breaks audit continuity; an ID that's PII *and* changes breaks both.
3. **Enumeration risk.** If an identifier is guessable (emails in a known domain), a leaked receipt snippet reveals more than just "a receipt exists" — it reveals who it's about.

Recommended: customers use their internal opaque identifier (a ULID, UUID, or equivalent) as `user_id`, and maintain the mapping to human identities in their own systems, outside the receipt ledger. If a customer needs to key identity on email, they **SHOULD** hash the email with a per-workspace salt before using it as `user_id`, producing an opaque-but-stable identifier.

### 10.7 Snapshot minimization in `policy_eval.field_value`

`field_value` copies a piece of evaluated customer context into a signed, immutable, long-lived record. Anything snapshotted here inherits every retention problem described in §10.6: it cannot be deleted, redacted, or regionally restricted after signing.

Issuers and customers **SHOULD**:

- Snapshot the minimum value the condition actually compared — the number or flag, not the record it came from. `"field_value": 2` (a score delta) is appropriate; copying a free-text note or a full profile attribute is not.
- Never route conditions on raw sensitive personal attributes (health status, protected-class data, salary, precise location). Where a sensitive signal is genuinely needed for routing, evaluate and snapshot a derived form — a boolean, a bucket, a scaled score — so the signed record carries the decision-relevant abstraction rather than the underlying attribute.
- Treat exports containing `policy_eval` with the same care as receipt exports generally (§10.4).

The format cannot police the semantics of what customers evaluate; this guidance marks the boundary between an audit artifact and a data-retention liability.

## 11. Changelog

- **1.0.0-draft.5 (2026-06-09)** — Immutability restored; versioning policy.
  - **Removed `authorization.update`** and the `authorization_updated` decision. Authorizations are immutable: any change to scopes, constraints, or verb-routing rules is expressed as revoke + create (§3.3, §8). The authorization chain (§3.5) is again create → actions → escalation resolutions → revoke.
  - **Removed `authorization_version`** from `policy_eval`, which is now exactly `{matched_condition, field_value}`. With immutable authorizations, the top-level `authorization_id` alone pins the rule set in force; no revision counter exists.
  - Added the non-normative `replaces` lineage convention: a creation receipt's context MAY name the predecessor authorization it supersedes (§3.3, §3.5).
  - Added the versioning policy (§3.2): pre-final drafts ship spec/verifiers/vectors in lockstep under wire version `"1.0"`; after 1.0.0 final, additive optional fields require a minor wire-version bump and verifiers declare accepted version sets.
  - Added §10.7: snapshot-minimization guidance for `policy_eval.field_value` (no raw sensitive attributes in signed records; snapshot derived forms).
  - Verifier: `policy_eval` schema check tightened to the two-member shape with strict `matched_condition` internals; update-event pairing rules deleted. Test vectors regenerated (update vectors removed; `replaces`, unknown-member, and malformed-`matched_condition` vectors added).

- **1.0.0-draft.4 (2026-06-09)** — Conditional policy evaluation.
  - Added optional top-level `policy_eval` block on action receipts (§3.6): `authorization_version`, `matched_condition`, `field_value`. Receipts now record *why* a verb fired and *which* authorization revision was in force, without defining the condition language (still a non-goal per §1).
  - Added `authorization.update` event receipts with the `authorization_updated` decision; the authorization chain (§3.5) now records constraint revisions, so every `policy_eval.authorization_version` resolves to a signed snapshot of the rules in force.
  - Value typing: condition values and `field_value` are restricted to integers, strings, booleans, or null, per canonicalization rule 6 (no floats).
  - Documented the fail-closed convention (`reason: "context_field_missing"`) as non-normative issuer guidance (§3.6.3).
  - Verifier: schema check extended for `policy_eval` (§7 step 2); pairing rules extended for the update event and the `policy_eval`-on-event prohibition (§7 step 3). Test vectors regenerated.
  - **Compatibility:** draft.3 verifiers reject any receipt carrying `policy_eval` under the unknown-top-level-field rule. Deploy verifier updates before issuers enable `policy_eval` emission. Receipts that omit `policy_eval` are byte-identical under draft.3 and draft.4.

- **1.0.0-draft.3 (2026-06-03)** — Escalation receipts.
  - Added `escalate` as an action receipt decision.
  - Added `escalation.resolve` event receipts with `escalation_approved` and `escalation_rejected` decisions.
  - Clarified that authorization create/revoke events require `resource: null`, while escalation resolution may carry the resource binding.

- **1.0.0-draft.2 (2026-05-09)** — Naming refinement.
  - Replaced the overloaded `action` field with two mutually exclusive discriminator fields: `scope` (action receipts) and `event` (event receipts).
  - Field's presence now carries the receipt kind explicitly. Pairing rules are simpler. Verifier logic shorter.
  - Reserved authorization-lifecycle event names (`authorization.create`, `authorization.revoke`) moved from `action` values to `event` values.
  - All existing pairing checks updated; test vectors regenerated.

- **1.0.0-draft (2026-04-21)** — Initial public draft.
  - Flat receipt structure: no wrapping `subject` or `action` objects. `user_id`, `agent_id`, `action`, `resource`, and `context` are all top-level fields.
  - Two receipt kinds share the same format: action receipts (decisioning) and event receipts (lifecycle).
  - Single Ed25519 signature over the canonical payload.
  - Asynchronous signing handled at the transport layer; pending receipts are not part of the receipt format.
  - Internal integrity checks (e.g. HMAC) are permitted but explicitly out of scope.
  - Explicit guidance against PII in `user_id` and `agent_id`.

---

*This specification is maintained at https://github.com/allowly/receipt-format. Comments, issues, and pull requests welcome.*
