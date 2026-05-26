# Allowly Receipt Format Specification

**Version:** 1.0.0-draft.2
**Status:** Draft — public review
**License:** This specification is published under CC-BY 4.0. Reference implementations are Apache 2.0.

---

## 1. Purpose

A *receipt* is a signed, immutable record of a single authorization event — either an authorization decision made by an authorization-check service at the moment an agent or human acted, or a lifecycle event on the authorization itself (creation, revocation). This document specifies the canonical format, signature scheme, and verification algorithm so that any party holding a receipt and the issuer's public key can verify the receipt offline, without contacting the issuer.

Two kinds of receipts share the same format:

- **Action receipts** record a single authorization decision: *at time T, the issuer decided that action A by agent G on behalf of user U was allowed, denied, or required confirmation, under authorization C.* These are produced by the issuer's `/check` endpoint.
- **Authorization receipts** record an authorization lifecycle event: *at time T, user U authorized agent G with scopes S,* or *at time T, that authorization was revoked.* These are produced when an authorization is created or revoked.

Both kinds of receipts use the same JSON structure, the same canonicalization, the same signature scheme, and the same verifier. They differ only in the values of a few fields (§3.3). An auditor presented with a dispute typically needs both: the authorization receipt proves *what was authorized*, the action receipts prove *what happened under that authorization*.

The goals of this format are, in order:

1. **Third-party verifiability.** An auditor, regulator, or end-user can verify a receipt without trusting the issuer's continued cooperation or uptime.
2. **Tamper evidence.** Any modification to the receipt content after signing is detectable.
3. **Portability.** Receipts remain verifiable if the issuer goes out of business, the customer switches vendors, or the verifier is written in a different language.
4. **Simplicity.** The verification algorithm is short enough to reimplement in any language in under 200 lines.

Non-goals: this spec does not define the *decision logic* that produced the receipt, the *policy language* used to describe permissions, or the *transport* used to deliver receipts. It defines only the signed artifact and how to verify it.

## 2. Terminology

The key words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** in this document are to be interpreted as described in RFC 2119 and RFC 8174.

- **Receipt** — a JSON object conforming to §3 plus its signature. Either an action receipt or an authorization receipt. A receipt always carries a real Ed25519 signature; an in-flight pending state is a transport-layer concept the issuer surfaces separately (§5.3).
- **Action receipt** — a receipt recording a single authorization decision at the moment of an action. See §3.3.
- **Authorization receipt** — a receipt recording an authorization lifecycle event (creation or revocation). See §3.3.
- **Issuer** — the entity that produced and signed the receipt. Identified by `workspace_id`.
- **Subject** — the end-user on whose behalf an agent acted, or who granted the authorization. Identified by `user_id`.
- **Verifier** — any party validating a receipt.
- **Canonical form** — the byte sequence produced by applying the canonicalization rules in §4 to a receipt's payload.

## 3. Receipt structure

A receipt is a JSON object with exactly the following top-level fields. Unknown fields **MUST NOT** be present in v1 receipts; verifiers **MUST** reject receipts containing unknown top-level fields.

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
| `scope` | string \| absent | conditional | Present on action receipts. The scope name being checked (e.g. `email.send`, `contact.enrich`). Format is issuer-defined but conventionally dotted. **MUST be absent on authorization receipts.** |
| `event` | string \| absent | conditional | Present on authorization receipts. One of `"authorization.create"` or `"authorization.revoke"`. **MUST be absent on action receipts.** |
| `resource` | string \| null | yes | An identifier for the target of the action, or `null` (always `null` for authorization receipts, or for action receipts whose scope has no resource). Issuers MUST NOT include the resource's contents, only an identifier. |
| `context` | object | yes | An opaque object of additional facts the issuer considered. Contents are issuer-defined. Verifiers MUST preserve the object byte-for-byte during canonicalization. MAY be empty (`{}`). |
| `authorization_id` | string \| null | yes | The authorization record this receipt relates to. For action receipts: the authorization that authorized the decision, or `null` if no authorization matched. For authorization receipts: the `authorization_id` being created or revoked (never `null`). |
| `policy_version` | string | yes | Version of the issuer's decision logic at time of issue. Format is issuer-defined. |
| `signature` | object | yes | See §5. |

### 3.2 Extensibility

Future versions MAY add fields. Verifiers implementing v1 **MUST** reject any receipt whose `version` field is not exactly `"1.0"`. Verifiers implementing a later version **MUST** refuse to verify v1 receipts using v2 rules; forward compatibility is by version gating, not by best-effort parsing.

### 3.3 Receipt kinds

Receipts come in two kinds, distinguished by which of two mutually exclusive fields is present:

**Action receipts** record a single authorization decision at the moment of an action. They are produced by the issuer's decisioning endpoint (conventionally `POST /v1/check`).

- `scope` — present, set to the scope name being checked. Conventionally dotted (`email.send`, `contact.enrich`, `payment.approve`).
- `event` — **MUST be absent.**
- `decision` — one of `"allow"`, `"deny"`, `"confirm"`.
- `authorization_id` — the matching authorization, or `null` if no authorization matched.
- `resource` — an identifier for the action's target, or `null`.

**Authorization receipts** record an authorization lifecycle event. They are produced when an authorization is created or revoked.

- `event` — present, one of:
  - `"authorization.create"` — the customer recorded that a user approved a set of scopes for an agent.
  - `"authorization.revoke"` — the authorization was revoked (by the user, by the customer, or automatically on expiry).
- `scope` — **MUST be absent.**
- `decision` — one of:
  - `"authorization_granted"` — paired with `event: "authorization.create"`.
  - `"authorization_revoked"` — paired with `event: "authorization.revoke"`.
- `authorization_id` — the authorization being created or revoked. **MUST NOT** be `null` on an authorization receipt.
- `resource` — **MUST** be `null` on an authorization receipt.
- `context` — conventionally carries lifecycle metadata: the full scope set at creation, `expires_at`, `requires_confirm_for`, the creation source (`csv_upload`, `onboarding_modal`), an optional `csv_hash` or similar integrity identifier, and for revocations a `revoked_by` field (`user`, `admin`, `expired`, `tombstone`).

Verifiers **MUST** enforce the following:

- Exactly one of `scope` and `event` is present. Receipts with both fields, or with neither, are rejected.
- If `event` is present, it MUST be one of `"authorization.create"` or `"authorization.revoke"`. The corresponding `decision` MUST be the matching value (`authorization_granted` or `authorization_revoked`). `authorization_id` MUST NOT be `null`. `resource` MUST be `null`.
- If `scope` is present, `decision` MUST be one of `"allow"`, `"deny"`, `"confirm"`. The reserved authorization-lifecycle decisions (`authorization_granted`, `authorization_revoked`) MUST NOT appear on action receipts.

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
    "scopes": ["contact.enrich", "outreach.send"],
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
2. Zero or more action receipts (each check that matched this authorization).
3. At most one `authorization.revoke` receipt (if and when the authorization was revoked).

The chain is self-verifying: every receipt is independently signed, ordered by `issued_at`, and cryptographically tied to the same `authorization_id`. Producing this chain is the primary artifact customers present in disputes.

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

Note: `scope` and `event` are mutually exclusive — the canonical form contains exactly one of them, never both. The lexicographic key sort places `event` before `scope`, which matters for canonicalization correctness when generating authorization receipts vs action receipts.

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
2. **Schema check.** Assert all fields in §3.1 are present with the correct types. Assert no unknown top-level fields are present. Assert `R.signature.value` is a non-empty string that decodes from base64url to exactly 64 bytes — this rejects placeholders, empty strings, and pending markers on shape alone.
3. **Receipt kind and pairing check.** Determine the receipt kind from which discriminator field is present, and enforce the corresponding constraints:
   - Exactly one of `scope` and `event` MUST be present. Reject if both are present, or if neither is present.
   - **If `event` is present** (authorization receipt):
     - `event` MUST be one of `"authorization.create"` or `"authorization.revoke"`.
     - If `event == "authorization.create"`: `decision` MUST equal `"authorization_granted"`.
     - If `event == "authorization.revoke"`: `decision` MUST equal `"authorization_revoked"`.
     - `authorization_id` MUST NOT be `null`.
     - `resource` MUST be `null`.
   - **If `scope` is present** (action receipt):
     - `decision` MUST be one of `"allow"`, `"deny"`, `"confirm"`.
     - The reserved authorization-lifecycle decisions (`authorization_granted`, `authorization_revoked`) MUST NOT appear.
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

A valid authorization receipt attests that: *at `issued_at`, the issuer identified by `workspace_id` recorded an authorization lifecycle event (`event`) for `authorization_id`, with `user_id` and `agent_id` as the parties, and context detailing the scopes and metadata.*

### 7.1 What verification does NOT prove

Verifiers and users of verified receipts **MUST NOT** assume the following:

1. **That the action actually happened.** An action receipt records what the agent *asked about*, not what the agent *did*. An `allow` decision followed by no action still produces a receipt.
2. **That the user's approval was informed.** An `authorization.create` receipt records that the customer told the issuer the user approved. It does not prove the customer's approval UI was clear, the user read it, or the user understood what they approved. The quality of the approval UX is the customer's responsibility, not the receipt's.
3. **That the context is true.** Fields like `initiated_by` and `origin` reflect what the customer's system reported at the time. The issuer does not independently verify them.
4. **That `user_id` corresponds to any particular real-world person.** It is an opaque identifier the customer controls.

These limits are intentional. The receipt attests to what the issuer observed and recorded, not to ground truth about the world.

## 8. Revocation

Receipts are immutable and never revoked. A revocation of an authorization is itself a new event that produces a new `authorization.revoke` receipt. After revocation, subsequent action checks against the same `authorization_id` return `deny` with `reason: "authorization_revoked"`, each producing its own signed action receipt. The complete history — creation, actions, revocation, and any post-revocation denies — is reconstructable via the authorization chain (§3.5).

## 9. Test vectors

Reference test vectors are provided in `test-vectors.json`. Implementations **MUST** pass all vectors in the `should_verify` group and **MUST** reject all vectors in the `should_reject` group with the specified reason.

Vectors include:

*Action receipts that MUST verify:*
- A minimal `allow` action receipt with an empty context.
- A `deny` receipt with `authorization_id: null`.
- A receipt with non-ASCII characters in multiple fields (tests UTF-8 handling).
- A receipt with a rich nested context object (tests canonicalization correctness).

*Authorization receipts that MUST verify:*
- A `authorization.create` receipt with scopes, expiry, and a `csv_hash` source identifier.
- A `authorization.revoke` receipt with `revoked_by: "user"` in context.

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
- A receipt with `event: "authorization.create"` but `decision: "allow"` (pairing violation).
- A receipt with `event: "authorization.revoke"` but `authorization_id: null` (pairing violation).
- A receipt with `event: "authorization.create"` but a non-null `resource` (pairing violation).
- An action receipt with `decision: "authorization_granted"` (reserved decision misuse).

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

## 11. Changelog

- **1.0.0-draft.2 (2026-05-09)** — Naming refinement.
  - Replaced the overloaded `action` field with two mutually exclusive discriminator fields: `scope` (action receipts) and `event` (authorization receipts).
  - Field's presence now carries the receipt kind explicitly. Pairing rules are simpler. Verifier logic shorter.
  - Reserved authorization-lifecycle event names (`authorization.create`, `authorization.revoke`) moved from `action` values to `event` values.
  - All existing pairing checks updated; test vectors regenerated.

- **1.0.0-draft (2026-04-21)** — Initial public draft.
  - Flat receipt structure: no wrapping `subject` or `action` objects. `user_id`, `agent_id`, `action`, `resource`, and `context` are all top-level fields.
  - Two receipt kinds share the same format: action receipts (decisioning) and authorization receipts (lifecycle).
  - Single Ed25519 signature over the canonical payload.
  - Asynchronous signing handled at the transport layer; pending receipts are not part of the receipt format.
  - Internal integrity checks (e.g. HMAC) are permitted but explicitly out of scope.
  - Explicit guidance against PII in `user_id` and `agent_id`.

---

*This specification is maintained at https://github.com/allowly/receipt-format. Comments, issues, and pull requests welcome.*
