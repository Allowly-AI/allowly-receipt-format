# Changelog

## v1.0.3 — 2026-06-12

Unified release tag: both reference verifiers — `allowly-receipt-format` (PyPI) and
`@allowly/verifier` (npm) — publish 1.0.3 from this one tag, ending the earlier
PyPI/npm version skew (PyPI was at 1.0.0, npm at 1.0.2). Packaging-only: format,
canonicalization, verifier behavior, and test vectors are unchanged from 1.0.0. The
format/wire version remains `"1.0"` and the spec label remains `1.0.0`. From this tag
forward both packages version in lockstep.

## v1.0.0 — 2026-06-12

Stable v1.0.0 release of the Allowly Receipt Format. Finalizes the draft.6
review unchanged; the wire `version` stays `"1.0"`. Supersedes the earlier
2026-05-29 packaging cut (the format kept evolving through draft.6 after it).

### Format

- Add `escalate` as a valid action receipt decision.
- Add `escalation.resolve` event receipts with `escalation_approved` and `escalation_rejected` decisions.
- Clarify that authorization create/revoke receipts keep `resource: null`, while escalation resolution receipts may carry the resource binding.
- Add optional `policy_eval` on action receipts to record which immutable authorization condition routed a decision.
- Remove update-style authorization receipts; authorization changes are revoke + create.
- Document `replaces` lineage metadata for superseding authorizations.
- Document the `confirm_when` / `escalate_when` issuer convention as a non-normative policy authoring shape.
- Make supersession lineage bidirectional: add `revoked_by: "superseded"` and the `superseded_by` forward pointer on revoke receipts, upgrade `replaces` to SHOULD when superseding, and recommend `create.issued_at <= revoke.issued_at` ordering (§3.3, §3.5, §8).
- Bound integers to the I-JSON safe range ±(2⁵³−1) in canonicalization rule 6.
- Correct the §4.2 rule 3 / §10.2 prose that wrongly claimed `json.dumps(sort_keys=True)` is a conforming canonicalizer.
- Replace the unimplementable "preserve `context` byte-for-byte" wording (§3.1).

### Verification

- Update Python and TypeScript reference verifiers to accept escalation action and event receipts.
- Update Python and TypeScript reference verifiers to validate strict `policy_eval` shape.
- **Fix two cross-language canonicalization defects:** the Python verifier now sorts object keys by UTF-16 code unit (was code point) and escapes control characters as `\uXXXX` (was short escapes like `\n`), using a hand-rolled serializer instead of `json.dumps`.
- Reject integers outside the I-JSON safe range in both verifiers.
- Require `issued_at` to be a full RFC 3339 instant with an explicit offset (the TS verifier previously parsed timezone-less strings in local time) and `signature.value` to be unpadded base64url with no out-of-alphabet characters.
- Regenerate shared test vectors with escalation, immutable authorization, `policy_eval`, supersession-lineage, control-character, supplementary-plane-key, out-of-range-integer, bad-timestamp, and bad-signature-encoding coverage.

### Python

- Package the Python reference verifier as `allowly-receipt-format` with import path
  `allowly_receipt_format`.
- Add the `allowly-receipt-verify` console script.
- Add typed verifier exceptions:
  - `SchemaError`
  - `UnknownKeyError`
  - `KeyOutsideActiveWindowError`
  - `SignatureMismatchError`
- Keep all typed exceptions under the existing `VerificationError` base class.

## v1.0.0-draft — 2026-04-21

Initial public draft of the Allowly Receipt Format.

### Format

- Flat receipt structure: `user_id`, `agent_id`, `action`, `resource`, `context` are all top-level fields.
- **Two receipt kinds** share the same format:
  - **Action receipts** — record a single authorization decision (`allow`, `deny`, `confirm`).
  - **Authorization receipts** — record an authorization lifecycle event (`authorization.create`, `authorization.revoke`).
- Verifier enforces `action` / `decision` / `authorization_id` / `resource` pairings to prevent field-desync forgeries.
- Single Ed25519 signature over the canonical payload.
- Canonicalization follows a strict subset of RFC 8785.
- Asynchronous signing supported via `"pending"` marker; pending receipts are not valid audit artifacts.

### Signing

- Ed25519 (RFC 8032) is the only signature algorithm in v1.
- Implementation notes for Google Cloud KMS (software vs HSM) and AWS KMS.
- Internal integrity checks (e.g. HMAC for storage-layer consistency) are permitted but explicitly outside the wire format.

### Verification

- Nine-step verification algorithm defined in §7.
- Pending receipts explicitly rejected.
- Action / decision pairing constraints explicitly enforced.
- Reference verifiers in Python and TypeScript; both pass the same 18 test vectors.

### Privacy

- §10.6 guidance that `user_id` and `agent_id` should not contain PII.

### Open questions for v1.0.0 final

- Test vector coverage for unusual Unicode edge cases (combining characters, surrogate pairs) is still thin.
- Key rotation overlap (receipts signed across a key rotation boundary) needs a worked example.
- Chained receipt presentation (creation + action receipts + revocation as a single evidence pack) may warrant a defined package format in a future version.
