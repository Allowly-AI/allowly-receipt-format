# Changelog

## Unreleased

### Format

- Add `escalate` as a valid action receipt decision.
- Add `escalation.resolve` event receipts with `escalation_approved` and `escalation_rejected` decisions.
- Clarify that authorization create/revoke receipts keep `resource: null`, while escalation resolution receipts may carry the resource binding.

### Verification

- Update Python and TypeScript reference verifiers to accept escalation action and event receipts.
- Regenerate shared test vectors with escalation coverage.

## v1.0.0 — 2026-05-29

Final v1.0.0 release of the Allowly Receipt Format.

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
- Internal integrity checks (e.g. HMAC for storage-layer consistency) are permitted but explicitly out of scope for the wire format.

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
- Chained receipt presentation (creation + action receipts + revocation as a single bundle) may warrant a defined bundle format in a future version.
