# Changelog

## Unreleased

## v2.1.1 — 2026-07-22

- **Receipt wire format 2.1.0.** Renamed the receipt `version` field to
  `schema_version` and set the only accepted value to `"2.1.0"`. The rename
  moves the field's canonical sort position (before `user_id`), so 2.0.0 and
  2.1.0 signatures are not interchangeable. Test vectors regenerated.
- Corrects the v2.1.0 release, which added `budget.settle` receipts to the
  spec without bumping the wire version — leaving new-event receipts labeled
  `"2.0.0"`, a claim 2.0.0-only verifiers reject.
- Breaking release with no compatibility branch or deprecation window:
  pre-launch, no deployed external verifiers, no receipts in the wild.
- Adopts the package-numbering scheme: verifier packages use
  `2.<wire minor>.<patch>` — the package minor always names the wire format it
  verifies, so `~2.1.x` ranges can never cross a wire boundary. Note the
  pre-scheme packages published as 2.1.0 verify wire 2.0.0 and are yanked.

## v2.1.0 — 2026-07-22

- Add `budget.settle` event receipts with the paired `budget_settled` decision
  for exact post-execution cost reconciliation.
- Require exact UTC millisecond timestamps for receipts and key active windows,
  with strict `active_until` typing and half-open boundary vectors.
- Make malformed receipts and export lines fail cleanly, reject hostile event
  names, and strengthen canonicalization and event-pairing regression coverage.
- Add the optional `hmac-v1` keyed-pseudonym convention in specification
  Appendix A and the offline `matches_ref` (Python) / `matchesRef` (TypeScript)
  helpers in both reference verifiers. Receipt schema, signature verification,
  canonicalization, and wire version are unchanged.

## v2.0.0 — 2026-07-20

- Document `deny_when` as a non-normative issuer convention and add a valid
  `deny_condition_matched` compatibility vector.
- Replace the old wire shape with receipt format `"2.0.0"`: top-level `alg` and `key_id` are now signed, and
  `signature` contains the canonical base64url Ed25519 signature string.
- Reference verifiers accept only receipt format `"2.0.0"`; there are no
  customer receipts requiring a compatibility branch.
- Reject unpaired surrogates, non-canonical base64url pad bits, and payloads
  over the normative depth/node limits; specify unique raw JSON names and
  integer-only token spelling at the interchange boundary.

## v1.0.5 — 2026-06-18

Packaging-only release to publish the current verifier packages from a fresh
tag after the earlier 1.0.4 tag was present on GitHub but not available on
PyPI. Format, canonicalization, verifier behavior, and test vectors are
unchanged.

## v1.0.4 — 2026-06-14

Internal refactor, no behavior change. Simplified the test-vector generator
(`scripts/gen_vectors.py`) and extracted a shared exact-keys validation helper in the
Python verifier. The format, canonicalization, verifier behavior, and `test-vectors.json`
are unchanged — the vectors are byte-identical and both reference verifiers pass. Both
packages (`allowly-receipt-format` on PyPI, `@allowly/verifier` on npm) publish 1.0.4 from
one tag. Wire version stays `"1.0"`; spec label stays `1.0.0`.

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
