# Allowly Receipt Format

An open format for **cryptographically signed, third-party-verifiable receipts** of AI agent authorization decisions.

A receipt is a signed record of one decision: *at time T, issuer W decided that agent A may (or may not) perform action X on resource R for user U under authorization C.* Anyone holding the receipt and the issuer's Ed25519 public key, authenticated directly or against a retained fingerprint, can verify it offline without contacting the issuer.

Action receipts can include `policy_eval`, a small record of which immutable authorization condition routed a decision to `deny`, `confirm`, or `escalate`. Daily `receipt.checkpoint` events commit to the issuer's registered signed receipt set for one UTC day. The current wire format is `"4"` (wire versions are plain integer strings).

Specification Appendix A also defines an optional `hmac-v1` convention for
customer-recomputable pseudonymous values inside `context`; it does not change
the receipt wire format or verification algorithm.

Appendix B defines the optional `allowly.seal.jcs-sha256.v1` profile for
strictly hashing JSON records with RFC 8785 and verifying the digest against a
normal signed wire-4 receipt. The record stays local; only its digest needs to
reach an issuer.

## Why this exists

AI agents are being given broad access to user data, and the audit story is currently *"trust the vendor's dashboard."* That's not enough for SOC 2, the EU AI Act, or any serious procurement review. The receipt format is the artifact that moves audit from "the vendor says so" to "here's a signature anyone can verify."

The format is vendor-neutral on purpose. Any service making agent authorization decisions can issue receipts in this format; any verifier can check them.

## Repo layout

- `spec/receipt-format.md` — the normative specification.
- [INTEROP.md](./INTEROP.md) — runtime-governance responsibilities, AARM mapping, and ACTA draft comparison.
- `verifiers/python/` — reference Python verifier (`allowly-receipt-format` on PyPI).
- `verifiers/typescript/` — reference TypeScript verifier (`@allowly/verifier` on npm).
- `test-vectors.json` — shared test vectors every implementation must pass.
- `vectors/seal/` — shared strict-hashing and signed SEAL verification vectors.
- `spec/profiles/allowly-conditional-evaluation-v1.md` — Allowly's conditional
  policy replay profile (unreleased).
- `vectors/policy/` — shared conditional policy evaluation fixtures.
- `GOVERNANCE.md` — how decisions about the spec get made.
- `CONTRIBUTING.md` — how to report bugs, propose changes, and add verifiers.
- `CHANGELOG.md` — version history.

## Quick start

Verify a receipt in Python:

```bash
pip install allowly-receipt-format
allowly-receipt-verify \
  --workspace-id "$ALLOWLY_WORKSPACE_ID" \
  --trusted-key-fingerprint "$ALLOWLY_TRUSTED_KEY_FINGERPRINT" \
  path/to/receipt.json path/to/keys.json
```

Obtain `keys.json` for the workspace ID in caller-trusted configuration; never
choose the trust anchor from the receipt's own `workspace_id` claim. Obtain the
`sha256:<64 lowercase hex>` fingerprint of each trusted Ed25519 public key over
an authenticated channel; repeat `--trusted-key-fingerprint` after rotations.
A key document or fingerprint bundled with receipts is not trusted merely
because it is in the same archive.

```python
import os

from allowly_receipt_format import verify_receipt, load_keys_from_json

# Load this from caller-trusted configuration, never from the receipt or key
# document. Key ids alone do not bind a receipt to a workspace.
configured_workspace_id = os.environ["ALLOWLY_WORKSPACE_ID"]
if keys_doc.get("workspace_id") != configured_workspace_id:
    raise ValueError("key document workspace does not match configuration")
verify_receipt(
    receipt,
    load_keys_from_json(keys_doc),
    expected_workspace_id=configured_workspace_id,
    trusted_key_fingerprints={os.environ["ALLOWLY_TRUSTED_KEY_FINGERPRINT"]},
)  # raises VerificationError if invalid
```

Verify a receipt in TypeScript:

```bash
npm install @allowly/verifier
```

```typescript
import { verifyReceipt, loadKeysFromJson, VerificationError } from "@allowly/verifier";

// verifyReceipt resolves on success and throws VerificationError on failure —
// it does not return a boolean. Load the workspace id from caller-trusted
// configuration, never from the receipt or key document.
const configuredWorkspaceId = process.env.ALLOWLY_WORKSPACE_ID;
const configuredKeyFingerprint = process.env.ALLOWLY_TRUSTED_KEY_FINGERPRINT;
if (!configuredWorkspaceId) throw new Error("ALLOWLY_WORKSPACE_ID is required");
if (!configuredKeyFingerprint) {
  throw new Error("ALLOWLY_TRUSTED_KEY_FINGERPRINT is required");
}
if (keysDoc.workspace_id !== configuredWorkspaceId) {
  throw new Error("key document workspace does not match configuration");
}
try {
  await verifyReceipt(receipt, loadKeysFromJson(keysDoc), {
    expectedWorkspaceId: configuredWorkspaceId,
    trustedKeyFingerprints: new Set([configuredKeyFingerprint]),
  });
  // valid
} catch (e) {
  if (e instanceof VerificationError) {
    // invalid: e.message says why
  } else throw e;
}
```

## Status

### Conditional policy replay (unreleased)

The feature branch adds `verify_policy_evaluation` in Python and
`verifyPolicyEvaluation` in TypeScript. They authenticate an action receipt and
its signed authorization snapshot, repeat the supported conditional calculation,
and report `matched`, `mismatch` or `not_checked` with a diagnostic. These results
are separate from signature verification. They do not reproduce budget, rate,
revocation or human-approval state, or establish that the inputs were true.

Use a reviewed source checkout for this feature. Published 4.1.0 packages do not
contain policy replay. The Python and TypeScript manifests identify the pending
coordinated release as 4.2.0. Install `./verifiers/python` into an isolated
environment, or build `verifiers/typescript` locally; see the package READMEs
for the new function and CLI options. Publish both packages and update consumer
locks before deployment. Existing signature verification commands above
continue to work with the published packages.

### Receipt wire format

**Verifier packages 4.x implement receipt wire format 4.** Wire versions are plain integers and the package major always equals the wire version it verifies, so default caret ranges (`^4.0.0`) can never cross a wire boundary. Receipts carry `schema_version: "4"` and sign top-level `alg` and `key_id`; `signature` is the base64url signature string. Reference verifiers accept only receipt wire format 4 and recompute checkpoint Merkle roots in both languages. A checkpoint proves equality to its signed set commitment, not that the issuer registered every real-world event or externally anchored the checkpoint.

There is intentionally no wire-3 compatibility path. Cut over only with an
empty receipt registry and no active wire-3 writers; rollback across this wire
boundary is unsupported.

## Licensing

- **Specification text and interoperability guide** (`spec/`, `INTEROP.md`): CC-BY 4.0. Fork it, reference it, implement it.
- **Reference code** (`verifiers/`, test harness): Apache 2.0.

## Who maintains this

The spec is currently maintained by [Allowly](https://allowly.ai). Contributions from anyone implementing or deploying receipt-based audit flows are welcome — see [GOVERNANCE.md](./GOVERNANCE.md) and [CONTRIBUTING.md](./CONTRIBUTING.md).
