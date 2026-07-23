# Allowly Receipt Format

An open format for **cryptographically signed, third-party-verifiable receipts** of AI agent authorization decisions.

A receipt is a signed record of one decision: *at time T, issuer W decided that agent A may (or may not) perform action X on resource R for user U under authorization C.* Anyone holding the receipt and the issuer's Ed25519 public key can verify it offline, without contacting the issuer.

Action receipts can include `policy_eval`, a small record of which immutable authorization condition routed a decision to `deny`, `confirm`, or `escalate`. Receipt format 2.1.0 signs the algorithm and key identifier so the trust-anchor selector cannot be swapped after issue.

Specification Appendix A also defines an optional `hmac-v1` convention for
customer-recomputable pseudonymous values inside `context`; it does not change
the receipt wire format or verification algorithm.

## Why this exists

AI agents are being given broad access to user data, and the audit story is currently *"trust the vendor's dashboard."* That's not enough for SOC 2, the EU AI Act, or any serious procurement review. The receipt format is the artifact that moves audit from "the vendor says so" to "here's a signature anyone can verify."

The format is vendor-neutral on purpose. Any service making agent authorization decisions can issue receipts in this format; any verifier can check them.

## Repo layout

- `spec/receipt-format.md` — the normative specification.
- `verifiers/python/` — reference Python verifier (`allowly-receipt-format` on PyPI).
- `verifiers/typescript/` — reference TypeScript verifier (`@allowly/verifier` on npm).
- `test-vectors.json` — shared test vectors every implementation must pass.
- `GOVERNANCE.md` — how decisions about the spec get made.
- `CONTRIBUTING.md` — how to report bugs, propose changes, and add verifiers.
- `CHANGELOG.md` — version history.

## Quick start

Verify a receipt in Python:

```bash
pip install allowly-receipt-format
allowly-receipt-verify path/to/receipt.json path/to/keys.json
```

```python
from allowly_receipt_format import verify_receipt, load_keys_from_json

# Always pass expected_workspace_id: key ids alone do not bind a receipt
# to a workspace, so verifying without it accepts receipts signed for a
# different (or attacker-supplied) key document.
verify_receipt(
    receipt,
    load_keys_from_json(keys_doc),
    expected_workspace_id=keys_doc["workspace_id"],
)  # raises VerificationError if invalid
```

Verify a receipt in TypeScript:

```bash
npm install @allowly/verifier
```

```typescript
import { verifyReceipt, loadKeysFromJson, VerificationError } from "@allowly/verifier";

// verifyReceipt resolves on success and throws VerificationError on failure —
// it does not return a boolean. Always pass expectedWorkspaceId: key ids alone
// do not bind a receipt to a workspace.
try {
  await verifyReceipt(receipt, loadKeysFromJson(keysDoc), {
    expectedWorkspaceId: keysDoc.workspace_id,
  });
  // valid
} catch (e) {
  if (e instanceof VerificationError) {
    // invalid: e.message says why
  } else throw e;
}
```

## Status

**Verifier packages 3.x implement receipt wire format 3.** Wire versions are plain integers and the package major always equals the wire version it verifies, so default caret ranges (`^3.0.0`) can never cross a wire boundary. Receipts carry `schema_version: "3"` and sign top-level `alg` and `key_id`; `signature` is the base64url signature string. Reference verifiers accept only receipt wire format 3, enforce byte-identical canonicalization across Python and TypeScript, and reject malformed Unicode, unsafe integers, and non-canonical signature encodings.

## Licensing

- **Specification text** (`spec/`): CC-BY 4.0. Fork it, reference it, implement it.
- **Reference code** (`verifiers/`, test harness): Apache 2.0.

## Who maintains this

The spec is currently maintained by [Allowly](https://allowly.ai). Contributions from anyone implementing or deploying receipt-based audit flows are welcome — see [GOVERNANCE.md](./GOVERNANCE.md) and [CONTRIBUTING.md](./CONTRIBUTING.md).
