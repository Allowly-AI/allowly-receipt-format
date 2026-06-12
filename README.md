# Allowly Receipt Format

An open format for **cryptographically signed, third-party-verifiable receipts** of AI agent authorization decisions.

A receipt is a signed record of one decision: *at time T, issuer W decided that agent A may (or may not) perform action X on resource R for user U under authorization C.* Anyone holding the receipt and the issuer's Ed25519 public key can verify it offline, without contacting the issuer.

Action receipts can include `policy_eval`, a small proof of which immutable authorization condition routed a decision to `confirm` or `escalate`. Draft.6 fixes two cross-language canonicalization defects in the reference verifiers and makes supersession lineage bidirectional (a revoked authorization can now point forward to its successor).

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
verify_receipt(receipt, load_keys_from_json(keys_doc))
```

Verify a receipt in TypeScript:

```bash
npm install @allowly/verifier
```

```typescript
import { verifyReceipt } from "@allowly/verifier";
const valid = await verifyReceipt(receipt, publicKeys);
```

## Status

**1.0.0-draft.6.** Draft receipt format and reference verifier test vectors. Authorizations stay immutable: `authorization_id` pins the rule set. Draft.6 corrects two canonicalization defects (UTF-16 key sort, control-character escaping) so the Python and TypeScript verifiers agree byte-for-byte, bounds integers to the I-JSON safe range, and adds a bidirectional supersession lineage (`revoked_by: "superseded"` / `superseded_by`).

## Licensing

- **Specification text** (`spec/`): CC-BY 4.0. Fork it, reference it, implement it.
- **Reference code** (`verifiers/`, test harness): Apache 2.0.

## Who maintains this

The spec is currently maintained by [Allowly](https://allowly.ai). Contributions from anyone implementing or deploying receipt-based audit flows are welcome — see [GOVERNANCE.md](./GOVERNANCE.md) and [CONTRIBUTING.md](./CONTRIBUTING.md).
