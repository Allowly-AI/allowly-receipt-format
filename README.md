# Allowly Receipt Format

An open format for **cryptographically signed, third-party-verifiable receipts** of AI agent authorization decisions.

A receipt is a signed record of one decision: *at time T, issuer W decided that agent A may (or may not) perform action X on resource R for user U under authorization C.* Anyone holding the receipt and the issuer's Ed25519 public key, authenticated directly or against a retained fingerprint, can verify it offline without contacting the issuer.

Every receipt carries `policy_ref`, naming its immutable policy edition or null when no policy applies. Action receipts can include `policy_eval`, the exact OPA input commitment and complete provisional result. Daily `receipt.checkpoint` events commit to the issuer's registered signed receipt set for one UTC day. The current wire format is `"5"` (wire versions are plain integer strings).

Format 5 uses standard flattened JWS: `{protected, payload, signature}`. Its
protected header is `{alg: "EdDSA", kid: "<key id>", typ: "allowly-receipt+jws"}`.
PyJWT and jose verify the exact stored bytes with Ed25519 keys. Allowly adds
strict evidence validation, workspace binding and key-window checks. This
5.0.0 rebuild is local and unpublished; earlier flat receipt formats are not
accepted.

Specification Appendix A also defines an optional `hmac-v1` convention for
customer-recomputable pseudonymous values inside `context`; it does not change
the receipt wire format or verification algorithm.

Appendix B defines the optional `allowly.seal.jcs-sha256.v1` profile for
strictly hashing JSON records with RFC 8785 and verifying the digest against a
normal signed wire-5 receipt. The record stays local; only its digest needs to
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
- `spec/profiles/allowly-opa-evaluation-v1.md` — Allowly's official OPA
  policy replay profile.
- `vectors/policy/` — shared OPA evidence fixtures.
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
evidence = verify_receipt(
    receipt,
    load_keys_from_json(keys_doc),
    expected_workspace_id=configured_workspace_id,
    trusted_key_fingerprints={os.environ["ALLOWLY_TRUSTED_KEY_FINGERPRINT"]},
)  # returns verified evidence, or raises VerificationError
```

Verify a receipt in TypeScript:

```bash
npm install @allowly/verifier
```

```typescript
import { verifyReceipt, loadKeysFromJson, VerificationError } from "@allowly/verifier";

// verifyReceipt returns verified evidence and throws VerificationError on failure —
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
  const evidence = await verifyReceipt(receipt, loadKeysFromJson(keysDoc), {
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

### Receipt wire format and replay

Both local verifier packages are version `5.0.0` and accept only receipt wire
`"5"`. There is no compatibility parser or client/data migration in this fresh
local build. Published packages and historical artifacts remain unchanged.

The ordinary Python, TypeScript and generated browser verifier checks the
recorded evidence schema, caller-trusted workspace/key binding and signature.
The separate Python `allowly-policy-replay` command checks original input,
policy definition and full engine/artifact commitments, then runs official
checksum-pinned OPA. It reports `matched`, `mismatched` or `not_checked`.
It does not prove final transaction enforcement, input truth, human approval,
provider execution or full receipt-history completeness. Existing identity,
Ed25519/KMS and TLSNotary verification remain separate.

See [the replay profile](spec/profiles/allowly-opa-evaluation-v1.md) and
[Python command instructions](verifiers/python/README.md).
Package publication and deployment remain outside this local build.

## Licensing

- **Specification text and interoperability guide** (`spec/`, `INTEROP.md`): CC-BY 4.0. Fork it, reference it, implement it.
- **Reference code** (`verifiers/`, test harness): Apache 2.0.

## Who maintains this

The spec is currently maintained by [Allowly](https://allowly.ai). Contributions from anyone implementing or deploying receipt-based audit flows are welcome — see [GOVERNANCE.md](./GOVERNANCE.md) and [CONTRIBUTING.md](./CONTRIBUTING.md).
