# @allowly/verifier

TypeScript reference verifier for [Allowly Receipt Format 2.0.0](https://github.com/Allowly-AI/allowly-receipt-format).

Zero runtime dependencies. Uses Node.js's built-in WebCrypto for Ed25519 verification.

## Install

```bash
npm install @allowly/verifier
```

Requires Node.js 20+.

## Usage

```typescript
import { verifyReceipt, VerificationError, loadKeysFromJson } from "@allowly/verifier";

const receipt = JSON.parse(receiptJson);
const keysDoc = JSON.parse(keysJson);
const keys = loadKeysFromJson(keysDoc);

try {
  await verifyReceipt(receipt, keys, { expectedWorkspaceId: keysDoc.workspace_id });
  console.log("valid");
} catch (e) {
  if (e instanceof VerificationError) {
    console.log(`invalid: ${e.message}`);
  } else {
    throw e;
  }
}
```

## Fetching the public keys

```typescript
const res = await fetch(`https://api.allowly.ai/v1/workspaces/${workspaceId}/keys`);
const keysDoc = await res.json();
const keys = loadKeysFromJson(keysDoc);
```

Key documents are cacheable (issuers set `Cache-Control`); cache them in production.

## API

### `verifyReceipt(receipt, publicKeys, opts?)`

Verifies a receipt. Resolves on success, throws `VerificationError` on any failure.

- `receipt` — the full receipt object (payload + signature).
- `publicKeys` — array of `PublicKey` objects. Get these via `loadKeysFromJson`.
- `opts.now` — optional `Date` override for time checks. Defaults to `new Date()`.
- `opts.expectedWorkspaceId` — optional. If set, the receipt's `workspace_id` must equal it. Pass the workspace the keys were published for (spec §7, "Workspace binding"); a `key_id` alone does not bind a receipt to a workspace.

### `canonicalize(payload)`

Produces the canonical JSON byte sequence per spec §4. Exposed for implementers building signers in TypeScript.

### `loadKeysFromJson(doc)`

Parses the `/v1/workspaces/{id}/keys` response into a `PublicKey[]`.

`verifyReceipt` accepts an already-parsed object. `JSON.parse` cannot report
duplicate member names or preserve whether an integer was written as `1`,
`1.0`, or `1e0`; reject those forms at the raw-JSON boundary when the original
receipt text is untrusted (spec §4.2).

## What verification proves

A valid receipt attests that the issuer made the recorded decision at the recorded time for the recorded subject/action. It does **not** prove that the action actually happened, that the user's authorization was informed, or that the `user_id` corresponds to any real-world person. See spec §7.1.

## License

Apache 2.0. Contributions welcome — see [CONTRIBUTING.md](https://github.com/Allowly-AI/allowly-receipt-format/blob/main/CONTRIBUTING.md).
