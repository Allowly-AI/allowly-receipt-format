# Python Reference Verifier

Packaged Python verifier for Allowly Receipt Format wire version 3.

## Install

```bash
pip install allowly-receipt-format
```

Only dependency: `cryptography` for Ed25519 signature verification.

## CLI

Verify a single receipt:

```bash
allowly-receipt-verify \
  --workspace-id "$ALLOWLY_WORKSPACE_ID" \
  --trusted-key-fingerprint "$ALLOWLY_TRUSTED_KEY_FINGERPRINT" \
  path/to/receipt.json path/to/keys.json
```

Verify a whole export or audit-package chain in one go (`.jsonl` or `.jsonl.gz`):

```bash
# Each line is either a bare receipt (audit-package chain.jsonl) or a
# {"receipt_id", ..., "receipt": {...}} export wrapper — both are handled.
allowly-receipt-verify \
  --export chain.jsonl \
  --workspace-id "$ALLOWLY_WORKSPACE_ID" \
  --trusted-key-fingerprint "$ALLOWLY_TRUSTED_KEY_FINGERPRINT" \
  keys.json
```

Verify only one authorization's chain and check its structure (exactly one
`authorization.create`, at most one `authorization.revoke`, well-formed
timestamps), printing the timeline:

```bash
allowly-receipt-verify \
  --export export.jsonl.gz \
  --authorization-id auth_01HXZ2... \
  --workspace-id "$ALLOWLY_WORKSPACE_ID" \
  --trusted-key-fingerprint "$ALLOWLY_TRUSTED_KEY_FINGERPRINT" \
  keys.json
```

`--workspace-id` and at least one `--trusted-key-fingerprint` are required.
Fingerprints use `sha256:<64 lowercase hex>` over the decoded raw 32-byte
Ed25519 public key. Repeat the fingerprint flag for every trusted rotation key
that may have signed the selected receipts.

For local development without installing from PyPI:

```bash
pip install -e .
python verifier.py \
  --workspace-id "$ALLOWLY_WORKSPACE_ID" \
  --trusted-key-fingerprint "$ALLOWLY_TRUSTED_KEY_FINGERPRINT" \
  path/to/receipt.json path/to/keys.json
```

Exit codes:
- `0` — all presented receipts valid (and, with `--authorization-id`, the presented chain is structurally well-formed)
- `1` — any receipt invalid, no receipts matched, or a chain anomaly (reason on stderr)

## Library

```python
from allowly_receipt_format import verify_receipt, VerificationError, load_keys_from_json
import json
import os

with open("receipt.json") as f:
    receipt = json.load(f)
with open("keys.json") as f:
    keys_doc = json.load(f)
configured_workspace_id = os.environ["ALLOWLY_WORKSPACE_ID"]
trusted_fingerprints = {os.environ["ALLOWLY_TRUSTED_KEY_FINGERPRINT"]}
if keys_doc.get("workspace_id") != configured_workspace_id:
    raise ValueError("key document workspace does not match configuration")
keys = load_keys_from_json(keys_doc)

try:
    verify_receipt(
        receipt,
        keys,
        expected_workspace_id=configured_workspace_id,
        trusted_key_fingerprints=trusted_fingerprints,
    )
    print("valid")
except VerificationError as e:
    print(f"invalid: {e}")
```

Always pass `expected_workspace_id` to bind the receipt to a workspace — a
`key_id` alone does not (spec §7, "Workspace binding"). Take that ID from
caller-trusted configuration, never from the receipt or key document, and
reject a key document that declares a different workspace. The CLI requires
that caller-trusted workspace ID plus one or more caller-trusted key
fingerprints. It checks the workspace against the key document and receipts,
and requires every selected receipt key to be pinned. A workspace ID or
fingerprint copied from the same untrusted bundle as the receipts is not an
independent trust anchor:

```python
verify_receipt(
    receipt,
    keys,
    expected_workspace_id="ws_01HXA1B2C3D4E5F6G7H8J9K0L1",
    trusted_key_fingerprints={"sha256:<64 lowercase hex>"},
)
```

`public_key_fingerprint(key)` returns that canonical fingerprint over the
decoded raw 32-byte Ed25519 public key. `load_keys_from_json` validates an
advertised `public_key_fingerprint`, but the advertised value is not itself a
trust anchor.

The package exposes typed verifier exceptions:

- `SchemaError`
- `UnknownKeyError`
- `KeyOutsideActiveWindowError`
- `SignatureMismatchError`

All inherit from `VerificationError`.

### Match a keyed pseudonym reference

`matches_ref` implements the optional `hmac-v1` convention in specification
Appendix A. Decode the show-once integration key, then match locally:

```python
import base64
from allowly_receipt_format import matches_ref

encoded_key = "<pseudonym_key_b64url>"
key = base64.urlsafe_b64decode(encoded_key + "=" * (-len(encoded_key) % 4))

assert matches_ref(
    key,
    "record",
    "MRN-48291",
    receipt["context"]["record_ref"],
)
```

Use the `context.ref_key_version` recorded in the receipt to select the retained
key version. Matching occurs entirely offline; it does not ask Allowly to
resolve an identifier.

`verify_receipt` accepts an already-parsed object, so it cannot detect duplicate
raw JSON names that a normal parser has already overwritten. The CLI uses a
duplicate-aware parser and rejects them. The verifier also rejects parsed
floating-point values, including the results of `1.0` and `1e0`; callers using
a different parser must preserve that distinction (spec §4.2).

## Test vectors

Run against the shared test vectors:

```bash
pip install -e .
python test_vectors.py ../../test-vectors.json
python test_exception_types.py ../../test-vectors.json
```

All `should_verify` vectors must pass; all `should_reject` vectors must be rejected with the expected reason.

## License

Apache 2.0.
