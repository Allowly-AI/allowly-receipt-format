# Python Reference Verifier

Packaged Python verifier for Allowly Receipt Format 2.1.0.

## Install

```bash
pip install allowly-receipt-format
```

Only dependency: `cryptography` for Ed25519 signature verification.

## CLI

Verify a single receipt:

```bash
allowly-receipt-verify path/to/receipt.json path/to/keys.json
```

Verify a whole export or audit-package chain in one go (`.jsonl` or `.jsonl.gz`):

```bash
# Each line is either a bare receipt (audit-package chain.jsonl) or a
# {"receipt_id", ..., "receipt": {...}} export wrapper — both are handled.
allowly-receipt-verify --export chain.jsonl keys.json
```

Verify only one authorization's chain and check its structure (exactly one
`authorization.create`, at most one `authorization.revoke`, well-formed
timestamps), printing the timeline:

```bash
allowly-receipt-verify --export export.jsonl.gz keys.json --authorization-id auth_01HXZ2...
```

For local development without installing from PyPI:

```bash
pip install -e .
python verifier.py path/to/receipt.json path/to/keys.json
```

Exit codes:
- `0` — all receipts valid (and, with `--authorization-id`, the chain is well-formed)
- `1` — any receipt invalid, no receipts matched, or a chain anomaly (reason on stderr)

## Library

```python
from allowly_receipt_format import verify_receipt, VerificationError, load_keys_from_json
import json

with open("receipt.json") as f:
    receipt = json.load(f)
with open("keys.json") as f:
    keys_doc = json.load(f)
keys = load_keys_from_json(keys_doc)

try:
    verify_receipt(receipt, keys, expected_workspace_id=keys_doc["workspace_id"])
    print("valid")
except VerificationError as e:
    print(f"invalid: {e}")
```

Always pass `expected_workspace_id` to bind the receipt to a workspace — a
`key_id` alone does not (spec §7, "Workspace binding"). The
`allowly-receipt-verify` CLI enforces this automatically using the key
document's `workspace_id`:

```python
verify_receipt(receipt, keys, expected_workspace_id="ws_01HXA1B2C3D4E5F6G7H8J9K0L1")
```

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

`verify_receipt` accepts an already-parsed object. Python's normal JSON parser
cannot report duplicate member names or preserve whether an integer was written
as `1`, `1.0`, or `1e0`; reject those forms at the raw-JSON boundary when the
original receipt text is untrusted (spec §4.2).

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
