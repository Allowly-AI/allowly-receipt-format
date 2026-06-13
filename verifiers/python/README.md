# Python Reference Verifier

Packaged Python verifier for the Allowly Receipt Format v1.0.

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
    keys = load_keys_from_json(json.load(f))

try:
    verify_receipt(receipt, keys)
    print("valid")
except VerificationError as e:
    print(f"invalid: {e}")
```

Pass `expected_workspace_id` to bind the receipt to a workspace — a `key_id`
alone does not (spec §7, "Workspace binding"). The `allowly-receipt-verify` CLI
enforces this automatically using the key document's `workspace_id`:

```python
verify_receipt(receipt, keys, expected_workspace_id="ws_01HXA1B2C3D4E5F6G7H8J9K0L1")
```

The package exposes typed verifier exceptions:

- `SchemaError`
- `UnknownKeyError`
- `KeyOutsideActiveWindowError`
- `SignatureMismatchError`

All inherit from `VerificationError`.

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
