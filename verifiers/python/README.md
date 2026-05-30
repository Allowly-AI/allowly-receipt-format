# Python Reference Verifier

Packaged Python verifier for the Allowly Receipt Format v1.0.

## Install

```bash
pip install allowly-receipt-format
```

Only dependency: `cryptography` for Ed25519 signature verification.

## CLI

```bash
allowly-receipt-verify path/to/receipt.json path/to/keys.json
```

For local development without installing from PyPI:

```bash
pip install -e .
python verifier.py path/to/receipt.json path/to/keys.json
```

Exit codes:
- `0` — receipt is valid
- `1` — receipt is invalid (reason printed to stderr)

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
