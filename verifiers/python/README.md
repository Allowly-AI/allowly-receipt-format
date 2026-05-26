# Python Reference Verifier

Single-file Python verifier for the Allowly Receipt Format v1.0.

## Install

```bash
pip install -r requirements.txt
```

Only dependency: `cryptography` for Ed25519 signature verification.

## CLI

```bash
python verifier.py path/to/receipt.json path/to/keys.json
```

Exit codes:
- `0` — receipt is valid
- `1` — receipt is invalid (reason printed to stderr)

## Library

```python
from verifier import verify_receipt, VerificationError, load_keys_from_json
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

## Test vectors

Run against the shared test vectors:

```bash
python test_vectors.py ../../test-vectors.json
```

All `should_verify` vectors must pass; all `should_reject` vectors must be rejected with the expected reason.

## License

Apache 2.0.
