"""
Check the Python verifier's public exception taxonomy.

Usage: python test_exception_types.py ../../test-vectors.json
"""
from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timezone

from allowly_receipt_format import (
    KeyOutsideActiveWindowError,
    SchemaError,
    SignatureMismatchError,
    UnknownKeyError,
    VerificationError,
    load_keys_from_json,
    verify_receipt,
)


def _expect(exc_type: type[VerificationError], receipt: dict, keys: list, *, now: datetime) -> None:
    try:
        verify_receipt(receipt, keys, now=now)
    except exc_type:
        return
    except VerificationError as exc:
        raise AssertionError(
            f"expected {exc_type.__name__}, got {type(exc).__name__}: {exc}"
        ) from exc
    raise AssertionError(f"expected {exc_type.__name__}, got success")


def main(vectors_path: str) -> int:
    with open(vectors_path) as f:
        vectors = json.load(f)

    receipt = copy.deepcopy(vectors["should_verify"][0]["receipt"])
    keys_doc = copy.deepcopy(vectors["public_keys"])
    keys = load_keys_from_json(keys_doc)
    now = datetime(2026, 12, 31, tzinfo=timezone.utc)

    _expect(UnknownKeyError, receipt, [], now=now)

    retired_keys_doc = copy.deepcopy(keys_doc)
    key_id = receipt["signature"]["key_id"]
    for key in retired_keys_doc["keys"]:
        if key["key_id"] == key_id:
            key["active_until"] = receipt["issued_at"]
            break
    _expect(KeyOutsideActiveWindowError, receipt, load_keys_from_json(retired_keys_doc), now=now)

    tampered = copy.deepcopy(receipt)
    tampered["reason"] = "tampered"
    _expect(SignatureMismatchError, tampered, keys, now=now)

    malformed = copy.deepcopy(receipt)
    malformed["extra"] = "not in v1 schema"
    _expect(SchemaError, malformed, keys, now=now)

    for exc_type in (
        SchemaError,
        UnknownKeyError,
        KeyOutsideActiveWindowError,
        SignatureMismatchError,
    ):
        assert issubclass(exc_type, VerificationError)

    print("Exception taxonomy passes.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python test_exception_types.py <path-to-test-vectors.json>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
