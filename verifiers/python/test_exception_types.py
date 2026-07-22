"""
Check the Python verifier's public exception taxonomy.

Usage: python test_exception_types.py ../../test-vectors.json
"""
from __future__ import annotations

import copy
import io
import json
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from allowly_receipt_format import (
    KeyOutsideActiveWindowError,
    SchemaError,
    SignatureMismatchError,
    UnknownKeyError,
    VerificationError,
    load_keys_from_json,
    main as verifier_main,
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


def _expect_bad_keys(doc: dict) -> None:
    try:
        load_keys_from_json(doc)
    except SchemaError:
        return
    raise AssertionError(f"expected SchemaError for keys doc {doc!r}")


def main(vectors_path: str) -> int:
    with open(vectors_path) as f:
        vectors = json.load(f)

    receipt = copy.deepcopy(next(
        vector["receipt"]
        for vector in vectors["should_verify"]
        if vector["name"] == "action_minimal_allow"
    ))
    keys_doc = copy.deepcopy(vectors["public_keys"])
    keys = load_keys_from_json(keys_doc)
    now = datetime(2026, 12, 31, tzinfo=timezone.utc)

    assert keys[0].active_from.year == 1

    for bad_receipt in (None, [], "x", 42):
        _expect(SchemaError, bad_receipt, keys, now=now)  # type: ignore[arg-type]

    _expect(UnknownKeyError, receipt, [], now=now)

    retired_keys_doc = copy.deepcopy(keys_doc)
    key_id = receipt["key_id"]
    for key in retired_keys_doc["keys"]:
        if key["key_id"] == key_id:
            key["active_until"] = receipt["issued_at"]
            break
    _expect(KeyOutsideActiveWindowError, receipt, load_keys_from_json(retired_keys_doc), now=now)

    tampered = copy.deepcopy(receipt)
    tampered["reason"] = "tampered"
    _expect(SignatureMismatchError, tampered, keys, now=now)

    malformed = copy.deepcopy(receipt)
    malformed["extra"] = "not in receipt schema"
    _expect(SchemaError, malformed, keys, now=now)

    for exc_type in (
        SchemaError,
        UnknownKeyError,
        KeyOutsideActiveWindowError,
        SignatureMismatchError,
    ):
        assert issubclass(exc_type, VerificationError)

    # Malformed / hostile key documents must raise SchemaError, never a raw
    # KeyError/TypeError, and duplicate ids or public keys must be rejected
    # (legacy v1.0 receipts still carry an unsigned key selector).
    for bad_doc in (
        {},                                # missing 'keys'
        {"keys": "not-a-list"},
        {"keys": [{}]},                    # entry missing fields
        {"keys": keys_doc["keys"] * 2},    # duplicate key_id + public key
    ):
        _expect_bad_keys(bad_doc)  # type: ignore[arg-type]

    for timestamp in (
        "2026-01-01T00:00:00Z",
        "2026-01-01T00:00:00.123456Z",
        "2026-01-01T00:00:00.123456789Z",
        "2026-01-01T00:00:00.000+00:00",
    ):
        bad_doc = copy.deepcopy(keys_doc)
        bad_doc["keys"][0]["active_from"] = timestamp
        _expect_bad_keys(bad_doc)

    for active_until in ("", 0, False):
        bad_doc = copy.deepcopy(keys_doc)
        bad_doc["keys"][0]["active_until"] = active_until
        _expect_bad_keys(bad_doc)

    missing_active_until = copy.deepcopy(keys_doc)
    del missing_active_until["keys"][0]["active_until"]
    _expect_bad_keys(missing_active_until)

    with TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        keys_path = tmp_path / "keys.json"
        export_path = tmp_path / "receipts.jsonl"
        keys_path.write_text(json.dumps(keys_doc), encoding="utf-8")
        export_path.write_text("[" * 2000 + "]" * 2000 + "\n{}\n", encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = verifier_main(["--export", str(export_path), str(keys_path)])
        assert rc == 1
        assert "(2 checked)" in stdout.getvalue()

    print("Exception taxonomy passes.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python test_exception_types.py <path-to-test-vectors.json>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
