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
from dataclasses import replace
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
    public_key_fingerprint,
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
    rotated_receipt = copy.deepcopy(next(
        vector["receipt"]
        for vector in vectors["should_verify"]
        if vector["name"] == "action_rotated_key"
    ))
    keys_doc = copy.deepcopy(vectors["public_keys"])
    keys = load_keys_from_json(keys_doc)
    now = datetime(2026, 12, 31, tzinfo=timezone.utc)

    try:
        verify_receipt(receipt, keys, now=datetime(2026, 12, 31))
    except SchemaError as exc:
        assert "now must be an aware datetime" in str(exc)
    else:
        raise AssertionError("naive verification clock was accepted")

    assert keys[0].active_from.year == 1
    assert keys_doc["keys"][0]["public_key_fingerprint"] == public_key_fingerprint(keys[0])

    _expect(UnknownKeyError, receipt, [], now=now)
    _expect(SchemaError, receipt, [replace(keys[0], alg="RSA"), *keys[1:]], now=now)

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

    try:
        verify_receipt(
            receipt,
            keys,
            now=now,
            trusted_key_fingerprints={"sha256:" + "0" * 64},
        )
    except VerificationError as exc:
        assert "fingerprint is not trusted" in str(exc)
    else:
        raise AssertionError("untrusted public-key fingerprint was accepted")

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
        {"workspace_id": "", "keys": []},
        {"workspace_id": "ws", "keys": "not-a-list"},
        {"workspace_id": "ws", "keys": [{}]},
        {**keys_doc, "keys": keys_doc["keys"] * 2},
    ):
        _expect_bad_keys(bad_doc)  # type: ignore[arg-type]

    for field, value in (
        ("alg", "RSA"),
        ("public_key_fingerprint", "sha256:" + "0" * 64),
    ):
        bad_doc = copy.deepcopy(keys_doc)
        bad_doc["keys"][0][field] = value
        _expect_bad_keys(bad_doc)

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
            rc = verifier_main([
                "--export", str(export_path),
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[0]),
                str(keys_path),
            ])
        assert rc == 1
        assert "(2 checked)" in stdout.getvalue()

        duplicate_path = tmp_path / "duplicate.jsonl"
        encoded = json.dumps(receipt, separators=(",", ":"))
        duplicate_path.write_text(encoded[:-1] + ',"decision":"allow"}\n', encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = verifier_main([
                "--export", str(duplicate_path),
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[0]),
                str(keys_path),
            ])
        assert rc == 1
        assert "duplicate JSON object name" in stderr.getvalue()

        receipt_path = tmp_path / "receipt.json"
        duplicate_keys_path = tmp_path / "duplicate-keys.json"
        receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
        duplicate_keys_path.write_text(
            '{"workspace_id":"ws_test","workspace_id":"ws_test","keys":[]}',
            encoding="utf-8",
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = verifier_main([
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[0]),
                str(receipt_path), str(duplicate_keys_path),
            ])
        assert rc == 1
        assert "duplicate JSON object name" in stderr.getvalue()

        rotation_path = tmp_path / "rotation.jsonl"
        rotation_path.write_text(
            "\n".join(json.dumps(item) for item in (receipt, rotated_receipt)) + "\n",
            encoding="utf-8",
        )
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            rc = verifier_main([
                "--export", str(rotation_path),
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[0]),
                str(keys_path),
            ])
        assert rc == 1
        assert "fingerprint is not trusted" in stderr.getvalue()

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = verifier_main([
                "--export", str(rotation_path),
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[0]),
                "--trusted-key-fingerprint", public_key_fingerprint(keys[1]),
                str(keys_path),
            ])
        assert rc == 0

        checkpoint_case = vectors["checkpoint_cases"][0]
        export_path.write_text(
            "".join(json.dumps(receipt) + "\n" for receipt in checkpoint_case["receipts"]),
            encoding="utf-8",
        )
        evidence_path = tmp_path / "checkpoint_evidence.json"
        evidence = {
            "version": "receipt_checkpoint_evidence.v1",
            "claim": "issuer-signed set commitment only",
            "checkpoints": [{
                "checkpoint": checkpoint_case["checkpoint"],
                "member_receipt_ids": [
                    receipt["receipt_id"] for receipt in checkpoint_case["receipts"]
                ],
            }],
        }
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = verifier_main([
                "--export", str(export_path),
                "--checkpoint-evidence", str(evidence_path),
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[0]),
                str(keys_path),
            ])
        assert rc == 0

        stderr = io.StringIO()
        with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
            rc = verifier_main([
                "--export", str(export_path),
                "--checkpoint-evidence", str(evidence_path),
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[1]),
                str(keys_path),
            ])
        assert rc == 1
        assert "fingerprint is not trusted" in stderr.getvalue()

        empty_checkpoint = next(
            item["receipt"]
            for item in vectors["should_verify"]
            if item["name"] == "receipt_checkpoint_previous"
        )
        export_path.write_text("", encoding="utf-8")
        evidence["checkpoints"] = [{
            "checkpoint": empty_checkpoint,
            "member_receipt_ids": [],
        }]
        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = verifier_main([
                "--export", str(export_path),
                "--checkpoint-evidence", str(evidence_path),
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[0]),
                str(keys_path),
            ])
        assert rc == 0

        export_path.write_text(
            "".join(json.dumps(receipt) + "\n" for receipt in checkpoint_case["receipts"]),
            encoding="utf-8",
        )
        evidence["checkpoints"] = [{
            "checkpoint": checkpoint_case["checkpoint"],
            "member_receipt_ids": [
                receipt["receipt_id"] for receipt in checkpoint_case["receipts"]
            ][:-1],
        }]

        evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            rc = verifier_main([
                "--export", str(export_path),
                "--checkpoint-evidence", str(evidence_path),
                "--workspace-id", keys_doc["workspace_id"],
                "--trusted-key-fingerprint", public_key_fingerprint(keys[0]),
                str(keys_path),
            ])
        assert rc == 1
    print("Exception taxonomy passes.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python test_exception_types.py <path-to-test-vectors.json>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
