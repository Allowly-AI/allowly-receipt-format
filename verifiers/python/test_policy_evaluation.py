from __future__ import annotations

import copy
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest
from allowly_receipt_format import (
    SchemaError,
    VerificationError,
    load_keys_from_json,
    verify_policy_evaluation,
)
from allowly_receipt_format import (
    main as verifier_main,
)
from allowly_receipt_format.policy import _evaluate_policy_conditions
from allowly_receipt_format.verifier import verify_receipt as verify_receipt_base

VECTORS_PATH = Path(__file__).resolve().parents[2] / "vectors" / "policy" / "profile-v1.json"


def _vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _inputs() -> tuple[dict, list, set[str], datetime]:
    vectors = _vectors()
    return (
        vectors,
        load_keys_from_json(vectors["public_keys"]),
        set(vectors["trusted_key_fingerprints"]),
        datetime(2026, 12, 31, tzinfo=timezone.utc),
    )


def _verify_case(case: dict, vectors: dict, keys: list, trusted: set[str], now: datetime) -> dict:
    return verify_policy_evaluation(
        case["receipt"],
        case["authorization_receipts"],
        keys,
        expected_workspace_id=vectors["expected_workspace_id"],
        trusted_key_fingerprints=trusted,
        now=now,
    )


def test_runtime_cases_match_frozen_expected_semantics() -> None:
    vectors = _vectors()
    for case in vectors["runtime_cases"]:
        result = _evaluate_policy_conditions(case["constraints"], case["context"])
        actual = (
            None
            if result is None
            else {
                "kind": result.kind,
                "reason": result.reason,
                "policy_eval": result.policy_eval,
            }
        )
        assert actual == case["expected"], case["name"]


def test_all_signed_shared_verification_cases() -> None:
    vectors, keys, trusted, now = _inputs()
    for case in vectors["verification_cases"]:
        assert _verify_case(case, vectors, keys, trusted, now) == case["expected"], case["name"]


def test_shared_validation_errors_stay_errors() -> None:
    vectors, keys, trusted, now = _inputs()
    for case in vectors["validation_error_cases"]:
        with pytest.raises(VerificationError, match=case["expected_error"]):
            _verify_case(case, vectors, keys, trusted, now)


def test_inputs_are_snapshotted_before_authentication_and_replay() -> None:
    vectors, keys, trusted, now = _inputs()
    case = copy.deepcopy(
        next(
            item
            for item in vectors["verification_cases"]
            if item["name"] == "runtime_deny_eq_string"
        )
    )
    original_receipt = case["receipt"]
    original_candidates = case["authorization_receipts"]
    calls = 0

    def verify_then_mutate(*args, **kwargs):
        nonlocal calls
        verify_receipt_base(*args, **kwargs)
        calls += 1
        if calls == 1:
            original_receipt["policy_eval"]["field_value"] = "changed after verification"
            original_candidates[0]["context"]["actions"][0]["constraints"] = {
                "confirm_when": [{"field": "different", "eq": True}]
            }

    with patch("allowly_receipt_format.policy.verify_receipt", verify_then_mutate):
        result = verify_policy_evaluation(
            original_receipt,
            original_candidates,
            keys,
            expected_workspace_id=vectors["expected_workspace_id"],
            trusted_key_fingerprints=trusted,
            now=now,
        )

    assert calls == 2
    assert original_receipt["policy_eval"]["field_value"] == "changed after verification"
    assert result == case["expected"]


def test_behavior_changing_json_subclasses_are_rejected() -> None:
    vectors, keys, trusted, now = _inputs()
    case = next(
        item
        for item in vectors["verification_cases"]
        if item["name"] == "runtime_deny_eq_string"
    )

    class ReceiptSubclass(dict):
        pass

    with pytest.raises(SchemaError, match="plain JSON"):
        verify_policy_evaluation(
            ReceiptSubclass(case["receipt"]),
            case["authorization_receipts"],
            keys,
            expected_workspace_id=vectors["expected_workspace_id"],
            trusted_key_fingerprints=trusted,
            now=now,
        )


def _run_cli(
    receipts: list[dict],
    vectors: dict,
    *,
    check_policy: bool = True,
) -> tuple[int, str, str]:
    with TemporaryDirectory() as tmp:
        directory = Path(tmp)
        keys_path = directory / "keys.json"
        export_path = directory / "receipts.jsonl"
        keys_path.write_text(json.dumps(vectors["public_keys"]), encoding="utf-8")
        export_path.write_text(
            "".join(json.dumps(receipt, separators=(",", ":")) + "\n" for receipt in receipts),
            encoding="utf-8",
        )
        args = [
            "--export",
            str(export_path),
            "--workspace-id",
            vectors["expected_workspace_id"],
            "--trusted-key-fingerprint",
            vectors["trusted_key_fingerprints"][0],
        ]
        if check_policy:
            args.append("--check-policy-evaluation")
        args.append(str(keys_path))
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = verifier_main(args)
        return result, stdout.getvalue(), stderr.getvalue()


def _named_case(vectors: dict, name: str) -> dict:
    return next(case for case in vectors["verification_cases"] if case["name"] == name)


def test_policy_cli_exit_codes_and_bounded_output() -> None:
    vectors = _vectors()

    matched = _named_case(vectors, "runtime_deny_eq_string")
    rc, stdout, stderr = _run_cli(
        [*matched["authorization_receipts"], matched["receipt"]], vectors
    )
    assert rc == 0
    assert "POLICY MATCHED" in stdout
    assert "1 matched, 0 mismatch, 0 not checked" in stdout
    assert "session_added_after_evaluation" not in stdout + stderr
    assert "recorded_evaluation" not in stdout + stderr

    mismatch = _named_case(vectors, "valid_signature_wrong_policy_eval")
    rc, stdout, _stderr = _run_cli(
        [*mismatch["authorization_receipts"], mismatch["receipt"]], vectors
    )
    assert rc == 3
    assert "POLICY MISMATCH" in stdout

    incomplete = _named_case(vectors, "policy_evaluation_not_recorded")
    rc, stdout, _stderr = _run_cli(
        [*incomplete["authorization_receipts"], incomplete["receipt"]], vectors
    )
    assert rc == 4
    assert "POLICY NOT_CHECKED" in stdout

    rc, stdout, _stderr = _run_cli(incomplete["authorization_receipts"], vectors)
    assert rc == 4
    assert "0 action receipt(s)" in stdout

    rc, stdout, stderr = _run_cli([], vectors)
    assert rc == 4
    assert "0 action receipt(s)" in stdout
    assert "No matching receipts" in stderr


def test_policy_cli_invalid_evidence_suppresses_semantic_success() -> None:
    vectors = _vectors()
    matched = copy.deepcopy(_named_case(vectors, "runtime_deny_eq_string"))
    invalid_candidate = copy.deepcopy(matched["authorization_receipts"][0])
    signature = invalid_candidate["signature"]
    invalid_candidate["signature"] = ("A" if signature[0] != "A" else "B") + signature[1:]

    rc, stdout, stderr = _run_cli(
        [
            *matched["authorization_receipts"],
            matched["receipt"],
            invalid_candidate,
        ],
        vectors,
    )
    assert rc == 1
    assert "POLICY MATCHED" not in stdout
    assert "skipped because supplied receipt evidence is invalid" in stderr


def test_policy_cli_mismatch_takes_precedence_over_incomplete() -> None:
    vectors = _vectors()
    mismatch = _named_case(vectors, "valid_signature_wrong_policy_eval")
    incomplete = _named_case(vectors, "policy_evaluation_not_recorded")
    receipts = [
        *mismatch["authorization_receipts"],
        mismatch["receipt"],
        *incomplete["authorization_receipts"],
        incomplete["receipt"],
    ]
    rc, stdout, _stderr = _run_cli(receipts, vectors)
    assert rc == 3
    assert "1 mismatch, 1 not checked" in stdout
