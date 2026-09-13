"""Run the public SEAL profile and verification vectors."""

from __future__ import annotations

import base64
import json
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from allowly_receipt_format import (
    SEAL_MAX_DEPTH,
    SEAL_MAX_UTF8_BYTES,
    SEAL_PROFILE,
    SealInputError,
    hash_seal_json,
    hash_seal_value,
    load_keys_from_json,
    verify_seal_json,
)


def generated_json(generator: dict[str, Any]) -> str:
    if generator["kind"] == "string_value_total_utf8_bytes":
        prefix, suffix = '{"v":"', '"}'
        return prefix + "a" * (generator["utf8_bytes"] - len(prefix) - len(suffix)) + suffix
    if generator["kind"] == "nested_arrays":
        depth = generator["depth"]
        return "[" * (depth - 1) + "0" + "]" * (depth - 1)
    raise AssertionError(f"unknown generator: {generator!r}")


def vector_input(case: dict[str, Any]) -> str | bytes:
    if "raw_json" in case:
        return case["raw_json"]
    if "raw_utf8_base64" in case:
        value = case["raw_utf8_base64"]
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return generated_json(case["generator"])


def main(profile_path: str, verification_path: str) -> int:
    profile = json.loads(Path(profile_path).read_text(encoding="utf-8"))
    verification = json.loads(Path(verification_path).read_text(encoding="utf-8"))

    assert profile["profile"] == SEAL_PROFILE
    assert profile["limits"] == {
        "max_utf8_bytes": SEAL_MAX_UTF8_BYTES,
        "max_depth": SEAL_MAX_DEPTH,
    }
    for case in profile["should_hash"] + profile["generated_should_hash"]:
        assert hash_seal_json(vector_input(case)) == case["record_sha256"], case["name"]
    for case in profile["equivalent"]:
        assert {hash_seal_json(raw) for raw in case["raw_jsons"]} == {
            case["record_sha256"]
        }, case["name"]
    for case in profile["should_differ"]:
        assert len({hash_seal_json(raw) for raw in case["raw_jsons"]}) == len(
            case["raw_jsons"]
        ), case["name"]
    for case in profile["should_reject"]:
        try:
            hash_seal_json(vector_input(case))
        except SealInputError as exc:
            assert exc.code == case["expected_code"], case["name"]
        else:
            raise AssertionError(f"{case['name']} should have been rejected")

    # The named parsed-value API is intentionally explicit about what a prior
    # parser erased, but it must agree with the raw boundary for safe values.
    for case in profile["should_hash"]:
        assert hash_seal_value(json.loads(case["raw_json"])) == case["record_sha256"]

    keys = load_keys_from_json(verification["public_keys"])
    options = {
        "expected_workspace_id": verification["expected_workspace_id"],
        "trusted_key_fingerprints": set(verification["trusted_key_fingerprints"]),
        "now": datetime.fromisoformat(verification["now"].replace("Z", "+00:00")),
    }
    for case in verification["should_verify"] + verification["should_reject"]:
        result = verify_seal_json(case["raw_json"], case["receipt"], keys, **options)
        assert asdict(result) == case["expected"], case["name"]

    print("SEAL Python vectors passed")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: test_seal.py PROFILE_VECTORS VERIFICATION_VECTORS")
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
