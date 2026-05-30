"""
Run the Python verifier against all test vectors.

Usage: python test_vectors.py ../../test-vectors.json
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from allowly_receipt_format import verify_receipt, load_keys_from_json, VerificationError


def main(vectors_path: str) -> int:
    with open(vectors_path) as f:
        vectors = json.load(f)

    keys = load_keys_from_json(vectors["public_keys"])
    # All vectors use issued_at in 2026; pin "now" so timestamp checks pass deterministically.
    now = datetime(2026, 12, 31, tzinfo=timezone.utc)

    failures = 0

    print(f"Testing {len(vectors['should_verify'])} should_verify vectors...")
    for v in vectors["should_verify"]:
        try:
            verify_receipt(v["receipt"], keys, now=now)
            print(f"  OK    {v['name']}")
        except VerificationError as e:
            print(f"  FAIL  {v['name']}: unexpected rejection: {e}")
            failures += 1

    print(f"\nTesting {len(vectors['should_reject'])} should_reject vectors...")
    for v in vectors["should_reject"]:
        try:
            verify_receipt(v["receipt"], keys, now=now)
            print(f"  FAIL  {v['name']}: should have been rejected")
            failures += 1
        except VerificationError as e:
            expected = v["expected_reason"]
            if expected.lower() in str(e).lower():
                print(f"  OK    {v['name']} ({e})")
            else:
                print(f"  FAIL  {v['name']}: wrong reason")
                print(f"        expected: {expected}")
                print(f"        got:      {e}")
                failures += 1

    print()
    if failures:
        print(f"{failures} failure(s)")
        return 1
    print("All vectors pass.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python test_vectors.py <path-to-test-vectors.json>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
