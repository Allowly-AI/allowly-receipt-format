"""
Run the Python verifier against all test vectors.

Usage: python test_vectors.py ../../test-vectors.json
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from allowly_receipt_format import (
    VerificationError,
    canonicalize,
    checkpoint_merkle_root,
    load_keys_from_json,
    public_key_fingerprint,
    verify_checkpoint,
    verify_receipt,
)

# Hand-written expected canonical form for the spec §4.3 reference example.
# Deliberately NOT produced by the reference canonicalizer: if canonicalization
# regresses, generated vectors would regress with it and tests would still pass.
GOLDEN_PAYLOAD = {
    "schema_version": "4",
    "receipt_id": "rcp_01HXZ2B3QW4N5M6P7R8S9T0V1W",
    "workspace_id": "ws_01HXA1B2C3D4E5F6G7H8J9K0L1",
    "issued_at": "2026-04-21T14:32:17.482Z",
    "decision": "allow",
    "reason": "authorization_granted_action_active",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {
        "session_id": "sess_7f2",
        "origin": "chat",
        "initiated_by": "user",
        "control": "line\n\t\x00",
        "types": [7, True, None],
        "😀_key": "emoji",
        "｡_key": "bmp",
    },
    "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
    "engine_version": "2026-04-17.1",
    "alg": "Ed25519",
    "key_id": "projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",
}
GOLDEN_CANONICAL = (
    '{"action":"outreach.send","agent_id":"referral_outreach",'
    '"alg":"Ed25519",'
    '"authorization_id":"auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",'
    '"context":{"control":"line\\u000a\\u0009\\u0000","initiated_by":"user",'
    '"origin":"chat","session_id":"sess_7f2","types":[7,true,null],'
    '"😀_key":"emoji","｡_key":"bmp"},'
    '"decision":"allow","engine_version":"2026-04-17.1",'
    '"issued_at":"2026-04-21T14:32:17.482Z",'
    '"key_id":"projects/allowly-prod/locations/global/keyRings/allowly-signing/cryptoKeys/ws_01HXA1/cryptoKeyVersions/3",'
    '"reason":"authorization_granted_action_active",'
    '"receipt_id":"rcp_01HXZ2B3QW4N5M6P7R8S9T0V1W",'
    '"resource":"edge:emp_8821:conn_9f2a","schema_version":"4","user_id":"emp_8821",'
    '"workspace_id":"ws_01HXA1B2C3D4E5F6G7H8J9K0L1"}'
)


def main(vectors_path: str) -> int:
    with open(vectors_path) as f:
        vectors = json.load(f)

    keys = load_keys_from_json(vectors["public_keys"])
    assert vectors["public_keys"]["keys"][0]["public_key_fingerprint"] == public_key_fingerprint(keys[0])
    # All vectors use issued_at in 2026; pin "now" so timestamp checks pass deterministically.
    now = datetime(2026, 12, 31, tzinfo=timezone.utc)

    failures = 0

    print("Testing golden canonical bytes (spec §4.3)...")
    got = canonicalize(GOLDEN_PAYLOAD).decode("utf-8")
    if got == GOLDEN_CANONICAL:
        print("  OK    golden_canonical_form")
    else:
        print(f"  FAIL  golden_canonical_form:\n    expected: {GOLDEN_CANONICAL}\n    got:      {got}")
        failures += 1

    print(f"\nTesting {len(vectors['should_verify'])} should_verify vectors...")
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

    print(f"\nTesting {len(vectors['checkpoint_cases'])} checkpoint vectors...")
    for case in vectors["checkpoint_cases"]:
        try:
            root = checkpoint_merkle_root(case["receipts"])
            if root != case["expected_merkle_root"]:
                raise VerificationError(
                    f"cross-language root mismatch: expected {case['expected_merkle_root']}, got {root}"
                )
            verify_checkpoint(
                case["checkpoint"],
                case["receipts"],
                keys,
                expected_workspace_id=vectors["public_keys"]["workspace_id"],
                previous_checkpoint=case["previous_checkpoint"],
                now=now,
            )
            try:
                verify_checkpoint(
                    case["checkpoint"],
                    case["receipts"][:-1],
                    keys,
                    expected_workspace_id=vectors["public_keys"]["workspace_id"],
                    now=now,
                )
                raise VerificationError("checkpoint accepted an omitted member")
            except VerificationError as exc:
                if "receipt_count mismatch" not in str(exc):
                    raise
            print(f"  OK    {case['name']}")
        except VerificationError as e:
            print(f"  FAIL  {case['name']}: {e}")
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
