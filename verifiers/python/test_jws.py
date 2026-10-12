"""Interoperate with stock JWS and reject ambiguous or untrusted wire framing."""
import base64
import copy
import json
from datetime import datetime, timezone
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from allowly_receipt_format import VerificationError, decode_receipt, load_keys_from_json, verify_receipt

VECTORS = json.loads((Path(__file__).resolve().parents[2] / "test-vectors.json").read_text())
RECEIPT = VECTORS["should_verify"][0]["receipt"]
KEYS = load_keys_from_json(VECTORS["public_keys"])
PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes(32))
NOW = datetime(2026, 12, 31, tzinfo=timezone.utc)
HEADER = {"alg": "EdDSA", "kid": "test-key/v1", "typ": "allowly-receipt+jws"}


def encoded(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def compact(receipt):
    return ".".join(receipt[field] for field in ("protected", "payload", "signature"))


def test_stock_pyjwt_verifies_issued_jws_and_issues_accepted_noncanonical_payload():
    assert json.loads(jwt.api_jws.PyJWS().decode_complete(
        compact(RECEIPT), PRIVATE.public_key(), algorithms=["EdDSA"])["payload"]) == decode_receipt(RECEIPT)
    # The signature authenticates original bytes, not JSON reconstructed by Allowly.
    payload = decode_receipt(RECEIPT)
    payload["context"]["unicode"] = "café\n東京"
    raw = json.dumps(payload, indent=2, ensure_ascii=True).encode()
    stock = jwt.api_jws.PyJWS().encode(raw, PRIVATE, algorithm="EdDSA", headers=HEADER)
    protected, body, signature = stock.split(".")
    wire = {"protected": protected, "payload": body, "signature": signature}
    assert verify_receipt(wire, KEYS, now=NOW, expected_workspace_id="ws_test") == payload


BAD_HEADERS = [
    {**HEADER, "alg": algorithm} for algorithm in ("none", "HS256", "RS256", "Ed25519")
] + [
    {**HEADER, "typ": "JWT"}, {**HEADER, "kid": ""}, {k: v for k, v in HEADER.items() if k != "kid"},
    *[{**HEADER, field: value} for field, value in (
        ("jku", "https://attacker.invalid/keys"), ("jwk", {}), ("crit", ["b64"]), ("b64", False))],
]


@pytest.mark.parametrize("header", BAD_HEADERS)
def test_rejects_algorithm_choice_and_untrusted_header_extensions(header):
    receipt = {**RECEIPT, "protected": encoded(json.dumps(header).encode())}
    with pytest.raises(VerificationError):
        verify_receipt(receipt, KEYS, now=NOW)


@pytest.mark.parametrize("field,raw", [
    ("protected", b'{"alg":"EdDSA","alg":"EdDSA","kid":"test-key/v1","typ":"allowly-receipt+jws"}'),
    ("protected", b'{"alg":"EdDSA","\\u0061lg":"EdDSA","kid":"test-key/v1","typ":"allowly-receipt+jws"}'),
    ("protected", b"\xef\xbb\xbf" + json.dumps(HEADER).encode()),
    ("payload", b"\xff"),
    ("payload", b""),
    ("payload", b'{"schema_version":"5","schema_version":"5"}'),
    ("payload", b'{"context":{"amount":1.0}}'),
    ("payload", b'{"context":{"amount":1e0}}'),
])
def test_rejects_non_strict_encoded_json(field, raw):
    with pytest.raises(VerificationError):
        decode_receipt({**RECEIPT, field: encoded(raw)})


def test_exact_envelope_and_protected_kid_cannot_be_replaced():
    for wire in ({**RECEIPT, "header": {}}, {**RECEIPT, "signatures": []}, decode_receipt(RECEIPT)):
        with pytest.raises(VerificationError):
            verify_receipt(wire, KEYS, now=NOW)
    replaced = copy.deepcopy(HEADER)
    replaced["kid"] = "test-key/v2"
    with pytest.raises(VerificationError):
        verify_receipt({**RECEIPT, "protected": encoded(json.dumps(replaced).encode())}, KEYS, now=NOW)
