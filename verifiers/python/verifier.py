"""
Allowly Receipt Verifier (Python reference implementation).

Verifies Allowly receipts per receipt-format.md v1.0.

Usage (library):
    from verifier import verify_receipt, VerificationError, load_keys_from_json

    try:
        verify_receipt(receipt_dict, public_keys)
        print("valid")
    except VerificationError as e:
        print(f"invalid: {e}")

Usage (CLI):
    python verifier.py path/to/receipt.json path/to/keys.json

Spec: https://github.com/allowly/receipt-format
License: Apache 2.0
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


SPEC_VERSION = "1.0"
ACTION_DECISIONS = {"allow", "deny", "confirm"}
AUTHORIZATION_LIFECYCLE_EVENTS = {
    "authorization.create": "authorization_granted",
    "authorization.revoke": "authorization_revoked",
}
AUTHORIZATION_LIFECYCLE_DECISIONS = {"authorization_granted", "authorization_revoked"}
REQUIRED_FIELDS = {
    "version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
    "user_id", "agent_id", "resource", "context",
    "authorization_id", "policy_version", "signature",
}
# Exactly one of these must be present:
DISCRIMINATOR_FIELDS = {"scope", "event"}
ALL_TOP_LEVEL_FIELDS = REQUIRED_FIELDS | DISCRIMINATOR_FIELDS
MAX_FUTURE_SKEW = timedelta(minutes=5)


class VerificationError(Exception):
    """Raised when a receipt fails any verification step."""


@dataclass
class PublicKey:
    key_id: str
    alg: str  # "Ed25519"
    public_key_bytes: bytes  # 32 raw bytes
    active_from: datetime
    active_until: datetime | None  # None = still active


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding."""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _parse_rfc3339(s: str) -> datetime:
    """Parse RFC 3339 timestamp. Requires Z suffix or explicit offset."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        raise VerificationError(f"timestamp missing timezone: {s}")
    return dt


def canonicalize(payload: dict[str, Any]) -> bytes:
    """
    Produce canonical JSON bytes per receipt-format.md §4.

    Rules:
      - UTF-8, no BOM
      - No whitespace between tokens
      - Object keys sorted lexicographically (UTF-16 code unit order)
      - Array order preserved
      - Integers only; no floats
      - Non-ASCII passed through as UTF-8 (ensure_ascii=False)
    """
    _assert_no_floats(payload)
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _assert_no_floats(obj: Any) -> None:
    """v1 receipts MUST NOT contain non-integer numbers."""
    if isinstance(obj, bool):
        return  # bool is a subclass of int in Python; allow.
    if isinstance(obj, float):
        raise VerificationError("v1 receipts must not contain non-integer numbers")
    if isinstance(obj, dict):
        for v in obj.values():
            _assert_no_floats(v)
    elif isinstance(obj, list):
        for v in obj:
            _assert_no_floats(v)


def verify_receipt(
    receipt: dict[str, Any],
    public_keys: list[PublicKey],
    *,
    now: datetime | None = None,
) -> None:
    """
    Verify a receipt. Raises VerificationError on any failure.

    Args:
        receipt: the full receipt dict (payload + signature).
        public_keys: list of known public keys for the workspace.
        now: override current time (for testing). Defaults to datetime.now(UTC).
    """
    now = now or datetime.now(timezone.utc)

    # Step 1: version check
    if receipt.get("version") != SPEC_VERSION:
        raise VerificationError(
            f"unsupported version: {receipt.get('version')!r} (want {SPEC_VERSION!r})"
        )

    # Step 2: schema check (includes signature.value shape — rejects placeholders)
    _check_schema(receipt)

    # Step 3: receipt kind and pairing
    has_scope = "scope" in receipt
    has_event = "event" in receipt
    decision = receipt["decision"]
    authorization_id = receipt["authorization_id"]
    resource = receipt["resource"]

    if has_scope and has_event:
        raise VerificationError(
            "receipt has both 'scope' and 'event'; exactly one must be present"
        )
    if not has_scope and not has_event:
        raise VerificationError(
            "receipt has neither 'scope' nor 'event'; exactly one must be present"
        )

    if has_event:
        # Authorization receipt
        event = receipt["event"]
        if not isinstance(event, str):
            raise VerificationError("event must be a string")
        if event not in AUTHORIZATION_LIFECYCLE_EVENTS:
            raise VerificationError(
                f"event must be one of {sorted(AUTHORIZATION_LIFECYCLE_EVENTS)}, got {event!r}"
            )
        expected_decision = AUTHORIZATION_LIFECYCLE_EVENTS[event]
        if decision != expected_decision:
            raise VerificationError(
                f"authorization receipt with event={event!r} must have "
                f"decision={expected_decision!r}, got {decision!r}"
            )
        if authorization_id is None:
            raise VerificationError(
                f"authorization receipt with event={event!r} must have non-null authorization_id"
            )
        if resource is not None:
            raise VerificationError(
                f"authorization receipt with event={event!r} must have null resource"
            )
    else:
        # Action receipt (has_scope is True)
        scope = receipt["scope"]
        if not isinstance(scope, str):
            raise VerificationError("scope must be a string")
        # Reject reserved authorization-lifecycle decisions on action receipts.
        if decision in AUTHORIZATION_LIFECYCLE_DECISIONS:
            raise VerificationError(
                f"decision={decision!r} requires an authorization receipt (event field), "
                f"got an action receipt with scope={scope!r}"
            )
        if decision not in ACTION_DECISIONS:
            raise VerificationError(
                f"action receipt must have decision in {sorted(ACTION_DECISIONS)}, "
                f"got {decision!r}"
            )

    # Step 4: algorithm check
    sig = receipt["signature"]
    if sig.get("alg") != "Ed25519":
        raise VerificationError(f"unsupported signature alg: {sig.get('alg')!r}")

    # Step 5: timestamp sanity
    issued_at = _parse_rfc3339(receipt["issued_at"])
    if issued_at > now + MAX_FUTURE_SKEW:
        raise VerificationError(
            f"receipt issued in the future: {issued_at.isoformat()} > {now.isoformat()}"
        )

    # Step 6: canonicalize
    payload = {k: v for k, v in receipt.items() if k != "signature"}
    canonical = canonicalize(payload)

    # Step 7: signature verification
    key = _find_key(public_keys, sig["key_id"], issued_at)
    sig_bytes = _b64url_decode(sig["value"])  # length already validated in schema check

    try:
        Ed25519PublicKey.from_public_bytes(key.public_key_bytes).verify(
            sig_bytes, canonical
        )
    except InvalidSignature:
        raise VerificationError("signature verification failed")

    # Step 8: accept (implicit — no exception raised)


def _check_schema(receipt: dict[str, Any]) -> None:
    extra = set(receipt.keys()) - ALL_TOP_LEVEL_FIELDS
    if extra:
        raise VerificationError(f"unknown top-level fields: {sorted(extra)}")
    missing = REQUIRED_FIELDS - set(receipt.keys())
    if missing:
        raise VerificationError(f"missing top-level fields: {sorted(missing)}")

    # String fields (always present)
    for field in ("version", "receipt_id", "workspace_id", "issued_at",
                  "decision", "reason", "user_id", "agent_id",
                  "policy_version"):
        if not isinstance(receipt[field], str):
            raise VerificationError(f"{field} must be a string")

    # Nullable string fields
    for field in ("resource", "authorization_id"):
        if not (isinstance(receipt[field], str) or receipt[field] is None):
            raise VerificationError(f"{field} must be string or null")

    # Object fields
    if not isinstance(receipt["context"], dict):
        raise VerificationError("context must be an object")
    if not isinstance(receipt["signature"], dict):
        raise VerificationError("signature must be an object")

    # Signature sub-fields
    sig = receipt["signature"]
    for field in ("alg", "key_id", "value"):
        if field not in sig:
            raise VerificationError(f"signature.{field} is required")
        if not isinstance(sig[field], str):
            raise VerificationError(f"signature.{field} must be a string")

    # signature.value must decode from base64url to exactly 64 bytes.
    # This rejects placeholder strings ("pending", empty, anything malformed)
    # before the verification path even starts.
    try:
        sig_bytes = _b64url_decode(sig["value"])
    except Exception:
        raise VerificationError(
            f"signature.value is not valid base64url: {sig['value']!r}"
        )
    if len(sig_bytes) != 64:
        raise VerificationError(
            f"signature.value must decode to 64 bytes (Ed25519), got {len(sig_bytes)}"
        )


def _find_key(
    keys: list[PublicKey], key_id: str, issued_at: datetime
) -> PublicKey:
    for k in keys:
        if k.key_id != key_id:
            continue
        if issued_at < k.active_from:
            raise VerificationError(f"key {key_id!r} not yet active at issued_at")
        if k.active_until is not None and issued_at >= k.active_until:
            raise VerificationError(f"key {key_id!r} retired before issued_at")
        return k
    raise VerificationError(f"no public key found for key_id={key_id!r}")


def load_keys_from_json(doc: dict[str, Any]) -> list[PublicKey]:
    """Parse the /v1/workspaces/{id}/keys response shape into PublicKey list."""
    out = []
    for k in doc["keys"]:
        out.append(PublicKey(
            key_id=k["key_id"],
            alg=k["alg"],
            public_key_bytes=_b64url_decode(k["public_key"]),
            active_from=_parse_rfc3339(k["active_from"]),
            active_until=_parse_rfc3339(k["active_until"]) if k.get("active_until") else None,
        ))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    import sys

    p = argparse.ArgumentParser(description="Verify an Allowly receipt.")
    p.add_argument("receipt", help="path to receipt JSON file")
    p.add_argument("keys", help="path to keys JSON file (workspace keys doc)")
    args = p.parse_args()

    with open(args.receipt) as f:
        receipt = json.load(f)
    with open(args.keys) as f:
        keys_doc = json.load(f)

    keys = load_keys_from_json(keys_doc)

    try:
        verify_receipt(receipt, keys)
        print(f"OK  receipt_id={receipt['receipt_id']} decision={receipt['decision']}")
        sys.exit(0)
    except VerificationError as e:
        print(f"INVALID  {e}", file=sys.stderr)
        sys.exit(1)
