"""
Allowly Receipt Verifier (Python reference implementation).

Verifies Allowly receipts per receipt-format.md v1.0.

Usage (library):
    from allowly_receipt_format import verify_receipt, VerificationError, load_keys_from_json

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
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


SPEC_VERSION = "1.0"
ACTION_DECISIONS = {"allow", "deny", "confirm", "escalate"}
EVENT_DECISIONS = {
    "authorization.create": {"authorization_granted"},
    "authorization.revoke": {"authorization_revoked"},
    "escalation.resolve": {"escalation_approved", "escalation_rejected"},
}
AUTHORIZATION_LIFECYCLE_EVENTS = {"authorization.create", "authorization.revoke"}
EVENT_ONLY_DECISIONS = {decision for decisions in EVENT_DECISIONS.values() for decision in decisions}
REQUIRED_FIELDS = {
    "version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
    "user_id", "agent_id", "resource", "context",
    "authorization_id", "policy_version", "signature",
}
OPTIONAL_FIELDS = {"policy_eval"}
# Exactly one of these must be present:
DISCRIMINATOR_FIELDS = {"action", "event"}
ALL_TOP_LEVEL_FIELDS = REQUIRED_FIELDS | DISCRIMINATOR_FIELDS | OPTIONAL_FIELDS
MAX_FUTURE_SKEW = timedelta(minutes=5)
# I-JSON / RFC 8785 safe-integer bound. Integers outside ±(2^53-1) cannot be
# represented exactly by IEEE-754 double consumers (e.g. JavaScript verifiers),
# so v1 receipts MUST NOT carry them (spec §4.2 rule 6).
MAX_SAFE_INTEGER = 2**53 - 1
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
)
__all__ = [
    "KeyOutsideActiveWindowError",
    "PublicKey",
    "SchemaError",
    "SignatureMismatchError",
    "UnknownKeyError",
    "VerificationError",
    "canonicalize",
    "load_keys_from_json",
    "main",
    "verify_receipt",
]


class VerificationError(Exception):
    """Raised when a receipt fails any verification step."""


class SchemaError(VerificationError):
    """Raised when receipt shape, field pairing, or timestamp validation fails."""


class UnknownKeyError(VerificationError):
    """Raised when the receipt references a key id absent from the public key set."""


class KeyOutsideActiveWindowError(VerificationError):
    """Raised when the referenced key does not cover receipt.issued_at."""


class SignatureMismatchError(VerificationError):
    """Raised when the Ed25519 signature does not match the canonical payload."""


@dataclass
class PublicKey:
    key_id: str
    alg: str  # "Ed25519"
    public_key_bytes: bytes  # 32 raw bytes
    active_from: datetime
    active_until: datetime | None  # None = still active


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding.

    The input MUST use the URL-safe alphabet (`A-Z a-z 0-9 - _`) with no
    padding. ``base64.urlsafe_b64decode`` silently ignores out-of-alphabet
    bytes, so we reject them explicitly to enforce spec §5.1.
    """
    if not _B64URL_RE.match(s):
        raise ValueError(f"not unpadded base64url: {s!r}")
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _parse_rfc3339(s: str) -> datetime:
    """Parse an RFC 3339 timestamp. Requires Z suffix or explicit offset.

    A timezone-less or date-only string is rejected: without an offset the
    instant is ambiguous and verifiers would disagree on the key-window check.
    """
    if not isinstance(s, str) or not _RFC3339_RE.match(s):
        raise SchemaError(f"not an RFC 3339 timestamp with timezone: {s!r}")
    iso = s[:-1] + "+00:00" if s.endswith("Z") else s
    dt = datetime.fromisoformat(iso)
    if dt.tzinfo is None:
        raise SchemaError(f"timestamp missing timezone: {s}")
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
      - Non-ASCII passed through as UTF-8

    NOTE: this is a hand-rolled serializer, not ``json.dumps(sort_keys=True,
    ...)``. The stdlib helper diverges from the spec in two ways that silently
    break cross-language signature verification:
      1. It sorts keys by Unicode code point, but §4.2 rule 3 mandates UTF-16
         code-unit order — these differ for non-BMP keys (e.g. an emoji key
         sorts *before* U+FF61 under UTF-16, *after* under code point).
      2. It emits short escapes like ``\\n`` for control characters, but §4.2
         rule 5 mandates the lowercase ``\\uXXXX`` form.
    """
    _assert_no_floats(payload)
    return _encode_value(payload).encode("utf-8")


def _utf16_sort_key(key: str) -> bytes:
    """Sort key for UTF-16 code-unit lexicographic order (spec §4.2 rule 3)."""
    return key.encode("utf-16-be")


def _encode_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):  # before int: bool is an int subclass.
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        return _encode_string(v)
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: _utf16_sort_key(kv[0]))
        return "{" + ",".join(
            _encode_string(k) + ":" + _encode_value(val) for k, val in items
        ) + "}"
    if isinstance(v, list):
        return "[" + ",".join(_encode_value(item) for item in v) + "]"
    raise SchemaError(f"unsupported type in payload: {type(v).__name__}")


def _encode_string(s: str) -> str:
    """Serialize a JSON string per §4.2 rule 5.

    Escapes only `"`, `\\`, and control chars U+0000-U+001F (as lowercase
    `\\uXXXX`). Non-ASCII is passed through as its UTF-8 byte sequence.
    """
    out = ['"']
    for ch in s:
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _assert_no_floats(obj: Any) -> None:
    """v1 receipts MUST NOT contain non-integer numbers, nor integers outside
    the I-JSON safe range (spec §4.2 rule 6)."""
    if isinstance(obj, bool):
        return  # bool is a subclass of int in Python; allow.
    if isinstance(obj, float):
        raise SchemaError("v1 receipts must not contain non-integer numbers")
    if isinstance(obj, int):
        if abs(obj) > MAX_SAFE_INTEGER:
            raise SchemaError(
                f"integer {obj} exceeds the safe range ±(2^53-1); v1 receipts "
                f"must not carry integers that lose precision in IEEE-754 doubles"
            )
        return
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
    expected_workspace_id: str | None = None,
) -> None:
    """
    Verify a receipt. Raises VerificationError on any failure.

    Args:
        receipt: the full receipt dict (payload + signature).
        public_keys: list of known public keys for the workspace.
        now: override current time (for testing). Defaults to datetime.now(UTC).
        expected_workspace_id: if given, the receipt's ``workspace_id`` MUST
            equal it. Key ids alone do not bind a receipt to a workspace, so
            pass the workspace the keys were published for to prevent a receipt
            from verifying against another workspace's key document.
    """
    now = now or datetime.now(timezone.utc)

    # Step 1: version check
    if receipt.get("version") != SPEC_VERSION:
        raise SchemaError(
            f"unsupported version: {receipt.get('version')!r} (want {SPEC_VERSION!r})"
        )

    if (
        expected_workspace_id is not None
        and receipt.get("workspace_id") != expected_workspace_id
    ):
        raise SchemaError(
            f"workspace_id mismatch: receipt has {receipt.get('workspace_id')!r}, "
            f"expected {expected_workspace_id!r}"
        )

    # Step 2: schema check (includes signature.value shape — rejects placeholders)
    _check_schema(receipt)

    # Step 3: receipt kind and pairing
    has_action = "action" in receipt
    has_event = "event" in receipt
    decision = receipt["decision"]
    authorization_id = receipt["authorization_id"]
    resource = receipt["resource"]

    if has_action and has_event:
        raise SchemaError(
            "receipt has both 'action' and 'event'; exactly one must be present"
        )
    if not has_action and not has_event:
        raise SchemaError(
            "receipt has neither 'action' nor 'event'; exactly one must be present"
        )

    if has_event:
        # Event receipt
        event = receipt["event"]
        if not isinstance(event, str):
            raise SchemaError("event must be a string")
        if event not in EVENT_DECISIONS:
            raise SchemaError(
                f"event must be one of {sorted(EVENT_DECISIONS)}, got {event!r}"
            )
        expected_decisions = EVENT_DECISIONS[event]
        if decision not in expected_decisions:
            raise SchemaError(
                f"event receipt with event={event!r} must have "
                f"decision in {sorted(expected_decisions)}, got {decision!r}"
            )
        if authorization_id is None:
            raise SchemaError(
                f"event receipt with event={event!r} must have non-null authorization_id"
            )
        if event in AUTHORIZATION_LIFECYCLE_EVENTS and resource is not None:
            raise SchemaError(
                f"authorization lifecycle receipt with event={event!r} must have null resource"
            )
        if "policy_eval" in receipt:
            raise SchemaError("policy_eval must be absent on event receipts")
    else:
        # Action receipt (has_action is True)
        action = receipt["action"]
        if not isinstance(action, str):
            raise SchemaError("action must be a string")
        # Reject reserved event-only decisions on action receipts.
        if decision in EVENT_ONLY_DECISIONS:
            raise SchemaError(
                f"decision={decision!r} requires an event receipt (event field), "
                f"got an action receipt with action={action!r}"
            )
        if decision not in ACTION_DECISIONS:
            raise SchemaError(
                f"action receipt must have decision in {sorted(ACTION_DECISIONS)}, "
                f"got {decision!r}"
            )

    # Step 4: algorithm check
    sig = receipt["signature"]
    if sig.get("alg") != "Ed25519":
        raise SchemaError(f"unsupported signature alg: {sig.get('alg')!r}")

    # Step 5: timestamp sanity
    issued_at = _parse_rfc3339(receipt["issued_at"])
    if issued_at > now + MAX_FUTURE_SKEW:
        raise SchemaError(
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
        raise SignatureMismatchError("signature verification failed") from None

    # Step 8: accept (implicit — no exception raised)


def _check_schema(receipt: dict[str, Any]) -> None:
    extra = set(receipt.keys()) - ALL_TOP_LEVEL_FIELDS
    if extra:
        raise SchemaError(f"unknown top-level fields: {sorted(extra)}")
    missing = REQUIRED_FIELDS - set(receipt.keys())
    if missing:
        raise SchemaError(f"missing top-level fields: {sorted(missing)}")

    # String fields (always present)
    for field in ("version", "receipt_id", "workspace_id", "issued_at",
                  "decision", "reason", "user_id", "agent_id",
                  "policy_version"):
        if not isinstance(receipt[field], str):
            raise SchemaError(f"{field} must be a string")

    # Nullable string fields
    for field in ("resource", "authorization_id"):
        if not (isinstance(receipt[field], str) or receipt[field] is None):
            raise SchemaError(f"{field} must be string or null")

    # Object fields
    if not isinstance(receipt["context"], dict):
        raise SchemaError("context must be an object")
    if not isinstance(receipt["signature"], dict):
        raise SchemaError("signature must be an object")

    # Signature sub-fields
    sig = receipt["signature"]
    for field in ("alg", "key_id", "value"):
        if field not in sig:
            raise SchemaError(f"signature.{field} is required")
        if not isinstance(sig[field], str):
            raise SchemaError(f"signature.{field} must be a string")

    # signature.value must decode from base64url to exactly 64 bytes.
    # This rejects placeholder strings ("pending", empty, anything malformed)
    # before the verification path even starts.
    try:
        sig_bytes = _b64url_decode(sig["value"])
    except Exception:
        raise SchemaError(
            f"signature.value is not valid base64url: {sig['value']!r}"
        )
    if len(sig_bytes) != 64:
        raise SchemaError(
            f"signature.value must decode to 64 bytes (Ed25519), got {len(sig_bytes)}"
        )

    if "policy_eval" in receipt:
        _check_policy_eval(receipt["policy_eval"])


def _is_policy_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, bool)) or (
        isinstance(value, int) and not isinstance(value, bool)
    )


def _is_policy_condition_value(value: Any) -> bool:
    if _is_policy_scalar(value):
        return True
    return isinstance(value, list) and all(_is_policy_scalar(item) for item in value)


def _check_policy_eval(value: Any) -> None:
    if not isinstance(value, dict):
        raise SchemaError("policy_eval must be an object")
    expected = {"matched_condition", "field_value"}
    extra = set(value.keys()) - expected
    missing = expected - set(value.keys())
    if extra:
        raise SchemaError(f"policy_eval has unknown fields: {sorted(extra)}")
    if missing:
        raise SchemaError(f"policy_eval missing fields: {sorted(missing)}")

    matched = value["matched_condition"]
    if matched is not None:
        if not isinstance(matched, dict):
            raise SchemaError("policy_eval.matched_condition must be an object or null")
        condition_fields = {"field", "op", "value"}
        extra = set(matched.keys()) - condition_fields
        missing = condition_fields - set(matched.keys())
        if extra:
            raise SchemaError(
                f"policy_eval.matched_condition has unknown fields: {sorted(extra)}"
            )
        if missing:
            raise SchemaError(
                f"policy_eval.matched_condition missing fields: {sorted(missing)}"
            )
        if not isinstance(matched["field"], str):
            raise SchemaError("policy_eval.matched_condition.field must be a string")
        if not isinstance(matched["op"], str):
            raise SchemaError("policy_eval.matched_condition.op must be a string")
        if not _is_policy_condition_value(matched["value"]):
            raise SchemaError(
                "policy_eval.matched_condition.value must be string, integer, boolean, null, or an array of those"
            )

    if not _is_policy_scalar(value["field_value"]):
        raise SchemaError("policy_eval.field_value must be string, integer, boolean, or null")


def _find_key(
    keys: list[PublicKey], key_id: str, issued_at: datetime
) -> PublicKey:
    for k in keys:
        if k.key_id != key_id:
            continue
        if issued_at < k.active_from:
            raise KeyOutsideActiveWindowError(f"key {key_id!r} not yet active at issued_at")
        if k.active_until is not None and issued_at >= k.active_until:
            raise KeyOutsideActiveWindowError(f"key {key_id!r} retired before issued_at")
        return k
    raise UnknownKeyError(f"no public key found for key_id={key_id!r}")


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


def main(argv: list[str] | None = None) -> int:
    import argparse

    p = argparse.ArgumentParser(description="Verify an Allowly receipt.")
    p.add_argument("receipt", help="path to receipt JSON file")
    p.add_argument("keys", help="path to keys JSON file (workspace keys doc)")
    args = p.parse_args(argv)

    with open(args.receipt) as f:
        receipt = json.load(f)
    with open(args.keys) as f:
        keys_doc = json.load(f)

    keys = load_keys_from_json(keys_doc)
    # The keys document is published per workspace; bind the receipt to it so a
    # receipt cannot verify against another workspace's keys that share a key_id.
    expected_workspace_id = keys_doc.get("workspace_id")

    try:
        verify_receipt(receipt, keys, expected_workspace_id=expected_workspace_id)
        print(f"OK  receipt_id={receipt['receipt_id']} decision={receipt['decision']}")
        return 0
    except VerificationError as e:
        import sys

        print(f"INVALID  {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    sys.exit(main())
