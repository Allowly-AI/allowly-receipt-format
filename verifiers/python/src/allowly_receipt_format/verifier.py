"""
Allowly Receipt Verifier (Python reference implementation).

Verifies Allowly receipts per receipt-format.md wire version 4.

Usage (library):
    from allowly_receipt_format import verify_receipt, VerificationError, load_keys_from_json

    try:
        verify_receipt(receipt_dict, public_keys)
        print("valid")
    except VerificationError as e:
        print(f"invalid: {e}")

Usage (CLI):
    python verifier.py path/to/receipt.json path/to/keys.json

Spec: https://github.com/Allowly-AI/allowly-receipt-format
License: Apache 2.0
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature


SPEC_VERSION = "4"
ACTION_DECISIONS = {"allow", "deny", "confirm", "escalate"}
EVENT_DECISIONS = {
    "authorization.create": {"authorization_granted"},
    "authorization.revoke": {"authorization_revoked"},
    "budget.settle": {"budget_settled"},
    "escalation.resolve": {"escalation_approved", "escalation_rejected"},
    "receipt.checkpoint": {"receipt_set_committed"},
}
AUTHORIZATION_LIFECYCLE_EVENTS = {"authorization.create", "authorization.revoke"}
EVENT_ONLY_DECISIONS = {decision for decisions in EVENT_DECISIONS.values() for decision in decisions}
REQUIRED_FIELDS = {
    "schema_version", "receipt_id", "workspace_id", "issued_at", "decision", "reason",
    "user_id", "agent_id", "resource", "context",
    "authorization_id", "engine_version", "alg", "key_id", "signature",
}
OPTIONAL_FIELDS = {"policy_eval"}
# Exactly one of these must be present:
DISCRIMINATOR_FIELDS = {"action", "event"}
ALL_TOP_LEVEL_FIELDS = REQUIRED_FIELDS | DISCRIMINATOR_FIELDS | OPTIONAL_FIELDS
MAX_FUTURE_SKEW = timedelta(minutes=5)
# I-JSON / RFC 8785 safe-integer bound. Integers outside ±(2^53-1) cannot be
# represented exactly by IEEE-754 double consumers (e.g. JavaScript verifiers),
# so receipts MUST NOT carry them (spec §4.2 rule 6).
MAX_SAFE_INTEGER = 2**53 - 1
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_RFC3339_RE = re.compile(
    r"^(?!0000)[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$"
)
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_HMAC_REF_RE = re.compile(r"^hmac-v1:[0-9a-f]{64}$")
_HMAC_REF_FIELDS = frozenset({"project", "record", "actor", "full_tuple"})
# Depth/node limits so hostile receipts fail with a VerificationError instead
# of exhausting the recursion stack or memory during canonicalization.
MAX_PAYLOAD_DEPTH = 32
MAX_PAYLOAD_NODES = 50_000
__all__ = [
    "KeyOutsideActiveWindowError",
    "PublicKey",
    "SchemaError",
    "SignatureMismatchError",
    "UnknownKeyError",
    "VerificationError",
    "canonicalize",
    "checkpoint_merkle_root",
    "load_keys_from_json",
    "main",
    "matches_ref",
    "verify_receipt",
    "verify_checkpoint",
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


_CHECKPOINT_ROOT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHECKPOINT_CONTEXT_FIELDS = {
    "period_start",
    "period_end",
    "receipt_count",
    "merkle_root",
    "previous_checkpoint_id",
    "previous_merkle_root",
}


@dataclass
class PublicKey:
    key_id: str
    alg: str  # "Ed25519"
    public_key_bytes: bytes  # 32 raw bytes
    active_from: datetime
    active_until: datetime | None  # None = still active


def matches_ref(key: bytes, field_name: str, value: str, ref: str) -> bool:
    """Match an application ``hmac-v1`` reference without contacting Allowly.

    ``key`` is the decoded per-integration pseudonym key. Inputs are used
    exactly as supplied: this helper does no trimming, case folding, or Unicode
    normalization.
    """
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes")
    if len(key) < 16:
        raise ValueError("key must contain at least 128 bits")
    if not isinstance(field_name, str) or field_name not in _HMAC_REF_FIELDS:
        raise ValueError("unsupported hmac-v1 field name")
    if not isinstance(value, str):
        raise TypeError("value must be a string")
    if _SURROGATE_RE.search(value):
        raise ValueError("value contains an unpaired Unicode surrogate")
    if not isinstance(ref, str) or not _HMAC_REF_RE.fullmatch(ref):
        return False
    message = field_name.encode("ascii") + b"\x00" + value.encode("utf-8")
    expected = "hmac-v1:" + hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, ref)


def _b64url_decode(s: str) -> bytes:
    """Decode base64url without padding.

    The input MUST use the URL-safe alphabet (`A-Z a-z 0-9 - _`) with no
    padding. ``base64.urlsafe_b64decode`` silently ignores out-of-alphabet
    bytes, so we reject them explicitly to enforce spec §5.1.
    """
    if not _B64URL_RE.match(s):
        raise ValueError(f"not unpadded base64url: {s!r}")
    padding = "=" * (-len(s) % 4)
    decoded = base64.urlsafe_b64decode(s + padding)
    canonical = base64.urlsafe_b64encode(decoded).decode().rstrip("=")
    if canonical != s:
        raise ValueError(f"non-canonical base64url: {s!r}")
    return decoded


def _parse_rfc3339(s: str) -> datetime:
    """Parse the format's exact UTC millisecond timestamp profile."""
    if not isinstance(s, str) or not _RFC3339_RE.match(s):
        raise SchemaError(
            f"timestamp must be UTC millisecond precision "
            f"YYYY-MM-DDTHH:MM:SS.sssZ, got {s!r}"
        )
    try:
        return datetime.fromisoformat(s[:-1] + "+00:00")
    except ValueError:
        # e.g. Feb 30: shape-valid but not a real calendar date.
        raise SchemaError(f"not a real calendar date/time: {s}") from None


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
    _validate_tree(payload)
    return _encode_value(payload).encode("utf-8")


def checkpoint_merkle_root(receipts: list[dict[str, Any]]) -> str:
    """Commit to an unordered signed-receipt set using spec §3.7."""
    leaves: list[bytes] = []
    seen_ids: set[str] = set()
    for receipt in receipts:
        if not isinstance(receipt, dict) or not isinstance(receipt.get("receipt_id"), str):
            raise SchemaError("checkpoint member must be a receipt object with receipt_id")
        if receipt["receipt_id"] in seen_ids:
            raise SchemaError(f"duplicate checkpoint member receipt_id: {receipt['receipt_id']!r}")
        seen_ids.add(receipt["receipt_id"])
        leaves.append(hashlib.sha256(b"\x00" + canonicalize(receipt)).digest())
    leaves.sort()
    if not leaves:
        return "sha256:" + hashlib.sha256(b"\x02").hexdigest()
    while len(leaves) > 1:
        if len(leaves) % 2:
            leaves.append(leaves[-1])
        leaves = [
            hashlib.sha256(b"\x01" + leaves[i] + leaves[i + 1]).digest()
            for i in range(0, len(leaves), 2)
        ]
    return f"sha256:{leaves[0].hex()}"


def _validate_tree(payload: Any) -> None:
    """Iterative pre-walk: bound depth/size, reject lone surrogates and
    non-integer/unsafe numbers (spec §4.2 rules 1 and 6).

    Runs before the recursive encoder so hostile payloads fail with a
    ``SchemaError`` instead of a raw ``RecursionError`` (deep nesting) or
    ``UnicodeEncodeError`` (lone surrogates hitting ``str.encode``). In a
    Python ``str`` any code point in U+D800–U+DFFF is by definition unpaired,
    so tampered text could otherwise canonicalize differently across
    implementations.
    """
    nodes = 0
    stack: list[tuple[Any, int]] = [(payload, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if depth > MAX_PAYLOAD_DEPTH:
            raise SchemaError(f"payload nesting exceeds max depth {MAX_PAYLOAD_DEPTH}")
        if nodes > MAX_PAYLOAD_NODES:
            raise SchemaError(f"payload exceeds max node count {MAX_PAYLOAD_NODES}")
        if isinstance(value, bool):  # before int: bool is an int subclass.
            continue
        if isinstance(value, float):
            raise SchemaError("receipts must not contain non-integer numbers")
        if isinstance(value, int):
            if abs(value) > MAX_SAFE_INTEGER:
                raise SchemaError(
                    f"integer {value} exceeds the safe range ±(2^53-1); receipts "
                    f"must not carry integers that lose precision in IEEE-754 doubles"
                )
        elif isinstance(value, str):
            if _SURROGATE_RE.search(value):
                raise SchemaError("string contains an unpaired Unicode surrogate")
        elif isinstance(value, dict):
            for k, v in value.items():
                if not isinstance(k, str):
                    raise SchemaError(f"object key must be a string, got {type(k).__name__}")
                if _SURROGATE_RE.search(k):
                    raise SchemaError("string contains an unpaired Unicode surrogate")
                stack.append((v, depth + 1))
        elif isinstance(value, list):
            for item in value:
                stack.append((item, depth + 1))


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
    if not isinstance(receipt, dict):
        raise SchemaError("receipt must be an object")
    now = now or datetime.now(timezone.utc)

    # Step 1: version check
    if receipt.get("schema_version") != SPEC_VERSION:
        raise SchemaError(
            f"unsupported schema_version: {receipt.get('schema_version')!r} (want {SPEC_VERSION!r})"
        )

    if (
        expected_workspace_id is not None
        and receipt.get("workspace_id") != expected_workspace_id
    ):
        raise SchemaError(
            f"workspace_id mismatch: receipt has {receipt.get('workspace_id')!r}, "
            f"expected {expected_workspace_id!r}"
        )

    # Step 2: schema check (includes signature shape — rejects placeholders)
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
        if event == "receipt.checkpoint":
            if authorization_id is not None:
                raise SchemaError("receipt.checkpoint must have null authorization_id")
            if resource is not None:
                raise SchemaError("receipt.checkpoint must have null resource")
            _check_checkpoint_context(receipt["context"], issued_at=receipt["issued_at"])
        elif authorization_id is None:
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
    if receipt["alg"] != "Ed25519":
        raise SchemaError(f"unsupported signature alg: {receipt['alg']!r}")

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
    key = _find_key(public_keys, receipt["key_id"], issued_at)
    sig_bytes = _b64url_decode(receipt["signature"])  # length already validated in schema check

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
    for field in ("schema_version", "receipt_id", "workspace_id", "issued_at",
                  "decision", "reason", "user_id", "agent_id",
                  "engine_version"):
        if not isinstance(receipt[field], str):
            raise SchemaError(f"{field} must be a string")

    # Nullable string fields
    for field in ("resource", "authorization_id"):
        if not (isinstance(receipt[field], str) or receipt[field] is None):
            raise SchemaError(f"{field} must be string or null")

    # Object fields
    if not isinstance(receipt["context"], dict):
        raise SchemaError("context must be an object")

    for field in ("alg", "key_id", "signature"):
        if not isinstance(receipt[field], str):
            raise SchemaError(f"{field} must be a string")

    # Signature text must be canonical base64url and decode to exactly 64 bytes.
    # This rejects placeholder strings ("pending", empty, anything malformed)
    # before the verification path even starts.
    try:
        sig_bytes = _b64url_decode(receipt["signature"])
    except Exception:
        raise SchemaError(
            f"signature is not valid canonical base64url: {receipt['signature']!r}"
        )
    if len(sig_bytes) != 64:
        raise SchemaError(
            f"signature must decode to 64 bytes (Ed25519), got {len(sig_bytes)}"
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


def _check_exact_keys(obj: dict[str, Any], expected: set[str], prefix: str) -> None:
    extra = set(obj.keys()) - expected
    missing = expected - set(obj.keys())
    if extra:
        raise SchemaError(f"{prefix} has unknown fields: {sorted(extra)}")
    if missing:
        raise SchemaError(f"{prefix} missing fields: {sorted(missing)}")


def _check_policy_eval(value: Any) -> None:
    if not isinstance(value, dict):
        raise SchemaError("policy_eval must be an object")
    _check_exact_keys(value, {"matched_condition", "field_value"}, "policy_eval")

    matched = value["matched_condition"]
    if matched is not None:
        if not isinstance(matched, dict):
            raise SchemaError("policy_eval.matched_condition must be an object or null")
        _check_exact_keys(
            matched,
            {"field", "op", "value"},
            "policy_eval.matched_condition",
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


def _check_checkpoint_context(value: Any, *, issued_at: str) -> None:
    if not isinstance(value, dict):
        raise SchemaError("receipt.checkpoint context must be an object")
    _check_exact_keys(value, _CHECKPOINT_CONTEXT_FIELDS, "receipt.checkpoint context")
    period_start = _parse_rfc3339(value["period_start"])
    period_end = _parse_rfc3339(value["period_end"])
    checkpoint_at = _parse_rfc3339(issued_at)
    if period_end <= period_start:
        raise SchemaError("receipt.checkpoint period_end must be after period_start")
    if (
        period_start.hour
        or period_start.minute
        or period_start.second
        or period_start.microsecond
        or period_end - period_start != timedelta(days=1)
    ):
        raise SchemaError("receipt.checkpoint period must be one UTC calendar day")
    if checkpoint_at < period_end:
        raise SchemaError("receipt.checkpoint issued_at must be at or after period_end")
    count = value["receipt_count"]
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise SchemaError("receipt.checkpoint receipt_count must be a non-negative integer")
    if not isinstance(value["merkle_root"], str) or not _CHECKPOINT_ROOT_RE.fullmatch(
        value["merkle_root"]
    ):
        raise SchemaError("receipt.checkpoint merkle_root must be sha256:<64 lowercase hex>")
    previous_id = value["previous_checkpoint_id"]
    previous_root = value["previous_merkle_root"]
    if (previous_id is None) != (previous_root is None):
        raise SchemaError("receipt.checkpoint previous id and root must both be null or strings")
    if previous_id is not None and not isinstance(previous_id, str):
        raise SchemaError("receipt.checkpoint previous_checkpoint_id must be string or null")
    if previous_root is not None and (
        not isinstance(previous_root, str) or not _CHECKPOINT_ROOT_RE.fullmatch(previous_root)
    ):
        raise SchemaError("receipt.checkpoint previous_merkle_root must be sha256:<64 lowercase hex> or null")


def verify_checkpoint(
    checkpoint: dict[str, Any],
    receipts: list[dict[str, Any]],
    public_keys: list[PublicKey],
    *,
    expected_workspace_id: str,
    previous_checkpoint: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> None:
    """Verify a signed checkpoint and recompute its exact presented member set."""
    verify_receipt(
        checkpoint,
        public_keys,
        now=now,
        expected_workspace_id=expected_workspace_id,
    )
    if checkpoint.get("event") != "receipt.checkpoint":
        raise SchemaError("checkpoint receipt must have event='receipt.checkpoint'")
    context = checkpoint["context"]
    period_start = _parse_rfc3339(context["period_start"])
    period_end = _parse_rfc3339(context["period_end"])
    for receipt in receipts:
        verify_receipt(
            receipt,
            public_keys,
            now=now,
            expected_workspace_id=expected_workspace_id,
        )
        if receipt.get("event") == "receipt.checkpoint":
            raise SchemaError("receipt.checkpoint cannot be a checkpoint member")
        issued_at = _parse_rfc3339(receipt["issued_at"])
        if not period_start <= issued_at < period_end:
            raise SchemaError(
                f"checkpoint member {receipt['receipt_id']!r} falls outside checkpoint period"
            )
    if context["receipt_count"] != len(receipts):
        raise VerificationError(
            f"checkpoint receipt_count mismatch: committed {context['receipt_count']}, got {len(receipts)}"
        )
    root = checkpoint_merkle_root(receipts)
    if not hmac.compare_digest(context["merkle_root"], root):
        raise VerificationError(
            f"checkpoint merkle_root mismatch: committed {context['merkle_root']}, got {root}"
        )
    if previous_checkpoint is not None:
        verify_receipt(
            previous_checkpoint,
            public_keys,
            now=now,
            expected_workspace_id=expected_workspace_id,
        )
        if previous_checkpoint.get("event") != "receipt.checkpoint":
            raise SchemaError("previous checkpoint must have event='receipt.checkpoint'")
        previous_context = previous_checkpoint["context"]
        if context["previous_checkpoint_id"] != previous_checkpoint["receipt_id"]:
            raise VerificationError("checkpoint previous_checkpoint_id mismatch")
        if context["previous_merkle_root"] != previous_context["merkle_root"]:
            raise VerificationError("checkpoint previous_merkle_root mismatch")
        if previous_context["period_end"] > context["period_start"]:
            raise VerificationError("checkpoint periods overlap or are out of order")


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
    """Parse the /v1/workspaces/{id}/keys response shape into PublicKey list.

    Raises SchemaError (never a raw KeyError/ValueError) on a malformed
    document, and rejects duplicate key ids and duplicate public keys so key
    lookup is unambiguous and one public key cannot carry conflicting active
    windows (spec §10.1).
    """
    if not isinstance(doc, dict) or not isinstance(doc.get("keys"), list):
        raise SchemaError("keys document must be an object with a 'keys' array")
    out = []
    seen_ids: set[str] = set()
    seen_pubs: set[str] = set()
    for i, k in enumerate(doc["keys"]):
        if not isinstance(k, dict):
            raise SchemaError(f"keys[{i}] must be an object")
        for field in ("key_id", "alg", "public_key", "active_from"):
            if not isinstance(k.get(field), str):
                raise SchemaError(f"keys[{i}].{field} must be a string")
        if "active_until" not in k or not (
            k["active_until"] is None or isinstance(k["active_until"], str)
        ):
            raise SchemaError(f"keys[{i}].active_until must be a string or null")
        if k["key_id"] in seen_ids:
            raise SchemaError(f"duplicate key_id in keys document: {k['key_id']!r}")
        if k["public_key"] in seen_pubs:
            raise SchemaError(f"duplicate public key in keys document: {k['key_id']!r}")
        seen_ids.add(k["key_id"])
        seen_pubs.add(k["public_key"])
        try:
            pub = _b64url_decode(k["public_key"])
        except ValueError:
            raise SchemaError(f"keys[{i}].public_key is not valid base64url") from None
        if len(pub) != 32:
            raise SchemaError(f"keys[{i}].public_key must decode to 32 bytes, got {len(pub)}")
        out.append(PublicKey(
            key_id=k["key_id"],
            alg=k["alg"],
            public_key_bytes=pub,
            active_from=_parse_rfc3339(k["active_from"]),
            active_until=(
                None
                if k["active_until"] is None
                else _parse_rfc3339(k["active_until"])
            ),
        ))
    return out


def _open_maybe_gzip(path: str):
    """Open a .jsonl or .jsonl.gz export as a text stream."""
    import gzip

    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")


def _extract_receipt(obj: Any) -> dict[str, Any]:
    """A line may be a bare receipt (audit-package chain.jsonl) or a receipt-export
    wrapper ``{"receipt_id", "workspace_id", "created_at", "receipt": {...}}``."""
    if isinstance(obj, dict) and isinstance(obj.get("receipt"), dict):
        return obj["receipt"]
    return obj


def _verify_export(
    path: str,
    keys: list[PublicKey],
    expected_workspace_id: str | None,
    authorization_id: str | None,
    checkpoint_evidence_path: str | None,
) -> int:
    import sys

    ok = failed = skipped = total = 0
    chain: list[dict[str, Any]] = []
    verified_by_id: dict[str, dict[str, Any]] = {}

    with _open_maybe_gzip(path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                receipt = _extract_receipt(json.loads(line))
            except (json.JSONDecodeError, RecursionError) as e:
                total += 1
                failed += 1
                print(f"INVALID  line {lineno}: not JSON ({e})", file=sys.stderr)
                continue
            if not isinstance(receipt, dict):
                total += 1
                failed += 1
                print(f"INVALID  line {lineno}: not a JSON object", file=sys.stderr)
                continue
            if authorization_id is not None and receipt.get("authorization_id") != authorization_id:
                skipped += 1
                continue
            total += 1
            rid = receipt.get("receipt_id", f"line {lineno}")
            try:
                verify_receipt(receipt, keys, expected_workspace_id=expected_workspace_id)
                if receipt["receipt_id"] in verified_by_id:
                    raise SchemaError(f"duplicate receipt_id in export: {receipt['receipt_id']!r}")
                label = receipt.get("action") or receipt.get("event") or "?"
                print(f"OK  {rid}  {label}  {receipt.get('decision')}")
                ok += 1
                chain.append(receipt)
                verified_by_id[receipt["receipt_id"]] = receipt
            except VerificationError as e:
                print(f"INVALID  {rid}  {e}", file=sys.stderr)
                failed += 1

    summary = f"\n{ok} ok, {failed} invalid"
    if authorization_id is not None:
        summary += f", {skipped} skipped (other authorizations)"
    summary += f"  ({total} checked)"
    print(summary)

    chain_rc = 0
    if authorization_id is not None:
        chain_rc = _check_chain_invariants(chain, authorization_id)

    checkpoint_rc = 0
    checkpoint_count = 0
    if checkpoint_evidence_path is not None:
        checkpoint_rc, checkpoint_count = _verify_checkpoint_evidence(
            checkpoint_evidence_path,
            verified_by_id,
            keys,
            expected_workspace_id,
        )

    if total == 0 and checkpoint_count == 0:
        print("No matching receipts or checkpoints found.", file=sys.stderr)
        return 1
    return 0 if failed == 0 and chain_rc == 0 and checkpoint_rc == 0 else 1


def _verify_checkpoint_evidence(
    path: str,
    verified_by_id: dict[str, dict[str, Any]],
    keys: list[PublicKey],
    expected_workspace_id: str | None,
) -> tuple[int, int]:
    import sys

    if expected_workspace_id is None:
        print("INVALID checkpoint evidence: keys document has no workspace_id", file=sys.stderr)
        return 1, 0
    try:
        with open(path, encoding="utf-8") as f:
            evidence = json.load(f)
        if not isinstance(evidence, dict) or evidence.get("version") != "receipt_checkpoint_evidence.v1":
            raise SchemaError("unsupported checkpoint evidence document")
        entries = evidence.get("checkpoints")
        if not isinstance(entries, list):
            raise SchemaError("checkpoint evidence checkpoints must be an array")

        checkpoints: dict[str, dict[str, Any]] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"checkpoint", "member_receipt_ids"}:
                raise SchemaError("checkpoint evidence entry has wrong fields")
            checkpoint = entry["checkpoint"]
            if not isinstance(checkpoint, dict) or not isinstance(checkpoint.get("receipt_id"), str):
                raise SchemaError("checkpoint evidence checkpoint must be a receipt object")
            if checkpoint["receipt_id"] in checkpoints:
                raise SchemaError("duplicate checkpoint receipt_id in evidence")
            checkpoints[checkpoint["receipt_id"]] = checkpoint

        for entry in entries:
            checkpoint = entry["checkpoint"]
            member_ids = entry["member_receipt_ids"]
            if (
                not isinstance(member_ids, list)
                or any(not isinstance(receipt_id, str) for receipt_id in member_ids)
                or len(set(member_ids)) != len(member_ids)
            ):
                raise SchemaError("checkpoint evidence member_receipt_ids must be unique strings")
            missing = [receipt_id for receipt_id in member_ids if receipt_id not in verified_by_id]
            if missing:
                raise VerificationError(
                    f"checkpoint evidence omits member receipt(s): {', '.join(missing[:5])}"
                )
            checkpoint_context = checkpoint.get("context")
            previous_id = (
                checkpoint_context.get("previous_checkpoint_id")
                if isinstance(checkpoint_context, dict)
                else None
            )
            verify_checkpoint(
                checkpoint,
                [verified_by_id[receipt_id] for receipt_id in member_ids],
                keys,
                expected_workspace_id=expected_workspace_id,
                previous_checkpoint=checkpoints.get(previous_id),
            )
            print(
                f"CHECKPOINT OK  {checkpoint['receipt_id']}  "
                f"{checkpoint['context']['period_start']}  {len(member_ids)} receipt(s)"
            )
    except (OSError, json.JSONDecodeError, VerificationError, RecursionError) as exc:
        print(f"INVALID checkpoint evidence: {exc}", file=sys.stderr)
        return 1, 0

    print(f"{len(entries)} checkpoint(s) recomputed from supplied signed receipts")
    return 0, len(entries)


def _check_chain_invariants(chain: list[dict[str, Any]], authorization_id: str) -> int:
    """Report the chain timeline and flag structural anomalies (spec §3.5)."""
    import sys

    creates = [r for r in chain if r.get("event") == "authorization.create"]
    revokes = [r for r in chain if r.get("event") == "authorization.revoke"]
    problems: list[str] = []

    if len(creates) == 0:
        problems.append("no authorization.create receipt in this chain")
    elif len(creates) > 1:
        problems.append(f"{len(creates)} authorization.create receipts (expected exactly 1)")
    if len(revokes) > 1:
        problems.append(f"{len(revokes)} authorization.revoke receipts (expected at most 1)")

    print("\nChain timeline:")
    for r in chain:
        kind = r.get("event") or f"action:{r.get('action')}"
        issued = r.get("issued_at", "?")
        try:
            _parse_rfc3339(r["issued_at"])
        except Exception:
            problems.append(f"{r.get('receipt_id')} has a non-RFC-3339 issued_at: {issued!r}")
        print(f"  {issued}  {kind}  {r.get('decision')}")

    if problems:
        for problem in problems:
            print(f"CHAIN WARNING: {problem}", file=sys.stderr)
        return 1

    # Completeness is not provable from signatures alone (spec §3.5): this
    # only attests that the receipts *supplied* are consistent.
    print(
        f"Receipt subset OK: 1 create, {len(revokes)} revoke, {len(chain)} signed "
        f"receipt(s). (Attests supplied receipts only; cannot prove none were omitted.)"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys

    p = argparse.ArgumentParser(description="Verify Allowly receipts.")
    p.add_argument(
        "paths",
        nargs="*",
        help="single mode: <receipt.json> <keys.json>; with --export: <keys.json>",
    )
    p.add_argument(
        "--export",
        metavar="FILE",
        help="verify a JSONL or .jsonl.gz export in bulk (audit-package chain.jsonl or a receipt export)",
    )
    p.add_argument(
        "--authorization-id",
        metavar="ID",
        help="with --export: verify only this authorization's chain and check chain invariants",
    )
    p.add_argument(
        "--checkpoint-evidence",
        metavar="FILE",
        help="with --export: recompute checkpoint entries in checkpoint_evidence.json",
    )
    args = p.parse_args(argv)

    # The keys document is published per workspace; bind receipts to it so a
    # receipt cannot verify against another workspace's keys that share a key_id.
    if args.export:
        if len(args.paths) != 1:
            p.error("with --export, provide exactly one positional argument: the keys JSON file")
        if args.authorization_id and args.checkpoint_evidence:
            p.error("--checkpoint-evidence cannot be used with an authorization-scoped export")
        with open(args.paths[0]) as f:
            keys_doc = json.load(f)
        keys = load_keys_from_json(keys_doc)
        return _verify_export(
            args.export,
            keys,
            keys_doc.get("workspace_id"),
            args.authorization_id,
            args.checkpoint_evidence,
        )

    if args.authorization_id:
        p.error("--authorization-id requires --export")
    if args.checkpoint_evidence:
        p.error("--checkpoint-evidence requires --export")
    if len(args.paths) != 2:
        p.error("provide <receipt.json> <keys.json>, or use --export <file> <keys.json>")

    receipt_path, keys_path = args.paths
    with open(receipt_path) as f:
        receipt = json.load(f)
    with open(keys_path) as f:
        keys_doc = json.load(f)

    keys = load_keys_from_json(keys_doc)
    expected_workspace_id = keys_doc.get("workspace_id")

    try:
        verify_receipt(receipt, keys, expected_workspace_id=expected_workspace_id)
        print(f"OK  receipt_id={receipt['receipt_id']} decision={receipt['decision']}")
        return 0
    except VerificationError as e:
        print(f"INVALID  {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    sys.exit(main())
