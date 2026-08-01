"""
Allowly Receipt Verifier (Python reference implementation).

Verifies Allowly receipts per receipt-format.md wire version 3.

Usage (library):
    from allowly_receipt_format import verify_receipt, VerificationError, load_keys_from_json

    try:
        verify_receipt(receipt_dict, public_keys)
        print("valid")
    except VerificationError as e:
        print(f"invalid: {e}")

Usage (CLI):
    allowly-receipt-verify --workspace-id WORKSPACE \
        --trusted-key-fingerprint sha256:HEX receipt.json keys.json

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


SPEC_VERSION = "3"
ACTION_DECISIONS = {"allow", "deny", "confirm", "escalate"}
EVENT_DECISIONS = {
    "authorization.create": {"authorization_granted"},
    "authorization.revoke": {"authorization_revoked"},
    "budget.settle": {"budget_settled"},
    "escalation.resolve": {"escalation_approved", "escalation_rejected"},
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
_PUBLIC_KEY_FINGERPRINT_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
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
    "load_keys_from_json",
    "main",
    "matches_ref",
    "public_key_fingerprint",
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


def public_key_fingerprint(key: PublicKey) -> str:
    """Return the canonical SHA-256 fingerprint of an Ed25519 public key."""
    return "sha256:" + hashlib.sha256(key.public_key_bytes).hexdigest()


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
    trusted_key_fingerprints: set[str] | frozenset[str] | None = None,
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
        trusted_key_fingerprints: if given, the selected public key's canonical
            ``sha256:<hex>`` fingerprint MUST be present in this caller-trusted set.
    """
    if not isinstance(receipt, dict):
        raise SchemaError("receipt must be an object")
    if now is None:
        now = datetime.now(timezone.utc)
    elif type(now) is not datetime or now.utcoffset() is None:
        raise SchemaError("now must be an aware datetime")

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
    fingerprint = public_key_fingerprint(key)
    if (
        trusted_key_fingerprints is not None
        and fingerprint not in trusted_key_fingerprints
    ):
        raise VerificationError(f"public key fingerprint is not trusted: {fingerprint}")
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


def _find_key(
    keys: list[PublicKey], key_id: str, issued_at: datetime
) -> PublicKey:
    for k in keys:
        try:
            candidate_id = k.key_id
        except (AttributeError, TypeError):
            raise SchemaError("public key entries must have PublicKey fields") from None
        if candidate_id != key_id:
            continue
        try:
            alg = k.alg
            raw_public_key = k.public_key_bytes
            active_from = k.active_from
            active_until = k.active_until
        except (AttributeError, TypeError):
            raise SchemaError("selected public key has invalid fields") from None
        if not isinstance(raw_public_key, (bytes, bytearray, memoryview)):
            raise SchemaError("selected public key bytes must be bytes-like")
        public_key_bytes = bytes(raw_public_key)
        if alg != "Ed25519":
            raise SchemaError(f"unsupported public key alg: {alg!r}")
        if len(public_key_bytes) != 32:
            raise SchemaError("selected Ed25519 public key must contain 32 raw bytes")
        if type(active_from) is not datetime or active_from.utcoffset() is None:
            raise SchemaError("selected public key active_from must be an aware datetime")
        if active_until is not None and (
            type(active_until) is not datetime or active_until.utcoffset() is None
        ):
            raise SchemaError("selected public key active_until must be an aware datetime or None")
        if active_until is not None and active_until <= active_from:
            raise SchemaError("selected public key active window is empty")
        key = PublicKey(
            key_id=candidate_id,
            alg=alg,
            public_key_bytes=public_key_bytes,
            active_from=active_from,
            active_until=active_until,
        )
        if issued_at < key.active_from:
            raise KeyOutsideActiveWindowError(f"key {key_id!r} not yet active at issued_at")
        if key.active_until is not None and issued_at >= key.active_until:
            raise KeyOutsideActiveWindowError(f"key {key_id!r} retired before issued_at")
        return key
    raise UnknownKeyError(f"no public key found for key_id={key_id!r}")


def load_keys_from_json(doc: dict[str, Any]) -> list[PublicKey]:
    """Parse the /v1/workspaces/{id}/keys response shape into PublicKey list.

    Raises SchemaError (never a raw KeyError/ValueError) on a malformed
    document, and rejects duplicate key ids and duplicate public keys so key
    lookup is unambiguous and one public key cannot carry conflicting active
    windows (spec §10.1).
    """
    if (
        not isinstance(doc, dict)
        or not isinstance(doc.get("workspace_id"), str)
        or not doc["workspace_id"]
        or not isinstance(doc.get("keys"), list)
    ):
        raise SchemaError(
            "keys document must be an object with a non-empty 'workspace_id' and a 'keys' array"
        )
    out = []
    seen_ids: set[str] = set()
    seen_pubs: set[str] = set()
    for i, k in enumerate(doc["keys"]):
        if not isinstance(k, dict):
            raise SchemaError(f"keys[{i}] must be an object")
        for field in ("key_id", "alg", "public_key", "active_from"):
            if not isinstance(k.get(field), str):
                raise SchemaError(f"keys[{i}].{field} must be a string")
        if k["alg"] != "Ed25519":
            raise SchemaError(f"keys[{i}].alg must be 'Ed25519'")
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
        key = PublicKey(
            key_id=k["key_id"],
            alg=k["alg"],
            public_key_bytes=pub,
            active_from=_parse_rfc3339(k["active_from"]),
            active_until=(
                None
                if k["active_until"] is None
                else _parse_rfc3339(k["active_until"])
            ),
        )
        if (
            "public_key_fingerprint" in k
            and k["public_key_fingerprint"] != public_key_fingerprint(key)
        ):
            raise SchemaError(
                f"keys[{i}].public_key_fingerprint does not match public_key"
            )
        out.append(key)
    return out


def _reject_duplicate_json_names(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for name, value in pairs:
        if name in obj:
            raise SchemaError(f"duplicate JSON object name: {name!r}")
        obj[name] = value
    return obj


def _load_json_file(path: str) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=_reject_duplicate_json_names)


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
    expected_workspace_id: str,
    trusted_key_fingerprints: set[str],
    authorization_id: str | None,
) -> int:
    import sys

    ok = failed = skipped = total = 0
    chain: list[dict[str, Any]] = []

    with _open_maybe_gzip(path) as f:
        for lineno, raw in enumerate(f, 1):
            line = raw.strip()
            if not line:
                continue
            try:
                receipt = _extract_receipt(json.loads(
                    line,
                    object_pairs_hook=_reject_duplicate_json_names,
                ))
            except (json.JSONDecodeError, RecursionError, SchemaError) as e:
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
                verify_receipt(
                    receipt,
                    keys,
                    expected_workspace_id=expected_workspace_id,
                    trusted_key_fingerprints=trusted_key_fingerprints,
                )
                label = receipt.get("action") or receipt.get("event") or "?"
                print(f"OK  {rid}  {label}  {receipt.get('decision')}")
                ok += 1
                chain.append(receipt)
            except VerificationError as e:
                print(f"INVALID  {rid}  {e}", file=sys.stderr)
                failed += 1

    summary = f"\n{ok} ok, {failed} invalid"
    if authorization_id is not None:
        summary += f", {skipped} skipped (other authorizations)"
    summary += f"  ({total} checked)"
    print(summary)

    if total == 0:
        print("No matching receipts found.", file=sys.stderr)
        return 1

    chain_rc = 0
    if authorization_id is not None:
        chain_rc = _check_chain_invariants(chain, authorization_id)

    return 0 if failed == 0 and chain_rc == 0 else 1


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
        "--workspace-id",
        required=True,
        help="caller-trusted workspace ID; must match both keys.json and every receipt",
    )
    p.add_argument(
        "--trusted-key-fingerprint",
        action="append",
        required=True,
        metavar="sha256:HEX",
        help="caller-trusted SHA-256 Ed25519 public-key fingerprint; repeat for rotations",
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
    args = p.parse_args(argv)

    trusted_fingerprints = set(args.trusted_key_fingerprint)
    if any(not _PUBLIC_KEY_FINGERPRINT_RE.fullmatch(fp) for fp in trusted_fingerprints):
        p.error("--trusted-key-fingerprint must be sha256: followed by 64 lowercase hex characters")

    if args.export:
        if len(args.paths) != 1:
            p.error("with --export, provide exactly one positional argument: the keys JSON file")
    else:
        if args.authorization_id:
            p.error("--authorization-id requires --export")
        if len(args.paths) != 2:
            p.error("provide <receipt.json> <keys.json>, or use --export <file> <keys.json>")

    try:
        keys_doc = _load_json_file(args.paths[-1])
        keys = load_keys_from_json(keys_doc)
        if keys_doc["workspace_id"] != args.workspace_id:
            raise SchemaError(
                f"workspace_id mismatch: keys document has {keys_doc['workspace_id']!r}, "
                f"expected {args.workspace_id!r}"
            )
    except (OSError, json.JSONDecodeError, RecursionError, VerificationError) as e:
        print(f"INVALID  keys document: {e}", file=sys.stderr)
        return 1

    if args.export:
        return _verify_export(
            args.export,
            keys,
            args.workspace_id,
            trusted_fingerprints,
            args.authorization_id,
        )

    receipt_path, _keys_path = args.paths
    try:
        receipt = _load_json_file(receipt_path)
        verify_receipt(
            receipt,
            keys,
            expected_workspace_id=args.workspace_id,
            trusted_key_fingerprints=trusted_fingerprints,
        )
        print(f"OK  receipt_id={receipt['receipt_id']} decision={receipt['decision']}")
        return 0
    except (OSError, json.JSONDecodeError, RecursionError, VerificationError) as e:
        print(f"INVALID  {e}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    sys.exit(main())
