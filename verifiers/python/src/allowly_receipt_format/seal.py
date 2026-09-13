"""RFC 8785 hashing and signed-receipt verification for Allowly SEAL."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Callable, Literal

import rfc8785

from .verifier import PublicKey, VerificationError, verify_receipt


SEAL_PROFILE = "allowly.seal.jcs-sha256.v1"
SEAL_ACTION = "record.seal"
SEAL_AGENT_ID = "allowly.seal"
SEAL_USER_ID = "allowly:seal"
SEAL_MAX_UTF8_BYTES = 1_048_576
SEAL_MAX_DEPTH = 32
_MAX_SAFE_INTEGER = 2**53 - 1
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

SealInputFailure = Literal[
    "invalid_type",
    "invalid_utf8",
    "size_limit",
    "depth_limit",
    "invalid_json",
    "duplicate_key",
    "invalid_unicode",
    "number_overflow",
    "number_underflow",
    "unsafe_integer",
    "number_precision",
    "unsupported_value",
    "canonicalization_failed",
]
SealVerificationFailure = Literal[
    "receipt_verification_failed",
    "not_seal_receipt",
    "seal_identity_mismatch",
    "seal_profile_mismatch",
    "invalid_record_digest",
    "invalid_record",
    "record_mismatch",
]


class SealInputError(ValueError):
    """Raised when a record cannot be hashed under the SEAL profile."""

    def __init__(self, code: SealInputFailure, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SealVerificationResult:
    """Independent signature and record-match outcomes for a SEAL receipt."""

    signature_verified: bool
    record_matches: bool
    failure_reason: SealVerificationFailure | None


def hash_seal_json(raw_json: str | bytes) -> str:
    """Hash strict raw JSON using the ``allowly.seal.jcs-sha256.v1`` profile.

    This raw boundary rejects duplicate decoded object names and numeric tokens
    that would lose significant information when converted to binary64.
    """

    raw_bytes, text = _decode_raw_json(raw_json)
    if len(raw_bytes) > SEAL_MAX_UTF8_BYTES:
        raise SealInputError(
            "size_limit",
            f"record exceeds the {SEAL_MAX_UTF8_BYTES}-byte SEAL limit",
        )
    _check_raw_depth(text)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_unique_object,
            parse_int=_parse_integer,
            parse_float=_parse_float,
            parse_constant=_reject_constant,
        )
    except SealInputError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise SealInputError("invalid_json", "record must be valid JSON") from exc
    return _hash_seal_value(value)


def hash_seal_value(record: Any) -> str:
    """Hash an already-parsed JSON value.

    Parsing has already erased duplicate object names and original number-token
    spellings. Use :func:`hash_seal_json` at untrusted/raw input boundaries.
    """

    return _hash_seal_value(record)


def verify_seal_json(
    raw_json: str | bytes,
    receipt: dict[str, Any],
    public_keys: list[PublicKey],
    *,
    expected_workspace_id: str,
    trusted_key_fingerprints: set[str] | frozenset[str] | None = None,
    now: Any = None,
) -> SealVerificationResult:
    """Verify a signed SEAL receipt and compare it with strict raw JSON."""

    return _verify_seal(
        lambda: hash_seal_json(raw_json),
        receipt,
        public_keys,
        expected_workspace_id=expected_workspace_id,
        trusted_key_fingerprints=trusted_key_fingerprints,
        now=now,
    )


def verify_seal_value(
    record: Any,
    receipt: dict[str, Any],
    public_keys: list[PublicKey],
    *,
    expected_workspace_id: str,
    trusted_key_fingerprints: set[str] | frozenset[str] | None = None,
    now: Any = None,
) -> SealVerificationResult:
    """Verify a SEAL against a parsed value, subject to the parsed boundary."""

    return _verify_seal(
        lambda: hash_seal_value(record),
        receipt,
        public_keys,
        expected_workspace_id=expected_workspace_id,
        trusted_key_fingerprints=trusted_key_fingerprints,
        now=now,
    )


def _verify_seal(
    record_digest: Callable[[], str],
    receipt: dict[str, Any],
    public_keys: list[PublicKey],
    *,
    expected_workspace_id: str,
    trusted_key_fingerprints: set[str] | frozenset[str] | None,
    now: Any,
) -> SealVerificationResult:
    try:
        verify_receipt(
            receipt,
            public_keys,
            expected_workspace_id=expected_workspace_id,
            trusted_key_fingerprints=trusted_key_fingerprints,
            now=now,
        )
    except VerificationError:
        return SealVerificationResult(False, False, "receipt_verification_failed")

    if receipt.get("action") != SEAL_ACTION or receipt.get("decision") != "allow":
        return SealVerificationResult(True, False, "not_seal_receipt")
    if receipt.get("agent_id") != SEAL_AGENT_ID or receipt.get("user_id") != SEAL_USER_ID:
        return SealVerificationResult(True, False, "seal_identity_mismatch")

    context = receipt.get("context")
    if not isinstance(context, dict) or context.get("seal_profile") != SEAL_PROFILE:
        return SealVerificationResult(True, False, "seal_profile_mismatch")
    expected_digest = context.get("record_sha256")
    if not isinstance(expected_digest, str) or not _SHA256_RE.fullmatch(expected_digest):
        return SealVerificationResult(True, False, "invalid_record_digest")

    try:
        actual_digest = record_digest()
    except SealInputError:
        return SealVerificationResult(True, False, "invalid_record")
    if not hmac.compare_digest(actual_digest, expected_digest):
        return SealVerificationResult(True, False, "record_mismatch")
    return SealVerificationResult(True, True, None)


def _decode_raw_json(raw_json: str | bytes) -> tuple[bytes, str]:
    if isinstance(raw_json, bytes):
        raw_bytes = raw_json
        try:
            text = raw_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise SealInputError("invalid_utf8", "record must be well-formed UTF-8") from exc
    elif isinstance(raw_json, str):
        if _SURROGATE_RE.search(raw_json):
            raise SealInputError("invalid_unicode", "record contains an unpaired Unicode surrogate")
        text = raw_json
        raw_bytes = text.encode("utf-8")
    else:
        raise SealInputError("invalid_type", "raw_json must be str or bytes")
    return raw_bytes, text


def _check_raw_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > SEAL_MAX_DEPTH:
                raise SealInputError(
                    "depth_limit",
                    f"record nesting exceeds the SEAL max depth {SEAL_MAX_DEPTH}",
                )
        elif char in "]}":
            depth -= 1


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SealInputError("duplicate_key", f"duplicate decoded object key: {key!r}")
        result[key] = value
    return result


def _parse_integer(token: str) -> int:
    value = int(token)
    if abs(value) > _MAX_SAFE_INTEGER:
        raise SealInputError("unsafe_integer", "record contains an integer outside ±(2^53-1)")
    return value


def _parse_float(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise SealInputError("number_overflow", "record contains a number outside binary64 range")
    try:
        exact = Decimal(token)
        represented = Decimal(repr(value))
    except InvalidOperation as exc:  # pragma: no cover - JSON grammar gates this first
        raise SealInputError("invalid_json", "record contains an invalid number") from exc
    if value == 0 and exact != 0:
        raise SealInputError("number_underflow", "record number underflows binary64 to zero")
    if value.is_integer() and abs(value) > _MAX_SAFE_INTEGER:
        raise SealInputError("unsafe_integer", "record contains an integer outside ±(2^53-1)")
    if exact != represented:
        raise SealInputError(
            "number_precision",
            "record number loses significant digits in the RFC 8785 binary64 model",
        )
    return value


def _reject_constant(token: str) -> Any:
    raise SealInputError("invalid_json", f"record contains non-JSON number {token}")


def _hash_seal_value(record: Any) -> str:
    _validate_seal_tree(record)
    try:
        canonical = rfc8785.dumps(record)
    except rfc8785.CanonicalizationError as exc:
        raise SealInputError("canonicalization_failed", "record cannot be canonicalized as RFC 8785") from exc
    if len(canonical) > SEAL_MAX_UTF8_BYTES:
        raise SealInputError(
            "size_limit",
            f"canonical record exceeds the {SEAL_MAX_UTF8_BYTES}-byte SEAL limit",
        )
    return hashlib.sha256(canonical).hexdigest()


def _validate_seal_tree(record: Any) -> None:
    stack: list[tuple[Any, int]] = [(record, 1)]
    while stack:
        value, depth = stack.pop()
        if depth > SEAL_MAX_DEPTH:
            raise SealInputError(
                "depth_limit",
                f"record nesting exceeds the SEAL max depth {SEAL_MAX_DEPTH}",
            )
        if value is None or type(value) is bool:
            continue
        if type(value) is int:
            if abs(value) > _MAX_SAFE_INTEGER:
                raise SealInputError("unsafe_integer", "record contains an integer outside ±(2^53-1)")
        elif type(value) is float:
            if not math.isfinite(value):
                raise SealInputError("number_overflow", "record contains a non-finite number")
            if value.is_integer() and abs(value) > _MAX_SAFE_INTEGER:
                raise SealInputError("unsafe_integer", "record contains an integer outside ±(2^53-1)")
        elif type(value) is str:
            if _SURROGATE_RE.search(value):
                raise SealInputError("invalid_unicode", "record contains an unpaired Unicode surrogate")
        elif type(value) is list:
            stack.extend((item, depth + 1) for item in value)
        elif type(value) is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise SealInputError("unsupported_value", "record object keys must be strings")
                if _SURROGATE_RE.search(key):
                    raise SealInputError("invalid_unicode", "record contains an unpaired Unicode surrogate")
                stack.append((item, depth + 1))
        else:
            raise SealInputError(
                "unsupported_value",
                f"record contains non-JSON type {type(value).__name__}",
            )


__all__ = [
    "SEAL_ACTION",
    "SEAL_AGENT_ID",
    "SEAL_MAX_DEPTH",
    "SEAL_MAX_UTF8_BYTES",
    "SEAL_PROFILE",
    "SEAL_USER_ID",
    "SealInputError",
    "SealVerificationResult",
    "hash_seal_json",
    "hash_seal_value",
    "verify_seal_json",
    "verify_seal_value",
]
