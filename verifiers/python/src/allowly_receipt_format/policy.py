"""Offline replay for Allowly conditional policy evidence.

This module intentionally reimplements the small, versioned policy evaluator.
It does not import the Allowly API and it does not claim to reproduce the full
decision engine.  The public function first authenticates every supplied
receipt, then compares only the recorded and calculated ``policy_eval``
objects.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .verifier import (
    _PUBLIC_KEY_FINGERPRINT_RE,
    PublicKey,
    SchemaError,
    _parse_rfc3339,
    canonicalize,
    verify_receipt,
)

POLICY_PROFILE = "allowly-conditional-evaluation-v1"
SUPPORTED_ACTION_ENGINE_VERSIONS = frozenset({"2026-09-16.1"})
SUPPORTED_AUTHORIZATION_ENGINE_VERSIONS = frozenset({"2026-09-16.1"})
RESERVED_RECEIPT_CONTEXT_KEYS = frozenset({"budget", "escalation", "session_id"})

_CONDITION_KEYS = ("deny_when", "escalate_when", "confirm_when")
_OPERATORS = frozenset(
    {
        "eq",
        "neq",
        "lt",
        "lte",
        "gt",
        "gte",
        "in",
        "nin",
        "contains_any",
        "contains_none",
        "empty",
        "exists",
    }
)
_MAX_POLICY_CONDITIONS = 10

__all__ = [
    "POLICY_PROFILE",
    "SUPPORTED_ACTION_ENGINE_VERSIONS",
    "SUPPORTED_AUTHORIZATION_ENGINE_VERSIONS",
    "verify_policy_evaluation",
]


class _UnsupportedPolicy(ValueError):
    """Internal marker for a signed policy shape this profile cannot replay."""


@dataclass(frozen=True)
class _ConditionResult:
    kind: str
    reason: str
    policy_eval: dict[str, Any]


def _result(
    receipt: dict[str, Any],
    *,
    authorization_receipt_id: str | None,
    status: str,
    diagnostic: str,
    recorded_evaluation: dict[str, Any] | None,
    calculated_evaluation: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "profile": POLICY_PROFILE,
        "engine_version": receipt["engine_version"],
        "receipt_id": receipt["receipt_id"],
        "authorization_receipt_id": authorization_receipt_id,
        "status": status,
        "diagnostic": diagnostic,
        "recorded_evaluation": recorded_evaluation,
        "calculated_evaluation": calculated_evaluation,
    }


def verify_policy_evaluation(
    receipt: dict[str, Any],
    authorization_receipts: list[dict[str, Any]],
    public_keys: list[PublicKey],
    *,
    expected_workspace_id: str,
    trusted_key_fingerprints: set[str] | frozenset[str],
    now: datetime | None = None,
) -> dict[str, Any]:
    """Authenticate and replay one action receipt's conditional evaluation.

    ``matched`` means only that the signed authorization conditions and the
    reconstructed signed context produce the same complete ``policy_eval``
    object.  It does not reproduce the final decision or prove that caller
    supplied facts were true.

    Malformed receipts, invalid signatures, workspace mismatches, and trust
    failures raise :class:`VerificationError`.  Missing or unsupported replay
    evidence returns ``status == "not_checked"`` with a stable diagnostic.
    """

    # Work only from one frozen view. Callers may hold and mutate the original
    # dictionaries while verification runs; later evaluation must use exactly
    # the bytes whose signatures were checked.
    if type(expected_workspace_id) is not str or not expected_workspace_id:
        raise SchemaError("expected_workspace_id must be a non-empty string")
    if type(trusted_key_fingerprints) not in (set, frozenset):
        raise SchemaError("trusted_key_fingerprints must be a non-empty set")
    if type(public_keys) is not list:
        raise SchemaError("public_keys must be a list")
    try:
        receipt = _snapshot_json(receipt)
        authorization_receipts = _snapshot_json(authorization_receipts)
        public_keys = [
            PublicKey(
                key_id=key.key_id,
                alg=key.alg,
                public_key_bytes=bytes(key.public_key_bytes),
                active_from=key.active_from,
                active_until=key.active_until,
            )
            for key in public_keys
        ]
        trusted_key_fingerprints = frozenset(trusted_key_fingerprints)
    except SchemaError:
        raise
    except (AttributeError, TypeError, ValueError, RuntimeError) as exc:
        raise SchemaError(f"policy evaluation inputs could not be copied: {exc}") from None

    if not trusted_key_fingerprints:
        raise SchemaError("trusted_key_fingerprints must be a non-empty set")
    if any(
        not isinstance(fingerprint, str)
        or not _PUBLIC_KEY_FINGERPRINT_RE.fullmatch(fingerprint)
        for fingerprint in trusted_key_fingerprints
    ):
        raise SchemaError(
            "trusted_key_fingerprints entries must be sha256: followed by 64 lowercase hex characters"
        )

    # Authenticate the action receipt and every supplied candidate before any
    # replay-status result is returned.  A bad extra candidate cannot be hidden
    # merely because another candidate is usable.
    verify_receipt(
        receipt,
        public_keys,
        now=now,
        expected_workspace_id=expected_workspace_id,
        trusted_key_fingerprints=trusted_key_fingerprints,
    )
    if not isinstance(authorization_receipts, list):
        raise SchemaError("authorization_receipts must be a list")
    for candidate in authorization_receipts:
        if not isinstance(candidate, dict):
            raise SchemaError("authorization_receipts entries must be receipt objects")
        verify_receipt(
            candidate,
            public_keys,
            now=now,
            expected_workspace_id=expected_workspace_id,
            trusted_key_fingerprints=trusted_key_fingerprints,
        )

    if "action" not in receipt:
        raise SchemaError("policy evaluation requires an action receipt")

    recorded = receipt.get("policy_eval")
    if recorded is None:
        return _result(
            receipt,
            authorization_receipt_id=None,
            status="not_checked",
            diagnostic="policy_evaluation_not_recorded",
            recorded_evaluation=None,
            calculated_evaluation=None,
        )

    if receipt["engine_version"] not in SUPPORTED_ACTION_ENGINE_VERSIONS:
        return _result(
            receipt,
            authorization_receipt_id=None,
            status="not_checked",
            diagnostic="unsupported_engine_version",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )

    authorization_id = receipt["authorization_id"]
    if not isinstance(authorization_id, str) or not authorization_id:
        return _result(
            receipt,
            authorization_receipt_id=None,
            status="not_checked",
            diagnostic="authorization_receipt_not_found",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )

    matching = [
        candidate
        for candidate in authorization_receipts
        if candidate.get("event") == "authorization.create"
        and candidate.get("authorization_id") == authorization_id
    ]
    distinct: dict[bytes, dict[str, Any]] = {}
    for candidate in matching:
        distinct.setdefault(canonicalize(candidate), candidate)
    if not distinct:
        return _result(
            receipt,
            authorization_receipt_id=None,
            status="not_checked",
            diagnostic="authorization_receipt_not_found",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )
    if len(distinct) > 1:
        return _result(
            receipt,
            authorization_receipt_id=None,
            status="not_checked",
            diagnostic="conflicting_authorization_receipts",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )

    authorization_receipt = next(iter(distinct.values()))
    authorization_receipt_id = authorization_receipt["receipt_id"]
    if (
        authorization_receipt["engine_version"]
        not in SUPPORTED_AUTHORIZATION_ENGINE_VERSIONS
        or _parse_rfc3339(authorization_receipt["issued_at"])
        > _parse_rfc3339(receipt["issued_at"])
    ):
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="not_checked",
            diagnostic="unsupported_authorization_snapshot",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )

    if (
        authorization_receipt["user_id"] != receipt["user_id"]
        or authorization_receipt["agent_id"] != receipt["agent_id"]
    ):
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="not_checked",
            diagnostic="authorization_subject_mismatch",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )

    actions = authorization_receipt["context"].get("actions")
    if not isinstance(actions, list) or not actions:
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="not_checked",
            diagnostic="unsupported_authorization_snapshot",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )
    if any(
        not isinstance(action, dict)
        or set(action) != {"name", "constraints"}
        or not isinstance(action.get("name"), str)
        or not action["name"]
        or not isinstance(action.get("constraints"), dict)
        for action in actions
    ):
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="not_checked",
            diagnostic="unsupported_authorization_snapshot",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )

    selected_actions = [action for action in actions if action["name"] == receipt["action"]]
    if not selected_actions:
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="not_checked",
            diagnostic="authorization_action_not_found",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )
    if len(selected_actions) > 1:
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="not_checked",
            diagnostic="authorization_action_ambiguous",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )
    if len({action["name"] for action in actions}) != len(actions):
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="not_checked",
            diagnostic="unsupported_authorization_snapshot",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )

    constraints = selected_actions[0]["constraints"]
    replay_context = {
        key: value
        for key, value in receipt["context"].items()
        if key not in RESERVED_RECEIPT_CONTEXT_KEYS
    }
    try:
        calculated_result = _evaluate_policy_conditions(constraints, replay_context)
    except _UnsupportedPolicy:
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="not_checked",
            diagnostic="unsupported_policy",
            recorded_evaluation=recorded,
            calculated_evaluation=None,
        )

    calculated = None if calculated_result is None else calculated_result.policy_eval
    if _json_equal(recorded, calculated):
        return _result(
            receipt,
            authorization_receipt_id=authorization_receipt_id,
            status="matched",
            diagnostic="matched",
            recorded_evaluation=recorded,
            calculated_evaluation=calculated,
        )
    return _result(
        receipt,
        authorization_receipt_id=authorization_receipt_id,
        status="mismatch",
        diagnostic="policy_evaluation_mismatch",
        recorded_evaluation=recorded,
        calculated_evaluation=calculated,
    )


def _snapshot_json(value: Any) -> Any:
    """Copy built-in JSON containers and reject behavior-changing subclasses."""
    nodes = 0

    def snapshot(item: Any, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if depth > 32:
            raise SchemaError("policy evaluation input nesting exceeds max depth 32")
        if nodes > 50_000:
            raise SchemaError("policy evaluation input exceeds max node count 50000")
        if item is None or type(item) in (str, int, bool, float):
            return item
        if type(item) is list:
            return [snapshot(member, depth + 1) for member in item]
        if type(item) is dict:
            copied: dict[str, Any] = {}
            for key, member in item.items():
                if type(key) is not str:
                    raise SchemaError("policy evaluation object keys must be strings")
                copied[key] = snapshot(member, depth + 1)
            return copied
        raise SchemaError(
            f"policy evaluation inputs must contain plain JSON values, got {type(item).__name__}"
        )

    try:
        return snapshot(value, 1)
    except RuntimeError as exc:
        raise SchemaError(f"policy evaluation input changed while being copied: {exc}") from None


def _evaluate_policy_conditions(
    constraints: dict[str, Any] | None,
    context: dict[str, Any] | None,
) -> _ConditionResult | None:
    constraints = constraints or {}
    context = context or {}
    _validate_policy(constraints)

    deny_result = _evaluate_condition_list(
        kind="deny",
        reason="deny_condition_matched",
        conditions=constraints.get("deny_when"),
        context=context,
        missing_kind="confirm",
    )
    if deny_result is not None and deny_result.reason == "deny_condition_matched":
        return deny_result
    deny_missing_fallback = deny_result

    escalate_result = _evaluate_condition_list(
        kind="escalate",
        reason="escalate_condition_matched",
        conditions=constraints.get("escalate_when"),
        context=context,
    )
    if escalate_result is not None:
        return escalate_result

    confirm_result = _evaluate_condition_list(
        kind="confirm",
        reason="confirm_condition_matched",
        conditions=constraints.get("confirm_when"),
        context=context,
    )
    if confirm_result is not None:
        return confirm_result

    if deny_missing_fallback is not None:
        return deny_missing_fallback
    if _has_policy_conditions(constraints):
        return _ConditionResult(
            kind="none",
            reason="policy_conditions_not_matched",
            policy_eval={"matched_condition": None, "field_value": None},
        )
    return None


def _validate_policy(constraints: dict[str, Any]) -> None:
    if not isinstance(constraints, dict):
        raise _UnsupportedPolicy("constraints must be an object")
    total = 0
    for key in _CONDITION_KEYS:
        conditions = constraints.get(key)
        if conditions is None:
            continue
        if not isinstance(conditions, list):
            raise _UnsupportedPolicy(f"{key} must be a list")
        total += len(conditions)
        if total > _MAX_POLICY_CONDITIONS:
            raise _UnsupportedPolicy("too many policy conditions")
        for condition in conditions:
            _normalize_condition(condition)


def _has_policy_conditions(constraints: dict[str, Any]) -> bool:
    return any(bool(constraints.get(key)) for key in _CONDITION_KEYS)


def _evaluate_condition_list(
    *,
    kind: str,
    reason: str,
    conditions: Any,
    context: dict[str, Any],
    missing_kind: str | None = None,
) -> _ConditionResult | None:
    if not isinstance(conditions, list):
        return None
    missing_result = None
    for condition in conditions:
        normalized = _normalize_condition(condition)
        field = normalized["field"]
        op = normalized["op"]
        expected = normalized["value"]
        present = field in context
        actual = context.get(field)
        policy_eval = {
            "matched_condition": normalized,
            "field_value": _policy_eval_field_value(
                op=op,
                actual=actual,
                expected=expected,
                present=present,
            ),
        }

        if op == "exists":
            if present == expected:
                return _ConditionResult(kind=kind, reason=reason, policy_eval=policy_eval)
            continue
        matched = _condition_matches(op=op, actual=actual, expected=expected) if present else None
        if matched is None:
            result = _ConditionResult(
                kind=missing_kind or kind,
                reason="context_field_missing",
                policy_eval=policy_eval,
            )
            if missing_kind is None:
                return result
            if missing_result is None:
                missing_result = result
            continue
        if matched:
            return _ConditionResult(kind=kind, reason=reason, policy_eval=policy_eval)
    return missing_result


def _condition_matches(*, op: str, actual: Any, expected: Any) -> bool | None:
    try:
        if op in {"eq", "neq"}:
            if not _same_json_scalar_type(actual, expected):
                return None
            return actual == expected if op == "eq" else actual != expected
        if op == "lt":
            return actual < expected if _is_int(actual) else None
        if op == "lte":
            return actual <= expected if _is_int(actual) else None
        if op == "gt":
            return actual > expected if _is_int(actual) else None
        if op == "gte":
            return actual >= expected if _is_int(actual) else None
        if op in {"in", "nin"}:
            comparable = [item for item in expected if _same_json_scalar_type(actual, item)]
            if not comparable:
                return None
            return actual in comparable if op == "in" else actual not in comparable
        if op in {"contains_any", "contains_none"}:
            if (
                not isinstance(actual, list)
                or any(not _is_scalar(item) for item in actual)
                or any(not _is_scalar(item) for item in expected)
            ):
                return None
            disjoint = _typed_scalar_set(actual).isdisjoint(_typed_scalar_set(expected))
            return not disjoint if op == "contains_any" else disjoint
        if op == "empty":
            if not isinstance(actual, list):
                return None
            return (len(actual) == 0) == expected
    except TypeError:
        return None
    return False


def _policy_eval_field_value(*, op: str, actual: Any, expected: Any, present: bool) -> Any:
    if not present:
        return None
    if op == "contains_any" and isinstance(actual, list) and isinstance(expected, list):
        expected_keys = _typed_scalar_set(expected)
        for item in actual:
            key = _typed_scalar_key(item)
            if key is not None and key in expected_keys:
                return item
        return None
    if op in {"contains_none", "empty"}:
        return None
    return actual if _is_scalar(actual) else None


def _normalize_condition(condition: Any) -> dict[str, Any]:
    if not isinstance(condition, dict):
        raise _UnsupportedPolicy("policy conditions must be objects")
    field = condition.get("field")
    if not isinstance(field, str) or not field:
        raise _UnsupportedPolicy("policy condition field must be a non-empty string")
    operator_keys = [key for key in condition if key in _OPERATORS]
    if set(condition) - {"field", *_OPERATORS}:
        raise _UnsupportedPolicy("policy condition has unsupported keys")
    if len(operator_keys) != 1 or len(condition) != 2:
        raise _UnsupportedPolicy("policy condition must contain field and exactly one operator")
    op = operator_keys[0]
    value = condition[op]
    if op == "exists":
        if not isinstance(value, bool):
            raise _UnsupportedPolicy("exists value must be boolean")
    elif op in {"in", "nin", "contains_any", "contains_none"}:
        if not isinstance(value, list) or not value or any(not _is_scalar(item) for item in value):
            raise _UnsupportedPolicy(f"{op} value must be a non-empty scalar list")
    elif op == "empty":
        if not isinstance(value, bool):
            raise _UnsupportedPolicy("empty value must be boolean")
    elif op in {"lt", "lte", "gt", "gte"}:
        if not _is_int(value):
            raise _UnsupportedPolicy(f"{op} value must be an integer")
    elif not _is_scalar(value):
        raise _UnsupportedPolicy("policy condition value must be a JSON scalar")
    return {"field": field, "op": op, "value": value}


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, bool)) or _is_int(value)


def _same_json_scalar_type(left: Any, right: Any) -> bool:
    return _is_scalar(left) and _is_scalar(right) and type(left) is type(right)


def _typed_scalar_key(value: Any) -> tuple[type, Any] | None:
    if not _is_scalar(value):
        return None
    return type(value), value


def _typed_scalar_set(values: list[Any]) -> set[tuple[type, Any]]:
    return {
        key
        for value in values
        if (key := _typed_scalar_key(value)) is not None
    }


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _json_equal(left: Any, right: Any) -> bool:
    """Compare JSON values without Python's ``True == 1`` coercion."""
    if type(left) is not type(right):
        return False
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(
            _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, list):
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right)
        )
    return left == right
