"""Generate deterministic shared vectors for the Allowly policy replay profile."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verifiers" / "python" / "src"))

from allowly_receipt_format import canonicalize

PROFILE = "allowly-conditional-evaluation-v1"
ENGINE = "2026-09-16.1"
CURRENT_ENGINE = "2026-09-24.1"
SUPPORTED_ENGINES = [ENGINE, CURRENT_ENGINE]
WORKSPACE_ID = "ws_policy_replay_v1"
USER_ID = "user_policy_replay_v1"
AGENT_ID = "agent_policy_replay_v1"
ACTION = "records.review"
KEY_ID = "test-policy-replay-key-v1"
CREATE_TIME = "2026-09-16T12:00:00.000Z"
ACTION_TIME = "2026-09-16T12:01:00.000Z"
NOW = "2026-12-31T00:00:00.000Z"
RUNTIME_COMMIT = "1a7b36e2e83d0a8b57914d16bc297d8f8090eb13"

_PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(
    hashlib.sha256(b"allowly-policy-profile-v1-fixture-key").digest()
)
_PUBLIC_KEY_BYTES = _PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
_FINGERPRINT = "sha256:" + hashlib.sha256(_PUBLIC_KEY_BYTES).hexdigest()
_MISSING = object()


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _sign(payload: dict[str, Any]) -> dict[str, Any]:
    receipt = {**payload, "alg": "Ed25519", "key_id": KEY_ID}
    receipt["signature"] = _b64url(_PRIVATE_KEY.sign(canonicalize(receipt)))
    return receipt


def _create_receipt(
    index: str,
    constraints: dict[str, Any],
    *,
    authorization_id: str,
    action_entries: list[Any] | None = None,
    engine_version: str = ENGINE,
    issued_at: str = CREATE_TIME,
    workspace_id: str = WORKSPACE_ID,
    user_id: str = USER_ID,
    agent_id: str = AGENT_ID,
) -> dict[str, Any]:
    actions = action_entries if action_entries is not None else [
        {"name": ACTION, "constraints": constraints}
    ]
    return _sign(
        {
            "schema_version": "4",
            "receipt_id": f"rcp_policy_{index}_create",
            "workspace_id": workspace_id,
            "issued_at": issued_at,
            "decision": "authorization_granted",
            "reason": "authorization_creation_reported_by_client",
            "user_id": user_id,
            "agent_id": agent_id,
            "event": "authorization.create",
            "resource": None,
            "context": {
                "actions": actions,
                "requires_confirm_for": [],
                "requires_escalation_for": [],
                "requires_deny_for": [],
                "escalation_targets": {},
                "expires_at": "2027-09-16T12:00:00+00:00",
                "policy_id": "policy_replay_fixture",
            },
            "authorization_id": authorization_id,
            "engine_version": engine_version,
        }
    )


def _action_receipt(
    index: str,
    context: dict[str, Any],
    *,
    authorization_id: str | None,
    policy_eval: Any = _MISSING,
    engine_version: str = ENGINE,
    issued_at: str = ACTION_TIME,
    workspace_id: str = WORKSPACE_ID,
    user_id: str = USER_ID,
    agent_id: str = AGENT_ID,
    action: str = ACTION,
    decision: str = "allow",
    reason: str = "authorization_granted_action_active",
) -> dict[str, Any]:
    # These three fields are added after the runtime evaluator. A correct
    # replay removes them before evaluating the raw context above.
    signed_context = {
        **context,
        "session_id": "session_added_after_evaluation",
        "budget": {"limit_micros": 1000, "spent_before_micros": 100},
        "escalation": {"id": "esc_fixture", "event": "requested"},
    }
    if engine_version == CURRENT_ENGINE:
        signed_context.update(
            {
                "identity_verification": {
                    "status": "verified",
                    "kind": "auth0_m2m",
                    "binding_id": "bind_fixture",
                    "subject": "agent-client",
                },
                "client_timestamp": "2026-09-24T12:00:59.000Z",
                "client_timestamp_source": "customer_reported",
                "execution": {
                    "operation_id": "operation_fixture",
                    "destination_id": "destination_fixture",
                    "request_fingerprint_profile": "allowly.execution.request.v1",
                    "request_fingerprint": "sha256:" + "1" * 64,
                },
            }
        )
    payload: dict[str, Any] = {
        "schema_version": "4",
        "receipt_id": f"rcp_policy_{index}_action",
        "workspace_id": workspace_id,
        "issued_at": issued_at,
        "decision": decision,
        "reason": reason,
        "user_id": user_id,
        "agent_id": agent_id,
        "action": action,
        "resource": "record:fixture",
        "context": signed_context,
        "authorization_id": authorization_id,
        "engine_version": engine_version,
    }
    if policy_eval is not _MISSING:
        payload["policy_eval"] = policy_eval
    return _sign(payload)


def _normalized(field: str, op: str, value: Any) -> dict[str, Any]:
    return {"field": field, "op": op, "value": value}


def _expected(
    kind: str,
    reason: str,
    field: str | None = None,
    op: str | None = None,
    value: Any = None,
    field_value: Any = None,
) -> dict[str, Any]:
    matched = None if field is None else _normalized(field, str(op), value)
    return {
        "kind": kind,
        "reason": reason,
        "policy_eval": {
            "matched_condition": matched,
            "field_value": field_value,
        },
    }


def _case(
    name: str,
    description: str,
    constraints: dict[str, Any],
    context: dict[str, Any],
    expected: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "constraints": constraints,
        "context": context,
        "expected": expected,
    }


RUNTIME_CASES = [
    _case(
        "deny_eq_string",
        "eq matches equal strings.",
        {"deny_when": [{"field": "tier", "eq": "blocked"}]},
        {"tier": "blocked"},
        _expected("deny", "deny_condition_matched", "tier", "eq", "blocked", "blocked"),
    ),
    _case(
        "confirm_neq_boolean",
        "neq preserves the boolean type.",
        {"confirm_when": [{"field": "approved", "neq": False}]},
        {"approved": True},
        _expected("confirm", "confirm_condition_matched", "approved", "neq", False, True),
    ),
    _case(
        "confirm_lt_integer",
        "lt matches an integer below the threshold.",
        {"confirm_when": [{"field": "score", "lt": 10}]},
        {"score": 9},
        _expected("confirm", "confirm_condition_matched", "score", "lt", 10, 9),
    ),
    _case(
        "confirm_lte_boundary",
        "lte includes the exact integer boundary.",
        {"confirm_when": [{"field": "score", "lte": 10}]},
        {"score": 10},
        _expected("confirm", "confirm_condition_matched", "score", "lte", 10, 10),
    ),
    _case(
        "escalate_gt_integer",
        "gt matches an integer above the threshold.",
        {"escalate_when": [{"field": "score", "gt": 10}]},
        {"score": 11},
        _expected("escalate", "escalate_condition_matched", "score", "gt", 10, 11),
    ),
    _case(
        "escalate_gte_boundary",
        "gte includes the exact integer boundary.",
        {"escalate_when": [{"field": "score", "gte": 10}]},
        {"score": 10},
        _expected("escalate", "escalate_condition_matched", "score", "gte", 10, 10),
    ),
    _case(
        "confirm_in_typed_boolean",
        "in compares only members with the actual scalar type.",
        {"confirm_when": [{"field": "choice", "in": [1, True, "true"]}]},
        {"choice": True},
        _expected("confirm", "confirm_condition_matched", "choice", "in", [1, True, "true"], True),
    ),
    _case(
        "deny_nin_typed_string",
        "nin compares same-type members and matches an absent string.",
        {"deny_when": [{"field": "choice", "nin": ["a", "b", 1]}]},
        {"choice": "c"},
        _expected("deny", "deny_condition_matched", "choice", "nin", ["a", "b", 1], "c"),
    ),
    _case(
        "contains_any_first_input_match",
        "contains_any records the first typed match in input order.",
        {"confirm_when": [{"field": "values", "contains_any": [True, 1]}]},
        {"values": [1, True, "x"]},
        _expected("confirm", "confirm_condition_matched", "values", "contains_any", [True, 1], 1),
    ),
    _case(
        "contains_none_empty_input",
        "contains_none matches an empty input array and records null.",
        {"deny_when": [{"field": "values", "contains_none": ["blocked"]}]},
        {"values": []},
        _expected("deny", "deny_condition_matched", "values", "contains_none", ["blocked"], None),
    ),
    _case(
        "empty_true",
        "empty true matches an empty array.",
        {"confirm_when": [{"field": "values", "empty": True}]},
        {"values": []},
        _expected("confirm", "confirm_condition_matched", "values", "empty", True, None),
    ),
    _case(
        "empty_false",
        "empty false matches a non-empty array.",
        {"confirm_when": [{"field": "values", "empty": False}]},
        {"values": [None]},
        _expected("confirm", "confirm_condition_matched", "values", "empty", False, None),
    ),
    _case(
        "exists_present_null",
        "A present null member exists.",
        {"confirm_when": [{"field": "value", "exists": True}]},
        {"value": None},
        _expected("confirm", "confirm_condition_matched", "value", "exists", True, None),
    ),
    _case(
        "exists_absent_false",
        "exists false matches an absent member.",
        {"confirm_when": [{"field": "value", "exists": False}]},
        {},
        _expected("confirm", "confirm_condition_matched", "value", "exists", False, None),
    ),
    _case(
        "conditions_not_matched",
        "Supported conditions with comparable input can produce no match.",
        {"confirm_when": [{"field": "tier", "eq": "blocked"}]},
        {"tier": "allowed"},
        _expected("none", "policy_conditions_not_matched"),
    ),
    _case(
        "explicit_null_eq",
        "Explicit null is distinct from an absent field and can match eq null.",
        {"deny_when": [{"field": "value", "eq": None}]},
        {"value": None},
        _expected("deny", "deny_condition_matched", "value", "eq", None, None),
    ),
    _case(
        "absent_eq_is_missing",
        "An absent eq field produces the missing-field result.",
        {"confirm_when": [{"field": "value", "eq": None}]},
        {},
        _expected("confirm", "context_field_missing", "value", "eq", None, None),
    ),
    _case(
        "boolean_integer_uncomparable",
        "Boolean true is not comparable to integer 1.",
        {"confirm_when": [{"field": "value", "eq": 1}]},
        {"value": True},
        _expected("confirm", "context_field_missing", "value", "eq", 1, True),
    ),
    _case(
        "in_without_comparable_member",
        "in is uncomparable when the policy array has no same-type member.",
        {"confirm_when": [{"field": "value", "in": [1, 2]}]},
        {"value": "1"},
        _expected("confirm", "context_field_missing", "value", "in", [1, 2], "1"),
    ),
    _case(
        "contains_any_no_match",
        "Comparable arrays can produce a normal no-match result.",
        {"confirm_when": [{"field": "values", "contains_any": ["a"]}]},
        {"values": ["b"]},
        _expected("none", "policy_conditions_not_matched"),
    ),
    _case(
        "contains_none_typed_boolean_integer",
        "Typed sets keep boolean true distinct from integer 1.",
        {"deny_when": [{"field": "values", "contains_none": [True]}]},
        {"values": [1]},
        _expected("deny", "deny_condition_matched", "values", "contains_none", [True], None),
    ),
    _case(
        "deny_match_precedence",
        "A deny match wins before matching escalation and confirmation conditions.",
        {
            "deny_when": [{"field": "deny", "eq": 1}],
            "escalate_when": [{"field": "escalate", "eq": 1}],
            "confirm_when": [{"field": "confirm", "eq": 1}],
        },
        {"deny": 1, "escalate": 1, "confirm": 1},
        _expected("deny", "deny_condition_matched", "deny", "eq", 1, 1),
    ),
    _case(
        "deny_missing_then_later_deny_match",
        "A missing deny is deferred so a later deny match can win.",
        {"deny_when": [{"field": "missing", "eq": 1}, {"field": "deny", "eq": 1}]},
        {"deny": 1},
        _expected("deny", "deny_condition_matched", "deny", "eq", 1, 1),
    ),
    _case(
        "deny_missing_then_escalate_match",
        "A later escalation match wins over the deferred deny fallback.",
        {
            "deny_when": [{"field": "missing", "eq": 1}],
            "escalate_when": [{"field": "risk", "eq": 1}],
        },
        {"risk": 1},
        _expected("escalate", "escalate_condition_matched", "risk", "eq", 1, 1),
    ),
    _case(
        "deny_missing_then_escalate_missing",
        "An escalation missing result returns before the deny fallback.",
        {
            "deny_when": [{"field": "deny_missing", "eq": 1}],
            "escalate_when": [{"field": "escalate_missing", "eq": 1}],
        },
        {},
        _expected("escalate", "context_field_missing", "escalate_missing", "eq", 1, None),
    ),
    _case(
        "deny_missing_then_confirm_match",
        "A confirmation match wins over the deferred deny fallback.",
        {
            "deny_when": [{"field": "missing", "eq": 1}],
            "escalate_when": [{"field": "value", "eq": 0}],
            "confirm_when": [{"field": "value", "eq": 1}],
        },
        {"value": 1},
        _expected("confirm", "confirm_condition_matched", "value", "eq", 1, 1),
    ),
    _case(
        "deny_missing_then_confirm_missing",
        "A confirmation missing result returns before the deny fallback.",
        {
            "deny_when": [{"field": "deny_missing", "eq": 1}],
            "escalate_when": [{"field": "value", "eq": 0}],
            "confirm_when": [{"field": "confirm_missing", "eq": 1}],
        },
        {"value": 1},
        _expected("confirm", "context_field_missing", "confirm_missing", "eq", 1, None),
    ),
    _case(
        "deny_missing_fallback",
        "The remembered deny missing result becomes a confirm after later no-match lists.",
        {
            "deny_when": [{"field": "deny_missing", "eq": 1}],
            "escalate_when": [{"field": "value", "eq": 0}],
            "confirm_when": [{"field": "value", "eq": 0}],
        },
        {"value": 1},
        _expected("confirm", "context_field_missing", "deny_missing", "eq", 1, None),
    ),
    _case(
        "first_condition_wins",
        "The first matching condition in one list is recorded.",
        {
            "confirm_when": [
                {"field": "score", "gte": 1},
                {"field": "score", "gt": 0},
            ]
        },
        {"score": 2},
        _expected("confirm", "confirm_condition_matched", "score", "gte", 1, 2),
    ),
    _case(
        "reserved_receipt_fields_are_absent",
        "budget, escalation and session_id are absent from the historical evaluator input.",
        {
            "deny_when": [{"field": "session_id", "exists": True}],
            "escalate_when": [{"field": "escalation", "exists": True}],
            "confirm_when": [{"field": "budget", "exists": True}],
        },
        {},
        _expected("none", "policy_conditions_not_matched"),
    ),
    _case(
        "no_policy_conditions",
        "Non-conditional constraints produce no conditional evaluator result.",
        {"max_per_day": 3},
        {"value": 1},
        None,
    ),
]


def _public_result(
    receipt: dict[str, Any],
    *,
    authorization_receipt_id: str | None,
    status: str,
    diagnostic: str,
    recorded: dict[str, Any] | None,
    calculated: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "profile": PROFILE,
        "engine_version": receipt["engine_version"],
        "receipt_id": receipt["receipt_id"],
        "authorization_receipt_id": authorization_receipt_id,
        "status": status,
        "diagnostic": diagnostic,
        "recorded_evaluation": recorded,
        "calculated_evaluation": calculated,
    }


def _runtime_verification_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    for number, runtime_case in enumerate(RUNTIME_CASES, 1):
        index = f"runtime_{number:02d}"
        authorization_id = f"auth_policy_{number:02d}"
        create = _create_receipt(
            index,
            runtime_case["constraints"],
            authorization_id=authorization_id,
        )
        evaluator_result = runtime_case["expected"]
        recorded = (
            _MISSING if evaluator_result is None else evaluator_result["policy_eval"]
        )
        kind = None if evaluator_result is None else evaluator_result["kind"]
        decision = {
            "deny": "deny",
            "confirm": "confirm",
            "escalate": "escalate",
            "none": "allow",
            None: "allow",
        }[kind]
        reason = (
            "authorization_granted_action_active"
            if evaluator_result is None
            else evaluator_result["reason"]
        )
        action = _action_receipt(
            index,
            runtime_case["context"],
            authorization_id=authorization_id,
            policy_eval=recorded,
            decision=decision,
            reason=reason,
        )
        if evaluator_result is None:
            expected = _public_result(
                action,
                authorization_receipt_id=None,
                status="not_checked",
                diagnostic="policy_evaluation_not_recorded",
                recorded=None,
                calculated=None,
            )
        else:
            expected = _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="matched",
                diagnostic="matched",
                recorded=evaluator_result["policy_eval"],
                calculated=evaluator_result["policy_eval"],
            )
        cases.append(
            {
                "name": f"runtime_{runtime_case['name']}",
                "receipt": action,
                "authorization_receipts": [create],
                "expected": expected,
            }
        )
    return cases


def _special_verification_cases() -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    base_constraints = {
        "confirm_when": [
            {"field": "first", "eq": 1},
            {"field": "second", "eq": 1},
        ]
    }
    base_context = {"first": 1, "second": 1}
    calculated = {
        "matched_condition": _normalized("first", "eq", 1),
        "field_value": 1,
    }
    later = {
        "matched_condition": _normalized("second", "eq", 1),
        "field_value": 1,
    }

    for label, authorization_engine in (
        ("current", CURRENT_ENGINE),
        ("legacy_authorization", ENGINE),
    ):
        authorization_id = f"auth_policy_current_{label}"
        constraints = {"confirm_when": [{"field": "review", "eq": True}]}
        policy_eval = {
            "matched_condition": _normalized("review", "eq", True),
            "field_value": True,
        }
        create = _create_receipt(
            f"current_{label}",
            constraints,
            authorization_id=authorization_id,
            engine_version=authorization_engine,
        )
        action = _action_receipt(
            f"current_{label}",
            {"review": True},
            authorization_id=authorization_id,
            policy_eval=policy_eval,
            engine_version=CURRENT_ENGINE,
        )
        cases.append(
            {
                "name": f"current_engine_with_{label}_snapshot",
                "receipt": action,
                "authorization_receipts": [create],
                "expected": _public_result(
                    action,
                    authorization_receipt_id=create["receipt_id"],
                    status="matched",
                    diagnostic="matched",
                    recorded=policy_eval,
                    calculated=policy_eval,
                ),
            }
        )

    authorization_id = "auth_policy_mismatch"
    create = _create_receipt("mismatch", base_constraints, authorization_id=authorization_id)
    action = _action_receipt(
        "mismatch",
        base_context,
        authorization_id=authorization_id,
        policy_eval=later,
        decision="confirm",
        reason="confirm_condition_matched",
    )
    cases.append(
        {
            "name": "valid_signature_wrong_policy_eval",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="mismatch",
                diagnostic="policy_evaluation_mismatch",
                recorded=later,
                calculated=calculated,
            ),
        }
    )

    authorization_id = "auth_policy_final_decision"
    constraints = {"confirm_when": [{"field": "review", "eq": True}]}
    policy_eval = {
        "matched_condition": _normalized("review", "eq", True),
        "field_value": True,
    }
    create = _create_receipt("final_decision", constraints, authorization_id=authorization_id)
    action = _action_receipt(
        "final_decision",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
        decision="allow",
        reason="confirmation_already_approved",
    )
    cases.append(
        {
            "name": "matched_policy_with_different_state_dependent_final_decision",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="matched",
                diagnostic="matched",
                recorded=policy_eval,
                calculated=policy_eval,
            ),
        }
    )

    authorization_id = "auth_policy_not_recorded"
    constraints = {"confirm_when": [{"field": "review", "eq": True}]}
    create = _create_receipt("not_recorded", constraints, authorization_id=authorization_id)
    action = _action_receipt(
        "not_recorded", {"review": True}, authorization_id=authorization_id
    )
    cases.append(
        {
            "name": "policy_evaluation_not_recorded",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=None,
                status="not_checked",
                diagnostic="policy_evaluation_not_recorded",
                recorded=None,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_unknown_engine"
    create = _create_receipt("unknown_engine", constraints, authorization_id=authorization_id)
    action = _action_receipt(
        "unknown_engine",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
        engine_version="2026-09-99.1",
    )
    cases.append(
        {
            "name": "unsupported_action_engine",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=None,
                status="not_checked",
                diagnostic="unsupported_engine_version",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_missing_create"
    action = _action_receipt(
        "missing_create",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "authorization_receipt_not_found",
            "receipt": action,
            "authorization_receipts": [],
            "expected": _public_result(
                action,
                authorization_receipt_id=None,
                status="not_checked",
                diagnostic="authorization_receipt_not_found",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_duplicate"
    create = _create_receipt("duplicate", constraints, authorization_id=authorization_id)
    action = _action_receipt(
        "duplicate",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "exact_duplicate_creation_receipt_is_accepted",
            "receipt": action,
            "authorization_receipts": [create, copy.deepcopy(create)],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="matched",
                diagnostic="matched",
                recorded=policy_eval,
                calculated=policy_eval,
            ),
        }
    )

    authorization_id = "auth_policy_conflict"
    create_one = _create_receipt("conflict_one", constraints, authorization_id=authorization_id)
    create_two = _create_receipt("conflict_two", constraints, authorization_id=authorization_id)
    action = _action_receipt(
        "conflict",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "conflicting_creation_receipts",
            "receipt": action,
            "authorization_receipts": [create_one, create_two],
            "expected": _public_result(
                action,
                authorization_receipt_id=None,
                status="not_checked",
                diagnostic="conflicting_authorization_receipts",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_old_snapshot"
    create = _create_receipt(
        "old_snapshot",
        constraints,
        authorization_id=authorization_id,
        engine_version="2026-09-15.1",
    )
    action = _action_receipt(
        "old_snapshot",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "unsupported_authorization_engine",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="not_checked",
                diagnostic="unsupported_authorization_snapshot",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_future_snapshot"
    create = _create_receipt(
        "future_snapshot",
        constraints,
        authorization_id=authorization_id,
        issued_at="2026-09-16T12:02:00.000Z",
    )
    action = _action_receipt(
        "future_snapshot",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "authorization_snapshot_created_after_action",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="not_checked",
                diagnostic="unsupported_authorization_snapshot",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_subject_mismatch"
    create = _create_receipt(
        "subject_mismatch",
        constraints,
        authorization_id=authorization_id,
        user_id="different_user",
    )
    action = _action_receipt(
        "subject_mismatch",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "authorization_subject_mismatch",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="not_checked",
                diagnostic="authorization_subject_mismatch",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_action_missing"
    create = _create_receipt(
        "action_missing",
        constraints,
        authorization_id=authorization_id,
        action_entries=[{"name": "other.action", "constraints": constraints}],
    )
    action = _action_receipt(
        "action_missing",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "authorization_action_not_found",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="not_checked",
                diagnostic="authorization_action_not_found",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_action_ambiguous"
    create = _create_receipt(
        "action_ambiguous",
        constraints,
        authorization_id=authorization_id,
        action_entries=[
            {"name": ACTION, "constraints": constraints},
            {"name": ACTION, "constraints": constraints},
        ],
    )
    action = _action_receipt(
        "action_ambiguous",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "authorization_action_ambiguous",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="not_checked",
                diagnostic="authorization_action_ambiguous",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_unknown_operator"
    unsupported_constraints = {"confirm_when": [{"field": "review", "regex": "yes"}]}
    create = _create_receipt(
        "unknown_operator", unsupported_constraints, authorization_id=authorization_id
    )
    action = _action_receipt(
        "unknown_operator",
        {"review": "yes"},
        authorization_id=authorization_id,
        policy_eval={"matched_condition": None, "field_value": None},
    )
    cases.append(
        {
            "name": "unsupported_policy_operator",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="not_checked",
                diagnostic="unsupported_policy",
                recorded={"matched_condition": None, "field_value": None},
                calculated=None,
            ),
        }
    )

    authorization_id = "auth_policy_snapshot_shape"
    create = _create_receipt(
        "snapshot_shape",
        constraints,
        authorization_id=authorization_id,
        action_entries=[ACTION],
    )
    action = _action_receipt(
        "snapshot_shape",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "unsupported_authorization_action_shape",
            "receipt": action,
            "authorization_receipts": [create],
            "expected": _public_result(
                action,
                authorization_receipt_id=create["receipt_id"],
                status="not_checked",
                diagnostic="unsupported_authorization_snapshot",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )

    action = _action_receipt(
        "null_authorization",
        {"review": True},
        authorization_id=None,
        policy_eval=policy_eval,
    )
    cases.append(
        {
            "name": "null_authorization_id",
            "receipt": action,
            "authorization_receipts": [],
            "expected": _public_result(
                action,
                authorization_receipt_id=None,
                status="not_checked",
                diagnostic="authorization_receipt_not_found",
                recorded=policy_eval,
                calculated=None,
            ),
        }
    )
    return cases


def _tamper_signature(receipt: dict[str, Any]) -> dict[str, Any]:
    tampered = copy.deepcopy(receipt)
    raw = bytearray(base64.urlsafe_b64decode(tampered["signature"] + "=="))
    raw[0] ^= 1
    tampered["signature"] = _b64url(bytes(raw))
    return tampered


def _validation_error_cases() -> list[dict[str, Any]]:
    constraints = {"confirm_when": [{"field": "review", "eq": True}]}
    policy_eval = {
        "matched_condition": _normalized("review", "eq", True),
        "field_value": True,
    }
    authorization_id = "auth_policy_validation_error"
    create = _create_receipt("validation_error", constraints, authorization_id=authorization_id)
    action = _action_receipt(
        "validation_error",
        {"review": True},
        authorization_id=authorization_id,
        policy_eval=policy_eval,
    )
    wrong_workspace = _create_receipt(
        "wrong_workspace",
        constraints,
        authorization_id="auth_irrelevant",
        workspace_id="ws_wrong_workspace",
    )
    no_recorded = _action_receipt(
        "no_recorded_bad_candidate",
        {"review": True},
        authorization_id=authorization_id,
    )
    return [
        {
            "name": "invalid_action_signature",
            "receipt": _tamper_signature(action),
            "authorization_receipts": [create],
            "expected_error": "signature verification failed",
        },
        {
            "name": "invalid_irrelevant_candidate_signature",
            "receipt": action,
            "authorization_receipts": [_tamper_signature(create)],
            "expected_error": "signature verification failed",
        },
        {
            "name": "wrong_workspace_irrelevant_candidate",
            "receipt": action,
            "authorization_receipts": [create, wrong_workspace],
            "expected_error": "workspace_id mismatch",
        },
        {
            "name": "candidate_is_authenticated_before_missing_policy_result",
            "receipt": no_recorded,
            "authorization_receipts": [_tamper_signature(create)],
            "expected_error": "signature verification failed",
        },
        {
            "name": "primary_receipt_must_be_action",
            "receipt": create,
            "authorization_receipts": [],
            "expected_error": "requires an action receipt",
        },
    ]


def main() -> None:
    public_keys = {
        "workspace_id": WORKSPACE_ID,
        "keys": [
            {
                "key_id": KEY_ID,
                "alg": "Ed25519",
                "public_key": _b64url(_PUBLIC_KEY_BYTES),
                "public_key_fingerprint": _FINGERPRINT,
                "active_from": "2026-01-01T00:00:00.000Z",
                "active_until": None,
            }
        ],
    }
    document = {
        "profile": PROFILE,
        "supported_action_engine_versions": SUPPORTED_ENGINES,
        "supported_authorization_engine_versions": SUPPORTED_ENGINES,
        "runtime_source": {
            "repository": "allowly-api",
            "commit": RUNTIME_COMMIT,
            "path": "app/services/policy_conditions.py",
        },
        "verification_now": NOW,
        "expected_workspace_id": WORKSPACE_ID,
        "public_keys": public_keys,
        "trusted_key_fingerprints": [_FINGERPRINT],
        "runtime_cases": RUNTIME_CASES,
        "verification_cases": _runtime_verification_cases()
        + _special_verification_cases(),
        "validation_error_cases": _validation_error_cases(),
    }
    output = ROOT / "vectors" / "policy" / "profile-v1.json"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(output.relative_to(ROOT))


if __name__ == "__main__":
    main()
