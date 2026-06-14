"""
Generate test-vectors.json with real Ed25519 signatures.
Deterministic seed so vectors are reproducible across runs.
"""
from __future__ import annotations

import base64
import copy
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).parent.parent / "verifiers" / "python"))
from verifier import canonicalize  # noqa: E402


SEED = bytes(32)
KEY_ID = "test-key/v1"
WORKSPACE_ID = "ws_test"
DEFAULT_AUTHORIZATION_ID = "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9"
DEFAULT_ENGINE_VERSION = "2026-04-17.1"
_MISSING = object()

priv = Ed25519PrivateKey.from_private_bytes(SEED)
pub = priv.public_key()
pub_bytes = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def make_receipt(
    receipt_id: str,
    *,
    issued_at: str = "2026-04-21T14:32:17.482Z",
    decision: str = "allow",
    reason: str = "authorization_granted_action_active",
    user_id: str = "emp_8821",
    agent_id: str = "referral_outreach",
    action: str | None = "outreach.send",
    event: str | None = None,
    resource: str | None = "edge:emp_8821:conn_9f2a",
    context: dict[str, Any] | None = None,
    authorization_id: str | None = DEFAULT_AUTHORIZATION_ID,
    engine_version: str = DEFAULT_ENGINE_VERSION,
    policy_eval: Any = _MISSING,
) -> dict[str, Any]:
    receipt: dict[str, Any] = {
        "version": "1.0",
        "receipt_id": receipt_id,
        "workspace_id": WORKSPACE_ID,
        "issued_at": issued_at,
        "decision": decision,
        "reason": reason,
        "user_id": user_id,
        "agent_id": agent_id,
    }
    if action is not None:
        receipt["action"] = action
    if event is not None:
        receipt["event"] = event
    receipt.update({
        "resource": resource,
        "context": {} if context is None else context,
        "authorization_id": authorization_id,
        "engine_version": engine_version,
    })
    if policy_eval is not _MISSING:
        receipt["policy_eval"] = policy_eval
    return receipt


def sign(payload: dict[str, Any]) -> dict[str, Any]:
    canonical = canonicalize(payload)
    sig = priv.sign(canonical)
    return {
        **payload,
        "signature": {
            "alg": "Ed25519",
            "key_id": KEY_ID,
            "value": b64url(sig),
        },
    }


def signed_receipt(receipt_id: str, **overrides: Any) -> dict[str, Any]:
    return sign(make_receipt(receipt_id, **overrides))


def ok(name: str, kind: str, description: str, receipt: dict[str, Any]) -> dict[str, Any]:
    return {"name": name, "kind": kind, "description": description, "receipt": receipt}


def bad(
    name: str,
    description: str,
    expected_reason: str,
    receipt: dict[str, Any],
) -> dict[str, Any]:
    return {
        "name": name,
        "description": description,
        "expected_reason": expected_reason,
        "receipt": receipt,
    }


# --- Action receipts (should verify) ---

minimal_allow = signed_receipt("rcp_01HXZMINIMAL0000000000000")

deny_null_authorization = signed_receipt(
    "rcp_01HXZDENY0000000000000000",
    issued_at="2026-04-21T15:00:00.000Z",
    decision="deny",
    reason="no_matching_authorization",
    action="files.delete",
    resource="gdrive:file:xyz",
    authorization_id=None,
)

unicode_resource = signed_receipt(
    "rcp_01HXZUNICODE00000000000000",
    issued_at="2026-04-21T15:30:00.000Z",
    user_id="usuário_123",
    agent_id="agent_日本語",
    action="email.send",
    resource="imap:folder:受信箱",
    context={"note": "Zürich → København"},
    authorization_id="auth_unicode",
)

rich_context = signed_receipt(
    "rcp_01HXZRICH00000000000000000",
    issued_at="2026-04-21T16:00:00.000Z",
    decision="confirm",
    reason="action_requires_user_confirmation",
    action="ats.export",
    context={
        "z_last": "should sort last",
        "a_first": "should sort first",
        "nested": {"z": 1, "a": 2, "m": [3, 2, 1]},
        "empty_obj": {},
        "empty_arr": [],
        "boolean": True,
        "null_val": None,
    },
    authorization_id="auth_rich",
)

escalate_action = signed_receipt(
    "rcp_01HXZESCALATE000000000000",
    issued_at="2026-04-21T16:10:00.000Z",
    decision="escalate",
    reason="escalation_required",
    action="candidate.delete",
    resource="candidate:123",
    context={
        "escalation": {
            "id": "esc_01HXZESCALATION000000000",
            "event": "requested",
            "status": "pending",
            "action": "candidate.delete",
            "escalation_to": "compliance",
        }
    },
    authorization_id="auth_escalate",
)

confirm_condition_matched = signed_receipt(
    "rcp_01J0Z7Q4BORDERLINE0CONFIRM",
    issued_at="2026-06-09T17:04:09.114Z",
    decision="confirm",
    reason="confirm_condition_matched",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action="hiring.reject_application",
    resource="application:req_2207:cand_55ab2",
    context={
        "initiated_by": "agent",
        "score": 68,
        "threshold": 70,
        "score_delta": 2,
        "opt_out": False,
    },
    authorization_id="auth_conditional",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": {"field": "score_delta", "op": "lt", "value": 5},
        "field_value": 2,
    },
)

confirm_condition_in_matched = signed_receipt(
    "rcp_01J0Z7Q4INRULE00CONFIRM",
    issued_at="2026-06-09T17:04:39.114Z",
    decision="confirm",
    reason="condition_requires_user_confirmation",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action="hiring.reject_application",
    resource="application:req_2207:cand_55ab2",
    context={
        "initiated_by": "agent",
        "rule_fired": "employment_gap",
    },
    authorization_id="auth_conditional",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": {
            "field": "rule_fired",
            "op": "in",
            "value": ["employment_gap", "availability"],
        },
        "field_value": "employment_gap",
    },
)

allow_conditions_evaluated = signed_receipt(
    "rcp_01J0Z7Q4CONDITIONOKALLOW",
    issued_at="2026-06-09T17:05:09.114Z",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action="hiring.reject_application",
    resource="application:req_2207:cand_55ab2",
    context={
        "initiated_by": "agent",
        "score": 82,
        "threshold": 70,
        "score_delta": 12,
        "opt_out": False,
    },
    authorization_id="auth_conditional",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": None,
        "field_value": None,
    },
)

confirm_context_field_missing = signed_receipt(
    "rcp_01J0Z7Q4MISSING0CONFIRM",
    issued_at="2026-06-09T17:06:09.114Z",
    decision="confirm",
    reason="context_field_missing",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action="hiring.reject_application",
    resource="application:req_2207:cand_55ab2",
    context={
        "initiated_by": "agent",
        "threshold": 70,
    },
    authorization_id="auth_conditional",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": {"field": "score_delta", "op": "lt", "value": 5},
        "field_value": None,
    },
)

# --- Event receipts (should verify) ---

authorization_create = signed_receipt(
    "rcp_01HXZAUTHORIZATIONCREATE00000000",
    issued_at="2026-04-21T14:30:00.000Z",
    decision="authorization_granted",
    reason="user_approved_via_customer_ui",
    action=None,
    event="authorization.create",
    resource=None,
    context={
        "actions": ["contact.enrich", "outreach.send"],
        "requires_confirm_for": ["outreach.send"],
        "expires_at": "2026-12-31T00:00:00Z",
        "source": "csv_upload_v2",
        "csv_hash": "sha256:abc123",
    },
)

authorization_create_replaces = signed_receipt(
    "rcp_01J0Z7Q4AUTHREPLACES0000",
    issued_at="2026-06-09T17:00:00.000Z",
    decision="authorization_granted",
    reason="user_approved_via_customer_ui",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action=None,
    event="authorization.create",
    resource=None,
    context={
        "actions": [
            {
                "name": "hiring.reject_application",
                "constraints": {
                    "confirm_when": [
                        {"field": "score_delta", "lt": 5},
                        {"field": "opt_out", "eq": True},
                    ],
                    "escalate_when": [
                        {"field": "score", "exists": False},
                    ],
                },
            }
        ],
        "replaces": "auth_previous_conditional",
        "expires_at": "2026-12-31T00:00:00Z",
        "source": "customer_policy_upload",
    },
    authorization_id="auth_conditional",
    engine_version="2026-06-01.2",
)

authorization_revoke = signed_receipt(
    "rcp_01HXZAUTHORIZATIONREVOKE00000000",
    issued_at="2026-05-15T09:12:00.000Z",
    decision="authorization_revoked",
    reason="user_revoked_via_settings",
    action=None,
    event="authorization.revoke",
    resource=None,
    context={"revoked_by": "user"},
)

escalation_resolve_approved = signed_receipt(
    "rcp_01HXZESCRESOLVE0000000000",
    issued_at="2026-04-21T16:15:00.000Z",
    decision="escalation_approved",
    reason="escalation_resolved_by_approver",
    action=None,
    event="escalation.resolve",
    resource="candidate:123",
    context={
        "escalation": {
            "id": "esc_01HXZESCALATION000000000",
            "event": "resolved",
            "status": "approved",
            "action": "candidate.delete",
            "escalation_to": "compliance",
            "resolved_by": "compliance:1",
        }
    },
    authorization_id="auth_escalate",
)

# Control characters in a context string value: canonicalization rule 5 requires
# the lowercase backslash-uXXXX form for U+0000..U+001F, not short escapes. A
# verifier that emits short escapes produces different canonical bytes and fails.
control_chars_context = signed_receipt(
    "rcp_01HXZCONTROLCHARS00000000",
    issued_at="2026-04-21T16:20:00.000Z",
    action="notes.append",
    resource="note:42",
    context={"note": "line1\nline2\ttab\r\x00end"},
    authorization_id="auth_control",
)

# Supplementary-plane (non-BMP) key alongside a BMP key: canonicalization rule 3
# sorts by UTF-16 code unit, under which an emoji key (surrogate D83D...) sorts
# BEFORE U+FF61 ("｡"). Code-point sorting reverses these two, yielding different
# canonical bytes. The emoji also exercises a 4-byte UTF-8 sequence in a key.
non_bmp_key_context = signed_receipt(
    "rcp_01HXZNONBMPKEY0000000000",
    issued_at="2026-04-21T16:25:00.000Z",
    action="emoji.tag",
    resource="post:7",
    context={"\U0001f600_reaction": 1, "｡_marker": 2, "plain": "x"},
    authorization_id="auth_nonbmp",
)

# Revoke receipt with the bidirectional supersession lineage (§3.3): revoked_by
# "superseded" plus a superseded_by forward pointer to the successor authorization.
authorization_revoke_superseded = signed_receipt(
    "rcp_01HXZREVOKESUPERSEDED0000",
    issued_at="2026-05-15T09:12:00.000Z",
    decision="authorization_revoked",
    reason="superseded_by_new_authorization",
    action=None,
    event="authorization.revoke",
    resource=None,
    context={
        "revoked_by": "superseded",
        "superseded_by": "auth_conditional",
    },
)

# --- should_reject ---

tampered = copy.deepcopy(minimal_allow)
tampered["user_id"] = "emp_ATTACKER"

forged = copy.deepcopy(minimal_allow)
forged["signature"]["value"] = b64url(b"\x00" * 64)

unknown_key = copy.deepcopy(minimal_allow)
unknown_key["signature"]["key_id"] = "unknown-key/v99"

v2_receipt = copy.deepcopy(minimal_allow)
v2_receipt["version"] = "2.0"

unknown_field = copy.deepcopy(minimal_allow)
unknown_field["extra_field"] = "should_be_rejected"

missing_field = copy.deepcopy(minimal_allow)
del missing_field["authorization_id"]

bad_decision = signed_receipt(
    "rcp_01HXZBADDEC0000000000000",
    decision="maybe",
    reason="bogus",
    authorization_id="auth_bad",
)

# Both action and event present
both_fields = signed_receipt(
    "rcp_01HXZBOTH0000000000000000",
    reason="bogus",
    event="authorization.create",
    authorization_id="auth_bad",
)

# Neither action nor event present
neither_field = signed_receipt(
    "rcp_01HXZNEITHER000000000000",
    reason="bogus",
    action=None,
    authorization_id="auth_bad",
)

# event=authorization.create, decision=allow (wrong pairing)
event_wrong_decision = signed_receipt(
    "rcp_01HXZPAIR1000000000000000",
    issued_at="2026-04-21T14:30:00.000Z",
    reason="bogus_pairing",
    action=None,
    event="authorization.create",
    resource=None,
    authorization_id="auth_bad",
)

# event=authorization.revoke, authorization_id=null (wrong)
event_null_authorization = signed_receipt(
    "rcp_01HXZPAIR2000000000000000",
    issued_at="2026-04-21T14:30:00.000Z",
    decision="authorization_revoked",
    reason="bogus_pairing",
    action=None,
    event="authorization.revoke",
    resource=None,
    authorization_id=None,
)

# event=authorization.create, resource non-null (wrong)
event_with_resource = signed_receipt(
    "rcp_01HXZPAIR3000000000000000",
    issued_at="2026-04-21T14:30:00.000Z",
    decision="authorization_granted",
    reason="bogus_pairing",
    action=None,
    event="authorization.create",
    resource="should_be_null",
    authorization_id="auth_bad",
)

# Action receipt with authorization-lifecycle decision
action_with_lifecycle_decision = signed_receipt(
    "rcp_01HXZPAIR4000000000000000",
    issued_at="2026-04-21T14:30:00.000Z",
    decision="authorization_granted",
    reason="bogus_pairing",
    authorization_id="auth_bad",
)

authorization_update_event = signed_receipt(
    "rcp_01J0Z7Q4AUTHUPDATE00000",
    issued_at="2026-06-09T17:10:00.000Z",
    decision="authorization_updated",
    reason="removed_in_draft5",
    action=None,
    event="authorization.update",
    resource=None,
    authorization_id="auth_bad",
    engine_version="2026-06-01.2",
)

policy_eval_on_event = signed_receipt(
    "rcp_01J0Z7Q4POLICYEVENT000",
    issued_at="2026-06-09T17:11:00.000Z",
    decision="authorization_granted",
    reason="bad_policy_eval_on_event",
    action=None,
    event="authorization.create",
    resource=None,
    authorization_id="auth_bad",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": None,
        "field_value": None,
    },
)

policy_eval_missing_field_value = signed_receipt(
    "rcp_01J0Z7Q4POLICYMISS000",
    issued_at="2026-06-09T17:13:00.000Z",
    decision="confirm",
    reason="confirm_condition_matched",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action="hiring.reject_application",
    resource="application:req_2207:cand_55ab2",
    context={"score_delta": 2},
    authorization_id="auth_bad",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": {"field": "score_delta", "op": "lt", "value": 5},
    },
)

policy_eval_condition_missing_op = signed_receipt(
    "rcp_01J0Z7Q4POLICYNOOP000",
    issued_at="2026-06-09T17:14:00.000Z",
    decision="confirm",
    reason="confirm_condition_matched",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action="hiring.reject_application",
    resource="application:req_2207:cand_55ab2",
    context={"score_delta": 2},
    authorization_id="auth_bad",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": {"field": "score_delta", "value": 5},
        "field_value": 2,
    },
)

policy_eval_condition_extra_member = signed_receipt(
    "rcp_01J0Z7Q4POLICYCONDEX",
    issued_at="2026-06-09T17:15:00.000Z",
    decision="confirm",
    reason="confirm_condition_matched",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action="hiring.reject_application",
    resource="application:req_2207:cand_55ab2",
    context={"score_delta": 2},
    authorization_id="auth_bad",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": {
            "field": "score_delta",
            "op": "lt",
            "value": 5,
            "debug": True,
        },
        "field_value": 2,
    },
)

policy_eval_float_value = signed_receipt(
    "rcp_01J0Z7Q4POLICYFLOAT0",
    issued_at="2026-06-09T17:16:00.000Z",
    decision="confirm",
    reason="confirm_condition_matched",
    user_id="cand_55ab2",
    agent_id="scout_referrals",
    action="hiring.reject_application",
    resource="application:req_2207:cand_55ab2",
    context={"score_delta": 2},
    authorization_id="auth_bad",
    engine_version="2026-06-01.2",
    policy_eval={
        "matched_condition": {"field": "score_delta", "op": "lt", "value": 5},
        "field_value": 2,
    },
)
policy_eval_float_value["policy_eval"]["field_value"] = 2.5

# Integer outside the I-JSON safe range ±(2^53-1) in context. Signed clean with a
# placeholder, then the out-of-range value is injected: the verifier rejects it at
# canonicalization (rule 6), before signature verification.
integer_out_of_range = signed_receipt(
    "rcp_01HXZBIGINT00000000000000",
    context={"amount": 0},
    authorization_id="auth_bigint",
)
integer_out_of_range["context"]["amount"] = 2**53  # one past the safe range

# issued_at without a timezone offset. Not a full RFC 3339 instant; rejected at the
# timestamp step before signature verification.
timestamp_no_timezone = copy.deepcopy(minimal_allow)
timestamp_no_timezone["issued_at"] = "2026-04-21T14:32:17.482"

# signature.value carrying base64 padding (and thus a non-base64url character).
# Rejected on the schema-level signature shape check.
signature_padded = copy.deepcopy(minimal_allow)
signature_padded["signature"]["value"] = minimal_allow["signature"]["value"] + "=="

# --- Assemble ---

keys_doc = {
    "workspace_id": WORKSPACE_ID,
    "keys": [
        {
            "key_id": KEY_ID,
            "alg": "Ed25519",
            "public_key": b64url(pub_bytes),
            "active_from": "2026-01-01T00:00:00Z",
            "active_until": None,
        }
    ],
}

should_verify = [
    ("action_minimal_allow", "action", "minimal allow action receipt with action field", minimal_allow),
    ("action_deny_null_authorization", "action", "deny decision with null authorization_id", deny_null_authorization),
    ("action_unicode", "action", "non-ASCII characters in multiple fields", unicode_resource),
    ("action_rich_context", "action", "nested context exercising canonicalization", rich_context),
    ("action_escalate", "action", "escalate action receipt with escalation context", escalate_action),
    ("action_confirm_condition_matched", "action", "confirm action receipt with policy_eval matched_condition", confirm_condition_matched),
    ("action_confirm_condition_in_matched", "action", "confirm action receipt with policy_eval in-condition array value", confirm_condition_in_matched),
    ("action_allow_conditions_evaluated", "action", "allow action receipt with policy_eval attesting no condition matched", allow_conditions_evaluated),
    ("action_confirm_context_field_missing", "action", "confirm action receipt with fail-closed missing context field", confirm_context_field_missing),
    ("authorization_create", "authorization", "authorization.create receipt with event field", authorization_create),
    ("authorization_create_replaces", "authorization", "authorization.create receipt with replaces lineage and conditional constraints", authorization_create_replaces),
    ("authorization_revoke", "authorization", "authorization.revoke receipt with event field", authorization_revoke),
    ("authorization_revoke_superseded", "authorization", "authorization.revoke with revoked_by=superseded and superseded_by forward pointer", authorization_revoke_superseded),
    ("escalation_resolve_approved", "event", "escalation.resolve receipt with approved decision and resource", escalation_resolve_approved),
    ("action_control_chars_context", "action", "context string with control characters (tests \\uXXXX escaping, rule 5)", control_chars_context),
    ("action_non_bmp_context_key", "action", "context with a supplementary-plane key (tests UTF-16 key sort, rule 3)", non_bmp_key_context),
]

should_reject = [
    ("tampered_payload", "user_id modified after signing", "signature verification failed", tampered),
    ("forged_signature", "signature bytes replaced with zeros", "signature verification failed", forged),
    ("unknown_key_id", "key_id not in published keys", "no public key found", unknown_key),
    ("future_version", "version 2.0 receipt (v1 verifier rejects)", "unsupported version", v2_receipt),
    ("unknown_top_level_field", "extra field not in spec", "unknown top-level fields", unknown_field),
    ("missing_required_field", "authorization_id field missing", "missing top-level fields", missing_field),
    ("bad_decision_value", "decision is not allow/deny/confirm/escalate", "action receipt must have decision in", bad_decision),
    ("both_action_and_event", "both action and event present", "both 'action' and 'event'", both_fields),
    ("neither_action_nor_event", "neither action nor event present", "neither 'action' nor 'event'", neither_field),
    ("authorization_update_event_rejected", "authorization.update event was removed in draft.5", "event must be one of", authorization_update_event),
    ("pairing_event_create_wrong_decision", "event=authorization.create but decision=allow", "must have decision", event_wrong_decision),
    ("pairing_event_revoke_null_authorization", "event=authorization.revoke but authorization_id=null", "must have non-null authorization_id", event_null_authorization),
    ("pairing_event_with_resource", "event=authorization.create but resource is non-null", "must have null resource", event_with_resource),
    ("policy_eval_on_event_receipt", "event receipt carrying policy_eval", "policy_eval must be absent on event receipts", policy_eval_on_event),
    ("policy_eval_missing_field_value", "policy_eval missing required field_value", "policy_eval missing fields", policy_eval_missing_field_value),
    ("policy_eval_matched_condition_missing_op", "matched_condition missing required op", "policy_eval.matched_condition missing fields", policy_eval_condition_missing_op),
    ("policy_eval_matched_condition_extra_member", "matched_condition carrying an unknown member", "policy_eval.matched_condition has unknown fields", policy_eval_condition_extra_member),
    ("policy_eval_field_value_float", "policy_eval field_value uses a non-integer number", "policy_eval.field_value must be", policy_eval_float_value),
    ("integer_out_of_safe_range", "context integer exceeds the I-JSON safe range ±(2^53-1)", "safe range", integer_out_of_range),
    ("issued_at_no_timezone", "issued_at lacks a timezone offset (not a full RFC 3339 instant)", "RFC 3339 timestamp with timezone", timestamp_no_timezone),
    ("signature_value_padded", "signature.value carries base64 padding / non-base64url characters", "base64url", signature_padded),
    ("pairing_action_with_lifecycle_decision", "action receipt with decision=authorization_granted", "requires an event receipt", action_with_lifecycle_decision),
]

vectors = {
    "spec_version": "1.0.0",
    "public_keys": keys_doc,
    "should_verify": [ok(*row) for row in should_verify],
    "should_reject": [bad(*row) for row in should_reject],
}

out_path = Path(__file__).parent.parent / "test-vectors.json"
with open(out_path, "w") as f:
    json.dump(vectors, f, indent=2, ensure_ascii=False)

print(f"wrote {out_path}")
print(f"  should_verify: {len(vectors['should_verify'])}")
print(f"  should_reject: {len(vectors['should_reject'])}")
