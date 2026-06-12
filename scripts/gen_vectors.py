"""
Generate test-vectors.json with real Ed25519 signatures.
Deterministic seed so vectors are reproducible across runs.
"""
import base64
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).parent.parent / "verifiers" / "python"))
from verifier import canonicalize  # noqa: E402


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


SEED = bytes(32)
priv = Ed25519PrivateKey.from_private_bytes(SEED)
pub = priv.public_key()
pub_bytes = pub.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
KEY_ID = "test-key/v1"


def sign(payload: dict) -> dict:
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


# --- Action receipts (should verify) ---

minimal_allow = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZMINIMAL0000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:32:17.482Z",
    "decision": "allow",
    "reason": "authorization_granted_action_active",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
    "engine_version": "2026-04-17.1",
})

deny_null_authorization = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZDENY0000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T15:00:00.000Z",
    "decision": "deny",
    "reason": "no_matching_authorization",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "files.delete",
    "resource": "gdrive:file:xyz",
    "context": {},
    "authorization_id": None,
    "engine_version": "2026-04-17.1",
})

unicode_resource = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZUNICODE00000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T15:30:00.000Z",
    "decision": "allow",
    "reason": "authorization_granted_action_active",
    "user_id": "usuário_123",
    "agent_id": "agent_日本語",
    "action": "email.send",
    "resource": "imap:folder:受信箱",
    "context": {"note": "Zürich → København"},
    "authorization_id": "auth_unicode",
    "engine_version": "2026-04-17.1",
})

rich_context = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZRICH00000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T16:00:00.000Z",
    "decision": "confirm",
    "reason": "action_requires_user_confirmation",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "ats.export",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {
        "z_last": "should sort last",
        "a_first": "should sort first",
        "nested": {"z": 1, "a": 2, "m": [3, 2, 1]},
        "empty_obj": {},
        "empty_arr": [],
        "boolean": True,
        "null_val": None,
    },
    "authorization_id": "auth_rich",
    "engine_version": "2026-04-17.1",
})

escalate_action = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZESCALATE000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T16:10:00.000Z",
    "decision": "escalate",
    "reason": "escalation_required",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "candidate.delete",
    "resource": "candidate:123",
    "context": {
        "escalation": {
            "id": "esc_01HXZESCALATION000000000",
            "event": "requested",
            "status": "pending",
            "action": "candidate.delete",
            "escalation_to": "compliance",
        }
    },
    "authorization_id": "auth_escalate",
    "engine_version": "2026-04-17.1",
})

confirm_condition_matched = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4BORDERLINE0CONFIRM",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:04:09.114Z",
    "decision": "confirm",
    "reason": "confirm_condition_matched",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "action": "hiring.reject_application",
    "resource": "application:req_2207:cand_55ab2",
    "context": {
        "initiated_by": "agent",
        "score": 68,
        "threshold": 70,
        "score_delta": 2,
        "opt_out": False,
    },
    "authorization_id": "auth_conditional",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": {"field": "score_delta", "op": "lt", "value": 5},
        "field_value": 2,
    },
})

confirm_condition_in_matched = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4INRULE00CONFIRM",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:04:39.114Z",
    "decision": "confirm",
    "reason": "condition_requires_user_confirmation",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "action": "hiring.reject_application",
    "resource": "application:req_2207:cand_55ab2",
    "context": {
        "initiated_by": "agent",
        "rule_fired": "employment_gap",
    },
    "authorization_id": "auth_conditional",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": {
            "field": "rule_fired",
            "op": "in",
            "value": ["employment_gap", "availability"],
        },
        "field_value": "employment_gap",
    },
})

allow_conditions_evaluated = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4CONDITIONOKALLOW",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:05:09.114Z",
    "decision": "allow",
    "reason": "authorization_granted_action_active",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "action": "hiring.reject_application",
    "resource": "application:req_2207:cand_55ab2",
    "context": {
        "initiated_by": "agent",
        "score": 82,
        "threshold": 70,
        "score_delta": 12,
        "opt_out": False,
    },
    "authorization_id": "auth_conditional",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": None,
        "field_value": None,
    },
})

confirm_context_field_missing = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4MISSING0CONFIRM",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:06:09.114Z",
    "decision": "confirm",
    "reason": "context_field_missing",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "action": "hiring.reject_application",
    "resource": "application:req_2207:cand_55ab2",
    "context": {
        "initiated_by": "agent",
        "threshold": 70,
    },
    "authorization_id": "auth_conditional",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": {"field": "score_delta", "op": "lt", "value": 5},
        "field_value": None,
    },
})

# --- Event receipts (should verify) ---

authorization_create = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZAUTHORIZATIONCREATE00000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:30:00.000Z",
    "decision": "authorization_granted",
    "reason": "user_approved_via_customer_ui",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "authorization.create",
    "resource": None,
    "context": {
        "actions": ["contact.enrich", "outreach.send"],
        "requires_confirm_for": ["outreach.send"],
        "expires_at": "2026-12-31T00:00:00Z",
        "source": "csv_upload_v2",
        "csv_hash": "sha256:abc123",
    },
    "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
    "engine_version": "2026-04-17.1",
})

authorization_create_replaces = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4AUTHREPLACES0000",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:00:00.000Z",
    "decision": "authorization_granted",
    "reason": "user_approved_via_customer_ui",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "event": "authorization.create",
    "resource": None,
    "context": {
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
    "authorization_id": "auth_conditional",
    "engine_version": "2026-06-01.2",
})

authorization_revoke = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZAUTHORIZATIONREVOKE00000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-05-15T09:12:00.000Z",
    "decision": "authorization_revoked",
    "reason": "user_revoked_via_settings",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "authorization.revoke",
    "resource": None,
    "context": {"revoked_by": "user"},
    "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
    "engine_version": "2026-04-17.1",
})

escalation_resolve_approved = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZESCRESOLVE0000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T16:15:00.000Z",
    "decision": "escalation_approved",
    "reason": "escalation_resolved_by_approver",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "escalation.resolve",
    "resource": "candidate:123",
    "context": {
        "escalation": {
            "id": "esc_01HXZESCALATION000000000",
            "event": "resolved",
            "status": "approved",
            "action": "candidate.delete",
            "escalation_to": "compliance",
            "resolved_by": "compliance:1",
        }
    },
    "authorization_id": "auth_escalate",
    "engine_version": "2026-04-17.1",
})

# Control characters in a context string value: canonicalization rule 5 requires
# the lowercase backslash-uXXXX form for U+0000..U+001F, not short escapes. A
# verifier that emits short escapes produces different canonical bytes and fails.
control_chars_context = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZCONTROLCHARS00000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T16:20:00.000Z",
    "decision": "allow",
    "reason": "authorization_granted_action_active",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "notes.append",
    "resource": "note:42",
    "context": {"note": "line1\nline2\ttab\r\x00end"},
    "authorization_id": "auth_control",
    "engine_version": "2026-04-17.1",
})

# Supplementary-plane (non-BMP) key alongside a BMP key: canonicalization rule 3
# sorts by UTF-16 code unit, under which an emoji key (surrogate D83D...) sorts
# BEFORE U+FF61 ("｡"). Code-point sorting reverses these two, yielding different
# canonical bytes. The emoji also exercises a 4-byte UTF-8 sequence in a key.
non_bmp_key_context = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZNONBMPKEY0000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T16:25:00.000Z",
    "decision": "allow",
    "reason": "authorization_granted_action_active",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "emoji.tag",
    "resource": "post:7",
    "context": {"\U0001f600_reaction": 1, "｡_marker": 2, "plain": "x"},
    "authorization_id": "auth_nonbmp",
    "engine_version": "2026-04-17.1",
})

# Revoke receipt with the bidirectional supersession lineage (§3.3): revoked_by
# "superseded" plus a superseded_by forward pointer to the successor authorization.
authorization_revoke_superseded = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZREVOKESUPERSEDED0000",
    "workspace_id": "ws_test",
    "issued_at": "2026-05-15T09:12:00.000Z",
    "decision": "authorization_revoked",
    "reason": "superseded_by_new_authorization",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "authorization.revoke",
    "resource": None,
    "context": {
        "revoked_by": "superseded",
        "superseded_by": "auth_conditional",
    },
    "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
    "engine_version": "2026-04-17.1",
})

# --- should_reject ---

tampered = json.loads(json.dumps(minimal_allow))
tampered["user_id"] = "emp_ATTACKER"

forged = json.loads(json.dumps(minimal_allow))
forged["signature"]["value"] = b64url(b"\x00" * 64)

unknown_key = json.loads(json.dumps(minimal_allow))
unknown_key["signature"]["key_id"] = "unknown-key/v99"

v2_receipt = json.loads(json.dumps(minimal_allow))
v2_receipt["version"] = "2.0"

unknown_field = json.loads(json.dumps(minimal_allow))
unknown_field["extra_field"] = "should_be_rejected"

missing_field = json.loads(json.dumps(minimal_allow))
del missing_field["authorization_id"]

bad_decision = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZBADDEC0000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:32:17.482Z",
    "decision": "maybe",
    "reason": "bogus",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_bad",
    "engine_version": "2026-04-17.1",
})

# Both action and event present
both_fields = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZBOTH0000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:32:17.482Z",
    "decision": "allow",
    "reason": "bogus",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "outreach.send",
    "event": "authorization.create",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_bad",
    "engine_version": "2026-04-17.1",
})

# Neither action nor event present
neither_field = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZNEITHER000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:32:17.482Z",
    "decision": "allow",
    "reason": "bogus",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_bad",
    "engine_version": "2026-04-17.1",
})

# event=authorization.create, decision=allow (wrong pairing)
event_wrong_decision = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZPAIR1000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:30:00.000Z",
    "decision": "allow",
    "reason": "bogus_pairing",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "authorization.create",
    "resource": None,
    "context": {},
    "authorization_id": "auth_bad",
    "engine_version": "2026-04-17.1",
})

# event=authorization.revoke, authorization_id=null (wrong)
event_null_authorization = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZPAIR2000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:30:00.000Z",
    "decision": "authorization_revoked",
    "reason": "bogus_pairing",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "authorization.revoke",
    "resource": None,
    "context": {},
    "authorization_id": None,
    "engine_version": "2026-04-17.1",
})

# event=authorization.create, resource non-null (wrong)
event_with_resource = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZPAIR3000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:30:00.000Z",
    "decision": "authorization_granted",
    "reason": "bogus_pairing",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "authorization.create",
    "resource": "should_be_null",
    "context": {},
    "authorization_id": "auth_bad",
    "engine_version": "2026-04-17.1",
})

# Action receipt with authorization-lifecycle decision
action_with_lifecycle_decision = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZPAIR4000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:30:00.000Z",
    "decision": "authorization_granted",
    "reason": "bogus_pairing",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_bad",
    "engine_version": "2026-04-17.1",
})

authorization_update_event = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4AUTHUPDATE00000",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:10:00.000Z",
    "decision": "authorization_updated",
    "reason": "removed_in_draft5",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "authorization.update",
    "resource": None,
    "context": {},
    "authorization_id": "auth_bad",
    "engine_version": "2026-06-01.2",
})

policy_eval_on_event = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4POLICYEVENT000",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:11:00.000Z",
    "decision": "authorization_granted",
    "reason": "bad_policy_eval_on_event",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "event": "authorization.create",
    "resource": None,
    "context": {},
    "authorization_id": "auth_bad",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": None,
        "field_value": None,
    },
})


policy_eval_missing_field_value = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4POLICYMISS000",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:13:00.000Z",
    "decision": "confirm",
    "reason": "confirm_condition_matched",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "action": "hiring.reject_application",
    "resource": "application:req_2207:cand_55ab2",
    "context": {"score_delta": 2},
    "authorization_id": "auth_bad",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": {"field": "score_delta", "op": "lt", "value": 5},
    },
})

policy_eval_condition_missing_op = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4POLICYNOOP000",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:14:00.000Z",
    "decision": "confirm",
    "reason": "confirm_condition_matched",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "action": "hiring.reject_application",
    "resource": "application:req_2207:cand_55ab2",
    "context": {"score_delta": 2},
    "authorization_id": "auth_bad",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": {"field": "score_delta", "value": 5},
        "field_value": 2,
    },
})

policy_eval_condition_extra_member = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4POLICYCONDEX",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:15:00.000Z",
    "decision": "confirm",
    "reason": "confirm_condition_matched",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "action": "hiring.reject_application",
    "resource": "application:req_2207:cand_55ab2",
    "context": {"score_delta": 2},
    "authorization_id": "auth_bad",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": {
            "field": "score_delta",
            "op": "lt",
            "value": 5,
            "debug": True,
        },
        "field_value": 2,
    },
})

policy_eval_float_value = sign({
    "version": "1.0",
    "receipt_id": "rcp_01J0Z7Q4POLICYFLOAT0",
    "workspace_id": "ws_test",
    "issued_at": "2026-06-09T17:16:00.000Z",
    "decision": "confirm",
    "reason": "confirm_condition_matched",
    "user_id": "cand_55ab2",
    "agent_id": "scout_referrals",
    "action": "hiring.reject_application",
    "resource": "application:req_2207:cand_55ab2",
    "context": {"score_delta": 2},
    "authorization_id": "auth_bad",
    "engine_version": "2026-06-01.2",
    "policy_eval": {
        "matched_condition": {"field": "score_delta", "op": "lt", "value": 5},
        "field_value": 2,
    },
})
policy_eval_float_value["policy_eval"]["field_value"] = 2.5

# Integer outside the I-JSON safe range ±(2^53-1) in context. Signed clean with a
# placeholder, then the out-of-range value is injected: the verifier rejects it at
# canonicalization (rule 6), before signature verification.
integer_out_of_range = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZBIGINT00000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:32:17.482Z",
    "decision": "allow",
    "reason": "authorization_granted_action_active",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "action": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {"amount": 0},
    "authorization_id": "auth_bigint",
    "engine_version": "2026-04-17.1",
})
integer_out_of_range["context"]["amount"] = 2**53  # one past the safe range

# issued_at without a timezone offset. Not a full RFC 3339 instant; rejected at the
# timestamp step before signature verification.
timestamp_no_timezone = json.loads(json.dumps(minimal_allow))
timestamp_no_timezone["issued_at"] = "2026-04-21T14:32:17.482"

# signature.value carrying base64 padding (and thus a non-base64url character).
# Rejected on the schema-level signature shape check.
signature_padded = json.loads(json.dumps(minimal_allow))
signature_padded["signature"]["value"] = minimal_allow["signature"]["value"] + "=="

# --- Assemble ---

keys_doc = {
    "workspace_id": "ws_test",
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

vectors = {
    "spec_version": "1.0.0-draft.6",
    "public_keys": keys_doc,
    "should_verify": [
        {"name": "action_minimal_allow", "kind": "action",
         "description": "minimal allow action receipt with action field",
         "receipt": minimal_allow},
        {"name": "action_deny_null_authorization", "kind": "action",
         "description": "deny decision with null authorization_id",
         "receipt": deny_null_authorization},
        {"name": "action_unicode", "kind": "action",
         "description": "non-ASCII characters in multiple fields",
         "receipt": unicode_resource},
        {"name": "action_rich_context", "kind": "action",
         "description": "nested context exercising canonicalization",
         "receipt": rich_context},
        {"name": "action_escalate", "kind": "action",
         "description": "escalate action receipt with escalation context",
         "receipt": escalate_action},
        {"name": "action_confirm_condition_matched", "kind": "action",
         "description": "confirm action receipt with policy_eval matched_condition",
         "receipt": confirm_condition_matched},
        {"name": "action_confirm_condition_in_matched", "kind": "action",
         "description": "confirm action receipt with policy_eval in-condition array value",
         "receipt": confirm_condition_in_matched},
        {"name": "action_allow_conditions_evaluated", "kind": "action",
         "description": "allow action receipt with policy_eval attesting no condition matched",
         "receipt": allow_conditions_evaluated},
        {"name": "action_confirm_context_field_missing", "kind": "action",
         "description": "confirm action receipt with fail-closed missing context field",
         "receipt": confirm_context_field_missing},
        {"name": "authorization_create", "kind": "authorization",
         "description": "authorization.create receipt with event field",
         "receipt": authorization_create},
        {"name": "authorization_create_replaces", "kind": "authorization",
         "description": "authorization.create receipt with replaces lineage and conditional constraints",
         "receipt": authorization_create_replaces},
        {"name": "authorization_revoke", "kind": "authorization",
         "description": "authorization.revoke receipt with event field",
         "receipt": authorization_revoke},
        {"name": "authorization_revoke_superseded", "kind": "authorization",
         "description": "authorization.revoke with revoked_by=superseded and superseded_by forward pointer",
         "receipt": authorization_revoke_superseded},
        {"name": "escalation_resolve_approved", "kind": "event",
         "description": "escalation.resolve receipt with approved decision and resource",
         "receipt": escalation_resolve_approved},
        {"name": "action_control_chars_context", "kind": "action",
         "description": "context string with control characters (tests \\uXXXX escaping, rule 5)",
         "receipt": control_chars_context},
        {"name": "action_non_bmp_context_key", "kind": "action",
         "description": "context with a supplementary-plane key (tests UTF-16 key sort, rule 3)",
         "receipt": non_bmp_key_context},
    ],
    "should_reject": [
        {"name": "tampered_payload",
         "description": "user_id modified after signing",
         "expected_reason": "signature verification failed",
         "receipt": tampered},
        {"name": "forged_signature",
         "description": "signature bytes replaced with zeros",
         "expected_reason": "signature verification failed",
         "receipt": forged},
        {"name": "unknown_key_id",
         "description": "key_id not in published keys",
         "expected_reason": "no public key found",
         "receipt": unknown_key},
        {"name": "future_version",
         "description": "version 2.0 receipt (v1 verifier rejects)",
         "expected_reason": "unsupported version",
         "receipt": v2_receipt},
        {"name": "unknown_top_level_field",
         "description": "extra field not in spec",
         "expected_reason": "unknown top-level fields",
         "receipt": unknown_field},
        {"name": "missing_required_field",
         "description": "authorization_id field missing",
         "expected_reason": "missing top-level fields",
         "receipt": missing_field},
        {"name": "bad_decision_value",
         "description": "decision is not allow/deny/confirm/escalate",
         "expected_reason": "action receipt must have decision in",
         "receipt": bad_decision},
        {"name": "both_action_and_event",
         "description": "both action and event present",
         "expected_reason": "both 'action' and 'event'",
         "receipt": both_fields},
        {"name": "neither_action_nor_event",
         "description": "neither action nor event present",
         "expected_reason": "neither 'action' nor 'event'",
         "receipt": neither_field},
        {"name": "authorization_update_event_rejected",
         "description": "authorization.update event was removed in draft.5",
         "expected_reason": "event must be one of",
         "receipt": authorization_update_event},
        {"name": "pairing_event_create_wrong_decision",
         "description": "event=authorization.create but decision=allow",
         "expected_reason": "must have decision",
         "receipt": event_wrong_decision},
        {"name": "pairing_event_revoke_null_authorization",
         "description": "event=authorization.revoke but authorization_id=null",
         "expected_reason": "must have non-null authorization_id",
         "receipt": event_null_authorization},
        {"name": "pairing_event_with_resource",
         "description": "event=authorization.create but resource is non-null",
         "expected_reason": "must have null resource",
         "receipt": event_with_resource},
        {"name": "policy_eval_on_event_receipt",
         "description": "event receipt carrying policy_eval",
         "expected_reason": "policy_eval must be absent on event receipts",
         "receipt": policy_eval_on_event},
        {"name": "policy_eval_missing_field_value",
         "description": "policy_eval missing required field_value",
         "expected_reason": "policy_eval missing fields",
         "receipt": policy_eval_missing_field_value},
        {"name": "policy_eval_matched_condition_missing_op",
         "description": "matched_condition missing required op",
         "expected_reason": "policy_eval.matched_condition missing fields",
         "receipt": policy_eval_condition_missing_op},
        {"name": "policy_eval_matched_condition_extra_member",
         "description": "matched_condition carrying an unknown member",
         "expected_reason": "policy_eval.matched_condition has unknown fields",
         "receipt": policy_eval_condition_extra_member},
        {"name": "policy_eval_field_value_float",
         "description": "policy_eval field_value uses a non-integer number",
         "expected_reason": "policy_eval.field_value must be",
         "receipt": policy_eval_float_value},
        {"name": "integer_out_of_safe_range",
         "description": "context integer exceeds the I-JSON safe range ±(2^53-1)",
         "expected_reason": "safe range",
         "receipt": integer_out_of_range},
        {"name": "issued_at_no_timezone",
         "description": "issued_at lacks a timezone offset (not a full RFC 3339 instant)",
         "expected_reason": "RFC 3339 timestamp with timezone",
         "receipt": timestamp_no_timezone},
        {"name": "signature_value_padded",
         "description": "signature.value carries base64 padding / non-base64url characters",
         "expected_reason": "base64url",
         "receipt": signature_padded},
        {"name": "pairing_action_with_lifecycle_decision",
         "description": "action receipt with decision=authorization_granted",
         "expected_reason": "requires an event receipt",
         "receipt": action_with_lifecycle_decision},
    ],
}

out_path = Path(__file__).parent.parent / "test-vectors.json"
with open(out_path, "w") as f:
    json.dump(vectors, f, indent=2, ensure_ascii=False)

print(f"wrote {out_path}")
print(f"  should_verify: {len(vectors['should_verify'])}")
print(f"  should_reject: {len(vectors['should_reject'])}")
