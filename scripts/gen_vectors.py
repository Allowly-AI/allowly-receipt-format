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
    "reason": "authorization_granted_scope_active",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "scope": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
    "policy_version": "2026-04-17.1",
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
    "scope": "files.delete",
    "resource": "gdrive:file:xyz",
    "context": {},
    "authorization_id": None,
    "policy_version": "2026-04-17.1",
})

unicode_resource = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZUNICODE00000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T15:30:00.000Z",
    "decision": "allow",
    "reason": "authorization_granted_scope_active",
    "user_id": "usuário_123",
    "agent_id": "agent_日本語",
    "scope": "email.send",
    "resource": "imap:folder:受信箱",
    "context": {"note": "Zürich → København"},
    "authorization_id": "auth_unicode",
    "policy_version": "2026-04-17.1",
})

rich_context = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZRICH00000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T16:00:00.000Z",
    "decision": "confirm",
    "reason": "scope_requires_user_confirmation",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "scope": "ats.export",
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
    "policy_version": "2026-04-17.1",
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
    "scope": "candidate.delete",
    "resource": "candidate:123",
    "context": {
        "escalation": {
            "id": "esc_01HXZESCALATION000000000",
            "event": "requested",
            "status": "pending",
            "scope": "candidate.delete",
            "escalation_to": "compliance",
        }
    },
    "authorization_id": "auth_escalate",
    "policy_version": "2026-04-17.1",
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
        "scopes": ["contact.enrich", "outreach.send"],
        "requires_confirm_for": ["outreach.send"],
        "expires_at": "2026-12-31T00:00:00Z",
        "source": "csv_upload_v2",
        "csv_hash": "sha256:abc123",
    },
    "authorization_id": "auth_01HXZ2A0K1L2M3N4P5Q6R7S8T9",
    "policy_version": "2026-04-17.1",
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
    "policy_version": "2026-04-17.1",
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
            "scope": "candidate.delete",
            "escalation_to": "compliance",
            "resolved_by": "compliance:1",
        }
    },
    "authorization_id": "auth_escalate",
    "policy_version": "2026-04-17.1",
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
    "scope": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_bad",
    "policy_version": "2026-04-17.1",
})

# Both scope and event present
both_fields = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZBOTH0000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:32:17.482Z",
    "decision": "allow",
    "reason": "bogus",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "scope": "outreach.send",
    "event": "authorization.create",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_bad",
    "policy_version": "2026-04-17.1",
})

# Neither scope nor event present
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
    "policy_version": "2026-04-17.1",
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
    "policy_version": "2026-04-17.1",
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
    "policy_version": "2026-04-17.1",
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
    "policy_version": "2026-04-17.1",
})

# Action receipt with authorization-lifecycle decision
scope_with_lifecycle_decision = sign({
    "version": "1.0",
    "receipt_id": "rcp_01HXZPAIR4000000000000000",
    "workspace_id": "ws_test",
    "issued_at": "2026-04-21T14:30:00.000Z",
    "decision": "authorization_granted",
    "reason": "bogus_pairing",
    "user_id": "emp_8821",
    "agent_id": "referral_outreach",
    "scope": "outreach.send",
    "resource": "edge:emp_8821:conn_9f2a",
    "context": {},
    "authorization_id": "auth_bad",
    "policy_version": "2026-04-17.1",
})

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
    "spec_version": "1.0.0-draft.3",
    "public_keys": keys_doc,
    "should_verify": [
        {"name": "action_minimal_allow", "kind": "action",
         "description": "minimal allow action receipt with scope field",
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
        {"name": "authorization_create", "kind": "authorization",
         "description": "authorization.create receipt with event field",
         "receipt": authorization_create},
        {"name": "authorization_revoke", "kind": "authorization",
         "description": "authorization.revoke receipt with event field",
         "receipt": authorization_revoke},
        {"name": "escalation_resolve_approved", "kind": "event",
         "description": "escalation.resolve receipt with approved decision and resource",
         "receipt": escalation_resolve_approved},
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
        {"name": "both_scope_and_event",
         "description": "both scope and event present",
         "expected_reason": "both 'scope' and 'event'",
         "receipt": both_fields},
        {"name": "neither_scope_nor_event",
         "description": "neither scope nor event present",
         "expected_reason": "neither 'scope' nor 'event'",
         "receipt": neither_field},
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
        {"name": "pairing_scope_with_lifecycle_decision",
         "description": "action receipt with decision=authorization_granted",
         "expected_reason": "requires an event receipt",
         "receipt": scope_with_lifecycle_decision},
    ],
}

out_path = Path(__file__).parent.parent / "test-vectors.json"
with open(out_path, "w") as f:
    json.dump(vectors, f, indent=2, ensure_ascii=False)

print(f"wrote {out_path}")
print(f"  should_verify: {len(vectors['should_verify'])}")
print(f"  should_reject: {len(vectors['should_reject'])}")
