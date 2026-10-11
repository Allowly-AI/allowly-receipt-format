"""Regenerate signed wire-5 OPA evidence vectors; fixture key, no policy interpreter."""
from __future__ import annotations

import base64
import argparse
import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verifiers/python/src"))
from allowly_receipt_format import canonicalize, jws_signing_input, jws_receipt

KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"allowly-opa-wire5-fixture").digest())
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
FP = "sha256:" + hashlib.sha256(PUB).hexdigest()
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--engine-manifest", type=Path, help="Exact manifest from the local runtime artifact builder")
args = parser.parse_args()
manifest_path = ROOT / "vectors/policy/engine-manifest.json"
if args.engine_manifest:
    manifest_path.write_bytes(args.engine_manifest.read_bytes())
MANIFEST = json.loads(manifest_path.read_text())


def digest(value):
    return hashlib.sha256(canonicalize(value)).hexdigest()


def sign(receipt):
    payload = {key: value for key, value in receipt.items() if key not in {"signature", "alg", "key_id"}}
    return {**payload, "key_id": "opa-fixture-key", "signature": base64.urlsafe_b64encode(KEY.sign(jws_signing_input(payload, "opa-fixture-key"))).decode().rstrip("=")}


def envelope(receipt):
    payload = {key: value for key, value in receipt.items() if key not in {"signature", "alg", "key_id"}}
    return jws_receipt(payload, "opa-fixture-key", receipt["signature"])


def case(name, decision, target, *, context=None, action_selected=False, final_decision=None, earlier_decision=None,
         policy_override=None, matched_rule_id="risk-rule"):
    context = {} if context is None else context
    policy = {"profile": "allowly.basic.v1", "action": "records.review",
        "decision": decision if action_selected else "allow", "target": target if action_selected else None,
        "fields": {"risk": "integer"}, "rules": [] if action_selected else [
            {"id": "risk-rule", "decision": decision, "target": target,
             "conditions": [{"field": "risk", "op": "gte", "value": 2}]}]}
    if earlier_decision:
        policy["rules"].insert(0, {"id": "earlier-weaker-rule", "decision": earlier_decision,
            "target": {"confirm": "agent_owner", "escalate": "member:earlier-reviewer"}.get(earlier_decision),
            "conditions": [{"field": "risk", "op": "gte", "value": 2}]})
    if policy_override is not None:
        policy = copy.deepcopy(policy_override)
    definition = {"profile": "allowly.policy.v1", "agent_id": "agent_fixture",
        "actions": [{"policy": policy, "guards": {}, "executable_operations": []}],
        "default_expiry_days": None}
    inner = {"policy": policy, "action": policy["action"], "context": context}
    selected = next((rule for rule in policy["rules"] if rule["id"] == matched_rule_id), None)
    result = {"profile": "allowly.basic.v1", "status": "ok", "decision": decision, "target": target,
        "matched_rule_id": None if action_selected else matched_rule_id,
        "evaluated_fields": {} if action_selected else {condition["field"]: context[condition["field"]]
            for condition in selected["conditions"] if condition["field"] in context}}
    receipt = sign({"schema_version": "5", "receipt_id": "rcp_" + name, "workspace_id": "ws_opa_fixture",
        "issued_at": "2026-10-09T12:00:00.000Z", "decision": final_decision or decision,
        "reason": "budget_exceeded" if final_decision else "policy_rule_matched",
        "user_id": "user_fixture", "agent_id": "agent_fixture", "action": policy["action"],
        "resource": None, "context": {"identity_verification": {"status": "verified"}},
        "authorization_id": "auth_fixture",
        "policy_ref": {"policy_id": "pol_fixture", "policy_version": 1, "definition_sha256": digest(definition)},
        "engine_version": "sha256:" + digest(MANIFEST),
        "policy_eval": {"input_sha256": digest(inner), "result": result},
        "alg": "Ed25519", "key_id": "opa-fixture-key"})
    return {"name": name, "receipt": receipt, "definition": definition, "input": inner}


cases = [
    case("action_allow", "allow", None, action_selected=True),
    case("rule_deny", "deny", None, context={"risk": 2}),
    case("rule_confirm", "confirm", "agent_owner", context={"risk": 2}),
    case("rule_escalate", "escalate", "member:reviewer", context={"risk": 2}),
    case("opa_allow_final_deny", "allow", None, action_selected=True, final_decision="deny"),
]
for weaker, stronger in [("confirm", "deny"), ("escalate", "deny"), ("confirm", "escalate"),
                         ("allow", "deny"), ("allow", "escalate"), ("allow", "confirm")]:
    cases.append(case(f"priority_{weaker}_then_{stronger}", stronger,
        {"confirm": "agent_owner", "escalate": "member:reviewer"}.get(stronger),
        context={"risk": 2}, earlier_decision=weaker))
# Exists evidence preserves missing versus explicit null, without reconstructing context.
for name, context, present in [("missing_exists", {}, False), ("null_exists", {"risk": None}, True)]:
    value = case(name, "confirm", "agent_owner", context=context)
    value["definition"]["actions"][0]["policy"]["rules"][0]["conditions"] = [
        {"field": "risk", "op": "exists", "value": present}]
    value["definition"]["actions"][0]["policy"]["fields"]["risk"] = "null"
    value["input"]["policy"] = copy.deepcopy(value["definition"]["actions"][0]["policy"])
    value["receipt"]["policy_ref"]["definition_sha256"] = digest(value["definition"])
    value["receipt"]["policy_eval"]["input_sha256"] = digest(value["input"])
    value["receipt"] = sign(value["receipt"])
    cases.append(value)

# Explicit expected outcomes, evaluated by stock OPA in the native replay suite.
# Lists retain their original types/order/duplicates in evidence and full input.
for name, op, operand, actual, matches in [
    ("list_any_bool_not_int", "contains_any", [True], [1], False),
    ("list_any_null", "contains_any", [None], [None, 1, True, "1", None], True),
    ("list_any_empty", "contains_any", [None], [], False),
    ("list_any_mixed_reordered", "contains_any", ["x", 1, True, None], [None, True, 1, "x", "x"], True),
    ("list_none_bool_not_int", "contains_none", [True], [1, "1"], True),
    ("list_none_null", "contains_none", [None], [False, None, None], False),
    ("list_none_empty", "contains_none", [None], [], True),
    ("list_none_duplicates", "contains_none", ["x", "x"], ["x", "x"], False),
    ("list_empty_true", "empty", True, [], True),
    ("list_empty_true_nonempty", "empty", True, [None], False),
    ("list_empty_false", "empty", False, ["x", 0, False, None], True),
    ("list_empty_false_empty", "empty", False, [], False),
]:
    policy = {"profile": "allowly.basic.v1", "action": "records.review",
        "decision": "allow", "target": None, "fields": {"items": "list"}, "rules": [
            {"id": "earlier-allow", "decision": "allow", "target": None,
             "conditions": [{"field": "items", "op": "exists", "value": True}]},
            {"id": "list-deny", "decision": "deny", "target": None,
             "conditions": [{"field": "items", "op": op, "value": operand}]}]}
    cases.append(case(name, "deny" if matches else "allow", None,
        context={"items": actual, "extra": {"retained": [False, 1, None]}}, policy_override=policy,
        matched_rule_id="list-deny" if matches else "earlier-allow"))

for first, second in [(True, False), (False, True), (True, True), (False, False)]:
    for reverse in [False, True]:
        conditions = [{"field": "first", "op": "eq", "value": True},
                      {"field": "second", "op": "eq", "value": True}]
        if reverse:
            conditions.reverse()
        policy = {"profile": "allowly.basic.v1", "action": "records.review",
            "decision": "allow", "target": None,
            "fields": {"first": "boolean", "second": "boolean"}, "rules": [
                {"id": "or-review", "decision": "confirm", "target": "agent_owner", "conditions": conditions}]}
        matched = first or second
        cases.append(case(f"or_{first}_{second}_{reverse}", "confirm" if matched else "allow",
            "agent_owner" if matched else None, action_selected=not matched,
            context={"first": first, "second": second, "extra": "complete input"},
            policy_override=policy, matched_rule_id="or-review"))

# Explicit action/rule outcomes distinguish action denial and the preserved
# conditional-first review ties. Full input is signed even when base evidence is empty.
priority = {"deny": 0, "escalate": 1, "confirm": 2, "allow": 3}
for action_decision in ["allow", "confirm", "escalate", "deny"]:
    action_target = {"confirm": "agent_owner", "escalate": "member:action-reviewer"}.get(action_decision)
    for rule_decision in ["allow", "confirm", "escalate", "deny"]:
        rule_target = {"confirm": "agent_owner", "escalate": "member:conditional-reviewer"}.get(rule_decision)
        policy = {"profile": "allowly.basic.v1", "action": "records.review",
            "decision": action_decision, "target": action_target,
            "fields": {"items": "list", "flag": "boolean"}, "rules": [
                {"id": "conditional", "decision": rule_decision, "target": rule_target, "conditions": [
                    {"field": "flag", "op": "eq", "value": True},
                    {"field": "items", "op": "contains_any", "value": [None, True, "x"]}]}]}
        rule_wins = action_decision != "deny" and priority[rule_decision] <= priority[action_decision]
        cases.append(case(f"action_{action_decision}_rule_{rule_decision}",
            rule_decision if rule_wins else action_decision, rule_target if rule_wins else action_target,
            action_selected=not rule_wins, policy_override=policy, matched_rule_id="conditional",
            context={"flag": False, "items": [1, None, True, "x", "x"], "extra": {"retained": [False, 1, None]}}))
    policy["rules"] = [{"id": "nonmatching", "decision": "deny", "target": None,
        "conditions": [{"field": "items", "op": "contains_any", "value": ["absent"]}]}]
    cases.append(case(f"action_{action_decision}_no_match", action_decision, action_target,
        action_selected=True, policy_override=policy, context={"items": [], "flag": False, "extra": "retained"}))

tampered = []
for field in ("policy_ref", "input_sha256", "result", "engine_version"):
    receipt = copy.deepcopy(cases[0]["receipt"])
    if field == "policy_ref":
        receipt[field]["policy_version"] = 2
    elif field == "input_sha256":
        receipt["policy_eval"][field] = "a" * 64
    elif field == "result":
        receipt["policy_eval"][field]["decision"] = "deny"
    else:
        receipt[field] = "sha256:" + "a" * 64
    tampered.append({"name": "tampered_" + field, "receipt": receipt})
document = {"profile": "allowly.basic.v1", "spec_version": "5", "verification_now": "2026-12-31T00:00:00.000Z",
    "expected_workspace_id": "ws_opa_fixture", "trusted_key_fingerprints": [FP],
    "public_keys": {"workspace_id": "ws_opa_fixture", "keys": [{"key_id": "opa-fixture-key", "alg": "Ed25519",
        "public_key": base64.urlsafe_b64encode(PUB).decode().rstrip("="), "public_key_fingerprint": FP,
        "active_from": "2026-01-01T00:00:00.000Z", "active_until": None}]},
    "signature_cases": cases, "tampered_cases": tampered}
output = ROOT / "vectors/policy/profile-v1.json"
for value in cases + tampered:
    value["receipt"] = envelope(value["receipt"])
output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
print(f"wrote {output}: {len(cases)} positive and {len(tampered)} tampered OPA evidence vectors")
