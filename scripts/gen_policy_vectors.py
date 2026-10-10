"""Regenerate signed wire-5 OPA evidence vectors; fixture key, no policy interpreter."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "verifiers/python/src"))
from allowly_receipt_format import canonicalize

KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"allowly-opa-wire5-fixture").digest())
PUB = KEY.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
FP = "sha256:" + hashlib.sha256(PUB).hexdigest()
MANIFEST = json.loads((ROOT / "vectors/policy/engine-manifest.json").read_text())


def digest(value):
    return hashlib.sha256(canonicalize(value)).hexdigest()


def sign(receipt):
    payload = {key: value for key, value in receipt.items() if key != "signature"}
    return {**payload, "signature": base64.urlsafe_b64encode(KEY.sign(canonicalize(payload))).decode().rstrip("=")}


def case(name, decision, target, *, context=None, default=False, final_decision=None):
    context = {} if context is None else context
    policy = {"profile": "allowly.basic.v1", "action": "records.review",
        "default_decision": decision if default else "deny", "default_target": target if default else None,
        "fields": {"risk": "integer"}, "rules": [] if default else [
            {"id": "risk-rule", "decision": decision, "target": target,
             "conditions": [{"field": "risk", "op": "gte", "value": 2}]}]}
    definition = {"profile": "allowly.policy.v1", "agent_id": "agent_fixture",
        "actions": [{"policy": policy, "guards": {}, "executable_operations": []}],
        "default_expiry_days": None}
    inner = {"policy": policy, "action": policy["action"], "context": context}
    result = {"profile": "allowly.basic.v1", "status": "ok", "decision": decision, "target": target,
        "matched_rule_id": None if default else "risk-rule", "evaluated_fields": {} if default else context}
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
    case("default_allow", "allow", None, default=True),
    case("rule_deny", "deny", None, context={"risk": 2}),
    case("rule_confirm", "confirm", "agent_owner", context={"risk": 2}),
    case("rule_escalate", "escalate", "member:reviewer", context={"risk": 2}),
    case("opa_allow_final_deny", "allow", None, default=True, final_decision="deny"),
]
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
output.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
print(f"wrote {output}: {len(cases)} positive and {len(tampered)} tampered OPA evidence vectors")
