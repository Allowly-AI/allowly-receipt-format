"""Source-distributed Observe assessment verifier; not a wire-5 receipt parser."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from allowly_receipt_format import canonicalize, load_keys_from_json, public_key_fingerprint
from allowly_receipt_format.evidence import evidence_context, validate_policy_definition
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIELDS = set("schema_version assessment_id workspace_id job_id project_id agent_id action issued_at policy_ref mapping_version mapping_sha256 reviewer_version engine_version source source_sha256 request_sha256 facts missing_information context policy_eval assessment_status application_reported_execution mode intervention".split())
HEX = re.compile(r"[0-9a-f]{64}\Z")
STAMP = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\Z")


class AssessmentError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise AssessmentError(message)


def exact(value, fields):
    require(type(value) is dict and set(value) == set(fields), "unexpected assessment fields")


def timestamp(value):
    require(type(value) is str and STAMP.fullmatch(value) is not None, "invalid timestamp")
    require(int(value[11:13]) < 24, "invalid timestamp")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AssessmentError("invalid timestamp") from exc


def b64(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]+", value) is not None, "invalid base64url")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    require(base64.urlsafe_b64encode(raw).decode().rstrip("=") == value, "noncanonical base64url")
    return raw


def encoded_json(value):
    raw = b64(value)
    try:
        parsed = json.loads(raw)
        require(canonicalize(parsed) == raw, "noncanonical or duplicate JSON")
        return parsed
    except (ValueError, TypeError, RecursionError) as exc:
        raise AssessmentError("invalid canonical assessment JSON") from exc


def validate_payload(payload, source, definition, mapping):
    exact(payload, FIELDS)
    for field in ("assessment_id", "workspace_id", "job_id", "project_id", "agent_id", "action", "reviewer_version", "mapping_version"):
        require(type(payload[field]) is str and 0 < len(payload[field]) <= 512, "invalid identifier")
    require(payload["schema_version"] == "allowly.assessment.v1", "unsupported assessment schema")
    require(payload["mode"] == "observe" and payload["intervention"] == "none", "invalid Observe mode")
    require(payload["application_reported_execution"] in ("sent", "accepted", "failed", "unknown"), "invalid reported execution")
    issued = timestamp(payload["issued_at"])
    require(issued <= datetime.now(timezone.utc) + timedelta(minutes=5), "future assessment")
    for field in ("source_sha256", "request_sha256", "mapping_sha256"):
        require(type(payload[field]) is str and HEX.fullmatch(payload[field]) is not None, "invalid digest")
    require(type(payload["engine_version"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", payload["engine_version"]), "invalid engine digest")
    ref = payload["policy_ref"]
    exact(ref, ("policy_id", "policy_version", "definition_sha256"))
    require(type(ref["policy_id"]) is str and bool(ref["policy_id"]), "invalid policy id")
    require(type(ref["policy_version"]) is int and 0 < ref["policy_version"] <= 2**53 - 1, "invalid policy version")
    require(type(ref["definition_sha256"]) is str and HEX.fullmatch(ref["definition_sha256"]), "invalid policy digest")
    validate_policy_definition(definition)
    digest = lambda value: hashlib.sha256(canonicalize(value)).hexdigest()
    require(digest(definition) == ref["definition_sha256"] and definition["agent_id"] == payload["agent_id"], "policy definition binding mismatch")
    entries = [entry for entry in definition["actions"] if entry["policy"]["action"] == payload["action"]]
    require(len(entries) == 1, "selected action missing")
    entry = entries[0]
    policy = entry["policy"]
    require("evidence" in entry and entry["guards"] == {} and entry["executable_operations"] == []
            and all(choice["decision"] in ("allow", "deny") for choice in [policy, *policy["rules"]]), "unsupported Observe policy")
    require(digest(mapping) == payload["mapping_sha256"] and mapping.get("mapping_version") == payload["mapping_version"], "mapping binding mismatch")
    exact(source, ("project_id", "trace_id", "observation_id", "observed_at", "captured_at", "content"))
    metadata = {key: value for key, value in source.items() if key != "content"}
    require(payload["source"] == metadata and source["project_id"] == payload["project_id"], "source binding mismatch")
    for field in ("project_id", "trace_id", "observation_id"):
        require(type(source[field]) is str and 0 < len(source[field]) <= 512, "invalid source id")
    observed, captured = timestamp(source["observed_at"]), timestamp(source["captured_at"])
    require(observed <= captured + timedelta(minutes=5) and captured <= datetime.now(timezone.utc) + timedelta(minutes=5), "invalid source time")
    require(len(canonicalize(source)) <= 65536 and digest(source) == payload["source_sha256"], "source digest or size mismatch")
    context = evidence_context(policy["fields"], entry["evidence"], source["content"], payload["facts"], payload["missing_information"], mapping)
    require(canonicalize(payload["context"]) == canonicalize(context), "incorrect derived context")
    request_fields = ("job_id", "project_id", "agent_id", "action", "policy_ref", "mapping_version", "reviewer_version", "source_sha256", "facts", "missing_information", "application_reported_execution", "mapping_sha256")
    request = {name: payload[name] for name in request_fields}
    request.update(source_snapshot=source, mapping_snapshot=mapping)
    require(len(canonicalize(request)) <= 65536 and digest(request) == payload["request_sha256"], "request commitment mismatch")
    if payload["missing_information"]:
        require(payload["policy_eval"] is None and payload["assessment_status"] == "insufficient_evidence", "missing evidence cannot become an assessment result")
    else:
        evaluation = payload["policy_eval"]
        exact(evaluation, ("input_sha256", "result"))
        require(evaluation["input_sha256"] == digest({"policy": policy, "action": payload["action"], "context": context}), "OPA input commitment mismatch")
        result = evaluation["result"]
        exact(result, ("profile", "status", "decision", "target", "matched_rule_id", "evaluated_fields"))
        require(result["profile"] == "allowly.basic.v1" and result["status"] == "ok" and result["decision"] in ("allow", "deny") and result["target"] is None, "invalid OPA result")
        rule_id = result["matched_rule_id"]
        require(rule_id is None or type(rule_id) is str and 0 < len(rule_id) <= 128, "invalid matched rule")
        rules = [rule for rule in policy["rules"] if rule["id"] == rule_id]
        require(rule_id is None or len(rules) == 1, "unknown matched rule")
        choice = rules[0] if rules else policy
        expected_fields = {condition["field"]: context[condition["field"]] for condition in choice.get("conditions", [])}
        require(result["decision"] == choice["decision"] and canonicalize(result["evaluated_fields"]) == canonicalize(expected_fields), "inconsistent OPA explanation")
        require(payload["assessment_status"] == ("violation_detected" if result["decision"] == "deny" else "no_violation_found"), "result/status mismatch")
    return payload


def verify_assessment(envelope, keys_document, source_snapshot, policy_definition, mapping_snapshot, *, expected_workspace_id, expected_project_id, trusted_key_fingerprints):
    """Authenticate the recorded bundle and cited source, not their real-world truth."""
    try:
        exact(envelope, ("protected", "payload", "signature"))
        require(len(canonicalize(envelope)) <= 350000, "assessment too large")
        header, payload = encoded_json(envelope["protected"]), encoded_json(envelope["payload"])
        exact(header, ("alg", "kid", "typ"))
        require(header["alg"] == "EdDSA" and header["typ"] == "allowly-assessment+jws" and type(header["kid"]) is str and bool(header["kid"]), "invalid assessment JWS header")
        require(type(expected_workspace_id) is str and bool(expected_workspace_id) and type(expected_project_id) is str and bool(expected_project_id), "caller trust context required")
        require(payload.get("workspace_id") == expected_workspace_id and keys_document.get("workspace_id") == expected_workspace_id and payload.get("project_id") == expected_project_id, "workspace/project mismatch")
        require(bool(trusted_key_fingerprints) and all(type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) for value in trusted_key_fingerprints), "caller trusted fingerprints required")
        keys = load_keys_from_json(keys_document)
        key = next((item for item in keys if item.key_id == header["kid"]), None)
        require(key is not None and public_key_fingerprint(key) in trusted_key_fingerprints, "untrusted assessment key")
        issued = timestamp(payload["issued_at"])
        require(issued >= key.active_from and (key.active_until is None or issued < key.active_until), "key outside active window")
        signature = b64(envelope["signature"])
        require(len(signature) == 64, "invalid signature length")
        Ed25519PublicKey.from_public_bytes(key.public_key_bytes).verify(signature, (envelope["protected"] + "." + envelope["payload"]).encode("ascii"))
        return validate_payload(payload, source_snapshot, policy_definition, mapping_snapshot)
    except AssessmentError:
        raise
    except Exception as exc:
        raise AssessmentError("assessment verification failed") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="JSON with signed_assessment, source_snapshot, policy_definition and mapping_snapshot")
    parser.add_argument("keys")
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--trusted-key-fingerprint", action="append", required=True)
    args = parser.parse_args()
    try:
        with open(args.bundle) as stream:
            bundle = json.load(stream)
        with open(args.keys) as stream:
            keys = json.load(stream)
        result = verify_assessment(bundle["signed_assessment"], keys, bundle["source_snapshot"], bundle["policy_definition"], bundle["mapping_snapshot"], expected_workspace_id=args.workspace_id, expected_project_id=args.project_id, trusted_key_fingerprints=set(args.trusted_key_fingerprint))
        print(f"Verified recorded assessment {result['assessment_id']}: {result['assessment_status']}")
        return 0
    except Exception:
        print("Assessment verification failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
