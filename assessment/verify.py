"""Source-distributed Observe assessment verifier; not a wire-5 receipt parser."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from datetime import datetime, timedelta, timezone

from allowly_receipt_format import canonicalize, load_keys_from_json, public_key_fingerprint
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FIELDS = set("schema_version assessment_id workspace_id job_id project_id agent_id action issued_at policy_ref mapping_version reviewer_version engine_version source source_sha256 request_sha256 facts missing_information context policy_eval assessment_status application_reported_execution mode intervention".split())
FACTS = ("contains_medical_information", "external_recipient")
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


def validate_payload(payload, source):
    exact(payload, FIELDS)
    for field in ("assessment_id", "workspace_id", "job_id", "project_id", "agent_id", "action", "reviewer_version"):
        require(type(payload[field]) is str and 0 < len(payload[field]) <= 512, "invalid identifier")
    require(payload["schema_version"] == "allowly.assessment.v1", "unsupported assessment schema")
    require(payload["mapping_version"] == "medical-external-v1", "unsupported mapping")
    require(payload["mode"] == "observe" and payload["intervention"] == "none", "invalid Observe mode")
    require(payload["application_reported_execution"] in ("sent", "failed", "unknown"), "invalid reported execution")
    issued = timestamp(payload["issued_at"])
    require(issued <= datetime.now(timezone.utc) + timedelta(minutes=5), "future assessment")
    for field in ("source_sha256", "request_sha256"):
        require(type(payload[field]) is str and HEX.fullmatch(payload[field]) is not None, "invalid digest")
    require(type(payload["engine_version"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", payload["engine_version"]), "invalid engine digest")
    ref = payload["policy_ref"]
    exact(ref, ("policy_id", "policy_version", "definition_sha256"))
    require(type(ref["policy_id"]) is str and bool(ref["policy_id"]), "invalid policy id")
    require(type(ref["policy_version"]) is int and 0 < ref["policy_version"] <= 2**53 - 1, "invalid policy version")
    require(type(ref["definition_sha256"]) is str and HEX.fullmatch(ref["definition_sha256"]), "invalid policy digest")
    exact(source, ("project_id", "trace_id", "observation_id", "observed_at", "captured_at", "content"))
    metadata = {key: value for key, value in source.items() if key != "content"}
    require(payload["source"] == metadata and source["project_id"] == payload["project_id"], "source binding mismatch")
    for field in ("project_id", "trace_id", "observation_id"):
        require(type(source[field]) is str and 0 < len(source[field]) <= 512, "invalid source id")
    observed, captured = timestamp(source["observed_at"]), timestamp(source["captured_at"])
    require(observed <= captured + timedelta(minutes=5) and captured <= datetime.now(timezone.utc) + timedelta(minutes=5), "invalid source time")
    content = source["content"]
    require(type(content) is dict and len(content) <= 32 and all(type(k) is str and type(v) is str for k, v in content.items()), "invalid source content")
    require(len(canonicalize(source)) <= 65536, "source too large")
    require(hashlib.sha256(canonicalize(source)).hexdigest() == payload["source_sha256"], "source digest mismatch")
    exact(payload["facts"], FACTS)
    absent = []
    for name in FACTS:
        fact = payload["facts"][name]
        if fact is None:
            absent.append(name)
            continue
        exact(fact, ("value", "citations"))
        require(type(fact["value"]) is bool, "fact must be a boolean")
        require(type(fact["citations"]) is list and 0 < len(fact["citations"]) <= 8, "fact needs evidence")
        for citation in fact["citations"]:
            exact(citation, ("field", "start", "end", "quote"))
            field, start, end, quote = (citation[key] for key in ("field", "start", "end", "quote"))
            require(field == ("body" if name == "contains_medical_information" else "recipient"), "unsupported evidence mapping")
            require(type(field) is str and field in content, "unknown evidence field")
            require(type(start) is int and type(end) is int and 0 <= start < end <= len(content[field]), "invalid evidence span")
            require(type(quote) is str and content[field][start:end] == quote, "unsupported evidence quote")
    missing = payload["missing_information"]
    require(type(missing) is list and all(type(item) is str for item in missing) and len(set(missing)) == len(missing) and set(missing) == set(absent), "missing evidence mismatch")
    if absent:
        require(payload["context"] == {} and payload["policy_eval"] is None and payload["assessment_status"] == "insufficient_evidence", "missing evidence cannot become an assessment result")
    else:
        derived = all(payload["facts"][name]["value"] for name in FACTS)
        exact(payload["context"], ("medical_external_disclosure",))
        require(type(payload["context"]["medical_external_disclosure"]) is bool and payload["context"]["medical_external_disclosure"] is derived, "incorrect conjunction")
        evidence = payload["policy_eval"]
        exact(evidence, ("input_sha256", "result"))
        require(type(evidence["input_sha256"]) is str and HEX.fullmatch(evidence["input_sha256"]), "invalid OPA input digest")
        result = evidence["result"]
        exact(result, ("profile", "status", "decision", "target", "matched_rule_id", "evaluated_fields"))
        require(result["profile"] == "allowly.basic.v1" and result["status"] == "ok" and result["decision"] in ("allow", "deny") and result["target"] is None, "invalid OPA result")
        require(result["matched_rule_id"] is None or type(result["matched_rule_id"]) is str, "invalid matched rule")
        require(type(result["evaluated_fields"]) is dict, "invalid evaluated fields")
        require(payload["assessment_status"] == ("violation_detected" if result["decision"] == "deny" else "no_violation_found"), "result/status mismatch")
    return payload


def verify_assessment(envelope, keys_document, source_snapshot, *, expected_workspace_id, expected_project_id, trusted_key_fingerprints):
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
        return validate_payload(payload, source_snapshot)
    except AssessmentError:
        raise
    except Exception as exc:
        raise AssessmentError("assessment verification failed") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", help="JSON with signed_assessment and source_snapshot")
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
        result = verify_assessment(bundle["signed_assessment"], keys, bundle["source_snapshot"], expected_workspace_id=args.workspace_id, expected_project_id=args.project_id, trusted_key_fingerprints=set(args.trusted_key_fingerprint))
        print(f"Verified recorded assessment {result['assessment_id']}: {result['assessment_status']}")
        return 0
    except Exception:
        print("Assessment verification failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
