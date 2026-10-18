"""Regenerate fictional signed assessment vectors. The test seed is public."""
import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from allowly_receipt_format import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).parent
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # Public test seed, never production.
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
FINGERPRINT = "sha256:" + hashlib.sha256(PUBLIC).hexdigest()
encode = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")


def envelope(payload, typ="allowly-assessment+jws", raw_payload=None, raw_header=None):
    header = raw_header or canonicalize({"alg": "EdDSA", "kid": "fictional-assessment-key", "typ": typ})
    signing = encode(header) + "." + encode(raw_payload or canonicalize(payload))
    protected, encoded = signing.split(".")
    return {"protected": protected, "payload": encoded, "signature": encode(KEY.sign(signing.encode()))}


def fixture():
    source = {"project_id": "project_fictional", "trace_id": "trace_fictional", "observation_id": "obs_fictional", "observed_at": "2026-10-17T12:00:00.000Z", "captured_at": "2026-10-17T12:00:01.000Z", "content": {"body": "🧪 Fictional candidate has a medical condition.", "recipient": "recruiter@external.example"}}
    facts = {name: {"value": True, "citations": [{"field": field, "start": 0, "end": len(source["content"][field]), "quote": source["content"][field]}]} for name, field in (("contains_medical_information", "body"), ("external_recipient", "recipient"))}
    payload = {"schema_version": "allowly.assessment.v1", "assessment_id": "asm_fictional", "workspace_id": "ws_fictional", "job_id": "job_fictional", "project_id": source["project_id"], "agent_id": "recruiting_agent", "action": "email.send", "issued_at": "2026-10-17T12:00:02.000Z", "policy_ref": {"policy_id": "medical-disclosure", "policy_version": 1, "definition_sha256": "a" * 64}, "mapping_version": "medical-external-v1", "reviewer_version": "fixture:not-a-live-model", "engine_version": "sha256:" + "b" * 64, "source": {key: value for key, value in source.items() if key != "content"}, "source_sha256": hashlib.sha256(canonicalize(source)).hexdigest(), "request_sha256": "c" * 64, "facts": facts, "missing_information": [], "context": {"medical_external_disclosure": True}, "policy_eval": {"input_sha256": "d" * 64, "result": {"profile": "allowly.basic.v1", "status": "ok", "decision": "deny", "target": None, "matched_rule_id": "medical-external", "evaluated_fields": {"medical_external_disclosure": True}}}, "assessment_status": "violation_detected", "application_reported_execution": "sent", "mode": "observe", "intervention": "none"}
    keys = {"workspace_id": "ws_fictional", "keys": [{"key_id": "fictional-assessment-key", "alg": "Ed25519", "public_key": encode(PUBLIC), "public_key_fingerprint": FINGERPRINT, "active_from": "2026-01-01T00:00:00.000Z", "active_until": None}]}
    return payload, source, keys


def main():
    payload, source, keys = fixture()
    cases = []
    def add(name, *, mutate=None, change_case=None, valid=False, typ="allowly-assessment+jws", raw_payload=None, raw_header=None):
        value = deepcopy(payload)
        if mutate:
            mutate(value)
        case = {"name": name, "valid": valid, "signed_assessment": envelope(value, typ, raw_payload, raw_header), "source_snapshot": deepcopy(source), "keys": deepcopy(keys), "workspace_id": "ws_fictional", "project_id": "project_fictional", "fingerprints": [FINGERPRINT]}
        if change_case:
            change_case(case)
        cases.append(case)
    add("violation_with_unicode_citation", valid=True)
    for medical, external in ((False, False), (False, True), (True, False)):
        def allow(value, medical=medical, external=external):
            value["facts"]["contains_medical_information"]["value"] = medical
            value["facts"]["external_recipient"]["value"] = external
            value["context"]["medical_external_disclosure"] = False
            value["policy_eval"]["result"].update(decision="allow", matched_rule_id=None, evaluated_fields={})
            value["assessment_status"] = "no_violation_found"
        add(f"and_{medical}_{external}", mutate=allow, valid=True)
    def missing(value):
        value["facts"]["external_recipient"] = None
        value.update(missing_information=["external_recipient"], context={}, policy_eval=None, assessment_status="insufficient_evidence")
    add("missing_evidence", mutate=missing, valid=True)
    empty_source = deepcopy(source)
    empty_source["content"] = {}
    def empty(value):
        value.update(facts={name: None for name in value["facts"]}, missing_information=list(value["facts"]), context={}, policy_eval=None, assessment_status="insufficient_evidence", source_sha256=hashlib.sha256(canonicalize(empty_source)).hexdigest())
    add("empty_source_is_insufficient", mutate=empty, change_case=lambda c: c.update(source_snapshot=deepcopy(empty_source)), valid=True)
    add("wrong_workspace", change_case=lambda c: c.update(workspace_id="ws_other"))
    add("wrong_project", change_case=lambda c: c.update(project_id="project_other"))
    add("no_trust_anchor", change_case=lambda c: c.update(fingerprints=[]))
    add("untrusted_key", change_case=lambda c: c.update(fingerprints=["sha256:" + "0" * 64]))
    add("wrong_key_workspace", change_case=lambda c: c["keys"].update(workspace_id="ws_other"))
    add("expired_key", change_case=lambda c: c["keys"]["keys"][0].update(active_until="2026-10-16T00:00:00.000Z"))
    add("duplicate_key", change_case=lambda c: c["keys"]["keys"].append(deepcopy(c["keys"]["keys"][0])))
    add("receipt_type_is_not_assessment", typ="allowly-receipt+jws")
    add("changed_source", change_case=lambda c: c["source_snapshot"]["content"].update(body="Different fictional text"))
    add("changed_uncited_source", change_case=lambda c: c["source_snapshot"]["content"].update(prompt="Uncommitted fictional prompt"))
    add("extra_envelope_field", change_case=lambda c: c["signed_assessment"].update(execution_approved=True))
    add("padded_signature", change_case=lambda c: c["signed_assessment"].update(signature=c["signed_assessment"]["signature"] + "="))
    add("tampered_signature", change_case=lambda c: c["signed_assessment"].update(signature=encode(bytes(64))))
    add("extra_payload_field", mutate=lambda p: p.update(authorization_id="not-an-authorization"))
    add("missing_payload_field", mutate=lambda p: p.pop("agent_id"))
    add("coerced_policy_version", mutate=lambda p: p["policy_ref"].update(policy_version=True))
    add("zero_policy_version", mutate=lambda p: p["policy_ref"].update(policy_version=0))
    add("coerced_fact", mutate=lambda p: p["facts"]["contains_medical_information"].update(value="true"))
    add("unsupported_quote", mutate=lambda p: p["facts"]["contains_medical_information"]["citations"][0].update(quote="invented"))
    add("wrong_semantic_source_field", mutate=lambda p: p["facts"]["contains_medical_information"].update(citations=deepcopy(p["facts"]["external_recipient"]["citations"])))
    add("utf16_offsets_are_wrong", mutate=lambda p: p["facts"]["contains_medical_information"]["citations"][0].update(end=len(source["content"]["body"]) + 1))
    add("conjunction_mismatch", mutate=lambda p: p["context"].update(medical_external_disclosure=False))
    add("status_mismatch", mutate=lambda p: p.update(assessment_status="no_violation_found"))
    add("execution_authority", mutate=lambda p: p.update(intervention="blocked"))
    add("unknown_mapping", mutate=lambda p: p.update(mapping_version="unreviewed"))
    add("future_issue", mutate=lambda p: p.update(issued_at="2999-01-01T00:00:00.000Z"))
    add("invalid_calendar", mutate=lambda p: p.update(issued_at="2026-02-30T12:00:00.000Z"))
    add("confirmation_is_not_observe", mutate=lambda p: p["policy_eval"]["result"].update(decision="confirm"))
    duplicate = canonicalize(payload).decode().replace('"mode":"observe"', '"mode":"observe","mode":"observe"')
    add("duplicate_json_field", raw_payload=duplicate.encode())
    add("noncanonical_header", raw_header=b'{ "alg":"EdDSA","kid":"fictional-assessment-key","typ":"allowly-assessment+jws"}')

    # Keep every historical medical vector byte-for-byte; append the new mapping.
    payload, source, _ = fixture()
    source["content"] = {"sender": "support@internal.example", "recipient": "recruiter@external.example",
                         "cc": "", "bcc": "", "subject": "Fictional Observe example", "body": "Fictional example only.", "attachments": "[]"}
    def domain_fact(recipient):
        return {"value": recipient.rsplit("@", 1)[1].lower(), "citations": [{"field": "recipient", "start": 0, "end": len(recipient), "quote": recipient}]}
    payload.update(mapping_version="email-recipient-domain-v1", reviewer_version="deterministic:email-recipient-domain-v1",
                   facts={"recipient_domain": domain_fact(source["content"]["recipient"])}, context={"recipient_domain": "external.example"},
                   source_sha256=hashlib.sha256(canonicalize(source)).hexdigest(), application_reported_execution="accepted")
    payload["policy_eval"]["result"].update(matched_rule_id="internal-email-only", evaluated_fields={"recipient_domain": "external.example"})
    add("domain_external_provider_accepted", valid=True)
    def changed_source(value):
        value["source_sha256"] = hashlib.sha256(canonicalize(source)).hexdigest()
    source["content"]["recipient"] = "Recruiter@INTERNAL.EXAMPLE"
    payload["facts"]["recipient_domain"] = domain_fact(source["content"]["recipient"])
    payload["context"] = {"recipient_domain": "internal.example"}
    payload["policy_eval"]["result"].update(decision="allow", matched_rule_id=None, evaluated_fields={})
    payload["assessment_status"] = "no_violation_found"
    changed_source(payload)
    add("domain_internal_uppercase_normalized", valid=True)
    for execution in ("sent", "failed", "unknown"):
        add("domain_reported_" + execution, mutate=lambda p, execution=execution: p.update(application_reported_execution=execution), valid=True)
    for field in ("recipient", "cc", "bcc"):
        original = source["content"].pop(field)
        def absent_domain(value):
            changed_source(value)
            value.update(facts={"recipient_domain": None}, missing_information=["recipient_domain"], context={}, policy_eval=None, assessment_status="insufficient_evidence")
        add("domain_missing_" + field + "_is_insufficient", mutate=absent_domain, valid=True)
        add("domain_missing_" + field + "_cannot_be_green", mutate=changed_source)
        source["content"][field] = original
    for field in ("cc", "bcc"):
        source["content"][field] = "other@external.example"
        add("domain_nonempty_" + field + "_is_insufficient", mutate=absent_domain, valid=True)
        add("domain_nonempty_" + field + "_cannot_be_green", mutate=changed_source)
        source["content"][field] = ""
        source["content"][field] = None
        add("domain_null_" + field + "_source_rejected", mutate=changed_source)
        add("domain_null_" + field + "_cannot_be_insufficient", mutate=absent_domain)
        source["content"][field] = ""
    changed_source(payload)
    add("domain_source_metadata_mismatch", mutate=lambda p: p["source"].update(trace_id="different_trace"))
    source["project_id"] = "different_project"
    def rehashed_project_mismatch(value):
        changed_source(value)
        value["source"]["project_id"] = source["project_id"]
    add("domain_source_project_rehashed_mismatch", mutate=rehashed_project_mismatch)
    source["project_id"] = payload["project_id"]
    add("domain_forged_value", mutate=lambda p: p["facts"]["recipient_domain"].update(value="external.example"))
    add("domain_boolean_fact", mutate=lambda p: p["facts"]["recipient_domain"].update(value=True))
    add("domain_wrong_context", mutate=lambda p: p.update(context={"recipient_domain": "external.example"}))
    recipient = source["content"]["recipient"]
    add("domain_partial_recipient_citation", mutate=lambda p: p["facts"]["recipient_domain"]["citations"][0].update(
        start=len("Recruiter@"), end=len(recipient), quote="INTERNAL.EXAMPLE"))
    add("domain_prefix_only_recipient_citation", mutate=lambda p: p["facts"]["recipient_domain"]["citations"][0].update(
        start=0, end=len("Recruiter"), quote="Recruiter"))
    add("domain_non_deterministic_reviewer", mutate=lambda p: p.update(reviewer_version="vertex:untrusted"))
    add("domain_medical_facts", mutate=lambda p: p.update(facts=fixture()[0]["facts"]))
    add("domain_extra_fact", mutate=lambda p: p["facts"].update(external_recipient=None))
    add("domain_missing_fact_not_declared", mutate=lambda p: p["facts"].update(recipient_domain=None))
    add("domain_duplicate_missing", mutate=lambda p: (absent_domain(p), p.update(missing_information=["recipient_domain", "recipient_domain"])))
    add("domain_duplicate_recipient_citation", mutate=lambda p: p["facts"]["recipient_domain"]["citations"].append(
        deepcopy(p["facts"]["recipient_domain"]["citations"][0])))
    original_source = deepcopy(source)
    def bound_source(value):
        changed_source(value)
        value["source"] = {key: item for key, item in source.items() if key != "content"}
    for name, field, replacement in (
        ("empty_trace_id", "trace_id", ""),
        ("long_trace_id", "trace_id", "t" * 513),
        ("nonstring_observation_id", "observation_id", 17),
        ("future_capture", "captured_at", "2999-01-01T00:00:00.000Z"),
        ("observation_after_capture", "observed_at", "2026-10-17T12:05:01.001Z"),
    ):
        source[field] = replacement
        add("domain_source_" + name, mutate=bound_source)
        source = deepcopy(original_source)
    for name, content in (
        ("null_content", None), ("array_content", []),
        ("nonstring_content_value", dict(source["content"], body=17)),
        ("too_many_content_fields", dict(source["content"], **{f"extra_{i}": "" for i in range(26)})),
        ("over_64k", dict(source["content"], body="a" * 65536)),
    ):
        source["content"] = content
        add("domain_source_" + name, mutate=bound_source)
        source = deepcopy(original_source)
    source["content"].update({f"extra_{i}": "" for i in range(25)})
    add("domain_source_32_content_fields", mutate=bound_source, valid=True)
    source = deepcopy(original_source)
    for length, valid in ((254, True), (255, False)):
        source["content"]["recipient"] = "a" * 64 + "@" + "b" * 63 + "." + "b" * 63 + "." + "b" * (length - 193)
        assert len(source["content"]["recipient"]) == length
        def long_recipient(value):
            bound_source(value)
            fact = domain_fact(source["content"]["recipient"])
            value.update(facts={"recipient_domain": fact}, context={"recipient_domain": fact["value"]}, assessment_status="violation_detected")
            value["policy_eval"]["result"].update(decision="deny", matched_rule_id="internal-email-only", evaluated_fields={"recipient_domain": fact["value"]})
        add(f"domain_recipient_{length}_characters", mutate=long_recipient, valid=valid)
        source = deepcopy(original_source)
    for name, recipient in (
        ("display_name", "Recruiter <recruiter@internal.example>"),
        ("list", "a@internal.example,b@external.example"),
        ("group", "Team:a@internal.example;"),
        ("quoted", '"recruiter"@internal.example'),
        ("comment", "recruiter(comment)@internal.example"),
        ("crlf", "recruiter@internal.example\r\n"),
        ("newline", "recruiter@internal.example\n"),
        ("unicode", "recruiter@internаl.example"),
        ("literal", "recruiter@[127.0.0.1]"),
        ("bad_label", "recruiter@-internal.example"),
        ("long_local", "a" * 65 + "@internal.example"),
        ("long_label", "a@" + "b" * 64 + ".example"),
    ):
        source["content"]["recipient"] = recipient
        def unsupported(value):
            changed_source(value)
            value["facts"]["recipient_domain"]["citations"][0].update(end=len(recipient), quote=recipient)
        add("domain_unsupported_" + name, mutate=unsupported)
    medical_payload, medical_source, _ = fixture()
    payload, source = medical_payload, medical_source
    add("medical_mapping_rejects_provider_accepted", mutate=lambda p: p.update(application_reported_execution="accepted"))
    ROOT.joinpath("vectors.json").write_text(json.dumps({"profile": "allowly.assessment.v1", "cases": cases}, ensure_ascii=False, indent=2) + "\n")
    print(f"Wrote {len(cases)} fictional signed vectors")


if __name__ == "__main__":
    main()
