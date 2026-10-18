"""Generate policy-defined evidence fixtures; retained historical vectors stay untouched."""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

from allowly_receipt_format import canonicalize
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).parent
KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))  # Public fixture seed.
PUBLIC = KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
FINGERPRINT = "sha256:" + hashlib.sha256(PUBLIC).hexdigest()
encode = lambda raw: base64.urlsafe_b64encode(raw).decode().rstrip("=")
digest = lambda value: hashlib.sha256(canonicalize(value)).hexdigest()


def envelope(payload, typ="allowly-assessment+jws", raw_payload=None, raw_header=None):
    header = raw_header or canonicalize({"alg": "EdDSA", "kid": "fictional-assessment-key", "typ": typ})
    signing = encode(header) + "." + encode(raw_payload or canonicalize(payload))
    protected, encoded = signing.split(".")
    return {"protected": protected, "payload": encoded, "signature": encode(KEY.sign(signing.encode()))}


def citation(content, field):
    return {"field": field, "start": 0, "end": len(content[field]), "quote": content[field]}


def request_document(bundle):
    value = bundle["assessment"]
    request_fields = "job_id project_id agent_id action policy_ref mapping_version reviewer_version source_sha256 facts missing_information application_reported_execution mapping_sha256".split()
    return {**{name: value[name] for name in request_fields},
            "source_snapshot": bundle["source_snapshot"], "mapping_snapshot": bundle["mapping_snapshot"]}


def commit_request(bundle):
    bundle["assessment"]["request_sha256"] = digest(request_document(bundle))


def commit(bundle):
    value = bundle["assessment"]
    value["policy_ref"]["definition_sha256"] = digest(bundle["policy_definition"])
    value["mapping_sha256"] = digest(bundle["mapping_snapshot"])
    value["source_sha256"] = digest(bundle["source_snapshot"])
    value["source"] = {key: item for key, item in bundle["source_snapshot"].items() if key != "content"}
    if value["policy_eval"] is not None:
        value["policy_eval"]["input_sha256"] = digest({"policy": bundle["policy_definition"]["actions"][0]["policy"], "action": value["action"], "context": value["context"]})
    commit_request(bundle)


def fixture():
    source = {"project_id": "project_fictional", "trace_id": "trace_fictional", "observation_id": "obs_fictional", "observed_at": "2026-10-17T12:00:00.000Z", "captured_at": "2026-10-17T12:00:01.000Z", "content": {"note": "🧪 Fictional controlled evidence.", "destination": "operator@External.Example", "copy": "", "hidden": ""}}
    evidence = {"first_signal": {"sources": ["note"], "instruction": "Determine whether the first test signal is present."}, "second_signal": {"sources": ["note", "destination"], "instruction": "Determine whether the second test signal is present."}, "both_signals": {"all_of": ["first_signal", "second_signal"]}}
    policy = {"profile": "allowly.basic.v1", "action": "records.inspect", "decision": "allow", "target": None, "fields": {name: "boolean" for name in evidence}, "rules": [{"id": "flag", "decision": "deny", "target": None, "conditions": [{"field": "both_signals", "op": "eq", "value": True}]}]}
    definition = {"profile": "allowly.policy.v1", "agent_id": "agent_fictional", "actions": [{"policy": policy, "guards": {}, "executable_operations": [], "evidence": evidence}], "default_expiry_days": None}
    mapping = {"observation_name": "records.inspect", "sources": {name: "/input/" + name for name in source["content"]}, "execution_pointer": "/output/status", "mapping_version": "fixture-arbitrary-label"}
    facts = {name: {"value": True, "citations": [citation(source["content"], "note")]} for name in ("first_signal", "second_signal")}
    value = {"schema_version": "allowly.assessment.v1", "assessment_id": "asm_fictional", "workspace_id": "ws_fictional", "job_id": "job_fictional", "project_id": source["project_id"], "agent_id": definition["agent_id"], "action": policy["action"], "issued_at": "2026-10-17T12:00:02.000Z", "policy_ref": {"policy_id": "policy_fixture", "policy_version": 1, "definition_sha256": ""}, "mapping_version": mapping["mapping_version"], "mapping_sha256": "", "reviewer_version": "fixture:not-a-live-model", "engine_version": "sha256:" + "b" * 64, "source": {}, "source_sha256": "", "request_sha256": "", "facts": facts, "missing_information": [], "context": {name: True for name in evidence}, "policy_eval": {"input_sha256": "", "result": {"profile": "allowly.basic.v1", "status": "ok", "decision": "deny", "target": None, "matched_rule_id": "flag", "evaluated_fields": {"both_signals": True}}}, "assessment_status": "violation_detected", "application_reported_execution": "accepted", "mode": "observe", "intervention": "none"}
    keys = {"workspace_id": "ws_fictional", "keys": [{"key_id": "fictional-assessment-key", "alg": "Ed25519", "public_key": encode(PUBLIC), "public_key_fingerprint": FINGERPRINT, "active_from": "2026-01-01T00:00:00.000Z", "active_until": None}]}
    bundle = {"assessment": value, "source_snapshot": source, "policy_definition": definition, "mapping_snapshot": mapping, "keys": keys, "workspace_id": "ws_fictional", "project_id": "project_fictional", "fingerprints": [FINGERPRINT]}
    commit(bundle)
    return bundle


def missing(bundle, field):
    value = bundle["assessment"]
    value["facts"][field] = None
    value.update(missing_information=[name for name, fact in value["facts"].items() if fact is None], context={}, policy_eval=None, assessment_status="insufficient_evidence")


def domain_fixture():
    bundle = fixture()
    entry, value = bundle["policy_definition"]["actions"][0], bundle["assessment"]
    entry["evidence"] = {"destination_host": {"source": "destination", "transform": "email_domain", "empty_sources": ["copy", "hidden"]}}
    entry["policy"].update(fields={"destination_host": "string"}, rules=[{"id": "flag", "decision": "deny", "target": None, "conditions": [{"field": "destination_host", "op": "ne", "value": "internal.example"}]}])
    value["facts"] = {"destination_host": {"value": "external.example", "citations": [citation(bundle["source_snapshot"]["content"], "destination")]}}
    value["context"] = {"destination_host": "external.example"}
    value["policy_eval"]["result"]["evaluated_fields"] = dict(value["context"])
    commit(bundle)
    return bundle


def main():
    cases = []
    def add(name, mutate=None, *, valid=False, recommit=False, request_only=False, base=None, typ="allowly-assessment+jws", raw_payload=None, raw_header=None, change_envelope=None):
        case = deepcopy(base or fixture())
        if mutate:
            mutate(case)
        if recommit:
            commit(case)
        elif request_only:
            commit_request(case)
        value = case.pop("assessment")
        case.update(name=name, valid=valid, signed_assessment=envelope(value, typ, raw_payload, raw_header))
        if change_envelope:
            change_envelope(case["signed_assessment"])
        cases.append(case)
    add("generic_unicode_citations_and_all_of", valid=True)
    add("wrong_mapping_hash_with_consistent_request", lambda c: c["assessment"].update(mapping_sha256="0" * 64), request_only=True)
    add("wrong_source_hash_with_consistent_request", lambda c: c["assessment"].update(source_sha256="0" * 64), request_only=True)
    boundary = fixture()
    boundary["mapping_snapshot"]["sources"]["padding"] = "/input/padding"
    boundary["source_snapshot"]["content"]["padding"] = ""
    commit(boundary)
    boundary["source_snapshot"]["content"]["padding"] = "." * (65536 - len(canonicalize(request_document(boundary))))
    commit(boundary)
    assert len(canonicalize(request_document(boundary))) == 65536
    add("request_at_byte_limit", base=boundary, valid=True)
    add("request_over_byte_limit", lambda c: c["source_snapshot"]["content"].update(padding=c["source_snapshot"]["content"]["padding"] + "."), base=boundary, recommit=True)
    for left, right in ((False, False), (False, True), (True, False)):
        def truth(case, left=left, right=right):
            value = case["assessment"]
            value["facts"]["first_signal"]["value"], value["facts"]["second_signal"]["value"] = left, right
            value["context"] = {"first_signal": left, "second_signal": right, "both_signals": False}
            value["policy_eval"]["result"].update(decision="allow", matched_rule_id=None, evaluated_fields={})
            value["assessment_status"] = "no_violation_found"
        add(f"all_of_{left}_{right}", truth, valid=True, recommit=True)
    add("missing_direct_fact", lambda c: missing(c, "second_signal"), valid=True, recommit=True)
    add("missing_first_cannot_hide_wrong_later_type", lambda c: (
        missing(c, "first_signal"), c["assessment"]["facts"]["second_signal"].update(value="true")), recommit=True)
    add("missing_first_cannot_hide_wrong_later_quote", lambda c: (
        missing(c, "first_signal"), c["assessment"]["facts"]["second_signal"]["citations"][0].update(quote="Invented")), recommit=True)
    add("false_plus_missing_is_insufficient", lambda c: (c["assessment"]["facts"]["first_signal"].update(value=False), missing(c, "second_signal")), valid=True, recommit=True)
    add("absent_required_source_cannot_be_present", lambda c: c["source_snapshot"]["content"].pop("destination"), recommit=True)
    add("absent_required_source_is_insufficient", lambda c: (c["source_snapshot"]["content"].pop("destination"), missing(c, "second_signal")), valid=True, recommit=True)
    for name, kind, value in (("text", "string", "value"), ("count", "integer", 0), ("nothing", "null", None), ("items", "list", [True, 1, "1", None])):
        def scalar(case, name=name, kind=kind, value=value):
            entry = case["policy_definition"]["actions"][0]
            entry["policy"].update(fields={name: kind}, rules=[])
            entry["evidence"] = {name: {"sources": ["note"], "instruction": "Extract the declared fixture value."}}
            case["assessment"].update(facts={name: {"value": value, "citations": [citation(case["source_snapshot"]["content"], "note")]}}, context={name: value}, assessment_status="no_violation_found")
            case["assessment"]["policy_eval"]["result"].update(decision="allow", matched_rule_id=None, evaluated_fields={})
        base = fixture(); scalar(base); commit(base)
        add("typed_" + name, valid=True, base=base)
        for label, bad in (("wrong_type", {}), ("float", 1.5), ("unsafe_integer", 2**53), ("nul", "a\0b"), ("nested_list", [[1]]), ("long_list", [1] * 65)):
            if label in ("float", "unsafe_integer"):  # Canonical encoding must also fail; test raw signed JSON.
                bad_payload = deepcopy(base["assessment"]); bad_payload["facts"][name]["value"] = bad
                add(f"typed_{name}_{label}", base=base, raw_payload=json.dumps(bad_payload, separators=(",", ":")).encode())
            else:
                add(f"typed_{name}_{label}", lambda c, bad=bad, name=name: (
                    c["assessment"]["facts"][name].update(value=bad), c["assessment"]["context"].update({name: bad})),
                    base=base, recommit=True)
    for name, mutate in (
        ("wrong_workspace", lambda c: c.update(workspace_id="ws_other")),
        ("wrong_project", lambda c: c.update(project_id="project_other")),
        ("untrusted_key", lambda c: c.update(fingerprints=["sha256:" + "0" * 64])),
        ("no_anchor", lambda c: c.update(fingerprints=[])),
        ("key_workspace", lambda c: c["keys"].update(workspace_id="ws_other")),
        ("expired_key", lambda c: c["keys"]["keys"][0].update(active_until="2026-10-16T00:00:00.000Z")),
        ("duplicate_key", lambda c: c["keys"]["keys"].append(deepcopy(c["keys"]["keys"][0]))),
        ("changed_policy", lambda c: c["policy_definition"]["actions"][0]["evidence"]["first_signal"].update(instruction="Changed instruction.")),
        ("changed_mapping", lambda c: c["mapping_snapshot"]["sources"].update(note="/different/source")),
        ("changed_source", lambda c: c["source_snapshot"]["content"].update(note="Changed source.")),
        ("request_digest", lambda c: c["assessment"].update(request_sha256="0" * 64)),
        ("input_digest", lambda c: c["assessment"]["policy_eval"].update(input_sha256="0" * 64)),
        ("quote", lambda c: c["assessment"]["facts"]["first_signal"]["citations"][0].update(quote="Invented")),
        ("utf16_offset", lambda c: c["assessment"]["facts"]["first_signal"]["citations"][0].update(end=len(c["source_snapshot"]["content"]["note"]) + 1)),
        ("wrong_source", lambda c: c["assessment"]["facts"]["first_signal"].update(citations=[citation(c["source_snapshot"]["content"], "destination")])),
        ("derived_value", lambda c: c["assessment"]["context"].update(both_signals=False)),
        ("coerced_context", lambda c: c["assessment"]["context"].update(first_signal=1)),
        ("status", lambda c: c["assessment"].update(assessment_status="no_violation_found")),
        ("intervention", lambda c: c["assessment"].update(intervention="blocked")),
        ("unknown_rule", lambda c: c["assessment"]["policy_eval"]["result"].update(matched_rule_id="unknown")),
        ("evaluated_fields", lambda c: c["assessment"]["policy_eval"]["result"].update(evaluated_fields={"both_signals": 1})),
        ("future", lambda c: c["assessment"].update(issued_at="2999-01-01T00:00:00.000Z")),
        ("calendar", lambda c: c["assessment"].update(issued_at="2026-02-30T12:00:00.000Z")),
        ("missing_payload_field", lambda c: c["assessment"].pop("agent_id")),
        ("extra_payload_field", lambda c: c["assessment"].update(authorization_id="not-authority")),
        ("mapping_label_mismatch", lambda c: c["assessment"].update(mapping_version="different-label")),
        ("empty_citations", lambda c: c["assessment"]["facts"]["first_signal"].update(citations=[])),
        ("boolean_offsets", lambda c: c["assessment"]["facts"]["first_signal"]["citations"][0].update(start=False)),
        ("boolean_policy_version", lambda c: c["assessment"]["policy_ref"].update(policy_version=True)),
    ):
        add(name, mutate, recommit=name in {"quote", "utf16_offset", "wrong_source", "empty_citations", "boolean_offsets"})
    for name, mutate in (
        ("evidence_null", lambda c: c["policy_definition"]["actions"][0].update(evidence=None)),
        ("extra_requirement_key", lambda c: c["policy_definition"]["actions"][0]["evidence"]["first_signal"].update(optional=True)),
        ("all_of_chain", lambda c: c["policy_definition"]["actions"][0]["evidence"]["both_signals"].update(all_of=["both_signals"])),
        ("duplicate_sources", lambda c: c["policy_definition"]["actions"][0]["evidence"]["first_signal"].update(sources=["note", "note"])),
        ("blank_instruction", lambda c: c["policy_definition"]["actions"][0]["evidence"]["first_signal"].update(instruction="  ")),
        ("unsupported_method", lambda c: c["policy_definition"]["actions"][0]["evidence"]["first_signal"].update(transform="unknown")),
        ("mapping_uncovered", lambda c: c["mapping_snapshot"]["sources"].pop("note")),
        ("mapping_unknown_content", lambda c: c["source_snapshot"]["content"].update(unmapped="extra")),
        ("bad_pointer_escape", lambda c: c["mapping_snapshot"]["sources"].update(note="/input/~2")),
        ("missing_green", lambda c: c["assessment"]["facts"].update(first_signal=None)),
        ("extra_fact", lambda c: c["assessment"]["facts"].update(extra=None)),
        ("extra_fact_member", lambda c: c["assessment"]["facts"]["first_signal"].update(optional=True)),
        ("extra_citation_member", lambda c: c["assessment"]["facts"]["first_signal"]["citations"][0].update(optional=True)),
        ("wrong_policy_agent", lambda c: c["policy_definition"].update(agent_id="other_agent")),
        ("unknown_policy_field", lambda c: c["policy_definition"]["actions"][0]["policy"].update(extra=True)),
        ("source_future_capture", lambda c: c["source_snapshot"].update(captured_at="2999-01-01T00:00:00.000Z")),
        ("source_after_capture", lambda c: c["source_snapshot"].update(observed_at="2026-10-17T12:05:01.001Z")),
        ("source_wrong_project", lambda c: c["source_snapshot"].update(project_id="other_project")),
        ("source_invalid_id", lambda c: c["source_snapshot"].update(observation_id=17)),
        ("source_nul", lambda c: c["source_snapshot"]["content"].update(destination="a\0b")),
        ("selected_execution_guard", lambda c: c["policy_definition"]["actions"][0].update(guards={"max_per_day": 1})),
    ):
        add(name, mutate, recommit=True)
    for name, change in (
        ("tampered_signature", lambda e: e.update(signature=encode(bytes(64)))),
        ("padded_signature", lambda e: e.update(signature=e["signature"] + "=")),
        ("extra_envelope_field", lambda e: e.update(approved=True)),
        ("missing_envelope_field", lambda e: e.pop("signature")),
    ):
        add(name, change_envelope=change)
    add("unknown_key_id", raw_header=canonicalize({"alg": "EdDSA", "kid": "unknown", "typ": "allowly-assessment+jws"}))
    add("receipt_type_rejected", typ="allowly-receipt+jws")
    original = fixture()["assessment"]
    add("duplicate_payload_json", raw_payload=canonicalize(original).replace(b'"mode":"observe"', b'"mode":"observe","mode":"observe"'))
    add("noncanonical_header", raw_header=b'{ "alg":"EdDSA","kid":"fictional-assessment-key","typ":"allowly-assessment+jws"}')
    base = domain_fixture()
    add("generic_deterministic_transform", valid=True, base=base)
    for field in ("destination", "copy", "hidden"):
        add("domain_missing_" + field, lambda c, field=field: c["source_snapshot"]["content"].pop(field), recommit=True, base=base)
        add("domain_missing_" + field + "_insufficient", lambda c, field=field: (c["source_snapshot"]["content"].pop(field), missing(c, "destination_host")), valid=True, recommit=True, base=base)
    for field in ("copy", "hidden"):
        add("domain_nonempty_" + field, lambda c, field=field: c["source_snapshot"]["content"].update({field: "other@example.test"}), recommit=True, base=base)
    for name, source, candidate in (("display", "Name <user@example.test>", "example.test"),
            ("list", "a@example.test,b@example.test", "example.test"), ("quoted", '"name"@example.test', "example.test"),
            ("unicode", "user@exаmple.test", "exаmple.test"), ("newline", "user@example.test\n", "example.test"),
            ("literal", "user@[127.0.0.1]", "[127.0.0.1]"), ("empty_local", "@example.test", "example.test"),
            ("long_local", "a" * 65 + "@example.test", "example.test")):
        def mailbox(case, source=source, candidate=candidate):
            case["source_snapshot"]["content"]["destination"] = source
            value = case["assessment"]
            value["facts"]["destination_host"].update(value=candidate, citations=[citation(case["source_snapshot"]["content"], "destination")])
            value["context"] = {"destination_host": candidate}
            value["policy_eval"]["result"]["evaluated_fields"] = dict(value["context"])
        add("domain_" + name, mailbox, recommit=True, base=base)
    add("domain_forged_value", lambda c: (
        c["assessment"]["facts"]["destination_host"].update(value="internal.example"),
        c["assessment"]["context"].update(destination_host="internal.example"),
        c["assessment"]["policy_eval"]["result"].update(evaluated_fields={"destination_host": "internal.example"})), recommit=True, base=base)
    add("domain_partial_citation", lambda c: c["assessment"]["facts"]["destination_host"]["citations"][0].update(start=9, quote="External.Example"), recommit=True, base=base)
    ROOT.joinpath("evidence-vectors.json").write_text(json.dumps({"profile": "allowly.assessment.v1", "cases": cases}, ensure_ascii=False, indent=2) + "\n")
    print(f"Wrote {len(cases)} policy-defined evidence vectors; historical vectors unchanged")


if __name__ == "__main__":
    main()
