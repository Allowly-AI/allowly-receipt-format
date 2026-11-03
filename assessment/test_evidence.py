"""Boundary checks shared by authoring, runtime and standalone verification."""
from copy import deepcopy

import pytest

from allowly_receipt_format.evidence import domain_value, evidence_context, validate_evidence, validate_mapping
from allowly_receipt_format import SchemaError
from assessment.generate_vectors import fixture


def test_missing_is_distinct_from_present_null_and_false():
    requirement = {"value": {"sources": ["record"], "instruction": "Read the captured value."}}
    citation = {"field": "record", "start": 0, "end": 4, "quote": "null"}
    assert evidence_context({"value": "null"}, requirement, {"record": "null"}, {"value": {"value": None, "citations": [citation]}}, []) == {"value": None}
    assert evidence_context({"value": "null"}, requirement, {}, {"value": None}, ["value"]) == {}
    with pytest.raises(ValueError):
        evidence_context({"value": "null"}, requirement, {}, {"value": None}, [])


@pytest.mark.parametrize("pointer", ["", "input/a", "/a~", "/a~2", "/a\0b", "/" + "a" * 256])
def test_mapping_rejects_invalid_json_pointers(pointer):
    mapping = fixture()["mapping_snapshot"]
    mapping["sources"]["note"] = pointer
    with pytest.raises(ValueError):
        validate_mapping(mapping)


def test_rfc6901_escapes_are_data_and_mapping_labels_have_no_semantics():
    mapping = fixture()["mapping_snapshot"]
    mapping["sources"]["note"] = "/input/a~1b~0c/"
    mapping["mapping_version"] = "any opaque label"
    validate_mapping(mapping)


@pytest.mark.parametrize("change", [
    lambda e: e["first_signal"].update(instruction="a" * 2049),
    lambda e: e["first_signal"].update(sources=["note\0"]),
    lambda e: e["first_signal"].update(sources=["note"] * 9),
    lambda e: e["both_signals"].update(all_of=["absent"]),
    lambda e: e["both_signals"].update(all_of=["first_signal", "first_signal"]),
    lambda e: e["second_signal"].update(all_of=["both_signals"]),
])
def test_evidence_cannot_expand_into_an_expression_language(change):
    entry = fixture()["policy_definition"]["actions"][0]
    evidence = deepcopy(entry["evidence"])
    change(evidence)
    with pytest.raises(ValueError):
        validate_evidence(entry["policy"]["fields"], evidence)


def test_ai_requires_all_declared_sources_even_when_citation_uses_one():
    case = fixture()
    entry, value = case["policy_definition"]["actions"][0], case["assessment"]
    del case["source_snapshot"]["content"]["destination"]
    with pytest.raises(ValueError, match="source unavailable"):
        evidence_context(entry["policy"]["fields"], entry["evidence"], case["source_snapshot"]["content"], value["facts"], [], case["mapping_snapshot"])


def test_domain_extractor_does_not_confuse_missing_envelope_with_empty():
    requirement = {"source": "destination", "transform": "email_domain", "empty_sources": ["copy", "hidden"]}
    assert domain_value({"destination": "User@EXAMPLE.TEST", "copy": "", "hidden": ""}, requirement) == "example.test"
    assert domain_value({"destination": "User@EXAMPLE.TEST", "copy": ""}, requirement) is None
    assert domain_value({"destination": None, "copy": "", "hidden": ""}, requirement) is None
    with pytest.raises(ValueError):
        domain_value(None, requirement)


@pytest.mark.parametrize("change", [
    lambda c: c["assessment"]["facts"].update(unrequested=None),
    lambda c: c["assessment"]["facts"]["second_signal"].update(value="true"),
    lambda c: c["assessment"]["facts"]["second_signal"].update(value=1),
    lambda c: c["assessment"]["facts"]["second_signal"].update(extra=True),
    lambda c: c["assessment"]["facts"]["second_signal"]["citations"][0].update(extra=True),
    lambda c: c["assessment"]["facts"]["second_signal"]["citations"][0].update(field="destination", quote="not the source"),
    lambda c: c["assessment"]["facts"]["second_signal"]["citations"][0].update(start=True),
    lambda c: c["assessment"]["facts"]["second_signal"]["citations"][0].update(end=999),
    lambda c: c["assessment"]["facts"]["second_signal"].update(citations=[]),
])
def test_an_unavailable_first_fact_never_skips_validation_of_later_evidence(change):
    case = fixture()
    case["assessment"]["facts"]["first_signal"] = None
    case["assessment"]["missing_information"] = ["first_signal"]
    change(case)
    entry, value = case["policy_definition"]["actions"][0], case["assessment"]
    with pytest.raises(ValueError):
        evidence_context(entry["policy"]["fields"], entry["evidence"], case["source_snapshot"]["content"],
                         value["facts"], value["missing_information"], case["mapping_snapshot"])


@pytest.mark.parametrize("kind,bad", [
    ("boolean", 1), ("boolean", "true"), ("boolean", None),
    ("integer", True), ("integer", "1"), ("integer", 1.5), ("integer", 2**53),
    ("string", False), ("string", "a\0b"), ("null", False),
    ("list", {}), ("list", [[1]]), ("list", [{"a": 1}]), ("list", [1] * 65),
    ("list", ["a\0b"]), ("list", [2**53]),
])
def test_typed_facts_are_rejected_before_the_request_hash_can_mask_them(kind, bad):
    fields = {"value": kind}
    evidence = {"value": {"sources": ["record"], "instruction": "Extract the recorded value."}}
    fact = {"value": bad, "citations": [{"field": "record", "start": 0, "end": 4, "quote": "data"}]}
    with pytest.raises(ValueError):
        evidence_context(fields, evidence, {"record": "data"}, {"value": fact}, [])


@pytest.mark.parametrize("kind,value", [("integer", 106), ("integer", 2**53-1),
    ("integer", -(2**53-1)), ("list", list(range(64))), ("boolean", False), ("null", None)])
def test_typed_positive_boundaries(kind, value):
    requirement = {"value": {"sources": ["record"], "instruction": "Read the value."}}
    facts = {"value": {"value": value, "citations": [{"field": "record", "start": 0, "end": 4, "quote": "data"}]}}
    assert evidence_context({"value": kind}, requirement, {"record": "data"}, facts, []) == {"value": value}


@pytest.mark.parametrize("count,valid", [(64, True), (65, False)])
def test_evidence_field_count_boundary(count, valid):
    fields = {f"f{i}": "boolean" for i in range(count)}
    requirements = {name: {"sources": ["record"], "instruction": "Read the value."} for name in fields}
    if valid:
        validate_evidence(fields, requirements)
    else:
        with pytest.raises(ValueError): validate_evidence(fields, requirements)


@pytest.mark.parametrize("fields,evidence", [
    ({"a" * 129: "boolean"}, {"a" * 129: {"sources": ["record"], "instruction": "Read."}}),
    ({"": "boolean"}, {"": {"sources": ["record"], "instruction": "Read."}}),
    ({"a": "object"}, {"a": {"sources": ["record"], "instruction": "Read."}}),
    ({"a": "boolean"}, {}),
    ({"a": "boolean"}, {"a": {"sources": [f"s{i}" for i in range(9)], "instruction": "Read."}}),
    ({"a": "string"}, {"a": {"source": "s" * 65, "transform": "email_domain", "empty_sources": []}}),
    ({"a": "boolean"}, {"a": {"source": "record", "transform": "email_domain", "empty_sources": []}}),
    ({"a": "string"}, {"a": {"source": "record", "transform": "email_domain", "empty_sources": [f"s{i}" for i in range(9)]}}),
    ({"a": "boolean", "b": "boolean", "c": "boolean"}, {"a": {"sources": ["record"], "instruction": "Read."}, "b": {"all_of": ["a"]}, "c": {"all_of": ["b"]}}),
])
def test_standalone_metadata_boundaries(fields, evidence):
    with pytest.raises(ValueError): validate_evidence(fields, evidence)


@pytest.mark.parametrize("count,valid", [(1, True), (16, True), (17, False)])
def test_all_of_dependency_count(count, valid):
    fields = {f"f{i}": "boolean" for i in range(count)}
    evidence = {name: {"sources": ["record"], "instruction": "Read."} for name in fields}
    evidence["combined"] = {"all_of": list(fields)}
    fields["combined"] = "boolean"
    if valid: validate_evidence(fields, evidence)
    else:
        with pytest.raises(ValueError): validate_evidence(fields, evidence)


def test_domain_positive_and_negative_length_boundaries():
    requirement = {"source": "record", "transform": "email_domain", "empty_sources": []}
    host = "a" * 63 + "." + "b" * 63 + "." + "c" * 61
    assert domain_value({"record": "u" * 64 + "@" + host}, requirement) == host  #254 bytes
    assert domain_value({"record": "u" * 64 + "@" + host + "c"}, requirement) is None  #255
    assert domain_value({"record": "u" * 65 + "@example.test"}, requirement) is None
    with pytest.raises(ValueError):
        domain_value({"s" * 65: "u@example.test"}, {**requirement, "source": "s" * 65})
    with pytest.raises(ValueError):
        domain_value({"record": "u@example.test", **{f"s{i}": "" for i in range(9)}},
                     {**requirement, "empty_sources": [f"s{i}" for i in range(9)]})
    validate_evidence({"value": "string"}, {"value": requirement})


@pytest.mark.parametrize("count,valid", [(32, True), (33, False)])
def test_content_count_boundary(count, valid):
    content = {f"s{i}": "data" for i in range(count)}
    evidence = {"value": {"sources": ["s0"], "instruction": "Read."}}
    if valid: assert evidence_context({"value": "boolean"}, evidence, content, {"value": None}, ["value"]) == {}
    else:
        with pytest.raises(ValueError): evidence_context({"value": "boolean"}, evidence, content, {"value": None}, ["value"])


@pytest.mark.parametrize("citations,quote,valid", [(8, "data", True), (9, "data", False),
    (1, "x" * 8192, True), (1, "x" * 8193, False), (1, "x\ud800", False)])
def test_citation_limits_and_canonical_unicode(citations, quote, valid):
    evidence = {"value": {"sources": ["record"], "instruction": "Read."}}
    fact = {"value": True, "citations": [{"field": "record", "start": 0, "end": len(quote), "quote": quote}] * citations}
    mapping = {"observation_name": "read", "sources": {"record": "/input/record"}, "execution_pointer": "/output/status", "mapping_version": "label"}
    if valid:
        assert evidence_context({"value": "boolean"}, evidence, {"record": quote}, {"value": fact}, [], mapping) == {"value": True}
    else:
        with pytest.raises((ValueError, SchemaError)): evidence_context({"value": "boolean"}, evidence, {"record": quote}, {"value": fact}, [], mapping)


def test_unencodable_instructions_and_overlong_unused_sources_are_rejected():
    with pytest.raises(SchemaError):
        validate_evidence({"value": "boolean"}, {"value": {"sources": ["record"], "instruction": "Read \ud800"}})
    with pytest.raises(ValueError):
        evidence_context({"value": "boolean"}, {"value": {"sources": ["record"], "instruction": "Read."}},
                         {"x" * 65: "unused"}, {"value": None}, ["value"])
