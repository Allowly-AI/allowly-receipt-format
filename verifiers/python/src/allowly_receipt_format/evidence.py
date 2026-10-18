"""Pure policy-defined evidence checks; no source provider or rule evaluator."""
from __future__ import annotations

import re

from .verifier import canonicalize

_TYPES = {"string", "integer", "boolean", "null", "list"}
_ATOM = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_MAILBOX = re.compile(rf"({_ATOM}(?:\.{_ATOM})*)@({_LABEL}(?:\.{_LABEL})+)")


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _text(value, limit):
    return type(value) is str and 0 < len(value) <= limit and "\0" not in value


def _names(value, minimum, maximum, limit=64):
    _require(type(value) is list and minimum <= len(value) <= maximum
             and all(_text(name, limit) for name in value)
             and len(set(value)) == len(value), "invalid unique evidence names")


def _value(value, declared):
    if declared == "list":
        return (type(value) is list and len(value) <= 64
                and all(_value(item, {str: "string", int: "integer", bool: "boolean", type(None): "null"}.get(type(item))) for item in value))
    if declared == "string":
        return type(value) is str and "\0" not in value
    if declared == "integer":
        return type(value) is int and abs(value) <= 2**53 - 1
    if declared == "boolean":
        return type(value) is bool
    return declared == "null" and value is None


def validate_evidence(fields, evidence):
    """Validate optional action metadata once present; types remain in fields."""
    _require(type(fields) is dict and len(fields) <= 64
             and all(_text(name, 128) and type(kind) is str and kind in _TYPES for name, kind in fields.items()), "invalid policy fields")
    _require(type(evidence) is dict and bool(evidence) and set(evidence) == set(fields), "evidence must cover policy fields exactly")
    for name, requirement in evidence.items():
        _require(type(requirement) is dict, "invalid evidence requirement")
        keys = set(requirement)
        if keys == {"sources", "instruction"}:
            _names(requirement["sources"], 1, 8)
            _require(_text(requirement["instruction"], 2048) and requirement["instruction"].strip(), "invalid extraction instruction")
        elif keys == {"source", "transform", "empty_sources"}:
            _require(fields[name] == "string" and requirement["transform"] == "email_domain"
                     and _text(requirement["source"], 64), "invalid evidence transform")
            _names(requirement["empty_sources"], 0, 8)
            _require(requirement["source"] not in requirement["empty_sources"], "transform source cannot be empty source")
        elif keys == {"all_of"}:
            _names(requirement["all_of"], 1, 16, 128)
            _require(fields[name] == "boolean" and all(
                dependency in fields and fields[dependency] == "boolean"
                and type(evidence.get(dependency)) is dict and "all_of" not in evidence[dependency]
                for dependency in requirement["all_of"]), "all_of requires direct boolean fields")
        else:
            raise ValueError("unsupported evidence requirement")
    canonicalize(evidence)


def _pointer(value):
    return (_text(value, 256) and value.startswith("/")
            and re.search(r"~(?![01])", value) is None)


def validate_mapping(mapping):
    _require(type(mapping) is dict and set(mapping) == {
        "observation_name", "sources", "execution_pointer", "mapping_version"}, "invalid mapping fields")
    _require(_text(mapping["observation_name"], 128) and _text(mapping["mapping_version"], 128)
             and _pointer(mapping["execution_pointer"]), "invalid mapping identity or pointer")
    sources = mapping["sources"]
    _require(type(sources) is dict and 1 <= len(sources) <= 32
             and all(_text(name, 64) and _pointer(pointer) for name, pointer in sources.items()), "invalid mapping sources")
    canonicalize(mapping)


def domain_value(content, requirement):
    """Return a complete single-mailbox domain, or unavailable evidence."""
    _require(type(content) is dict and type(requirement) is dict
             and set(requirement) == {"source", "transform", "empty_sources"}
             and requirement["transform"] == "email_domain" and _text(requirement["source"], 64), "invalid domain extraction input")
    _names(requirement["empty_sources"], 0, 8)
    _require(requirement["source"] not in requirement["empty_sources"], "source cannot be empty source")
    source = content.get(requirement["source"])
    if (type(source) is not str or len(source) > 254
            or any(content.get(name) != "" for name in requirement["empty_sources"])):
        return None
    match = _MAILBOX.fullmatch(source)
    if match is None or len(match[1]) > 64 or len(match[2]) > 253:
        return None
    return match[2].lower()


def evidence_context(fields, evidence, content, facts, missing_information, mapping=None):
    """Validate source-bound typed facts and derive the complete OPA context."""
    validate_evidence(fields, evidence)
    _require(type(content) is dict and len(content) <= 32 and all(
        _text(name, 64) and type(value) is str and "\0" not in value for name, value in content.items()), "invalid evidence content")
    required_sources = set()
    direct = {name: item for name, item in evidence.items() if "all_of" not in item}
    for item in direct.values():
        required_sources.update(item["sources"] if "sources" in item else [item["source"], *item["empty_sources"]])
    if mapping is not None:
        validate_mapping(mapping)
        _require(required_sources <= set(mapping["sources"]) and set(content) <= set(mapping["sources"]), "mapping does not cover evidence")
    _require(type(facts) is dict and set(facts) == set(direct), "facts must match direct evidence fields")
    absent = [name for name in direct if facts[name] is None]
    _require(type(missing_information) is list and all(type(name) is str for name in missing_information)
             and len(set(missing_information)) == len(missing_information)
             and set(missing_information) == set(absent), "missing evidence mismatch")
    for name, requirement in direct.items():
        fact = facts[name]
        if fact is None:
            continue
        _require(type(fact) is dict and set(fact) == {"value", "citations"}
                 and _value(fact["value"], fields[name]), "invalid typed fact")
        if "sources" in requirement:
            _require(all(source in content for source in requirement["sources"]), "required extraction source unavailable")
        citations = fact["citations"]
        _require(type(citations) is list and 1 <= len(citations) <= 8, "fact requires citations")
        allowed = requirement.get("sources", [requirement.get("source")])
        for citation in citations:
            _require(type(citation) is dict and set(citation) == {"field", "start", "end", "quote"}, "invalid citation fields")
            field, start, end, quote = (citation[key] for key in ("field", "start", "end", "quote"))
            _require(type(field) is str and field in allowed and field in content
                     and type(start) is int and type(end) is int and 0 <= start < end <= len(content[field])
                     and _text(quote, 8192) and content[field][start:end] == quote, "citation does not match permitted source")
        if "transform" in requirement:
            source = content.get(requirement["source"])
            _require(fact["value"] == domain_value(content, requirement) and len(citations) == 1
                     and citations[0] == {"field": requirement["source"], "start": 0, "end": len(source), "quote": source}, "deterministic fact mismatch")
    canonicalize(facts)
    if absent:
        return {}
    context = {name: fact["value"] for name, fact in facts.items()}
    context.update({name: all(context[dependency] for dependency in item["all_of"])
                    for name, item in evidence.items() if "all_of" in item})
    return context


def validate_policy_definition(definition):
    """Check the complete retained edition without interpreting its rules."""
    _require(type(definition) is dict and set(definition) == {"profile", "agent_id", "actions", "default_expiry_days"}
             and definition["profile"] == "allowly.policy.v1" and _text(definition["agent_id"], 128), "invalid policy definition")
    expiry = definition["default_expiry_days"]
    _require(expiry is None or type(expiry) is int and 1 <= expiry <= 3650, "invalid policy expiry")
    actions = definition["actions"]
    _require(type(actions) is list and 1 <= len(actions) <= 32, "invalid policy actions")
    names, grants_seen = set(), set()
    for entry in actions:
        _require(type(entry) is dict and set(entry) in ({"policy", "guards", "executable_operations"}, {"policy", "guards", "executable_operations", "evidence"}), "invalid policy action")
        policy = entry["policy"]
        _require(type(policy) is dict and set(policy) == {"profile", "action", "decision", "target", "fields", "rules"}
                 and policy["profile"] == "allowly.basic.v1" and _text(policy["action"], 64)
                 and policy["action"] not in {"allow", "deny", "confirm", "escalate"}
                 and policy["action"] not in names, "invalid or duplicate action policy")
        names.add(policy["action"])
        fields = policy["fields"]
        _require(type(fields) is dict and len(fields) <= 64 and all(
            _text(name, 128) and type(kind) is str and kind in _TYPES for name, kind in fields.items()), "invalid policy fields")
        if "evidence" in entry:
            validate_evidence(fields, entry["evidence"])
        rules = policy["rules"]
        _require(type(rules) is list and len(rules) <= 32, "invalid policy rules")
        rule_ids = set()
        for choice in [policy, *rules]:
            _require(type(choice) is dict, "invalid policy choice")
            decision, target = choice.get("decision"), choice.get("target")
            _require(type(decision) is str and decision in {"allow", "deny", "confirm", "escalate"}, "invalid policy decision")
            _require((decision in {"allow", "deny"} and target is None)
                     or (decision == "confirm" and target == "agent_owner")
                     or (decision == "escalate" and _text(target, 135) and target.startswith("member:") and target[7:].strip()), "invalid policy target")
        for rule in rules:
            _require(type(rule) is dict and set(rule) == {"id", "decision", "target", "conditions"}
                     and _text(rule["id"], 128) and rule["id"] not in rule_ids, "invalid or duplicate policy rule")
            rule_ids.add(rule["id"])
            conditions = rule["conditions"]
            _require(type(conditions) is list and 1 <= len(conditions) <= 10, "invalid conditions")
            for condition in conditions:
                _require(type(condition) is dict and set(condition) == {"field", "op", "value"}
                         and type(condition["field"]) is str and condition["field"] in fields, "invalid condition field")
                declared, op, value = fields[condition["field"]], condition["op"], condition["value"]
                _require(type(op) is str and op in {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "exists", "contains_any", "contains_none", "empty"}, "invalid condition operator")
                if op == "exists":
                    valid = type(value) is bool
                elif op == "empty":
                    valid = declared == "list" and type(value) is bool
                elif op in {"contains_any", "contains_none"}:
                    valid = declared == "list" and _value(value, "list") and bool(value)
                elif op in {"in", "not_in"}:
                    valid = declared != "list" and type(value) is list and len(value) <= 64 and all(_value(item, declared) for item in value)
                else:
                    valid = declared != "list" and _value(value, declared) and (op not in {"gt", "gte", "lt", "lte"} or declared == "integer")
                _require(valid, "invalid condition value")
        guards = entry["guards"]
        _require(type(guards) is dict and set(guards) <= {"resource_pattern", "allowed_initiators", "max_per_day"}, "invalid policy guards")
        if "resource_pattern" in guards:
            _require(_text(guards["resource_pattern"], 256), "invalid resource guard")
        if "allowed_initiators" in guards:
            _names(guards["allowed_initiators"], 1, 128, 128)
        if "max_per_day" in guards:
            _require(type(guards["max_per_day"]) is int and 1 <= guards["max_per_day"] <= 2**53 - 1, "invalid count guard")
        grants = entry["executable_operations"]
        _require(type(grants) is list and len(grants) <= 100, "invalid executable grants")
        for grant in grants:
            _require(type(grant) is dict and set(grant) == {"enabled_executable_id", "provider_id", "operation_id", "catalog_revision", "definition_fingerprint", "minimum_evidence_mode"}, "invalid executable grant fields")
            _require(all(_text(grant[name], 128) for name in ("enabled_executable_id", "provider_id", "operation_id", "catalog_revision"))
                     and type(grant["definition_fingerprint"]) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", grant["definition_fingerprint"])
                     and grant["minimum_evidence_mode"] in ("receipt", "witnessed"), "invalid executable grant")
            identity = grant["enabled_executable_id"], grant["operation_id"]
            _require(identity not in grants_seen, "duplicate executable grant")
            grants_seen.add(identity)
    _require(len(canonicalize(definition)) <= 65536, "policy definition too large")
