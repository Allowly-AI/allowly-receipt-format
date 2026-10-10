"""Separate offline replay using pinned official OPA; no Python rule interpreter."""
from __future__ import annotations

import hashlib
import io
import json
import platform
import subprocess
import tarfile
import tempfile
from dataclasses import replace
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any

from .verifier import (PublicKey, SchemaError, VerificationError, _PUBLIC_KEY_FINGERPRINT_RE,
    _check_exact_keys, _check_policy_result, _load_json_file, canonicalize,
    load_keys_from_json, verify_receipt)

OPA_COMMIT = "2a109e54103370d2ef288782ef3cb4c8a37902b2"
OPA_ARTIFACTS = {
    "darwin/arm64": {"commit": OPA_COMMIT, "artifact_sha256": "a00a6469a0968c47c01137ed0dacaa88148be5d0eaa8524310cd371f3a98a169"},
    "linux/arm64": {"commit": OPA_COMMIT + "-dirty", "artifact_sha256": "9a1f3625529c6f01240fe68286dde06aa0b23c5253da700ac48f4d943ff8a4de"},
    "linux/amd64": {"commit": OPA_COMMIT + "-dirty", "artifact_sha256": "668506eb17a2eaa1fce6cc0d1f42ef85125d4ac5bda5fc74d1152d0c77145031"},
}
MODULE_SHA256 = "76d8e826f88e0e1fc34d274687044609b2c298e562289f502b712e907928b40c"
MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _host_platform() -> str | None:
    return {("Darwin", "arm64"): "darwin/arm64", ("Linux", "aarch64"): "linux/arm64",
            ("Linux", "arm64"): "linux/arm64", ("Linux", "x86_64"): "linux/amd64"}.get((platform.system(), platform.machine()))


def _digest(value: Any) -> str:
    return hashlib.sha256(canonicalize(value)).hexdigest()


def _snapshot(value: Any) -> Any:
    return json.loads(canonicalize(value))


def _exact(value: Any, fields: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise SchemaError(f"{label} must be an object")
    _check_exact_keys(value, fields, label)


def _artifact(path: str | Path) -> bytes:
    with open(path, "rb") as stream:
        value = stream.read(MAX_ARTIFACT_BYTES + 1)
    if len(value) > MAX_ARTIFACT_BYTES:
        raise ValueError("artifact exceeds replay size bound")
    return value


def _check_manifest(manifest: dict) -> None:
    _exact(manifest, {"schema", "policy_profile", "evaluator", "runtime"}, "engine manifest")
    if manifest["schema"] != "allowly.engine.v1" or manifest["policy_profile"] != "allowly.policy.v1":
        raise ValueError("unsupported engine manifest")
    evaluator = manifest["evaluator"]
    _exact(evaluator, {"profile", "entrypoint", "module", "opa", "bundle"}, "evaluator")
    if evaluator["profile"] != "allowly.basic.v1" or evaluator["entrypoint"] != "/v1/data/allowly/basic/result":
        raise ValueError("unsupported evaluator")
    if evaluator["module"] != {"path": "policies/opa/allowly_basic.rego",
        "api_id": "policies/opa/policies/opa/allowly_basic.rego", "sha256": MODULE_SHA256}:
        raise ValueError("unsupported Rego module")
    opa = evaluator["opa"]
    _exact(opa, {"version", "commit", "platform", "artifact_sha256"}, "official OPA artifact")
    artifact = OPA_ARTIFACTS.get(opa["platform"])
    if artifact is None or opa != {"version": "1.21.1", "platform": opa["platform"], **artifact}:
        raise ValueError("unsupported official OPA artifact")
    if evaluator["bundle"] != {"roots": [""], "revision": "allowly.basic.v1", "rego_version": 1} or type(evaluator["bundle"].get("rego_version")) is not int:
        raise ValueError("unsupported full-root bundle")
    runtime = manifest["runtime"]
    _exact(runtime, {"artifact_sha256", "format", "files"}, "runtime")
    if runtime["format"] != "tar" or not isinstance(runtime["files"], list) or not 1 <= len(runtime["files"]) <= 5000:
        raise ValueError("unsupported runtime artifact")
    for entry in runtime["files"]:
        _exact(entry, {"path", "sha256"}, "runtime file")
        path = entry["path"]
        if not isinstance(path, str) or not path or PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise ValueError("invalid runtime member path")
        if not isinstance(entry["sha256"], str) or not _PUBLIC_KEY_FINGERPRINT_RE.fullmatch("sha256:" + entry["sha256"]):
            raise ValueError("invalid runtime member digest")
    if not isinstance(runtime["artifact_sha256"], str) or not _PUBLIC_KEY_FINGERPRINT_RE.fullmatch("sha256:" + runtime["artifact_sha256"]):
        raise ValueError("invalid runtime artifact digest")


def _runtime_matches(raw: bytes, runtime: dict) -> bool:
    if hashlib.sha256(raw).hexdigest() != runtime["artifact_sha256"]:
        return False
    expected = {entry["path"]: entry["sha256"] for entry in runtime["files"]}
    if len(expected) != len(runtime["files"]):
        return False
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        if len(members) != len(expected) or len({member.name for member in members}) != len(members):
            return False
        for member in members:
            if not member.isfile() or member.name not in expected or member.size > MAX_ARTIFACT_BYTES:
                return False
            stream = archive.extractfile(member)
            if stream is None or hashlib.sha256(stream.read()).hexdigest() != expected[member.name]:
                return False
    return True


def replay_policy(
    receipt: dict[str, Any], public_keys: list[PublicKey], *,
    expected_workspace_id: str, trusted_key_fingerprints: set[str] | frozenset[str],
    manifest: dict | None = None, definition: dict | None = None,
    input_document: dict | None = None, opa_binary: str | Path | None = None,
    rego_file: str | Path | None = None, runtime_artifact: str | Path | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Authenticate first, then replay only the complete provisional result.

    Missing artifacts or unsupported engines return not_checked. Commitment or
    result comparison failures return mismatched. Invalid signatures raise
    VerificationError. This does not check final enforcement or TLSNotary.
    """
    if type(expected_workspace_id) is not str or not expected_workspace_id:
        raise SchemaError("expected_workspace_id must be a nonempty string")
    if type(trusted_key_fingerprints) not in (set, frozenset) or not trusted_key_fingerprints or any(
        not isinstance(value, str) or not _PUBLIC_KEY_FINGERPRINT_RE.fullmatch(value) for value in trusted_key_fingerprints):
        raise SchemaError("caller-trusted key fingerprints are required")
    receipt = _snapshot(receipt)
    keys = [replace(key, public_key_bytes=bytes(key.public_key_bytes)) for key in public_keys]
    verify_receipt(receipt, keys, expected_workspace_id=expected_workspace_id,
        trusted_key_fingerprints=frozenset(trusted_key_fingerprints), now=now)

    def report(status: str, diagnostic: str) -> dict:
        return {"receipt_id": receipt["receipt_id"], "signature_verified": True,
            "policy_replay": status, "diagnostic": diagnostic,
            "transactional_enforcement": "not_checked", "witnessed_execution": "not_checked"}

    if "policy_eval" not in receipt:
        return report("not_checked", "policy_evaluation_not_recorded")
    if any(value is None for value in (manifest, definition, input_document, opa_binary, rego_file, runtime_artifact)):
        return report("not_checked", "missing_replay_artifacts")
    try:
        manifest, definition, input_document = map(_snapshot, (manifest, definition, input_document))
        if "sha256:" + _digest(manifest) != receipt["engine_version"]:
            return report("mismatched", "engine_manifest_digest_mismatch")
        _check_manifest(manifest)
    except (VerificationError, ValueError, TypeError, KeyError):
        return report("not_checked", "unsupported_engine_manifest")
    try:
        _exact(definition, {"profile", "agent_id", "actions", "default_expiry_days"}, "policy definition")
        if definition["profile"] != "allowly.policy.v1" or definition["agent_id"] != receipt["agent_id"]:
            return report("mismatched", "policy_definition_binding_mismatch")
        if _digest(definition) != receipt["policy_ref"]["definition_sha256"]:
            return report("mismatched", "policy_definition_digest_mismatch")
        _exact(input_document, {"policy", "action", "context"}, "original OPA input")
        if not isinstance(input_document["context"], dict) or input_document["action"] != receipt["action"]:
            return report("mismatched", "policy_input_binding_mismatch")
        actions = definition["actions"]
        if not isinstance(actions, list) or not actions:
            raise ValueError("invalid actions")
        for action in actions:
            _exact(action, {"policy", "guards", "executable_operations"}, "policy action")
        names = [action["policy"]["action"] for action in actions]
        selected = [action["policy"] for action in actions if action["policy"]["action"] == receipt["action"]]
        if len(set(names)) != len(names) or len(selected) != 1 or canonicalize(selected[0]) != canonicalize(input_document["policy"]):
            return report("mismatched", "selected_policy_mismatch")
        inner_bytes = canonicalize(input_document)
        if len(inner_bytes) > 65536:
            return report("not_checked", "policy_input_size_exceeded")
        if hashlib.sha256(inner_bytes).hexdigest() != receipt["policy_eval"]["input_sha256"]:
            return report("mismatched", "policy_input_digest_mismatch")
        module = _artifact(rego_file)
        if hashlib.sha256(module).hexdigest() != MODULE_SHA256:
            return report("mismatched", "rego_artifact_digest_mismatch")
        if not _runtime_matches(_artifact(runtime_artifact), manifest["runtime"]):
            return report("mismatched", "runtime_artifact_digest_mismatch")
        binary_bytes = _artifact(Path(opa_binary).resolve(strict=True))
        opa = manifest["evaluator"]["opa"]
        if hashlib.sha256(binary_bytes).hexdigest() != opa["artifact_sha256"]:
            return report("mismatched", "opa_artifact_digest_mismatch")
        if _host_platform() != opa["platform"]:
            return report("not_checked", "unsupported_replay_platform")
        # Only checksum-pinned Rego and a fixed query execute. No private input
        # is logged, no network configuration or alternate interpreter is used.
        with tempfile.TemporaryDirectory(prefix="allowly-opa-replay-") as directory:
            binary = Path(directory) / "opa"
            binary.write_bytes(binary_bytes)
            binary.chmod(0o500)
            pinned_module = Path(directory) / "allowly_basic.rego"
            pinned_module.write_bytes(module)
            version = subprocess.run([str(binary), "version"], check=True, capture_output=True, timeout=5)
            actual = dict(line.split(": ", 1) for line in version.stdout.decode().splitlines() if ": " in line)
            if (actual["Version"], actual["Build Commit"], actual["Platform"]) != (opa["version"], opa["commit"], opa["platform"]):
                return report("not_checked", "unsupported_opa_build")
            result = subprocess.run([str(binary), "eval", "--format=json", "--stdin-input",
                "--data", str(pinned_module), "data.allowly.basic.result"],
                input=inner_bytes, check=True, capture_output=True, timeout=5)
        if len(result.stdout) > 32768:
            return report("not_checked", "invalid_opa_result")
        values = json.loads(result.stdout)["result"]
        if len(values) != 1 or len(values[0]["expressions"]) != 1:
            return report("not_checked", "undefined_opa_result")
        calculated = values[0]["expressions"][0]["value"]
        calculated_bytes = canonicalize(calculated)
        _check_policy_result(calculated)
        if calculated_bytes != canonicalize(receipt["policy_eval"]["result"]):
            return report("mismatched", "provisional_result_mismatch")
        return report("matched", "provisional_result_matches")
    except OSError:
        return report("not_checked", "replay_artifact_unavailable")
    except (subprocess.SubprocessError, VerificationError, ValueError, TypeError, KeyError, tarfile.TarError):
        return report("not_checked", "invalid_replay_artifact_or_opa_result")


def main(argv: list[str] | None = None) -> int:
    import argparse
    import sys
    parser = argparse.ArgumentParser(description="Verify one receipt and replay its provisional result with official OPA.")
    parser.add_argument("receipt")
    parser.add_argument("keys")
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--trusted-key-fingerprint", action="append", required=True)
    for name in ("manifest", "definition", "input", "opa-binary", "rego-file", "runtime-artifact"):
        parser.add_argument("--" + name)
    args = parser.parse_args(argv)
    try:
        keys_doc = _load_json_file(args.keys)
        if keys_doc.get("workspace_id") != args.workspace_id:
            raise SchemaError("key document workspace_id mismatch")
        receipt, keys = _load_json_file(args.receipt), load_keys_from_json(keys_doc)
        options = {"expected_workspace_id": args.workspace_id,
            "trusted_key_fingerprints": set(args.trusted_key_fingerprint)}
        # Authenticate receipt evidence before inspecting optional artifacts.
        report = replay_policy(receipt, keys, **options)
        try:
            artifacts = {key: _load_json_file(path) if path else None for key, path in (
                ("manifest", args.manifest), ("definition", args.definition), ("input_document", args.input))}
        except (OSError, ValueError, RecursionError, VerificationError):
            report["diagnostic"] = "replay_artifact_unavailable_or_invalid"
        else:
            report = replay_policy(receipt, keys, **options, **artifacts,
                opa_binary=args.opa_binary, rego_file=args.rego_file, runtime_artifact=args.runtime_artifact)
        print(json.dumps(report))
        return {"matched": 0, "mismatched": 3, "not_checked": 4}[report["policy_replay"]]
    except (OSError, ValueError, RecursionError, VerificationError) as exc:
        print(f"INVALID receipt evidence: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
