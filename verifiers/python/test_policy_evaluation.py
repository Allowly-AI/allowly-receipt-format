"""Wire-5 evidence checks and separate official-OPA replay regressions."""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from allowly_receipt_format import VerificationError, canonicalize, load_keys_from_json, verify_receipt
from allowly_receipt_format import policy as native_policy
from allowly_receipt_format.policy import main, replay_policy

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "vectors/policy/profile-v1.json").read_text())
MANIFEST = json.loads((ROOT / "vectors/policy/engine-manifest.json").read_text())
KEYS = load_keys_from_json(VECTORS["public_keys"])
NOW = datetime(2026, 12, 31, tzinfo=timezone.utc)
OPTIONS = {"expected_workspace_id": VECTORS["expected_workspace_id"],
    "trusted_key_fingerprints": set(VECTORS["trusted_key_fingerprints"]), "now": NOW}
PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"allowly-opa-wire5-fixture").digest())


def signed(receipt):
    payload = {key: value for key, value in receipt.items() if key != "signature"}
    return {**payload, "signature": base64.urlsafe_b64encode(PRIVATE_KEY.sign(canonicalize(payload))).decode().rstrip("=")}


def replay(case, **overrides):
    artifacts = {"manifest": MANIFEST, "definition": case["definition"], "input_document": case["input"],
        "opa_binary": "/missing/opa", "rego_file": "/missing/module", "runtime_artifact": "/missing/runtime"}
    artifacts.update(overrides)
    return replay_policy(case["receipt"], KEYS, **OPTIONS, **artifacts)


@pytest.mark.parametrize("case", VECTORS["signature_cases"], ids=lambda case: case["name"])
def test_new_evidence_signature(case):
    verify_receipt(case["receipt"], KEYS, **OPTIONS)
    result = replay_policy(case["receipt"], KEYS, **OPTIONS)
    assert result["signature_verified"] is True
    assert result["policy_replay"] == "not_checked"
    assert result["transactional_enforcement"] == result["witnessed_execution"] == "not_checked"


@pytest.mark.parametrize("case", VECTORS["tampered_cases"], ids=lambda case: case["name"])
def test_all_new_commitments_are_signed(case):
    with pytest.raises(VerificationError, match="signature verification failed"):
        verify_receipt(case["receipt"], KEYS, **OPTIONS)


def test_input_hash_is_complete_and_preserves_missing_null_and_order():
    case = copy.deepcopy(VECTORS["signature_cases"][0])
    input_document = copy.deepcopy(case["input"])
    input_document["context"]["private_extra"] = None
    assert replay(case, input_document=input_document)["diagnostic"] == "policy_input_digest_mismatch"
    definition = copy.deepcopy(case["definition"])
    definition["default_expiry_days"] = 5
    assert replay(case, definition=definition)["diagnostic"] == "policy_definition_digest_mismatch"
    assert canonicalize({"x": None}) != canonicalize({})
    assert canonicalize({"x": [1, 2]}) != canonicalize({"x": [2, 1]})
    assert canonicalize({"a": 1, "b": 2}) == canonicalize({"b": 2, "a": 1})


def test_manifest_is_complete_and_authenticated_before_binary_execution():
    case = VECTORS["signature_cases"][0]
    manifest = copy.deepcopy(MANIFEST)
    manifest["runtime"]["artifact_sha256"] = "a" * 64
    assert replay(case, manifest=manifest)["diagnostic"] == "engine_manifest_digest_mismatch"
    manifest = {"schema": "allowly.engine.v1"}
    case = copy.deepcopy(case)
    case["receipt"]["engine_version"] = "sha256:" + hashlib.sha256(canonicalize(manifest)).hexdigest()
    case["receipt"] = signed(case["receipt"])
    assert replay(case, manifest=manifest)["policy_replay"] == "not_checked"


@pytest.mark.parametrize("platform", ["darwin/arm64", "linux/arm64", "linux/amd64"])
def test_exact_fixed_official_platform_manifest(platform):
    manifest = copy.deepcopy(MANIFEST)
    manifest["evaluator"]["opa"] = {"version": "1.21.1", "platform": platform,
                                    **native_policy.OPA_ARTIFACTS[platform]}
    native_policy._check_manifest(manifest)
    original = copy.deepcopy(manifest)
    for field, value in [("platform", "linux/unknown"), ("artifact_sha256", "a" * 64), ("commit", "normalized-commit"), ("version", "1.21.0")]:
        manifest = copy.deepcopy(original)
        manifest["evaluator"]["opa"][field] = value
        with pytest.raises(ValueError, match="official OPA artifact"):
            native_policy._check_manifest(manifest)
    if platform.startswith("linux/"):
        manifest = copy.deepcopy(original)
        manifest["evaluator"]["opa"]["commit"] = native_policy.OPA_COMMIT
        with pytest.raises(ValueError, match="official OPA artifact"):
            native_policy._check_manifest(manifest)


@pytest.mark.parametrize("system,machine,expected", [
    ("Darwin", "arm64", "darwin/arm64"), ("Linux", "aarch64", "linux/arm64"),
    ("Linux", "x86_64", "linux/amd64"), ("Windows", "ARM64", None),
])
def test_native_replay_host_platform_is_not_caller_configurable(monkeypatch, system, machine, expected):
    monkeypatch.setattr(native_policy.platform, "system", lambda: system)
    monkeypatch.setattr(native_policy.platform, "machine", lambda: machine)
    assert native_policy._host_platform() == expected


def test_workspace_and_pin_checks_precede_missing_artifacts():
    case = VECTORS["signature_cases"][0]
    with pytest.raises(VerificationError, match="workspace_id mismatch"):
        replay_policy(case["receipt"], KEYS, **{**OPTIONS, "expected_workspace_id": "another-workspace"})
    with pytest.raises(VerificationError, match="fingerprints"):
        replay_policy(case["receipt"], KEYS, **{**OPTIONS, "trusted_key_fingerprints": set()})
    with pytest.raises(VerificationError, match="not trusted"):
        replay_policy(case["receipt"], KEYS, **{**OPTIONS, "trusted_key_fingerprints": {"sha256:" + "a" * 64}})


def cli_files(case, tmp_path):
    paths = {}
    for name, value in (("receipt", case["receipt"]), ("keys", VECTORS["public_keys"]),
            ("manifest", MANIFEST), ("definition", case["definition"]), ("input", case["input"])):
        path = tmp_path / (name + ".json")
        path.write_text(json.dumps(value))
        paths[name] = str(path)
    args = [paths["receipt"], paths["keys"], "--workspace-id", VECTORS["expected_workspace_id"],
        "--trusted-key-fingerprint", VECTORS["trusted_key_fingerprints"][0]]
    return paths, args


def test_cli_authenticates_first_and_does_not_expose_private_artifacts(tmp_path, capsys):
    case = copy.deepcopy(VECTORS["signature_cases"][0])
    paths, args = cli_files(case, tmp_path)
    assert main(args) == 4
    report = json.loads(capsys.readouterr().out)
    assert report["policy_replay"] == "not_checked"
    assert report["signature_verified"] is True
    Path(paths["input"]).write_text("PRIVATE-MALFORMED-INPUT")
    assert main(args + ["--input", paths["input"]]) == 4
    output = capsys.readouterr()
    assert json.loads(output.out)["diagnostic"] == "replay_artifact_unavailable_or_invalid"
    assert "PRIVATE-MALFORMED-INPUT" not in output.out + output.err

    case["receipt"]["policy_eval"]["result"]["decision"] = "deny"
    Path(paths["receipt"]).write_text(json.dumps(case["receipt"]))
    assert main(args + ["--input", paths["input"]]) == 1
    output = capsys.readouterr()
    assert not output.out
    assert "signature verification failed" in output.err


def test_real_opa_copy_and_cli_roundtrip(tmp_path, monkeypatch, capsys):
    paths = {key: os.getenv(env) for key, env in [
        ("opa_binary", "ALLOWLY_OPA_BINARY"), ("rego_file", "ALLOWLY_OPA_MODULE_FILE"),
        ("runtime_artifact", "ALLOWLY_OPA_RUNTIME_ARTIFACT")]}
    if not all(paths.values()):
        pytest.skip("supply checksum-pinned official OPA, retained Rego and runtime archive")
    original = tmp_path / "caller-opa"
    original.write_bytes(Path(paths["opa_binary"]).read_bytes())
    original.chmod(0o500)
    calls = []
    run = native_policy.subprocess.run

    def replace_caller_path(command, **options):
        checked_copy = Path(command[0])
        assert checked_copy != original
        assert hashlib.sha256(checked_copy.read_bytes()).hexdigest() == MANIFEST["evaluator"]["opa"]["artifact_sha256"]
        if not calls:
            original.chmod(0o600)
            original.write_bytes(b"replaced after binary digest verification")
        calls.append(command)
        return run(command, **options)

    monkeypatch.setattr(native_policy.subprocess, "run", replace_caller_path)
    result = replay(VECTORS["signature_cases"][0], **{**paths, "opa_binary": original})
    assert result["policy_replay"] == "matched", result
    assert len(calls) == 2 and calls[0][0] == calls[1][0]

    files, args = cli_files(VECTORS["signature_cases"][0], tmp_path)
    for name in ("manifest", "definition", "input"):
        args.extend(["--" + name, files[name]])
    for name, path in paths.items():
        args.extend(["--" + name.replace("_", "-"), path])
    assert main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["policy_replay"] == "matched"
    assert report["transactional_enforcement"] == report["witnessed_execution"] == "not_checked"


@pytest.mark.parametrize("case", VECTORS["signature_cases"], ids=lambda case: case["name"])
def test_real_official_opa_replay(case, tmp_path):
    paths = {key: os.getenv(env) for key, env in [
        ("opa_binary", "ALLOWLY_OPA_BINARY"), ("rego_file", "ALLOWLY_OPA_MODULE_FILE"),
        ("runtime_artifact", "ALLOWLY_OPA_RUNTIME_ARTIFACT")]}
    if not all(paths.values()):
        pytest.skip("supply checksum-pinned official OPA, retained Rego and runtime archive")
    result = replay(case, **paths)
    assert result["policy_replay"] == "matched", result
    assert result["transactional_enforcement"] == result["witnessed_execution"] == "not_checked"

    forged = copy.deepcopy(case)
    forged["receipt"]["policy_eval"]["result"]["decision"] = "allow" if case["receipt"]["policy_eval"]["result"]["decision"] == "deny" else "deny"
    forged["receipt"]["policy_eval"]["result"]["target"] = None
    forged["receipt"] = signed(forged["receipt"])
    assert replay(forged, **paths)["diagnostic"] == "provisional_result_mismatch"

    altered = tmp_path / "modified-artifact"
    altered.write_bytes(b"modified")
    assert replay(case, **{**paths, "rego_file": altered})["diagnostic"] == "rego_artifact_digest_mismatch"
    assert replay(case, **{**paths, "runtime_artifact": altered})["diagnostic"] == "runtime_artifact_digest_mismatch"
    assert replay(case, **{**paths, "opa_binary": altered})["diagnostic"] == "opa_artifact_digest_mismatch"
