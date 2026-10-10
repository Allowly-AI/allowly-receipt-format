"""Wire-5 evidence checks and separate official-OPA replay regressions."""
from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import tarfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from allowly_receipt_format import VerificationError, canonicalize, decode_receipt, jws_signing_input, jws_receipt, load_keys_from_json, verify_receipt
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
    return jws_receipt(receipt, "opa-fixture-key", PRIVATE_KEY.sign(jws_signing_input(receipt, "opa-fixture-key")))


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
    payload = decode_receipt(case["receipt"])
    payload["engine_version"] = "sha256:" + hashlib.sha256(canonicalize(manifest)).hexdigest()
    case["receipt"] = signed(payload)
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


@pytest.mark.parametrize("change", ["module", "metadata", "extra", "duplicate", "missing", "symlink"])
def test_bundle_content_pin_rejects_other_executable_contents(change):
    module = b"pinned module"
    metadata = MANIFEST["evaluator"]["bundle"]
    members = [(".manifest", json.dumps(metadata).encode()),
               (".signatures.json", b"{}"), ("policies/opa/allowly_basic.rego", module)]
    if change == "module":
        members[-1] = (members[-1][0], b"changed module")
    elif change == "metadata":
        members[0] = (".manifest", b'{"roots":["other"]}')
    elif change == "extra":
        members.append(("unexpected.rego", b"additional executable policy"))
    elif change == "duplicate":
        members.append(members[-1])
    elif change == "missing":
        members.pop(1)
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, value in members:
            member = tarfile.TarInfo(name)
            member.size = len(value)
            if change == "symlink" and name == ".manifest":
                member.type = tarfile.SYMTYPE
                member.linkname = "elsewhere"
            archive.addfile(member, io.BytesIO(value))
    assert native_policy._bundle_matches(output.getvalue(), metadata, module) is False


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

    payload = decode_receipt(case["receipt"])
    payload["policy_eval"]["result"]["decision"] = "deny"
    case["receipt"] = jws_receipt(payload, "opa-fixture-key", case["receipt"]["signature"])
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
    assert len(calls) == 3 and len({call[0] for call in calls}) == 1

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
    payload = decode_receipt(forged["receipt"])
    payload["policy_eval"]["result"]["decision"] = "allow" if payload["policy_eval"]["result"]["decision"] == "deny" else "deny"
    payload["policy_eval"]["result"]["target"] = None
    forged["receipt"] = signed(payload)
    assert replay(forged, **paths)["diagnostic"] == "provisional_result_mismatch"

    altered = tmp_path / "modified-artifact"
    altered.write_bytes(b"modified")
    assert replay(case, **{**paths, "rego_file": altered})["diagnostic"] == "rego_artifact_digest_mismatch"
    assert replay(case, **{**paths, "runtime_artifact": altered})["diagnostic"] == "runtime_artifact_digest_mismatch"
    assert replay(case, **{**paths, "opa_binary": altered})["diagnostic"] == "opa_artifact_digest_mismatch"


def test_stock_opa_rejects_bad_bundle_signature_even_with_rebound_manifest(tmp_path, monkeypatch):
    paths = {key: os.getenv(env) for key, env in [
        ("opa_binary", "ALLOWLY_OPA_BINARY"), ("rego_file", "ALLOWLY_OPA_MODULE_FILE"),
        ("runtime_artifact", "ALLOWLY_OPA_RUNTIME_ARTIFACT")]}
    if not all(paths.values()):
        pytest.skip("supply checksum-pinned official OPA, retained Rego and runtime archive")

    def read_tar(raw, mode):
        with tarfile.open(fileobj=io.BytesIO(raw), mode=mode) as archive:
            return {member.name: archive.extractfile(member).read() for member in archive.getmembers()}

    def pack_tar(files, mode):
        output = io.BytesIO()
        with tarfile.open(fileobj=output, mode=mode) as archive:
            for name, data in files.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
        return output.getvalue()

    manifest = copy.deepcopy(MANIFEST)
    files = read_tar(Path(paths["runtime_artifact"]).read_bytes(), "r:")
    bundle_path = manifest["evaluator"]["signed_bundle"]["path"]
    bundle = read_tar(files[bundle_path], "r:gz")
    signature_path = next(name for name in bundle if name.endswith(".signatures.json"))
    signatures = json.loads(bundle[signature_path])
    protected, payload, _ = signatures["signatures"][0].split(".")
    signatures["signatures"][0] = protected + "." + payload + "." + base64.urlsafe_b64encode(bytes(64)).decode().rstrip("=")
    bundle[signature_path] = json.dumps(signatures).encode()
    files[bundle_path] = pack_tar(bundle, "w:gz")
    manifest["evaluator"]["signed_bundle"]["artifact_sha256"] = hashlib.sha256(files[bundle_path]).hexdigest()
    altered_runtime = pack_tar(files, "w:")
    manifest["runtime"]["artifact_sha256"] = hashlib.sha256(altered_runtime).hexdigest()
    for member in manifest["runtime"]["files"]:
        member["sha256"] = hashlib.sha256(files[member["path"]]).hexdigest()
    artifact = tmp_path / "runtime.tar"
    artifact.write_bytes(altered_runtime)
    case = copy.deepcopy(VECTORS["signature_cases"][0])
    evidence = decode_receipt(case["receipt"])
    evidence["engine_version"] = "sha256:" + hashlib.sha256(canonicalize(manifest)).hexdigest()
    case["receipt"] = signed(evidence)
    commands = []
    run = native_policy.subprocess.run

    def record(command, **options):
        commands.append(command)
        return run(command, **options)

    monkeypatch.setattr(native_policy.subprocess, "run", record)
    result = replay(case, manifest=manifest, **{**paths, "runtime_artifact": artifact})
    assert result["policy_replay"] == "not_checked", result
    assert result["diagnostic"] == "invalid_replay_artifact_or_opa_result"
    assert [command[1] for command in commands] == ["version", "build"]
