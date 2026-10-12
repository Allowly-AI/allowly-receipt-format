"""Regression checks for release-runner arguments; no source is mutated here."""

import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from scripts import mutation_gate as gate


def test_policy_replay_changes_are_critical_python_mutation_targets(monkeypatch):
    target = "verifiers/python/src/allowly_receipt_format/policy.py"
    calls = []

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args, 0, stdout=f"{target}\nREADME.md\n", stderr="")

    monkeypatch.setattr(gate, "run", run)
    assert gate.critical_targets("release-base") == ([target], [])
    assert calls == [(["git", "diff", "--name-only", "release-base...HEAD"], {"capture": True})]


def test_python_gate_names_sources_and_runs_complete_suite_through_shell(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="1" if args[1:] == ["result-ids", "killed"] else "", stderr="")

    monkeypatch.setattr(gate, "run", run)
    monkeypatch.setattr(gate, "find_mutmut", lambda: "mutmut")
    monkeypatch.delenv("PYTHON_MUTATION_RUNNER", raising=False)
    target = "verifiers/python/src/allowly_receipt_format/verifier.py"
    assert gate.python_gate("base", [target]) == 0
    command = next(args for args in calls if args[:2] == ["mutmut", "run"])
    assert command[command.index("--paths-to-mutate") + 1] == target
    runner = shlex.split(command[command.index("--runner") + 1])
    assert runner[:2] == ["sh", "-c"]
    assert "test_jws.py" in runner[2]
    assert "test_policy_evaluation.py" in runner[2]
    assert "test_seal.py" in runner[2]


@pytest.mark.parametrize("exit_code", [0, 1, 2, 5])
def test_python_mutation_runner_normalizes_all_failures(monkeypatch, exit_code):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="1" if args[1:] == ["result-ids", "killed"] else "", stderr="")

    monkeypatch.setattr(gate, "run", run)
    monkeypatch.setattr(gate, "find_mutmut", lambda: "mutmut")
    monkeypatch.setenv("PYTHON_MUTATION_RUNNER",
                       f"{shlex.quote(sys.executable)} -c {shlex.quote(f'raise SystemExit({exit_code})')}")
    assert gate.python_gate("base", ["verifiers/python/src/allowly_receipt_format/verifier.py"]) == 0
    command = next(args for args in calls if args[:2] == ["mutmut", "run"])
    runner = shlex.split(command[command.index("--runner") + 1])
    assert subprocess.run(runner).returncode == (0 if exit_code == 0 else 1)


@pytest.mark.parametrize("counts,tool_status,expected", [
    ({"killed": 80, "survived": 20}, 2, 0),
    ({"killed": 79, "survived": 21}, 2, 1),
    ({"killed": 80, "suspicious": 20}, 8, 0),
    ({"killed": 100, "untested": 1}, 0, 2),
    ({"killed": 100, "skipped": 1}, 0, 2),
    ({"killed": 100, "timeout": 1}, 4, 4),
    ({"killed": 100}, 1, 1),
    ({}, 0, 2),
])
def test_python_mutation_gate_requires_complete_raw_80_percent(monkeypatch, counts, tool_status, expected):
    def run(args, **kwargs):
        if args[:2] == ["mutmut", "run"]:
            return subprocess.CompletedProcess(args, tool_status)
        status = args[-1]
        return subprocess.CompletedProcess(args, 0, stdout=" ".join(str(i) for i in range(counts.get(status, 0))), stderr="")

    monkeypatch.setattr(gate, "run", run)
    monkeypatch.setattr(gate, "find_mutmut", lambda: "mutmut")
    assert gate.python_gate("base", ["verifiers/python/src/allowly_receipt_format/verifier.py"]) == expected


def test_browser_baseline_failure_blocks_typescript_mutation(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 7)

    monkeypatch.setattr(gate, "run", run)
    assert gate.typescript_gate(["verifiers/typescript/verifier.ts"]) == 7
    assert calls == [["npm", "test"]]


@pytest.mark.parametrize("raw_status, classified_status", [(0, 0), (1, 0), (0, 1), (1, 1), (1, 2)])
def test_typescript_gate_requires_fresh_classified_report(monkeypatch, tmp_path, raw_status, classified_status):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STRYKER_CMD", raising=False)
    report = Path("verifiers/typescript/reports/mutation/mutation.json")
    report.parent.mkdir(parents=True)
    report.write_text("stale report")
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[0].endswith("stryker"):
            assert not report.exists(), "a prior report must never satisfy this run"
            report.write_text("fresh report")
            return subprocess.CompletedProcess(args, raw_status)
        if args[:2] == ["node", "scripts/mutation_report_gate.cjs"]:
            assert report.read_text() == "fresh report"
            return subprocess.CompletedProcess(args, classified_status)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(gate, "run", run)
    assert gate.typescript_gate(["verifiers/typescript/verifier.ts"]) == (classified_status or raw_status)
    assert calls[0] == ["npm", "test"]
    assert calls[1] == ["node", "--test", "scripts/test_mutation_report_gate.cjs"]
    assert calls[2] == ["./node_modules/.bin/stryker", "run", "stryker.conf.cjs",
                        "--reporters", "json", "--concurrency", "2", "--timeoutMS", "20000"]
    assert calls[3] == ["node", "scripts/mutation_report_gate.cjs", str(report)]


def test_typescript_gate_refuses_missing_fresh_report(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STRYKER_CMD", raising=False)
    report = Path("verifiers/typescript/reports/mutation/mutation.json")
    report.parent.mkdir(parents=True)
    report.write_text("stale report")
    monkeypatch.setattr(gate, "run", lambda args, **kwargs: subprocess.CompletedProcess(args, 1 if args[0].endswith("stryker") else 0))
    assert gate.typescript_gate(["verifiers/typescript/verifier.ts"]) == 2
    assert not report.exists()


def test_typescript_tool_failure_cannot_be_overridden_by_report(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("STRYKER_CMD", raising=False)
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[0].endswith("stryker"):
            report = Path("verifiers/typescript/reports/mutation/mutation.json")
            report.parent.mkdir(parents=True)
            report.write_text("fresh report")
            return subprocess.CompletedProcess(args, 7)
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(gate, "run", run)
    assert gate.typescript_gate(["verifiers/typescript/verifier.ts"]) == 7
    assert len(calls) == 3
