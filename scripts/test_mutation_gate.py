"""Regression checks for release-runner arguments; no source is mutated here."""

import shlex
import subprocess
from scripts import mutation_gate as gate


def test_python_gate_names_sources_and_runs_complete_suite_through_shell(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(gate, "run", run)
    monkeypatch.setattr(gate, "find_mutmut", lambda: "mutmut")
    monkeypatch.delenv("PYTHON_MUTATION_RUNNER", raising=False)
    target = "verifiers/python/src/allowly_receipt_format/verifier.py"
    assert gate.python_gate("base", [target]) == 0
    command = next(args for args in calls if args[:2] == ["mutmut", "run"])
    assert command[command.index("--paths-to-mutate") + 1] == target
    runner = shlex.split(command[command.index("--runner") + 1])
    assert runner[:2] == ["sh", "-c"]
    assert "test_policy_evaluation.py" in runner[2]
    assert "test_seal.py" in runner[2]


def test_browser_baseline_failure_blocks_typescript_mutation(monkeypatch):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 7)

    monkeypatch.setattr(gate, "run", run)
    assert gate.typescript_gate(["verifiers/typescript/verifier.ts"]) == 7
    assert calls == [["npm", "test"]]
