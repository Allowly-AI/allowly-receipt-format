"""Keep the maintained wire-5 trust checks on CI and publication paths."""
from pathlib import Path

import pytest


WORKFLOWS = Path(__file__).resolve().parents[1] / ".github/workflows"


@pytest.mark.parametrize("name", ["verify.yml", "publish-python.yml"])
def test_python_workflows_run_jws_and_opa_tests_before_build(name):
    workflow = (WORKFLOWS / name).read_text()
    gate = "python -m pytest -q test_jws.py test_policy_evaluation.py"
    assert "pip install -e verifiers/python pytest" in workflow
    assert gate in workflow
    assert workflow.index(gate) < workflow.index("python -m build")


def test_typescript_ci_runs_exact_jws_interop_before_packaging():
    workflow = (WORKFLOWS / "verify.yml").read_text()
    assert workflow.count("node dist/test_jws.js ../../test-vectors.json") == 2


def test_typescript_publication_runs_complete_maintained_test_command():
    workflow = (WORKFLOWS / "publish-typescript.yml").read_text()
    assert workflow.index("run: npm test") < workflow.index("run: npm publish")


def test_mutation_waiver_is_limited_to_the_approved_release_branch():
    workflow = (WORKFLOWS / "verify.yml").read_text()
    assert "if: github.event_name == 'pull_request' && github.head_ref != 'release/5.0.0'" in workflow
    assert "run: python scripts/mutation_gate.py" in workflow
