"""Changed-lines mutation gate for receipt-format verifiers.

CI uses the default `origin/main...HEAD` diff. Local hooks can narrow it, for
example `MUTATION_BASE=HEAD~1 python scripts/mutation_gate.py` in post-commit.
Prefer pre-push/post-commit over pre-commit because mutation tools edit files
or create temporary sandboxes.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


PYTHON_CRITICAL_PATHS = {
    "verifiers/python/src/allowly_receipt_format/verifier.py",
    "verifiers/python/verifier.py",
}
TYPESCRIPT_CRITICAL_PATHS = {
    "verifiers/typescript/verifier.ts",
}


def run(
    args: list[str],
    *,
    cwd: str | None = None,
    check: bool = True,
    capture: bool = False,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, check=check, text=True, capture_output=capture)


def critical_targets(base: str) -> tuple[list[str], list[str]]:
    changed = run(["git", "diff", "--name-only", f"{base}...HEAD"], capture=True).stdout.splitlines()
    python_targets = sorted(path for path in changed if path in PYTHON_CRITICAL_PATHS)
    typescript_targets = sorted(path for path in changed if path in TYPESCRIPT_CRITICAL_PATHS)
    return python_targets, typescript_targets


def refuse_dirty(paths: list[str]) -> int:
    if not paths:
        return 0
    dirty = run(["git", "status", "--porcelain", "--", *paths], capture=True).stdout
    if dirty.strip():
        print("Critical source files have uncommitted changes; refusing to run mutation tools:", file=sys.stderr)
        print(dirty, file=sys.stderr)
        return 2
    return 0


def find_mutmut() -> str | None:
    return (
        os.environ.get("MUTMUT_BIN")
        or shutil.which("mutmut")
        or (".venv/bin/mutmut" if Path(".venv/bin/mutmut").exists() else None)
        or ("/tmp/mutmut-venv/bin/mutmut" if Path("/tmp/mutmut-venv/bin/mutmut").exists() else None)
    )


def python_gate(base: str, targets: list[str]) -> int:
    mutmut = find_mutmut()
    if not mutmut:
        print("mutmut is not installed; run `python -m pip install 'mutmut<3'` first", file=sys.stderr)
        return 2

    cache = Path(".mutmut-cache")
    if cache.exists():
        if cache.is_dir():
            shutil.rmtree(cache)
        else:
            cache.unlink()

    with tempfile.NamedTemporaryFile("w", suffix=".patch", delete=False) as patch:
        patch.write(run(["git", "diff", f"{base}...HEAD", "--", *targets], capture=True).stdout)
        patch_path = patch.name

    print("Running Python mutation gate for:")
    for target in targets:
        print(f"  {target}")

    python = shlex.quote(os.environ.get("PYTHON_BIN", sys.executable))
    runner = os.environ.get(
        "PYTHON_MUTATION_RUNNER",
        f"PYTHONPATH=verifiers/python/src {python} verifiers/python/test_vectors.py test-vectors.json && "
        f"PYTHONPATH=verifiers/python/src {python} verifiers/python/test_exception_types.py test-vectors.json && "
        f"PYTHONPATH=verifiers/python/src {python} verifiers/python/test_pseudonym_refs.py",
    )
    result = run(
        [
            mutmut,
            "run",
            "--use-patch-file",
            patch_path,
            "--tests-dir",
            "verifiers/python/",
            "--runner",
            runner,
            "--simple-output",
            "--no-progress",
        ],
        check=False,
    )
    survivors = run([mutmut, "result-ids", "survived"], check=False, capture=True)
    if survivors.returncode != 0:
        sys.stderr.write(survivors.stderr)
        return result.returncode or survivors.returncode
    survivor_ids = survivors.stdout.split()
    if survivor_ids:
        print("Surviving Python verifier mutants:")
        print("\n".join(survivor_ids))
        run([mutmut, "results"], check=False)
        return 1
    if result.returncode not in (0, 2, 10):
        return result.returncode
    print("Python mutation gate passed.")
    return 0


def typescript_gate(targets: list[str]) -> int:
    print("Running TypeScript mutation gate for:")
    for target in targets:
        print(f"  {target}")

    command = os.environ.get("STRYKER_CMD")
    if command:
        return run(shlex.split(command), cwd="verifiers/typescript", check=False).returncode

    return run(
        [
            "npx",
            "--yes",
            "--package",
            "@stryker-mutator/core",
            "stryker",
            "run",
            "stryker.conf.cjs",
        ],
        cwd="verifiers/typescript",
        check=False,
    ).returncode


def main() -> int:
    base = os.environ.get("MUTATION_BASE", "origin/main")
    python_targets, typescript_targets = critical_targets(base)
    targets = python_targets + typescript_targets
    if not targets:
        print("No critical receipt verifier source changes; skipping mutation gate.")
        return 0

    dirty_status = refuse_dirty(targets)
    if dirty_status:
        return dirty_status

    if python_targets:
        status = python_gate(base, python_targets)
        if status:
            return status
    if typescript_targets:
        status = typescript_gate(typescript_targets)
        if status:
            return status

    print("Receipt-format mutation gate passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
