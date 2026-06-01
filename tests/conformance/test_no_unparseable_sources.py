"""Every committed Python source under src/ must parse.

Finding: the tree carried unparseable files (truncated escaped-string blobs) that
were hidden from ruff/mypy via per-file excludes and silently dropped from
coverage. This is the non-skippable gate: a syntactically-broken committed source
fails the build instead of being excluded. (Checks git-TRACKED files, so local
untracked scratch files don't affect it — and neither can they hide a real one.)
"""

from __future__ import annotations

import ast
import subprocess
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]


def test_all_committed_python_sources_parse():
    # Prefer git-tracked files (so local untracked scratch can't trip the gate).
    # Fall back to globbing when not in a git work tree (e.g. an exported tarball
    # or `git archive` extract), where every present .py is by definition shipped.
    git = subprocess.run(["git", "ls-files", "src/"], cwd=_REPO, capture_output=True, text=True)
    if git.returncode == 0 and git.stdout.strip():
        py_files = [f for f in git.stdout.split() if f.endswith(".py")]
    else:
        py_files = [str(p.relative_to(_REPO)) for p in (_REPO / "src").rglob("*.py")]
    assert py_files, "expected Python sources under src/"

    broken = []
    for rel in py_files:
        try:
            ast.parse((_REPO / rel).read_text(encoding="utf-8"))
        except SyntaxError as e:
            broken.append(f"{rel}: {e}")

    assert not broken, "Unparseable committed Python sources (fix or remove them):\n" + "\n".join(broken)
