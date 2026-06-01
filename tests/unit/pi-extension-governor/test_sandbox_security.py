"""Security regression tests for the extension sandbox + static inspector.

These encode the two demonstrated critical findings:
  1. The "sandbox" ran untrusted code in-process via exec() with a fake
     __builtins__ — escapable to full RCE (read /etc/passwd, run shell).
  2. The static inspector is a name-blocklist that rated the escape 100/100 safe.

Fix posture (chosen): FAIL CLOSED. execute() refuses to run untrusted code by
default; only an explicit opt-in runs it in an isolated subprocess with a
stripped environment + enforced limits + hard kill. The inspector additionally
rejects the indirect-access patterns the escape relies on.
"""

from __future__ import annotations

import os
from pathlib import Path

from pi_extension_governor.inspector import (
    CapabilityClassification,
    StaticCapabilityInspector,
)
from pi_extension_governor.sandbox import SandboxedExtensionRuntime, _isolated_child_env

# The classic subclass-traversal escape: reaches the real builtins (and os) without
# ever naming `import os` / eval / subprocess — so a name-blocklist misses it.
ESCAPE_SUBCLASS = (
    "for sub in type('').__mro__[-1].__subclasses__():\n"
    "    if sub.__name__ == 'catch_warnings':\n"
    "        bi = sub()._module.__builtins__\n"
    "        OUTPUT = {'pwned': bi['__import__']('os').getcwd()}\n"
)

# The module-injection escape demonstrated in the audit: the injected real `json`
# module leaks the full unrestricted builtins via its __globals__.
ESCAPE_GLOBALS = "OUTPUT = {'pwned': json.dumps.__globals__['__builtins__']['__import__']('os').getcwd()}"

BENIGN = "OUTPUT = {'artifact_type': 'SemanticIRTrace', 'payload': {'endpoints': 3}}"


def _inspect_source(source: str, tmp_path: Path) -> set:
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "ext.py").write_text(source)
    inspector = StaticCapabilityInspector()
    report = inspector.inspect_package(pkg, "h")
    return report.classifications


# ── Inspector: must reject the indirect-access escape patterns ─────────────────


def test_inspector_rejects_subclass_traversal_escape(tmp_path) -> None:
    classifications = _inspect_source(ESCAPE_SUBCLASS, tmp_path)
    assert CapabilityClassification.REJECTED in classifications


def test_inspector_rejects_dunder_globals_escape(tmp_path) -> None:
    classifications = _inspect_source(ESCAPE_GLOBALS, tmp_path)
    assert CapabilityClassification.REJECTED in classifications


def test_inspector_still_passes_benign_code(tmp_path) -> None:
    # Guard against false positives: ordinary code must stay safe.
    classifications = _inspect_source("def add(a, b):\n    return a + b\n", tmp_path)
    assert CapabilityClassification.DETERMINISTIC_SAFE in classifications
    assert CapabilityClassification.REJECTED not in classifications


# ── Sandbox: fail closed by default ────────────────────────────────────────────


def test_sandbox_refuses_escape_by_default_without_executing(tmp_path) -> None:
    rt = SandboxedExtensionRuntime()  # no opt-in
    result = rt.execute(ESCAPE_GLOBALS, {})
    assert result.status == "REJECTED"
    # The crucial guarantee: the code did NOT run, so nothing was exfiltrated.
    assert "pwned" not in (result.output or {})


def test_sandbox_refuses_benign_by_default(tmp_path) -> None:
    rt = SandboxedExtensionRuntime()
    result = rt.execute(BENIGN, {})
    assert result.status == "REJECTED"


# ── Sandbox: opt-in path still works for benign code, in isolation ─────────────


def test_sandbox_opt_in_executes_benign() -> None:
    rt = SandboxedExtensionRuntime(allow_execution=True)
    result = rt.execute(BENIGN, {})
    assert result.status == "SUCCESS"
    assert result.output is not None
    assert result.output["payload"]["endpoints"] == 3


def test_isolated_child_env_strips_parent_secrets() -> None:
    # The opt-in executor must not expose the parent's environment (secrets)
    # to the child process running untrusted code.
    os.environ["PI_AUDIT_SECRET_PROBE"] = "do-not-leak"
    try:
        env = _isolated_child_env()
        assert "PI_AUDIT_SECRET_PROBE" not in env
        # And it isn't smuggled in under any other key/value.
        assert "do-not-leak" not in env.values()
    finally:
        del os.environ["PI_AUDIT_SECRET_PROBE"]
