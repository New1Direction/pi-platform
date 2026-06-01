"""Sandboxed Extension Runtime.

SECURITY POSTURE — FAIL CLOSED.

In-process ``exec()`` with a restricted ``__builtins__`` is NOT a security
boundary. It is escapable to full RCE: untrusted code can reach the real,
unrestricted builtins through the object graph (e.g.
``type("").__mro__[-1].__subclasses__()`` or ``obj.__globals__["__builtins__"]``)
without ever naming ``import os`` / ``eval`` / ``subprocess``. The previous
implementation also injected real ``json``/``datetime`` modules, handing the
attacker a direct pivot.

This runtime therefore refuses to execute untrusted code by default. Execution
must be explicitly enabled (constructor flag or ``PI_EXTENSION_ALLOW_CODE_EXECUTION``
env var). When enabled, the extension runs in a **separate, isolated subprocess**
with:

  * a stripped environment — the parent's secrets (API keys, JWT secrets, cloud
    credentials) are never inherited (see :func:`_isolated_child_env`);
  * isolated-interpreter mode (``python -I``) — no inherited PYTHON* vars, no
    cwd/user-site on ``sys.path``;
  * enforced memory (RLIMIT_AS) and CPU/wall limits, plus a hard parent-side
    wall-clock kill the child cannot disable;
  * no shared Python object graph with the orchestrator.

This is a real boundary improvement over in-process exec, but it is still NOT a
complete OS-level sandbox (there is no seccomp/network jail). For untrusted code
in production, run the child under seccomp / gVisor / a locked-down,
network-isolated container.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path  # noqa: F401  (kept for the public type hints below)
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class SandboxResult:
    status: str  # SUCCESS, TIMEOUT, MEMORY_EXCEEDED, EXCEPTION, REJECTED
    output: Optional[Dict[str, Any]]
    output_hash: str
    execution_time_ms: int
    memory_peak_mb: int
    stdout_captured: str
    stderr_captured: str
    traceback: Optional[str]


class SandboxRuntimeError(Exception):
    pass


# Operators must explicitly opt in to executing untrusted extension code.
# Unset / falsey => fail closed (no execution).
_ALLOW_EXEC_ENV = "PI_EXTENSION_ALLOW_CODE_EXECUTION"


def _execution_enabled(explicit: Optional[bool]) -> bool:
    if explicit is not None:
        return explicit
    return os.getenv(_ALLOW_EXEC_ENV, "").strip().lower() in ("1", "true", "yes", "on")


def _isolated_child_env() -> Dict[str, str]:
    """Minimal environment handed to the extension subprocess.

    Deliberately does NOT inherit the parent's environment, so secrets present
    in ``os.environ`` (API keys, JWT secrets, cloud credentials) are invisible to
    untrusted extension code. Only a minimal, non-sensitive baseline is provided.
    """
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


# Trusted bootstrap executed in the child via ``python -I -c``. It reads a JSON
# request from stdin, applies resource limits, runs the (untrusted) extension
# source under a restricted namespace, and writes a JSON result to stdout. The
# restricted namespace is one (defeatable) layer; the real containment is the
# isolated process + stripped env + rlimits + hard parent kill.
_CHILD_RUNNER = r"""
import json, sys, signal, traceback
try:
    import resource
except Exception:
    resource = None


def _main():
    req = json.load(sys.stdin)
    source = req["source"]
    inputs = req.get("inputs") or {}
    cpu_seconds = int(req.get("cpu_seconds", 1))
    memory_bytes = int(req.get("memory_bytes", 0))
    output_size_max = int(req.get("output_size_max", 1048576))

    if resource is not None and memory_bytes > 0:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
        except (ValueError, OSError):
            pass

    def _alarm(signum, frame):
        raise TimeoutError("cpu/wall time limit exceeded")

    try:
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(max(1, cpu_seconds))
    except (ValueError, OSError, AttributeError):
        pass

    stdout_lines = []
    safe_builtins = {
        "len": len, "range": range, "enumerate": enumerate, "zip": zip,
        "map": map, "filter": filter, "isinstance": isinstance, "type": type,
        "print": lambda *a: stdout_lines.append(" ".join(str(x) for x in a)),
        "str": str, "int": int, "float": float, "bool": bool, "list": list,
        "dict": dict, "tuple": tuple, "set": set, "sorted": sorted,
        "reversed": reversed, "sum": sum, "min": min, "max": max,
        "abs": abs, "round": round,
    }
    g = {"__builtins__": safe_builtins, "INPUTS": inputs, "OUTPUT": {}}
    loc = {}
    status = "SUCCESS"
    output = {}
    tb = None
    try:
        code = compile(source, "<extension>", "exec")
        exec(code, g, loc)
        output = loc.get("OUTPUT", g.get("OUTPUT", {}))
        if not isinstance(output, dict):
            raise TypeError("Extension must output dict, got %s" % type(output).__name__)
        serialized = json.dumps(output, sort_keys=True, separators=(",", ":"), default=str)
        if len(serialized.encode()) > output_size_max:
            status = "REJECTED"
            output = {"error": "Output size %d exceeds max %d" % (len(serialized.encode()), output_size_max)}
    except TimeoutError:
        status = "TIMEOUT"; output = {"error": "Execution exceeded CPU/time limit"}
    except MemoryError:
        status = "MEMORY_EXCEEDED"; output = {"error": "Memory limit exceeded"}
    except BaseException as e:  # untrusted code: never let it crash the reporter
        status = "EXCEPTION"; output = {"error": str(e), "error_type": type(e).__name__}
        tb = traceback.format_exc()
    finally:
        try:
            signal.alarm(0)
        except Exception:
            pass

    peak_mb = 0
    if resource is not None:
        try:
            peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            peak_mb = int(peak / (1024 * 1024)) if sys.platform == "darwin" else int(peak / 1024)
        except Exception:
            peak_mb = 0

    sys.stdout.write(json.dumps({
        "status": status,
        "output": output,
        "stdout": "\n".join(stdout_lines),
        "memory_peak_mb": peak_mb,
        "traceback": tb,
    }))


_main()
"""


class SandboxedExtensionRuntime:
    """Fail-closed runtime for extension execution.

    By default ``execute`` refuses to run untrusted code. Pass
    ``allow_execution=True`` (or set ``PI_EXTENSION_ALLOW_CODE_EXECUTION=1``) to
    run extensions in an isolated subprocess. See the module docstring for the
    isolation guarantees and their limits.
    """

    def __init__(
        self,
        cpu_ms_max: int = 1000,
        memory_mb_max: int = 128,
        output_size_max: int = 1024 * 1024,
        allowed_modules: Optional[List[str]] = None,
        read_only_dirs: Optional[List[Path]] = None,
        *,
        allow_execution: Optional[bool] = None,
    ) -> None:
        self.cpu_ms_max = cpu_ms_max
        self.memory_mb_max = memory_mb_max
        self.output_size_max = output_size_max
        self.allowed_modules = allowed_modules or []
        self.read_only_dirs = read_only_dirs or []
        self._allow_execution = allow_execution

    def _result(
        self,
        status: str,
        output: Optional[Dict[str, Any]],
        start_time: float,
        stdout: str = "",
        stderr: str = "",
        traceback_str: Optional[str] = None,
        memory_peak_mb: int = 0,
    ) -> SandboxResult:
        output_hash = (
            hashlib.sha256(json.dumps(output, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
            if output
            else ""
        )
        return SandboxResult(
            status=status,
            output=output,
            output_hash=output_hash,
            execution_time_ms=int((time.time() - start_time) * 1000),
            memory_peak_mb=memory_peak_mb,
            stdout_captured=stdout,
            stderr_captured=stderr,
            traceback=traceback_str,
        )

    def execute(self, extension_entrypoint: str, inputs: Dict[str, Any]) -> SandboxResult:
        """Execute an extension — but only if execution is explicitly enabled.

        Fail closed: with no opt-in, this REFUSES to run the code (the code is
        never compiled or executed in this process) and returns a REJECTED
        result. With opt-in, it runs in an isolated subprocess.
        """
        start_time = time.time()
        if not _execution_enabled(self._allow_execution):
            return self._result(
                "REJECTED",
                {
                    "error": (
                        "Extension code execution is disabled (fail-closed). In-process "
                        "exec() is not a security boundary. Set "
                        f"{_ALLOW_EXEC_ENV}=1 (or pass allow_execution=True) to run "
                        "extensions in an isolated subprocess."
                    )
                },
                start_time,
            )
        return self._execute_isolated(extension_entrypoint, inputs, start_time)

    def _execute_isolated(self, source: str, inputs: Dict[str, Any], start_time: float) -> SandboxResult:
        cpu_seconds = max(1, self.cpu_ms_max // 1000)
        payload = json.dumps(
            {
                "source": source,
                "inputs": inputs,
                "cpu_seconds": cpu_seconds,
                "memory_bytes": self.memory_mb_max * 1024 * 1024,
                "output_size_max": self.output_size_max,
            }
        )
        # Hard parent-side backstop the child cannot disable (e.g. if untrusted
        # code escapes the restricted namespace and cancels its own SIGALRM).
        wall_timeout = max(2.0, cpu_seconds + 2.0)
        try:
            proc = subprocess.run(
                [sys.executable, "-I", "-c", _CHILD_RUNNER],
                input=payload,
                env=_isolated_child_env(),
                capture_output=True,
                text=True,
                timeout=wall_timeout,
            )
        except subprocess.TimeoutExpired:
            return self._result("TIMEOUT", {"error": "Execution exceeded wall-clock limit"}, start_time)
        except Exception as e:  # spawn failure — fail closed, do not execute in-process
            return self._result("EXCEPTION", {"error": f"sandbox spawn failed: {e}"}, start_time)

        if not proc.stdout.strip():
            # Child produced no report: killed by the OS/a signal (e.g. hard
            # RLIMIT) before it could report. Treat as a failure, not a success.
            return self._result(
                "EXCEPTION",
                {"error": "extension subprocess produced no output", "stderr": proc.stderr[:500]},
                start_time,
                stderr=proc.stderr,
            )
        try:
            rep = json.loads(proc.stdout)
        except Exception:
            return self._result(
                "EXCEPTION",
                {"error": "could not parse sandbox output"},
                start_time,
                stdout=proc.stdout[:500],
                stderr=proc.stderr,
            )

        output = rep.get("output") or {}
        return self._result(
            rep.get("status", "EXCEPTION"),
            output,
            start_time,
            stdout=rep.get("stdout", ""),
            stderr=proc.stderr,
            traceback_str=rep.get("traceback"),
            memory_peak_mb=int(rep.get("memory_peak_mb", 0) or 0),
        )

    def verify_determinism(self, extension_entrypoint: str, inputs: Dict[str, Any], runs: int = 3) -> bool:
        """Run identical inputs multiple times. Same input -> same output hash required.

        Returns False if execution is disabled (fail-closed) since no SUCCESS run
        can be produced.
        """
        hashes: List[str] = []
        for _ in range(runs):
            result = self.execute(extension_entrypoint, inputs)
            if result.status != "SUCCESS":
                return False
            hashes.append(result.output_hash)
        return len(set(hashes)) == 1
