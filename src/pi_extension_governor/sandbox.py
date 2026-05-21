"""Sandboxed Extension Runtime.

Bounded execution environment for external extensions.
CPU ceilings, memory ceilings, deterministic IO boundaries.
No direct orchestrator access. No state mutation privileges.
"""

from __future__ import annotations

import hashlib
import json
import resource
import signal
import traceback
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
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


@contextmanager
def _cpu_timeout(seconds: int):
    """Context manager for CPU time limit using SIGALRM."""
    def _handler(signum, frame):
        raise TimeoutError(f"CPU time limit exceeded: {seconds}s")
    old_handler = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)


class SandboxedExtensionRuntime:
    """Deterministic sandbox for extension execution.

    Runs extensions in a controlled subprocess-like environment
    with strict resource ceilings.
    """

    def __init__(
        self,
        cpu_ms_max: int = 1000,
        memory_mb_max: int = 128,
        output_size_max: int = 1024 * 1024,
        allowed_modules: Optional[List[str]] = None,
        read_only_dirs: Optional[List[Path]] = None,
    ) -> None:
        self.cpu_ms_max = cpu_ms_max
        self.memory_mb_max = memory_mb_max
        self.output_size_max = output_size_max
        self.allowed_modules = allowed_modules or []
        self.read_only_dirs = read_only_dirs or []

    def execute(self, extension_entrypoint: str, inputs: Dict[str, Any]) -> SandboxResult:
        """Execute an extension with bounded resources.

        WARNING: This executes Python code. In production, this MUST run
        inside a proper sandbox (seccomp, namespaces, or containers).
        This implementation provides resource ceilings as a baseline.
        """
        import time
        start_time = time.time()
        memory_peak = 0
        stdout_lines: List[str] = []
        stderr_lines: List[str] = []
        output: Optional[Dict[str, Any]] = None
        status = "SUCCESS"
        exc_traceback: Optional[str] = None

        try:
            # Set memory limit (soft limit only — hard limit requires root)
            max_bytes = self.memory_mb_max * 1024 * 1024
            try:
                resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))
            except (ValueError, OSError):
                pass  # May fail in some environments

            # CPU time limit via alarm
            with _cpu_timeout(max(1, self.cpu_ms_max // 1000)):
                # Execute in restricted namespace
                safe_globals = {
                    "__builtins__": {
                        "len": len, "range": range, "enumerate": enumerate,
                        "zip": zip, "map": map, "filter": filter,
                        "isinstance": isinstance, "type": type,
                        "print": lambda *args: stdout_lines.append(" ".join(str(a) for a in args)),
                        "str": str, "int": int, "float": float, "bool": bool,
                        "list": list, "dict": dict, "tuple": tuple, "set": set,
                        "sorted": sorted, "reversed": reversed,
                        "sum": sum, "min": min, "max": max,
                        "abs": abs, "round": round,
                        "hashlib": __import__("hashlib"),
                        "json": __import__("json"),
                        "datetime": __import__("datetime"),
                    },
                    "INPUTS": inputs,
                    "OUTPUT": {},
                }
                safe_locals: Dict[str, Any] = {}

                # Compile and execute
                code = compile(extension_entrypoint, "<sandbox>", "exec")
                exec(code, safe_globals, safe_locals)

                output = safe_locals.get("OUTPUT", safe_globals.get("OUTPUT", {}))
                if not isinstance(output, dict):
                    raise TypeError(f"Extension must output dict, got {type(output)}")

                # Check output size
                output_bytes = len(json.dumps(output, default=str).encode())
                if output_bytes > self.output_size_max:
                    status = "REJECTED"
                    output = {"error": f"Output size {output_bytes} exceeds max {self.output_size_max}"}

        except TimeoutError:
            status = "TIMEOUT"
            output = {"error": f"Execution exceeded {self.cpu_ms_max}ms CPU limit"}
        except MemoryError:
            status = "MEMORY_EXCEEDED"
            output = {"error": f"Memory exceeded {self.memory_mb_max}MB limit"}
        except Exception as e:
            status = "EXCEPTION"
            output = {"error": str(e), "error_type": type(e).__name__}
            exc_traceback = traceback.format_exc()

        execution_time_ms = int((time.time() - start_time) * 1000)
        output_hash = hashlib.sha256(
            json.dumps(output, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest() if output else ""

        return SandboxResult(
            status=status,
            output=output,
            output_hash=output_hash,
            execution_time_ms=execution_time_ms,
            memory_peak_mb=memory_peak,
            stdout_captured="\n".join(stdout_lines),
            stderr_captured="\n".join(stderr_lines),
            traceback=exc_traceback,
        )

    def verify_determinism(self, extension_entrypoint: str, inputs: Dict[str, Any], runs: int = 3) -> bool:
        """Run identical inputs multiple times. Same input -> same output hash required."""
        hashes: List[str] = []
        for _ in range(runs):
            result = self.execute(extension_entrypoint, inputs)
            if result.status != "SUCCESS":
                return False
            hashes.append(result.output_hash)
        return len(set(hashes)) == 1
