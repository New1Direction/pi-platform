"""Static Capability Inspector.

AST-based analysis of extension packages BEFORE execution.
Classifies packages into deterministic safety categories.
No execution of untrusted code.
"""

from __future__ import annotations

import ast
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class CapabilityClassification(str, Enum):
    DETERMINISTIC_SAFE = "deterministic_safe"
    NON_DETERMINISTIC = "non_deterministic"
    REPLAY_UNSAFE = "replay_unsafe"
    TELEMETRY_RISK = "telemetry_risk"
    POLICY_VIOLATION = "policy_violation"
    REJECTED = "rejected"


@dataclass(frozen=True)
class InspectionFinding:
    rule: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    detail: str
    file_path: str
    line_number: int


@dataclass(frozen=True)
class InspectionReport:
    package_hash: str
    classifications: Set[CapabilityClassification]
    findings: List[InspectionFinding]
    determinism_score: int  # 0-100
    replay_safety_score: int  # 0-100
    inspected_at: str
    inspection_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_hash": self.package_hash,
            "classifications": sorted([c.value for c in self.classifications]),
            "findings": [
                {
                    "rule": f.rule,
                    "severity": f.severity,
                    "detail": f.detail,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                }
                for f in self.findings
            ],
            "determinism_score": self.determinism_score,
            "replay_safety_score": self.replay_safety_score,
            "inspected_at": self.inspected_at,
            "inspection_hash": self.inspection_hash,
        }


class StaticCapabilityInspector:
    """Deterministic AST-based static analysis for extension safety."""

    # Dangerous imports that indicate non-deterministic or unsafe behavior
    DANGEROUS_IMPORTS: Set[str] = {
        "subprocess",
        "os.system",
        "socket",
        "urllib.request",
        "http.client",
        "requests",
        "ftplib",
        "smtplib",
        "eval",
        "exec",
        "compile",
        "__import__",
        "importlib",
        "ctypes",
        "mmap",
        "multiprocessing",
        "threading",
        "concurrent.futures",
        "asyncio.subprocess",
        "tempfile",
        "shutil",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.makedirs",
        "os.mkdir",
        "open",  # file write detection handled separately
        "pickle",
        "marshal",
        "shelve",
        "yaml.load",  # unsafe yaml loading
    }

    # Obfuscation indicators
    OBFUSCATION_PATTERNS: Set[str] = {
        "base64.b64decode",
        "base64.b64encode",
        "codecs.decode",
        "zlib.decompress",
        "gzip.decompress",
        "binascii.unhexlify",
        "string.translate",
        "chr(",
        "ord(",
    }

    # Telemetry / hidden communication patterns
    TELEMETRY_PATTERNS: Set[str] = {
        "telemetry",
        "tracking",
        "analytics",
        "metrics",
        "logs.send",
        "report_usage",
        "phone_home",
        "beacon",
    }

    def __init__(self, policy_banned_imports: Optional[Set[str]] = None) -> None:
        self.policy_banned_imports = policy_banned_imports or set()
        self.findings: List[InspectionFinding] = []
        self.classifications: Set[CapabilityClassification] = set()

    def inspect_package(self, package_path: Path, package_hash: str) -> InspectionReport:
        """Inspect all Python files in a package directory."""
        self.findings = []
        self.classifications = set()

        py_files = list(package_path.rglob("*.py"))
        if not py_files:
            self._add_finding("no_python_files", "HIGH", "Package contains no Python files for inspection", str(package_path), 0)
            self.classifications.add(CapabilityClassification.REJECTED)

        for py_file in py_files:
            self._inspect_file(py_file)

        # Score calculation
        determinism_score = self._compute_determinism_score()
        replay_safety_score = self._compute_replay_safety_score()

        # Classify based on findings
        self._apply_classification_rules()

        report_data = {
            "package_hash": package_hash,
            "findings": [
                {
                    "rule": f.rule,
                    "severity": f.severity,
                    "detail": f.detail,
                    "file_path": f.file_path,
                    "line_number": f.line_number,
                }
                for f in self.findings
            ],
            "classifications": sorted([c.value for c in self.classifications]),
            "determinism_score": determinism_score,
            "replay_safety_score": replay_safety_score,
        }
        inspection_hash = hashlib.sha256(
            json.dumps(report_data, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        return InspectionReport(
            package_hash=package_hash,
            classifications=self.classifications,
            findings=self.findings,
            determinism_score=determinism_score,
            replay_safety_score=replay_safety_score,
            inspected_at=datetime.now().isoformat(),
            inspection_hash=inspection_hash,
        )

    def _inspect_file(self, file_path: Path) -> None:
        try:
            source = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source)
        except SyntaxError as e:
            self._add_finding("syntax_error", "CRITICAL", f"Syntax error in {file_path}: {e}", str(file_path), e.lineno or 0)
            self.classifications.add(CapabilityClassification.REJECTED)
            return
        except Exception as e:
            self._add_finding("parse_error", "CRITICAL", f"Could not parse {file_path}: {e}", str(file_path), 0)
            self.classifications.add(CapabilityClassification.REJECTED)
            return

        for node in ast.walk(tree):
            self._check_imports(node, file_path)
            self._check_calls(node, file_path, source)
            self._check_eval_exec(node, file_path)
            self._check_file_operations(node, file_path)
            self._check_threading(node, file_path)

    def _check_imports(self, node: ast.AST, file_path: Path) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name
                if name in self.DANGEROUS_IMPORTS or name in self.policy_banned_imports:
                    self._add_finding("dangerous_import", "CRITICAL", f"Banned import: {name}", str(file_path), getattr(node, "lineno", 0))
                    self.classifications.add(CapabilityClassification.POLICY_VIOLATION)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            full_names = [f"{module}.{alias.name}" for alias in node.names]
            for name in full_names:
                if name in self.DANGEROUS_IMPORTS or name in self.policy_banned_imports:
                    self._add_finding("dangerous_import_from", "CRITICAL", f"Banned import: {name}", str(file_path), getattr(node, "lineno", 0))
                    self.classifications.add(CapabilityClassification.POLICY_VIOLATION)

    def _check_calls(self, node: ast.AST, file_path: Path, source: str) -> None:
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            if func_name:
                # Check obfuscation
                if any(func_name.endswith(p) or func_name == p for p in self.OBFUSCATION_PATTERNS):
                    self._add_finding("obfuscation_indicator", "HIGH", f"Obfuscation pattern: {func_name}", str(file_path), getattr(node, "lineno", 0))
                    self.classifications.add(CapabilityClassification.TELEMETRY_RISK)
                # Check telemetry
                if any(t in func_name.lower() for t in self.TELEMETRY_PATTERNS):
                    self._add_finding("telemetry_indicator", "HIGH", f"Telemetry pattern: {func_name}", str(file_path), getattr(node, "lineno", 0))
                    self.classifications.add(CapabilityClassification.TELEMETRY_RISK)
                # Check network
                if any(n in func_name for n in ["socket", "connect", "urlopen", "get", "post", "send"]):
                    self._add_finding("network_access", "CRITICAL", f"Network call: {func_name}", str(file_path), getattr(node, "lineno", 0))
                    self.classifications.add(CapabilityClassification.REPLAY_UNSAFE)
                # Check subprocess
                if "subprocess" in func_name or "Popen" in func_name or "system" in func_name:
                    self._add_finding("subprocess_spawn", "CRITICAL", f"Subprocess call: {func_name}", str(file_path), getattr(node, "lineno", 0))
                    self.classifications.add(CapabilityClassification.REJECTED)
                # Check reflection
                if func_name in ["eval", "exec", "compile"]:
                    self._add_finding("dynamic_execution", "CRITICAL", f"Dynamic execution: {func_name}", str(file_path), getattr(node, "lineno", 0))
                    self.classifications.add(CapabilityClassification.REJECTED)

    def _check_eval_exec(self, node: ast.AST, file_path: Path) -> None:
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            if func_name in ["eval", "exec", "compile"]:
                self._add_finding("dynamic_execution_direct", "CRITICAL", f"Direct {func_name}() call detected", str(file_path), getattr(node, "lineno", 0))
                self.classifications.add(CapabilityClassification.REJECTED)

    def _check_file_operations(self, node: ast.AST, file_path: Path) -> None:
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            write_ops = ["open", "os.remove", "os.unlink", "shutil.rmtree", "shutil.move", "os.rename"]
            if func_name and any(func_name.startswith(w) or func_name == w for w in write_ops):
                # Check if it's read-only mode
                if func_name == "open" and len(node.args) >= 2:
                    mode_arg = node.args[1]
                    if isinstance(mode_arg, ast.Constant) and isinstance(mode_arg.value, str):
                        if any(c in mode_arg.value for c in "wax+"):
                            self._add_finding("filesystem_mutation", "CRITICAL", f"File write mode: {mode_arg.value}", str(file_path), getattr(node, "lineno", 0))
                            self.classifications.add(CapabilityClassification.REPLAY_UNSAFE)
                elif func_name != "open":
                    self._add_finding("filesystem_mutation", "CRITICAL", f"Filesystem mutation: {func_name}", str(file_path), getattr(node, "lineno", 0))
                    self.classifications.add(CapabilityClassification.REPLAY_UNSAFE)

    def _check_threading(self, node: ast.AST, file_path: Path) -> None:
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node.func)
            if func_name and ("Thread" in func_name or "Process" in func_name or "Pool" in func_name or "Executor" in func_name):
                self._add_finding("thread_spawn", "HIGH", f"Thread/process spawn: {func_name}", str(file_path), getattr(node, "lineno", 0))
                self.classifications.add(CapabilityClassification.NON_DETERMINISTIC)

    def _get_call_name(self, func: ast.AST) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            node: ast.AST = func
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return ".".join(reversed(parts))
        return None

    def _add_finding(self, rule: str, severity: str, detail: str, file_path: str, line_number: int) -> None:
        self.findings.append(InspectionFinding(
            rule=rule,
            severity=severity,
            detail=detail,
            file_path=file_path,
            line_number=line_number,
        ))

    def _compute_determinism_score(self) -> int:
        score = 100
        for finding in self.findings:
            if finding.severity == "CRITICAL":
                score -= 25
            elif finding.severity == "HIGH":
                score -= 15
            elif finding.severity == "MEDIUM":
                score -= 5
        return max(0, score)

    def _compute_replay_safety_score(self) -> int:
        score = 100
        for finding in self.findings:
            if finding.rule in ["network_access", "filesystem_mutation", "subprocess_spawn", "thread_spawn"]:
                if finding.severity == "CRITICAL":
                    score -= 30
                elif finding.severity == "HIGH":
                    score -= 20
        return max(0, score)

    def _apply_classification_rules(self) -> None:
        if CapabilityClassification.REJECTED in self.classifications:
            # Rejected is terminal
            self.classifications = {CapabilityClassification.REJECTED}
            return
        if not self.classifications:
            self.classifications.add(CapabilityClassification.DETERMINISTIC_SAFE)

    @staticmethod
    def compute_package_hash(package_path: Path) -> str:
        """Compute deterministic hash of package directory contents."""
        hashes: List[str] = []
        for py_file in sorted(package_path.rglob("*.py")):
            hashes.append(hashlib.sha256(py_file.read_bytes()).hexdigest())
        combined = "".join(sorted(hashes))
        return hashlib.sha256(combined.encode()).hexdigest()

    @staticmethod
    def compute_string_hash(source: str) -> str:
        return hashlib.sha256(source.encode()).hexdigest()
