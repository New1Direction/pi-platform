from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field


# 1. Configuration resolver
def is_strict_mode() -> bool:
    env_val = os.getenv("PI_GIT_SEC_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_GIT_SEC_STRICT_MODE", True))
        except Exception:
            pass
    return True

# 2. Heuristics scanner for dependencies and security patches
def detect_git_sec_anomalies(content: str, filename: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not content:
        return 0.0, []

    fn_lower = filename.lower()

    # A. Dependency Checkers (requirements.txt, package.json)
    if "requirements.txt" in fn_lower:
        lines = content.splitlines()
        for idx, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Detect unpinned or wildcard/range dependencies
            # Clean requirements.txt pin is usually: package==1.2.3 or package===1.2.3
            # If it uses >=, <=, >, <, ~=, or no pin at all, flag it.
            if "==" not in line and "===" not in line:
                violations.append(f"unpinned or range dependency in requirements.txt (line {idx+1}): '{line}'")
                max_risk = max(max_risk, 75.0)

            # Typosquatting / Suspicious Packages
            suspicious_packages = ["discord-py-self", "urllib5", "colorama-plus", "reqs", "pip-install-all"]
            package_name = line.split("=")[0].split(">")[0].split("<")[0].split("~")[0].strip().lower()
            if package_name in suspicious_packages:
                violations.append(f"high-risk typosquatted / suspicious package detected (line {idx+1}): '{package_name}'")
                max_risk = max(max_risk, 85.0)

    elif "package.json" in fn_lower:
        # Simple JSON search or regex search for dynamic/unpinned dependencies
        # Flag wildcard versions "*" or dynamic ranges starting with "^", "~"
        wildcard_matches = re.findall(r'"([^"]+)"\s*:\s*"([*^~]|[xX]|\b(?:latest)\b)', content)
        for pkg, ver in wildcard_matches:
            violations.append(f"unpinned or floating dependency in package.json: '{pkg}': '{ver}'")
            max_risk = max(max_risk, 75.0)

    # B. Dangerous Code Execution Checks (.py, .js, .ts, .sh, .sol)
    source_extensions = [".py", ".js", ".ts", ".sh", ".sol", ".go", ".c", ".cpp"]
    if any(fn_lower.endswith(ext) for ext in source_extensions) or fn_lower == "pi-platform":
        # Check for arbitrary code execution / unsafe string evaluation
        eval_patterns = [
            (r"\beval\s*\(", "arbitrary code evaluation 'eval()'"),
            (r"\bexec\s*\(", "arbitrary code execution 'exec()'"),
            (r"subprocess\.(?:Popen|run|call)\(.*shell\s*=\s*True", "insecure subprocess with shell=True"),
            (r"os\.system\s*\(", "insecure system execution 'os.system()'"),
        ]
        for pat, desc in eval_patterns:
            if re.search(pat, content):
                violations.append(f"dangerous execution function: {desc}")
                max_risk = max(max_risk, 90.0)

    # C. Hardcoded Credentials & Sensitive Data Secrets
    secret_patterns = [
        (r"(?:api_key|apikey|api-key)\s*[:=]\s*['\"][a-zA-Z0-9_-]{20,}['\"]", "hardcoded API key"),
        (r"(?:private_key|privatekey)\s*[:=]\s*['\"](?:0x)?[a-fA-F0-9]{64,}['\"]", "hardcoded private key hex signature"),
        (r"(?:secret|client_secret|client-secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-+=/]{30,}['\"]", "hardcoded client secret token"),
    ]
    for pat, desc in secret_patterns:
        if re.search(pat, content, re.IGNORECASE):
            violations.append(f"potential leak of secret information: {desc}")
            max_risk = max(max_risk, 95.0)

    return max_risk, violations

# 3. Pydantic Input and Output envelopes
class GitSecInput(BaseModel):
    filename: str = Field(..., description="The name of the file being scanned")
    content: str = Field(..., description="The string content of the file or patch to scan")

class GitSecOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates whether the file is safe to proceed under strict-mode")
    risk_score: float = Field(..., description="The calculated security risk level (0-100)")
    status: str = Field(..., description="Scanner status classification (PASSED, WARN_VULNERABILITY, REJECTED_VULNERABILITY)")
    flagged_vulnerabilities: List[str] = Field(default_factory=list, description="List of identified issues")

# 4. Core Micro-Agent Class
class PiGitSecScanner:
    """CI/CD dependency and security patch micro-agent sandbox scanner."""

    def __init__(self) -> None:
        self.agent_name = "PiGitSecScanner"

    def scan_file(self, input_envelope: GitSecInput) -> GitSecOutput:
        """Runs the complete suite of heuristics against target file content or patch string."""
        risk, violations = detect_git_sec_anomalies(input_envelope.content, input_envelope.filename)

        is_strict = is_strict_mode()
        is_secure = True
        status = "PASSED"

        if risk >= 80.0:
            if is_strict:
                is_secure = False
                status = "REJECTED_VULNERABILITY"
            else:
                status = "WARN_VULNERABILITY"
        elif risk >= 70.0:
            # Under 80.0, we warn but do not strictly block unless configured otherwise
            status = "WARN_VULNERABILITY"

        return GitSecOutput(
            is_secure=is_secure,
            risk_score=risk,
            status=status,
            flagged_vulnerabilities=violations
        )
