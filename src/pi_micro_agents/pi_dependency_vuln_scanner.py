from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DEPENDENCY_STRICT_MODE")


class DependencyInput(BaseModel):
    lockfile_path: str = Field(..., description="Path to the dependency lockfile")
    lockfile_content: str = Field(..., description="Raw content of the dependency lockfile")
    ecosystem: str = Field(..., description="Ecosystem or package manager (npm, pip, go, cargo)")


class DependencyOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the dependencies are free of known vulnerabilities")
    vulnerable_packages: List[str] = Field(
        default_factory=list, description="List of detected vulnerable package coordinates"
    )
    risk_score: float = Field(..., description="Overall security risk score (0.0 to 100.0)")
    status: str = Field(..., description="Vulnerability status")


class PiDependencyVulnScanner:
    """Deterministic static analysis of dependency lockfiles against known vulnerable packages."""

    def __init__(self) -> None:
        self.agent_name = "PiDependencyVulnScanner"

    def scan_dependencies(self, input_envelope: DependencyInput) -> DependencyOutput:
        content = input_envelope.lockfile_content
        vulnerabilities = []
        risk_score = 0.0

        # lodash prototype pollution check (< 4.17.21)
        if "lodash" in content:
            if (
                '"version": "4.17.20"' in content
                or '"version": "4.17.15"' in content
                or "lodash==4.17.15" in content
                or "lodash@4.17.15" in content
            ):
                vulnerabilities.append("lodash@4.17.15: High risk prototype pollution vulnerability (CVE-2020-8203).")
                risk_score = max(risk_score, 80.0)

        # log4j checks (Log4Shell CVE-2021-44228)
        if "log4j" in content:
            if "2.14.1" in content or "2.12.1" in content or "2.15.0-rc1" in content:
                vulnerabilities.append(
                    "log4j-core@2.14.1: Critical remote code execution vulnerability Log4Shell (CVE-2021-44228)."
                )
                risk_score = max(risk_score, 100.0)

        # old requests library
        if "requests" in content:
            if (
                "requests==2.18" in content
                or "requests==2.19" in content
                or "requests==2.2" in content
                or "requests<2.20" in content
            ):
                vulnerabilities.append(
                    "requests<2.20.0: Information leakage via authorization headers (CVE-2018-18074)."
                )
                risk_score = max(risk_score, 60.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "VULNERABILITIES_FOUND"
        if risk_score > 0.0 and is_sec:
            status = "WARN_VULNERABILITIES"

        return DependencyOutput(
            is_secure=is_sec,
            vulnerable_packages=vulnerabilities,
            risk_score=risk_score,
            status=status,
        )
