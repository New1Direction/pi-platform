from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_FIREWALL_STRICT_MODE")


class FirewallInput(BaseModel):
    rules_content: str = Field(..., description="Raw text of firewall rules or network configuration")


class FirewallOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if the firewall configuration is secure")
    open_ports: List[int] = Field(default_factory=list, description="Exposed management or database ports identified")
    issues: List[str] = Field(default_factory=list, description="Firewall issues and compliance violations")
    risk_score: float = Field(..., description="Security risk rating (0.0 to 100.0)")
    status: str = Field(..., description="Firewall compliance status")


class PiFirewallRuleAuditor:
    """Detects exposed administrative interfaces (SSH, RDP) or database ports open to the public internet."""

    def __init__(self) -> None:
        self.agent_name = "PiFirewallRuleAuditor"

    def audit_firewall(self, input_envelope: FirewallInput) -> FirewallOutput:
        content = input_envelope.rules_content.lower()
        issues = []
        open_ports = []
        risk_score = 0.0

        # Port 22 SSH Check
        if "port: 22" in content or "port=22" in content or "ssh" in content:
            if "0.0.0.0/0" in content or "any" in content or "allow all" in content:
                open_ports.append(22)
                issues.append("Exposed SSH Access: Administrative interface (SSH port 22) open to public internet.")
                risk_score = max(risk_score, 90.0)

        # Port 3389 RDP Check
        if "port: 3389" in content or "port=3389" in content or "rdp" in content:
            if "0.0.0.0/0" in content or "any" in content or "allow all" in content:
                open_ports.append(3389)
                issues.append("Exposed RDP Access: Administrative interface (RDP port 3389) open to public internet.")
                risk_score = max(risk_score, 95.0)

        # Port 27017 MongoDB Check
        if "port: 27017" in content or "port=27017" in content or "mongodb" in content:
            if "0.0.0.0/0" in content or "any" in content or "allow all" in content:
                open_ports.append(27017)
                issues.append("Exposed Database Port: NoSQL storage engine (MongoDB port 27017) accessible to anyone.")
                risk_score = max(risk_score, 85.0)

        is_sec = True
        if risk_score > 30.0 and is_strict_mode():
            is_sec = False

        status = "PASSED" if is_sec else "FAILED_FIREWALL_COMPLIANCE"
        if risk_score > 0.0 and is_sec:
            status = "WARN_FIREWALL"

        return FirewallOutput(
            is_secure=is_sec,
            open_ports=open_ports,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
