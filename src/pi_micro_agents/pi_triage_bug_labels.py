from __future__ import annotations
import os
import re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TRIAGE_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class TriageInput(BaseModel):
    log_content: str = Field(..., description="Bug traceback or error log content")

class TriageOutput(BaseModel):
    is_secure: bool = Field(..., description="True if triage successfully classified severity")
    recommended_labels: List[str] = Field(default_factory=list, description="Recommended GitHub labels")
    component: str = Field(..., description="Assessed system component")
    status: str = Field(..., description="Status (PASSED, REJECTED_TRIAGE, WARN_TRIAGE)")

class PiTriageBugLabels:
    """Deterministic micro-agent that parses bug tracebacks and suggests triage labels."""

    def __init__(self) -> None:
        self.agent_name = "PiTriageBugLabels"

    def triage_bug(self, input_envelope: TriageInput) -> TriageOutput:
        log = input_envelope.log_content
        labels = []
        component = "unknown"
        
        # Parse component keywords
        components = [
            ("solidity", "web3-solidity"),
            ("solana", "web3-solana"),
            ("anchor", "web3-solana"),
            ("circom", "zero-knowledge"),
            ("docker", "devops-docker"),
            ("kubernetes", "devops-k8s"),
            ("jwt", "api-auth"),
            ("auth", "api-auth")
        ]
        for key, name in components:
            if key in log.lower():
                component = name
                break
                
        # Parse severity
        if "critical" in log.lower() or "fatal" in log.lower() or "syntaxerror" in log.lower():
            labels.append("severity-critical")
        elif "warning" in log.lower() or "deprecated" in log.lower():
            labels.append("severity-warning")
        else:
            labels.append("severity-normal")
            
        if component != "unknown":
            labels.append(component)
            
        is_secure = "severity-critical" not in labels
        
        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_TRIAGE"
            else:
                status = "WARN_TRIAGE"
                is_secure = True
                
        return TriageOutput(
            is_secure=is_secure,
            recommended_labels=labels,
            component=component,
            status=status
        )
