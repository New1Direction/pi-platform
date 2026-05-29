from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

from pi_agent_interceptor.proxy import PIGovernShield
from pi_micro_agents.pi_prompt_shield import detect_prompt_injection


class PiOrchestratorShield:
    """Safety shields for the PiOrchestrator (prompt injection, command safety, and AST screening)."""

    @staticmethod
    def check_defensive_only(context: Dict[str, Any]) -> bool:
        """Returns True if defensive-only mode is active and blocked payloads are found."""
        is_defensive_only = os.getenv("PI_ORCHESTRATOR_DEFENSIVE_ONLY") == "true"
        if is_defensive_only:
            if (context.get("command") or context.get("cmd") or
                context.get("content") or context.get("proposed_content") or context.get("source_code")):
                return True
        return False

    @staticmethod
    def check_prompt_injection(goal: str) -> Tuple[float, List[str]]:
        """Wraps prompt injection security audit."""
        return detect_prompt_injection(goal)

    @staticmethod
    def check_command_safety(context: Dict[str, Any]) -> Tuple[float, str] | None:
        """Inspects shell commands inside the context for malicious or unsafe operations."""
        cmd_candidate = context.get("command") or context.get("cmd")
        if cmd_candidate and isinstance(cmd_candidate, str):
            cmd_risk = PIGovernShield.analyze_command_sensitivity(cmd_candidate)
            if cmd_risk >= 80.0:
                return cmd_risk, cmd_candidate
        return None

    @staticmethod
    def check_ast_safety(context: Dict[str, Any]) -> List[str] | None:
        """Inspects proposed python scripts to prevent unverified execution paths."""
        code_candidate = context.get("content") or context.get("proposed_content") or context.get("source_code")
        if code_candidate and isinstance(code_candidate, str):
            ast_violations = PIGovernShield.inspect_ast(code_candidate)
            if ast_violations:
                return [f"AST security violation: {v}" for v in ast_violations]
        return None
