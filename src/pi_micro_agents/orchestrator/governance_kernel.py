from __future__ import annotations

import logging
from typing import List, Optional

from pi_agent_interceptor.proxy import PIGovernShield

logger = logging.getLogger("pi_platform.governance")


class GovernanceViolationError(Exception):
    """Raised when runtime limits or security constraints are breached."""

    pass


class PiRuntimeGovernanceKernel:
    """Zero-trust Governance Kernel that manages resource quotas and safety gates for agent execution."""

    def __init__(
        self,
        max_time_ms: float = 5000.0,
        max_tokens: int = 100000,
        min_trust_rating: float = 0.7,
        disallowed_imports: Optional[List[str]] = None,
    ) -> None:
        self.max_time_ms = max_time_ms
        self.max_tokens = max_tokens
        self.min_trust_rating = min_trust_rating
        self.disallowed_imports = disallowed_imports or ["socket", "subprocess", "os.system", "shutil"]

    def enforce_budgets(self, elapsed_time_ms: float, tokens_consumed: int) -> None:
        """Enforces execution and token budgets, raising errors if boundaries are breached."""
        if elapsed_time_ms > self.max_time_ms:
            raise GovernanceViolationError(
                f"Execution time {elapsed_time_ms:.2f}ms exceeded allocated budget of {self.max_time_ms}ms"
            )
        if tokens_consumed > self.max_tokens:
            raise GovernanceViolationError(
                f"Tokens consumed {tokens_consumed} exceeded allocated ceiling of {self.max_tokens}"
            )

    def evaluate_ast_safety(self, source_code: str) -> None:
        """Audits python AST nodes and blocks execution upon finding blacklisted imports or violations."""
        # 1. Use the pre-existing PIGovernShield inspect_ast checks
        violations = PIGovernShield.inspect_ast(source_code)
        if violations:
            raise GovernanceViolationError(f"AST security screening failed: {', '.join(violations)}")

        # 2. Check for explicit disallowed library imports in raw text or import statements
        for forbidden in self.disallowed_imports:
            if f"import {forbidden}" in source_code or f"from {forbidden}" in source_code:
                raise GovernanceViolationError(
                    f"AST security screening failed: Unauthorized import '{forbidden}' detected"
                )

    def check_degradation_trigger(self, queue_depth: int, latency_ms: float) -> bool:
        """Returns True if the system matches conditions indicating adaptive soft-degradation is required."""
        # Triggers degradation if latency is over 80% of total budget OR queue depth exceeds 20
        if latency_ms >= (0.8 * self.max_time_ms):
            logger.warning(f"Latency ({latency_ms}ms) approaching budget limit. Degradation triggered.")
            return True
        if queue_depth > 20:
            logger.warning(f"Queue depth ({queue_depth}) exceeded safety boundary (20). Degradation triggered.")
            return True
        return False

    def check_trust_clearance(self, trust_rating: float) -> None:
        """Validates if agent trust rating meets requirements for advanced operations."""
        if trust_rating < self.min_trust_rating:
            raise GovernanceViolationError(
                f"Agent trust rating {trust_rating:.2f} is below min required clearance of {self.min_trust_rating:.2f}"
            )
