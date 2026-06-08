"""
src/pi_runtime/browser/autonomous_dom_navigation.py

Governed dynamic reasoning wrapper around browser-use.
Consumes external BrowserContext footprints to enforce 3-phase loops.
"""

from uuid import UUID

from browser_use.agent.service import Agent as BUAgent

# Assuming browser-use is installed in the target environment
from browser_use.browser.context import BrowserContext as BUContext
from playwright.async_api import BrowserContext

from .models import NavigationState, NavigationStep


class AutonomousDomNavigation:
    """
    Executes atomic interaction loops using browser-use primitives
    while operating strictly within a borrowed stealth perimeter.
    """

    def __init__(self, session_id: UUID, playwright_context: BrowserContext):
        self.session_id = session_id
        # Wrap the raw Playwright context inside browser-use's context abstraction
        self.bu_context = BUContext(context=playwright_context)

    async def execute_step(self, intent: str) -> NavigationStep:
        """
        Executes a single step loop: OBSERVED -> INFERRED -> VERIFIED.
        Forces browser-use to evaluate the current state without taking off.
        """
        try:
            # 1. Phase: OBSERVED
            # browser-use extracts state internally when an agent step is processed.
            # We explicitly instantiate a short-lived single-step agent worker.
            agent = BUAgent(
                task=intent,
                context=self.bu_context,
                max_actions_per_step=1,  # Enforce strict atomic boundaries
            )

            # 2 & 3. Phase: INFERRED & VERIFIED
            # Run exactly one processing step loop inside browser-use
            history = await agent.run(max_steps=1)

            # Extract execution feedback from browser-use historical tracking
            last_step_success = False
            evidence_log = "No action taken or execution failed"
            action_type = "unknown"

            if history and history.history:
                last_result = history.history[-1]
                last_step_success = not last_result.is_done
                action_type = str(last_result.action)
                evidence_log = f"Action output: {last_result.result}"

            return NavigationStep(
                state=NavigationState.VERIFIED if last_step_success else NavigationState.OBSERVED,
                action=action_type,
                target=None,
                success=last_step_success,
                evidence=evidence_log,
                snapshot_mode="PASSTHROUGH",
                snapshot_cut_ratio=0.0,
            )

        except Exception as e:
            return NavigationStep(
                state=NavigationState.OBSERVED,
                action="exception",
                success=False,
                evidence=f"Execution block failure: {str(e)}",
                snapshot_mode="PASSTHROUGH",
                snapshot_cut_ratio=None,
            )
