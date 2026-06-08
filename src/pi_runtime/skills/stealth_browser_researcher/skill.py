"""
stealth_browser_researcher

Main state machine executor with snapshot pruning integration.
Max 5 steps per loop. Strict epistemic control.
Each step: navigate → snapshot → prune → log → yield.
"""

import logging
from typing import Any, Callable, Dict, Optional

from src.pi_runtime.browser.models import BrowserState
from src.pi_runtime.browser.snapshot_pruning import SnapshotState, process_snapshot
from src.pi_runtime.browser.stealth_session_control import StealthSessionControl

logger = logging.getLogger("pi_runtime.skills.stealth_browser_researcher")


class StealthBrowserResearcher:
    """Personal + Red Team browser agent with bounded flexibility.

    Uses Accio-style snapshot pruning for token-efficient page views.
    Each snapshot decision is logged to PI_SNAPSHOT_LOGS for threshold tuning.
    """

    MAX_STEPS = 5

    def __init__(self):
        self.session_control = StealthSessionControl(backend="HeadlessX")
        self.step_count = 0
        self._snapshot_diff_state: Optional[SnapshotState] = None  # carries prev snapshot for diff

    async def run(self, objective: str, on_step: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
        """Execute the skill: navigate → snapshot → prune → log → yield."""
        try:
            session = await self.session_control.initialize()
            session = await self.session_control.inject_fingerprint(session)

            if session.state != BrowserState.SESSION_ACTIVE:
                telemetry = await self.session_control.purge_and_fail_closed(reason="fingerprint_injection_failed")
                return {"status": "FAIL_CLOSED", "telemetry": telemetry}

            context, _ = self.session_control.get_context_handles()
            if not context:
                telemetry = await self.session_control.purge_and_fail_closed(reason="no_browser_context")
                return {"status": "FAIL_CLOSED", "telemetry": telemetry}

            self.step_count = 0
            step_results = []

            while self.step_count < self.MAX_STEPS:
                self.step_count += 1

                # Navigate or interact per objective
                page = await context.new_page()
                try:
                    await page.goto(objective, wait_until="domcontentloaded", timeout=30000)

                    # Get ARIA snapshot
                    aria_snapshot = await page.evaluate("""
                        () => {
                            // Basic ARIA extraction: roles + names from the accessibility tree
                            const results = [];
                            const walker = document.createTreeWalker(
                                document.body,
                                NodeFilter.SHOW_ELEMENT,
                                null,
                                false
                            );
                            let node;
                            while (node = walker.nextNode()) {
                                const role = node.getAttribute('role') ||
                                    (node.tagName === 'A' ? 'link' :
                                     node.tagName === 'BUTTON' ? 'button' :
                                     node.tagName === 'INPUT' ? getInputRole(node) :
                                     node.tagName === 'IMG' ? 'img' : '');
                                const name = node.getAttribute('aria-label') ||
                                    node.getAttribute('title') ||
                                    (node.textContent || '').trim().slice(0, 80);
                                if (role && name) {
                                    results.push({role, name, tag: node.tagName});
                                }
                            }
                            function getInputRole(el) {
                                const t = (el.getAttribute('type') || 'text').toLowerCase();
                                return ['checkbox','radio','button','submit','reset'].includes(t) ? t : 'textbox';
                            }
                            return results.map(r => `${r.role} "${r.name}"`).join('\\n');
                        }
                    """)

                    # Apply snapshot pruning pipeline
                    prune_result = process_snapshot(
                        aria_snapshot,
                        prev_state=self._snapshot_diff_state,
                        target_url=objective,
                        task_id=str(session.session_id),
                        turn_number=self.step_count,
                    )

                    # Update diff state for next turn
                    self._snapshot_diff_state = SnapshotState(
                        aria_text=prune_result["aria_text"],
                        target_id=str(session.session_id),
                        host="unknown",
                        pruned_entries=[],
                    )

                    # Build step result
                    step_result = {
                        "step": self.step_count,
                        "action": "navigate_and_snapshot",
                        "evidence": f"Snapshot mode: {prune_result['mode']}, "
                        f"cut_ratio: {prune_result.get('cut_ratio', 0):.1%}, "
                        f"chars: {prune_result.get('size_before', 0)} → {prune_result.get('size_after', 0)}",
                        "snapshot_mode": prune_result["mode"],
                        "snapshot_cut_ratio": prune_result.get("cut_ratio", 0),
                    }
                    step_results.append(step_result)

                except Exception as nav_err:
                    step_result = {
                        "step": self.step_count,
                        "action": "navigate_failed",
                        "evidence": f"Navigation error: {nav_err}",
                        "snapshot_mode": None,
                        "snapshot_cut_ratio": None,
                    }
                    step_results.append(step_result)
                finally:
                    await page.close()

                if on_step:
                    on_step(step_result)

            return {
                "status": "YIELD_TO_OPERATOR",
                "session_id": str(session.session_id),
                "steps_taken": self.step_count,
                "history": step_results,
            }

        except Exception as e:
            logger.exception("Stealth browser researcher failed")
            telemetry = await self.session_control.purge_and_fail_closed(
                reason="runtime_exception_during_navigation", details={"error": str(e)}
            )
            return {"status": "FAIL_CLOSED", "telemetry": telemetry}
