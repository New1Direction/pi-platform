"""
src/pi_runtime/orchestrator.py

Master Registry Update:
Plugs the Stealth Browser Researcher into the core dispatch loop.
"""

import logging
from typing import Any, Dict

from src.pi_runtime.skills.stealth_browser_researcher.bridge import BrowserResearcherChainDriver

logger = logging.getLogger("pi_runtime.orchestrator")


class SquadOrchestrator:
    """
    Main execution hub for PI-Platform agents.
    Governs state transitions and dispatches artifacts to specialized drivers.
    """

    def __init__(self):
        # Domain Registry
        self.drivers = {
            # New: Stealth Browser Researcher Capability
            "browser_recon": BrowserResearcherChainDriver(),
            # Placeholders for existing/future drivers
            "code_execution": None,
            "file_ops": None,
        }

    def process_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        """
        Routes an artifact to its designated capability driver based on domain.
        """
        domain = artifact.get("domain", "default")
        driver = self.drivers.get(domain)

        if not driver:
            logger.error(f"Execution Error: No driver registered for domain '{domain}'")
            return {
                "artifact_id": artifact.get("artifact_id"),
                "next_state": "ABORTED",
                "error": f"Unsupported domain: {domain}",
            }

        logger.info(f"Dispatching artifact {artifact.get('artifact_id')} to domain '{domain}'")

        # This calls our Bridge -> Skill -> browser-use / Maxun stack
        return driver.execute_chain_step(artifact)
