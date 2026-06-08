"""
src/pi_runtime/skills/stealth_browser_researcher/run_sample_artifact.py (Emitter Test)

Verifies that real-time pulses are correctly emitted during a simulated run.
"""

import json
import logging
import sys
from pathlib import Path

# Ensure the project root is on the path when running directly
project_root = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(project_root))

from src.pi_runtime.skills.stealth_browser_researcher.bridge import BrowserResearcherChainDriver
from src.pi_runtime.tui.event_bus import ExecutionEventBus

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("pulse_test")


def pulse_logger(event_type: str, data: dict):
    """Mocks the TUI's event ingestion."""
    color = "\033[94m"  # Blue
    if "complete" in event_type:
        color = "\033[92m"  # Green
    if "step" in event_type:
        color = "\033[93m"  # Yellow

    print(f"{color}[EVENT: {event_type}]\033[0m {json.dumps(data, indent=2)}")


def verify_emitter_signals():
    # 1. Initialize Bus and Driver
    bus = ExecutionEventBus()
    bus.subscribe(pulse_logger)
    driver = BrowserResearcherChainDriver(event_bus=bus)

    # 2. Mock artifact
    sample_payload = {"artifact_id": "art_test_pulse_001", "objective": "Verify real-time TUI feedback loops."}

    print("\n--- Starting Emitter Verification ---\n")

    # 3. Execute
    driver.execute_chain_step(sample_payload)


if __name__ == "__main__":
    verify_emitter_signals()
