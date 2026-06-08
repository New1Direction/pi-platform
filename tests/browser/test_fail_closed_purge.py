"""
tests/browser/test_fail_closed_purge.py

Hardened test harness with structural dependency guards.
Gracefully handles missing execution binaries or environment drift.
"""

from unittest.mock import AsyncMock, patch

import pytest

from src.pi_runtime.browser.stealth_session_control import StealthSessionControl
from src.pi_runtime.skills.stealth_browser_researcher.skill import StealthBrowserResearcher

# Guard 1: Detect browser_use capability
try:
    import browser_use

    HAS_BROWSER_USE = True
except ImportError:
    HAS_BROWSER_USE = False

# Guard 2: Detect playwright binary installation state
try:
    from playwright.async_api import async_playwright

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False


@pytest.mark.asyncio
@pytest.mark.skipif(not HAS_PLAYWRIGHT, reason="Requires 'playwright' package installed.")
async def test_fail_closed_purge_leaves_zero_residual_state():
    """
    Validates teardown of all core browser handles during unexpected initial drops.
    """
    control = StealthSessionControl(backend="HeadlessX")

    try:
        await control.initialize()
        telemetry = await control.purge_and_fail_closed(reason="simulated_fingerprint_mismatch")

        assert telemetry["failure_reason"] == "simulated_fingerprint_mismatch"
        assert control.current_session is None
        assert control._context is None
        assert control._browser is None
        assert control._playwright is None
    except Exception as e:
        if "Executable doesn't exist" in str(e):
            pytest.skip("Playwright package is present, but Firefox binaries are missing. Run 'playwright install'.")
        raise e


@pytest.mark.asyncio
@pytest.mark.skipif(
    not HAS_BROWSER_USE or not HAS_PLAYWRIGHT,
    reason="Requires both 'browser-use' and 'playwright' dependencies to execute.",
)
async def test_mid_loop_navigation_exception_trigger():
    """
    Validates that a critical exception occurring during the
    INTERACTIVE_REASONING phase triggers an immediate fail-closed purge.
    """
    researcher = StealthBrowserResearcher()

    with patch(
        "src.pi_runtime.browser.autonomous_dom_navigation.AutonomousDomNavigation.execute_step", new_callable=AsyncMock
    ) as mock_execute_step:
        mock_execute_step.side_effect = RuntimeError("Anti-bot injection detected or unexpected DOM challenge")

        try:
            result = await researcher.run(objective="Extract internal infrastructure schemas.")

            assert result["status"] == "FAIL_CLOSED"
            assert result["telemetry"]["failure_reason"] == "runtime_exception_during_navigation"
            assert researcher.session_control.current_session is None
            assert researcher.step_count >= 0
        except Exception as e:
            if "Executable doesn't exist" in str(e):
                pytest.skip("Firefox binaries missing. Run 'playwright install'.")
            raise e
