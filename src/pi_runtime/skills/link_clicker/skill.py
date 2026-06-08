"""
link_clicker

Visible browser link/button clicking skill.
"""

from typing import Any, Callable, Dict, Optional

from playwright.async_api import async_playwright


class LinkClicker:
    """Clicks elements in a visible browser."""

    def __init__(self, headless: bool = False):
        self.headless = headless

    async def click(
        self, url: str, selector: str, on_step: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        if on_step:
            on_step({"step": 0, "action": "navigate", "evidence": f"Going to {url}"})

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            page = await browser.new_page()
            await page.goto(url)

            try:
                if on_step:
                    on_step({"step": 1, "action": "locate", "evidence": f"Looking for {selector}"})

                await page.click(selector, timeout=10000)

                if on_step:
                    on_step({"step": 2, "action": "click", "evidence": f"Clicked {selector}"})

                await browser.close()
                return {"status": "VERIFIED", "clicked": selector}

            except Exception as e:
                await browser.close()
                return {"status": "FAIL_CLOSED", "error": str(e)}
