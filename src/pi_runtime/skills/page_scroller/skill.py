"""
page_scroller

Visible browser scrolling skill.
"""

from typing import Any, Callable, Dict, Optional

from playwright.async_api import async_playwright


class PageScroller:
    """Scrolls pages in a visible browser."""

    def __init__(self, headless: bool = False):
        self.headless = headless

    async def scroll(
        self, url: str, mode: str = "bottom", on_step: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        if on_step:
            on_step({"step": 0, "action": "navigate", "evidence": f"Going to {url}"})

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            page = await browser.new_page()
            await page.goto(url)

            try:
                if mode == "bottom":
                    if on_step:
                        on_step({"step": 1, "action": "scroll", "evidence": "Scrolling to bottom"})
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                else:
                    # Simple pixel scroll for now
                    await page.evaluate("window.scrollBy(0, 800)")

                if on_step:
                    on_step({"step": 2, "action": "scroll_complete", "evidence": "Scroll finished"})

                await browser.close()
                return {"status": "VERIFIED", "mode": mode}

            except Exception as e:
                await browser.close()
                return {"status": "FAIL_CLOSED", "error": str(e)}
