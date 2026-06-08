"""
form_filler

Visible browser form filling skill.
"""

from typing import Any, Callable, Dict, Optional

from playwright.async_api import async_playwright


class FormFiller:
    """Fills form fields in a visible browser."""

    def __init__(self, headless: bool = False):
        self.headless = headless

    async def fill(
        self, url: str, fields: Dict[str, str], on_step: Optional[Callable[[Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Fill form fields on the given URL.
        """
        if on_step:
            on_step({"step": 0, "action": "navigate", "evidence": f"Going to {url}"})

        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=self.headless)
            context = await browser.new_context()
            page = await context.new_page()

            await page.goto(url)

            filled = 0
            for selector, value in fields.items():
                try:
                    await page.fill(selector, value)
                    filled += 1
                    if on_step:
                        on_step({"step": filled, "action": "fill", "evidence": f"Filled {selector}"})
                except Exception as e:
                    if on_step:
                        on_step({"step": filled, "action": "error", "evidence": str(e)})
                    await browser.close()
                    return {"status": "FAIL_CLOSED", "error": str(e)}

            await browser.close()
            return {"status": "DONE", "fields_filled": filled, "url": url}
