---
name: page_scroller
version: 0.1.0
category: browser-automation
description: Scrolls through pages intelligently in a visible browser.
tags: [browser, scroll, visible, testing]
---

# page_scroller

**Role:** Scroll pages in a controlled, visible way.

## Responsibilities
- Scroll to bottom, element, or by pixels
- Detect when further scrolling has no effect
- Emit step_progress events
- Support visible mode

## States
IDLE → SCROLLING → VERIFIED
FAIL_CLOSED on timeout
```