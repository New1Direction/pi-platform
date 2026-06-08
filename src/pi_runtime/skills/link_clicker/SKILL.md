---
name: link_clicker
version: 0.1.0
category: browser-automation
description: Clicks links or buttons in a visible browser session.
tags: [browser, click, visible, testing]
---

# link_clicker

**Role:** Click elements reliably in a visible browser.

## Responsibilities
- Locate and click links/buttons
- Wait for element to be clickable
- Emit step_progress events
- Support visible mode

## States
IDLE → LOCATING → CLICKING → VERIFIED
FAIL_CLOSED on failure
```