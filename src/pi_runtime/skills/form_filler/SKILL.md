---
name: form_filler
version: 0.1.0
category: browser-automation
description: Fills form fields with provided data in a visible browser session.
tags: [browser, form, visible, testing]
---

# form_filler

**Role:** Fill form fields reliably in a visible browser.

## Responsibilities
- Accept field selectors + values
- Type in a human-like manner
- Emit step_progress events
- Support visible (headed) mode for testing

## States
IDLE → FILLING → VERIFIED → DONE
FAIL_CLOSED on error

## Events Emitted
- artifact_started
- step_progress
- execution_complete
```