"""
pi_ide_re.stages - the dynamic + static RE pipeline stages.

Every stage follows the same contract: a live ``capture()`` (best-effort, needs
external tooling like frida/mitmproxy/ghidra and degrades gracefully when
absent) and a deterministic ``ingest()`` that turns saved artifacts into
content-addressed graph nodes. Ingest is what the test suite and replay rely
on; capture is the thin live adapter.
"""

from __future__ import annotations

from .base import Stage, StageError, StageResult

__all__ = ["Stage", "StageError", "StageResult"]
