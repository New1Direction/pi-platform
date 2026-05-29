from __future__ import annotations

import json
import os
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_RUST_TUI_RESOURCE_LIMIT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_RUST_TUI_RESOURCE_LIMIT_STRICT_MODE", True))
        except Exception:
            pass
    return True


class RustTuiResourceLimitInput(BaseModel):
    file_path: str = Field(..., description="Rust source file path")
    rust_code: str = Field(..., description="Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class RustTuiResourceLimitOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if TUI resource limit checks passed")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable segments or keywords")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustTuiResourceLimit:
    """Specialized terminal micro-agent that audits Rust Ratatui/TUI rendering loops for lack of rate limits or frame limits."""

    def __init__(self) -> None:
        self.agent_name = "PiRustTuiResourceLimit"

    def audit_tui_resources(self, input_envelope: RustTuiResourceLimitInput) -> RustTuiResourceLimitOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        # Scans for loops that do ratatui/tui terminal rendering
        # E.g. while let, loop, while, and containing terminal.draw()
        # Look for infinite loops or rendering loops
        has_draw = "terminal.draw" in code or "Terminal::draw" in code or "draw(" in code

        if has_draw:
            # We want to check if they have duration limits, poll, sleep, or interval
            # E.g. event::poll, sleep, Interval, tick
            has_throttle = any(
                x in code for x in ["event::poll", "Duration::from", "sleep(", "tick(", "interval(", "FrameRate", "fps"]
            )

            if not has_throttle:
                vulnerable_elements.append("terminal_draw_loop")
                flagged_findings.append(
                    "Rust TUI rendering loop contains drawing calls (terminal.draw) but lacks explicit "
                    "frame throttling or tick/poll intervals (e.g. event::poll or thread::sleep). This can cause "
                    "extreme CPU consumption and resource exhaustion in terminal contexts."
                )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 70.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_RUST_TUI_LIMIT"
            else:
                status = "WARN_RUST_TUI_LIMIT"
                is_secure = True

        return RustTuiResourceLimitOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
