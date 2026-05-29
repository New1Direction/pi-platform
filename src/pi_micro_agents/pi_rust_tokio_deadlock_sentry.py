from __future__ import annotations

import json
import os
import re
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_RUST_TOKIO_DEADLOCK_ST_STRICT_MODE", True))
        except Exception:
            pass
    return True


class RustTokioDeadlockInput(BaseModel):
    file_path: str = Field(..., description="Rust source file path")
    rust_code: str = Field(..., description="Rust source code content")
    check_level: str = Field(default="STRICT", description="Strictness level")


class RustTokioDeadlockOutput(BaseModel):
    is_secure: bool = Field(..., description="Indicates if Tokio deadlock checks passed")
    vulnerable_elements: List[str] = Field(default_factory=list, description="Vulnerable segments or functions")
    flagged_findings: List[str] = Field(default_factory=list, description="Detailed findings")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status classification")


class PiRustTokioDeadlockSentry:
    """Specialized concurrency micro-agent auditing Rust code for Tokio async deadlocks and nested lock hold patterns."""

    def __init__(self) -> None:
        self.agent_name = "PiRustTokioDeadlockSentry"

    def audit_tokio_deadlock(self, input_envelope: RustTokioDeadlockInput) -> RustTokioDeadlockOutput:
        code = input_envelope.rust_code
        vulnerable_elements = []
        flagged_findings = []

        # Find async functions holding Mutex guards across await points
        # Search for .lock() followed by .await
        # Or blocks containing std::sync::Mutex or tokio::sync::Mutex used without proper drops
        # Check standard deadlock pattern: locking std::sync::Mutex in an async block holding across .await
        has_std_mutex = ("std::sync" in code or "parking_lot" in code) and ("Mutex" in code or "RwLock" in code)
        has_await = ".await" in code

        if has_std_mutex and has_await:
            # Let's see if a MutexGuard is kept across an await point.
            # Simplified static analyzer looking for standard synchronous locking in async blocks
            if re.search(r"\.lock\(\)[\s\S]*?\.await", code):
                vulnerable_elements.append("sync_lock_held_across_await")
                flagged_findings.append(
                    "Rust async block holds a synchronous std::sync::Mutex guard across an '.await' point. "
                    "This can lead to runtime thread deadlocks or block the Tokio executor pool completely."
                )

            # Check block_on deadlock patterns E.g. block_on inside an async function
            if re.search(r"async[\s\S]*?block_on\(", code):
                vulnerable_elements.append("block_on_inside_async")
                flagged_findings.append(
                    "Rust async function or block uses a synchronous 'block_on' executor call. "
                    "Calling block_on nested inside an existing async task runtime can cause executor stack overflow or immediate deadlocks."
                )

        is_secure = len(vulnerable_elements) == 0
        risk_score = 75.0 if not is_secure else 0.0

        is_strict = is_strict_mode()
        status = "PASSED"
        if not is_secure:
            if is_strict:
                status = "REJECTED_RUST_TOKIO_DEADLOCK"
            else:
                status = "WARN_RUST_TOKIO_DEADLOCK"
                is_secure = True

        return RustTokioDeadlockOutput(
            is_secure=is_secure,
            vulnerable_elements=vulnerable_elements,
            flagged_findings=flagged_findings,
            risk_score=risk_score,
            status=status,
        )
