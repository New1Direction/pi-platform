"""
Browser skill models — frozen data structures.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional
from uuid import UUID, uuid4


class BrowserState(str, Enum):
    IDLE = "IDLE"
    AUTHENTICATING = "AUTHENTICATING"
    SESSION_ACTIVE = "SESSION_ACTIVE"
    STALE = "STALE"
    FAIL_CLOSED = "FAIL_CLOSED"


class NavigationState(str, Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    VERIFIED = "VERIFIED"


@dataclass(frozen=True)
class StealthSession:
    """Represents a fingerprinted stealth browser session."""

    session_id: UUID = field(default_factory=uuid4)
    backend: str = "HeadlessX"
    state: BrowserState = BrowserState.IDLE
    fingerprint: Optional[Dict[str, Any]] = None
    cookies: Dict[str, str] = field(default_factory=dict)
    storage: Dict[str, Any] = field(default_factory=dict)
    snapshot_state: Optional["SnapshotStateRef"] = None  # ref to live snapshot state


@dataclass(frozen=True)
class SnapshotStateRef:
    """Reference to the live snapshot diff state for a session.

    Updated by the snapshot pruning pipeline after each page view.
    Carries the last pruned ARIA text, ref set, and target info
    for Jaccard diffing across turns.
    """

    aria_text: str = ""
    target_id: Optional[str] = None
    host: Optional[str] = None
    ref_count: int = 0
    last_updated: float = field(default_factory=time.time)


@dataclass(frozen=True)
class NavigationStep:
    """Single bounded navigation step."""

    step_id: UUID = field(default_factory=uuid4)
    state: NavigationState = NavigationState.OBSERVED
    action: str = ""
    target: Optional[str] = None
    success: bool = False
    evidence: Optional[str] = None
    snapshot_mode: Optional[str] = None  # FULL | DIFF | FULL_FALLBACK
    snapshot_cut_ratio: Optional[float] = None  # 0.0-1.0 savings from pruning


@dataclass(frozen=True)
class ExtractionSchemaPayload:
    """Represents a structured visual extraction payload from Maxun."""

    payload_id: UUID = field(default_factory=uuid4)
    scraper_id: str = ""
    target_url: str = ""
    extracted_data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0
    sink_path: Optional[str] = None
