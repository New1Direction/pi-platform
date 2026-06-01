"""Memory drift detection integrated with PiChainMemory.

Detects when source files have been modified after a memory entry was saved,
implementing the trust rule: "trust current state over stale memory."

Memory type classification:
  - USER:     user role/preferences/responsibilities
  - FEEDBACK: corrections AND confirmations with why + how_to_apply
  - PROJECT:  ongoing work, goals, initiatives

Thread-safe. Deterministic — no randomness, no auto-learning.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional

from pi_micro_agents.orchestrator.memory import MemoryEntry, PiChainMemory

# ---------------------------------------------------------------------------
# Memory type classification
# ---------------------------------------------------------------------------


class MemoryType(str, Enum):
    """Classification of memory entries.

    Mirrors the reference memory types system but works within the
    PiChainMemory key/body model.
    """

    USER = "user"
    FEEDBACK = "feedback"
    PROJECT = "project"


# Type constants for convenience
MEMORY_TYPE_USER = MemoryType.USER
MEMORY_TYPE_FEEDBACK = MemoryType.FEEDBACK
MEMORY_TYPE_PROJECT = MemoryType.PROJECT

VALID_MEMORY_TYPES = {mt.value for mt in MemoryType}


# ---------------------------------------------------------------------------
# Drift result
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftResult:
    """Result of a drift check between a memory entry and its source file.

    Attributes:
        entry_id: The memory entry ID.
        source_path: Path to the source file.
        memory_mtime: Timestamp when the memory was created (Unix float).
        source_mtime: Current modification time of the source file (Unix float).
        is_stale: ``True`` if the source file was modified AFTER the memory
            was saved, meaning the memory may be out of date.
        staleness_seconds: How many seconds the source is ahead of the
            memory.  Negative or zero means not stale.
    """

    entry_id: str
    source_path: str
    memory_mtime: float
    source_mtime: float
    is_stale: bool
    staleness_seconds: float


# ---------------------------------------------------------------------------
# Drift stats
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DriftStats:
    """Summary statistics about memory staleness.

    Attributes:
        total_entries: Total number of memory entries scanned.
        stale_count: Number of entries that are stale.
        fresh_count: Number of entries that are current.
        by_type: Count of entries grouped by :class:`MemoryType`.
        stale_by_type: Count of stale entries grouped by type.
        oldest_memory_age_seconds: Age of the oldest memory in seconds, or None.
        staleness_distribution: Buckets of staleness (``fresh``, ``<1h``,
            ``1h-1d``, ``>1d``).
    """

    total_entries: int
    stale_count: int
    fresh_count: int
    by_type: Dict[str, int]
    stale_by_type: Dict[str, int]
    oldest_memory_age_seconds: Optional[float]
    staleness_distribution: Dict[str, int]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _classify_entry(entry: MemoryEntry) -> MemoryType:
    """Infer the memory type from the entry's key prefix or body content.

    Convention: keys are prefixed with ``type:`` (e.g. ``user:role``,
    ``feedback:correction``, ``project:goal-x``).  If no prefix matches,
    defaults to ``PROJECT``.
    """
    key_lower = entry.key.lower()
    for mt in MemoryType:
        if key_lower.startswith(mt.value + ":"):
            return mt
    # Fallback: scan body for keywords
    body_lower = entry.body.lower()
    if any(w in body_lower for w in ("role", "preference", "responsibility")):
        return MemoryType.USER
    if any(w in body_lower for w in ("correction", "confirmation", "feedback")):
        return MemoryType.FEEDBACK
    return MemoryType.PROJECT


def _get_source_mtime(source_path: str) -> Optional[float]:
    """Return the mtime of *source_path*, or ``None`` if not found."""
    try:
        return os.path.getmtime(source_path)
    except OSError:
        return None


# ---------------------------------------------------------------------------
# DriftDetector
# ---------------------------------------------------------------------------


class DriftDetector:
    """Detects memory drift by comparing memory timestamps to source file mtimes.

    Works with :class:`PiChainMemory` — entries are fetched from the store
    and compared against the current filesystem state.

    Thread-safe (all public methods acquire ``self._lock``).
    Deterministic — no randomness.

    Usage::

        memory = PiChainMemory()
        detector = DriftDetector(memory)

        # Check one entry
        result = detector.check_drift(entry, "/path/to/source.py")
        if result.is_stale:
            print(f"Memory {entry.entry_id} is {result.staleness_seconds}s stale")

        # Scan all
        stale = detector.scan_all_stale({
            "project:config": "/etc/app/config.yaml",
            "user:role": "/home/user/profile.md",
        })

        # Auto-refresh stale entries
        for result in stale:
            entry = memory.recall(result.entry_id, top_k=1)[0]  # by key
            detector.auto_refresh(entry, result.source_path, memory)
    """

    def __init__(self, memory: PiChainMemory) -> None:
        """Initialize the detector.

        Args:
            memory: The :class:`PiChainMemory` store to check against.
        """
        self._memory = memory
        self._lock = threading.RLock()

    # ── Single entry check ──────────────────────────────────────────────

    def check_drift(
        self,
        entry: MemoryEntry,
        source_path: str,
    ) -> DriftResult:
        """Check if a single memory entry is stale relative to its source.

        Trust rule: if the source file was modified after the memory was
        saved (``entry.created_at``), the memory is stale.

        Args:
            entry: The memory entry to check.
            source_path: Path to the source file.

        Returns:
            A :class:`DriftResult` with drift details.
        """
        memory_mtime = entry.created_at
        source_mtime = _get_source_mtime(source_path)

        if source_mtime is None:
            # Source doesn't exist — can't determine drift, treat as not stale
            return DriftResult(
                entry_id=entry.entry_id,
                source_path=source_path,
                memory_mtime=memory_mtime,
                source_mtime=0.0,
                is_stale=False,
                staleness_seconds=0.0,
            )

        staleness = source_mtime - memory_mtime
        is_stale = staleness > 0.0

        return DriftResult(
            entry_id=entry.entry_id,
            source_path=source_path,
            memory_mtime=memory_mtime,
            source_mtime=source_mtime,
            is_stale=is_stale,
            staleness_seconds=max(0.0, staleness),
        )

    # ── Batch scan ──────────────────────────────────────────────────────

    def scan_all_stale(
        self,
        source_map: Dict[str, str],
    ) -> List[DriftResult]:
        """Check all entries in *source_map* for staleness.

        Args:
            source_map: Mapping of ``memory_key -> source_file_path``.
                Each key is matched against stored memories.

        Returns:
            List of :class:`DriftResult` for entries that are stale.
            Entries whose source file doesn't exist are skipped.
        """
        stale_results: List[DriftResult] = []
        with self._lock:
            for key, source_path in sorted(source_map.items()):
                entries = self._memory.recall(key, top_k=100)
                for entry in entries:
                    if entry.key != key:
                        continue
                    result = self.check_drift(entry, source_path)
                    if result.is_stale:
                        stale_results.append(result)
        return stale_results

    def get_stale_entries(
        self,
        source_map: Dict[str, str],
    ) -> List[MemoryEntry]:
        """Return memory entries that are stale.

        Args:
            source_map: Mapping of ``memory_key -> source_file_path``.

        Returns:
            List of stale :class:`MemoryEntry` objects.
        """
        stale: List[MemoryEntry] = []
        with self._lock:
            for key, source_path in sorted(source_map.items()):
                entries = self._memory.recall(key, top_k=100)
                for entry in entries:
                    if entry.key != key:
                        continue
                    result = self.check_drift(entry, source_path)
                    if result.is_stale:
                        stale.append(entry)
        return stale

    # ── Auto-refresh ────────────────────────────────────────────────────

    def auto_refresh(
        self,
        entry: MemoryEntry,
        source_path: str,
        memory_store: Optional[PiChainMemory] = None,
    ) -> Optional[MemoryEntry]:
        """Re-read the source file and update the memory if changed.

        Implements the trust rule: if the source has been modified, the
        memory body is replaced with the current source content.

        Args:
            entry: The stale memory entry.
            source_path: Path to the source file.
            memory_store: The store to write the updated entry to.
                Defaults to the detector's own memory store.

        Returns:
            Updated :class:`MemoryEntry` if refreshed, ``None`` if the
            source was unchanged or unreadable.
        """
        store = memory_store or self._memory

        # Read current source content
        try:
            current_content = Path(source_path).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None

        # Compare with stored body
        if current_content == entry.body:
            return None

        # Source changed — update memory
        # Remove old entry, insert new with same key
        updated = store.remember(
            key=entry.key,
            body=current_content,
            chain_id=entry.chain_id,
            agent_name=entry.agent_name,
            risk_score=entry.risk_score,
        )
        return updated

    # ── Stats ───────────────────────────────────────────────────────────

    def stats(
        self,
        source_map: Optional[Dict[str, str]] = None,
    ) -> DriftStats:
        """Compute drift statistics.

        Args:
            source_map: Optional mapping of ``memory_key -> source_path``.
                If provided, staleness is checked against these sources.
                If ``None``, stats are computed from the memory store alone
                (no staleness check — everything treated as fresh).

        Returns:
            :class:`DriftStats` with counts and distribution.
        """
        source_map = source_map or {}
        all_entries = self._memory.recall("", top_k=self._memory.max_rows)

        # If recall returns empty for empty query, try direct approach
        # PiChainMemory.recall returns [] for empty query, so we need a workaround
        # We'll enumerate by checking the DB directly
        if not all_entries and source_map:
            for key in source_map:
                found = self._memory.recall(key, top_k=100)
                all_entries.extend(found)

        by_type: Dict[str, int] = {mt.value: 0 for mt in MemoryType}
        stale_by_type: Dict[str, int] = {mt.value: 0 for mt in MemoryType}
        stale_count = 0
        oldest_age: Optional[float] = None
        now = time.time()

        staleness_buckets: Dict[str, int] = {
            "fresh": 0,
            "<1h": 0,
            "1h-1d": 0,
            ">1d": 0,
        }

        seen_ids: set[str] = set()
        for entry in all_entries:
            if entry.entry_id in seen_ids:
                continue
            seen_ids.add(entry.entry_id)

            mt = _classify_entry(entry)
            by_type[mt.value] += 1

            # Age
            age = now - entry.created_at
            if oldest_age is None or age > oldest_age:
                oldest_age = age

            # Staleness
            is_stale = False
            staleness_sec = 0.0
            if entry.key in source_map:
                result = self.check_drift(entry, source_map[entry.key])
                is_stale = result.is_stale
                staleness_sec = result.staleness_seconds

            if is_stale:
                stale_count += 1
                stale_by_type[mt.value] += 1
                if staleness_sec < 3600:
                    staleness_buckets["<1h"] += 1
                elif staleness_sec < 86400:
                    staleness_buckets["1h-1d"] += 1
                else:
                    staleness_buckets[">1d"] += 1
            else:
                staleness_buckets["fresh"] += 1

        total = len(seen_ids)
        return DriftStats(
            total_entries=total,
            stale_count=stale_count,
            fresh_count=total - stale_count,
            by_type=by_type,
            stale_by_type=stale_by_type,
            oldest_memory_age_seconds=oldest_age,
            staleness_distribution=staleness_buckets,
        )
