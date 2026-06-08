"""
providers.py - RE target provider pattern (Theme 3, P3).

Each target (antigravity-ide, orbstack, ...) is modeled as a ``TargetProvider``
exposing three operations - binary acquisition, behavior capture, patch - behind
a thread-safe ``ProviderRegistry`` with a single ``dispatch()`` site. The single
dispatch point keeps every cross-target operation auditable and replayable
(this is the same "one labeled dispatcher" discipline applied to providers; see
playbook.Campaign._dispatch for the per-campaign version).
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import Any, Dict, List

VALID_OPS = ("acquire", "behavior", "patch")


class ProviderNotFound(KeyError):
    """Raised when no provider is registered for a target."""


class TargetProvider(ABC):
    """A reverse-engineering provider for one target."""

    target: str = ""

    @abstractmethod
    def acquire(self) -> Dict[str, Any]:
        """Acquire the binary/app + record provenance."""

    @abstractmethod
    def behavior(self) -> Dict[str, Any]:
        """Capture/ingest runtime behavior."""

    @abstractmethod
    def patch(self) -> Dict[str, Any]:
        """Produce/apply a patch plan."""


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: Dict[str, TargetProvider] = {}
        self._lock = threading.Lock()

    def register(self, provider: TargetProvider) -> None:
        if not getattr(provider, "target", ""):
            raise ValueError("provider must set a non-empty .target")
        with self._lock:
            self._providers[provider.target] = provider

    def get(self, target: str) -> TargetProvider:
        with self._lock:
            if target not in self._providers:
                raise ProviderNotFound(target)
            return self._providers[target]

    def list_targets(self) -> List[str]:
        with self._lock:
            return sorted(self._providers)

    def dispatch(self, target: str, op: str, **kwargs: Any) -> Dict[str, Any]:
        """Single auditable site for every provider operation."""
        if op not in VALID_OPS:
            raise ValueError(f"invalid op '{op}'. Must be one of {VALID_OPS}.")
        provider = self.get(target)
        return getattr(provider, op)(**kwargs)
