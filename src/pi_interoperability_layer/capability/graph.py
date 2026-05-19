"""Extension Compatibility Graph.

Deterministic compatibility matrix for capabilities.
Tracks dependency, conflict, and requirement relationships
in a directed graph enforced before installation.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from pi_extension_governor.manifest import CapabilityClass, TrustZone
from pi_extension_governor.manifest import ExtensionManifest


class CompatibilityType(Enum):
    DEPENDS_ON = "depends_on"
    CONFLICTS_WITH = "conflicts_with"
    REQUIRES_CAPABILITY = "requires_capability"
    PROVIDES_CAPABILITY = "provides_capability"
    SUPERSEDES = "supersedes"
    COMPATIBLE_WITH = "compatible_with"


class CompatibilityVerdict(Enum):
    COMPATIBLE = "compatible"
    CONFLICT = "conflict"
    MISSING_DEPENDENCY = "missing_dependency"
    ZONE_INCOMPATIBLE = "zone_incompatible"
    CAPABILITY_MISMATCH = "capability_mismatch"
    VERSION_INCOMPATIBLE = "version_incompatible"


@dataclass(frozen=True)
class CompatibilityEdge:
    source_id: str
    target_id: str
    edge_type: CompatibilityType
    reason: str = ""


@dataclass(frozen=True)
class CompatibilityCheck:
    verdict: CompatibilityVerdict
    evidence: str
    source_id: str
    target_id: str
    edges: Tuple[CompatibilityEdge, ...] = field(default_factory=tuple)


class ExtensionCompatibilityGraph:
    """Directed graph of extension relationships.

    Deterministic. No learning. Validated at install time.
    """

    def __init__(self) -> None:
        self._edges: Dict[str, List[CompatibilityEdge]] = {}
        self._capability_providers: Dict[CapabilityClass, Set[str]] = {}
        self._installed: Set[str] = set()

    def declare_edge(self, edge: CompatibilityEdge) -> None:
        self._edges.setdefault(edge.source_id, []).append(edge)
        if edge.edge_type == CompatibilityType.PROVIDES_CAPABILITY:
            # Infer capability from edge reason if not explicit
            self._register_capability_if_needed(edge.source_id, edge.reason)

    def register_installed(self, extension_id: str) -> None:
        self._installed.add(extension_id)

    def deregister(self, extension_id: str) -> None:
        self._installed.discard(extension_id)
        self._edges.pop(extension_id, None)
        # Clean up capability providers
        for cap, providers in list(self._capability_providers.items()):
            providers.discard(extension_id)
            if not providers:
                del self._capability_providers[cap]

    def check_compatibility(self, source_id: str, target_id: str) -> CompatibilityCheck:
        """Check compatibility between two extension IDs.

        Returns CONFLICT if there is a CONFLICTS_WITH edge between them.
        Returns COMPATIBLE otherwise.
        """
        for edge in self._edges.get(source_id, []):
            if edge.target_id == target_id and edge.edge_type == CompatibilityType.CONFLICTS_WITH:
                return CompatibilityCheck(
                    verdict=CompatibilityVerdict.CONFLICT,
                    evidence=edge.reason,
                    source_id=source_id,
                    target_id=target_id,
                    edges=(edge,),
                )
        for edge in self._edges.get(target_id, []):
            if edge.target_id == source_id and edge.edge_type == CompatibilityType.CONFLICTS_WITH:
                return CompatibilityCheck(
                    verdict=CompatibilityVerdict.CONFLICT,
                    evidence=edge.reason,
                    source_id=source_id,
                    target_id=target_id,
                    edges=(edge,),
                )
        return CompatibilityCheck(
            verdict=CompatibilityVerdict.COMPATIBLE,
            evidence="No conflicts detected",
            source_id=source_id,
            target_id=target_id,
        )

    def check_install(
        self,
        extension_id: str,
        manifest: ExtensionManifest,
        registry_lookup: callable,
    ) -> List[CompatibilityCheck]:
        results: List[CompatibilityCheck] = []

        # 1. Identity conflict check
        if extension_id in self._installed:
            results.append(
                CompatibilityCheck(
                    verdict=CompatibilityVerdict.CONFLICT,
                    evidence="Extension already installed",
                    source_id=extension_id,
                    target_id=extension_id,
                )
            )

        # 2. Zone compatibility
        if manifest.trust_zone == TrustZone.SANDBOX_EXPERIMENTAL:
            for installed_id in self._installed:
                entry = registry_lookup(installed_id)
                if entry and entry.trust_zone == TrustZone.CORE_TRUSTED:
                    results.append(
                        CompatibilityCheck(
                            verdict=CompatibilityVerdict.ZONE_INCOMPATIBLE,
                            evidence="Sandbox extension cannot coexist with core trusted",
                            source_id=extension_id,
                            target_id=installed_id,
                        )
                    )

        # 3. Dependency resolution
        depends = [e for e in self._edges.get(extension_id, []) if e.edge_type == CompatibilityType.DEPENDS_ON]
        for dep in depends:
            if dep.target_id not in self._installed:
                results.append(
                    CompatibilityCheck(
                        verdict=CompatibilityVerdict.MISSING_DEPENDENCY,
                        evidence=f"Missing required dependency: {dep.target_id}",
                        source_id=extension_id,
                        target_id=dep.target_id,
                        edges=(dep,),
                    )
                )

        # 4. Conflict checks
        conflicts = [e for e in self._edges.get(extension_id, []) if e.edge_type == CompatibilityType.CONFLICTS_WITH]
        for c in conflicts:
            if c.target_id in self._installed:
                results.append(
                    CompatibilityCheck(
                        verdict=CompatibilityVerdict.CONFLICT,
                        evidence=f"Conflicts with installed extension: {c.target_id} ({c.reason})",
                        source_id=extension_id,
                        target_id=c.target_id,
                        edges=(c,),
                    )
                )

        # 5. Capability requirement satisfaction
        requires = [e for e in self._edges.get(extension_id, []) if e.edge_type == CompatibilityType.REQUIRES_CAPABILITY]
        for req in requires:
            cap_class = self._parse_capability_from_reason(req.reason)
            providers = self._capability_providers.get(cap_class, set())
            if not providers:
                results.append(
                    CompatibilityCheck(
                        verdict=CompatibilityVerdict.CAPABILITY_MISMATCH,
                        evidence=f"No provider for required capability: {cap_class.value}",
                        source_id=extension_id,
                        target_id=req.target_id,
                        edges=(req,),
                    )
                )

        return results

    def transitive_closure(self, extension_id: str) -> Set[str]:
        """Return all extensions reachable via DEPENDS_ON edges."""
        visited: Set[str] = set()
        stack = [extension_id]
        while stack:
            current = stack.pop()
            if current in visited:
                continue
            visited.add(current)
            for e in self._edges.get(current, []):
                if e.edge_type == CompatibilityType.DEPENDS_ON:
                    stack.append(e.target_id)
        return visited

    def topological_phase_order(self) -> List[Set[str]]:
        """Deterministic topological sort by in-degree.
        Returns phases (sets of extensions that can execute in parallel).
        """
        in_degree: Dict[str, int] = {}
        adjacency: Dict[str, List[str]] = {}
        for src, edges in self._edges.items():
            in_degree.setdefault(src, 0)
            adjacency.setdefault(src, [])
            for e in edges:
                if e.edge_type == CompatibilityType.DEPENDS_ON:
                    adjacency[src].append(e.target_id)
                    in_degree[e.target_id] = in_degree.get(e.target_id, 0) + 1

        phases: List[Set[str]] = []
        remaining = {k for k in in_degree if k in self._installed}
        while remaining:
            phase = {k for k in remaining if in_degree.get(k, 0) == 0}
            if not phase:
                break  # cycle detected
            phases.append(phase)
            remaining -= phase
            for k in phase:
                for dep in adjacency.get(k, []):
                    if dep in in_degree:
                        in_degree[dep] -= 1
        return phases

    def _register_capability_if_needed(self, extension_id: str, reason: str) -> None:
        cap = self._parse_capability_from_reason(reason)
        if cap:
            self._capability_providers.setdefault(cap, set()).add(extension_id)

    @staticmethod
    def _parse_capability_from_reason(reason: str) -> Optional[CapabilityClass]:
        for cap in CapabilityClass:
            if cap.value in reason.lower():
                return cap
        return None

    def to_hashes(self) -> str:
        """Deterministic hash of the graph state."""
        lines = []
        for src in sorted(self._edges):
            for e in sorted(self._edges[src], key=lambda x: (x.target_id, x.edge_type.value)):
                lines.append(f"{src}->{e.target_id}:{e.edge_type.value}")
        return hashlib.sha256("|".join(lines).encode()).hexdigest()
