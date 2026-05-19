"""Dependency Graph Expansion Worker.

Integrates npm-style package dependencies into the existing
ExtensionCompatibilityGraph as CapabilityClass-aware edges.
Deterministic. No inference.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from pi_extension_governor.manifest import CapabilityClass, ExtensionManifest

from pi_interoperability_layer.capability.graph import (
    CompatibilityEdge,
    CompatibilityType,
    ExtensionCompatibilityGraph,
)


@dataclass(frozen=True)
class DependencyExpansionReceipt:
    manifest_id: str
    edges_added: int
    conflicts_detected: int
    missing_deps: Tuple[str, ...]
    receipt_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "manifest_id": self.manifest_id,
                "edges": self.edges_added,
                "conflicts": self.conflicts_detected,
                "missing": sorted(self.missing_deps),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class DependencyGraphExpansionWorker:
    """Deterministic dependency expansion for catalog packages.

    Maps npm dependencies to compatibility graph edges.
    Produces DEPENDS_ON edges with capability class inference.
    """

    def __init__(self, graph: Optional[ExtensionCompatibilityGraph] = None) -> None:
        self.graph = graph or ExtensionCompatibilityGraph()

    def expand(
        self,
        manifest: ExtensionManifest,
        known_manifests: Optional[Dict[str, ExtensionManifest]] = None,
    ) -> DependencyExpansionReceipt:
        """Expand a manifest's dependencies into the compatibility graph.

        Args:
            manifest: The package whose dependencies to expand.
            known_manifests: Map of dependency name → known ExtensionManifest.
                             If a dependency is not known, it is recorded as missing.
        """
        known = known_manifests or {}
        edges_added = 0
        conflicts = 0
        missing: List[str] = []

        for dep in manifest.dependencies:
            dep_name = self._strip_version(dep)
            if dep_name in known:
                dep_manifest = known[dep_name]
                edge = CompatibilityEdge(
                    source_id=manifest.extension_id,
                    target_id=dep_manifest.extension_id,
                    edge_type=CompatibilityType.DEPENDS_ON,
                    reason=f"Dependency: {dep} ({manifest.capability_class.value} → {dep_manifest.capability_class.value})",
                )
                self.graph.declare_edge(edge)
                edges_added += 1
                # Install-time conflict validation belongs in the pipeline, not here.
                # Edge construction records topology only.
            else:
                missing.append(dep_name)

        receipt = DependencyExpansionReceipt(
            manifest_id=manifest.extension_id,
            edges_added=edges_added,
            conflicts_detected=conflicts,
            missing_deps=tuple(sorted(set(missing))),
            receipt_hash="",
        )
        return DependencyExpansionReceipt(
            manifest_id=receipt.manifest_id,
            edges_added=receipt.edges_added,
            conflicts_detected=receipt.conflicts_detected,
            missing_deps=receipt.missing_deps,
            receipt_hash=receipt.compute_hash(),
        )

    @staticmethod
    def _strip_version(dep: str) -> str:
        """Strip version specifier from npm dependency string.

        Handles:
        - package-name
        - package-name@^1.0.0
        - @scope/package@~2.0.0
        """
        if "@" not in dep:
            return dep
        parts = dep.rsplit("@", 1)
        # Scoped packages: @scope/name@version
        if dep.startswith("@"):
            if parts[0].count("@") == 1 and "/" in parts[0]:
                # @scope/name@version
                return parts[0]
            elif parts[0].startswith("@") and "/" in parts[0]:
                return parts[0]
        # Regular package: name@version
        if "/" not in parts[0]:
            return parts[0]
        return dep
