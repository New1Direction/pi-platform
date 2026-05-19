"""Ecosystem Trust Zone Enforcement.

Splits ecosystem into CORE_TRUSTED, GOVERNED_EXTENSION, SANDBOX_EXPERIMENTAL.
Experimental packages never gain governance authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from pi_extension_governor.manifest import ExtensionManifest, ExtensionStatus, TrustZone


@dataclass(frozen=True)
class TrustZoneDecision:
    manifest_id: str
    requested_zone: TrustZone
    assigned_zone: TrustZone
    allowed: bool
    reason: str


class TrustZoneEnforcer:
    """Deterministic trust zone enforcement for extension packages."""

    def __init__(
        self,
        core_trusted_packages: Optional[Set[str]] = None,
        sandbox_always_experimental: bool = True,
    ) -> None:
        self.core_trusted_packages = core_trusted_packages or set()
        self.sandbox_always_experimental = sandbox_always_experimental

    def evaluate(self, manifest: ExtensionManifest) -> TrustZoneDecision:
        """Determine trust zone for an extension.

        Rules:
        - CORE_TRUSTED: only if explicitly in core_trusted_packages AND passes all governance
        - GOVERNED_EXTENSION: standard path for admitted extensions
        - SANDBOX_EXPERIMENTAL: default for new/untrusted extensions; never gains governance authority
        """
        requested = manifest.trust_zone

        # Experimental packages are always experimental
        if self.sandbox_always_experimental and requested == TrustZone.SANDBOX_EXPERIMENTAL:
            return TrustZoneDecision(
                manifest_id=manifest.extension_id,
                requested_zone=requested,
                assigned_zone=TrustZone.SANDBOX_EXPERIMENTAL,
                allowed=True,
                reason="Experimental packages remain in sandbox; no governance authority granted",
            )

        # Core trusted requires explicit allowlist
        if requested == TrustZone.CORE_TRUSTED:
            if manifest.package_hash in self.core_trusted_packages:
                return TrustZoneDecision(
                    manifest_id=manifest.extension_id,
                    requested_zone=requested,
                    assigned_zone=TrustZone.CORE_TRUSTED,
                    allowed=True,
                    reason="Package in core trusted allowlist",
                )
            else:
                return TrustZoneDecision(
                    manifest_id=manifest.extension_id,
                    requested_zone=requested,
                    assigned_zone=TrustZone.GOVERNED_EXTENSION,
                    allowed=True,
                    reason="Core trusted request denied; downgraded to governed extension",
                )

        # Governed extension path
        if requested == TrustZone.GOVERNED_EXTENSION:
            return TrustZoneDecision(
                manifest_id=manifest.extension_id,
                requested_zone=requested,
                assigned_zone=TrustZone.GOVERNED_EXTENSION,
                allowed=True,
                reason="Standard governed extension path",
            )

        # Default fallback
        return TrustZoneDecision(
            manifest_id=manifest.extension_id,
            requested_zone=requested,
            assigned_zone=TrustZone.SANDBOX_EXPERIMENTAL,
            allowed=True,
            reason="Default sandbox assignment",
        )

    def can_gain_governance_authority(self, manifest: ExtensionManifest) -> bool:
        """Experimental packages can NEVER gain governance authority."""
        return manifest.trust_zone != TrustZone.SANDBOX_EXPERIMENTAL
