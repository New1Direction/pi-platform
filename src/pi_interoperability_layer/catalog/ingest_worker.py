"""Package Catalog Ingest Worker.

Deterministic worker that pulls packages from Notte catalog
and normalizes them into governed capability manifests.
No state mutation. No credential storage.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from pi_extension_governor.manifest import (
    CapabilityClass,
    ExtensionManifest,
    ExtensionStatus,
    TrustZone,
)

from pi_interoperability_layer.catalog.notte_client import (
    CatalogPage,
    CatalogSearchResult,
    NotteCatalogClient,
)


@dataclass(frozen=True)
class CatalogIngestReceipt:
    """Immutable receipt for catalog ingestion."""

    ingest_id: str
    page: int
    packages_ingested: int
    raw_hash: str
    normalized_manifests: Tuple[ExtensionManifest, ...]
    timestamp: str
    receipt_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "ingest_id": self.ingest_id,
                "page": self.page,
                "packages": self.packages_ingested,
                "raw_hash": self.raw_hash,
                "manifests": [m.compute_hash() for m in self.normalized_manifests],
                "timestamp": self.timestamp,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class PackageCatalogIngestWorker:
    """Deterministic catalog ingestion worker.

    Inputs: search query, page parameters.
    Outputs: normalized ExtensionManifests + ingest receipt.
    No credential storage. API key from env only.
    """

    def __init__(self, client: Optional[NotteCatalogClient] = None) -> None:
        self.client = client

    def ingest_page(
        self,
        query: str = "",
        package_type: str = "all",
        page: int = 1,
        page_size: int = 20,
    ) -> CatalogIngestReceipt:
        """Ingest a single page of catalog results."""
        client = self.client or NotteCatalogClient()
        catalog_page = client.search(query, package_type, page, page_size)
        manifests: List[ExtensionManifest] = []
        for pkg in catalog_page.packages:
            manifest = self._normalize_to_manifest(pkg)
            manifests.append(manifest)
        receipt = CatalogIngestReceipt(
            ingest_id=f"ingest_{page}_{catalog_page.page_hash[:16]}",
            page=page,
            packages_ingested=len(manifests),
            raw_hash=catalog_page.page_hash,
            normalized_manifests=tuple(manifests),
            timestamp=datetime.now(timezone.utc).isoformat(),
            receipt_hash="",
        )
        # Recreate with computed hash
        receipt = CatalogIngestReceipt(
            ingest_id=receipt.ingest_id,
            page=receipt.page,
            packages_ingested=receipt.packages_ingested,
            raw_hash=receipt.raw_hash,
            normalized_manifests=receipt.normalized_manifests,
            timestamp=receipt.timestamp,
            receipt_hash=receipt.compute_hash(),
        )
        return receipt

    def ingest_package(self, package_name: str) -> CatalogIngestReceipt:
        """Ingest a specific package by name."""
        client = self.client or NotteCatalogClient()
        pkg = client.package_details(package_name)
        manifest = self._normalize_to_manifest(pkg)
        receipt = CatalogIngestReceipt(
            ingest_id=f"ingest_pkg_{pkg.package_name}_{pkg.raw_metadata_hash[:16]}",
            page=1,
            packages_ingested=1,
            raw_hash=pkg.raw_metadata_hash,
            normalized_manifests=(manifest,),
            timestamp=datetime.now(timezone.utc).isoformat(),
            receipt_hash="",
        )
        receipt = CatalogIngestReceipt(
            ingest_id=receipt.ingest_id,
            page=receipt.page,
            packages_ingested=receipt.packages_ingested,
            raw_hash=receipt.raw_hash,
            normalized_manifests=receipt.normalized_manifests,
            timestamp=receipt.timestamp,
            receipt_hash=receipt.compute_hash(),
        )
        return receipt

    def _normalize_to_manifest(self, pkg: CatalogSearchResult) -> ExtensionManifest:
        """Normalize a catalog package into a governed ExtensionManifest.

        Classification is deferred to CapabilityClassifierWorker.
        All new packages start as SANDBOX_EXPERIMENTAL.
        """
        return ExtensionManifest(
            extension_id=f"catalog_{pkg.package_name}_{pkg.package_version}",
            package_name=pkg.package_name,
            package_version=pkg.package_version,
            package_hash="",
            capability_class=CapabilityClass.STATIC_ANALYZER,  # default; classifier overrides
            description=pkg.description,
            entrypoint="index.js",
            dependencies=list(pkg.dependencies),
            trust_zone=TrustZone.SANDBOX_EXPERIMENTAL,
            telemetry_surfaces=[],
            resource_cpu_ms_max=5000,
            replayability_claim=False,  # must be proven in sandbox
            deterministic_claim=False,  # must be proven in sandbox
            metadata={
                "catalog_source": "notte_pi_packages",
                "catalog_type": pkg.package_type,
                "keywords": list(pkg.keywords),
                "author": pkg.author,
                "license": pkg.license,
                "raw_fingerprint": pkg.compute_fingerprint(),
            },
            status=ExtensionStatus.PENDING_INSPECTION,
        )
