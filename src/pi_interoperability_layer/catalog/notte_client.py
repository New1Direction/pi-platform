"""Notte Pi-Package Catalog Client.

Thin deterministic client for the Notte pi-packages-catalog function.
API key is read exclusively from the NOTTE_API_KEY environment variable.
No hardcoded credentials. No state mutation. Replay-safe.
"""

from __future__ import annotations

import hashlib
import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

NOTTE_CATALOG_ENDPOINT = (
    "https://us-prod.notte.cc/functions/71b6214f-16c4-4702-b0c3-b3c948debf8a/runs/start"
)


@dataclass(frozen=True)
class CatalogSearchResult:
    """Normalized result from a catalog search."""

    package_name: str
    package_version: str
    package_type: str
    description: str
    keywords: Tuple[str, ...]
    author: str
    license: str
    dependencies: Tuple[str, ...]
    dev_dependencies: Tuple[str, ...]
    raw_metadata_hash: str
    ingest_timestamp: str

    def compute_fingerprint(self) -> str:
        canonical = json.dumps(
            {
                "name": self.package_name,
                "version": self.package_version,
                "type": self.package_type,
                "description": self.description,
                "keywords": sorted(self.keywords),
                "author": self.author,
                "license": self.license,
                "dependencies": sorted(self.dependencies),
                "dev_dependencies": sorted(self.dev_dependencies),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode()).hexdigest()


@dataclass(frozen=True)
class CatalogPage:
    """A single page of catalog results."""

    page: int
    page_size: int
    total_packages: int
    packages: List[CatalogSearchResult]
    page_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "page": self.page,
                "page_size": self.page_size,
                "total": self.total_packages,
                "packages": [p.compute_fingerprint() for p in self.packages],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class NotteCatalogClient:
    """Deterministic client for Notte pi-packages-catalog.

    All calls are replayable given the same inputs.
    No ambient state. No credential storage.
    """

    def __init__(self, endpoint: Optional[str] = None) -> None:
        self.endpoint = endpoint or NOTTE_CATALOG_ENDPOINT
        self._api_key = os.environ.get("NOTTE_API_KEY", "")
        if not self._api_key:
            raise RuntimeError(
                "NOTTE_API_KEY environment variable is required. "
                "Set it before initializing NotteCatalogClient."
            )

    def search(
        self,
        query: str = "",
        package_type: str = "all",
        page: int = 1,
        page_size: int = 20,
    ) -> CatalogPage:
        """Execute a catalog search via the Notte function.

        Returns a deterministic CatalogPage.
        """
        payload: Dict[str, Any] = {
            "function_id": "71b6214f-16c4-4702-b0c3-b3c948debf8a",
            "variables": {
                "action": "search",
                "query": query,
                "package_name": "",
                "package_type": package_type,
                "page": page,
                "page_size": page_size,
            },
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "x-notte-api-key": self._api_key,
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode()
        raw_hash = hashlib.sha256(raw.encode()).hexdigest()
        data = json.loads(raw)
        return self._normalize_page(data, page, page_size, raw_hash)

    def package_details(self, package_name: str) -> CatalogSearchResult:
        """Fetch details for a specific package."""
        payload: Dict[str, Any] = {
            "function_id": "71b6214f-16c4-4702-b0c3-b3c948debf8a",
            "variables": {
                "action": "details",
                "query": "",
                "package_name": package_name,
                "package_type": "all",
                "page": 1,
                "page_size": 1,
            },
        }
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "x-notte-api-key": self._api_key,
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read().decode()
        raw_hash = hashlib.sha256(raw.encode()).hexdigest()
        data = json.loads(raw)
        return self._normalize_package(data, raw_hash)

    def _normalize_page(
        self,
        data: Dict[str, Any],
        page: int,
        page_size: int,
        raw_hash: str,
    ) -> CatalogPage:
        packages: List[CatalogSearchResult] = []
        total = 0
        if isinstance(data, dict):
            results = data.get("results") or data.get("packages") or data.get("data") or []
            total = data.get("total") or data.get("total_packages") or len(results)
            if isinstance(results, list):
                for item in results:
                    pkg = self._normalize_package(item, raw_hash)
                    packages.append(pkg)
        return CatalogPage(
            page=page,
            page_size=page_size,
            total_packages=total,
            packages=packages,
            page_hash=raw_hash,
        )

    def _normalize_package(self, item: Dict[str, Any], raw_hash: str) -> CatalogSearchResult:
        name = item.get("name") or item.get("package_name") or "unknown"
        version = item.get("version") or item.get("package_version") or "0.0.0"
        pkg_type = item.get("type") or item.get("package_type") or "npm"
        description = item.get("description") or ""
        keywords = tuple(sorted(set(item.get("keywords") or [])))
        author = item.get("author") or ""
        license_str = item.get("license") or ""
        deps = tuple(sorted(item.get("dependencies") or []))
        dev_deps = tuple(sorted(item.get("dev_dependencies") or []))
        return CatalogSearchResult(
            package_name=name,
            package_version=version,
            package_type=pkg_type,
            description=description,
            keywords=keywords,
            author=author,
            license=license_str,
            dependencies=deps,
            dev_dependencies=dev_deps,
            raw_metadata_hash=raw_hash,
            ingest_timestamp="",
        )
