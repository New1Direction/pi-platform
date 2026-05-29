"""Connector Marketplace + Governance Integration.

Extends the Capability Marketplace to support connector admission,
compatibility validation, trust-tier enforcement, and governance compilation.

All connector registrations are append-only. Historical versions preserved.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

from pi_connector_fabric.sdk.core import ConnectorCapabilityClass, ConnectorManifest, ConnectorSandboxPolicy
from pi_event_fabric.governance.compiler import (
    Effect,
    GovernanceDecision,
    GovernanceEngine,
)


class ConnectorMarketplaceRegistry:
    """Append-only registry for connector manifests.

    Historical connector versions are never deleted.
    New versions create new records.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS connector_manifests (
        manifest_id TEXT PRIMARY KEY,
        connector_id TEXT NOT NULL,
        version TEXT NOT NULL,
        name TEXT NOT NULL,
        manifest_json TEXT NOT NULL,
        manifest_hash TEXT NOT NULL,
        trust_tier TEXT NOT NULL,
        verified INTEGER NOT NULL DEFAULT 0,
        registered_at TEXT NOT NULL,
        registered_by TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS connector_signatures (
        signature_id TEXT PRIMARY KEY,
        connector_id TEXT NOT NULL,
        version TEXT NOT NULL,
        signature_hash TEXT NOT NULL,
        signed_at TEXT NOT NULL,
        signed_by TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_connector_id ON connector_manifests(connector_id);
    CREATE INDEX IF NOT EXISTS idx_trust_tier ON connector_manifests(trust_tier);
    """

    TRUST_TIERS: Set[str] = {"unverified", "community", "verified", "certified", "governance_approved"}

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._lock:
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.executescript(self.SCHEMA)
            conn.commit()
            conn.close()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def register(
        self,
        manifest: ConnectorManifest,
        registered_by: str = "system",
    ) -> Tuple[bool, str]:
        """Register a connector manifest."""
        manifest_id = f"{manifest.connector_id}@{manifest.version}"
        with self._lock:
            conn = self._conn()
            existing = conn.execute(
                "SELECT manifest_hash FROM connector_manifests WHERE manifest_id = ?",
                (manifest_id,),
            ).fetchone()
            if existing:
                conn.close()
                return False, f"Manifest {manifest_id} already registered"

            conn.execute(
                """INSERT INTO connector_manifests
                   (manifest_id, connector_id, version, name, manifest_json, manifest_hash,
                    trust_tier, verified, registered_at, registered_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)""",
                (
                    manifest_id, manifest.connector_id, manifest.version,
                    manifest.name, json.dumps(manifest.to_dict(), sort_keys=True),
                    manifest.manifest_hash, manifest.trust_tier,
                    1 if manifest.author_verified else 0, registered_by,
                ),
            )
            conn.commit()
            conn.close()
        return True, f"Registered {manifest_id} (hash={manifest.manifest_hash[:16]})"

    def list_connectors(
        self,
        trust_tier: Optional[str] = None,
        capability: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            if trust_tier:
                rows = conn.execute(
                    "SELECT * FROM connector_manifests WHERE trust_tier = ? ORDER BY registered_at DESC",
                    (trust_tier,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM connector_manifests ORDER BY registered_at DESC"
                ).fetchall()
            conn.close()

        results = []
        for row in rows:
            manifest = json.loads(row["manifest_json"])
            if capability and capability not in manifest.get("capability_classes", []):
                continue
            results.append(dict(row))
        return results

    def get_manifest(self, connector_id: str, version: str) -> Optional[ConnectorManifest]:
        manifest_id = f"{connector_id}@{version}"
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT manifest_json FROM connector_manifests WHERE manifest_id = ?",
                (manifest_id,),
            ).fetchone()
            conn.close()
        if not row:
            return None
        data = json.loads(row["manifest_json"])
        return ConnectorManifest(
            connector_id=data["connector_id"],
            name=data["name"],
            version=data["version"],
            description=data["description"],
            capability_classes=tuple(ConnectorCapabilityClass(c) for c in data["capability_classes"]),
            sandbox_policy=ConnectorSandboxPolicy(data["sandbox_policy"]),
            target_systems=tuple(data["target_systems"]),
            output_schemas=tuple(data["output_schemas"]),
            required_credentials=tuple(data["required_credentials"]),
            config_schema=data["config_schema"],
            author_verified=data["author_verified"],
            trust_tier=data["trust_tier"],
        )

    def sign_connector(
        self,
        connector_id: str,
        version: str,
        signer_id: str,
    ) -> str:
        """Produce deterministic signature hash for a connector."""
        manifest = self.get_manifest(connector_id, version)
        if not manifest:
            raise ValueError(f"Manifest not found: {connector_id}@{version}")

        sig_data = json.dumps({
            "connector_id": connector_id,
            "version": version,
            "manifest_hash": manifest.manifest_hash,
            "signer": signer_id,
            "timestamp": manifest.manifest_hash[:16],  # deterministic proxy
        }, sort_keys=True, separators=(",", ":"))
        sig_hash = hashlib.sha256(sig_data.encode()).hexdigest()

        signature_id = f"sig_{connector_id}_{version}_{sig_hash[:16]}"
        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT OR IGNORE INTO connector_signatures
                   (signature_id, connector_id, version, signature_hash, signed_at, signed_by)
                   VALUES (?, ?, ?, ?, datetime('now'), ?)""",
                (signature_id, connector_id, version, sig_hash, signer_id),
            )
            conn.commit()
            conn.close()
        return sig_hash

    def verify_signature(self, connector_id: str, version: str) -> bool:
        """Check if a connector has been signed."""
        with self._lock:
            conn = self._conn()
            row = conn.execute(
                "SELECT 1 FROM connector_signatures WHERE connector_id = ? AND version = ?",
                (connector_id, version),
            ).fetchone()
            conn.close()
        return row is not None


class ConnectorGovernance:
    """Governance integration for connector execution.

    Uses the existing GovernanceEngine + GovernanceRegistry.
    Fail-closed: no connector runs without explicit policy match.
    """

    def __init__(self, marketplace: ConnectorMarketplaceRegistry, governance: GovernanceEngine) -> None:
        self.marketplace = marketplace
        self.governance = governance

    def evaluate_connector_ingestion(
        self,
        connector_id: str,
        version: str,
        tenant_id: str,
        actor_id: str,
        correlation_id: str,
    ) -> GovernanceDecision:
        """Evaluate governance policy for a connector ingestion request."""
        manifest = self.marketplace.get_manifest(connector_id, version)
        if not manifest:
            # Unknown connector = fail closed
            return GovernanceDecision(
                decision_id=f"dec_{correlation_id}_unknown",
                context_id=correlation_id,
                effect=Effect.DENY,
                matched_rules=[],
                denied_by="governance:unknown_connector",
                evaluated_at="",
            )

        context = {
            "connector_id": connector_id,
            "connector_trust_tier": manifest.trust_tier,
            "sandbox_policy": manifest.sandbox_policy.value,
            "tenant_id": tenant_id,
            "actor_id": actor_id,
            "action": "connector:ingest",
            "correlation_id": correlation_id,
            "timestamp": "",
        }
        return self.governance.evaluate(context)

    def enforce_minimum_trust(
        self,
        connector_id: str,
        version: str,
        minimum_tier: str,
    ) -> bool:
        """Enforce minimum trust tier for connector execution."""
        manifest = self.marketplace.get_manifest(connector_id, version)
        if not manifest:
            return False
        tier_order = ["unverified", "community", "verified", "certified", "governance_approved"]
        try:
            return tier_order.index(manifest.trust_tier) >= tier_order.index(minimum_tier)
        except ValueError:
            return False
