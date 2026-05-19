"""Multi-Tenant SaaS Control Plane.

Deterministic tenant isolation for the semantic capability platform.
All artifacts are tenant-scoped. No cross-tenant leakage.
No probabilistic decision-making.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field

from pi_extension_governor.manifest import CapabilityClass, TrustZone


# ── Tenant Model ─────────────────────────────────────────────────

class TenantStatus(str, Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    PROVISIONING = "provisioning"
    DECOMMISSIONED = "decommissioned"


class TenantTier(str, Enum):
    DEVELOPMENT = "development"
    STANDARD = "standard"
    ENTERPRISE = "enterprise"


@dataclass(frozen=True)
class ResourceQuota:
    """Bounded resource limits for a tenant."""

    max_capabilities: int = 100
    max_executions_per_hour: int = 1000
    max_storage_mb: int = 1024  # 1GB
    max_graph_nodes: int = 500
    max_workers_per_execution: int = 10
    max_replay_retention_days: int = 30
    max_policy_rules: int = 50

    def check_add_capability(self, current_count: int) -> Tuple[bool, Optional[str]]:
        if current_count + 1 > self.max_capabilities:
            return False, f"Capability limit exceeded: {current_count}/{self.max_capabilities}"
        return True, None

    def check_storage(self, current_mb: int, new_mb: int) -> Tuple[bool, Optional[str]]:
        if current_mb + new_mb > self.max_storage_mb:
            return False, f"Storage limit exceeded: {current_mb + new_mb}/{self.max_storage_mb} MB"
        return True, None

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "max_capabilities": self.max_capabilities,
                "max_executions_per_hour": self.max_executions_per_hour,
                "max_storage_mb": self.max_storage_mb,
                "max_graph_nodes": self.max_graph_nodes,
                "max_workers_per_execution": self.max_workers_per_execution,
                "max_replay_retention_days": self.max_replay_retention_days,
                "max_policy_rules": self.max_policy_rules,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class Tenant(BaseModel):
    """Immutable tenant record with deterministic identity."""

    tenant_id: str
    tenant_name: str
    tier: TenantTier = TenantTier.DEVELOPMENT
    status: TenantStatus = TenantStatus.PROVISIONING
    quota: ResourceQuota = Field(default_factory=ResourceQuota)
    trust_zones: Set[TrustZone] = Field(default_factory=set)
    allowed_capability_classes: Set[CapabilityClass] = Field(default_factory=set)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)
    model_config = {"frozen": True}

    def compute_hash(self) -> str:
        payload = self.model_dump(
            exclude={"updated_at", "created_at"},
        )
        # Convert sets to sorted lists for determinism
        payload["trust_zones"] = sorted([z.value for z in self.trust_zones])
        payload["allowed_capability_classes"] = sorted([c.value for c in self.allowed_capability_classes])
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()


# ── Tenant Registry ──────────────────────────────────────────────

@dataclass(frozen=True)
class TenantRegistryEntry:
    tenant: Tenant
    capability_count: int = 0
    execution_count_hour: int = 0
    storage_used_mb: int = 0
    policy_count: int = 0
    registered_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_audit_hash: str = ""


class TenantRegistry:
    """Deterministic tenant registry with quota enforcement.

    Each tenant is an isolated namespace. No cross-tenant sharing
    except where explicitly declared via capability edges.
    """

    def __init__(self, root_dir: Optional[Path] = None) -> None:
        self.root_dir = root_dir or Path("./tenant_registry")
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._entries: Dict[str, TenantRegistryEntry] = {}
        self._audit_log: List[Dict[str, Any]] = []

    def register(self, tenant: Tenant) -> Tuple[bool, Optional[str]]:
        """Register a new tenant.

        Returns (success, error_message).
        """
        if tenant.tenant_id in self._entries:
            return False, "Tenant already exists"
        self._entries[tenant.tenant_id] = TenantRegistryEntry(
            tenant=tenant,
            last_audit_hash=tenant.compute_hash(),
        )
        self._audit(tenant.tenant_id, "REGISTER", tenant.compute_hash())
        return True, None

    def get(self, tenant_id: str) -> Optional[TenantRegistryEntry]:
        return self._entries.get(tenant_id)

    def get_all(self) -> Tuple[TenantRegistryEntry, ...]:
        return tuple(self._entries.values())

    def update_status(self, tenant_id: str, status: TenantStatus) -> bool:
        entry = self._entries.get(tenant_id)
        if not entry:
            return False
        updated_tenant = entry.tenant.model_copy(update={"status": status, "updated_at": datetime.now(timezone.utc)})
        self._entries[tenant_id] = TenantRegistryEntry(
            tenant=updated_tenant,
            capability_count=entry.capability_count,
            execution_count_hour=entry.execution_count_hour,
            storage_used_mb=entry.storage_used_mb,
            policy_count=entry.policy_count,
            registered_at=entry.registered_at,
            last_audit_hash=updated_tenant.compute_hash(),
        )
        self._audit(tenant_id, "UPDATE_STATUS", f"status={status.value}")
        return True

    def increment_capability(self, tenant_id: str) -> Tuple[bool, Optional[str]]:
        """Increment capability count for a tenant, enforcing quota."""
        entry = self._entries.get(tenant_id)
        if not entry:
            return False, "Tenant not found"
        ok, err = entry.tenant.quota.check_add_capability(entry.capability_count)
        if not ok:
            return False, err
        self._entries[tenant_id] = TenantRegistryEntry(
            tenant=entry.tenant,
            capability_count=entry.capability_count + 1,
            execution_count_hour=entry.execution_count_hour,
            storage_used_mb=entry.storage_used_mb,
            policy_count=entry.policy_count,
            registered_at=entry.registered_at,
            last_audit_hash=entry.last_audit_hash,
        )
        self._audit(tenant_id, "INCREMENT_CAPABILITY", f"count={entry.capability_count + 1}")
        return True, None

    def check_execution_allowed(self, tenant_id: str) -> Tuple[bool, Optional[str]]:
        """Check if tenant can execute, enforcing execution rate quota."""
        entry = self._entries.get(tenant_id)
        if not entry:
            return False, "Tenant not found"
        if entry.tenant.status != TenantStatus.ACTIVE:
            return False, f"Tenant status is {entry.tenant.status.value}, not active"
        if entry.execution_count_hour >= entry.tenant.quota.max_executions_per_hour:
            return False, f"Execution rate limit: {entry.execution_count_hour}/{entry.tenant.quota.max_executions_per_hour}"
        return True, None

    def record_execution(self, tenant_id: str) -> None:
        """Record an execution for rate limiting."""
        entry = self._entries.get(tenant_id)
        if entry:
            self._entries[tenant_id] = TenantRegistryEntry(
                tenant=entry.tenant,
                capability_count=entry.capability_count,
                execution_count_hour=entry.execution_count_hour + 1,
                storage_used_mb=entry.storage_used_mb,
                policy_count=entry.policy_count,
                registered_at=entry.registered_at,
                last_audit_hash=entry.last_audit_hash,
            )
            self._audit(tenant_id, "EXECUTION", f"hour_count={entry.execution_count_hour + 1}")

    def _audit(self, tenant_id: str, action: str, detail: str) -> None:
        self._audit_log.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tenant_id": tenant_id,
                "action": action,
                "detail": detail,
            }
        )

    def get_audit_log(self, tenant_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log, optionally filtered by tenant."""
        log = self._audit_log
        if tenant_id:
            log = [e for e in log if e["tenant_id"] == tenant_id]
        return log[-limit:]


# ── Tenant Policy Engine ─────────────────────────────────────────

@dataclass(frozen=True)
class TenantPolicyRule:
    """A tenant-scoped policy rule with evidence."""

    rule_id: str
    rule_type: str  # e.g., "capability_class_ban", "trust_zone_requirement"
    target_value: str
    action: str  # "allow" or "deny"
    evidence: str = ""


class TenantPolicyEngine:
    """Deterministic policy evaluation per tenant.

    Enforces per-tenant restrictions on capability classes,
    trust zones, and execution parameters.
    """

    DENY_OVERRIDES_ALLOW = True  # fail-closed

    def __init__(self) -> None:
        self._rules: Dict[str, List[TenantPolicyRule]] = {}  # tenant_id -> rules

    def add_rule(self, tenant_id: str, rule: TenantPolicyRule) -> None:
        rules = self._rules.setdefault(tenant_id, [])
        rules.append(rule)

    def evaluate_capability_class(
        self, tenant_id: str, cap_class: CapabilityClass
    ) -> Tuple[bool, str]:
        rules = self._rules.get(tenant_id, [])
        allows = [r for r in rules if r.rule_type == "capability_class" and r.target_value == cap_class.value and r.action == "allow"]
        denies = [r for r in rules if r.rule_type == "capability_class" and r.target_value == cap_class.value and r.action == "deny"]
        if denies:
            return False, f"Capability class {cap_class.value} denied by policy: {denies[0].evidence}"
        # If any allow rules exist, require at least one match
        if any(r.rule_type == "capability_class" and r.action == "allow" for r in rules) and not allows:
            return False, f"Capability class {cap_class.value} not in allowed set"
        return True, "OK"

    def evaluate_trust_zone(
        self, tenant_id: str, zone: TrustZone
    ) -> Tuple[bool, str]:
        rules = self._rules.get(tenant_id, [])
        denies = [r for r in rules if r.rule_type == "trust_zone" and r.target_value == zone.value and r.action == "deny"]
        if denies:
            return False, f"Trust zone {zone.value} denied by policy: {denies[0].evidence}"
        return True, "OK"

    def get_rules(self, tenant_id: str) -> Tuple[TenantPolicyRule, ...]:
        return tuple(self._rules.get(tenant_id, []))


# ── Tenant Execution Log ─────────────────────────────────────────

@dataclass(frozen=True)
class TenantExecutionRecord:
    tenant_id: str
    execution_id: str
    pipeline_hash: str
    manifest_id: str
    status: str  # "started", "completed", "failed", "rejected"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    evidence: str = ""
    replay_artifact_hash: str = ""

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "tenant_id": self.tenant_id,
                "execution_id": self.execution_id,
                "pipeline_hash": self.pipeline_hash,
                "manifest_id": self.manifest_id,
                "status": self.status,
                "started_at": self.started_at,
                "evidence": self.evidence,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class TenantExecutionLog:
    """Append-only execution log per tenant.

    Records every execution attempt, success or failure.
    Supports replay by pipeline_hash.
    """

    def __init__(self, root_dir: Optional[Path] = None) -> None:
        self.root_dir = root_dir or Path("./tenant_executions")
        self.root_dir.mkdir(parents=True, exist_ok=True)
        self._records: Dict[str, List[TenantExecutionRecord]] = {}

    def record(self, rec: TenantExecutionRecord) -> None:
        self._records.setdefault(rec.tenant_id, []).append(rec)

    def get_by_tenant(self, tenant_id: str, limit: int = 100) -> Tuple[TenantExecutionRecord, ...]:
        records = self._records.get(tenant_id, [])
        return tuple(records[-limit:])

    def get_by_execution_id(self, tenant_id: str, execution_id: str) -> Optional[TenantExecutionRecord]:
        for rec in self._records.get(tenant_id, []):
            if rec.execution_id == execution_id:
                return rec
        return None

    def get_replay_candidates(self, tenant_id: str, pipeline_hash: str) -> Tuple[TenantExecutionRecord, ...]:
        """Get all executions matching a pipeline hash for replay."""
        records = self._records.get(tenant_id, [])
        return tuple(r for r in records if r.pipeline_hash == pipeline_hash)

    def get_compliance_report(self, tenant_id: str) -> Dict[str, Any]:
        records = self._records.get(tenant_id, [])
        total = len(records)
        completed = sum(1 for r in records if r.status == "completed")
        failed = sum(1 for r in records if r.status == "failed")
        rejected = sum(1 for r in records if r.status == "rejected")
        return {
            "tenant_id": tenant_id,
            "total_executions": total,
            "completed": completed,
            "failed": failed,
            "rejected": rejected,
            "success_rate": completed / total if total else 0,
            "report_generated_at": datetime.now(timezone.utc).isoformat(),
            "record_hashes": [r.compute_hash() for r in records[-10:]],  # last 10 for integrity
        }
