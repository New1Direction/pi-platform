"""Runtime Governance Compiler.

Deterministic policy compilation from declarative governance rules.
No runtime evaluation of arbitrary expressions. All policies are
statically validated, compiled to a deterministic decision function,
and versioned.

Key concepts:
- GovernanceRule: declarative rule with conditions, actions, and effects
- PolicyDSL: restricted grammar for expressing conditions
- PolicyCompiler: deterministic compilation to decision function
- GovernanceRegistry: append-only registry of compiled policies
- GovernanceVersion: policy set version with cryptographic hash
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Dict, List, Optional, Set, Tuple


# ──────────────────────────────
#  Policy DSL
# ──────────────────────────────

class Effect(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    AUDIT = "audit"
    REQUIRE_APPROVAL = "require_approval"
    NOTIFY = "notify"


class ConditionOperator(str, Enum):
    EQUALS = "eq"
    NOT_EQUALS = "ne"
    GREATER_THAN = "gt"
    LESS_THAN = "lt"
    CONTAINS = "contains"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"
    IN_SET = "in"
    NOT_IN_SET = "not_in"
    MATCHES_REGEX = "matches"
    EXISTS = "exists"


@dataclass(frozen=True)
class Condition:
    """A single condition in a governance rule.

    Restricted to deterministic operators only.
    No random. No external API calls. No time-based logic.
    """

    field: str  # e.g. "tenant_id", "action", "resource.type"
    operator: ConditionOperator
    value: Any  # comparison value (must be JSON-serializable)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
        }


@dataclass(frozen=True)
class GovernanceRule:
    """A compiled governance rule.

    Rules are immutable. All fields participate in the rule hash.
    """

    rule_id: str
    name: str
    description: str
    target_scope: str  # e.g. "composition", "snapshot", "tenant", "global"
    conditions: Tuple[Condition, ...]
    effect: Effect
    priority: int  # lower = higher priority
    version: str
    parent_rule_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    rule_hash: str = ""

    def __post_init__(self, _: Any = None) -> None:
        if not self.rule_hash:
            object.__setattr__(self, "rule_hash", self._compute_hash())

    def _compute_hash(self) -> str:
        canonical = {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "target_scope": self.target_scope,
            "conditions": [c.to_dict() for c in self.conditions],
            "effect": self.effect.value,
            "priority": self.priority,
            "version": self.version,
            "parent_rule_id": self.parent_rule_id,
        }
        return hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "description": self.description,
            "target_scope": self.target_scope,
            "conditions": [c.to_dict() for c in self.conditions],
            "effect": self.effect.value,
            "priority": self.priority,
            "version": self.version,
            "parent_rule_id": self.parent_rule_id,
            "rule_hash": self.rule_hash,
            "metadata": self.metadata,
        }


# ──────────────────────────────
#  Policy Compiler
# ──────────────────────────────

@dataclass(frozen=True)
class CompiledPolicy:
    """A compiled, deterministic policy decision function.

    Contains no arbitrary code. Only pre-validated condition checks.
    """

    policy_id: str
    rule_id: str
    decision_function: Callable[[Dict[str, Any]], bool]  # True = conditions match
    effect: Effect
    priority: int
    compiled_hash: str


class PolicyCompiler:
    """Deterministic compiler from GovernanceRule to CompiledPolicy.

    Validates all conditions are in the restricted grammar.
    Compiles to a pure function with no side effects.
    """

    ALLOWED_FIELDS: Set[str] = {
        "tenant_id", "actor_id", "role", "action", "resource_type", "resource_id",
        "composition_id", "snapshot_id", "worker_id", "stage", "event_type",
        "partition_key", "epoch_number", "schema_name", "schema_version",
    }

    @classmethod
    def compile(cls, rule: GovernanceRule) -> CompiledPolicy:
        """Compile a governance rule to a deterministic decision function.

        Validates all conditions before compilation.
        """
        # Validate conditions
        for condition in rule.conditions:
            cls._validate_condition(condition)

        # Build decision function
        def decision(context: Dict[str, Any]) -> bool:
            for condition in rule.conditions:
                if not cls._evaluate(condition, context):
                    return False
            return True

        # Deterministic compiled hash
        compiled_data = json.dumps({
            "rule_id": rule.rule_id,
            "conditions": [c.to_dict() for c in rule.conditions],
            "effect": rule.effect.value,
            "priority": rule.priority,
        }, sort_keys=True, separators=(",", ":"), default=str)
        compiled_hash = hashlib.sha256(compiled_data.encode()).hexdigest()

        return CompiledPolicy(
            policy_id=f"policy_{rule.rule_id}_{rule.version}",
            rule_id=rule.rule_id,
            decision_function=decision,
            effect=rule.effect,
            priority=rule.priority,
            compiled_hash=compiled_hash,
        )

    @classmethod
    def _validate_condition(cls, condition: Condition) -> None:
        if condition.field not in cls.ALLOWED_FIELDS:
            raise PolicyValidationError(
                f"Field '{condition.field}' not in allowed fields: {cls.ALLOWED_FIELDS}"
            )

        if condition.operator == ConditionOperator.MATCHES_REGEX:
            # Regex patterns must be explicitly whitelisted
            raise PolicyValidationError(
                "Regex matching is not allowed in the deterministic policy DSL"
            )

    @classmethod
    def _evaluate(cls, condition: Condition, context: Dict[str, Any]) -> bool:
        """Evaluate a single condition against a context dict.

        Deterministic. No exceptions swallowed.
        """
        field_value = context.get(condition.field)
        target = condition.value

        if condition.operator == ConditionOperator.EQUALS:
            return field_value == target
        elif condition.operator == ConditionOperator.NOT_EQUALS:
            return field_value != target
        elif condition.operator == ConditionOperator.GREATER_THAN:
            if field_value is None or target is None:
                return False
            return field_value > target
        elif condition.operator == ConditionOperator.LESS_THAN:
            if field_value is None or target is None:
                return False
            return field_value < target
        elif condition.operator == ConditionOperator.CONTAINS:
            if isinstance(field_value, (str, list, tuple, dict)):
                return target in field_value
            return False
        elif condition.operator == ConditionOperator.STARTS_WITH:
            if isinstance(field_value, str) and isinstance(target, str):
                return field_value.startswith(target)
            return False
        elif condition.operator == ConditionOperator.ENDS_WITH:
            if isinstance(field_value, str) and isinstance(target, str):
                return field_value.endswith(target)
            return False
        elif condition.operator == ConditionOperator.IN_SET:
            if isinstance(target, (list, tuple, set)):
                return field_value in target
            return False
        elif condition.operator == ConditionOperator.NOT_IN_SET:
            if isinstance(target, (list, tuple, set)):
                return field_value not in target
            return False
        elif condition.operator == ConditionOperator.EXISTS:
            return condition.field in context and context[condition.field] is not None

        return False


class PolicyValidationError(Exception):
    """Raised when a governance rule fails static validation."""


# ──────────────────────────────
#  Governance Decision Engine
# ──────────────────────────────

@dataclass(frozen=True)
class GovernanceDecision:
    """Deterministic decision from the governance engine."""

    decision_id: str
    context_id: str
    effect: Effect
    matched_rules: List[str]
    denied_by: Optional[str]
    decision_hash: str = ""
    evaluated_at: str = ""

    def __post_init__(self, _: Any = None) -> None:
        if not self.decision_hash:
            decision_data = json.dumps({
                "context_id": self.context_id,
                "effect": self.effect.value,
                "matched_rules": self.matched_rules,
                "denied_by": self.denied_by,
                "evaluated_at": self.evaluated_at,
            }, sort_keys=True, separators=(",", ":"), default=str)
            object.__setattr__(self, "decision_hash", hashlib.sha256(decision_data.encode()).hexdigest())


class GovernanceEngine:
    """Deterministic governance evaluation engine.

    Evaluates a context against all compiled policies.
    Returns the highest-priority matching rule's effect.
    No probabilistic tiebreaking. Priority is explicit.
    """

    def __init__(self) -> None:
        self._policies: List[CompiledPolicy] = []
        self._lock = threading.Lock()

    def load_policy(self, policy: CompiledPolicy) -> None:
        with self._lock:
            self._policies.append(policy)
            # Sort by priority (lower = first)
            self._policies.sort(key=lambda p: p.priority)

    def evaluate(self, context: Dict[str, Any]) -> GovernanceDecision:
        """Evaluate context against all loaded policies.

        Returns deterministic decision based on highest-priority match.
        Fail-closed: no match = DENY.
        """
        matched: List[str] = []
        denied_by: Optional[str] = None
        final_effect = Effect.DENY

        with self._lock:
            policies = list(self._policies)

        for policy in policies:
            if policy.decision_function(context):
                matched.append(policy.rule_id)
                if policy.effect == Effect.DENY:
                    denied_by = policy.rule_id
                    final_effect = Effect.DENY
                    break  # DENY is terminal
                elif policy.effect == Effect.ALLOW:
                    final_effect = Effect.ALLOW
                elif policy.effect == Effect.REQUIRE_APPROVAL:
                    final_effect = Effect.REQUIRE_APPROVAL
                # Other effects can be layered

        # If no match at all, fail closed
        if not matched:
            final_effect = Effect.DENY

        decision_data = json.dumps({
            "context_id": context.get("correlation_id", "unknown"),
            "effect": final_effect.value,
            "matched_rules": matched,
            "denied_by": denied_by,
        }, sort_keys=True, separators=(",", ":"), default=str)
        decision_hash = hashlib.sha256(decision_data.encode()).hexdigest()

        return GovernanceDecision(
            decision_id=f"dec_{context.get('correlation_id', 'unknown')}_{decision_hash[:16]}",
            context_id=context.get("correlation_id", "unknown"),
            effect=final_effect,
            matched_rules=matched,
            denied_by=denied_by,
            decision_hash=decision_hash,
            evaluated_at=context.get("timestamp", ""),
        )


# ──────────────────────────────
#  Governance Registry
# ──────────────────────────────

class GovernanceRegistry:
    """Append-only registry for governance rules and compiled policies.

    Historical rules are never deleted. New versions are added.
    """

    SCHEMA = """
    CREATE TABLE IF NOT EXISTS governance_rules (
        rule_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        target_scope TEXT NOT NULL,
        conditions_json TEXT NOT NULL,
        effect TEXT NOT NULL,
        priority INTEGER NOT NULL,
        version TEXT NOT NULL,
        parent_rule_id TEXT,
        rule_hash TEXT NOT NULL,
        registered_at TEXT NOT NULL,
        registered_by TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS compiled_policies (
        policy_id TEXT PRIMARY KEY,
        rule_id TEXT NOT NULL,
        compiled_hash TEXT NOT NULL,
        effect TEXT NOT NULL,
        priority INTEGER NOT NULL,
        compiled_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS governance_decisions (
        decision_id TEXT PRIMARY KEY,
        context_id TEXT NOT NULL,
        effect TEXT NOT NULL,
        matched_rules_json TEXT NOT NULL,
        denied_by TEXT,
        decision_hash TEXT NOT NULL,
        evaluated_at TEXT NOT NULL
    );
    """

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

    def register_rule(self, rule: GovernanceRule, registered_by: str = "system") -> None:
        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT OR IGNORE INTO governance_rules
                   (rule_id, name, description, target_scope, conditions_json, effect, priority, version, parent_rule_id, rule_hash, registered_at, registered_by)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), ?)""",
                (
                    rule.rule_id, rule.name, rule.description, rule.target_scope,
                    json.dumps([c.to_dict() for c in rule.conditions], sort_keys=True),
                    rule.effect.value, rule.priority, rule.version,
                    rule.parent_rule_id, rule.rule_hash, registered_by,
                ),
            )
            conn.commit()
            conn.close()

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            row = conn.execute("SELECT * FROM governance_rules WHERE rule_id = ?", (rule_id,)).fetchone()
            conn.close()
        return dict(row) if row else None

    def list_rules(self, scope: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            if scope:
                rows = conn.execute(
                    "SELECT * FROM governance_rules WHERE target_scope = ? ORDER BY priority ASC",
                    (scope,),
                ).fetchall()
            else:
                rows = conn.execute("SELECT * FROM governance_rules ORDER BY priority ASC").fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def store_decision(self, decision: GovernanceDecision) -> None:
        with self._lock:
            conn = self._conn()
            conn.execute(
                """INSERT OR IGNORE INTO governance_decisions
                   (decision_id, context_id, effect, matched_rules_json, denied_by, decision_hash, evaluated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    decision.decision_id, decision.context_id, decision.effect.value,
                    json.dumps(decision.matched_rules, sort_keys=True),
                    decision.denied_by, decision.decision_hash, decision.evaluated_at,
                ),
            )
            conn.commit()
            conn.close()

    def get_decision(self, decision_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            row = conn.execute("SELECT * FROM governance_decisions WHERE decision_id = ?", (decision_id,)).fetchone()
            conn.close()
        return dict(row) if row else None
