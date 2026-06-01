from __future__ import annotations

import hashlib
import json
import sqlite3
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from pi_event_fabric.bus.core import (
    DomainEvent,
    EventBusStorage,
    EventType,
    PartitionKey,
    _canonical,
)
from pi_interoperability_layer.snapshot.clock import DeterministicClock


class SemanticMetadata(BaseModel):
    semantic_intent: str = Field(..., description="The semantic intent of the agent interaction")
    execution_lineage: List[str] = Field(
        default_factory=list, description="Ordered trace of agents involved in execution"
    )
    trust_level: float = Field(default=1.0, description="Trust-level ranking from 0.0 to 1.0")
    causality_chain: List[str] = Field(
        default_factory=list, description="Hashes of parent events triggering this event"
    )
    reproducibility_hash: str = Field(default="", description="Cryptographic hash proving determinism of inputs")
    schema_version: str = Field(default="1.0.0", description="Semantic schema version number")
    policy_classification: str = Field(default="standard", description="Zero-trust policy classification category")


class CausalChainBreakError(ValueError):
    """Raised when one or more parent event hashes in the causality chain cannot be verified."""

    pass


class TrustEnforcementError(ValueError):
    """Raised when trust level does not meet security threshold requirements."""

    pass


class PiSemanticEventFabric:
    """Wraps raw EventBusStorage to enforce typed semantic events and causality DAG verification."""

    def __init__(self, storage: EventBusStorage, min_trust_threshold: float = 0.0) -> None:
        self.storage = storage
        self.min_trust_threshold = min_trust_threshold

    def append_semantic(
        self,
        event_type: EventType,
        partition_key: str,
        payload: Dict[str, Any],
        semantic_intent: str,
        execution_lineage: List[str],
        trust_level: float,
        causality_chain: List[str],
        schema_version: str,
        policy_classification: str,
        tenant_id: str,
        actor_id: str,
        correlation_id: str,
        clock: Optional[DeterministicClock] = None,
        bypass_causal_check: bool = False,
    ) -> DomainEvent:
        """Appends a semantic event to the event bus after verifying trust boundaries and causality chain."""
        # 1. Enforce trust boundaries
        if trust_level < self.min_trust_threshold:
            raise TrustEnforcementError(
                f"Event trust level {trust_level} is below min required threshold {self.min_trust_threshold}"
            )

        # 2. Verify causality chain existence in database
        if not bypass_causal_check:
            for parent_hash in causality_chain:
                if not self.check_event_hash_exists(parent_hash):
                    raise CausalChainBreakError(
                        f"Causality chain broken: parent event hash {parent_hash} not found in database"
                    )

        # 3. Compute reproducibility hash
        # Standard input signature: payload + execution_lineage + intent
        repro_input = {
            "payload": payload,
            "execution_lineage": execution_lineage,
            "semantic_intent": semantic_intent,
            "schema_version": schema_version,
        }
        repro_json = json.dumps(_canonical(repro_input), sort_keys=True, default=str)
        reproducibility_hash = hashlib.sha256(repro_json.encode()).hexdigest()

        # 4. Construct semantic metadata structure
        metadata = SemanticMetadata(
            semantic_intent=semantic_intent,
            execution_lineage=execution_lineage,
            trust_level=trust_level,
            causality_chain=causality_chain,
            reproducibility_hash=reproducibility_hash,
            schema_version=schema_version,
            policy_classification=policy_classification,
        )

        # 5. Embed metadata into payload under reserved namespace
        semantic_payload = {**payload, "_semantic": metadata.dict()}

        # 6. Append using standard EventBusStorage
        event = self.storage.append(
            event_type=event_type,
            partition_key=partition_key,
            payload=semantic_payload,
            tenant_id=tenant_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            clock=clock,
        )
        return event

    def check_event_hash_exists(self, event_hash: str) -> bool:
        """Checks if a given event hash is already written in the database."""
        conn = sqlite3.connect(self.storage.db_path)
        try:
            row = conn.execute("SELECT 1 FROM events WHERE event_hash = ?", (event_hash,)).fetchone()
            return row is not None
        finally:
            conn.close()

    def get_causality_dag(self, start_event_hash: str) -> Dict[str, Any]:
        """Traverses the causality DAG backwards to build nodes and dependency edges."""
        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, str]] = []
        to_visit = [start_event_hash]
        visited = set()

        conn = sqlite3.connect(self.storage.db_path)
        conn.row_factory = sqlite3.Row

        try:
            while to_visit:
                curr_hash = to_visit.pop(0)
                if curr_hash in visited:
                    continue
                visited.add(curr_hash)

                row = conn.execute("SELECT * FROM events WHERE event_hash = ?", (curr_hash,)).fetchone()
                if row is None:
                    continue

                payload = json.loads(row["payload_json"])
                semantic = payload.get("_semantic", {})

                nodes[curr_hash] = {
                    "event_id": row["event_id"],
                    "event_type": row["event_type"],
                    "event_hash": curr_hash,
                    "semantic_intent": semantic.get("semantic_intent", "unknown"),
                    "trust_level": semantic.get("trust_level", 1.0),
                    "schema_version": semantic.get("schema_version", "1.0.0"),
                    "policy_classification": semantic.get("policy_classification", "standard"),
                }

                parents = semantic.get("causality_chain", [])
                for parent_hash in parents:
                    edges.append({"from": parent_hash, "to": curr_hash})
                    if parent_hash not in visited:
                        to_visit.append(parent_hash)
        finally:
            conn.close()

        return {"nodes": list(nodes.values()), "edges": edges}

    def write_agent_snapshot(
        self,
        agent_id: str,
        state: Dict[str, Any],
        correlation_id: str,
        tenant_id: str = "default",
        actor_id: str = "system",
        clock: Optional[DeterministicClock] = None,
    ) -> DomainEvent:
        """Writes a cryptographically signed state snapshot for an agent."""
        state_json = json.dumps(_canonical(state), sort_keys=True, default=str)
        state_signature = hashlib.sha256(state_json.encode()).hexdigest()

        payload = {
            "agent_id": agent_id,
            "agent_state": state,
            "state_signature": state_signature,
        }

        # Snapshots always have full trust and bypass causal checks
        return self.append_semantic(
            event_type=EventType.SNAPSHOT_STORED,
            partition_key=PartitionKey.SNAPSHOTS,
            payload=payload,
            semantic_intent=f"checkpoint_agent_state:{agent_id}",
            execution_lineage=[agent_id],
            trust_level=1.0,
            causality_chain=[],
            schema_version="1.0.0",
            policy_classification="governed",
            tenant_id=tenant_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            clock=clock,
            bypass_causal_check=True,
        )
