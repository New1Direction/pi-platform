"""Node 4: Dependency Mapper.

Trace state lineages across SemanticIRTraces to discover auth flows
and call-order dependencies.
"""

from __future__ import annotations

import uuid
from typing import Dict, List, Set

from pi_agent_chain.models import (
    DependencyGraph,
    SemanticIRTrace,
    StateEdge,
)


class FlowMapperNode:
    """Build a directed graph of data dependencies across endpoints."""

    TOKEN_TYPES: Dict[str, List[str]] = {
        "BearerToken": ["JWT", "UUIDv4", "HexDigest", "UNKNOWN_HEX"],
        "CSRFToken": ["UUIDv4", "UUIDv1", "HexDigest"],
        "SessionID": ["UUIDv4", "UUIDv1", "HexDigest", "UNKNOWN_HEX"],
        "QueryParam": ["UUIDv4", "UUIDv1", "STRING"],
    }

    def __init__(self, session_window_id: str | None = None) -> None:
        self.session_window_id = session_window_id or str(uuid.uuid4())

    def map_flow(self, traces: List[SemanticIRTrace]) -> DependencyGraph:
        """Build dependency graph from SemanticIRTraces."""
        edges: List[StateEdge] = []
        endpoints: Set[str] = set()

        # Index response fields by semantic format
        response_index: Dict[str, List[tuple[str, str, str, float]]] = {}
        for trace in traces:
            ep = f"{trace.method} {trace.endpoint_template}"
            endpoints.add(ep)
            for field in trace.fields:
                if field.path.startswith("response."):
                    key = field.inferred_type
                    response_index.setdefault(key, []).append(
                        (ep, field.path, field.example_value or "", field.entropy_score)
                    )

        # Scan request fields for consumers
        for trace in traces:
            consumer_ep = f"{trace.method} {trace.endpoint_template}"
            for field in trace.fields:
                if (
                    not field.path.startswith("request.")
                    and not field.path.startswith("header.")
                    and not field.path.startswith("query.")
                ):
                    continue
                fmt = field.inferred_type
                for _token_type, allowed_formats in self.TOKEN_TYPES.items():
                    if fmt in allowed_formats or field.entropy_score > 0.85:
                        producers = response_index.get(fmt, [])
                        for prod_ep, prod_path, example, _entropy in producers:
                            if prod_ep == consumer_ep:
                                continue
                            if example and field.example_value and example[:8] == field.example_value[:8]:
                                edges.append(
                                    StateEdge(
                                        upstream_endpoint=prod_ep,
                                        upstream_field=prod_path,
                                        downstream_endpoint=consumer_ep,
                                        downstream_field=field.path,
                                        carrier_mechanism=self._infer_location(field.path),
                                    )
                                )

        return DependencyGraph(
            edges=edges,
            nodes=sorted(endpoints),
            session_window_id=self.session_window_id,
        )

    @staticmethod
    def _infer_location(key_path: str) -> str:
        lower = key_path.lower()
        if "header" in lower or lower.startswith("header."):
            return "HEADER"
        if "cookie" in lower:
            return "COOKIE"
        if "query" in lower or lower.startswith("query."):
            return "QUERY"
        return "BODY"
