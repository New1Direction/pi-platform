from __future__ import annotations

import re
from typing import Any, Dict, List, Set, Tuple

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Strict-mode resolution (delegates to the central resolver)
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_GHOST_STRICT_MODE")


# 2. Heuristic Detection Core for Code/Text Payloads
def detect_shadow_parameters(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Heuristics scanning for shadow keywords and assignments
    keywords = ["admin", "debug", "override", "internal", "bypass", "secret", "test", "shadow", "hidden", "private"]
    for kw in keywords:
        # Check for assignment patterns like admin=, admin_mode, ?debug=true, etc.
        assign_pat = re.compile(rf"\b{kw}(?:_mode|_flag)?\s*=", re.IGNORECASE)
        query_pat = re.compile(rf"[?&]{kw}\b", re.IGNORECASE)

        if assign_pat.search(text) or query_pat.search(text):
            violations.append(f"shadow parameter indicator '{kw}' detected")
            max_risk = max(max_risk, 90.0 if kw in ["bypass", "admin", "override"] else 75.0)

    return max_risk, violations


# 3. Schema Scanner and Intent Graph Builder
class PiSchemaGhost:
    """Micro-agent scanning OpenAPI/tool schemas for shadow parameters and mapping intent graphs."""

    def __init__(self) -> None:
        self.keywords = [
            "admin",
            "debug",
            "override",
            "internal",
            "bypass",
            "secret",
            "test",
            "shadow",
            "hidden",
            "private",
        ]

    def scan(self, spec: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
        """Scans OpenAPI dict, injects x-intent-graph, and returns validation errors if strict."""
        errors: List[str] = []
        endpoints_with_params: Dict[str, Set[str]] = {}

        paths = spec.get("paths", {})
        for path_key, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, operation in path_item.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch", "options", "head"]:
                    continue
                endpoint = f"{method.upper()} {path_key}"
                detected_shadows: Set[str] = set()

                # A. Scan direct parameters (query, header, path, cookie)
                params = operation.get("parameters", [])
                if isinstance(params, list):
                    for p in params:
                        if not isinstance(p, dict):
                            continue
                        name = p.get("name", "")
                        if self._is_shadow_name(name):
                            detected_shadows.add(name)

                # B. Scan requestBody schema
                req_body = operation.get("requestBody", {})
                if isinstance(req_body, dict):
                    content = req_body.get("content", {})
                    for media_type in content.values():
                        if isinstance(media_type, dict) and "schema" in media_type:
                            self._extract_shadows_from_schema(media_type["schema"], detected_shadows)

                # C. Scan responses schemas
                responses = operation.get("responses", {})
                if isinstance(responses, dict):
                    for resp in responses.values():
                        if not isinstance(resp, dict):
                            continue
                        content = resp.get("content", {})
                        for media_type in content.values():
                            if isinstance(media_type, dict) and "schema" in media_type:
                                self._extract_shadows_from_schema(media_type["schema"], detected_shadows)

                if detected_shadows:
                    endpoints_with_params[endpoint] = detected_shadows

        # D. Construct Intent Graph
        nodes = [{"id": ep, "shadow_parameters": sorted(params)} for ep, params in endpoints_with_params.items()]
        edges = []
        eps_list = list(endpoints_with_params.keys())

        # Connect endpoints sharing the same shadow parameters
        for i in range(len(eps_list)):
            for j in range(i + 1, len(eps_list)):
                ep_a = eps_list[i]
                ep_b = eps_list[j]
                shared = endpoints_with_params[ep_a] & endpoints_with_params[ep_b]
                if shared:
                    edges.append(
                        {
                            "source": ep_a,
                            "target": ep_b,
                            "shared_parameters": sorted(shared),
                            "relationship_type": "shared_shadow_control_plane",
                        }
                    )

        intent_graph = {
            "nodes": nodes,
            "edges": edges,
            "scanned_at": __import__("datetime").datetime.utcnow().isoformat(),
        }

        # E. Embed Intent Graph directly into OpenAPI components or root
        spec["x-intent-graph"] = intent_graph

        # F. Enforce Strict-Mode Policy
        if is_strict_mode():
            critical_keywords = ["bypass", "admin", "override", "secret"]
            for ep, shadows in endpoints_with_params.items():
                violating = [s for s in shadows if any(ck in s.lower() for ck in critical_keywords)]
                if violating:
                    errors.append(
                        f"POLICY_VIOLATION: Endpoint '{ep}' exposes critical shadow parameters: {sorted(violating)} (SchemaGhost v2)"
                    )

        return spec, errors

    def _is_shadow_name(self, name: str) -> bool:
        name_lower = name.lower()
        return any(kw in name_lower for kw in self.keywords)

    def _extract_shadows_from_schema(self, schema: Dict[str, Any], detected: Set[str]) -> None:
        if not isinstance(schema, dict):
            return
        # Direct properties
        props = schema.get("properties", {})
        if isinstance(props, dict):
            for k in props.keys():
                if self._is_shadow_name(k):
                    detected.add(k)
        # Nested array items
        items = schema.get("items")
        if isinstance(items, dict) and items:
            self._extract_shadows_from_schema(items, detected)
        # Nested object properties or combinations (anyOf, allOf, oneOf)
        for comb in ["anyOf", "allOf", "oneOf"]:
            subschemas = schema.get(comb, [])
            if isinstance(subschemas, list):
                for s in subschemas:
                    self._extract_shadows_from_schema(s, detected)
