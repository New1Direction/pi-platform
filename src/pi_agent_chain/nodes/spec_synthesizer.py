"""Node 5: Spec Synthesizer.

Compile frozen SemanticIRTraces and DependencyGraph into a valid OpenAPI 3.1 spec.
CFG-enforced: no unconstrained text generation outside valid spec grammar.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List

from pi_agent_chain.models import DependencyGraph, SemanticField, SemanticIRTrace, SynthesizedSpec


class SpecSynthesizerNode:
    """Synthesize OpenAPI 3.1 from semantic traces and dependency graph."""

    def synthesize(
        self,
        traces: List[SemanticIRTrace],
        graph: DependencyGraph,
    ) -> SynthesizedSpec:
        paths: Dict[str, Any] = {}
        schemas: Dict[str, Any] = {}

        for trace in traces:
            path_key = trace.endpoint_template
            method = trace.method.lower()

            if path_key not in paths:
                paths[path_key] = {}

            req_fields = [f for f in trace.fields if f.path.startswith(("request.", "header.", "query.", "body."))]
            resp_fields = [f for f in trace.fields if f.path.startswith("response.")]

            request_schema = self._fields_to_schema(req_fields, schemas)
            response_schema = self._fields_to_schema(resp_fields, schemas)

            operation: Dict[str, Any] = {
                "operationId": f"{method}_{path_key.replace('/', '_').strip('_')}",
                "responses": {
                    "200": {
                        "description": "Synthesized response",
                        "content": {
                            "application/json": {
                                "schema": response_schema,
                            }
                        },
                    }
                },
            }

            if req_fields:
                operation["requestBody"] = {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": request_schema,
                        }
                    },
                }

            sec = self._security_for_endpoint(trace, graph)
            if sec:
                operation["security"] = sec

            paths[path_key][method] = operation

        spec: Dict[str, Any] = {
            "openapi": "3.1.0",
            "info": {
                "title": "Synthesized API",
                "version": "0.1.0-synthesized",
            },
            "paths": paths,
            "components": {
                "schemas": schemas,
            },
        }
        # One-line SchemaGhost activation
        from pi_micro_agents.pi_schema_ghost import PiSchemaGhost

        spec, ghost_errors = PiSchemaGhost().scan(spec)

        errors = self._validate_spec(spec) + ghost_errors
        raw_json = json.dumps(spec, indent=2, sort_keys=True)

        return SynthesizedSpec(
            spec_json=raw_json,
            validation_errors=errors,
            is_valid=len(errors) == 0,
        )

    def _fields_to_schema(self, fields: List[SemanticField], schema_registry: Dict[str, Any]) -> Dict[str, Any]:
        properties: Dict[str, Any] = {}
        required: List[str] = []

        for field in fields:
            prop_name = field.path.replace(".", "_").replace("[", "_").replace("]", "")
            if prop_name in properties:
                continue

            openapi_type = self._map_inferred_type(field.inferred_type)
            prop: Dict[str, Any] = {"type": openapi_type}

            if field.inferred_type in ("UUIDv4", "UUIDv1"):
                prop["format"] = "uuid"
            elif field.inferred_type in ("ISO8601", "UnixTimestamp", "UnixTimestampMS"):
                prop["format"] = "date-time"
            elif field.inferred_type == "Email":
                prop["format"] = "email"
            elif field.inferred_type in ("IPv4", "IPv6"):
                prop["format"] = field.inferred_type.lower()
            elif field.inferred_type == "JWT":
                prop["pattern"] = r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$"

            if field.inferred_type.startswith("UNKNOWN"):
                prop["description"] = f"Unknown format; entropy={field.entropy_score:.2f} conf={field.confidence:.2f}"

            properties[prop_name] = prop
            required.append(prop_name)

        return {
            "type": "object",
            "properties": properties,
            "required": required,
        }

    @staticmethod
    def _map_inferred_type(inferred: str) -> str:
        mapping = {
            "INTEGER": "integer",
            "UnixTimestamp": "integer",
            "UnixTimestampMS": "integer",
            "NUMBER": "number",
            "BOOLEAN": "boolean",
            "STRING": "string",
            "UUIDv4": "string",
            "UUIDv1": "string",
            "JWT": "string",
            "Email": "string",
            "URL": "string",
            "IPv4": "string",
            "IPv6": "string",
            "Base64": "string",
            "HexDigest": "string",
            "ISO8601": "string",
            "UNKNOWN_HEX": "string",
            "UNKNOWN_STR": "string",
        }
        return mapping.get(inferred, "string")

    def _security_for_endpoint(self, trace: SemanticIRTrace, graph: DependencyGraph) -> List[Dict[str, List[str]]]:
        ep = f"{trace.method} {trace.endpoint_template}"
        sec: List[Dict[str, List[str]]] = []
        for edge in graph.edges:
            if edge.downstream_endpoint == ep:
                if edge.carrier_mechanism == "HEADER":
                    sec.append({"bearerAuth": []})
                elif edge.carrier_mechanism in ("COOKIE", "BODY"):
                    sec.append({"cookieAuth": []})
        seen: List[Dict[str, List[str]]] = []
        for item in sec:
            if item not in seen:
                seen.append(item)
        return seen

    def _validate_spec(self, spec: Dict[str, Any]) -> List[str]:
        errors: List[str] = []
        if spec.get("openapi") != "3.1.0":
            errors.append("Missing or incorrect openapi version")
        if "paths" not in spec or not spec["paths"]:
            errors.append("No paths defined")
        for path, methods in spec.get("paths", {}).items():
            for method, op in methods.items():
                if "operationId" not in op:
                    errors.append(f"Missing operationId for {method.upper()} {path}")
        return errors
