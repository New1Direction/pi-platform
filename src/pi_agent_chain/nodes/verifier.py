"""Node 6: Differential Verification Engine.

Execute stateful mutations and property-based test generation against
the live API using the synthesized specification.
Seed locked at 1337 (or governance config value).
"""

from __future__ import annotations

import random
from typing import Any, Dict, List, Optional

import httpx

from pi_agent_chain.models import (
    BehavioralDelta,
    NormalizedTrafficPacket,
    SynthesizedSpec,
    VerificationReport,
)


class DifferentialVerifierNode:
    """Verify synthesized spec against live API traffic."""

    def __init__(
        self,
        base_url: str,
        seed: int = 1337,
        max_endpoints: int = 100,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.seed = seed
        self.max_endpoints = max_endpoints
        self.timeout = timeout
        self.rng = random.Random(seed)

    async def verify(
        self,
        spec: SynthesizedSpec,
        known_packets: List[NormalizedTrafficPacket],
    ) -> VerificationReport:
        openapi = spec.openapi_dict()
        paths = openapi.get("paths", {})
        deltas: List[BehavioralDelta] = []
        tested = 0
        total = len(paths)

        items = list(paths.items())[: self.max_endpoints]

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            for path_template, methods in items:
                for method, operation in methods.items():
                    if method.upper() not in (
                        "GET",
                        "POST",
                        "PUT",
                        "DELETE",
                        "PATCH",
                    ):
                        continue

                    known = self._find_known_packet(
                        known_packets, path_template, method.upper()
                    )

                    delta = await self._test_endpoint(
                        client, path_template, method.upper(), operation, known
                    )
                    if delta:
                        deltas.append(delta)
                    tested += 1

        coverage = (tested / total * 100) if total > 0 else 0.0
        passed = len(deltas) == 0
        return VerificationReport(
            passed=passed,
            behavioral_deltas=deltas,
            spec_coverage_percentage=coverage,
            tested_endpoints=tested,
            total_endpoints=total,
        )

    async def _test_endpoint(
        self,
        client: httpx.AsyncClient,
        path_template: str,
        method: str,
        operation: Dict[str, Any],
        known: Optional[NormalizedTrafficPacket],
    ) -> Optional[BehavioralDelta]:
        url = f"{self.base_url}{path_template}"
        payload = self._build_synthetic_payload(operation, known)
        headers = self._build_synthetic_headers(operation, known)

        try:
            response = await client.request(
                method, url, json=payload, headers=headers
            )
        except httpx.RequestError:
            return BehavioralDelta(
                path=path_template,
                action=method,
                observed_status=0,
                expected_status=200,
                contradiction_detected=True,
            )

        expected_status = known.response_status if known else 200
        actual_status = response.status_code

        if abs(actual_status - expected_status) > 50:
            return BehavioralDelta(
                path=path_template,
                action=method,
                observed_status=actual_status,
                expected_status=expected_status,
                contradiction_detected=True,
            )

        return None

    def _build_synthetic_payload(
        self,
        operation: Dict[str, Any],
        known: Optional[NormalizedTrafficPacket],
    ) -> Optional[Dict[str, Any]]:
        if known and known.raw_payload:
            try:
                import json as _json
                return _json.loads(known.raw_payload)
            except Exception:
                pass

        schema = (
            operation.get("requestBody", {})
            .get("content", {})
            .get("application/json", {})
            .get("schema", {})
        )
        return self._schema_to_example(schema)

    def _build_synthetic_headers(
        self,
        operation: Dict[str, Any],
        known: Optional[NormalizedTrafficPacket],
    ) -> Dict[str, str]:
        headers = {}
        if known:
            for k, v in known.raw_headers:
                headers[k] = v
            for key in list(headers.keys()):
                if key.lower() in ("authorization", "cookie", "x-csrf-token"):
                    del headers[key]
        return headers

    def _schema_to_example(self, schema: Dict[str, Any]) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        for prop_name, prop_schema in schema.get("properties", {}).items():
            ptype = prop_schema.get("type", "string")
            fmt = prop_schema.get("format", "")
            if ptype == "integer":
                result[prop_name] = self.rng.randint(1, 1000)
            elif ptype == "number":
                result[prop_name] = round(self.rng.random() * 100, 2)
            elif ptype == "boolean":
                result[prop_name] = self.rng.choice([True, False])
            elif ptype == "string" and fmt == "uuid":
                result[prop_name] = "00000000-0000-0000-0000-000000000000"
            elif ptype == "string" and fmt == "date-time":
                result[prop_name] = "2024-01-01T00:00:00Z"
            elif ptype == "string" and fmt == "email":
                result[prop_name] = "test@example.com"
            else:
                result[prop_name] = "string"
        return result

    @staticmethod
    def _find_known_packet(
        packets: List[NormalizedTrafficPacket],
        path_template: str,
        method: str,
    ) -> Optional[NormalizedTrafficPacket]:
        for p in packets:
            if p.method.upper() == method.upper() and p.endpoint_path_template == path_template:
                return p
        return None
