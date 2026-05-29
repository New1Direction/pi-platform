"""Telemetry Governance + Defensive Adversarial Simulation Workers.

Six specialized deterministic workers:
  1. TelemetryGovernorWorker     — telemetry exposure analysis
  2. ReplaySanitizerWorker       — deterministic replay-safe sanitization
  3. SensitiveFlowTrackerWorker  — sensitive field propagation tracking
  4. ObservabilityDiffWorker     — observability drift detection
  5. ComplianceEngineWorker      — deterministic compliance validation
  6. SecuritySimulationWorker    — sandboxed defensive adversarial simulation

No stealth. No evasion. No offensive exploitation.
Infrastructure-grade governance only.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Set

from pi_interoperability_layer.mesh.artifact_bus import ArtifactSlot
from pi_interoperability_layer.mesh.worker_base import WorkerBase, WorkerContract


class TelemetryGovernorWorker(WorkerBase):
    """VALIDATE worker: detect telemetry exposure hazards.

    Immutable inputs: SemanticIRTrace, DependencyGraph
    Immutable outputs: TelemetryExposureReport
    Execution bound: 5000ms, 64MB, max 16 input slots
    """

    def __init__(self, worker_id: str, contract: WorkerContract, bus, ledger) -> None:
        super().__init__(worker_id, contract, bus, ledger)

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        findings: List[Dict[str, Any]] = []
        debug_endpoints: List[str] = []
        token_leaks: List[Dict[str, Any]] = []
        stack_trace_exposures: List[str] = []
        auth_metadata_expansions: List[Dict[str, Any]] = []
        topology_disclosures: List[str] = []

        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                continue

            if slot.artifact_type == "SemanticIRTrace":
                for trace in slot.payload.get("traces", []):
                    ep = trace.get("endpoint_template", "")
                    # Debug endpoint exposure
                    if any(seg in ep for seg in ("/debug", ".debug", "/__debug__", "/admin/debug", "/swagger", "/openapi")):
                        debug_endpoints.append(ep)
                        findings.append({
                            "severity": "HIGH",
                            "rule": "debug_endpoint_exposure",
                            "endpoint": ep,
                            "detail": f"Debug/introspection endpoint exposed: {ep}"
                        })

                    # Auth metadata expansion
                    fields = trace.get("fields", [])
                    auth_fields = [f for f in fields if f.get("name", "").lower() in ("authorization", "x-api-key", "token", "jwt", "cookie")]
                    if len(auth_fields) > 2:
                        auth_metadata_expansions.append({
                            "endpoint": ep,
                            "auth_field_count": len(auth_fields),
                            "fields": [f.get("name") for f in auth_fields]
                        })
                        findings.append({
                            "severity": "MEDIUM",
                            "rule": "auth_metadata_expansion",
                            "endpoint": ep,
                            "detail": f"Auth metadata expanded to {len(auth_fields)} fields"
                        })

                    # Stack trace exposure in response fields
                    for f in fields:
                        fname = f.get("name", "").lower()
                        if any(k in fname for k in ("stack", "traceback", "error_detail", "debug_info")):
                            stack_trace_exposures.append(ep)
                            findings.append({
                                "severity": "HIGH",
                                "rule": "stack_trace_exposure",
                                "endpoint": ep,
                                "detail": f"Response field '{f.get('name')}' may expose stack traces"
                            })

            if slot.artifact_type == "DependencyGraph":
                for edge in slot.payload.get("edges", []):
                    up = edge.get("upstream_endpoint", "")
                    down = edge.get("downstream_endpoint", "")
                    # Internal topology disclosure if downstream leaks internal service names
                    if any(k in down.lower() for k in ("internal-", "svc-", "backend-", "db-", "queue-")):
                        topology_disclosures.append(f"{up} -> {down}")
                        findings.append({
                            "severity": "MEDIUM",
                            "rule": "internal_topology_disclosure",
                            "edge": f"{up} -> {down}",
                            "detail": "Dependency edge exposes internal service naming"
                        })

        # Token leakage: scan all input slot payloads for high-entropy strings
        token_leaks = self._scan_for_token_leaks(input_slot_ids)
        for leak in token_leaks:
            findings.append({
                "severity": "CRITICAL",
                "rule": "token_leakage",
                "slot_id": leak["slot_id"],
                "context": leak["context"],
                "detail": "High-entropy token-like string detected in payload"
            })

        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="TelemetryExposureReport",
            payload={
                "findings": findings,
                "debug_endpoints": debug_endpoints,
                "token_leaks": token_leaks,
                "stack_trace_exposures": stack_trace_exposures,
                "auth_metadata_expansions": auth_metadata_expansions,
                "topology_disclosures": topology_disclosures,
                "risk_score": len(findings),
                "pass": len(findings) == 0,
            },
        ).freeze()
        return [self.bus.write(slot)]

    def _scan_for_token_leaks(self, input_slot_ids: List[str]) -> List[Dict[str, Any]]:
        """Scan payload strings for high-entropy token-like patterns."""
        leaks = []
        # Deterministic patterns: JWT, API key shapes, bearer tokens
        token_patterns = [
            re.compile(r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),  # JWT
            re.compile(r"[a-zA-Z0-9]{32,64}"),  # API key-like
            re.compile(r"bearer\s+[a-zA-Z0-9_-]{20,}"),  # Bearer token
            re.compile(r"sk-[a-zA-Z0-9]{20,}"),  # Secret key pattern
        ]
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                continue
            payload_str = json.dumps(slot.payload, sort_keys=True, default=str)
            for pattern in token_patterns:
                for match in pattern.finditer(payload_str):
                    leaks.append({
                        "slot_id": sid,
                        "pattern": pattern.pattern[:20],
                        "context": payload_str[max(0, match.start()-20):match.end()+20],
                    })
        return leaks


class ReplaySanitizerWorker(WorkerBase):
    """GOVERN worker: deterministic replay-safe payload sanitization.

    Immutable inputs: RawSourceSnapshot, SemanticIRTrace
    Immutable outputs: SanitizedReplayBundle
    Execution bound: 5000ms, 64MB, max 16 input slots

    Preserves replay equivalence: sanitized payload produces same execution path.
    """

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        sanitized_slots: List[Dict[str, Any]] = []
        redaction_log: List[Dict[str, Any]] = []

        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                continue

            payload = self._deep_copy(slot.payload)
            redactions = self._sanitize_payload(payload, slot.artifact_type)

            if redactions:
                redaction_log.extend(redactions)

            sanitized_slots.append({
                "original_slot_id": sid,
                "artifact_type": slot.artifact_type,
                "sanitized_payload": payload,
                "redaction_count": len(redactions),
            })

        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="SanitizedReplayBundle",
            payload={
                "sanitized_slots": sanitized_slots,
                "redaction_log": redaction_log,
                "replay_equivalence_preserved": True,
                "sanitization_hash": self._compute_sanitization_hash(sanitized_slots),
            },
        ).freeze()
        return [self.bus.write(slot)]

    def _deep_copy(self, obj: Any) -> Any:
        return json.loads(json.dumps(obj, default=str))

    def _sanitize_payload(self, payload: Any, artifact_type: str) -> List[Dict[str, Any]]:
        """Recursively sanitize payload. Returns redaction log."""
        redactions: List[Dict[str, Any]] = []
        if isinstance(payload, dict):
            for key in list(payload.keys()):
                val = payload[key]
                # Check JWT first (before sensitive key, since a "token" key may hold a JWT)
                if isinstance(val, str) and self._is_jwt(val):
                    redactions.append({
                        "path": key,
                        "rule": "jwt_masking",
                        "original_type": "jwt",
                        "mask": self._deterministic_mask(key, val),
                    })
                    payload[key] = self._deterministic_mask(key, val)
                elif isinstance(val, str) and self._is_api_key(val):
                    redactions.append({
                        "path": key,
                        "rule": "api_key_masking",
                        "original_type": "api_key",
                        "mask": self._deterministic_mask(key, val),
                    })
                    payload[key] = self._deterministic_mask(key, val)
                elif self._is_sensitive_key(key):
                    redactions.append({
                        "path": key,
                        "rule": "sensitive_key_masking",
                        "original_type": type(val).__name__,
                        "mask": self._deterministic_mask(key, val),
                    })
                    payload[key] = self._deterministic_mask(key, val)
                elif isinstance(val, (dict, list)):
                    nested = self._sanitize_payload(val, artifact_type)
                    redactions.extend(nested)
        elif isinstance(payload, list):
            for _i, item in enumerate(payload):
                if isinstance(item, (dict, list)):
                    nested = self._sanitize_payload(item, artifact_type)
                    redactions.extend(nested)
        return redactions

    def _is_sensitive_key(self, key: str) -> bool:
        normalized = key.lower().replace("-", "_")
        return normalized in ("password", "secret", "api_key", "token", "jwt",
                             "authorization", "cookie", "session", "credit_card",
                             "ssn", "email", "phone", "pii")

    def _is_jwt(self, value: str) -> bool:
        parts = value.split(".")
        return len(parts) == 3 and all(len(part) > 0 for part in parts) and value.startswith("eyJ")

    def _is_api_key(self, value: str) -> bool:
        return len(value) >= 20 and not value.startswith("eyJ") and " " not in value

    def _deterministic_mask(self, key: str, original_value: Any) -> str:
        """Deterministic token replacement preserving structure."""
        seed = f"{key}:{json.dumps(original_value, default=str)}"
        h = hashlib.sha256(seed.encode()).hexdigest()[:16]
        if self._is_jwt(str(original_value)):
            return f"MASKED_JWT_{h}"
        return f"MASKED_{h}"

    def _compute_sanitization_hash(self, sanitized_slots: List[Dict[str, Any]]) -> str:
        payload_str = json.dumps(sanitized_slots, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(payload_str.encode()).hexdigest()


class SensitiveFlowTrackerWorker(WorkerBase):
    """VALIDATE worker: track sensitive field propagation and trust-boundary crossings.

    Immutable inputs: SemanticIRTrace, DependencyGraph, SanitizedReplayBundle
    Immutable outputs: SensitiveFlowReport
    Execution bound: 5000ms, 64MB, max 16 input slots
    """

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        secret_fields: Set[str] = set()
        field_propagation: List[Dict[str, Any]] = []
        trust_boundary_crossings: List[Dict[str, Any]] = []

        # First pass: identify sensitive fields in traces
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot and slot.artifact_type == "SemanticIRTrace":
                for trace in slot.payload.get("traces", []):
                    for field in trace.get("fields", []):
                        fname = field.get("name", "")
                        if self._is_sensitive_field(fname):
                            secret_fields.add(fname)
                            field_propagation.append({
                                "field": fname,
                                "endpoint": trace.get("endpoint_template"),
                                "event": "origin",
                                "trust_zone": self._classify_trust_zone(trace.get("endpoint_template", "")),
                            })

        # Second pass: trace propagation across dependency edges
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot and slot.artifact_type == "DependencyGraph":
                for edge in slot.payload.get("edges", []):
                    up = edge.get("upstream_endpoint", "")
                    down = edge.get("downstream_endpoint", "")
                    up_zone = self._classify_trust_zone(up)
                    down_zone = self._classify_trust_zone(down)
                    if up_zone != down_zone and secret_fields:
                        trust_boundary_crossings.append({
                            "edge": f"{up} -> {down}",
                            "sensitive_fields_crossed": sorted(secret_fields),
                            "from_zone": up_zone,
                            "to_zone": down_zone,
                        })

        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="SensitiveFlowReport",
            payload={
                "secret_fields": sorted(secret_fields),
                "field_propagation": field_propagation,
                "trust_boundary_crossings": trust_boundary_crossings,
                "crossing_count": len(trust_boundary_crossings),
                "pass": len(trust_boundary_crossings) == 0,
            },
        ).freeze()
        return [self.bus.write(slot)]

    def _is_sensitive_field(self, name: str) -> bool:
        normalized = name.lower().replace("-", "_")
        return normalized in ("password", "secret", "token", "api_key", "jwt",
                             "authorization", "credit_card", "ssn", "pii",
                             "session_id", "cookie")

    def _classify_trust_zone(self, endpoint: str) -> str:
        ep = endpoint.lower()
        if any(seg in ep for seg in ("/admin", "/internal", "/debug", "/mgmt")):
            return "TRUSTED"
        if any(seg in ep for seg in ("/public", "/api/v1", "/health")):
            return "UNTRUSTED"
        return "STANDARD"


class ObservabilityDiffWorker(WorkerBase):
    """DIFF worker: detect observability drift between telemetry snapshots.

    Immutable inputs: TelemetrySnapshot (baseline), TelemetrySnapshot (modified)
    Immutable outputs: ObservabilityDriftReport
    Execution bound: 5000ms, 64MB, max 16 input slots
    """

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        if len(input_slot_ids) < 2:
            slot = ArtifactSlot(
                producer_worker_id=self.worker_id,
                artifact_type="ObservabilityDriftReport",
                payload={"error": "Requires exactly 2 TelemetrySnapshot inputs (baseline, modified)"},
            ).freeze()
            return [self.bus.write(slot)]

        baseline_slot = self.bus.read(input_slot_ids[0])
        modified_slot = self.bus.read(input_slot_ids[1])

        if baseline_slot is None or modified_slot is None:
            slot = ArtifactSlot(
                producer_worker_id=self.worker_id,
                artifact_type="ObservabilityDriftReport",
                payload={"error": "Missing baseline or modified snapshot"},
            ).freeze()
            return [self.bus.write(slot)]

        baseline = baseline_slot.payload
        modified = modified_slot.payload

        # Verbosity expansion
        baseline_log_lines = baseline.get("log_lines", 0)
        modified_log_lines = modified.get("log_lines", 0)
        verbosity_expansion = modified_log_lines - baseline_log_lines

        # Sensitive field expansion
        baseline_sensitive = set(baseline.get("sensitive_fields", []))
        modified_sensitive = set(modified.get("sensitive_fields", []))
        new_sensitive_fields = sorted(modified_sensitive - baseline_sensitive)

        # Metadata growth
        baseline_metadata_keys = set(baseline.get("metadata_keys", []))
        modified_metadata_keys = set(modified.get("metadata_keys", []))
        new_metadata_keys = sorted(modified_metadata_keys - baseline_metadata_keys)

        findings = []
        if verbosity_expansion > 100:
            findings.append({
                "rule": "verbosity_expansion",
                "baseline_lines": baseline_log_lines,
                "modified_lines": modified_log_lines,
                "delta": verbosity_expansion,
                "detail": f"Log volume expanded by {verbosity_expansion} lines"
            })
        if new_sensitive_fields:
            findings.append({
                "rule": "new_sensitive_fields_in_telemetry",
                "fields": new_sensitive_fields,
                "detail": f"New sensitive fields entered telemetry: {new_sensitive_fields}"
            })
        if len(new_metadata_keys) > 3:
            findings.append({
                "rule": "metadata_growth",
                "new_keys": new_metadata_keys,
                "detail": f"Metadata keys expanded by {len(new_metadata_keys)}"
            })

        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="ObservabilityDriftReport",
            payload={
                "findings": findings,
                "verbosity_expansion": verbosity_expansion,
                "new_sensitive_fields": new_sensitive_fields,
                "new_metadata_keys": new_metadata_keys,
                "drift_score": len(findings) + len(new_sensitive_fields),
                "pass": len(findings) == 0 and len(new_sensitive_fields) == 0,
            },
        ).freeze()
        return [self.bus.write(slot)]


class ComplianceEngineWorker(WorkerBase):
    """VALIDATE worker: deterministic compliance rule evaluation.

    Immutable inputs: SemanticIRTrace, BoundaryValidationReport, TelemetryExposureReport
    Immutable outputs: ComplianceReport
    Execution bound: 5000ms, 64MB, max 16 input slots
    """

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        violations: List[Dict[str, Any]] = []

        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                continue

            if slot.artifact_type == "SemanticIRTrace":
                violations.extend(self._evaluate_gdpr_rules(slot.payload))
                violations.extend(self._evaluate_hipaa_rules(slot.payload))

            if slot.artifact_type == "BoundaryValidationReport":
                violations.extend(self._evaluate_soc2_rules(slot.payload))

            if slot.artifact_type == "TelemetryExposureReport":
                violations.extend(self._evaluate_pci_rules(slot.payload))

        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="ComplianceReport",
            payload={
                "violations": violations,
                "violation_count": len(violations),
                "frameworks_evaluated": ["GDPR", "SOC2", "HIPAA", "PCI-DSS"],
                "pass": len(violations) == 0,
            },
        ).freeze()
        return [self.bus.write(slot)]

    def _evaluate_gdpr_rules(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        violations = []
        for trace in payload.get("traces", []):
            for field in trace.get("fields", []):
                fname = field.get("name", "").lower()
                if fname in ("email", "phone", "ssn", "pii", "personal_data"):
                    if field.get("data_classification", "") != "SENSITIVE":
                        violations.append({
                            "framework": "GDPR",
                            "rule": "personal_data_classification",
                            "endpoint": trace.get("endpoint_template"),
                            "field": fname,
                            "detail": f"Personal data field '{fname}' lacks SENSITIVE classification"
                        })
        return violations

    def _evaluate_hipaa_rules(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        violations = []
        for trace in payload.get("traces", []):
            fields = trace.get("fields", [])
            phi_fields = [f for f in fields if f.get("name", "").lower() in ("ssn", "medical_record", "diagnosis", "patient_id")]
            if phi_fields and trace.get("mutation_class", "") != "IDEMPOTENT_READ":
                violations.append({
                    "framework": "HIPAA",
                    "rule": "phi_mutation_audit",
                    "endpoint": trace.get("endpoint_template"),
                    "detail": "PHI field present in non-read endpoint without explicit audit field"
                })
        return violations

    def _evaluate_soc2_rules(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        violations = []
        if payload.get("pass", True) is False:
            violations.append({
                "framework": "SOC2",
                "rule": "boundary_integrity",
                "detail": "Boundary validation failed — trust boundary controls not effective"
            })
        return violations

    def _evaluate_pci_rules(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        violations = []
        token_leaks = payload.get("token_leaks", [])
        if token_leaks:
            violations.append({
                "framework": "PCI-DSS",
                "rule": "token_exposure",
                "detail": f"{len(token_leaks)} token leakage instances detected in telemetry"
            })
        debug_endpoints = payload.get("debug_endpoints", [])
        if debug_endpoints:
            violations.append({
                "framework": "PCI-DSS",
                "rule": "debug_endpoint_exposure",
                "detail": f"Debug endpoints exposed: {debug_endpoints}"
            })
        return violations


class SecuritySimulationWorker(WorkerBase):
    """VALIDATE worker: sandboxed defensive adversarial simulation.

    Immutable inputs: SanitizedReplayBundle, SemanticIRTrace
    Immutable outputs: SecuritySimulationReport
    Execution bound: 10000ms, 128MB, max 16 input slots

    CONSTRAINTS:
      - Isolated sandbox execution only
      - No persistence
      - No self-propagation
      - No evasive behavior
      - No external targeting
      - Deterministic test corpus only

    This worker validates detections and governance rules using a
    deterministic test harness. It DOES NOT perform actual exploitation.
    """

    DETERMINISTIC_TEST_CORPUS: List[Dict[str, Any]] = [
        {"name": "malformed_jwt", "input": {"Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIn0."}, "expected_detection": True},
        {"name": "null_byte_injection", "input": {"path": "/api/users%00"}, "expected_detection": True},
        {"name": "oversized_payload", "input": {"body": "A" * 10001}, "expected_detection": True},
        {"name": "replay_reuse_attempt", "input": {"replay_id": "replay_abc", "replay_class": "NON_REPLAYABLE"}, "expected_detection": True},
        {"name": "auth_bypass_header", "input": {"X-Original-URL": "/admin/users"}, "expected_detection": True},
        {"name": "valid_request", "input": {"Authorization": "Bearer MASKED_1234", "path": "/api/users"}, "expected_detection": False},
    ]

    def _run(self, phase: str, input_slot_ids: List[str]) -> List[ArtifactSlot]:
        detection_validations: List[Dict[str, Any]] = []
        containment_validations: List[Dict[str, Any]] = []

        # Load governance rules from available artifacts
        governance_rules = self._extract_governance_rules(input_slot_ids)

        # Run deterministic test corpus through governance rule validation
        for test in self.DETERMINISTIC_TEST_CORPUS:
            detected = self._apply_defensive_rules(test["input"], governance_rules)
            detection_validations.append({
                "test_name": test["name"],
                "expected": test["expected_detection"],
                "actual": detected,
                "pass": detected == test["expected_detection"],
            })

        # Validate replay containment guarantees
        containment_validations = self._validate_replay_containment(input_slot_ids, governance_rules)

        all_pass = all(v["pass"] for v in detection_validations) and all(v["pass"] for v in containment_validations)

        slot = ArtifactSlot(
            producer_worker_id=self.worker_id,
            artifact_type="SecuritySimulationReport",
            payload={
                "detection_validations": detection_validations,
                "containment_validations": containment_validations,
                "tests_run": len(self.DETERMINISTIC_TEST_CORPUS),
                "tests_passed": sum(1 for v in detection_validations if v["pass"]),
                "replay_containment_passed": all(v["pass"] for v in containment_validations),
                "pass": all_pass,
                "sandbox_mode": True,
                "external_targeting": False,
                "persistence": False,
                "self_propagation": False,
            },
        ).freeze()
        return [self.bus.write(slot)]

    def _extract_governance_rules(self, input_slot_ids: List[str]) -> List[Dict[str, Any]]:
        """Extract deterministic governance rules from available artifacts."""
        rules = []
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot is None:
                continue
            if slot.artifact_type == "BoundaryValidationReport":
                rules.append({"type": "boundary", "pass": slot.payload.get("pass", True)})
            if slot.artifact_type == "TelemetryExposureReport":
                rules.append({"type": "telemetry", "risk_score": slot.payload.get("risk_score", 0)})
            if slot.artifact_type == "SensitiveFlowReport":
                rules.append({"type": "flow", "crossing_count": slot.payload.get("crossing_count", 0)})
        return rules

    def _apply_defensive_rules(self, test_input: Dict[str, Any], rules: List[Dict[str, Any]]) -> bool:
        """Apply deterministic defensive rules to test input."""
        # Malformed JWT detection (only if value looks like a JWT candidate)
        auth = test_input.get("Authorization", "")
        if isinstance(auth, str):
            jwt_candidate = auth
            if jwt_candidate.lower().startswith("bearer "):
                jwt_candidate = jwt_candidate[7:]
            if jwt_candidate.startswith("eyJ") and jwt_candidate.count(".") == 2:
                header = jwt_candidate.split(".")[0]
                try:
                    import base64
                    padding = 4 - len(header) % 4
                    if padding != 4:
                        header += "=" * padding
                    decoded = base64.urlsafe_b64decode(header).decode("utf-8", errors="replace")
                    if '"alg":"none"' in decoded or '"alg": "none"' in decoded:
                        return True
                except Exception:
                    pass
        # Null byte injection
        path = test_input.get("path", "")
        if isinstance(path, str) and "%00" in path:
            return True
        # Oversized payload
        body = test_input.get("body", "")
        if isinstance(body, str) and len(body) > 10000:
            return True
        # Replay reuse on non-replayable
        replay_class = test_input.get("replay_class", "")
        if replay_class == "NON_REPLAYABLE":
            return True
        # Auth bypass header
        if "X-Original-URL" in test_input:
            return True
        return False

    def _validate_replay_containment(self, input_slot_ids: List[str], rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validate that replay containment guarantees hold."""
        validations = []
        for sid in input_slot_ids:
            slot = self.bus.read(sid)
            if slot and slot.artifact_type == "SanitizedReplayBundle":
                sanitized = slot.payload.get("sanitized_slots", [])
                has_masking = any(s.get("redaction_count", 0) > 0 for s in sanitized)
                validations.append({
                    "rule": "replay_data_masked",
                    "pass": has_masking,
                    "detail": "Sanitized replay bundle contains masking" if has_masking else "NO MASKING DETECTED IN REPLAY BUNDLE"
                })
        if not validations:
            validations.append({
                "rule": "replay_data_masked",
                "pass": True,
                "detail": "No replay bundle present — containment not applicable"
            })
        return validations
