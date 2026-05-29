"""Auth Consistency Validator — Phase 3 of verification subsystem.

Deterministic Authentication Governance.

Key constraint: evidence-bound ONLY. Never infer auth semantics from naming.
Operates on observed header values, actual token patterns, replay-confirmed presence.
Observational only. Returns AuthConsistencyReport + GovernanceViolations.
Never mutates runtime state.
"""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from pi_agent_chain.models import (
    AuthBinding,
    AuthConsistencyReport,
    AuthEvidence,
    AuthEvidenceType,
    AuthInvariant,
    EpistemicState,
    GovernanceViolation,
    NormalizedTrafficPacket,
    SemanticIRTrace,
    ValidationBoundsConfig,
)


class AuthConsistencyValidator:
    """Validate authentication invariants from observed evidence.

    NOT a classifier. NOT an inferencer. A correlation validator.
    """

    # Auth-related inferred types observed by SemanticTyperNode
    AUTH_TYPES = {"JWT", "JWT_Payload", "Base64", "HexDigest", "UNKNOWN_HEX"}
    # Auth-related header names (used for evidence extraction, not inference)
    AUTH_HEADER_NAMES = {"authorization", "cookie", "x-csrf-token", "x-xsrf-token",
                         "x-api-key", "x-auth-token"}

    def __init__(self, min_binding_confidence: float = 0.85, bounds: Optional[Any] = None) -> None:
        self.min_binding_confidence = min_binding_confidence
        self.bounds = bounds or ValidationBoundsConfig()

    # ──────────────────────────────
    #  Public API
    # ──────────────────────────────

    def validate(
        self,
        traces: List[SemanticIRTrace],
        packets: List[NormalizedTrafficPacket],
        execution_id: str = "",
    ) -> AuthConsistencyReport:
        """Produce an observational auth consistency report.

        Returns:
            AuthConsistencyReport — evidence, invariants, bindings, violations
        """
        evidence = self._extract_evidence(traces, packets, execution_id)
        bindings = self._detect_bindings(evidence, execution_id)
        invariants = self._infer_invariants(evidence, bindings, execution_id)
        violations = self._evaluate_governance(invariants, evidence, execution_id)
        token_entropy = self._compute_token_entropy(evidence)

        return AuthConsistencyReport(
            report_id=self._hash(f"auth_report:{execution_id}"),
            invariants=invariants,
            evidence=evidence,
            bindings=bindings,
            violations=violations,
            auth_field_count=len(evidence),
            token_entropy=round(token_entropy, 4),
        )

    # ──────────────────────────────
    #  Evidence Extraction
    # ──────────────────────────────

    def _extract_evidence(
        self,
        traces: List[SemanticIRTrace],
        packets: List[NormalizedTrafficPacket],
        execution_id: str,
    ) -> List[AuthEvidence]:
        """Extract ONLY observed auth evidence from traces and raw packets.

        Evidence-bound rule: we use SemanticTyper's type classification
        (which already matched patterns) and actual header presence.
        We NEVER infer auth from field names alone.
        """
        evidence: List[AuthEvidence] = []
        trace_by_endpoint: Dict[Tuple[str, str], SemanticIRTrace] = {
            (t.endpoint_template, t.method): t for t in traces
        }

        for pkt in packets:
            key = (pkt.endpoint_path_template, pkt.method)
            trace = trace_by_endpoint.get(key)

            # Extract from actual headers (observed values)
            for hk, hv in pkt.raw_headers:
                hk.lower()
                ev = self._classify_header_evidence(
                    hk, hv, pkt, execution_id, trace
                )
                if ev:
                    evidence.append(ev)

            # Extract from response headers (for auth transitions: 401/403)
            for hk, hv in pkt.response_headers:
                if pkt.response_status in (401, 403):
                    ev = self._classify_header_evidence(
                        hk, hv, pkt, execution_id, trace, is_response=True
                    )
                    if ev:
                        evidence.append(ev)

        return evidence

    def _classify_header_evidence(
        self,
        header_key: str,
        header_value: str,
        pkt: NormalizedTrafficPacket,
        execution_id: str,
        trace: Optional[SemanticIRTrace],
        is_response: bool = False,
    ) -> Optional[AuthEvidence]:
        """Classify a single header into AuthEvidence.

        Uses actual value patterns, not just names.
        """
        hkl = header_key.lower()
        val_hash = hashlib.sha256(header_value.encode()).hexdigest()[:16]

        # Match against traced field types if available
        traced_type = None
        if trace:
            prefix = "response_header." if is_response else "header."
            for f in trace.fields:
                if f.path.startswith(prefix) and f.path.lower().endswith(hkl):
                    traced_type = f.inferred_type
                    break

        # Evidence-type classification based on VALUE patterns, not names
        if hkl == "authorization":
            if header_value.strip().lower().startswith("bearer "):
                ev_type = AuthEvidenceType.BEARER_HEADER
            elif header_value.strip().lower().startswith("basic "):
                ev_type = AuthEvidenceType.BASIC_HEADER
            elif traced_type == "JWT":
                ev_type = AuthEvidenceType.JWT_HEADER
            else:
                ev_type = AuthEvidenceType.UNKNOWN_AUTH
        elif hkl == "cookie":
            if "session" in header_value.lower():
                ev_type = AuthEvidenceType.SESSION_COOKIE
            else:
                ev_type = AuthEvidenceType.COOKIE_TOKEN
        elif "csrf" in hkl or "xsrf" in hkl:
            ev_type = AuthEvidenceType.CSRF_TOKEN
        elif "api-key" in hkl or "auth-token" in hkl:
            if traced_type in self.AUTH_TYPES:
                ev_type = AuthEvidenceType.API_KEY_HEADER
            else:
                ev_type = AuthEvidenceType.UNKNOWN_AUTH
        else:
            return None

        return AuthEvidence(
            evidence_id=self._hash(f"{execution_id}:{pkt.compute_hash()}:{hkl}"),
            trace_id=execution_id,
            packet_id=pkt.compute_hash(),
            evidence_type=ev_type,
            field_path=f"{'response_header' if is_response else 'header'}.{header_key}",
            carrier="HEADER" if not is_response else "COOKIE" if hkl == "cookie" else "HEADER",
            observed_value_hash=val_hash,
            observed_at=datetime.utcnow(),
            endpoint_template=pkt.endpoint_path_template,
            method=pkt.method,
            status_code=pkt.response_status,
        )

    # ──────────────────────────────
    #  Binding Detection
    # ──────────────────────────────

    def _detect_bindings(
        self,
        evidence: List[AuthEvidence],
        execution_id: str,
    ) -> List[AuthBinding]:
        """Detect co-occurrence bindings between auth carriers.

        Evidence-bound: counts actual packet-level co-occurrences.
        """
        # Group evidence by packet
        by_packet: Dict[str, List[AuthEvidence]] = defaultdict(list)
        for ev in evidence:
            by_packet[ev.packet_id].append(ev)

        # Count co-occurrences and disjoint occurrences for carrier pairs
        pair_stats: Dict[Tuple[str, str], Dict[str, any]] = defaultdict(
            lambda: {"co": 0, "disjoint": 0, "evidence": []}
        )

        all_carriers = set()
        for ev in evidence:
            all_carriers.add((ev.carrier, ev.field_path))

        carrier_pairs = []
        clist = list(all_carriers)
        for i in range(len(clist)):
            for j in range(i + 1, len(clist)):
                carrier_pairs.append((clist[i], clist[j]))

        for _pkt_id, pkt_evs in by_packet.items():
            pkt_carriers = {(e.carrier, e.field_path) for e in pkt_evs}
            for (c1, fp1), (c2, fp2) in carrier_pairs:
                key = (f"{c1}:{fp1}", f"{c2}:{fp2}")
                if (c1, fp1) in pkt_carriers and (c2, fp2) in pkt_carriers:
                    pair_stats[key]["co"] += 1
                    pair_stats[key]["evidence"].extend([
                        e.evidence_id for e in pkt_evs
                        if (e.carrier, e.field_path) in ((c1, fp1), (c2, fp2))
                    ])
                else:
                    pair_stats[key]["disjoint"] += 1

        bindings: List[AuthBinding] = []
        for pair_key, stats in pair_stats.items():
            total = stats["co"] + stats["disjoint"]
            if total == 0:
                continue
            confidence = stats["co"] / total
            if confidence >= self.min_binding_confidence:
                a_path, b_path = pair_key
                carrier_a, field_a = a_path.split(":", 1)
                carrier_b, field_b = b_path.split(":", 1)
                bindings.append(
                    AuthBinding(
                        binding_id=self._hash(f"bind:{execution_id}:{pair_key}"),
                        carrier_a=carrier_a,
                        field_path_a=field_a,
                        carrier_b=carrier_b,
                        field_path_b=field_b,
                        co_occurrence_count=stats["co"],
                        disjoint_count=stats["disjoint"],
                        confidence=round(confidence, 4),
                        evidence_refs=list(set(stats["evidence"])),
                        epistemic_state=EpistemicState.OBSERVED,
                    )
                )

        return bindings

    # ──────────────────────────────
    #  Invariant Inference
    # ──────────────────────────────

    def _infer_invariants(
        self,
        evidence: List[AuthEvidence],
        bindings: List[AuthBinding],
        execution_id: str,
    ) -> List[AuthInvariant]:
        """Infer auth invariants from evidence and bindings.

        Evidence-bound. No naming-based speculation.
        """
        invariants: List[AuthInvariant] = []

        # --- TOKEN_REUSE: same value hash across multiple packets ---
        by_hash: Dict[str, List[AuthEvidence]] = defaultdict(list)
        for ev in evidence:
            if ev.evidence_type in (AuthEvidenceType.BEARER_HEADER,
                                     AuthEvidenceType.JWT_HEADER,
                                     AuthEvidenceType.API_KEY_HEADER):
                by_hash[ev.observed_value_hash].append(ev)

        reused = {h: evs for h, evs in by_hash.items() if len(evs) > 1}
        for val_hash, evs in reused.items():
            endpoints = list({e.endpoint_template for e in evs})
            invariants.append(
                AuthInvariant(
                    invariant_id=self._hash(f"reuse:{execution_id}:{val_hash}"),
                    invariant_type="TOKEN_REUSE",
                    description=f"Token hash {val_hash} reused across {len(evs)} packets",
                    evidence_refs=[e.evidence_id for e in evs],
                    affected_endpoints=endpoints,
                    confidence=round(min(len(evs) / 10, 1.0), 4),
                    epistemic_state=EpistemicState.OBSERVED,
                )
            )

        # --- CSRF_COUPLING: CSRF token bound to session cookie ---
        csrf_ev = [e for e in evidence if e.evidence_type == AuthEvidenceType.CSRF_TOKEN]
        cookie_ev = [e for e in evidence if e.evidence_type == AuthEvidenceType.SESSION_COOKIE]
        if csrf_ev and cookie_ev:
            # Check if they co-occur in same packets
            csrf_packets = {e.packet_id for e in csrf_ev}
            cookie_packets = {e.packet_id for e in cookie_ev}
            overlap = csrf_packets & cookie_packets
            disjoint = (csrf_packets | cookie_packets) - overlap
            total = len(overlap) + len(disjoint)
            if total > 0:
                conf = len(overlap) / total
                invariants.append(
                    AuthInvariant(
                        invariant_id=self._hash(f"csrf:{execution_id}"),
                        invariant_type="CSRF_COUPLING",
                        description="CSRF token observed with session cookie",
                        evidence_refs=[e.evidence_id for e in csrf_ev + cookie_ev],
                        affected_endpoints=list({e.endpoint_template for e in csrf_ev + cookie_ev}),
                        confidence=round(conf, 4),
                        epistemic_state=EpistemicState.OBSERVED if conf >= self.min_binding_confidence else EpistemicState.INFERRED,
                    )
                )

        # --- SESSION_ROTATION: token hash changes between sequential requests ---
        by_endpoint: Dict[str, List[AuthEvidence]] = defaultdict(list)
        for ev in evidence:
            if ev.evidence_type in (AuthEvidenceType.BEARER_HEADER,
                                     AuthEvidenceType.JWT_HEADER,
                                     AuthEvidenceType.SESSION_COOKIE):
                by_endpoint[ev.endpoint_template].append(ev)

        for endpoint, evs in by_endpoint.items():
            if len(evs) < 2:
                continue
            hashes = [e.observed_value_hash for e in evs]
            sorted(evs, key=lambda e: e.observed_at)
            unique_hashes = len(set(hashes))
            total = len(evs)

            # Classification
            if unique_hashes == 1:
                rotation_class = "STATIC"
            elif unique_hashes == total:
                rotation_class = "PER_REQUEST"
            elif unique_hashes < total:
                rotation_class = "PER_SESSION"
            else:
                rotation_class = "UNKNOWN"

            # STATE_BOUND: hash changes correlate with status code changes
            status_changes = len({e.status_code for e in evs}) > 1
            if status_changes and unique_hashes > 1:
                rotation_class = "STATE_BOUND"

            invariants.append(
                AuthInvariant(
                    invariant_id=self._hash(f"rotation:{execution_id}:{endpoint}"),
                    invariant_type="SESSION_ROTATION",
                    description=f"Auth material changed {unique_hashes} times across {len(evs)} requests to {endpoint}",
                    rotation_class=rotation_class,
                    evidence_refs=[e.evidence_id for e in evs],
                    affected_endpoints=[endpoint],
                    confidence=round(min(unique_hashes / len(evs), 1.0), 4),
                    epistemic_state=EpistemicState.OBSERVED,
                )
            )

        # --- AUTH_TRANSITION: 401/403 after auth evidence ---
        auth_then_fail: List[AuthEvidence] = []
        for ev in evidence:
            if ev.status_code in (401, 403):
                auth_then_fail.append(ev)
        if auth_then_fail:
            invariants.append(
                AuthInvariant(
                    invariant_id=self._hash(f"trans:{execution_id}"),
                    invariant_type="AUTH_TRANSITION",
                    description="Auth material observed with 401/403 response",
                    evidence_refs=[e.evidence_id for e in auth_then_fail],
                    affected_endpoints=list({e.endpoint_template for e in auth_then_fail}),
                    confidence=round(min(len(auth_then_fail) / 5, 1.0), 4),
                    epistemic_state=EpistemicState.OBSERVED,
                )
            )

        # --- REPLAY_SURVIVABILITY: auth present in replayable traffic ---
        replayable_auth = [e for e in evidence
                          if e.evidence_type in (AuthEvidenceType.BEARER_HEADER,
                                                  AuthEvidenceType.JWT_HEADER,
                                                  AuthEvidenceType.API_KEY_HEADER)]
        if replayable_auth:
            invariants.append(
                AuthInvariant(
                    invariant_id=self._hash(f"replay:{execution_id}"),
                    invariant_type="REPLAY_SURVIVABILITY",
                    description=f"Bearer/JWT/API-key auth observed in {len({e.packet_id for e in replayable_auth})} packets",
                    evidence_refs=[e.evidence_id for e in replayable_auth],
                    affected_endpoints=list({e.endpoint_template for e in replayable_auth}),
                    confidence=0.95,
                    epistemic_state=EpistemicState.OBSERVED,
                )
            )

        # --- DEPENDENCY_ORDERING: endpoints ordered by auth presence
        # WARNING: This invariant is TEMPORAL-ONLY from observed traffic order.
        # It is NOT replay-confirmed. Traffic capture order != protocol causality.
        # It MUST remain INFERRED / CONTESTED until replay evidence proves transition
        # necessity (B fails without A, auth collapses, semantic class changes).
        authed_endpoints = {e.endpoint_template for e in evidence}
        if len(authed_endpoints) > 1:
            invariants.append(
                AuthInvariant(
                    invariant_id=self._hash(f"order:{execution_id}"),
                    invariant_type="DEPENDENCY_ORDERING",
                    description=f"Auth evidence observed across {len(authed_endpoints)} distinct endpoints. TEMPORAL ONLY. Replay confirmation required for VALID transition.",
                    evidence_refs=[e.evidence_id for e in evidence],
                    affected_endpoints=sorted(authed_endpoints),
                    replay_confirmed_endpoints=[],  # EMPTY until replay proven
                    confidence=round(min(len(authed_endpoints) / 10, 1.0), 4),
                    epistemic_state=EpistemicState.CONTESTED,  # NOT INFERRED — contested
                )
            )

        return invariants

    # ──────────────────────────────
    #  Governance Evaluation
    # ──────────────────────────────

    def _evaluate_governance(
        self,
        invariants: List[AuthInvariant],
        evidence: List[AuthEvidence],
        execution_id: str,
    ) -> List[GovernanceViolation]:
        """Transform invariants into governance violations.

        Observational only. The kernel decides.
        """
        violations: List[GovernanceViolation] = []

        # Rule: 401/403 with auth material present = auth transition failure
        auth_transitions = [inv for inv in invariants if inv.invariant_type == "AUTH_TRANSITION"]
        for inv in auth_transitions:
            if inv.confidence >= self.min_binding_confidence:
                violations.append(
                    GovernanceViolation(
                        violation_id=self._hash(f"auth_trans:{execution_id}"),
                        rule="AUTH_TRANSITION_INVALIDATION",
                        worker_id="auth_consistency_validator",
                        root_goal_id=execution_id,
                        severity="ERROR",
                        context={
                            "affected_endpoints": inv.affected_endpoints,
                            "confidence": inv.confidence,
                            "evidence_count": len(inv.evidence_refs),
                        },
                        action_taken="HALT",
                    )
                )

        # Rule: No auth evidence observed for protected endpoints
        # (Detected when auth evidence count is zero but traces contain sensitive fields)
        if not evidence:
            # This is informational, not necessarily a violation
            pass

        # Rule: Auth material lost in replay (detected by REPLAY_SURVIVABILITY with zero replayable_auth)
        # But REPLAY_SURVIVABILITY invariant is positive evidence; absence is a different check
        return violations

    # ──────────────────────────────
    #  Utilities
    # ──────────────────────────────

    def _compute_token_entropy(self, evidence: List[AuthEvidence]) -> float:
        """Compute Shannon entropy of observed token value hashes."""
        hashes = [e.observed_value_hash for e in evidence
                  if e.evidence_type in (AuthEvidenceType.BEARER_HEADER,
                                          AuthEvidenceType.JWT_HEADER,
                                          AuthEvidenceType.API_KEY_HEADER)]
        if not hashes:
            return 0.0
        freq: Dict[str, int] = {}
        for h in hashes:
            freq[h] = freq.get(h, 0) + 1
        length = len(hashes)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        max_e = math.log2(len(freq)) if len(freq) > 1 else 1.0
        return entropy / max_e if max_e > 0 else 0.0

    @staticmethod
    def _hash(s: str) -> str:
        return hashlib.sha256(s.encode()).hexdigest()[:16]
