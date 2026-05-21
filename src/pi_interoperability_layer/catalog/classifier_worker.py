"""Capability Classifier Worker.

Deterministic mapping from package metadata to CapabilityClass.
No LLM inference. Rule-based classification with evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from pi_extension_governor.manifest import CapabilityClass, ExtensionManifest


@dataclass(frozen=True)
class ClassificationEvidence:
    rule: str
    matched_keywords: Tuple[str, ...]
    confidence_basis: str  # "keyword_match", "dependency_pattern", "description_pattern"


@dataclass(frozen=True)
class CapabilityClassificationResult:
    manifest_id: str
    assigned_class: CapabilityClass
    evidence: Tuple[ClassificationEvidence, ...]
    classification_hash: str

    def compute_hash(self) -> str:
        data = json.dumps(
            {
                "manifest_id": self.manifest_id,
                "class": self.assigned_class.value,
                "evidence": [
                    {"rule": e.rule, "keywords": sorted(e.matched_keywords), "basis": e.confidence_basis}
                    for e in self.evidence
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(data.encode()).hexdigest()


class CapabilityClassifierWorker:
    """Deterministic capability classification worker.

    Maps package metadata to CapabilityClass using keyword/dependency/description
    rule matching. No probabilistic scoring. Evidence-bound only.
    """

    # Keyword → CapabilityClass mapping
    _KEYWORD_RULES: Dict[CapabilityClass, Set[str]] = {
        CapabilityClass.OPENAPI_TOOLING: {
            "openapi", "swagger", "api", "rest", "http", "endpoint",
            "schema", "spec", "contract", "oas", "graphql",
        },
        CapabilityClass.KUBERNETES_MANIFEST: {
            "kubernetes", "k8s", "helm", "container", "pod", "deployment",
            "namespace", "cluster", "docker", "oci",
        },
        CapabilityClass.TERRAFORM_ANALYSIS: {
            "terraform", "iac", "infrastructure", "cloud", "aws", "azure",
            "gcp", "provider", "resource", "module",
        },
        CapabilityClass.CICD_INTEGRATION: {
            "ci", "cd", "pipeline", "github-actions", "gitlab", "jenkins",
            "build", "deploy", "release", "workflow",
        },
        CapabilityClass.VISUALIZATION: {
            "visualization", "chart", "graph", "diagram", "plot", "render",
            "svg", "canvas", "dashboard", "ui",
        },
        CapabilityClass.OBSERVABILITY_ADAPTER: {
            "observability", "monitoring", "telemetry", "logging", "metrics",
            "trace", "alert", "prometheus", "grafana", "dashboard",
        },
        CapabilityClass.STATIC_ANALYZER: {
            "lint", "static", "analysis", "audit", "security", "scan",
            "vulnerability", "sast", "check", "verify",
        },
    }

    _DEPENDENCY_RULES: Dict[CapabilityClass, Set[str]] = {
        CapabilityClass.OPENAPI_TOOLING: {"@apidevtools", "swagger-parser", "openapi-types"},
        CapabilityClass.KUBERNETES_MANIFEST: {"@kubernetes", "kubectl", "helm"},
        CapabilityClass.TERRAFORM_ANALYSIS: {"terraform"},
        CapabilityClass.OBSERVABILITY_ADAPTER: {"@opentelemetry", "prom-client", "winston"},
    }

    def classify(self, manifest: ExtensionManifest) -> CapabilityClassificationResult:
        """Classify a manifest into a CapabilityClass with evidence."""
        evidence: List[ClassificationEvidence] = []
        scores: Dict[CapabilityClass, int] = dict.fromkeys(CapabilityClass, 0)

        # Keyword matching
        text = (manifest.description + " " + " ".join(manifest.metadata.get("keywords", []))).lower()
        for cap_class, keywords in self._KEYWORD_RULES.items():
            matched = {kw for kw in keywords if kw in text}
            if matched:
                scores[cap_class] += len(matched)
                evidence.append(ClassificationEvidence(
                    rule=f"keyword_match_{cap_class.value}",
                    matched_keywords=tuple(sorted(matched)),
                    confidence_basis="keyword_match",
                ))

        # Dependency pattern matching
        deps = set(manifest.dependencies)
        for cap_class, patterns in self._DEPENDENCY_RULES.items():
            matched = {p for p in patterns if any(p in d for d in deps)}
            if matched:
                scores[cap_class] += len(matched) * 2  # deps weighted higher
                evidence.append(ClassificationEvidence(
                    rule=f"dependency_pattern_{cap_class.value}",
                    matched_keywords=tuple(sorted(matched)),
                    confidence_basis="dependency_pattern",
                ))

        # Tie-breaking: prefer explicit class if already set and has score
        if manifest.capability_class != CapabilityClass.STATIC_ANALYZER:
            if scores.get(manifest.capability_class, 0) > 0:
                assigned = manifest.capability_class
            else:
                assigned = max(scores, key=lambda c: scores[c]) if any(scores.values()) else CapabilityClass.STATIC_ANALYZER
        else:
            assigned = max(scores, key=lambda c: scores[c]) if any(scores.values()) else CapabilityClass.STATIC_ANALYZER

        result = CapabilityClassificationResult(
            manifest_id=manifest.extension_id,
            assigned_class=assigned,
            evidence=tuple(evidence),
            classification_hash="",
        )
        return CapabilityClassificationResult(
            manifest_id=result.manifest_id,
            assigned_class=result.assigned_class,
            evidence=result.evidence,
            classification_hash=result.compute_hash(),
        )
