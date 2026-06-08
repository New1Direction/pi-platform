"""Semantic Spec-Fuzzer & Chaos Engine (Radius-Fuzzer).

Responsible for deep schema mutations, type-confusion injections,
undocumented parameter discovery, and proxy-mediated execution.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

logger = logging.getLogger("pi_semantic_radius.fuzzer")


class SemanticParameterSpec(BaseModel):
    name: str
    type_str: str  # uuid, int, string, email, date, float, object
    required: bool = True
    nested_schema: Optional[Dict[str, Any]] = None


class FuzzTarget(BaseModel):
    path: str
    method: str
    parameters: List[SemanticParameterSpec] = Field(default_factory=list)
    headers: List[str] = Field(default_factory=list)
    blast_radius: int = 1
    sd_score: float = 0.0


class MutationPayload(BaseModel):
    target_path: str
    method: str
    headers: Dict[str, str]
    params: Dict[str, Any]
    mutation_class: str
    original_type_drift: str


class RadiusFuzzerEngine:
    """Radius-Fuzzer Core Engine.

    Enforces deep schema mutations, type-confusion injections,
    undocumented parameter discovery, and proxy-mediated routing.
    """

    # Dictionary of shadow parameters used for undocumented parameter enumeration
    SHADOW_PARAMETERS: List[Tuple[str, str]] = [
        ("admin", "bool"),
        ("debug", "bool"),
        ("role", "string"),
        ("internal", "bool"),
        ("bypass", "bool"),
        ("tenant", "uuid"),
        ("super", "bool"),
        ("sandbox", "bool"),
        ("user_id", "uuid"),
        ("override", "string"),
    ]

    def __init__(
        self,
        target_base_url: str = "http://127.0.0.1:8000",
        proxy_url: Optional[str] = "http://127.0.0.1:8080",
    ) -> None:
        self.target_base_url = target_base_url
        self.proxy_url = proxy_url

    def prioritize_targets(
        self,
        targets: List[FuzzTarget],
        weight_blast_radius: float = 0.6,
        weight_parameter_count: float = 0.4,
    ) -> List[FuzzTarget]:
        """Calculates Semantic Disruption Score (S_d) and prioritizes targets."""
        prioritized = []
        for t in targets:
            complexity = len(t.parameters) * 5.0
            sd_score = (weight_blast_radius * t.blast_radius) + (weight_parameter_count * complexity)

            # Create a new FuzzTarget copy with calculated score
            updated_target = FuzzTarget(
                path=t.path,
                method=t.method,
                parameters=t.parameters,
                headers=t.headers,
                blast_radius=t.blast_radius,
                sd_score=round(sd_score, 2),
            )
            prioritized.append(updated_target)

        return sorted(prioritized, key=lambda x: x.sd_score, reverse=True)

    def generate_type_confusion(self, param: SemanticParameterSpec) -> Any:
        """Injects deep type-confusion inputs targeting parsers."""
        t_str = param.type_str.lower()
        if t_str == "uuid":
            return [str(uuid.uuid4()), 12345]  # Swaps uuid with dynamic array
        elif t_str == "int":
            return "not_an_integer_string"
        elif t_str == "float":
            return {"scientific_notation": "1e309"}  # Large exponential float object
        elif t_str == "email":
            return "plain_string_without_at_symbol"
        elif t_str == "date":
            return 99999999999999  # Unix epoch timestamp overflow instead of ISO8601
        elif t_str == "object":
            return "string_instead_of_object"
        return {"type_confusion_nested": True}

    def generate_boundary_overflow(self, param: SemanticParameterSpec) -> Any:
        """Injects extreme values to trigger numerical overflows or memory spikes."""
        t_str = param.type_str.lower()
        if t_str == "int":
            return 99999999999999999999999999999999999999999999999  # Standard Python big int
        elif t_str == "float":
            return float("inf")  # Floating point infinity
        elif t_str == "string":
            return "A" * 50000  # 50KB string buffer
        elif t_str == "uuid":
            return "00000000-0000-0000-0000-000000000000"  # Null UUID
        return "boundary_limit_val"

    def enumerate_undocumented_parameters(self, target: FuzzTarget) -> List[MutationPayload]:
        """Injects shadow/undocumented parameters to probe for access control leaks."""
        payloads = []
        base_headers = dict.fromkeys(target.headers, "active_sandbox_token")
        base_params = {p.name: self._get_default_val(p.type_str) for p in target.parameters}

        # Inject each shadow parameter sequentially
        for s_name, s_type in self.SHADOW_PARAMETERS:
            shadow_val = self._get_shadow_val(s_type)
            mutated_params = base_params.copy()
            mutated_params[s_name] = shadow_val

            payloads.append(
                MutationPayload(
                    target_path=target.path,
                    method=target.method,
                    headers=base_headers,
                    params=mutated_params,
                    mutation_class="undocumented_parameter",
                    original_type_drift=f"shadow_param_injected:{s_name}:{s_type}",
                )
            )

        return payloads

    def generate_mutations(self, target: FuzzTarget) -> List[MutationPayload]:
        """Compiles a complete list of high-entropy mutations for a target."""
        payloads = []
        base_headers = dict.fromkeys(target.headers, "active_sandbox_token")

        # 1. Generate Type Confusion
        tc_params = {}
        for p in target.parameters:
            tc_params[p.name] = self.generate_type_confusion(p)
        payloads.append(
            MutationPayload(
                target_path=target.path,
                method=target.method,
                headers=base_headers,
                params=tc_params,
                mutation_class="type_confusion",
                original_type_drift="swapped_parameter_types",
            )
        )

        # 2. Generate Boundary Overflow
        bo_params = {}
        for p in target.parameters:
            bo_params[p.name] = self.generate_boundary_overflow(p)
        payloads.append(
            MutationPayload(
                target_path=target.path,
                method=target.method,
                headers=base_headers,
                params=bo_params,
                mutation_class="boundary_overflow",
                original_type_drift="numerical_buffer_overflow",
            )
        )

        # 3. Generate Shadow Enumeration
        payloads.extend(self.enumerate_undocumented_parameters(target))

        return payloads

    def _get_default_val(self, type_str: str) -> Any:
        t_str = type_str.lower()
        if t_str == "uuid":
            return str(uuid.uuid4())
        elif t_str == "int":
            return 1
        elif t_str == "float":
            return 1.0
        elif t_str == "email":
            return "test@example.com"
        elif t_str == "date":
            return "2026-05-20"
        elif t_str == "object":
            return {}
        return "default_str"

    def _get_shadow_val(self, type_str: str) -> Any:
        if type_str == "bool":
            return True
        elif type_str == "uuid":
            return str(uuid.uuid4())
        return "admin_override"
