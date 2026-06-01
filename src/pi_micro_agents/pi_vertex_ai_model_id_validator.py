from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field

# Catalog mapping task type to standard list of supported models
_SUPPORTED_MODELS: Dict[str, List[str]] = {
    "generation": [
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
        "gemini-2.0-pro",
        "gemini-1.5-flash",
        "gemini-1.5-pro",
        "gemini-1.5-flash-8b",
        "gemini-2.5-flash",
        "gemini-2.5-pro",
    ],
    "embedding": [
        "text-embedding-004",
        "text-embedding-005",
        "text-multilingual-embedding-002",
        "multimodalembedding@001",
    ],
    "vision": [
        "gemini-2.0-flash",
        "gemini-2.0-pro",
        "gemini-1.5-pro",
        "gemini-2.5-pro",
    ],
    "routing": [
        "gemini-2.0-flash",
        "gemini-2.0-flash-lite",
    ],
}

_DEPRECATED_MODELS = {
    "gemini-1.0-pro": "gemini-2.0-flash",
    "gemini-1.0-ultra": "gemini-2.0-flash",
    "text-bison": "gemini-2.0-flash",
    "chat-bison": "gemini-2.0-flash",
    "textembedding-gecko": "text-embedding-004",
}

_ALL_KNOWN_MODELS = set([m for models in _SUPPORTED_MODELS.values() for m in models] + list(_DEPRECATED_MODELS.keys()))


class VertexAIModelIDInput(BaseModel):
    model_id: str = Field(..., description="Vertex AI model ID to validate")
    task_type: str = Field(
        default="generation",
        description="The target task type: generation, embedding, vision, or routing",
    )


class VertexAIModelIDOutput(BaseModel):
    is_valid: bool = Field(..., description="True if the model is valid and not deprecated")
    model_family: str = Field(..., description="Detected family of the model")
    is_deprecated: bool = Field(..., description="True if the model is officially deprecated")
    recommended_alternative: str = Field(..., description="Recommended current alternative if deprecated")
    supported_tasks: List[str] = Field(default_factory=list, description="Tasks supported by this model")
    issues: List[str] = Field(default_factory=list, description="Validation issues identified")
    risk_score: float = Field(..., description="Calculated risk score")
    status: str = Field(..., description="Validation status: PASS, WARN, or FAIL")


class PiVertexAIModelIDValidator:
    """Validator agent for GCP Vertex AI Model IDs to detect deprecated or unsupported models."""

    def __init__(self) -> None:
        self.agent_name = "PiVertexAIModelIDValidator"

    def execute(self, input_envelope: VertexAIModelIDInput) -> VertexAIModelIDOutput:
        model_id = input_envelope.model_id
        task_type = input_envelope.task_type

        # Determine model family
        if model_id.startswith("gemini-2.5"):
            model_family = "gemini-2.5"
        elif model_id.startswith("gemini-2.0"):
            model_family = "gemini-2.0"
        elif model_id.startswith("gemini-1.5"):
            model_family = "gemini-1.5"
        elif model_id.startswith("gemini-1.0"):
            model_family = "gemini-1.0"
        elif model_id.startswith("text-embedding"):
            model_family = "text-embedding"
        elif model_id.startswith("text-multilingual-embedding") or model_id.startswith("textembedding-gecko"):
            model_family = "text-embedding"
        elif model_id.startswith("multimodalembedding") or "multimodal" in model_id:
            model_family = "multimodal"
        elif "bison" in model_id:
            model_family = "bison"
        else:
            model_family = "unknown"

        is_deprecated = model_id in _DEPRECATED_MODELS
        recommended_alternative = _DEPRECATED_MODELS.get(model_id, "")

        # Find supported tasks
        supported_tasks = []
        for task, models in _SUPPORTED_MODELS.items():
            if model_id in models:
                supported_tasks.append(task)

        issues = []
        risk_score = 0.0

        if model_id not in _ALL_KNOWN_MODELS:
            issues.append(f"Model ID '{model_id}' is unknown.")
            risk_score += 30.0
        elif is_deprecated:
            issues.append(f"Model ID '{model_id}' is deprecated. Recommended alternative: {recommended_alternative}")
            risk_score += 50.0

        valid_task_types = ["generation", "embedding", "vision", "routing"]
        if task_type not in valid_task_types:
            issues.append(f"Invalid task type '{task_type}'.")
            risk_score += 25.0
        elif model_id in _ALL_KNOWN_MODELS and model_id not in _SUPPORTED_MODELS.get(task_type, []):
            issues.append(f"Model ID '{model_id}' does not support task type '{task_type}'.")
            risk_score += 25.0

        risk_score = min(risk_score, 100.0)
        is_valid = (model_id in _ALL_KNOWN_MODELS) and (not is_deprecated)

        if not is_valid or risk_score > 60.0:
            status = "FAIL"
        elif risk_score >= 30.0:
            status = "WARN"
        else:
            status = "PASS"

        return VertexAIModelIDOutput(
            is_valid=is_valid,
            model_family=model_family,
            is_deprecated=is_deprecated,
            recommended_alternative=recommended_alternative,
            supported_tasks=supported_tasks,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
