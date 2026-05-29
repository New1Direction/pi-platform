"""Parity spec for PiVertexAIModelIDValidator.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiVertexAIModelIDValidator"

_mod = load_py_agent("pi_vertex_ai_model_id_validator.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiVertexAIModelIDValidator()
    out = agent.execute(_mod.VertexAIModelIDInput(**data))
    return out.model_dump()


SAMPLES = [
    # Clean, supported model for the default task -> PASS
    {"input": {"model_id": "gemini-2.0-flash", "task_type": "generation"}},
    # Supported model, task_type defaulted (omitted) -> exercises default
    {"input": {"model_id": "gemini-2.5-pro"}},
    # Deprecated model -> +50, also unsupported for task -> +25 => FAIL
    {"input": {"model_id": "text-bison", "task_type": "generation"}},
    # Deprecated embedding model, correct task type
    {"input": {"model_id": "textembedding-gecko", "task_type": "embedding"}},
    # Unknown model -> +30, is_valid False => FAIL, family unknown
    {"input": {"model_id": "gemini-9.9-omega", "task_type": "generation"}},
    # Known model but invalid task type -> +25, still valid => PASS
    {"input": {"model_id": "gemini-2.5-pro", "task_type": "classification"}},
    # Known model that does not support the requested (valid) task type -> +25 WARN
    {"input": {"model_id": "text-embedding-004", "task_type": "generation"}},
    # Embedding model supported for its task -> PASS, multiple-family detection
    {"input": {"model_id": "multimodalembedding@001", "task_type": "embedding"}},
    # Vision-supported model on vision task -> PASS
    {"input": {"model_id": "gemini-1.5-pro", "task_type": "vision"}},
    # Edge: empty model_id -> unknown family, unknown model
    {"input": {"model_id": "", "task_type": "generation"}},
]
