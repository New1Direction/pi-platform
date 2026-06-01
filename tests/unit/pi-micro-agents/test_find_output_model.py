"""_find_output_model must not silently pick a model on an ambiguous field-set match.

Finding: the Rust-output reconstruction selects the agent module's pydantic model
whose field set equals the Rust JSON keys, returning the FIRST match in vars()
iteration order. If a module defines two models with identical field sets, the
choice is arbitrary (iteration-order dependent) and could reconstruct the wrong
type. It must instead refuse (raise) on ambiguity so the caller falls back to the
Python agent rather than risking a wrong reconstruction.
"""

from __future__ import annotations

import types

import pytest
from pydantic import BaseModel

from pi_micro_agents.orchestrator import consensus


def test_find_output_model_single_match(monkeypatch):
    class OutA(BaseModel):
        x: int
        y: int

    mod = types.ModuleType("fake_single_mod")
    mod.OutA = OutA
    monkeypatch.setitem(__import__("sys").modules, "fake_single_mod", mod)

    class A:
        __module__ = "fake_single_mod"

    assert consensus._find_output_model(A, {"x", "y"}) is OutA


def test_find_output_model_raises_on_ambiguous_field_set(monkeypatch):
    class OutA(BaseModel):
        x: int
        y: int

    class OutB(BaseModel):
        x: int
        y: int

    mod = types.ModuleType("fake_ambiguous_mod")
    mod.OutA = OutA
    mod.OutB = OutB
    monkeypatch.setitem(__import__("sys").modules, "fake_ambiguous_mod", mod)

    class A:
        __module__ = "fake_ambiguous_mod"

    with pytest.raises(Exception):
        consensus._find_output_model(A, {"x", "y"})
