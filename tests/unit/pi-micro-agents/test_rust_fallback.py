"""The Rust acceleration must fail SAFE to the Python agent for ANY failure.

Critical finding: a Rust panic crosses the PyO3 boundary as
``pyo3_runtime.PanicException`` — a ``BaseException`` subclass, NOT ``Exception``
— so the orchestrator's ``except Exception`` guard could not catch it, aborting
the request instead of falling back. (The Rust side is also fixed to convert
panics to ``Err``; this pins the Python-side defence-in-depth for an unpatched
cdylib.)
"""

from __future__ import annotations

from pi_micro_agents.orchestrator import consensus


class _FakePanicException(BaseException):
    """Mimics pyo3_runtime.PanicException (subclasses BaseException, not Exception)."""


class _FakeCore:
    def list_agents(self):
        return ["FakeAgent"]

    def run_agent(self, name, payload):
        raise _FakePanicException("rust agent panicked: index out of bounds")


class _Perturbed:
    def model_dump_json(self):
        return "{}"


def test_try_rust_agent_falls_back_on_panic_like_baseexception(monkeypatch):
    monkeypatch.setattr(consensus, "_rust_enabled", lambda: True)
    monkeypatch.setattr(consensus, "_rust_agent_names", lambda: frozenset({"FakeAgent"}))
    monkeypatch.setattr(consensus, "_rust_core", lambda: _FakeCore())

    # Must return None (=> caller falls back to the Python agent), NOT propagate.
    result = consensus._try_rust_agent("FakeAgent", object, _Perturbed())
    assert result is None


def test_try_rust_agent_still_falls_back_on_ordinary_exception(monkeypatch):
    class _BadCore(_FakeCore):
        def run_agent(self, name, payload):
            raise ValueError("bad serialization")

    monkeypatch.setattr(consensus, "_rust_enabled", lambda: True)
    monkeypatch.setattr(consensus, "_rust_agent_names", lambda: frozenset({"FakeAgent"}))
    monkeypatch.setattr(consensus, "_rust_core", lambda: _BadCore())
    assert consensus._try_rust_agent("FakeAgent", object, _Perturbed()) is None


def test_try_rust_agent_does_not_swallow_keyboard_interrupt(monkeypatch):
    class _InterruptCore(_FakeCore):
        def run_agent(self, name, payload):
            raise KeyboardInterrupt()

    monkeypatch.setattr(consensus, "_rust_enabled", lambda: True)
    monkeypatch.setattr(consensus, "_rust_agent_names", lambda: frozenset({"FakeAgent"}))
    monkeypatch.setattr(consensus, "_rust_core", lambda: _InterruptCore())

    # KeyboardInterrupt / SystemExit must still propagate — never swallowed.
    import pytest

    with pytest.raises(KeyboardInterrupt):
        consensus._try_rust_agent("FakeAgent", object, _Perturbed())
