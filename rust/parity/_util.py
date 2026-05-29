"""Shared helpers for the Rust<->Python parity harness."""
from __future__ import annotations

import importlib.util
import pathlib
import sys

# rust/parity/_util.py -> parents[2] == repo root
SRC = pathlib.Path(__file__).resolve().parents[2] / "src" / "pi_micro_agents"


def load_py_agent(filename: str):
    """Load an original micro-agent module *by file path*.

    This deliberately bypasses ``pi_micro_agents/__init__.py`` (a 66 KB module
    that eagerly imports every agent, including the 51 corrupted ones) so a
    single broken sibling can't take down the whole parity suite.

    The module is registered in ``sys.modules`` *before* execution so pydantic
    can resolve the string annotations produced by ``from __future__ import
    annotations`` (it looks up ``sys.modules[cls.__module__]`` to rebuild
    models with forward refs like ``List[str]``).
    """
    fp = SRC / filename
    mod_name = f"piagent_{fp.stem}"
    spec = importlib.util.spec_from_file_location(mod_name, fp)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load {fp}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod
