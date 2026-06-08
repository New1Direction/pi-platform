"""
dynamic_trace.py - Frida DynamicTraceStage (Theme 1, P1).

Two halves:

* ``capture()`` - LIVE. Attaches (or spawns) a process with Frida, loads an
  instrumentation script, and collects the messages it sends back into a
  normalized "capture" dict. Needs the ``frida`` package and a running target;
  raises a clear StageError otherwise.
* ``ingest()`` - DETERMINISTIC. Turns a saved capture dict into content-addressed
  ``DynamicTrace`` nodes (one per hook, findings deduped) plus a target entity
  node and ``observed-in`` edges. This is the half tests + replay rely on.

Modeled on KikkaSkills/analysis/frida/frida-toolkit.py (FridaManager: enumerate
/ attach / spawn / on_message), but reshaped so the analysis output is a
reproducible graph rather than console logs.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from ..artifacts import ArtifactStore
from ..graph_schema import DynamicTrace, EdgeMetadata, GraphEdge, GraphNode, NodeMetadata, content_hash
from .base import StageError, StageResult


def _import_frida():  # pragma: no cover - thin import shim (monkeypatched in tests)
    import frida

    return frida


def _finding_from_payload(payload: Dict[str, Any]) -> str:
    """Extract the salient string from a hook message payload."""
    for key in ("selector", "string", "preview", "symbol", "endpoint", "data"):
        if payload.get(key):
            return str(payload[key])
    rest = {k: v for k, v in payload.items() if k != "hook"}
    return json.dumps(rest, sort_keys=True) if rest else "(empty)"


class DynamicTraceStage:
    name = "dynamic-trace"

    def __init__(self, store: Optional[ArtifactStore] = None):
        self.store = store

    # ---- deterministic ingest ------------------------------------------

    def ingest(self, capture: Dict[str, Any]) -> StageResult:
        target = capture.get("target", "unknown-target")
        pid = capture.get("pid")
        captured_at = capture.get("captured_at")
        messages = capture.get("messages", [])

        by_hook: Dict[str, List[str]] = {}
        errors = 0
        for msg in messages:
            mtype = msg.get("type")
            if mtype == "error":
                errors += 1
                continue
            payload = msg.get("payload")
            if not isinstance(payload, dict):
                continue
            hook = str(payload.get("hook", "unknown"))
            by_hook.setdefault(hook, []).append(_finding_from_payload(payload))

        entity_id = f"entity/{content_hash({'target': target})}"
        entity = GraphNode(
            id=entity_id,
            type="entity",
            title=target,
            content=f"Live-instrumented target: {target}",
            metadata=NodeMetadata(source_page="(dynamic-capture)", tags=["target", "dynamic-trace"]),
        )

        nodes: List[GraphNode] = [entity]
        edges: List[GraphEdge] = []
        for hook in sorted(by_hook):
            trace = DynamicTrace(
                target=target,
                hook=hook,
                findings=sorted(set(by_hook[hook])),
                pid=pid,
                captured_at=captured_at,
            )
            node = trace.to_graph_node()
            nodes.append(node)
            edges.append(
                GraphEdge(
                    source=node.id,
                    target=entity_id,
                    metadata=EdgeMetadata(relation_type="observed-in", created_by=self.name),
                )
            )

        return StageResult(
            stage=self.name,
            nodes=nodes,
            edges=edges,
            summary={
                "target": target,
                "hooks": len(by_hook),
                "messages": len(messages),
                "errors": errors,
            },
        )

    def ingest_file(self, path: Union[str, Path]) -> StageResult:
        with open(path, "r", encoding="utf-8") as f:
            return self.ingest(json.load(f))

    # ---- live capture --------------------------------------------------

    @staticmethod
    def frida_available() -> bool:
        try:
            _import_frida()
            return True
        except Exception:
            return False

    def capture(
        self,
        target: str,
        *,
        script_source: str,
        attach_pid: Optional[int] = None,
        spawn: Optional[List[str]] = None,
        device_id: Optional[str] = None,
        timeout: float = 10.0,
        phase: str = "dynamic",
    ) -> Dict[str, Any]:
        """Run a Frida script against a live target and return a capture dict.

        Either attach to a running process (``attach_pid`` or ``target`` name)
        or ``spawn`` a new one. Collected messages are normalized for ingest().
        """
        try:
            frida = _import_frida()
        except Exception as e:  # ImportError or frida load failure
            raise StageError(
                "frida is required for live dynamic tracing. "
                "Install it with `pip install frida frida-tools`. "
                f"(import failed: {e})"
            ) from e

        device = frida.get_device(device_id) if device_id else frida.get_local_device()
        messages: List[Dict[str, Any]] = []

        def _on_message(message: Dict[str, Any], data: Any) -> None:
            messages.append(message)

        spawned_pid: Optional[int] = None
        try:
            if spawn:
                spawned_pid = device.spawn(spawn)
                session = device.attach(spawned_pid)
            elif attach_pid is not None:
                session = device.attach(attach_pid)
            else:
                session = device.attach(target)
        except Exception as e:
            raise StageError(f"could not attach to '{target}': {e}") from e

        pid = spawned_pid if spawned_pid is not None else getattr(session, "pid", attach_pid)
        try:
            script = session.create_script(script_source)
            script.on("message", _on_message)
            script.load()
            if spawned_pid is not None:
                device.resume(spawned_pid)
            time.sleep(timeout)
        finally:
            try:
                session.detach()
            except Exception:
                pass

        capture = {
            "target": target,
            "pid": pid,
            "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "script": "inline",
            "messages": messages,
        }
        if self.store is not None:
            self.store.store_payload(phase, self.name, f"{target}-trace", capture, kind="trace")
        return capture
