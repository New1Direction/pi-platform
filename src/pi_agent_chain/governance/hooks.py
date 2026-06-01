"""Governance Hook System.

Production hook event bus integrated into the PI Platform governance layer.

All payloads are frozen for immutability. Hooks execute in registration order.
The first ``block`` result short-circuits emission. ``once`` hooks auto-remove
after execution.  The registry is thread-safe.

When an :class:`EventBus` is provided to :meth:`HookRegistry.emit`, every
emission is also written to the PI event fabric for cryptographic audit trail.

Deterministic. Fail-closed. Append-only.
"""

from __future__ import annotations

import abc
import fnmatch
import json
import os
import re
import shlex
import subprocess
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Sequence, Tuple

from pi_event_fabric.bus.core import EventType as BusEventType

# ──────────────────────────────────────────────────────────────────────
#  Hook Event Types
# ──────────────────────────────────────────────────────────────────────


class HookEventType(str, Enum):
    """All hookable lifecycle events in the PI Platform."""

    PRE_TOOL_USE = "pre_tool_use"
    POST_TOOL_USE = "post_tool_use"
    USER_PROMPT_SUBMIT = "user_prompt_submit"
    SUBAGENT_STOP = "subagent_stop"
    NOTIFICATION = "notification"
    STOP = "stop"
    PRE_COMPACT = "pre_compact"
    ASYNC_REWAKE = "async_rewake"


# ──────────────────────────────────────────────────────────────────────
#  Frozen Payloads
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PreToolUsePayload:
    """Fired just before a tool is executed.

    Attributes:
        tool_name: Canonical tool name, e.g. ``Bash``, ``Write``, ``Read``.
        tool_input: The arguments the tool will receive.
        session_id: Opaque session identifier.
        correlation_id: Used to trace paired Pre/Post events.
    """

    tool_name: str
    tool_input: Dict[str, Any]
    session_id: str = ""
    correlation_id: str = ""


@dataclass(frozen=True)
class PostToolUsePayload:
    """Fired after a tool has executed.

    Attributes:
        tool_name: Canonical tool name.
        tool_input: The arguments the tool received.
        tool_output: Return value or error from the tool.
        exit_code: For shell tools: process exit code.
        duration_ms: Wall-clock execution time.
        session_id: Opaque session identifier.
        correlation_id: Used to trace paired Pre/Post events.
    """

    tool_name: str
    tool_input: Dict[str, Any]
    tool_output: Any = None
    exit_code: Optional[int] = None
    duration_ms: float = 0.0
    session_id: str = ""
    correlation_id: str = ""


@dataclass(frozen=True)
class UserPromptSubmitPayload:
    """Fired when the user submits a new prompt.

    Attributes:
        prompt_text: Raw user input.
        session_id: Opaque session identifier.
    """

    prompt_text: str
    session_id: str = ""


@dataclass(frozen=True)
class SubagentStopPayload:
    """Fired when a child agent finishes its work.

    Attributes:
        agent_id: Identifier of the sub-agent.
        result_summary: Human-readable summary of the result.
        exit_status: ``completed``, ``failed``, or ``cancelled``.
        session_id: Opaque session identifier.
    """

    agent_id: str
    result_summary: str = ""
    exit_status: str = "completed"
    session_id: str = ""


@dataclass(frozen=True)
class NotificationPayload:
    """Fired on any internal notification (e.g. permission request).

    Attributes:
        message: Notification text.
        severity: ``info``, ``warning``, or ``error``.
        metadata: Arbitrary structured metadata.
    """

    message: str
    severity: str = "info"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StopPayload:
    """Fired when the main agent loop is about to exit.

    Attributes:
        reason: Why the loop is stopping (user interrupt, max turns, etc.).
        session_id: Opaque session identifier.
    """

    reason: str = ""
    session_id: str = ""


@dataclass(frozen=True)
class PreCompactPayload:
    """Fired before conversation history is compacted/summarised.

    Attributes:
        message_count: Number of messages about to be compacted.
        session_id: Opaque session identifier.
    """

    message_count: int = 0
    session_id: str = ""


@dataclass(frozen=True)
class AsyncRewakePayload:
    """Fired when a previously suspended async task resumes.

    Attributes:
        task_id: Identifier of the resuming task.
        resume_reason: Why the task is being resumed.
        session_id: Opaque session identifier.
    """

    task_id: str
    resume_reason: str = ""
    session_id: str = ""


# ── Lookup table: event type -> payload class ─────────────────────────

PAYLOAD_TYPE_MAP: Dict[HookEventType, type] = {
    HookEventType.PRE_TOOL_USE: PreToolUsePayload,
    HookEventType.POST_TOOL_USE: PostToolUsePayload,
    HookEventType.USER_PROMPT_SUBMIT: UserPromptSubmitPayload,
    HookEventType.SUBAGENT_STOP: SubagentStopPayload,
    HookEventType.NOTIFICATION: NotificationPayload,
    HookEventType.STOP: StopPayload,
    HookEventType.PRE_COMPACT: PreCompactPayload,
    HookEventType.ASYNC_REWAKE: AsyncRewakePayload,
}


# ──────────────────────────────────────────────────────────────────────
#  HookResult
# ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HookResult:
    """Aggregated result of running all hooks for one event emission.

    Attributes:
        behavior: ``allow``, ``block``, or ``modify``.
        reason: Human-readable explanation (from the winning hook).
        output: Raw output from the last hook that executed.
    """

    behavior: str = "allow"
    reason: str = ""
    output: Any = None


# ──────────────────────────────────────────────────────────────────────
#  Base Hook
# ──────────────────────────────────────────────────────────────────────


@dataclass
class BaseHook(abc.ABC):
    """Abstract base for all hook types.

    Attributes:
        type: Discriminator tag, e.g. ``"bash"``.
        if_filter: fnmatch-style pattern applied to the tool signature.
            Example: ``"Bash(git *)"`` matches any Bash tool call whose
            first argument starts with ``git``.
        timeout: Max seconds before the hook is killed.
        status_message: Human-readable description shown in the UI.
        once: If ``True`` the hook auto-removes after its first
            successful execution.
    """

    type: str
    if_filter: Optional[str] = None
    timeout: float = 30.0
    status_message: str = ""
    once: bool = False

    @abc.abstractmethod
    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Run the hook.

        Args:
            context: Arbitrary event context (tool name, input, etc.).

        Returns:
            A dict with at least ``{"stdout": str, "stderr": str,
            "exit_code": int}``.  Additional keys are allowed.
        """


# ──────────────────────────────────────────────────────────────────────
#  Interpolation helper (shared across hook types)
# ──────────────────────────────────────────────────────────────────────


def _interpolate(template: str, context: Dict[str, Any], *, quote_values: bool = False) -> str:
    """Safe ``{key}`` interpolation from context — missing keys become empty string.

    Supports dotted paths: ``{tool_input.command}`` resolves
    ``context["tool_input"]["command"]``.

    When ``quote_values`` is True, each substituted value is ``shlex.quote``-d so
    it is safe to embed in a shell command string — interpolated (potentially
    attacker-controlled) values become a single literal argument and cannot inject
    extra commands. The template's own literal text is left untouched.
    """

    def _repl(match: re.Match[str]) -> str:
        key_path = match.group(1)
        obj: Any = context
        for part in key_path.split("."):
            if isinstance(obj, dict):
                obj = obj.get(part, "")
            else:
                obj = getattr(obj, part, "")
        value = str(obj)
        return shlex.quote(value) if quote_values else value

    return re.sub(r"\{([^}]+)\}", _repl, template)


def _env_interp(value: str) -> str:
    """Replace ``${VAR}`` with the value of ``os.environ["VAR"]``."""

    def _repl(match: re.Match[str]) -> str:
        return os.environ.get(match.group(1), "")

    return re.sub(r"\$\{(\w+)\}", _repl, value)


# ──────────────────────────────────────────────────────────────────────
#  Concrete Hook Types
# ──────────────────────────────────────────────────────────────────────


@dataclass
class BashCommandHook(BaseHook):
    """Runs a shell command and captures its output.

    The ``command`` string supports ``{variable}`` interpolation from
    ``context``.

    Example::

        BashCommandHook(
            command="echo {tool_input[message]}",
            if_filter="Bash(git commit *)",
        )
    """

    type: str = field(default="bash", init=False)
    command: str = ""
    working_dir: Optional[str] = None
    env_overrides: Dict[str, str] = field(default_factory=dict)

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute ``self.command`` via subprocess.

        Interpolated context values are shell-escaped (``quote_values=True``) so a
        value carrying shell metacharacters (``;``, ``|``, ``$(...)``, backticks)
        is treated as a single literal argument and cannot inject commands.
        """
        cmd = _interpolate(self.command, context, quote_values=True)
        env = {**os.environ, **self.env_overrides}
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                cwd=self.working_dir,
                env=env,
            )
            return {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "exit_code": proc.returncode,
            }
        except subprocess.TimeoutExpired:
            return {
                "stdout": "",
                "stderr": f"Hook timed out after {self.timeout}s",
                "exit_code": -1,
            }


@dataclass
class HttpHook(BaseHook):
    """POSTs JSON to a URL, with ``${ENV_VAR}`` interpolation in headers.

    Headers may contain ``${VAR}`` references that are resolved from
    the process environment at call time.  Uses ``urllib`` from the
    standard library (no external dependency required).

    Attributes:
        url: Target URL (supports ``{variable}`` interpolation from context).
        headers: HTTP headers (values support ``${ENV_VAR}`` interpolation).
        body_template: JSON string with ``{variable}`` interpolation from context.
    """

    type: str = field(default="http", init=False)
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body_template: str = "{}"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """POST JSON to ``self.url`` with env-var header interpolation."""
        import urllib.error
        import urllib.request

        url = _interpolate(self.url, context)
        headers = {k: _env_interp(v) for k, v in self.headers.items()}
        body_raw = _interpolate(self.body_template, context)

        try:
            req = urllib.request.Request(
                url,
                data=body_raw.encode("utf-8"),
                headers={**headers, "Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                resp_body = resp.read().decode()
                return {
                    "stdout": resp_body,
                    "stderr": "",
                    "exit_code": 0,
                    "http_status": resp.status,
                }
        except Exception as exc:
            return {
                "stdout": "",
                "stderr": str(exc),
                "exit_code": 1,
            }


@dataclass
class AgentHook(BaseHook):
    """Spawns a verifier sub-agent (stubbed).

    In production this would create a lightweight agent session with
    its own context window and return the agent's verdict.

    Attributes:
        agent_prompt: Prompt template with ``{variable}`` interpolation.
    """

    type: str = field(default="agent", init=False)
    agent_prompt: str = ""

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Return an allow decision (stub)."""
        prompt = _interpolate(self.agent_prompt, context)
        return {
            "stdout": json.dumps({"decision": "allow", "reason": "agent-stub"}),
            "stderr": "",
            "exit_code": 0,
            "agent_prompt_used": prompt,
        }


@dataclass
class PromptHook(BaseHook):
    """Evaluates an LLM prompt (stubbed — returns a mock response).

    In a production system this would call the LLM and parse the
    structured response into an allow/block decision.

    Attributes:
        prompt_template: Template with ``{variable}`` interpolation from context.
    """

    type: str = field(default="prompt", init=False)
    prompt_template: str = ""

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Return an allow decision (stub)."""
        prompt = _interpolate(self.prompt_template, context)
        return {
            "stdout": json.dumps({"decision": "allow", "reason": "stub"}),
            "stderr": "",
            "exit_code": 0,
            "prompt_used": prompt,
        }


@dataclass
class McpToolHook(BaseHook):
    """Calls an MCP server tool with input interpolation.

    Attributes:
        server_name: Name of the MCP server to route to.
        tool_name: Tool on that server to invoke.
        input_template: JSON string with ``{variable}`` interpolation.
    """

    type: str = field(default="mcp_tool", init=False)
    server_name: str = ""
    tool_name: str = ""
    input_template: str = "{}"

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Resolve input template and invoke MCP tool (stub)."""
        raw = _interpolate(self.input_template, context)
        try:
            parsed_input = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            return {
                "stdout": "",
                "stderr": f"Invalid JSON in input_template: {raw!r}",
                "exit_code": 1,
            }

        # In production we'd call the MCP client here.
        return {
            "stdout": json.dumps(
                {
                    "server": self.server_name,
                    "tool": self.tool_name,
                    "input": parsed_input,
                    "result": "mcp-stub",
                }
            ),
            "stderr": "",
            "exit_code": 0,
        }


# ──────────────────────────────────────────────────────────────────────
#  Registry Entry (internal)
# ──────────────────────────────────────────────────────────────────────


@dataclass
class _HookEntry:
    """Internal bookkeeping for one registration."""

    event_type: HookEventType
    matcher: Optional[str]
    """fnmatch pattern applied to ``f"{tool_name}({tool_input_summary})"``."""
    hooks: List[BaseHook] = field(default_factory=list)


# ──────────────────────────────────────────────────────────────────────
#  Helpers
# ──────────────────────────────────────────────────────────────────────


def _build_signature(tool_name: str, tool_input: Optional[Dict[str, Any]]) -> str:
    """Build the string matched against ``matcher`` patterns.

    Format: ``ToolName(first_arg_value ...)`` — the values come from
    the tool input dict, joined by spaces.
    """
    if not tool_input:
        return f"{tool_name}()"
    parts = " ".join(str(v) for v in tool_input.values())
    return f"{tool_name}({parts})"


def _matches(signature: str, pattern: Optional[str]) -> bool:
    """Return True if *signature* matches *pattern* (fnmatch)."""
    if pattern is None:
        return True
    return fnmatch.fnmatch(signature, pattern)


# ──────────────────────────────────────────────────────────────────────
#  HookRegistry — the deterministic event bus
# ──────────────────────────────────────────────────────────────────────


class HookRegistry:
    """Central hook registry integrated into the PI Platform governance layer.

    Thread-safe. Hooks execute in registration order. The first ``block``
    result short-circuits emission. ``once`` hooks auto-remove after execution.

    When an :class:`~pi_event_fabric.bus.core.EventBus` is provided to
    :meth:`emit`, every emission is also logged to the PI event fabric for
    cryptographic audit trail.

    Usage::

        registry = HookRegistry()
        registry.register(
            HookEventType.PRE_TOOL_USE,
            matcher="Bash(rm *)",
            hooks=[BashCommandHook(command="echo 'blocked'")],
        )

        result = registry.emit(HookEventType.PRE_TOOL_USE, payload)
    """

    def __init__(self) -> None:
        self._entries: List[_HookEntry] = []
        self._lock = threading.Lock()

    # ── Registration ────────────────────────────────────────────────

    def register(
        self,
        event_type: HookEventType,
        matcher: Optional[str],
        hooks: Sequence[BaseHook],
    ) -> None:
        """Register *hooks* for *event_type*, optionally filtered by *matcher*.

        Args:
            event_type: Which lifecycle event to listen on.
            matcher: fnmatch pattern like ``"Bash(git *)"`` or ``None``
                to match all emissions.
            hooks: Hook instances to run in order when matched.
        """
        entry = _HookEntry(
            event_type=event_type,
            matcher=matcher,
            hooks=list(hooks),
        )
        with self._lock:
            self._entries.append(entry)

    # ── Emission ────────────────────────────────────────────────────

    def emit(
        self,
        event_type: HookEventType,
        payload: Any,
        event_bus: Optional[Any] = None,
    ) -> HookResult:
        """Fire *event_type* with *payload* and return the aggregated result.

        Hooks execute in registration order.  The first ``block`` result
        short-circuits.  ``once`` hooks are removed after execution.

        If *event_bus* is provided (an
        :class:`~pi_event_fabric.bus.core.EventBusStorage` instance),
        the emission is also recorded in the PI event fabric's governance
        partition for cryptographic audit trail.

        Args:
            event_type: The event being fired.
            payload: Typed payload dataclass (see payload classes above).
            event_bus: Optional PI EventBus storage for audit logging.

        Returns:
            :class:`HookResult` summarising the combined decisions.
        """
        with self._lock:
            return self._emit_locked(event_type, payload, event_bus)

    def _emit_locked(
        self,
        event_type: HookEventType,
        payload: Any,
        event_bus: Optional[Any] = None,
    ) -> HookResult:
        """Internal emission under lock."""
        tool_name = getattr(payload, "tool_name", "")
        tool_input = getattr(payload, "tool_input", None)
        signature = _build_signature(tool_name, tool_input) if tool_name else ""

        combined_behavior = "allow"
        reason = ""
        output: Any = None
        hooks_to_remove: List[Tuple[int, int]] = []  # (entry_idx, hook_idx)

        for entry_idx, entry in enumerate(self._entries):
            if entry.event_type != event_type:
                continue
            if not _matches(signature, entry.matcher):
                continue

            for hook_idx, hook in enumerate(entry.hooks):
                ctx: Dict[str, Any] = {
                    "tool_name": tool_name,
                    "tool_input": tool_input,
                    "signature": signature,
                    "payload": payload,
                }
                try:
                    hook_output = hook.execute(ctx)
                except Exception as exc:
                    hook_output = {"stdout": "", "stderr": str(exc), "exit_code": -1}

                exit_code = hook_output.get("exit_code", 0)
                stdout = hook_output.get("stdout", "")

                # Non-zero exit code => block (fail-closed)
                if exit_code != 0:
                    combined_behavior = "block"
                    reason = hook_output.get("stderr", "") or f"exit_code={exit_code}"
                    result = HookResult(behavior="block", reason=reason, output=hook_output)
                    self._maybe_audit(event_type, payload, result, event_bus)
                    return result

                # Check structured response for modify / block decisions
                if stdout:
                    try:
                        parsed = json.loads(stdout)
                        decision = parsed.get("decision", "allow")
                        if decision == "block":
                            combined_behavior = "block"
                            reason = parsed.get("reason", "hook blocked")
                            result = HookResult(behavior="block", reason=reason, output=hook_output)
                            self._maybe_audit(event_type, payload, result, event_bus)
                            return result
                        if decision == "modify":
                            combined_behavior = "modify"
                            reason = parsed.get("reason", "")
                            output = hook_output
                    except (json.JSONDecodeError, TypeError):
                        pass

                output = hook_output

                if hook.once:
                    hooks_to_remove.append((entry_idx, hook_idx))

        # Clean up once hooks (reverse order to keep indices valid)
        for ei, hi in sorted(hooks_to_remove, reverse=True):
            try:
                self._entries[ei].hooks.pop(hi)
            except IndexError:
                pass
        # Remove empty entries
        self._entries = [e for e in self._entries if e.hooks]

        result = HookResult(behavior=combined_behavior, reason=reason, output=output)
        self._maybe_audit(event_type, payload, result, event_bus)
        return result

    def _maybe_audit(
        self,
        event_type: HookEventType,
        payload: Any,
        result: HookResult,
        event_bus: Optional[Any] = None,
    ) -> None:
        """Log emission to the PI EventBus for audit trail.

        Maps hook event types to governance partition events in the
        PI event fabric.  This is best-effort — failures are swallowed
        to avoid disrupting hook evaluation.
        """
        if event_bus is None:
            return
        try:
            payload_dict = {
                "hook_event_type": event_type.value,
                "behavior": result.behavior,
                "reason": result.reason,
                "payload_type": type(payload).__name__,
                "payload_repr": repr(payload)[:2048],
            }
            event_bus.append(
                event_type=BusEventType.GOVERNANCE_RULE_APPLIED,
                partition_key="governance",
                payload=payload_dict,
                tenant_id="system",
                actor_id="hook_registry",
                correlation_id=f"hook_{event_type.value}",
            )
        except Exception:
            # Audit logging must never disrupt hook evaluation.
            pass

    # ── Introspection ───────────────────────────────────────────────

    @property
    def entry_count(self) -> int:
        """Number of registered entry groups."""
        with self._lock:
            return len(self._entries)

    @property
    def total_hook_count(self) -> int:
        """Total number of individual hooks across all entries."""
        with self._lock:
            return sum(len(e.hooks) for e in self._entries)

    def clear(self) -> None:
        """Remove all registrations."""
        with self._lock:
            self._entries.clear()
