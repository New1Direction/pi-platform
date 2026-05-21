"""Deterministic violation models for diff runtime."""

from __future__ import annotations

from typing import Any, Dict, List


class DiffViolation:
    """Evidence-bound violation record from diff runtime."""

    def __init__(
        self,
        pass_name: str,
        rule: str,
        severity: str,
        context: Dict[str, Any],
    ) -> None:
        self.pass_name = pass_name
        self.rule = rule
        self.severity = severity
        self.context = context

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pass_name": self.pass_name,
            "rule": self.rule,
            "severity": self.severity,
            "context": self.context,
        }


class DiffViolationBuilder:
    """Deterministic builder for diff violations."""

    def __init__(self, pass_name: str) -> None:
        self.pass_name = pass_name

    def build(
        self,
        rule: str,
        severity: str,
        context: Dict[str, Any],
    ) -> DiffViolation:
        return DiffViolation(
            pass_name=self.pass_name,
            rule=rule,
            severity=severity,
            context=context,
        )

    def critical(
        self,
        rule: str,
        endpoint: str = "",
        field_path: str = "",
        provenance: List[str] | None = None,
        extra: Dict[str, Any] | None = None,
    ) -> DiffViolation:
        ctx: Dict[str, Any] = {
            "endpoint": endpoint,
            "field_path": field_path,
            "provenance_chain": provenance or [],
        }
        if extra:
            ctx.update(extra)
        return self.build(rule=rule, severity="CRITICAL", context=ctx)

    def error(
        self,
        rule: str,
        endpoint: str = "",
        field_path: str = "",
        provenance: List[str] | None = None,
        extra: Dict[str, Any] | None = None,
    ) -> DiffViolation:
        ctx: Dict[str, Any] = {
            "endpoint": endpoint,
            "field_path": field_path,
            "provenance_chain": provenance or [],
        }
        if extra:
            ctx.update(extra)
        return self.build(rule=rule, severity="ERROR", context=ctx)

    def warning(
        self,
        rule: str,
        endpoint: str = "",
        field_path: str = "",
        provenance: List[str] | None = None,
        extra: Dict[str, Any] | None = None,
    ) -> DiffViolation:
        ctx: Dict[str, Any] = {
            "endpoint": endpoint,
            "field_path": field_path,
            "provenance_chain": provenance or [],
        }
        if extra:
            ctx.update(extra)
        return self.build(rule=rule, severity="WARNING", context=ctx)
