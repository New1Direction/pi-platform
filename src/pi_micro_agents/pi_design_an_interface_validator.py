from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_DESIGN_INTERFACE_STRICT_MODE")


class DesignAnInterfaceInput(BaseModel):
    interface_content: str = Field(..., description="Proposed class or interface definitions")


class DesignAnInterfaceOutput(BaseModel):
    is_secure: bool = Field(..., description="True if design complies with strict standards")
    validation_warnings: List[str] = Field(default_factory=list, description="Validation issues found")
    status: str = Field(..., description="Status (PASSED, REJECTED_DESIGN_INTERFACE, WARN_DESIGN_INTERFACE)")


class PiDesignAnInterfaceValidator:
    """Deterministic micro-agent that checks interfaces for missing type safety annotations."""

    def __init__(self) -> None:
        self.agent_name = "PiDesignAnInterfaceValidator"

    def validate_interface(self, input_envelope: DesignAnInterfaceInput) -> DesignAnInterfaceOutput:
        content = input_envelope.interface_content
        warnings = []

        # Check if Python or TS functions lack return types or parameter types
        lines = content.splitlines()
        for idx, line in enumerate(lines, 1):
            clean = line.strip()
            if clean.startswith("def ") and "->" not in clean:
                warnings.append(f"Line {idx}: Python function definition is missing return type hint.")
            if "interface " in clean or "class " in clean:
                # Check for docstrings or JSDoc
                if idx > 1 and "*/" not in lines[idx - 2] and '"""' not in lines[idx - 2]:
                    warnings.append(f"Line {idx}: Interface or class lacks descriptive documentation block.")

        is_secure = len(warnings) == 0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_DESIGN_INTERFACE"
            else:
                status = "WARN_DESIGN_INTERFACE"
                is_secure = True

        return DesignAnInterfaceOutput(is_secure=is_secure, validation_warnings=warnings, status=status)
