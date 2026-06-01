from __future__ import annotations

import ast
import re
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_MAGIC_NUMBER_STRICT_MODE")


class MagicNumberInput(BaseModel):
    file_path: str = Field(..., description="Path of the code file being audited")
    code_content: str = Field(..., description="Source code content")


class MagicNumberOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no hardcoded magic numbers are found in computations")
    flagged: List[str] = Field(default_factory=list, description="List of magic numbers flagged")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiMagicNumberScanner:
    """Deterministic micro-agent that scans code files for hardcoded magic numbers (excluding 0, 1, 2) in expressions."""

    def __init__(self) -> None:
        self.agent_name = "PiMagicNumberScanner"

    def scan_magic_numbers(self, input_envelope: MagicNumberInput) -> MagicNumberOutput:
        file_path = input_envelope.file_path
        code = input_envelope.code_content
        flagged = []

        # List of acceptable/common numbers
        allowed_numbers = {0, 1, 2, 10, 100, 1000}

        if file_path.endswith(".py"):
            try:
                tree = ast.parse(code)

                class MagicNumVisitor(ast.NodeVisitor):
                    def visit_BinOp(self, node: ast.BinOp) -> None:
                        self.check_num_node(node.left, "binary operation")
                        self.check_num_node(node.right, "binary operation")
                        self.generic_visit(node)

                    def visit_Compare(self, node: ast.Compare) -> None:
                        self.check_num_node(node.left, "comparison")
                        for comparator in node.comparators:
                            self.check_num_node(comparator, "comparison")
                        self.generic_visit(node)

                    def check_num_node(self, node: ast.AST, context: str) -> None:
                        # In Python < 3.8, numbers are in ast.Num. In newer, they are ast.Constant.
                        val = None
                        if isinstance(node, ast.Constant):
                            val = node.value
                        elif isinstance(node, ast.Num):
                            val = node.n

                        if isinstance(val, (int, float)) and not isinstance(val, bool):
                            if val not in allowed_numbers:
                                flagged.append(str(val))

                visitor = MagicNumVisitor()
                visitor.visit(tree)

            except SyntaxError:
                pass

        # Fallback regex scanner if no python AST was run or found nothing
        if len(flagged) == 0:
            lines = code.splitlines()
            for _idx, line in enumerate(lines, start=1):
                # Look for expressions like ' * 86400', ' + 3600', ' / 123.45', ' == 99'
                # Excluding assignments like 'LIMIT = 5' which is standard definition
                if re.search(r"=\s*\d+", line) and not (line.strip().isupper() or "const" in line or "final" in line):
                    # Check if number is in line after an operator
                    match = re.search(r"[+\-*/%<>]=?\s*(\d+(?:\.\d+)?)", line)
                    if match:
                        val_str = match.group(1)
                        try:
                            val = float(val_str) if "." in val_str else int(val_str)
                            if val not in allowed_numbers:
                                flagged.append(val_str)
                        except ValueError:
                            pass

        is_secure = len(flagged) == 0
        risk_score = 55.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_MAGIC_NUMBER"
            else:
                status = "WARN_MAGIC_NUMBER"
                is_secure = True

        return MagicNumberOutput(is_secure=is_secure, flagged=flagged, risk_score=risk_score, status=status)
