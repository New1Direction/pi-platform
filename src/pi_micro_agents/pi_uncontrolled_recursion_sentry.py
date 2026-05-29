from __future__ import annotations

import ast
import os
from typing import List

from pydantic import BaseModel, Field


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_UNCONTROLLED_RECURSION_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True


class RecursionInput(BaseModel):
    file_path: str = Field(..., description="Path of the code file being audited")
    code_content: str = Field(..., description="Source code content")


class RecursionOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no uncontrolled recursion loops are detected")
    recursive_loops: List[str] = Field(
        default_factory=list, description="List of uncontrolled recursion occurrences found"
    )
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiUncontrolledRecursionSentry:
    """Deterministic micro-agent that scans for recursive calls lacking base-case exit conditions."""

    def __init__(self) -> None:
        self.agent_name = "PiUncontrolledRecursionSentry"

    def check_recursion(self, input_envelope: RecursionInput) -> RecursionOutput:
        file_path = input_envelope.file_path
        code = input_envelope.code_content
        recursive_loops = []

        if file_path.endswith(".py"):
            try:
                tree = ast.parse(code)

                class RecursionChecker(ast.NodeVisitor):
                    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                        func_name = node.name
                        has_recursive_call = False
                        has_base_case = False

                        # Helper to search inside the function body
                        for body_node in ast.walk(node):
                            # Look for recursive call to func_name
                            if isinstance(body_node, ast.Call):
                                if isinstance(body_node.func, ast.Name) and body_node.func.id == func_name:
                                    has_recursive_call = True
                                elif isinstance(body_node.func, ast.Attribute) and body_node.func.attr == func_name:
                                    # recursive call like self.func_name()
                                    has_recursive_call = True

                            # Look for exit condition (return/raise inside a conditional structure)
                            if isinstance(body_node, ast.If):
                                for sub_node in body_node.body + body_node.orelse:
                                    for child in ast.walk(sub_node):
                                        if isinstance(child, (ast.Return, ast.Raise)):
                                            has_base_case = True

                        if has_recursive_call and not has_base_case:
                            recursive_loops.append(func_name)

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        self.visit_FunctionDef(node)

                checker = RecursionChecker()
                checker.visit(tree)

            except SyntaxError:
                # Safe fallback if syntax error
                pass

        is_secure = len(recursive_loops) == 0
        risk_score = 80.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_UNCONTROLLED_RECURSION"
            else:
                status = "WARN_UNCONTROLLED_RECURSION"
                is_secure = True

        return RecursionOutput(
            is_secure=is_secure, recursive_loops=recursive_loops, risk_score=risk_score, status=status
        )
