from __future__ import annotations

import ast
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_AST_DEPTH_STRICT_MODE")


class AstDepthInput(BaseModel):
    file_path: str = Field(..., description="Path of the code file being audited")
    code_content: str = Field(..., description="Source code content")
    max_depth: int = Field(4, description="Maximum allowed block nesting depth")


class AstDepthOutput(BaseModel):
    is_secure: bool = Field(..., description="True if nesting depth does not exceed threshold")
    complex_functions: List[str] = Field(
        default_factory=list, description="List of functions or blocks exceeding max depth"
    )
    max_depth_observed: int = Field(..., description="Deepest control flow nesting level observed in the code")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiAstDepthGuard:
    """Deterministic micro-agent that checks block nesting depth in code (AST nesting/indentation levels)."""

    def __init__(self) -> None:
        self.agent_name = "PiAstDepthGuard"

    def check_ast_depth(self, input_envelope: AstDepthInput) -> AstDepthOutput:
        file_path = input_envelope.file_path
        code = input_envelope.code_content
        max_allowed_depth = input_envelope.max_depth

        complex_functions = []
        max_depth_observed = 0

        # Try Python AST Parsing first if the file looks like python
        if file_path.endswith(".py"):
            try:
                tree = ast.parse(code)

                class DepthVisitor(ast.NodeVisitor):
                    def __init__(self) -> None:
                        self.current_depth = 0
                        self.max_depth_in_func = 0
                        self.current_func = None

                    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
                        old_func = self.current_func
                        old_max = self.max_depth_in_func
                        old_depth = self.current_depth

                        self.current_func = node.name
                        self.max_depth_in_func = 0
                        self.current_depth = 0

                        self.generic_visit(node)

                        nonlocal max_depth_observed
                        if self.max_depth_in_func > max_depth_observed:
                            max_depth_observed = self.max_depth_in_func

                        if self.max_depth_in_func > max_allowed_depth:
                            complex_functions.append(node.name)

                        self.current_func = old_func
                        self.max_depth_in_func = old_max
                        self.current_depth = old_depth

                    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                        self.visit_FunctionDef(node)

                    # Control flow statements increase depth
                    def visit_block_node(self, node: ast.AST) -> None:
                        self.current_depth += 1
                        if self.current_depth > self.max_depth_in_func:
                            self.max_depth_in_func = self.current_depth
                        self.generic_visit(node)
                        self.current_depth -= 1

                    def visit_If(self, node: ast.If) -> None:
                        self.visit_block_node(node)

                    def visit_For(self, node: ast.For) -> None:
                        self.visit_block_node(node)

                    def visit_While(self, node: ast.While) -> None:
                        self.visit_block_node(node)

                    def visit_Try(self, node: ast.Try) -> None:
                        self.visit_block_node(node)

                    def visit_With(self, node: ast.With) -> None:
                        self.visit_block_node(node)

                visitor = DepthVisitor()
                visitor.visit(tree)

            except SyntaxError:
                # Fallback to indentation analysis
                pass

        # If it's not python or AST parsing failed/did not run, do indentation analysis fallback
        if max_depth_observed == 0:
            # Count indentation depth
            # Every 4 spaces or 1 tab counts as 1 nesting level
            lines = code.splitlines()
            current_func = "global"
            max_depth_in_func = 0

            for _idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue

                # Check function definitions
                if (
                    line.lstrip().startswith("def ")
                    or line.lstrip().startswith("function ")
                    or line.lstrip().startswith("async ")
                ):
                    if max_depth_in_func > max_allowed_depth:
                        complex_functions.append(current_func)
                    # Reset for new block
                    current_func = stripped.split("(")[0]
                    max_depth_in_func = 0

                # Compute indentation
                leading_spaces = len(line) - len(line.lstrip())
                # Assume 4 spaces = 1 level
                indent_level = leading_spaces // 4
                if indent_level > max_depth_in_func:
                    max_depth_in_func = indent_level
                if indent_level > max_depth_observed:
                    max_depth_observed = indent_level

            # Check final function
            if max_depth_in_func > max_allowed_depth:
                complex_functions.append(current_func)

        is_secure = len(complex_functions) == 0
        risk_score = 65.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_AST_DEPTH"
            else:
                status = "WARN_AST_DEPTH"
                is_secure = True

        return AstDepthOutput(
            is_secure=is_secure,
            complex_functions=complex_functions,
            max_depth_observed=max_depth_observed,
            risk_score=risk_score,
            status=status,
        )
