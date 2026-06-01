from __future__ import annotations

import ast
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_ERROR_CATCH_STRICT_MODE")


class ErrorCatchInput(BaseModel):
    file_path: str = Field(..., description="Path of the code file being audited")
    code_content: str = Field(..., description="Source code content")


class ErrorCatchOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no try-except/catch blocks swallow errors silently")
    swallowed_error_blocks: List[str] = Field(default_factory=list, description="List of swallowed error blocks found")
    risk_score: float = Field(..., description="Risk score from 0.0 to 100.0")
    status: str = Field(..., description="Status of the audit")


class PiErrorHandlingCatchAllGuard:
    """Deterministic micro-agent that audits exception handling blocks to prevent silent error swallowing."""

    def __init__(self) -> None:
        self.agent_name = "PiErrorHandlingCatchAllGuard"

    def check_error_handling(self, input_envelope: ErrorCatchInput) -> ErrorCatchOutput:
        file_path = input_envelope.file_path
        code = input_envelope.code_content
        swallowed = []

        if file_path.endswith(".py"):
            try:
                tree = ast.parse(code)

                class CatchAllVisitor(ast.NodeVisitor):
                    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
                        # Check body of the except handler
                        is_swallowed = True

                        for body_node in ast.walk(node):
                            # If it raises an exception or re-raises, it's not swallowed
                            if isinstance(body_node, ast.Raise):
                                is_swallowed = False
                                break
                            # If it calls logger.exception, logger.error, logging.exception, self._halt, etc.
                            if isinstance(body_node, ast.Call):
                                call_repr = ""
                                if isinstance(body_node.func, ast.Attribute):
                                    call_repr = body_node.func.attr
                                elif isinstance(body_node.func, ast.Name):
                                    call_repr = body_node.func.id

                                if any(
                                    x in call_repr.lower()
                                    for x in ["exception", "error", "warn", "fail", "halt", "log"]
                                ):
                                    is_swallowed = False
                                    break

                        if is_swallowed:
                            # Verify if body is just pass or print
                            [type(n) for n in node.body]
                            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                                detail = "body is empty 'pass'"
                            else:
                                detail = "no active logging or raise statements found in block"

                            swallowed.append(f"Line {node.lineno}: Silent exception block found ({detail})")

                        self.generic_visit(node)

                visitor = CatchAllVisitor()
                visitor.visit(tree)

            except SyntaxError:
                pass

        # Fallback regex scanner for other code or when AST parsing failed
        if len(swallowed) == 0:
            lines = code.splitlines()
            except_block_started = False
            except_indent = 0
            except_line_idx = -1

            for idx, line in enumerate(lines, start=1):
                stripped = line.strip()
                if except_block_started:
                    current_indent = len(line) - len(line.lstrip())
                    if current_indent <= except_indent and stripped:
                        # Left the except block, check if we found any logging/raise
                        except_block_started = False
                    else:
                        # We are inside the except block. Check if it contains pass or is empty
                        if stripped == "pass" or stripped == "return" or stripped == "return None":
                            swallowed.append(
                                f"Line {except_line_idx}: Silent exception handling block detected via regex"
                            )
                            except_block_started = False

                # Detect the start of an except or catch block
                if (
                    stripped.startswith("except:")
                    or stripped.startswith("except ")
                    or stripped.startswith("catch ")
                    or stripped.startswith("catch(")
                ):
                    except_block_started = True
                    except_indent = len(line) - len(line.lstrip())
                    except_line_idx = idx

        is_secure = len(swallowed) == 0
        risk_score = 70.0 if not is_secure else 0.0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_ERROR_CATCH"
            else:
                status = "WARN_ERROR_CATCH"
                is_secure = True

        return ErrorCatchOutput(
            is_secure=is_secure, swallowed_error_blocks=swallowed, risk_score=risk_score, status=status
        )
