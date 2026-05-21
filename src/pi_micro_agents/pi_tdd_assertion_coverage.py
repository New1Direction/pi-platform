from __future__ import annotations
import os
import re
from typing import List
from pydantic import BaseModel, Field

def is_strict_mode() -> bool:
    env_val = os.getenv("PI_TDD_ASSERT_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"
    return True

class TddAssertionInput(BaseModel):
    test_code_content: str = Field(..., description="Test suite source code")

class TddAssertionOutput(BaseModel):
    is_secure: bool = Field(..., description="True if assertions are present in all tests")
    empty_tests: List[str] = Field(default_factory=list, description="Test methods missing asserts")
    status: str = Field(..., description="Status (PASSED, REJECTED_TDD_ASSERT, WARN_TDD_ASSERT)")

class PiTddAssertionCoverage:
    """Deterministic micro-agent that parses test code to check for active assertions."""

    def __init__(self) -> None:
        self.agent_name = "PiTddAssertionCoverage"

    def check_assertion_coverage(self, input_envelope: TddAssertionInput) -> TddAssertionOutput:
        code = input_envelope.test_code_content
        empty_tests = []
        
        # Simple static parser for test methods in Python
        methods = re.findall(r"def\s+(test_[a-zA-Z0-9_]+)\s*\([^)]*\)\s*:", code)
        
        # Split code by def test_
        blocks = re.split(r"def\s+test_[a-zA-Z0-9_]+\s*\([^)]*\)\s*:", code)
        
        # The first block is imports, subsequent blocks are the bodies of the test methods
        if len(blocks) > 1 and len(methods) == len(blocks) - 1:
            for idx, method_name in enumerate(methods):
                body = blocks[idx + 1]
                # Check next method definition to isolate the body (if multiple methods)
                # Just checks if body has any assert keyword
                if "assert" not in body and "self.assert" not in body and "expect(" not in body:
                    empty_tests.append(method_name)
                    
        is_secure = len(empty_tests) == 0
        
        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_TDD_ASSERT"
            else:
                status = "WARN_TDD_ASSERT"
                is_secure = True
                
        return TddAssertionOutput(
            is_secure=is_secure,
            empty_tests=empty_tests,
            status=status
        )
