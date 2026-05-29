from __future__ import annotations

import os
from typing import List

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_TDD_FILE_STRICT_MODE")


class TddTestFileInput(BaseModel):
    modified_files: List[str] = Field(..., description="List of modified/added files in changeset")


class TddTestFileOutput(BaseModel):
    is_secure: bool = Field(..., description="True if TDD requirements are met")
    vulnerable_files: List[str] = Field(
        default_factory=list, description="Implementation files lacking matching test files"
    )
    status: str = Field(..., description="Status (PASSED, REJECTED_TDD_FILE, WARN_TDD_FILE)")


class PiTddTestFileVerifier:
    """Deterministic micro-agent that checks if changesets include both implementation and test files."""

    def __init__(self) -> None:
        self.agent_name = "PiTddTestFileVerifier"

    def verify_test_files(self, input_envelope: TddTestFileInput) -> TddTestFileOutput:
        files = input_envelope.modified_files
        missing_tests = []

        # Identify production code files (e.g. .py or .ts files that are not tests themselves)
        for f in files:
            # Skip test files, config files, metadata, or documentation
            if "test" in f.lower() or f.endswith(".md") or f.endswith(".json") or f.endswith(".yml") or "/" not in f:
                continue

            # Formulate expected test file name
            dir_name, base_name = os.path.split(f)
            expected_test_py = f"test_{base_name}"
            expected_test_ts = base_name.replace(".ts", ".test.ts").replace(".tsx", ".test.tsx")

            has_test = False
            for tf in files:
                if "test" in tf.lower() and (
                    expected_test_py in tf or expected_test_ts in tf or base_name.split(".")[0] in tf
                ):
                    has_test = True
                    break

            if not has_test:
                missing_tests.append(f)

        is_secure = len(missing_tests) == 0

        status = "PASSED"
        if not is_secure:
            if is_strict_mode():
                status = "REJECTED_TDD_FILE"
            else:
                status = "WARN_TDD_FILE"
                is_secure = True

        return TddTestFileOutput(is_secure=is_secure, vulnerable_files=missing_tests, status=status)
