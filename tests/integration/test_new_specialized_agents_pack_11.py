"""Integration tests for the 25 Matt Pocock-inspired PI micro-agents (Cohort 11: Agents 116-140)."""

from __future__ import annotations

import os
import pytest

from pi_micro_agents import (
    PiCavemanTokenCompressor, CavemanCompressorInput,
    PiGrillMeQuestionnaire, GrillMeInput,
    PiHandoffCheckpointSentry, HandoffInput,
    PiToPrdValidator, ToPrdInput,
    PiToIssuesBreakdown, ToIssuesInput,
    PiTriageBugLabels, TriageInput,
    PiZoomOutSystemExplainer, ZoomOutInput,
    PiDesignAnInterfaceValidator, DesignAnInterfaceInput,
    PiRequestRefactorPlanVerifier, RequestRefactorInput,
    PiTddTestFileVerifier, TddTestFileInput,
    PiTddAssertionCoverage, TddAssertionInput,
    PiTddMockingSanityChecker, TddMockingInput,
    PiGitSafetyGuardrail, GitSafetyInput,
    PiTypeScriptWizardryCheck, TypeScriptWizardryInput,
    PiArchitectureImportBoundarySentry, ImportBoundaryInput,
    PiDepreciationScanner, DepreciationInput,
    PiDeadCodePruner, DeadCodeInput,
    PiMockDataTaintingSentry, MockDataTaintingInput,
    PiReadmeValidator, ReadmeInput,
    PiChangelogAuditor, ChangelogInput,
    PiAstDepthGuard, AstDepthInput,
    PiUncontrolledRecursionSentry, RecursionInput,
    PiMagicNumberScanner, MagicNumberInput,
    PiErrorHandlingCatchAllGuard, ErrorCatchInput,
    PiSemanticCommitMessageLinter, CommitLinterInput
)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Ensure clean test environment variables before each test runs."""
    monkeypatch.delenv("PI_CAVEMAN_COMPRESSOR_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_GRILL_ME_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_HANDOFF_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TO_PRD_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TO_ISSUES_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TRIAGE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ZOOM_OUT_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_DESIGN_INTERFACE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_REQUEST_REFACTOR_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TDD_FILE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TDD_ASSERT_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TDD_MOCK_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_GIT_SAFETY_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_TYPESCRIPT_WIZARDRY_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_IMPORT_BOUNDARY_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_DEPRECIATION_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_DEAD_CODE_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_MOCK_TAINT_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_README_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_CHANGELOG_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_AST_DEPTH_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_UNCONTROLLED_RECURSION_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_MAGIC_NUMBER_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_ERROR_CATCH_STRICT_MODE", raising=False)
    monkeypatch.delenv("PI_COMMIT_LINTER_STRICT_MODE", raising=False)


# =====================================================================
# 116. PiCavemanTokenCompressor Verification
# =====================================================================
def test_caveman_token_compressor():
    agent = PiCavemanTokenCompressor()
    res = agent.compress_tokens(CavemanCompressorInput(text_payload="Hello, please write a script for me thank you."))
    assert res.is_secure
    assert "hello" not in res.compressed_text.lower()
    assert "please" not in res.compressed_text.lower()
    assert res.status == "PASSED"


# =====================================================================
# 117. PiGrillMeQuestionnaire Verification
# =====================================================================
def test_grill_me_questionnaire(monkeypatch):
    agent = PiGrillMeQuestionnaire()
    
    # Contains TBD
    res_vuln = agent.grill_plan(GrillMeInput(plan_content="This is my plan etc. and it is TBD."))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_GRILL_ME"
    
    monkeypatch.setenv("PI_GRILL_ME_STRICT_MODE", "false")
    res_warn = agent.grill_plan(GrillMeInput(plan_content="This is my plan etc. and it is TBD."))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_GRILL_ME"
    
    res_safe = agent.grill_plan(GrillMeInput(plan_content="Complete architectural design specifying absolute targets."))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 118. PiHandoffCheckpointSentry Verification
# =====================================================================
def test_handoff_checkpoint_sentry(monkeypatch):
    agent = PiHandoffCheckpointSentry()
    
    # Missing reproduction steps
    res_vuln = agent.audit_handoff(HandoffInput(handoff_content="Status is broken. Next steps are to fix it."))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_HANDOFF"
    
    monkeypatch.setenv("PI_HANDOFF_STRICT_MODE", "false")
    res_warn = agent.audit_handoff(HandoffInput(handoff_content="Status is broken. Next steps are to fix it."))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_HANDOFF"
    
    res_safe = agent.audit_handoff(HandoffInput(handoff_content="Status is green. Reproduction: run pytest. Next steps: release."))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 119. PiToPrdValidator Verification
# =====================================================================
def test_to_prd_validator(monkeypatch):
    agent = PiToPrdValidator()
    
    # Missing non-goals
    res_vuln = agent.validate_prd(ToPrdInput(prd_content="Objectives: build website. Specifications: use html."))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_TO_PRD"
    
    monkeypatch.setenv("PI_TO_PRD_STRICT_MODE", "false")
    res_warn = agent.validate_prd(ToPrdInput(prd_content="Objectives: build website. Specifications: use html."))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TO_PRD"
    
    res_safe = agent.validate_prd(ToPrdInput(prd_content="Objectives: build website. Specifications: use html. Non-goals: hosting. Validation: run lighthouse."))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 120. PiToIssuesBreakdown Verification
# =====================================================================
def test_to_issues_breakdown(monkeypatch):
    agent = PiToIssuesBreakdown()
    
    # Missing acceptance criteria
    res_vuln = agent.breakdown_issues(ToIssuesInput(spec_content="Task 1: Code backend."))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_TO_ISSUES"
    
    monkeypatch.setenv("PI_TO_ISSUES_STRICT_MODE", "false")
    res_warn = agent.breakdown_issues(ToIssuesInput(spec_content="Task 1: Code backend."))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TO_ISSUES"
    
    res_safe = agent.breakdown_issues(ToIssuesInput(spec_content="Task 1: Code backend. Checklist: - create db. Acceptance Criteria: server responds with 200."))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 121. PiTriageBugLabels Verification
# =====================================================================
def test_triage_bug_labels(monkeypatch):
    agent = PiTriageBugLabels()
    
    # Fatal stack log
    res_vuln = agent.triage_bug(TriageInput(log_content="fatal error in solidity module compilation"))
    assert not res_vuln.is_secure
    assert "web3-solidity" in res_vuln.recommended_labels
    assert res_vuln.status == "REJECTED_TRIAGE"
    
    monkeypatch.setenv("PI_TRIAGE_STRICT_MODE", "false")
    res_warn = agent.triage_bug(TriageInput(log_content="fatal error in solidity module compilation"))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TRIAGE"
    
    res_safe = agent.triage_bug(TriageInput(log_content="normal warning in docker setup"))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 122. PiZoomOutSystemExplainer Verification
# =====================================================================
def test_zoom_out_system_explainer(monkeypatch):
    agent = PiZoomOutSystemExplainer()
    
    # Too many imports
    imports_code = "\n".join([f"import pkg_{i}" for i in range(20)])
    res_vuln = agent.explain_system(ZoomOutInput(file_path="app.py", code_content=imports_code))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_ZOOM_OUT"
    
    monkeypatch.setenv("PI_ZOOM_OUT_STRICT_MODE", "false")
    res_warn = agent.explain_system(ZoomOutInput(file_path="app.py", code_content=imports_code))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ZOOM_OUT"
    
    res_safe = agent.explain_system(ZoomOutInput(file_path="app.py", code_content="import math\nimport os"))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 123. PiDesignAnInterfaceValidator Verification
# =====================================================================
def test_design_an_interface_validator(monkeypatch):
    agent = PiDesignAnInterfaceValidator()
    
    # Missing typed variables or docstrings
    interface_vuln = "def handle_request(req):\n    pass"
    res_vuln = agent.validate_interface(DesignAnInterfaceInput(interface_content=interface_vuln))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_DESIGN_INTERFACE"
    
    monkeypatch.setenv("PI_DESIGN_INTERFACE_STRICT_MODE", "false")
    res_warn = agent.validate_interface(DesignAnInterfaceInput(interface_content=interface_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_DESIGN_INTERFACE"
    
    interface_safe = 'def handle_request(req: dict) -> bool:\n    """Processes incoming request."""\n    return True'
    res_safe = agent.validate_interface(DesignAnInterfaceInput(interface_content=interface_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 124. PiRequestRefactorPlanVerifier Verification
# =====================================================================
def test_request_refactor_plan_verifier(monkeypatch):
    agent = PiRequestRefactorPlanVerifier()
    
    # Missing dependency map
    plan_vuln = "Refactor main file. Target files: main.py. Migration path: deploy."
    res_vuln = agent.verify_refactor(RequestRefactorInput(plan_content=plan_vuln))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_REQUEST_REFACTOR"
    
    monkeypatch.setenv("PI_REQUEST_REFACTOR_STRICT_MODE", "false")
    res_warn = agent.verify_refactor(RequestRefactorInput(plan_content=plan_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_REQUEST_REFACTOR"
    
    plan_safe = "Refactor main. Target files: main.py. Dependency map: none. Migration path: deploy."
    res_safe = agent.verify_refactor(RequestRefactorInput(plan_content=plan_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 125. PiTddTestFileVerifier Verification
# =====================================================================
def test_tdd_test_file_verifier(monkeypatch):
    agent = PiTddTestFileVerifier()
    
    # Missing corresponding test file for production changes
    res_vuln = agent.verify_test_files(TddTestFileInput(modified_files=["src/auth.py", "src/models.py", "tests/test_auth.py"]))
    assert not res_vuln.is_secure
    assert "src/models.py" in res_vuln.vulnerable_files
    assert res_vuln.status == "REJECTED_TDD_FILE"
    
    monkeypatch.setenv("PI_TDD_FILE_STRICT_MODE", "false")
    res_warn = agent.verify_test_files(TddTestFileInput(modified_files=["src/auth.py", "src/models.py", "tests/test_auth.py"]))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TDD_FILE"
    
    res_safe = agent.verify_test_files(TddTestFileInput(modified_files=["src/auth.py", "tests/test_auth.py"]))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 126. PiTddAssertionCoverage Verification
# =====================================================================
def test_tdd_assertion_coverage(monkeypatch):
    agent = PiTddAssertionCoverage()
    
    # Test method lacking assert statements
    test_vuln = """
    def test_example():
        x = 1 + 1
    """
    res_vuln = agent.check_assertion_coverage(TddAssertionInput(test_code_content=test_vuln))
    assert not res_vuln.is_secure
    assert "test_example" in res_vuln.empty_tests
    assert res_vuln.status == "REJECTED_TDD_ASSERT"
    
    monkeypatch.setenv("PI_TDD_ASSERT_STRICT_MODE", "false")
    res_warn = agent.check_assertion_coverage(TddAssertionInput(test_code_content=test_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TDD_ASSERT"
    
    test_safe = """
    def test_example():
        assert 1 + 1 == 2
    """
    res_safe = agent.check_assertion_coverage(TddAssertionInput(test_code_content=test_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 127. PiTddMockingSanityChecker Verification
# =====================================================================
def test_tdd_mocking_sanity_checker(monkeypatch):
    agent = PiTddMockingSanityChecker()
    
    # Excess/unsafe mocking (>=3 flagged mock patterns)
    test_vuln = """
    def test_mocking():
        m1 = unittest.mock.patch('sys.exit')
        m2 = MagicMock()
        m3 = Mock()
    """
    res_vuln = agent.check_mocking_sanity(TddMockingInput(test_code_content=test_vuln))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_TDD_MOCK"
    
    monkeypatch.setenv("PI_TDD_MOCK_STRICT_MODE", "false")
    res_warn = agent.check_mocking_sanity(TddMockingInput(test_code_content=test_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TDD_MOCK"
    
    test_safe = """
    def test_mocking():
        m1 = Mock()
    """
    res_safe = agent.check_mocking_sanity(TddMockingInput(test_code_content=test_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 128. PiGitSafetyGuardrail Verification
# =====================================================================
def test_git_safety_guardrail(monkeypatch):
    agent = PiGitSafetyGuardrail()
    
    # Dangerous git command
    res_vuln = agent.check_git_safety(GitSafetyInput(command_string="git push origin main --force"))
    assert not res_vuln.is_secure
    assert "push --force" in res_vuln.blocked_commands
    assert res_vuln.status == "REJECTED_GIT_SAFETY"
    
    monkeypatch.setenv("PI_GIT_SAFETY_STRICT_MODE", "false")
    res_warn = agent.check_git_safety(GitSafetyInput(command_string="git push origin main --force"))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_GIT_SAFETY"
    
    res_safe = agent.check_git_safety(GitSafetyInput(command_string="git status"))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 129. PiTypeScriptWizardryCheck Verification
# =====================================================================
def test_typescript_wizardry_check(monkeypatch):
    agent = PiTypeScriptWizardryCheck()
    
    # TypeScript bad practice (any, as any)
    ts_vuln = "const x: any = 5;\nconst y = z as any;"
    res_vuln = agent.check_typescript(TypeScriptWizardryInput(code_content=ts_vuln))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_TYPESCRIPT_WIZARDRY"
    
    monkeypatch.setenv("PI_TYPESCRIPT_WIZARDRY_STRICT_MODE", "false")
    res_warn = agent.check_typescript(TypeScriptWizardryInput(code_content=ts_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_TYPESCRIPT_WIZARDRY"
    
    ts_safe = "const x: number = 5;\nconst y = z;"
    res_safe = agent.check_typescript(TypeScriptWizardryInput(code_content=ts_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 130. PiArchitectureImportBoundarySentry Verification
# =====================================================================
def test_architecture_import_boundary_sentry(monkeypatch):
    agent = PiArchitectureImportBoundarySentry()
    
    # Boundary violation
    code_vuln = "from app.domain import models"
    res_vuln = agent.check_import_boundaries(ImportBoundaryInput(
        file_path="app/infrastructure/db.py",
        code_content=code_vuln,
        forbidden_mappings={"app/infrastructure": ["app/domain"]}
    ))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_IMPORT_BOUNDARY"
    
    monkeypatch.setenv("PI_IMPORT_BOUNDARY_STRICT_MODE", "false")
    res_warn = agent.check_import_boundaries(ImportBoundaryInput(
        file_path="app/infrastructure/db.py",
        code_content=code_vuln,
        forbidden_mappings={"app/infrastructure": ["app/domain"]}
    ))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_IMPORT_BOUNDARY"
    
    res_safe = agent.check_import_boundaries(ImportBoundaryInput(
        file_path="app/infrastructure/db.py",
        code_content="from app.infrastructure import config",
        forbidden_mappings={"app/infrastructure": ["app/domain"]}
    ))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 131. PiDepreciationScanner Verification
# =====================================================================
def test_depreciation_scanner(monkeypatch):
    agent = PiDepreciationScanner()
    
    # Deprecated pattern match
    code_vuln = "import imp"
    res_vuln = agent.scan_depreciation(DepreciationInput(
        file_path="app.py",
        code_content=code_vuln,
        deprecated_patterns=["import imp"]
    ))
    assert not res_vuln.is_secure
    assert "import imp" in res_vuln.symbols_found
    assert res_vuln.status == "REJECTED_DEPRECIATION"
    
    monkeypatch.setenv("PI_DEPRECIATION_STRICT_MODE", "false")
    res_warn = agent.scan_depreciation(DepreciationInput(
        file_path="app.py",
        code_content=code_vuln,
        deprecated_patterns=["import imp"]
    ))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_DEPRECIATION"
    
    res_safe = agent.scan_depreciation(DepreciationInput(
        file_path="app.py",
        code_content="import importlib",
        deprecated_patterns=["import imp"]
    ))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 132. PiDeadCodePruner Verification
# =====================================================================
def test_dead_code_pruner(monkeypatch):
    agent = PiDeadCodePruner()
    
    # Dead code: unused private variable or unused import
    code_vuln = "import unused_pkg\ndef foo():\n    _unused_var = 1"
    res_vuln = agent.prune_dead_code(DeadCodeInput(file_path="app.py", code_content=code_vuln))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_DEAD_CODE"
    
    monkeypatch.setenv("PI_DEAD_CODE_STRICT_MODE", "false")
    res_warn = agent.prune_dead_code(DeadCodeInput(file_path="app.py", code_content=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_DEAD_CODE"
    
    res_safe = agent.prune_dead_code(DeadCodeInput(file_path="app.py", code_content="def foo():\n    return 1"))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 133. PiMockDataTaintingSentry Verification
# =====================================================================
def test_mock_data_tainting_sentry(monkeypatch):
    agent = PiMockDataTaintingSentry()
    
    # Tainted elements in mock data (e.g. real high-entropy key)
    code_vuln = 'let key = "AKIAIOSFODNN7EXAMPLE";'
    res_vuln = agent.check_mock_tainting(MockDataTaintingInput(file_path="mocks.js", data_content=code_vuln))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_MOCK_TAINT"
    
    monkeypatch.setenv("PI_MOCK_TAINT_STRICT_MODE", "false")
    res_warn = agent.check_mock_tainting(MockDataTaintingInput(file_path="mocks.js", data_content=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_MOCK_TAINT"
    
    res_safe = agent.check_mock_tainting(MockDataTaintingInput(file_path="mocks.js", data_content="let key = 'mock_key_value';"))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 134. PiReadmeValidator Verification
# =====================================================================
def test_readme_validator(monkeypatch):
    agent = PiReadmeValidator()
    
    # Missing required section (e.g. Installation)
    res_vuln = agent.validate_readme(ReadmeInput(readme_content="# Readme\nThis is my codebase."))
    assert not res_vuln.is_secure
    assert "installation" in res_vuln.missing_sections
    assert res_vuln.status == "REJECTED_README"
    
    monkeypatch.setenv("PI_README_STRICT_MODE", "false")
    res_warn = agent.validate_readme(ReadmeInput(readme_content="# Readme\nThis is my codebase."))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_README"
    
    res_safe = agent.validate_readme(ReadmeInput(readme_content="# Readme\n## Installation\nrun pip install\n## Prerequisites\nPython 3.8+\n## Usage\nrun app"))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 135. PiChangelogAuditor Verification
# =====================================================================
def test_changelog_auditor(monkeypatch):
    agent = PiChangelogAuditor()
    
    # Missing or invalid version entry
    res_vuln = agent.audit_changelog(ChangelogInput(
        changelog_content="# Changelog\n## [0.9.0]\n- initial release",
        target_version="1.0.0"
    ))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_CHANGELOG"
    
    monkeypatch.setenv("PI_CHANGELOG_STRICT_MODE", "false")
    res_warn = agent.audit_changelog(ChangelogInput(
        changelog_content="# Changelog\n## [0.9.0]\n- initial release",
        target_version="1.0.0"
    ))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_CHANGELOG"
    
    res_safe = agent.audit_changelog(ChangelogInput(
        changelog_content="# Changelog\n## [1.0.0]\n- initial release",
        target_version="1.0.0"
    ))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 136. PiAstDepthGuard Verification
# =====================================================================
def test_ast_depth_guard(monkeypatch):
    agent = PiAstDepthGuard()
    
    # Highly nested code (exceeds max_depth = 5)
    nested_code = """
def deeply_nested():
    if True:
        if True:
            if True:
                if True:
                    if True:
                        pass
    """
    res_vuln = agent.check_ast_depth(AstDepthInput(
        file_path="app.py",
        code_content=nested_code,
        max_depth=4
    ))
    assert not res_vuln.is_secure
    assert "deeply_nested" in res_vuln.complex_functions
    assert res_vuln.status == "REJECTED_AST_DEPTH"
    
    monkeypatch.setenv("PI_AST_DEPTH_STRICT_MODE", "false")
    res_warn = agent.check_ast_depth(AstDepthInput(
        file_path="app.py",
        code_content=nested_code,
        max_depth=4
    ))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_AST_DEPTH"
    
    safe_code = """
def flat():
    if True:
        pass
    """
    res_safe = agent.check_ast_depth(AstDepthInput(
        file_path="app.py",
        code_content=safe_code,
        max_depth=4
    ))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 137. PiUncontrolledRecursionSentry Verification
# =====================================================================
def test_uncontrolled_recursion_sentry(monkeypatch):
    agent = PiUncontrolledRecursionSentry()
    
    # Recursion call without checking any parameter
    rec_vuln = """
def recurse():
    return recurse()
    """
    res_vuln = agent.check_recursion(RecursionInput(file_path="app.py", code_content=rec_vuln))
    assert not res_vuln.is_secure
    assert "recurse" in res_vuln.recursive_loops
    assert res_vuln.status == "REJECTED_UNCONTROLLED_RECURSION"
    
    monkeypatch.setenv("PI_UNCONTROLLED_RECURSION_STRICT_MODE", "false")
    res_warn = agent.check_recursion(RecursionInput(file_path="app.py", code_content=rec_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_UNCONTROLLED_RECURSION"
    
    rec_safe = """
def recurse(n):
    if n <= 0:
        return 0
    return recurse(n-1)
    """
    res_safe = agent.check_recursion(RecursionInput(file_path="app.py", code_content=rec_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 138. PiMagicNumberScanner Verification
# =====================================================================
def test_magic_number_scanner(monkeypatch):
    agent = PiMagicNumberScanner()
    
    # Magical numeric constant
    code_vuln = "def area(r):\n    return 3.14159 * r * r"
    res_vuln = agent.scan_magic_numbers(MagicNumberInput(file_path="app.py", code_content=code_vuln))
    assert not res_vuln.is_secure
    assert "3.14159" in res_vuln.flagged
    assert res_vuln.status == "REJECTED_MAGIC_NUMBER"
    
    monkeypatch.setenv("PI_MAGIC_NUMBER_STRICT_MODE", "false")
    res_warn = agent.scan_magic_numbers(MagicNumberInput(file_path="app.py", code_content=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_MAGIC_NUMBER"
    
    code_safe = "PI = 3.14159\ndef area(r):\n    return PI * r * r"
    res_safe = agent.scan_magic_numbers(MagicNumberInput(file_path="app.py", code_content=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 139. PiErrorHandlingCatchAllGuard Verification
# =====================================================================
def test_error_handling_catch_all_guard(monkeypatch):
    agent = PiErrorHandlingCatchAllGuard()
    
    # Try except swallowing error
    code_vuln = """
try:
    x = 1/0
except Exception:
    pass
    """
    res_vuln = agent.check_error_handling(ErrorCatchInput(file_path="app.py", code_content=code_vuln))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_ERROR_CATCH"
    
    monkeypatch.setenv("PI_ERROR_CATCH_STRICT_MODE", "false")
    res_warn = agent.check_error_handling(ErrorCatchInput(file_path="app.py", code_content=code_vuln))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_ERROR_CATCH"
    
    code_safe = """
try:
    x = 1/0
except Exception as e:
    logger.error(e)
    raise e
    """
    res_safe = agent.check_error_handling(ErrorCatchInput(file_path="app.py", code_content=code_safe))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"


# =====================================================================
# 140. PiSemanticCommitMessageLinter Verification
# =====================================================================
def test_semantic_commit_message_linter(monkeypatch):
    agent = PiSemanticCommitMessageLinter()
    
    # Non semantic commit message
    res_vuln = agent.audit_commit_message(CommitLinterInput(commit_message="fixed bug in router"))
    assert not res_vuln.is_secure
    assert res_vuln.status == "REJECTED_COMMIT_LINTER"
    
    monkeypatch.setenv("PI_COMMIT_LINTER_STRICT_MODE", "false")
    res_warn = agent.audit_commit_message(CommitLinterInput(commit_message="fixed bug in router"))
    assert res_warn.is_secure
    assert res_warn.status == "WARN_COMMIT_LINTER"
    
    res_safe = agent.audit_commit_message(CommitLinterInput(commit_message="fix(router): correct keyword lookup registry"))
    assert res_safe.is_secure
    assert res_safe.status == "PASSED"
