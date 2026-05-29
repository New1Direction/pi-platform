"""Parity spec for PiTddAssertionCoverage.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiTddAssertionCoverage"

_mod = load_py_agent("pi_tdd_assertion_coverage.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiTddAssertionCoverage()
    out = agent.check_assertion_coverage(_mod.TddAssertionInput(**data))
    return out.model_dump()


# All tests have assertions -> PASSED.
_CLEAN = "\n".join(
    [
        "import unittest",
        "",
        "def test_addition(self):",
        "    assert 1 + 1 == 2",
        "",
        "def test_equality(self):",
        "    self.assertEqual(2, 2)",
        "",
        "def test_expect(self):",
        "    expect(x).to_equal(3)",
        "",
    ]
)

# One test method has no assertion -> empty_tests=['test_empty'].
_ONE_EMPTY = "\n".join(
    [
        "import unittest",
        "",
        "def test_ok(self):",
        "    assert True",
        "",
        "def test_empty(self):",
        "    x = 1",
        "    y = 2",
        "",
    ]
)

# Multiple empty tests, preserving discovery order.
_MULTI_EMPTY = "\n".join(
    [
        "def test_one(self):",
        "    foo = 1",
        "def test_two(self):",
        "    assert foo",
        "def test_three(self):",
        "    bar = 2",
        "",
    ]
)

# A single empty test (whole file is one method) -> flagged.
_SINGLE_EMPTY = "def test_solo(self):\n    pass\n"

# No test_ methods at all -> the parser short-circuits, is_secure True.
_NO_TESTS = "\n".join(
    [
        "import unittest",
        "",
        "def helper(self):",
        "    return 1",
        "",
        "class Foo:",
        "    pass",
        "",
    ]
)

# Empty string edge case.
_EMPTY = ""

SAMPLES = [
    {"input": {"test_code_content": _CLEAN}},
    {"input": {"test_code_content": _ONE_EMPTY}},
    {"input": {"test_code_content": _MULTI_EMPTY}},
    {"input": {"test_code_content": _SINGLE_EMPTY}},
    {"input": {"test_code_content": _NO_TESTS}},
    {"input": {"test_code_content": _EMPTY}},
    # non-strict env -> WARN path, is_secure coerced back to True.
    {"input": {"test_code_content": _ONE_EMPTY},
     "env": {"PI_TDD_ASSERT_STRICT_MODE": "false"}},
    # explicit strict env -> REJECTED path.
    {"input": {"test_code_content": _ONE_EMPTY},
     "env": {"PI_TDD_ASSERT_STRICT_MODE": "true"}},
]
