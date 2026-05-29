"""Parity spec for PiTddMockingSanityChecker.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiTddMockingSanityChecker"

_mod = load_py_agent("pi_tdd_mocking_sanity_checker.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiTddMockingSanityChecker()
    out = agent.check_mocking_sanity(_mod.TddMockingInput(**data))
    return out.model_dump()


# Clean test code: no mock primitives at all -> PASSED.
_CLEAN = "\n".join(
    [
        "def test_add():",
        "    assert add(1, 2) == 3",
        "    assert add(-1, 1) == 0",
    ]
)

# A single unspec'd mock: flagged but under the threshold (<3) -> PASSED.
_ONE_MOCK = "m = MagicMock()"

# Exactly two unspec'd mocks: flagged, still under threshold -> PASSED.
_TWO_MOCKS = "\n".join(
    [
        "    m1 = MagicMock()  ",
        "m2 = mock.patch('module.thing')",
    ]
)

# Three unspec'd mocks across every distinct trigger token -> REJECTED.
_THREE_MOCKS = "\n".join(
    [
        "a = MagicMock()",
        "with mock.patch('os.path.exists') as p:",
        "b = Mock(return_value=42)",
        "c = mock.Mock()",
    ]
)

# Mocks that DO carry spec=/autospec= are never flagged -> PASSED.
_SPECD = "\n".join(
    [
        "a = MagicMock(spec=Foo)",
        "b = mock.patch('x', autospec=True)",
        "c = Mock(spec=Bar)",
        "d = mock.Mock(spec=Baz)",
    ]
)

SAMPLES = [
    {"input": {"test_code_content": _CLEAN}},
    {"input": {"test_code_content": _ONE_MOCK}},
    {"input": {"test_code_content": _TWO_MOCKS}},
    {"input": {"test_code_content": _THREE_MOCKS}},
    {"input": {"test_code_content": _SPECD}},
    {"input": {"test_code_content": ""}},
    # over threshold + strict env -> REJECTED_TDD_MOCK
    {"input": {"test_code_content": _THREE_MOCKS},
     "env": {"PI_TDD_MOCK_STRICT_MODE": "true"}},
    # over threshold + non-strict env -> WARN_TDD_MOCK, is_secure coerced True
    {"input": {"test_code_content": _THREE_MOCKS},
     "env": {"PI_TDD_MOCK_STRICT_MODE": "false"}},
]
