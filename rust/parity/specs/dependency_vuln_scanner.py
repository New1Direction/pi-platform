"""Parity spec for PiDependencyVulnScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiDependencyVulnScanner"

_mod = load_py_agent("pi_dependency_vuln_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiDependencyVulnScanner()
    out = agent.scan_dependencies(_mod.DependencyInput(**data))
    return out.model_dump()


_CLEAN = '{"name": "app", "dependencies": {"express": "4.18.2"}}'
_LODASH = '{"lodash": {"version": "4.17.20"}}'
_LODASH_PIP = "lodash==4.17.15\nflask==2.0.0"
_LOG4J = "log4j-core 2.14.1\nspring-boot 2.6.0"
_REQUESTS = "requests==2.18.4\nurllib3==1.24"
_REQUESTS_RANGE = "requests<2.20\nclick==8.0"
_MULTI = "\n".join(
    [
        "lodash@4.17.15",
        "log4j-core 2.15.0-rc1",
        "requests==2.19.1",
    ]
)

SAMPLES = [
    # clean lockfile -> PASSED, risk 0
    {"input": {"lockfile_path": "package-lock.json", "lockfile_content": _CLEAN, "ecosystem": "npm"}},
    # lodash prototype pollution (npm version form) -> strict reject
    {"input": {"lockfile_path": "package-lock.json", "lockfile_content": _LODASH, "ecosystem": "npm"}},
    # lodash via pip == form
    {"input": {"lockfile_path": "requirements.txt", "lockfile_content": _LODASH_PIP, "ecosystem": "pip"}},
    # log4j critical (Log4Shell) -> risk 100, strict reject
    {"input": {"lockfile_path": "pom.xml", "lockfile_content": _LOG4J, "ecosystem": "maven"}},
    # old requests library == form
    {"input": {"lockfile_path": "requirements.txt", "lockfile_content": _REQUESTS, "ecosystem": "pip"}},
    # requests range form
    {"input": {"lockfile_path": "requirements.txt", "lockfile_content": _REQUESTS_RANGE, "ecosystem": "pip"}},
    # multiple vulns at once -> max risk wins (100), all listed
    {"input": {"lockfile_path": "mixed.lock", "lockfile_content": _MULTI, "ecosystem": "npm"}},
    # empty lockfile -> PASSED
    {"input": {"lockfile_path": "empty.lock", "lockfile_content": "", "ecosystem": "cargo"}},
    # non-strict env -> WARN_VULNERABILITIES, is_secure stays True
    {"input": {"lockfile_path": "pom.xml", "lockfile_content": _LOG4J, "ecosystem": "maven"},
     "env": {"PI_DEPENDENCY_STRICT_MODE": "false"}},
    # explicit strict env -> VULNERABILITIES_FOUND
    {"input": {"lockfile_path": "pom.xml", "lockfile_content": _LOG4J, "ecosystem": "maven"},
     "env": {"PI_DEPENDENCY_STRICT_MODE": "true"}},
]
