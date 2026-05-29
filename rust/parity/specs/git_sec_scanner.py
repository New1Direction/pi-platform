"""Parity spec for PiGitSecScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGitSecScanner"

_mod = load_py_agent("pi_git_sec_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGitSecScanner()
    out = agent.scan_file(_mod.GitSecInput(**data))
    return out.model_dump()


# --- Sample payloads ---

_CLEAN_REQS = "requests==2.31.0\nflask==3.0.0\n# a comment\n"
_UNPINNED_REQS = "requests>=2.0.0\nnumpy~=1.26\n"
_TYPOSQUAT_REQS = "urllib5==1.0.0\nrequests==2.31.0\n"
_CLEAN_PKG_JSON = '{\n  "dependencies": {\n    "react": "18.2.0",\n    "lodash": "4.17.21"\n  }\n}'
_FLOATING_PKG_JSON = '{\n  "dependencies": {\n    "react": "^18.2.0",\n    "left-pad": "*",\n    "express": "latest"\n  }\n}'
_DANGEROUS_PY = "import os\nresult = eval(user_input)\nos.system('rm -rf /tmp/x')\n"
_SUBPROCESS_PY = "import subprocess\nsubprocess.run(cmd, shell=True)\n"
_SECRET_PY = "api_key = 'AWS_KEY_SCRUBBEDGHIJ'\n"
_PRIVATE_KEY = "private_key = '0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789'\n"

SAMPLES = [
    # clean / passing requirements.txt
    {"input": {"filename": "requirements.txt", "content": _CLEAN_REQS}},
    # unpinned/range dependency -> risk 75 -> WARN
    {"input": {"filename": "requirements.txt", "content": _UNPINNED_REQS}},
    # typosquatted package -> risk 85 -> REJECTED under strict
    {"input": {"filename": "requirements.txt", "content": _TYPOSQUAT_REQS}},
    # clean package.json
    {"input": {"filename": "package.json", "content": _CLEAN_PKG_JSON}},
    # floating package.json deps -> risk 75 -> WARN
    {"input": {"filename": "package.json", "content": _FLOATING_PKG_JSON}},
    # dangerous code execution in a .py source file -> risk 90 -> REJECTED
    {"input": {"filename": "app.py", "content": _DANGEROUS_PY}},
    # subprocess shell=True in a source file -> risk 90 -> REJECTED
    {"input": {"filename": "deploy.sh", "content": _SUBPROCESS_PY}},
    # hardcoded secret -> risk 95 -> REJECTED
    {"input": {"filename": "config.py", "content": _SECRET_PY}},
    # hardcoded private key hex -> risk 95
    {"input": {"filename": "wallet.py", "content": _PRIVATE_KEY}},
    # empty / edge input -> no content -> PASSED
    {"input": {"filename": "requirements.txt", "content": ""}},
    # env var branch: non-strict downgrades REJECTED -> WARN
    {"input": {"filename": "app.py", "content": _DANGEROUS_PY},
     "env": {"PI_GIT_SEC_STRICT_MODE": "false"}},
    # env var branch: strict keeps REJECTED
    {"input": {"filename": "app.py", "content": _DANGEROUS_PY},
     "env": {"PI_GIT_SEC_STRICT_MODE": "true"}},
]
