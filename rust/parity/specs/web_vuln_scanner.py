"""Parity spec for PiWebVulnScanner.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}

Note: the Python module defines `is_strict_mode()` reading the env var
`PI_WEB_VULN_STRICT_MODE`, but `scan_web_vulnerabilities` never calls it, so no
environment variable affects this agent's output. There are therefore no `env`
samples.
"""
from _util import load_py_agent

RUST_NAME = "PiWebVulnScanner"

_mod = load_py_agent("pi_web_vuln_scanner.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiWebVulnScanner()
    out = agent.scan_web_vulnerabilities(_mod.WebVulnInput(**data))
    return out.model_dump()


# Clean: references a Content-Security-Policy header, no XSS / CSRF issues.
_CLEAN = "res.setHeader('Content-Security-Policy', \"default-src 'self'\")\nconst csrfToken = generate()"

# XSS via dangerouslySetInnerHTML (also missing CSP -> two findings, risk 85).
_XSS_REACT = "return <div dangerouslySetInnerHTML={{__html: userInput}} />"

# XSS via `innerHTML =` (also missing CSP -> two findings, risk 85).
_XSS_INNERHTML = "el.innerHTML = req.query.message"

# CSRF disabled via `csrf: false` (also missing CSP -> two findings, risk 80).
_CSRF_OFF = "app.use(csurf({ csrf: false }))"

# CSRF disabled via `enable_csrf = False` (uppercase F -> matched after lower()).
_CSRF_PY = "WTF_CSRF_ENABLED = True\nENABLE_CSRF = False"

# CSRF disabled via `csrf_protect = false`.
_CSRF_PROTECT = "csrf_protect = false"

# Only the CSP finding fires (no XSS, no CSRF, no csp/content-security-policy).
_CSP_ONLY = "const total = a + b;"

# Everything fires: XSS + CSRF + (still no CSP token) -> three findings, risk 85.
_ALL = "node.innerHTML = data\nconfig = { csrf: false }"

# Mentions 'csp' as a bare substring -> suppresses the CSP finding even without a
# real header (parity edge: Python uses a naive `"csp" not in code.lower()`).
_CSP_SUBSTRING = "let cspNonce = makeNonce();\nconst x = 1;"

SAMPLES = [
    {"input": {"file_path": "clean.js", "code_content": _CLEAN}},
    {"input": {"file_path": "App.tsx", "code_content": _XSS_REACT}},
    {"input": {"file_path": "dom.js", "code_content": _XSS_INNERHTML}},
    {"input": {"file_path": "server.js", "code_content": _CSRF_OFF}},
    {"input": {"file_path": "settings.py", "code_content": _CSRF_PY}},
    {"input": {"file_path": "settings.py", "code_content": _CSRF_PROTECT}},
    {"input": {"file_path": "math.js", "code_content": _CSP_ONLY}},
    {"input": {"file_path": "kitchen_sink.js", "code_content": _ALL}},
    {"input": {"file_path": "nonce.js", "code_content": _CSP_SUBSTRING}},
    {"input": {"file_path": "empty.js", "code_content": ""}},
]
