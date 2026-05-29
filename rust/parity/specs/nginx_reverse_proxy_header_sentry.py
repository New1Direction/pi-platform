"""Parity spec for PiNginxReverseProxyHeaderSentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiNginxReverseProxyHeaderSentry"

_mod = load_py_agent("pi_nginx_reverse_proxy_header_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiNginxReverseProxyHeaderSentry()
    out = agent.audit_nginx_headers(_mod.NginxReverseProxyHeaderInput(**data))
    return out.model_dump()


# A location block with proxy_pass AND proxy_set_header -> secure.
_SECURE = "\n".join(
    [
        "location /api {",
        "    proxy_pass http://backend;",
        "    proxy_set_header Host $host;",
        "    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
        "}",
    ]
)

# proxy_pass with no tracking headers at all -> flagged/vulnerable.
_VULN = "\n".join(
    [
        "location /app {",
        "    proxy_pass http://upstream;",
        "}",
    ]
)

# proxy_pass + X-Forwarded-For present (no proxy_set_header keyword literal) -> secure.
_VULN_BUT_XFF = "\n".join(
    [
        "location /xff {",
        "    proxy_pass http://upstream;",
        "    add_header X-Forwarded-For $remote_addr;",
        "}",
    ]
)

# No proxy_pass anywhere -> secure regardless of headers.
_NO_PROXY = "\n".join(
    [
        "location /static {",
        "    root /var/www/html;",
        "    index index.html;",
        "}",
    ]
)

# Multiple blocks: one secure, one vulnerable -> aggregate flagged.
_MULTI = "\n".join(
    [
        "location /ok {",
        "    proxy_pass http://a;",
        "    proxy_set_header Host $host;",
        "}",
        "location /bad {",
        "    proxy_pass http://b;",
        "}",
        "location /assets {",
        "    root /srv;",
        "}",
    ]
)

SAMPLES = [
    {"input": {"file_path": "nginx.conf", "nginx_code": _SECURE}},
    {"input": {"file_path": "nginx.conf", "nginx_code": _VULN}},
    {"input": {"file_path": "nginx.conf", "nginx_code": _VULN_BUT_XFF}},
    {"input": {"file_path": "nginx.conf", "nginx_code": _NO_PROXY}},
    {"input": {"file_path": "nginx.conf", "nginx_code": _MULTI}},
    {"input": {"file_path": "nginx.conf", "nginx_code": ""}},
    {"input": {"file_path": "nginx.conf", "nginx_code": _VULN, "check_level": "LENIENT"}},
    # non-strict env -> WARN path, is_secure coerced back to True
    {"input": {"file_path": "nginx.conf", "nginx_code": _VULN},
     "env": {"PI_NGINX_REVERSE_PROXY_STRICT_MODE": "false"}},
    {"input": {"file_path": "nginx.conf", "nginx_code": _VULN},
     "env": {"PI_NGINX_REVERSE_PROXY_STRICT_MODE": "true"}},
]
