"""Parity spec for PiRuntimeAnomalySentry.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiRuntimeAnomalySentry"

_mod = load_py_agent("pi_runtime_anomaly_sentry.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiRuntimeAnomalySentry()
    out = agent.audit_runtime(_mod.RuntimeInput(**data))
    return out.model_dump()


_CLEAN = "cpu: 12%\nmemory: 40%\nerror_rate: 0%\nthreads: nominal"
_CPU = "cpu_spike detected on worker-3\nmemory ok"
_OOM = "container restarted: OOM_KILLED\nnode pressure high"
_ERROR = "error_rate: 45%\nlatency rising"
_5XX = "5xx_errors: high across edge nodes"
_SHELL = "unauthorized outbound to 8.8.8.8 via sh: /bin/sh -c"
_CMD = "suspicious connection to evil.example.com spawning cmd.exe"
# uppercase to exercise .lower() normalization
_UPPER = "Detected SUSPICIOUS CONNECTION TO 10.0.0.1 launching CMD.EXE"
# multiple anomalies -> risk_score is the max across all matches
_MULTI = "cpu_spike\nerror_rate: 45%\nunauthorized outbound traffic"

SAMPLES = [
    {"input": {"metrics_content": _CLEAN}},
    {"input": {"metrics_content": _CPU}},
    {"input": {"metrics_content": _OOM}},
    {"input": {"metrics_content": _ERROR}},
    {"input": {"metrics_content": _5XX}},
    {"input": {"metrics_content": _SHELL}},
    {"input": {"metrics_content": _CMD}},
    {"input": {"metrics_content": _UPPER}},
    {"input": {"metrics_content": _MULTI}},
    {"input": {"metrics_content": ""}},
    # non-strict env -> WARN_ANOMALIES path, is_secure stays True
    {"input": {"metrics_content": _CPU},
     "env": {"PI_RUNTIME_STRICT_MODE": "false"}},
    {"input": {"metrics_content": _CPU},
     "env": {"PI_RUNTIME_STRICT_MODE": "true"}},
]
