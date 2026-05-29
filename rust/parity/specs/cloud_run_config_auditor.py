"""Parity spec for PiCloudRunConfigAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiCloudRunConfigAuditor"

_mod = load_py_agent("pi_cloud_run_config_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiCloudRunConfigAuditor()
    out = agent.execute(_mod.CloudRunConfigInput(**data))
    return out.model_dump()


# Fully hardened config: vpc connector, resources+limits, probe, securityContext.
_SECURE = """\
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/vpc-access-connector: projects/x/locations/us/connectors/c
    spec:
      containers:
        - image: gcr.io/proj/app
          resources:
            limits:
              cpu: "1"
              memory: 512Mi
          livenessProbe:
            httpGet:
              path: /healthz
          securityContext:
            runAsNonRoot: true
"""

# Public ingress via allUsers binding (not allowed) -> high risk.
_PUBLIC = """\
apiVersion: serving.knative.dev/v1
kind: Service
bindings:
  - role: roles/run.invoker
    members:
      - allUsers
"""

# allowUnauthenticated: true variant.
_ALLOW_UNAUTH = """\
metadata:
  annotations:
    run.googleapis.com/allowUnauthenticated: true
"""

# Cleartext sensitive env var.
_CLEARTEXT_SECRET = """\
spec:
  containers:
    - image: gcr.io/proj/app
      resources:
        limits:
          cpu: "1"
      env:
        - name: DB_PASSWORD
          value: hunter2
      livenessProbe:
        httpGet:
          path: /
      securityContext:
        runAsNonRoot: true
      annotations:
        vpc-access-connector: c
"""

# Sensitive env referenced via valueFrom -> NOT flagged.
_SECRET_VALUEFROM = """\
spec:
  containers:
    - image: gcr.io/proj/app
      resources:
        limits:
          cpu: "1"
      env:
        - name: API_TOKEN
          valueFrom:
            secretKeyRef:
              name: my-secret
              key: token
          value: valueFrom
      livenessProbe:
        httpGet:
          path: /
      securityContext:
        runAsNonRoot: true
      annotations:
        vpc-access: c
"""

# Sensitive env whose value is a $-interpolation -> NOT flagged.
_SECRET_INTERP = """\
spec:
  containers:
    - image: gcr.io/proj/app
      resources:
        limits:
          cpu: "1"
      env:
        - name: SECRET_KEY
          value: $SECRET_KEY_REF
      startupProbe:
        httpGet:
          path: /
      securityContext:
        runAsNonRoot: true
      annotations:
        vpc-access-connector: c
"""

# Minimal config missing everything (no limits, vpc, probes, nonroot).
_BARE = """\
spec:
  containers:
    - image: gcr.io/proj/app
"""

SAMPLES = [
    {"input": {"service_yaml": _SECURE}},
    {"input": {"service_yaml": _PUBLIC}},
    {"input": {"service_yaml": _PUBLIC, "allow_unauthenticated": True}},
    {"input": {"service_yaml": _ALLOW_UNAUTH}},
    {"input": {"service_yaml": _CLEARTEXT_SECRET}},
    {"input": {"service_yaml": _SECRET_VALUEFROM}},
    {"input": {"service_yaml": _SECRET_INTERP}},
    {"input": {"service_yaml": _BARE}},
    {"input": {"service_yaml": ""}},
]
