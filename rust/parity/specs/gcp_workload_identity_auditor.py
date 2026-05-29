"""Parity spec for PiGCPWorkloadIdentityAuditor.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGCPWorkloadIdentityAuditor"

_mod = load_py_agent("pi_gcp_workload_identity_auditor.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGCPWorkloadIdentityAuditor()
    out = agent.execute(_mod.WorkloadIdentityInput(**data))
    return out.model_dump()


SAMPLES = [
    # 1. Clean/passing: no key file, gke with binding, dedicated valid SA -> PASS
    {"input": {
        "uses_service_account_key_file": False,
        "has_workload_identity_binding": True,
        "service_account_email": "app-runtime@my-project.iam.gserviceaccount.com",
        "deployment_target": "gke",
    }},
    # 2. Static key file path only -> +40 WARN
    {"input": {
        "uses_service_account_key_file": True,
        "has_workload_identity_binding": True,
        "service_account_email": "app@my-project.iam.gserviceaccount.com",
        "deployment_target": "cloud_run",
    }},
    # 3. GKE missing workload identity binding -> +30 WARN
    {"input": {
        "uses_service_account_key_file": False,
        "has_workload_identity_binding": False,
        "service_account_email": "app@my-project.iam.gserviceaccount.com",
        "deployment_target": "gke",
    }},
    # 4. Default compute SA (-compute@developer.gserviceaccount.com) -> +25
    {"input": {
        "uses_service_account_key_file": False,
        "has_workload_identity_binding": True,
        "service_account_email": "123456789-compute@developer.gserviceaccount.com",
        "deployment_target": "compute_engine",
    }},
    # 5. Default appspot SA (@appspot.gserviceaccount.com) -> +25
    {"input": {
        "uses_service_account_key_file": False,
        "has_workload_identity_binding": True,
        "service_account_email": "my-project@appspot.gserviceaccount.com",
        "deployment_target": "functions",
    }},
    # 6. default- prefixed SA -> +25, plus invalid email format (no @ or .) -> +15
    {"input": {
        "uses_service_account_key_file": False,
        "has_workload_identity_binding": True,
        "service_account_email": "default-sa",
        "deployment_target": "cloud_run",
    }},
    # 7. Worst case: key file + gke no binding + default sa + bad email -> capped 100 FAIL
    {"input": {
        "uses_service_account_key_file": True,
        "has_workload_identity_binding": False,
        "service_account_email": "DEFAULT-something",
        "deployment_target": "GKE",
    }},
    # 8. Empty email -> skips default sa + email format checks entirely
    {"input": {
        "uses_service_account_key_file": False,
        "has_workload_identity_binding": True,
        "service_account_email": "",
        "deployment_target": "cloud_run",
    }},
    # 9. Edge: relies on default deployment_target (gke), no binding, valid SA -> +30 WARN
    {"input": {
        "uses_service_account_key_file": False,
        "has_workload_identity_binding": False,
        "service_account_email": "svc@proj.iam.gserviceaccount.com",
    }},
    # 10. Invalid email format only (no dot) on non-gke -> +15 PASS-ish
    {"input": {
        "uses_service_account_key_file": False,
        "has_workload_identity_binding": True,
        "service_account_email": "bademail@nodothere",
        "deployment_target": "cloud_run",
    }},
]
