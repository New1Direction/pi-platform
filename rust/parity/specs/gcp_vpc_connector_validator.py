"""Parity spec for PiGCPVPCConnectorValidator.

A spec declares:
  RUST_NAME       - registry key passed to pi_core.run_agent
  run_python(data)-> dict  - run the ORIGINAL python agent, return model_dump()
  SAMPLES         - list of {"input": {...}, "env": {...optional...}}
"""
from _util import load_py_agent

RUST_NAME = "PiGCPVPCConnectorValidator"

_mod = load_py_agent("pi_gcp_vpc_connector_validator.py")


def run_python(data: dict) -> dict:
    agent = _mod.PiGCPVPCConnectorValidator()
    out = agent.execute(_mod.VPCConnectorInput(**data))
    return out.model_dump()


SAMPLES = [
    # Clean / passing: valid name, RFC1918 /28.
    {"input": {"connector_name": "my-connector", "ip_cidr_range": "10.8.0.0/28"}},
    # Valid name + valid /28 in 172.16/12 private space, explicit network.
    {"input": {"connector_name": "vpc-conn-2", "ip_cidr_range": "172.20.0.0/28",
               "network": "prod-vpc"}},
    # Valid name + valid /28 in 192.168/16 private space.
    {"input": {"connector_name": "c", "ip_cidr_range": "192.168.0.0/28"}},
    # Invalid name (uppercase + underscore), valid cidr -> name path (+35).
    {"input": {"connector_name": "Bad_Name", "ip_cidr_range": "10.0.0.0/28"}},
    # Name starting with a digit (invalid), valid cidr.
    {"input": {"connector_name": "9connector", "ip_cidr_range": "10.0.0.0/28"}},
    # Malformed CIDR string -> cidr-format path (+45).
    {"input": {"connector_name": "conn", "ip_cidr_range": "not-a-cidr"}},
    # Octet out of range (300) -> octet path (+45) plus non-RFC1918 (+25).
    {"input": {"connector_name": "conn", "ip_cidr_range": "300.0.0.0/28"}},
    # Wrong prefix size /24 in private space -> prefix path (+45).
    {"input": {"connector_name": "conn", "ip_cidr_range": "192.168.1.0/24"}},
    # Public range /28 -> RFC1918 path only (+25), is_valid stays True.
    {"input": {"connector_name": "conn", "ip_cidr_range": "8.8.8.0/28"}},
    # Public range + wrong prefix -> +45 +25 = 70 -> FAIL.
    {"input": {"connector_name": "conn", "ip_cidr_range": "8.8.8.8/24"}},
    # 172 range boundary just outside private (172.32) -> non-RFC1918.
    {"input": {"connector_name": "edge-conn", "ip_cidr_range": "172.32.0.0/28"}},
    # Edge: empty connector_name (invalid name) + bad cidr -> both penalties.
    {"input": {"connector_name": "", "ip_cidr_range": ""}},
]
