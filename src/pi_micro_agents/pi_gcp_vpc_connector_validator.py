from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class VPCConnectorInput(BaseModel):
    connector_name: str = Field(..., description="The name of the GCP Serverless VPC Access connector")
    ip_cidr_range: str = Field(..., description="The /28 private IPv4 CIDR range reserved for the connector")
    network: str = Field(default="default", description="The VPC network to associate with the connector")


class VPCConnectorOutput(BaseModel):
    is_valid: bool = Field(..., description="True if the connector name and CIDR range satisfy GCP rules")
    issues: List[str] = Field(default_factory=list, description="List of validation issues found")
    risk_score: float = Field(..., description="Calculated security risk score from 0.0 to 100.0")
    status: str = Field(..., description="Validation status: PASS, WARN, or FAIL")


class PiGCPVPCConnectorValidator:
    """Validator agent for GCP Serverless VPC Access Connectors, checking name structures, /28 sizing, and RFC 1918 private range allocations."""

    def __init__(self) -> None:
        self.agent_name = "PiGCPVPCConnectorValidator"

    def execute(self, input_envelope: VPCConnectorInput) -> VPCConnectorOutput:
        connector_name = input_envelope.connector_name
        ip_cidr_range = input_envelope.ip_cidr_range

        issues = []
        risk_score = 0.0
        is_name_valid = True
        is_cidr_valid = True

        # Rule 1: Validate Connector Name
        # GCP Connector Name: must start with lowercase letter, max 63 characters, only lowercase letters, numbers, and hyphens.
        if not re.match(r"^[a-z][a-z0-9-]{0,62}$", connector_name):
            is_name_valid = False
            issues.append(
                "Connector name must start with a lowercase letter, be 1-63 characters, and contain only lowercase letters, numbers, or hyphens."
            )
            risk_score += 35.0

        # Rule 2: Validate CIDR Range format and prefix size /28
        cidr_match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})$", ip_cidr_range)
        if not cidr_match:
            is_cidr_valid = False
            issues.append("IP CIDR range must be in valid IPv4 CIDR format (e.g. 10.0.0.0/28).")
            risk_score += 45.0
        else:
            o1, o2, o3, o4, prefix = map(int, cidr_match.groups())

            # Check IP octets validity
            if not (0 <= o1 <= 255 and 0 <= o2 <= 255 and 0 <= o3 <= 255 and 0 <= o4 <= 255):
                is_cidr_valid = False
                issues.append("IP address contains octets outside the 0-255 range.")
                risk_score += 45.0

            # Check prefix size (GCP VPC Access connector strictly requires /28)
            if prefix != 28:
                is_cidr_valid = False
                issues.append(
                    f"GCP Serverless VPC Access connector CIDR range must have a /28 prefix size (got /{prefix})."
                )
                risk_score += 45.0

            # Check RFC 1918 private range allocation
            # Private ranges:
            # 10.0.0.0/8
            # 172.16.0.0/12 (172.16.0.0 - 172.31.255.255)
            # 192.168.0.0/16
            is_rfc1918 = False
            if o1 == 10:
                is_rfc1918 = True
            elif o1 == 172 and (16 <= o2 <= 31):
                is_rfc1918 = True
            elif o1 == 192 and o2 == 168:
                is_rfc1918 = True

            if not is_rfc1918:
                issues.append(f"IP CIDR range '{ip_cidr_range}' is not in the private RFC 1918 address space.")
                risk_score += 25.0

        risk_score = min(risk_score, 100.0)
        is_valid = is_name_valid and is_cidr_valid

        if not is_valid or risk_score > 60.0:
            status = "FAIL"
        elif risk_score >= 30.0:
            status = "WARN"
        else:
            status = "PASS"

        return VPCConnectorOutput(
            is_valid=is_valid,
            issues=issues,
            risk_score=risk_score,
            status=status,
        )
