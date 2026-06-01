from __future__ import annotations

from typing import Dict, List

from pydantic import BaseModel, Field


class PrivacyMapperInput(BaseModel):
    data_sources: List[str] = Field(..., description="List of recognized data source nodes (e.g. user_db)")
    data_destinations: List[str] = Field(..., description="List of target data destination nodes")
    flow_connections: List[Dict[str, str]] = Field(
        ..., description="List of dictionaries representing active mapping paths"
    )


class PrivacyMapperOutput(BaseModel):
    is_secure: bool = Field(..., description="True if no high-risk unsecured data flow paths exist")
    unsecured_flows: List[str] = Field(default_factory=list, description="List of identified unsafe data flows")
    risk_score: float = Field(..., description="Calculated security risk score from 0.0 to 100.0")
    status: str = Field(..., description="Operational safety status classification")


class PiDataFlowPrivacyMapper:
    """Specialized Data Flow Integrity Auditor mapping compliance across secured database and untrusted boundaries."""

    def __init__(self) -> None:
        self.agent_name = "PiDataFlowPrivacyMapper"

    def map_data_privacy_flows(self, input_envelope: PrivacyMapperInput) -> PrivacyMapperOutput:
        connections = input_envelope.flow_connections
        unsecured = []
        risk_score = 0.0

        for conn in connections:
            frm = conn.get("from", "")
            to = conn.get("to", "")

            # If sensitive data source flows to an untrusted external endpoint
            if ("db" in frm.lower() or "user" in frm.lower()) and (
                "untrusted" in to.lower() or "external" in to.lower()
            ):
                unsecured.append(f"{frm} -> {to}")
                risk_score += 40.0

        risk_score = min(risk_score, 100.0)
        is_secure = risk_score < 40.0
        status = "PASSED" if is_secure else "COMPROMISED"

        return PrivacyMapperOutput(is_secure=is_secure, unsecured_flows=unsecured, risk_score=risk_score, status=status)
