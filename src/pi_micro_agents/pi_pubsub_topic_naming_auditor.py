from __future__ import annotations

import re
from typing import List

from pydantic import BaseModel, Field


class PubSubTopicNamingInput(BaseModel):
    topic_name: str = Field(..., description="The name of the Pub/Sub topic to audit")
    subscription_names: List[str] = Field(
        default_factory=list,
        description="Optional list of associated subscription names to audit",
    )
    project_id: str = Field(
        default="",
        description="Optional GCP project ID to validate format compatibility",
    )


class PubSubTopicNamingOutput(BaseModel):
    is_valid: bool = Field(..., description="True if the topic name satisfies all hard naming rules")
    topic_issues: List[str] = Field(default_factory=list, description="Issues identified with the topic name")
    subscription_issues: List[str] = Field(
        default_factory=list, description="Issues identified with the subscription names"
    )
    naming_score: float = Field(..., description="Calculated naming quality score from 0.0 to 100.0")
    risk_score: float = Field(..., description="Derived risk score from 0.0 to 100.0")
    status: str = Field(..., description="Auditing status: PASS, WARN, or FAIL")


class PiPubSubTopicNamingAuditor:
    """Audits GCP Pub/Sub topic and subscription naming structures against GCP standards and conventions."""

    def __init__(self) -> None:
        self.agent_name = "PiPubSubTopicNamingAuditor"

    def execute(self, input_envelope: PubSubTopicNamingInput) -> PubSubTopicNamingOutput:
        topic_name = input_envelope.topic_name
        subscription_names = input_envelope.subscription_names
        project_id = input_envelope.project_id

        topic_issues = []
        subscription_issues = []
        naming_score = 100.0

        # 1. Topic name validation
        # Rule 1: Length must be 3-255 characters
        if not (3 <= len(topic_name) <= 255):
            topic_issues.append("Topic name must be between 3 and 255 characters long.")
            naming_score -= 25.0

        # Rule 2: Must start with a letter
        if not topic_name or not topic_name[0].isalpha():
            topic_issues.append("Topic name must start with a letter.")
            naming_score -= 25.0

        # Rule 3: Valid characters only: letters, numbers, hyphens, underscores, dots, tildes, percent signs, pluses
        if not re.match(r"^[a-zA-Z0-9-_.~+%]+$", topic_name):
            topic_issues.append("Topic name contains invalid characters.")
            naming_score -= 25.0

        # Rule 4: Must not start with 'goog' prefix
        if topic_name.lower().startswith("goog"):
            topic_issues.append("Topic name cannot start with the reserved 'goog' prefix.")
            naming_score -= 25.0

        # Convention: Warn on test/temp/demo in production/naming
        if any(w in topic_name.lower() for w in ["test", "temp", "demo"]):
            topic_issues.append("Topic name contains placeholder keywords (test, temp, demo).")
            naming_score -= 5.0

        # 2. Subscription name validation
        for sub in subscription_names:
            sub_rule_failed = False
            if not (3 <= len(sub) <= 255):
                subscription_issues.append(f"Subscription '{sub}' must be between 3 and 255 characters long.")
                naming_score -= 25.0
                sub_rule_failed = True

            if not sub or not sub[0].isalpha():
                subscription_issues.append(f"Subscription '{sub}' must start with a letter.")
                naming_score -= 25.0
                sub_rule_failed = True

            if not re.match(r"^[a-zA-Z0-9-_.~+%]+$", sub):
                subscription_issues.append(f"Subscription '{sub}' contains invalid characters.")
                naming_score -= 25.0
                sub_rule_failed = True

            # Convention: Should end with '-sub', '-subscription', or 'Subscription'
            if not sub_rule_failed:
                if not (sub.endswith("-sub") or sub.endswith("-subscription") or sub.endswith("Subscription")):
                    subscription_issues.append(
                        f"Subscription '{sub}' does not follow naming convention suffixes (-sub, -subscription, Subscription)."
                    )
                    naming_score -= 5.0

        # 3. Project ID validation if provided
        if project_id:
            # GCP project ID: 6-30 chars, starts with letter, only letters, numbers, hyphens
            if not (6 <= len(project_id) <= 30) or not re.match(r"^[a-z][a-z0-9-]*$", project_id):
                topic_issues.append(f"Project ID '{project_id}' is in an invalid format.")
                naming_score -= 10.0

        naming_score = max(naming_score, 0.0)
        risk_score = 100.0 - naming_score

        # is_valid is True only if there are no critical topic rule failures (any topic issue with 25 deduction)
        # Check if we have any critical topic issues
        critical_violations = [
            issue
            for issue in topic_issues
            if "must start with a letter" in issue.lower()
            or "between 3 and 255" in issue.lower()
            or "invalid characters" in issue.lower()
            or "reserved 'goog'" in issue.lower()
        ]
        is_valid = len(critical_violations) == 0

        if not is_valid or risk_score > 60.0:
            status = "FAIL"
        elif risk_score >= 30.0:
            status = "WARN"
        else:
            status = "PASS"

        return PubSubTopicNamingOutput(
            is_valid=is_valid,
            topic_issues=topic_issues,
            subscription_issues=subscription_issues,
            naming_score=naming_score,
            risk_score=risk_score,
            status=status,
        )
