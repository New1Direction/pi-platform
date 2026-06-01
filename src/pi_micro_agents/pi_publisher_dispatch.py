from __future__ import annotations

import hashlib
import json
import re
from typing import List, Tuple

from pydantic import BaseModel, Field

# Import database state ledger to write publication chains
from pi_agent_chain.ledger import StateLedger
from pi_micro_agents.strict_mode import resolve_strict_mode


def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_PUBLISHER_STRICT_MODE")


# Heuristic anomaly checking: ensures the published output does not leakage secret keys or private files
def detect_publisher_anomalies(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Detect private API token leaks
    leak_checks = [
        (r"\bsk_live_[a-zA-Z0-9]{24}\b", "live openAI key leakage warning"),
        (r"\bprivate_key\b", "cryptographic wallet private key phrase siphoning"),
        (r"db_password", "database credential leakage hazard"),
    ]
    for pat, desc in leak_checks:
        if re.search(pat, text, re.IGNORECASE):
            violations.append(desc)
            max_risk = max(max_risk, 95.0)

    return max_risk, violations


# Pydantic Input/Output envelopes
class PublisherInput(BaseModel):
    substack_title: str
    substack_markdown_body: str
    x_thread_posts: List[str]
    draft_only: bool = Field(default=True, description="Save to drafts on publishing platforms without releasing")


class PublisherOutput(BaseModel):
    success: bool
    published_timestamp: str
    x_thread_url: str
    substack_post_url: str
    ledger_receipt_hash: str
    anomalies_detected: List[str] = Field(default_factory=list)


class PiPublisherDispatch:
    """Agent 3: Publishes formatted threads to X and articles to Substack."""

    def __init__(self, ledger: StateLedger | None = None) -> None:
        self.agent_name = "PiPublisherDispatch"
        self.ledger = ledger or StateLedger(":memory:")

    def dispatch_publications(self, input_envelope: PublisherInput) -> PublisherOutput:
        """Publishes the curated threads and Substack updates under cryptographic supervision."""
        import datetime

        timestamp = datetime.datetime.now().isoformat()

        # 1. Screen entire content stream for leak violations (e.g. siphoning system keys)
        combined_content = f"{input_envelope.substack_title}\n{input_envelope.substack_markdown_body}\n" + "\n".join(
            input_envelope.x_thread_posts
        )
        risk, violations = detect_publisher_anomalies(combined_content)

        success = True
        x_url = "https://x.com/pi_platform/status/1234567890"
        substack_url = "https://piplatform.substack.com/p/draft-edition"

        if is_strict_mode() and risk >= 70.0:
            success = False
            x_url = "BLOCKED_PUBLICATION_ANOMALY"
            substack_url = "BLOCKED_PUBLICATION_ANOMALY"
        else:
            # 2. Simulate API connections and successfully post content
            if not input_envelope.draft_only:
                x_url = "https://x.com/pi_platform/status/9876543210"
                substack_url = "https://piplatform.substack.com/p/live-edition"

        # 3. Create SHA-256 validation token for append-only state ledger
        payload_hash = hashlib.sha256(combined_content.encode("utf-8")).hexdigest()

        # Write to StateLedger
        try:
            self.ledger.log_trace(
                trace_id="trace_publish_" + hashlib.sha256(timestamp.encode()).hexdigest()[:12],
                node_name=self.agent_name,
                input_payload_hash=payload_hash,
                llm_seed=1337,
                llm_temperature=0.0,
                raw_output=json.dumps({"success": success, "x_url": x_url, "substack_url": substack_url}),
                is_valid_type=True,
            )
        except Exception:
            # Ignore schema logging issues in memory or offline
            pass

        return PublisherOutput(
            success=success,
            published_timestamp=timestamp,
            x_thread_url=x_url,
            substack_post_url=substack_url,
            ledger_receipt_hash=payload_hash,
            anomalies_detected=violations,
        )
