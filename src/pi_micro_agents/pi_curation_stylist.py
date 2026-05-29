from __future__ import annotations

import json
import os
import re
from typing import List, Tuple

from pydantic import BaseModel, Field

# Import schemas from Agent 1 to preserve continuity
from pi_micro_agents.pi_niche_scraper import ScrapedRepo, ScrapedTweet


def is_strict_mode() -> bool:
    env_val = os.getenv("PI_STYLIST_STRICT_MODE")
    if env_val is not None:
        return env_val.lower() == "true"

    config_path = os.path.expanduser("~/.antigravitycli/config.json")
    if not os.path.exists(config_path):
        config_path = os.path.join(os.path.dirname(__file__), "../../.antigravitycli/config.json")

    if os.path.exists(config_path):
        try:
            with open(config_path, "r") as f:
                data = json.load(f)
                return bool(data.get("PI_STYLIST_STRICT_MODE", True))
        except Exception:
            pass
    return True


# 2. Heuristic check to prevent styled content from hosting markdown exfiltration links
def detect_stylist_anomalies(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Check for Markdown Image Exfiltration payloads siphoning WAL telemetry
    exfiltration_pattern = r"!\[.*?\]\(https?://[^)]*?log\?leak="
    if re.search(exfiltration_pattern, text, re.IGNORECASE):
        violations.append("stealth markdown telemetry exfiltration payload detected")
        max_risk = 95.0

    return max_risk, violations


# 3. Pydantic Inputs and Outputs
class CurationInput(BaseModel):
    niche: str
    tweets: List[ScrapedTweet]
    github_repos: List[ScrapedRepo]
    transcripts: List[str] = Field(default_factory=list, description="YouTube transcripts to summarize")
    tone: str = Field(default="informative", description="The editorial tone, e.g. educational, engaging")


class CurationOutput(BaseModel):
    success: bool
    substack_title: str
    substack_markdown_body: str
    x_thread_posts: List[str] = Field(default_factory=list)
    anomalies_detected: List[str] = Field(default_factory=list)


# 4. Core Agent Class
class PiCurationStylist:
    """Agent 2: Packages, rewrites, and styles social and repo telemetry into articles and threads."""

    def __init__(self) -> None:
        self.agent_name = "PiCurationStylist"

    def format_newsletter(self, input_envelope: CurationInput) -> CurationOutput:
        """Converts raw scraped feeds into fully formatted newsletter content and threads."""
        title = f"{input_envelope.niche.upper()} Curation Weekly: Real-time CUDA & Weight Tuning"

        # Build Markdown newsletter body
        body_lines = [
            f"# {title}",
            f"\nWelcome to this week's autonomous {input_envelope.niche} updates, synthesized securely under the PI Platform framework.\n",
            "## 🐦 Top Lead Insights",
        ]

        for tweet in input_envelope.tweets:
            body_lines.append(f"*   **{tweet.handle}**: {tweet.text}")

        body_lines.append("\n## 🪐 Trending Repositories")
        for repo in input_envelope.github_repos:
            body_lines.append(
                f"*   **[{repo.name}](https://github.com/{repo.name})**: {repo.description} (⭐ {repo.stars:,})"
            )

        if input_envelope.transcripts:
            body_lines.append("\n## 📼 YouTube Transcripts & Creator Insights")
            for t in input_envelope.transcripts:
                # Add bullet points of the first few sentences or summarize
                snippet = t.split(".")[0] + "..." if "." in t else t
                body_lines.append(f"*   {snippet}")

        substack_body = "\n".join(body_lines)

        # Compile X Twitter thread posts
        x_posts = [
            f"1/ {input_envelope.niche.upper()} Curation Weekly is out! This week we cover native CUDA training and agent-orchestration frameworks. 🧵 👇",
        ]
        idx = 2
        for repo in input_envelope.github_repos:
            x_posts.append(
                f"{idx}/ Highlighted Repo: {repo.name} - {repo.description}. Already at {repo.stars:,} stars! https://github.com/{repo.name}"
            )
            idx += 1

        x_posts.append(f"{idx}/ Read the full edition and subscribe for more automated updates!")

        # Check for safety anomalies/exfiltration vectors
        risk, violations = detect_stylist_anomalies(substack_body)
        success = True
        if is_strict_mode() and risk >= 70.0:
            success = False
            substack_body = ""
            x_posts = []

        return CurationOutput(
            success=success,
            substack_title=title,
            substack_markdown_body=substack_body,
            x_thread_posts=x_posts,
            anomalies_detected=violations,
        )
