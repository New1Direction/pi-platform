from __future__ import annotations

import re
from typing import List, Tuple

from pydantic import BaseModel, Field

from pi_micro_agents.strict_mode import resolve_strict_mode


# 1. Configuration resolver
def is_strict_mode() -> bool:
    return resolve_strict_mode("PI_SCRAPER_STRICT_MODE")


# 2. Heuristic anomaly checking (checks if X feed data contains system override attacks)
def detect_scraper_anomalies(text: str) -> Tuple[float, List[str]]:
    violations = []
    max_risk = 0.0
    if not text:
        return 0.0, []

    # Detect malicious pattern override attempts within scraped feeds
    scraper_checks = [
        (r"ignore\s+all\s+previous\s+instructions", "direct jailbreak instruction detected in tweet stream"),
        (r"<\|im_start\|>system", "BiDi or markdown injection attempting prompt structure spoofing"),
        (r"rm\s+-rf\s+/", "dangerous command execution code payload in feed source"),
    ]
    for pat, desc in scraper_checks:
        if re.search(pat, text, re.IGNORECASE):
            violations.append(desc)
            max_risk = max(max_risk, 85.0)

    return max_risk, violations


# 3. Pydantic Inputs and Outputs
class ScraperInput(BaseModel):
    niche: str = Field(..., description="The niche topic to target on X, e.g. AI or Web3")
    max_items: int = Field(default=5, description="Maximum number of items to scrape")
    github_stars_threshold: int = Field(default=500, description="Minimum GitHub repository stars")
    target_handles: List[str] = Field(default_factory=list, description="Curated user handles to target")


class ScrapedTweet(BaseModel):
    handle: str
    text: str
    engagement_count: int


class ScrapedRepo(BaseModel):
    name: str
    description: str
    stars: int


class ScraperOutput(BaseModel):
    success: bool
    scraped_at: str
    tweets: List[ScrapedTweet] = Field(default_factory=list)
    github_repos: List[ScrapedRepo] = Field(default_factory=list)
    anomalies_detected: List[str] = Field(default_factory=list)


# 4. Core Agent Class
class PiNicheScraper:
    """Agent 1: Ingests X and GitHub repositories niche telemetry safely."""

    def __init__(self) -> None:
        self.agent_name = "PiNicheScraper"

    def scrape_niche(self, input_envelope: ScraperInput) -> ScraperOutput:
        """Simulates scraping the selected niche while enforcing prompt injection inspection."""
        # 1. Mock ingestion from target handles/niches
        scraped_tweets = [
            ScrapedTweet(
                handle="@karpathy",
                text="llm.c training runs are looking solid. Building native C/CUDA training from scratch is extremely clean.",
                engagement_count=9800,
            ),
            ScrapedTweet(
                handle="@levelsio",
                text="Autonomous AI agents running micro-tasks is definitely the dominant pipeline model for startups in 2026.",
                engagement_count=4500,
            ),
        ]

        scraped_repos = [
            ScrapedRepo(
                name="karpathy/llm.c",
                description="LLM training in simple, pure C/CUDA",
                stars=24800,
            ),
            ScrapedRepo(
                name="uagents/uagents",
                description="Fetch.ai lightweight autonomous agent orchestration framework",
                stars=1800,
            ),
        ]

        # In a real setup, we would perform active scraping here.
        # Check all text items for prompt jailbreak anomalies
        detected_anomalies = []
        for tweet in scraped_tweets:
            risk, violations = detect_scraper_anomalies(tweet.text)
            if risk >= 70.0:
                detected_anomalies.extend(violations)

        # Handle strict mode fail-closed actions
        success = True
        if is_strict_mode() and detected_anomalies:
            success = False
            scraped_tweets = []
            scraped_repos = []

        import datetime

        scraped_time = datetime.datetime.now().isoformat()

        return ScraperOutput(
            success=success,
            scraped_at=scraped_time,
            tweets=scraped_tweets,
            github_repos=scraped_repos,
            anomalies_detected=detected_anomalies,
        )
