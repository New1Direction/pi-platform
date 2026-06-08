"""
PiAutonomousResearchDirector

The top-level conductor.
Given a high-level goal (e.g. "Map the full attack surface of Antigravity IDE"), it:
- Breaks it down
- Uses PiTaskRouter to decide agents
- Uses PiWorkflowCoordinator to execute
- Monitors progress and spawns new research as needed

This is the agent that turns the system from "tool-assisted" into "autonomous research organism".
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class ResearchCampaignInput(BaseModel):
    goal: str
    target_nodes: List[str] = Field(default_factory=list)
    max_depth: int = 3


class ResearchCampaignOutput(BaseModel):
    campaign_id: str
    goal: str
    spawned_research: List[str]
    status: str
    agent: str = "PiAutonomousResearchDirector"


class PiAutonomousResearchDirector:
    """
    The highest-level orchestration agent.
    Eventually this will be the one that can run long-running autonomous research campaigns.
    """

    def __init__(self):
        self.agent_name = "PiAutonomousResearchDirector"

    def launch_campaign(self, input_data: ResearchCampaignInput) -> ResearchCampaignOutput:
        # Very high-level stub for now
        # In reality it would interact with the router + coordinator + memory keeper

        spawned = (
            [f"Deep research on {node}" for node in input_data.target_nodes[:5]]
            if input_data.target_nodes
            else ["Deep research on Language Server protocol", "Deep research on Gemini context poisoning"]
        )

        return ResearchCampaignOutput(
            campaign_id=f"campaign-{hash(input_data.goal) % 100000}",
            goal=input_data.goal,
            spawned_research=spawned,
            status="initialized",
            agent=self.agent_name,
        )
