import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List

from pydantic import BaseModel, Field


class AgentMetadata(BaseModel):
    """Governed metadata for every PI micro agent."""

    name: str
    description: str
    version: str = "0.1.0"
    input_contract: str
    output_contract: str
    governance_requirements: List[str] = Field(default_factory=list)
    provenance_required: bool = True
    registered_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)
    owner: str = "PI-Platform"

    def to_dict(self):
        return self.model_dump()


class PIAgentRegistry:
    """Central governed registry for all deterministic PI micro agents."""

    def __init__(self):
        self.agents: Dict[str, AgentMetadata] = {}
        self._registry_path = Path("/Users/clubpenguin/Documents/pi-platform/src/pi_agent_registry/registry.json")
        self._load()

    def register(self, metadata: AgentMetadata):
        """Register an agent with full governance metadata."""
        self.agents[metadata.name] = metadata
        self._save()
        print(f"✓ Registered PI Agent: {metadata.name} v{metadata.version}")
        return True

    def get(self, name: str) -> AgentMetadata | None:
        return self.agents.get(name)

    def list_agents(self) -> List[AgentMetadata]:
        return list(self.agents.values())

    def to_markdown(self) -> str:
        """Generate human-readable roster for Obsidian."""
        lines = [
            "# PI Agent Registry\n",
            f"**Last Updated:** {datetime.utcnow().isoformat()}\n",
            "| Agent Name | Description | Version | Tags |",
            "|------------|-------------|---------|------|",
        ]
        for agent in sorted(self.agents.values(), key=lambda x: x.name):
            tags = ", ".join(agent.tags) if agent.tags else "-"
            lines.append(f"| {agent.name} | {agent.description[:60]}... | {agent.version} | {tags} |")
        return "\n".join(lines)

    def _save(self):
        data = {name: meta.to_dict() for name, meta in self.agents.items()}
        self._registry_path.write_text(json.dumps(data, indent=2, default=str))

    def _load(self):
        if self._registry_path.exists():
            try:
                data = json.loads(self._registry_path.read_text())
                for name, meta in data.items():
                    self.agents[name] = AgentMetadata(**meta)
            except Exception:
                pass


# Global singleton
registry = PIAgentRegistry()


def register_agent(
    name: str,
    description: str,
    input_contract: str,
    output_contract: str,
    tags: List[str] = None,
    version: str = "0.1.0",
):
    """Decorator to register agents with governance metadata."""

    def decorator(cls):
        metadata = AgentMetadata(
            name=name,
            description=description,
            version=version,
            input_contract=input_contract,
            output_contract=output_contract,
            tags=tags or [],
        )
        registry.register(metadata)
        return cls

    return decorator


# Export for easy use
__all__ = ["registry", "register_agent", "AgentMetadata"]
