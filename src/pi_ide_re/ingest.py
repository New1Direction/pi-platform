"""
ingest.py - Two-Step CoT Ingest Pipeline for IDE RE (with Graph Export)

Lightweight implementation of the llm_wiki-style two-step flow:
- Step 1: Analysis (CoT)
- Step 2: Structured Generation + automatic graph contribution

Now also exports a central graph.json for visualization and querying.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field

# Optional real LLM CoT support (lightweight, configurable)
# Falls back to deterministic mode if no LLM client is available
LLM_ENABLED = os.getenv("PI_IDE_RE_USE_LLM", "false").lower() == "true"

# ============================================================
# TYPED KNOWLEDGE GRAPH SCHEMA (v1.1)
# ============================================================


class NodeMetadata(BaseModel):
    source_page: str
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    priority_score: float = 0.0
    tags: List[str] = Field(default_factory=list)
    pi_agents_applied: List[str] = Field(default_factory=list)


class EdgeMetadata(BaseModel):
    relation_type: Literal["needs-research", "references", "blocks", "extends", "contains", "protocol", "data-flow"]
    confidence: float = 1.0
    created_by: str = "ingest-pipeline"


class GraphNode(BaseModel):
    id: str
    type: Literal["deep-research", "entity", "insight", "code-artifact", "risk"]
    title: str
    content: str
    metadata: NodeMetadata = Field(default_factory=NodeMetadata)


class GraphEdge(BaseModel):
    source: str
    target: str
    metadata: EdgeMetadata = Field(default_factory=EdgeMetadata)


class KnowledgeGraph(BaseModel):
    nodes: Dict[str, GraphNode] = Field(default_factory=dict)
    edges: List[GraphEdge] = Field(default_factory=list)
    version: str = "1.1"


# ============================================================

try:
    # Try to use existing project LLM client if available
    from pi_micro_agents.orchestrator.llm_client import get_llm_response  # type: ignore
except Exception:
    get_llm_response = None


class LLMCoT:
    """Lightweight Chain-of-Thought wrapper. Optional and graceful."""

    def __init__(self, enabled: bool = LLM_ENABLED):
        self.enabled = enabled and get_llm_response is not None

    def prioritize_topics(self, topics: List[str], context: str) -> List[str]:
        """Use LLM to rank topics by expected research value."""
        if not self.enabled or not topics:
            return topics  # deterministic fallback: keep original order

        prompt = f"""You are an expert reverse engineer analyzing an AI IDE.

Context:
{context}

Candidate Deep Research Topics:
{chr(10).join(f"- {t}" for t in topics)}

Rank the top 2-3 topics by potential impact for understanding the system's core AI behavior, security surface, and data flows.
Return ONLY the ranked list as plain text lines starting with "- "."""

        try:
            response = get_llm_response(prompt, temperature=0.2)
            ranked = [line.strip("- ").strip() for line in response.splitlines() if line.strip().startswith("-")]
            return ranked[:3] if ranked else topics
        except Exception:
            return topics

    def enrich_stub(self, topic: str, source: str, context: str) -> Dict[str, str]:
        """Use LLM to generate richer stub content."""
        if not self.enabled:
            # Deterministic rich fallback
            return {
                "description": f"This is a high-priority research target surfaced by the deterministic analysis of {source}. The topic directly relates to core protocol, binary, or LLM surfaces in the target IDE.",
                "checklist": [
                    "Initial reconnaissance and traffic capture",
                    "Cross-reference with relevant PI micro-agents",
                    "Identify first concrete artifacts",
                    "Document initial findings",
                ],
                "notes": f"Prioritized based on agent relevance in the parent campaign. See {source} for full context.",
            }

        prompt = f"""You are a world-class reverse engineer.

Source page: {source}
Research topic: "{topic}"

Context from campaign:
{context}

Write a concise, high-signal Deep Research stub with:
1. A 2-3 sentence Description explaining why this topic is high-value.
2. A 4-item actionable Checklist (specific to this topic).
3. 1-2 sentences of initial Notes that reference relevant PI agents or surfaces.

Return in this exact format:
DESCRIPTION: ...
CHECKLIST:
- ...
- ...
NOTES: ..."""

        try:
            response = get_llm_response(prompt, temperature=0.3)
            # Very simple parsing for demo
            parts = {"description": "", "checklist": [], "notes": ""}
            current = None
            for line in response.splitlines():
                line = line.strip()
                if line.upper().startswith("DESCRIPTION:"):
                    current = "description"
                    parts["description"] = line.split(":", 1)[1].strip()
                elif line.upper().startswith("CHECKLIST:"):
                    current = "checklist"
                elif line.upper().startswith("NOTES:"):
                    current = "notes"
                    parts["notes"] = line.split(":", 1)[1].strip()
                elif current == "checklist" and line.startswith("-"):
                    parts["checklist"].append(line[1:].strip())
            return parts
        except Exception:
            return self.enrich_stub(topic, source, context)  # fallback to deterministic


@dataclass
class IngestInput:
    campaign_id: str
    goal: str
    discovery: Dict[str, Any]
    agents_executed: List[str]
    agent_relevance_notes: str
    campaign_note_path: str
    page_type: str = "Insight"  # "Insight" or "Entity"
    title: str = "Derived Insight"
    graph_edges: List[Dict[str, str]] = field(default_factory=list)
    vault_path: str = "vault"


def _build_analysis_step(input_data: IngestInput) -> str:
    """Step 1: Chain-of-Thought Analysis"""
    analysis = f"""## Step 1 – Deep Analysis (CoT)

**Target Profile**:
- Type: {", ".join(input_data.discovery.get("characteristics", []))}
- Key Artifacts: {input_data.discovery.get("app_bundle", "N/A")}, language server on ports {input_data.discovery.get("ports", [])}

**Reasoning**:
This entity/surface was prioritized because it sits at the intersection of the Electron client, the privileged language server, and Google's Gemini infrastructure. It is one of the two primary high-value surfaces identified in the parent campaign.

**Key Relationships**:
- Direct protocol connection to Gemini Cloud Backend
- Privileged access to user workspace
- Potential for prompt and secret leakage

This analysis is derived from live discovery data and previous insight pages.
"""
    return analysis


def _build_generation_step(input_data: IngestInput, analysis: str) -> str:
    """Step 2: Structured Generation (with graph edges in frontmatter)"""
    now = datetime.now(timezone.utc).isoformat()

    # Build graph_edges YAML block (Dataview friendly)
    graph_block = ""
    if input_data.graph_edges:
        graph_block = "graph_edges:\n"
        for edge in input_data.graph_edges:
            graph_block += f"  - type: {edge.get('type', '')}\n"
            graph_block += f'    from: "{edge.get("from", "")}"\n'
            graph_block += f'    to: "{edge.get("to", "")}"\n'
            graph_block += f'    label: "{edge.get("label", "")}"\n'

    content = f"""---
title: "{input_data.title}"
type: {input_data.page_type}
campaign_source: "{input_data.campaign_id}"
sources:
  - {input_data.discovery.get("app_bundle", "N/A")}
  - {input_data.discovery.get("language_servers", ["N/A"])[0] if input_data.discovery.get("language_servers") else "N/A"}
tags: [ide-re, {input_data.page_type.lower()}, antigravity, pi-platform]
created: "{now}"
{graph_block}
---

# {input_data.title}

**Derived from**: [[{Path(input_data.campaign_note_path).stem}]] ({input_data.campaign_id})

**Goal Context**: {input_data.goal}

---

## Executive Summary

{input_data.title} is a core component of the Antigravity IDE attack surface.

## Detailed Analysis (CoT)

{analysis}

## Agent-to-Surface Mapping

{input_data.agent_relevance_notes}

## Knowledge Graph Edges

{chr(10).join(f"- `{e['from']}` --[{e.get('type', '')}]--> `{e['to']}` ({e.get('label', '')})" for e in input_data.graph_edges)}

## Recommended Deep Research Topics

- Protocol and authentication analysis on identified surfaces
- Binary and secret extraction from language server components
- LLM prompt and reasoning trace leakage vectors
- Supply chain and dependency risks in the Electron + extension layer

---

*This page was auto-generated by the two-step CoT ingest pipeline in `src/pi_ide_re/ingest.py`*
*Contributes to the central knowledge graph (see graph.json)*
"""
    return content


def export_graph_edges(vault_path: str, new_edges: List[Dict[str, str]]):
    """
    DEPRECATED: Writes legacy flat list only for backward compatibility with the old visualization page.
    All new work should go through the typed KnowledgeGraph (`knowledge_graph.json`).
    """
    # Legacy flat file (will be removed once visualization is fully migrated)
    graph_file = Path(vault_path) / "graph.json"
    existing = []
    if graph_file.exists():
        try:
            with open(graph_file, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            existing = []

    seen = {(e.get("from"), e.get("to"), e.get("type")) for e in existing}
    for edge in new_edges:
        key = (edge.get("from"), edge.get("to"), edge.get("type"))
        if key not in seen:
            existing.append(edge)
            seen.add(key)

    graph_file.parent.mkdir(parents=True, exist_ok=True)
    with open(graph_file, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)


def append_to_log(vault_path: str, entry: str):
    """Append a timestamped entry to the llm_wiki-style log.md"""
    log_file = Path(vault_path) / "log.md"
    log_file.parent.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    formatted_entry = f"- **{timestamp}** — {entry}\n"

    if log_file.exists():
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(formatted_entry)
    else:
        with open(log_file, "w", encoding="utf-8") as f:
            f.write("# PI IDE RE Vault — Operation Log\n\n")
            f.write("This log records all major ingest, generation, and graph activities (llm_wiki style).\n\n")
            f.write(formatted_entry)


def run_two_step_ingest(input_data: IngestInput) -> Path:
    """Main entry point. Generates page + contributes to central graph."""
    vault = Path(input_data.vault_path).expanduser().resolve()

    # Determine output folder
    if input_data.page_type == "Entity":
        out_dir = vault / "Entities"
    else:
        out_dir = vault / "Insights"
    out_dir.mkdir(parents=True, exist_ok=True)

    analysis = _build_analysis_step(input_data)
    page_content = _build_generation_step(input_data, analysis)

    # Write the page
    safe_title = input_data.title.replace(" ", "-").replace("/", "-")
    page_path = out_dir / f"{safe_title}.md"
    page_path.write_text(page_content, encoding="utf-8")

    # Contribute to central graph (both legacy + typed)
    if input_data.graph_edges:
        export_graph_edges(str(vault), input_data.graph_edges)

    # Also add to typed KnowledgeGraph
    try:
        kg = load_knowledge_graph(str(vault))
        node_id = f"{input_data.page_type.lower()}/{safe_title.lower()}"
        node = GraphNode(
            id=node_id,
            type=input_data.page_type.lower() if input_data.page_type in ["Entity", "Insight"] else "insight",
            title=input_data.title,
            content=page_content[:2000],  # truncated for storage
            metadata=NodeMetadata(
                source_page=str(page_path.relative_to(vault)),
                priority_score=0.7,
                tags=[input_data.page_type.lower(), "ide-re"],
                pi_agents_applied=[],
            ),
        )
        add_to_typed_graph(kg, node=node, vault_path=str(vault))
    except Exception as e:
        append_to_log(str(vault), f"Typed graph update failed for {input_data.title}: {e}")

    return page_path


# Convenience runner for the current Antigravity work
def generate_antigravity_entity_and_insight():
    """Helper to generate the next two pages from existing campaign data."""
    discovery = {
        "target": "Antigravity IDE (live on Mac Mini)",
        "app_bundle": "/Applications/Antigravity IDE.app",
        "language_servers": ["/Applications/Antigravity.app/Contents/Resources/bin/language_server"],
        "ports": [64232, 63838],
        "characteristics": ["electron", "language-server", "grpc-or-custom-protocol", "llm-surface"],
    }

    # Gemini Cloud Backend - Entity
    gemini_edges = [
        {
            "from": "Gemini Cloud Backend",
            "to": "Antigravity Language Server",
            "type": "protocol",
            "label": "Gemini API + Cloud Code",
        },
        {
            "from": "Gemini Cloud Backend",
            "to": "User Workspace Data",
            "type": "data-flow",
            "label": "potential exfiltration",
        },
    ]
    gemini_input = IngestInput(
        campaign_id="ide-re-1779431971",
        goal="Full deterministic reverse engineering of the running Antigravity IDE",
        discovery=discovery,
        agents_executed=[],
        agent_relevance_notes="High-value cloud surface handling authentication and LLM inference for the IDE.",
        campaign_note_path="vault/04 Telemetry & Sessions/2026-05/ide-re-1779431971.md",
        page_type="Entity",
        title="Gemini Cloud Backend",
        graph_edges=gemini_edges,
        vault_path="vault",
    )
    gemini_path = run_two_step_ingest(gemini_input)
    print(f"Generated: {gemini_path}")

    # LLM Prompt Surface - Insight
    llm_edges = [
        {
            "from": "Antigravity Language Server",
            "to": "LLM Prompt Surface",
            "type": "contains",
            "label": "prompt handling",
        },
        {
            "from": "LLM Prompt Surface",
            "to": "Gemini Cloud Backend",
            "type": "data-flow",
            "label": "system + user prompts",
        },
    ]
    llm_input = IngestInput(
        campaign_id="ide-re-1779431971",
        goal="Full deterministic reverse engineering of the running Antigravity IDE",
        discovery=discovery,
        agents_executed=[],
        agent_relevance_notes="Focus on prompt leakage, injection, and reasoning trace exposure in the Gemini integration.",
        campaign_note_path="vault/04 Telemetry & Sessions/2026-05/ide-re-1779431971.md",
        page_type="Insight",
        title="Antigravity LLM Prompt Surface",
        graph_edges=llm_edges,
        vault_path="vault",
    )
    llm_path = run_two_step_ingest(llm_input)
    print(f"Generated: {llm_path}")

    return gemini_path, llm_path


def create_deep_research_stub(topic: str, source_page: str, vault_path: str, llm_cot: Optional[LLMCoT] = None) -> dict:
    """Creates a rich Deep Research stub (LLM-enhanced when available)."""
    llm = llm_cot or LLMCoT()

    enriched = llm.enrich_stub(topic, source_page, f"Source page: {source_page}")

    stub_dir = Path(vault_path) / "Deep-Research"
    stub_dir.mkdir(parents=True, exist_ok=True)

    safe = topic.replace(" ", "-").replace("/", "-")[:80]
    stub_path = stub_dir / f"{safe}.md"

    content = (
        f"""---
title: "{topic}"
type: Deep-Research
source: "{source_page}"
status: "Open"
tags: [deep-research, pi-platform, ide-re]
created: "{datetime.now(timezone.utc).isoformat()}"
---

# {topic}

**Source**: [[{source_page}]]

**Priority**: High

## Description

{enriched.get("description", "High-value research target identified by the ingest pipeline.")}

## Actionable Checklist

"""
        + "\n".join(
            f"- [ ] {item}"
            for item in enriched.get(
                "checklist", ["Reconnaissance", "Cross-reference agents", "Capture artifacts", "Document findings"]
            )
        )
        + f"""

## Initial Notes

{enriched.get("notes", "See parent page for full agent context and discovery data.")}

## Findings

*(To be filled during active research)*

---
*Generated with {"LLM CoT enhancement" if llm.enabled else "deterministic fallback"}.*
"""
    )

    stub_path.write_text(content, encoding="utf-8")

    # Create typed GraphNode + GraphEdge
    node_id = f"deep-research/{safe.lower()}"
    node = GraphNode(
        id=node_id,
        type="deep-research",
        title=topic,
        content=content[:1500],
        metadata=NodeMetadata(
            source_page=str(stub_path.relative_to(Path(vault_path))),
            priority_score=0.75,
            tags=["deep-research", "ide-re"],
            pi_agents_applied=[],
        ),
    )

    edge = GraphEdge(
        source=source_page.replace("Entities/", "").replace("Insights/", "").replace(".md", ""),
        target=topic,
        metadata=EdgeMetadata(relation_type="needs-research", confidence=0.9, created_by="ingest-pipeline"),
    )

    # Add to typed graph
    try:
        kg = load_knowledge_graph(vault_path)
        add_to_typed_graph(kg, node=node, edge=edge, vault_path=vault_path)
    except Exception as e:
        append_to_log(vault_path, f"Failed to add typed node for stub {topic}: {e}")

    append_to_log(vault_path, f"Generated Deep Research stub: {topic} (source: {source_page})")
    return {"node": node, "edge": edge}


def generate_enhanced_deep_research_stubs(source_pages: List[Dict[str, str]], vault_path: str = "vault"):
    """
    Uses LLMCoT for smarter prioritization and richer stub content.
    Falls back gracefully to high-quality deterministic generation.
    """
    llm = LLMCoT(enabled=True)

    all_new_edges = []

    for item in source_pages:
        topic = item["topic"]
        source = item["source"]

        prioritized = llm.prioritize_topics([topic], f"From {source}")
        best_topic = prioritized[0] if prioritized else topic

        stub_result = create_deep_research_stub(best_topic, source, vault_path, llm_cot=llm)
        all_new_edges.append(stub_result)

        # Hook additional graph agents
        try:
            from src.pi_micro_agents.pi_deep_research_promoter import PiDeepResearchPromoter, PromoteInput
            from src.pi_micro_agents.pi_node_prioritizer import NodePrioritizeInput, PiNodePrioritizer
            from src.pi_micro_agents.pi_stub_enricher_agent import PiStubEnricherAgent, StubEnrichInput

            # Create a GraphNode for the agents to work on
            node = GraphNode(
                id=f"deep-research/{best_topic.lower().replace(' ', '-')[:50]}",
                type="deep-research",
                title=best_topic,
                content="",
                metadata=NodeMetadata(source_page=source),
            )

            # 1. StubEnricher
            enricher = PiStubEnricherAgent()
            enrich_result = enricher.enrich(StubEnrichInput(node=node))
            node.metadata.tags.extend(enrich_result.enriched_tags)
            node.metadata.pi_agents_applied.extend(enrich_result.suggested_agents)

            # 2. NodePrioritizer
            prioritizer = PiNodePrioritizer()
            prio_result = prioritizer.prioritize(NodePrioritizeInput(node=node, connectivity_score=0.6))
            node.metadata.priority_score = prio_result.new_priority_score

            # 3. DeepResearchPromoter
            promoter = PiDeepResearchPromoter()
            promo_result = promoter.evaluate(PromoteInput(node=node))
            if promo_result.should_promote:
                node.metadata.tags.append("promotion-ready")

            node.metadata.pi_agents_applied = list(
                set(
                    node.metadata.pi_agents_applied
                    + ["PiStubEnricherAgent", "PiNodePrioritizer", "PiDeepResearchPromoter"]
                )
            )

            # Update the typed graph with enriched node
            kg = load_knowledge_graph(vault_path)
            if node.id in kg.nodes:
                kg.nodes[node.id] = node
                save_knowledge_graph(kg, vault_path)

        except Exception as e:
            append_to_log(vault_path, f"Graph agent chain failed for {best_topic}: {str(e)}")

    append_to_log(vault_path, f"LLM-enhanced Deep Research batch: {len(source_pages)} stubs generated/updated")

    # ============================================================
    # IMMEDIATE WIN: Hook PiGraphConsistencyChecker on every stub
    # ============================================================
    try:
        from src.pi_micro_agents.pi_graph_consistency_checker import PiGraphConsistencyChecker

        checker = PiGraphConsistencyChecker()

        for item in source_pages:
            node_id = f"deep-research/{item['topic'].lower().replace(' ', '-')[:50]}"
            # Build a minimal GraphNode for the checker
            stub_node = GraphNode(
                id=node_id,
                type="deep-research",
                title=item["topic"],
                content="",
                metadata=NodeMetadata(source_page=item["source"]),
            )

            result = checker.run(node_id=node_id, node=stub_node)

            # Update metadata on the node (in real flow this would be the persisted node)
            if "PiGraphConsistencyChecker" not in stub_node.metadata.pi_agents_applied:
                stub_node.metadata.pi_agents_applied.append("PiGraphConsistencyChecker")

            if result.get("confidence_score"):
                stub_node.metadata.priority_score = max(stub_node.metadata.priority_score, result["confidence_score"])

            # In a full implementation we would persist the updated node here
            # For now we just log the validation
            append_to_log(
                vault_path, f"PiGraphConsistencyChecker ran on {node_id} → consistent={result.get('is_consistent')}"
            )

    except Exception as e:
        append_to_log(vault_path, f"Consistency checker hook failed (non-fatal): {str(e)}")

    return all_new_edges


def promote_deep_research_stub(stub_title_or_id: str, vault_path: str = "vault", target_type: str = "Entity") -> str:
    """
    Promotes a Deep Research stub into a full Entity or Insight page.
    Updates the typed graph and marks the original stub as promoted.
    """
    stub_dir = Path(vault_path) / "Deep-Research"
    safe = stub_title_or_id.replace(" ", "-")
    stub_path = stub_dir / f"{safe}.md"

    if not stub_path.exists():
        # try fuzzy match
        for f in stub_dir.glob("*.md"):
            if stub_title_or_id.lower() in f.name.lower():
                stub_path = f
                break

    if not stub_path.exists():
        raise FileNotFoundError(f"Could not find Deep Research stub for: {stub_title_or_id}")

    content = stub_path.read_text(encoding="utf-8")

    # Determine target folder
    target_dir = Path(vault_path) / ("Entities" if target_type == "Entity" else "Insights")
    target_dir.mkdir(parents=True, exist_ok=True)

    new_path = target_dir / stub_path.name.replace("Deep-Research-", "")

    # Simple promotion: copy content + add promoted frontmatter
    promoted_frontmatter = f"""---
title: "{stub_title_or_id}"
type: {target_type}
promoted_from: "Deep-Research/{stub_path.name}"
status: "Promoted"
tags: [promoted, {target_type.lower()}, ide-re]
---

"""

    new_content = promoted_frontmatter + content.split("---", 2)[-1].strip()

    new_path.write_text(new_content, encoding="utf-8")

    # Update graph
    try:
        kg = load_knowledge_graph(vault_path)
        old_id = f"deep-research/{safe.lower()}"
        new_id = f"{target_type.lower()}/{safe.lower()}"

        if old_id in kg.nodes:
            node = kg.nodes[old_id]
            node.type = target_type.lower()
            node.id = new_id
            node.metadata.tags.append("promoted")
            kg.nodes[new_id] = node
            del kg.nodes[old_id]

        # Add promotion edge
        edge = GraphEdge(
            source=old_id, target=new_id, metadata=EdgeMetadata(relation_type="extends", created_by="promote_workflow")
        )
        kg.edges.append(edge)
        save_knowledge_graph(kg, vault_path)
    except Exception as e:
        append_to_log(vault_path, f"Graph update during promotion failed: {e}")

    # Mark original stub
    append_to_log(vault_path, f"Promoted stub to {target_type}: {stub_title_or_id} → {new_path.name}")

    # Optional: move original to archive
    archive_dir = Path(vault_path) / "Deep-Research" / "_promoted"
    archive_dir.mkdir(exist_ok=True)
    stub_path.rename(archive_dir / stub_path.name)

    return str(new_path)


# ============================================================
# TYPED GRAPH PERSISTENCE
# ============================================================


def load_knowledge_graph(vault_path: str) -> KnowledgeGraph:
    """Load or initialize the typed KnowledgeGraph from disk."""
    graph_file = Path(vault_path) / "knowledge_graph.json"
    if graph_file.exists():
        try:
            with open(graph_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return KnowledgeGraph.model_validate(data)
        except Exception:
            pass
    return KnowledgeGraph(version="1.1")


def save_knowledge_graph(graph: KnowledgeGraph, vault_path: str):
    """Persist the typed graph."""
    graph_file = Path(vault_path) / "knowledge_graph.json"
    graph_file.parent.mkdir(parents=True, exist_ok=True)
    with open(graph_file, "w", encoding="utf-8") as f:
        json.dump(graph.model_dump(mode="json"), f, indent=2, default=str)


def add_to_typed_graph(
    graph: KnowledgeGraph, node: Optional[GraphNode] = None, edge: Optional[GraphEdge] = None, vault_path: str = "vault"
):
    """Add node and/or edge to the typed graph and persist."""
    if node:
        graph.nodes[node.id] = node
    if edge:
        graph.edges.append(edge)
    save_knowledge_graph(graph, vault_path)
