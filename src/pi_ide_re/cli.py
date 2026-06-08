"""
Simple REPL / CLI for querying the typed KnowledgeGraph.

Usage:
    python -m src.pi_ide_re.cli
    or
    python -m src.pi_ide_re.cli --query "open_deep_research" --limit 10
"""

import argparse
import cmd
import json
from typing import Optional

from src.pi_ide_re.graph_schema import load_knowledge_graph
from src.pi_micro_agents.pi_graph_query_engine import GraphQueryInput, PiGraphQueryEngine


class GraphREPL(cmd.Cmd):
    intro = "Antigravity Knowledge Graph REPL. Type 'help' or 'help <command>' for more info.\n"
    prompt = "graph> "

    def __init__(self):
        super().__init__()
        self.kg = load_knowledge_graph("vault")
        self.engine = PiGraphQueryEngine()
        self.update_prompt()

    def update_prompt(self):
        node_count = len(self.kg.nodes)
        self.prompt = f"graph ({node_count} nodes)> "

    def do_reload(self, arg):
        """Reload the knowledge graph from disk."""
        self.kg = load_knowledge_graph("vault")
        self.update_prompt()
        print("Knowledge graph reloaded.")

    def do_search(self, arg):
        """Search nodes by title or content. Usage: search <term>"""
        if not arg:
            print("Usage: search <term>")
            return
        result = self.engine.query(GraphQueryInput(graph=self.kg, query_type="search", query_value=arg, limit=15))
        self._print_results(result.results)

    def do_open(self, arg):
        """List open Deep Research items ready for review. Usage: open"""
        result = self.engine.query(GraphQueryInput(graph=self.kg, query_type="open_deep_research", limit=20))
        self._print_results(result.results)

    def do_neighbors(self, arg):
        """Show neighbors of a node. Usage: neighbors <node_id or title>"""
        if not arg:
            print("Usage: neighbors <node_id>")
            return
        # Try to find best matching node
        node_id = self._resolve_node_id(arg)
        if not node_id:
            print(f"Node not found: {arg}")
            return
        result = self.engine.query(GraphQueryInput(graph=self.kg, query_type="neighbors", node_id=node_id))
        self._print_results(result.results)

    def do_nodes(self, arg):
        """List nodes by type or tag. Usage: nodes type=deep-research | nodes tag=protocol"""
        if "=" not in arg:
            print("Usage: nodes type=deep-research  or  nodes tag=llm-surface")
            return
        key, value = arg.split("=", 1)
        qtype = "nodes_by_type" if key.strip() == "type" else "nodes_by_tag"
        result = self.engine.query(
            GraphQueryInput(graph=self.kg, query_type=qtype, query_value=value.strip(), limit=20)
        )
        self._print_results(result.results)

    def do_promote(self, arg):
        """Promote a Deep Research stub (demo). Usage: promote <title>"""
        if not arg:
            print("Usage: promote <stub title>")
            return
        from src.pi_ide_re.ingest import promote_deep_research_stub

        try:
            new_path = promote_deep_research_stub(arg, vault_path="vault")
            print(f"Promoted to: {new_path}")
            self.do_reload("")
        except Exception as e:
            print(f"Promotion failed: {e}")

    def do_graph(self, arg):
        """Show basic graph stats."""
        print(f"Nodes: {len(self.kg.nodes)}")
        print(f"Edges: {len(self.kg.edges)}")
        types = {}
        for node in self.kg.nodes.values():
            types[node.type] = types.get(node.type, 0) + 1
        print("By type:", types)

    def do_exit(self, arg):
        """Exit the REPL."""
        print("Goodbye.")
        return True

    def default(self, line):
        if line.lower() in ("exit", "quit", "q"):
            return self.do_exit("")
        print(f"Unknown command: {line}. Type 'help' for available commands.")

    def _print_results(self, results):
        if not results:
            print("No results.")
            return
        for r in results[:15]:
            if isinstance(r, dict):
                title = r.get("title") or r.get("id") or str(r)
                extra = ""
                if "priority" in r:
                    extra += f" (priority: {r['priority']})"
                if "agents" in r and r["agents"]:
                    extra += f" agents: {len(r['agents'])}"
                print(f"- {title}{extra}")
            else:
                print(f"- {r}")

    def _resolve_node_id(self, name: str) -> Optional[str]:
        name_lower = name.lower()
        for nid, node in self.kg.nodes.items():
            if name_lower in nid.lower() or name_lower in node.title.lower():
                return nid
        return None


def main():
    parser = argparse.ArgumentParser(description="Antigravity Knowledge Graph REPL")
    parser.add_argument("--query", help="Run a single query and exit")
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()

    if args.query:
        kg = load_knowledge_graph("vault")
        engine = PiGraphQueryEngine()
        # Simple heuristic for query type
        if "open" in args.query.lower():
            qtype = "open_deep_research"
        elif "search" in args.query.lower():
            qtype = "search"
            args.query = args.query.replace("search", "").strip()
        else:
            qtype = "search"
        result = engine.query(GraphQueryInput(graph=kg, query_type=qtype, query_value=args.query, limit=args.limit))
        print(json.dumps(result.results, indent=2))
    else:
        GraphREPL().cmdloop()


if __name__ == "__main__":
    main()
