"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  addEdge,
  useNodesState,
  useEdgesState,
  type Edge,
  type Node,
  type Connection,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { CompositionNode, CompositionEdge, MarketplaceCapability } from "@/types";

interface DagVisualizerProps {
  capabilities: MarketplaceCapability[];
  onChange?: (nodes: CompositionNode[], edges: CompositionEdge[]) => void;
  simulationValid?: boolean | null;
}

const runtimeColor: Record<string, string> = {
  "pi-semantic-recon": "#238636",
  "pi-semantic-diff": "#1f6feb",
  "pi-semantic-validator": "#8957e5",
  "pi-blast-radius": "#d29922",
  "pi-interoperability-layer": "#a371f7",
  "pi-extension-governor": "#f0883e",
  "pi-catalog-integration": "#3fb950",
};

export default function DagVisualizer({ capabilities, onChange, simulationValid }: DagVisualizerProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selectedRuntime, setSelectedRuntime] = useState<string>("pi-semantic-recon");
  const [selectedOperation, setSelectedOperation] = useState<string>("VALIDATE");

  const filteredCapabilities = useMemo(
    () => capabilities.filter((c) => c.runtime === selectedRuntime),
    [capabilities, selectedRuntime]
  );

  const addNode = useCallback(() => {
    const id = `node_${Date.now()}`;
    const newNode: Node = {
      id,
      position: { x: Math.random() * 300 + 50, y: Math.random() * 200 + 50 },
      data: {
        label: `${selectedRuntime}::${selectedOperation}`,
        runtime: selectedRuntime,
        operation: selectedOperation,
      },
      style: {
        background: runtimeColor[selectedRuntime] || "#30363d",
        color: "#fff",
        border: simulationValid === false ? "2px solid #da3633" : simulationValid === true ? "2px solid #238636" : "1px solid #30363d",
        borderRadius: 8,
        padding: 10,
        width: 200,
      },
    };
    setNodes((nds) => [...nds, newNode]);
  }, [selectedRuntime, selectedOperation, setNodes, simulationValid]);

  const onConnect = useCallback(
    (connection: Connection) => {
      const newEdge: Edge = {
        id: `e_${connection.source}-${connection.target}`,
        source: connection.source!,
        target: connection.target!,
        label: "SEQ",
        animated: true,
        style: { stroke: "#8b949e" },
      };
      setEdges((eds) => addEdge(newEdge, eds));
    },
    [setEdges]
  );

  useEffect(() => {
    if (!onChange) return;
    const compNodes: CompositionNode[] = nodes.map((n) => ({
      node_id: n.id,
      runtime: n.data.runtime,
      operation: n.data.operation,
      artifacts: [],
      required_schema_version: "1.0.0",
      bounds: {},
      dependencies: edges.filter((e) => e.target === n.id).map((e) => e.source),
    }));
    const compEdges: CompositionEdge[] = edges.map((e) => ({
      source: e.source,
      target: e.target,
      edge_type: "SEQUENTIAL",
    }));
    onChange(compNodes, compEdges);
  }, [nodes, edges, onChange]);

  return (
    <div className="flex flex-col gap-3 h-full">
      <div className="flex items-center gap-3 p-3 bg-[var(--card)] rounded-lg border border-[var(--border)]">
        <select
          className="bg-[var(--input)] text-[var(--foreground)] rounded px-2 py-1 text-sm border border-[var(--border)]"
          value={selectedRuntime}
          onChange={(e) => setSelectedRuntime(e.target.value)}
        >
          {Array.from(new Set(capabilities.map((c) => c.runtime))).map((r) => (
            <option key={r} value={r}>{r}</option>
          ))}
        </select>
        <select
          className="bg-[var(--input)] text-[var(--foreground)] rounded px-2 py-1 text-sm border border-[var(--border)]"
          value={selectedOperation}
          onChange={(e) => setSelectedOperation(e.target.value)}
        >
          {filteredCapabilities.map((c) => (
            <option key={c.operation} value={c.operation}>{c.operation}</option>
          ))}
        </select>
        <button
          onClick={addNode}
          className="bg-[var(--primary)] text-[var(--primary-foreground)] px-3 py-1 rounded text-sm hover:opacity-90"
        >
          Add Node
        </button>
      </div>
      <div className="flex-1 border border-[var(--border)] rounded-lg bg-[var(--card)] min-h-[400px]">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          fitView
        >
          <Background color="#30363d" gap={16} />
          <Controls />
          <MiniMap nodeColor={(n) => runtimeColor[n.data?.runtime] || "#30363d"} />
        </ReactFlow>
      </div>
    </div>
  );
}
