"use client";
import { useMemo } from "react";
import ReactFlow, {
  Background,
  Controls,
  Handle,
  Position,
  MarkerType,
  type Edge,
  type Node
} from "reactflow";
import "reactflow/dist/style.css";
import {
  Mail,
  Server,
  UserRound,
  ShieldAlert,
  ShieldCheck,
  type LucideIcon
} from "lucide-react";
import type { AttackGraph, GraphNode as GraphNodeData } from "@/types";

type GraphNodeType = GraphNodeData["type"];

interface GraphNodeCardData {
  label: string;
  type: GraphNodeType;
  malicious?: boolean;
}

interface TypeMetaEntry {
  icon: LucideIcon;
  label: string;
  color: string;
}

const TYPE_META: Record<GraphNodeType, TypeMetaEntry> = {
  sender: { icon: Mail, label: "Sender", color: "#F5A524" },
  relay: { icon: Server, label: "Relay hop", color: "#00D9C0" },
  recipient: { icon: UserRound, label: "Recipient", color: "#22C55E" }
};

function GraphNodeCard({ data }: { data: GraphNodeCardData }) {
  const meta = TYPE_META[data.type];
  const Icon = meta.icon;
  const borderColor = data.malicious ? "#F4415C" : meta.color;

  return (
    <div className="w-[220px] rounded border bg-[#10141C] px-3 py-2.5" style={{ borderColor, borderWidth: 1.5 }}>
      <Handle type="target" position={Position.Left} style={{ background: "#5B6478", border: "none" }} />

      <div className="flex items-center gap-2">
        <Icon className="h-3.5 w-3.5 flex-none" style={{ color: borderColor }} />
        <span className="font-mono text-[11px] uppercase tracking-wide text-ink-muted">{meta.label}</span>
      </div>

      <p className="mt-1.5 truncate font-mono text-xs text-ink" title={data.label}>
        {data.label}
      </p>

      <div className="mt-1.5 flex items-center gap-1.5">
        {data.malicious ? (
          <span className="flex items-center gap-1 rounded bg-verdict-phishing/10 px-1.5 py-0.5 font-mono text-[10px] uppercase text-verdict-phishing">
            <ShieldAlert className="h-3 w-3" /> malicious
          </span>
        ) : (
          <span className="flex items-center gap-1 rounded bg-verdict-safe/10 px-1.5 py-0.5 font-mono text-[10px] uppercase text-verdict-safe">
            <ShieldCheck className="h-3 w-3" /> clean
          </span>
        )}
      </div>

      <Handle type="source" position={Position.Right} style={{ background: "#5B6478", border: "none" }} />
    </div>
  );
}

const nodeTypes = { graphNode: GraphNodeCard };

export function FlowGraph({ graph }: { graph: AttackGraph }) {
  const nodes: Node<GraphNodeCardData>[] = useMemo(
    () =>
      graph.nodes.map((n, i) => ({
        id: n.id,
        type: "graphNode",
        position: { x: i * 280, y: 0 },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        data: { label: n.label, type: n.type, malicious: n.malicious }
      })),
    [graph.nodes]
  );

  const edges: Edge[] = useMemo(
    () =>
      graph.edges.map((e, i) => ({
        id: `e${i}`,
        source: e.from,
        target: e.to,
        type: "smoothstep",
        animated: true,
        style: { stroke: "#5B6478" },
        markerEnd: { type: MarkerType.ArrowClosed, color: "#5B6478" }
      })),
    [graph.edges]
  );

  return (
    <div style={{ height: 420 }}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        proOptions={{ hideAttribution: true }}
        nodesDraggable={false}
        nodesConnectable={false}
      >
        <Background color="#212836" gap={24} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}