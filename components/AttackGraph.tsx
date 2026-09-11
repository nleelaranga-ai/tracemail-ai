"use client";
import { useState } from "react";
import { Share2, X, ShieldAlert, ShieldCheck, Server, Globe, ExternalLink, Activity } from "lucide-react";
import { api } from "@/services/api";
import type { AttackGraph as AttackGraphType, GraphNodeDetail } from "@/types";

interface AttackGraphProps {
  graph: AttackGraphType;
}

export function AttackGraph({ graph }: AttackGraphProps) {
  const [selectedNode, setSelectedNode] = useState<string | null>(null);
  const [nodeDetail, setNodeDetail] = useState<GraphNodeDetail | null>(null);
  const [loading, setLoading] = useState(false);

  const handleNodeClick = async (label: string) => {
    setSelectedNode(label);
    setLoading(true);
    try {
      const detail = await api.getNodeDetail(label);
      setNodeDetail(detail);
    } catch (err) {
      console.warn("Could not load node detail:", err);
    } finally {
      setLoading(false);
    }
  };

  const nodes = graph?.nodes || [];
  const edges = graph?.edges || [];

  return (
    <div className="relative rounded-xl border border-bg-border bg-bg-surface overflow-hidden shadow-sm">
      <div className="flex items-center justify-between border-b border-bg-border px-5 py-3.5 bg-bg-surface/90">
        <div className="flex items-center gap-2 text-sm font-semibold text-ink">
          <Share2 className="h-4 w-4 text-trace" />
          Interactive Attack Topology Graph
        </div>
        <span className="text-xs text-ink-muted">Click any node to inspect WHOIS, ASN & Reputation</span>
      </div>

      <div className="p-6">
        <div className="flex flex-wrap items-center justify-center gap-6 sm:gap-12 py-8">
          {nodes.map((node, idx) => {
            const isMalicious = node.malicious ?? (node.id === "sender" || node.id.includes("hop1"));
            const isSelected = selectedNode === node.label;
            return (
              <div key={node.id} className="flex items-center gap-4">
                <button
                  onClick={() => handleNodeClick(node.label)}
                  className={`group relative flex flex-col items-center p-4 rounded-xl border transition-all text-center max-w-[200px] ${
                    isSelected
                      ? "border-trace bg-trace/15 ring-2 ring-trace/30 scale-105"
                      : isMalicious
                      ? "border-red-500/40 bg-red-500/5 hover:border-red-500/70"
                      : "border-emerald-500/40 bg-emerald-500/5 hover:border-emerald-500/70"
                  }`}
                >
                  <div className={`p-3 rounded-full mb-2 ${isMalicious ? "bg-red-500/20 text-red-400" : "bg-emerald-500/20 text-emerald-400"}`}>
                    {node.type === "sender" ? <ShieldAlert className="h-5 w-5" /> : node.type === "relay" ? <Server className="h-5 w-5" /> : <ShieldCheck className="h-5 w-5" />}
                  </div>
                  <span className="text-xs uppercase font-mono tracking-wider text-ink-muted">{node.type}</span>
                  <span className="mt-1 text-xs font-semibold text-ink break-all">{node.label}</span>
                  <span className={`mt-1 text-[10px] font-mono px-2 py-0.5 rounded-full ${isMalicious ? "bg-red-500/20 text-red-400" : "bg-emerald-500/20 text-emerald-400"}`}>
                    {isMalicious ? "Malicious (Click)" : "Clean (Click)"}
                  </span>
                </button>
                {idx < nodes.length - 1 && (
                  <div className="hidden sm:flex items-center text-ink-muted">
                    <div className="h-0.5 w-6 sm:w-10 bg-gradient-to-r from-bg-border to-trace/60" />
                    <span className="text-xs font-mono text-trace">►</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Slide-out or Bottom Node Detail Drawer */}
      {selectedNode && (
        <div className="border-t border-bg-border bg-bg-raised/95 p-5 transition-all">
          <div className="flex items-center justify-between border-b border-bg-border/60 pb-3">
            <div className="flex items-center gap-2">
              <Globe className="h-4 w-4 text-trace" />
              <h4 className="font-display text-sm font-semibold text-ink">Entity Forensic Telemetry: {selectedNode}</h4>
            </div>
            <button onClick={() => setSelectedNode(null)} className="rounded p-1 text-ink-muted hover:bg-bg-border hover:text-ink">
              <X className="h-4 w-4" />
            </button>
          </div>

          {loading && (
            <div className="py-6 text-center text-xs font-mono text-ink-muted">
              Querying WHOIS, RDAP, ASN reputation and route telemetry…
            </div>
          )}

          {!loading && nodeDetail && (
            <div className="mt-4 grid grid-cols-1 sm:grid-cols-3 gap-4 text-xs">
              <div className="rounded-lg border border-bg-border bg-bg/80 p-3">
                <span className="text-ink-muted font-mono uppercase tracking-wider text-[10px]">Reputation & Status</span>
                <p className={`mt-1 font-bold ${nodeDetail.reputation === "malicious" ? "text-red-400" : "text-emerald-400"}`}>
                  {nodeDetail.verdict} ({nodeDetail.abuseScore}/100 Abuse Score)
                </p>
                <p className="mt-1 text-ink-muted font-mono">ASN: {nodeDetail.asn}</p>
              </div>

              <div className="rounded-lg border border-bg-border bg-bg/80 p-3">
                <span className="text-ink-muted font-mono uppercase tracking-wider text-[10px]">WHOIS & Registration</span>
                <p className="mt-1 font-semibold text-ink">Registrar: {nodeDetail.whois.registrar}</p>
                <p className="mt-1 text-ink-muted">Registered: {nodeDetail.whois.creationDate}</p>
              </div>

              <div className="rounded-lg border border-bg-border bg-bg/80 p-3">
                <span className="text-ink-muted font-mono uppercase tracking-wider text-[10px]">Geographic Routing</span>
                <p className="mt-1 font-semibold text-ink">{nodeDetail.city}, {nodeDetail.country}</p>
                <p className="mt-1 text-ink-muted">Observed in email routing path</p>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
