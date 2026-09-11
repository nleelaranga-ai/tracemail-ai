"use client";
import { Building2, ShieldAlert, AlertTriangle, CheckCircle } from "lucide-react";
import type { DepartmentMetric } from "@/types";

interface ThreatHeatmapProps {
  departments: DepartmentMetric[];
}

export function ThreatHeatmap({ departments }: ThreatHeatmapProps) {
  return (
    <div className="rounded-xl border border-bg-border bg-bg-surface overflow-hidden shadow-sm">
      <div className="border-b border-bg-border px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Building2 className="h-5 w-5 text-trace" />
          <h3 className="font-display text-base font-semibold text-ink">Department Vulnerability & Threat Matrix</h3>
        </div>
        <span className="text-xs text-ink-muted font-mono">5 Departments Audited</span>
      </div>

      <div className="divide-y divide-bg-border">
        {departments.map((d, i) => {
          const isCrit = d.riskLevel === "Critical";
          const isHigh = d.riskLevel === "High";
          return (
            <div key={i} className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-bg-raised transition-colors">
              <div className="min-w-0 max-w-md">
                <div className="flex items-center gap-2.5">
                  <span className="font-semibold text-sm text-ink">{d.department}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                    isCrit ? "bg-red-500/20 text-red-400 border border-red-500/30" : isHigh ? "bg-amber-500/20 text-amber-400 border border-amber-500/30" : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                  }`}>
                    {d.riskLevel}
                  </span>
                </div>
                <p className="mt-1 text-xs text-ink-muted">
                  Primary Threat Vector: <span className="text-ink">{d.topAttackType}</span>
                </p>
                <p className="mt-0.5 text-[11px] font-mono text-ink-faint">
                  Targets: {d.primaryTarget}
                </p>
              </div>

              <div className="flex items-center gap-6 flex-shrink-0">
                <div className="text-right">
                  <span className="text-[11px] font-mono text-ink-muted">Inbound Attacks</span>
                  <p className="text-base font-bold font-mono text-ink">{d.threatCount} attacks</p>
                </div>
                <div className="text-right">
                  <span className="text-[11px] font-mono text-ink-muted">Phishing Blocks</span>
                  <p className="text-base font-bold font-mono text-red-400">{d.phishingCount}</p>
                </div>
                <div className="w-24 text-right">
                  <span className="text-[11px] font-mono text-ink-muted">Risk Exposure</span>
                  <div className="mt-1 h-2 w-full rounded-full bg-bg-border overflow-hidden">
                    <div
                      className={`h-full rounded-full ${isCrit ? "bg-red-500" : isHigh ? "bg-amber-500" : "bg-emerald-500"}`}
                      style={{ width: `${d.vulnerabilityScore}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
