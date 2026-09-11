"use client";
import { useEffect, useState } from "react";
import { Navbar } from "@/components/Navbar";
import { ThreatHeatmap } from "@/components/ThreatHeatmap";
import { api } from "@/services/api";
import type { DepartmentMetric } from "@/types";
import { Building2, ShieldCheck, AlertOctagon, Users } from "lucide-react";

export default function OrgPage() {
  const [departments, setDepartments] = useState<DepartmentMetric[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getOrgHeatmap()
      .then(setDepartments)
      .catch((err) => console.error("Failed to load org heatmap:", err))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="min-h-screen bg-bg">
      <Navbar />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
        <div className="border-b border-bg-border pb-6">
          <div className="flex items-center gap-2">
            <Building2 className="h-5 w-5 text-trace" />
            <h1 className="font-display text-2xl font-bold text-ink">Organization Security Posture Dashboard</h1>
          </div>
          <p className="mt-1 text-sm text-ink-muted">
            Institutional exposure heatmap showing department vulnerability scores, targeted personnel, and attack concentrations.
          </p>
        </div>

        {/* Top Org Stats */}
        <div className="mt-8 grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-5 shadow-sm">
            <span className="text-xs font-mono uppercase tracking-wider text-red-400">Highest Risk Division</span>
            <p className="mt-2 font-display text-xl font-bold text-red-400">Finance & Accounting</p>
            <span className="mt-1 text-xs text-ink-muted">Vulnerability Index: 88/100 (BEC Target)</span>
          </div>
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-5 shadow-sm">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400">Repeated Attack Vector</span>
            <p className="mt-2 font-display text-xl font-bold text-amber-400">Executive Wire Spoofing</p>
            <span className="mt-1 text-xs text-ink-muted">38 blocked wire diversion attempts</span>
          </div>
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 shadow-sm">
            <span className="text-xs font-mono uppercase tracking-wider text-emerald-400">Safest Division</span>
            <p className="mt-2 font-display text-xl font-bold text-emerald-400">Sales & Client Operations</p>
            <span className="mt-1 text-xs text-ink-muted">Vulnerability Index: 28/100 (Low Risk)</span>
          </div>
        </div>

        {/* Heatmap Grid */}
        <div className="mt-8">
          {loading ? (
            <div className="p-8 text-center text-xs text-ink-muted">Aggregating departmental risk indices…</div>
          ) : (
            <ThreatHeatmap departments={departments} />
          )}
        </div>
      </main>
    </div>
  );
}
