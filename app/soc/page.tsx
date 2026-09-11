"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Navbar } from "@/components/Navbar";
import { api } from "@/services/api";
import type { SocOverview } from "@/types";
import { ShieldAlert, AlertTriangle, ShieldCheck, Activity, Globe, Flame, ExternalLink, RefreshCw } from "lucide-react";

export default function SocPage() {
  const [data, setData] = useState<SocOverview | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchOverview = () => {
    setLoading(true);
    api.getSocOverview()
      .then(setData)
      .catch((err) => console.error("Error loading SOC overview:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    fetchOverview();
  }, []);

  return (
    <div className="min-h-screen bg-bg">
      <Navbar />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-bg-border pb-6">
          <div>
            <div className="flex items-center gap-2">
              <span className="flex h-2.5 w-2.5 rounded-full bg-red-500 animate-ping" />
              <span className="font-mono text-xs uppercase tracking-wider text-red-400 font-bold">SOC Live Telemetry Active</span>
            </div>
            <h1 className="mt-1 font-display text-2xl font-bold text-ink">Global Threat Command Center</h1>
            <p className="mt-1 text-sm text-ink-muted">Organization-wide real-time threat telemetry, brand spoofing & attack waves</p>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={fetchOverview}
              className="flex items-center gap-2 rounded-lg border border-bg-border bg-bg-surface px-3 py-2 text-xs font-semibold text-ink hover:bg-bg-raised transition"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh SOC Intel
            </button>
            <Link
              href="/dashboard"
              className="rounded-lg bg-trace px-4 py-2 text-xs font-semibold text-white shadow-sm hover:bg-trace/90 transition"
            >
              + New Email Investigation
            </Link>
          </div>
        </div>

        {/* Metric Cards */}
        <div className="mt-8 grid grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="rounded-xl border border-bg-border bg-bg-surface p-5 shadow-sm">
            <span className="text-xs font-mono uppercase tracking-wider text-ink-muted">Total Scanned</span>
            <p className="mt-2 font-display text-3xl font-bold text-ink">{data?.totalScanned ?? "..."}</p>
            <span className="mt-1 text-[11px] text-ink-muted">Processed through Gateway</span>
          </div>
          <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-5 shadow-sm">
            <span className="text-xs font-mono uppercase tracking-wider text-red-400">Phishing Detected</span>
            <p className="mt-2 font-display text-3xl font-bold text-red-400">{data?.phishingDetected ?? "..."}</p>
            <span className="mt-1 text-[11px] text-red-400/80">Quarantined / High Risk</span>
          </div>
          <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-5 shadow-sm">
            <span className="text-xs font-mono uppercase tracking-wider text-amber-400">Critical Incidents</span>
            <p className="mt-2 font-display text-3xl font-bold text-amber-400">{data?.criticalThreats ?? "..."}</p>
            <span className="mt-1 text-[11px] text-amber-400/80">Score ≥ 85 / BEC Fraud</span>
          </div>
          <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-5 shadow-sm">
            <span className="text-xs font-mono uppercase tracking-wider text-emerald-400">Verified Safe</span>
            <p className="mt-2 font-display text-3xl font-bold text-emerald-400">{data?.safeEmails ?? "..."}</p>
            <span className="mt-1 text-[11px] text-emerald-400/80">Passing Cryptographic SPF/DKIM</span>
          </div>
        </div>

        {/* 2-Column Analytics */}
        <div className="mt-8 grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Top Impersonated Brands */}
          <div className="rounded-xl border border-bg-border bg-bg-surface p-6 shadow-sm">
            <div className="flex items-center justify-between border-b border-bg-border pb-4">
              <h3 className="font-display text-base font-semibold text-ink">Most Impersonated Brands (BEC / Phish)</h3>
              <Flame className="h-4 w-4 text-red-400" />
            </div>
            <div className="mt-4 space-y-3">
              {data?.topBrands?.map((b, i) => (
                <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-bg hover:bg-bg-raised transition">
                  <span className="text-sm font-semibold text-ink">{b.brand}</span>
                  <span className="font-mono text-xs font-bold px-2.5 py-1 rounded bg-red-500/10 text-red-400 border border-red-500/20">
                    {b.count} incidents
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* Top Origin Nations */}
          <div className="rounded-xl border border-bg-border bg-bg-surface p-6 shadow-sm">
            <div className="flex items-center justify-between border-b border-bg-border pb-4">
              <h3 className="font-display text-base font-semibold text-ink">Threat Infrastructure Origins</h3>
              <Globe className="h-4 w-4 text-trace" />
            </div>
            <div className="mt-4 space-y-3">
              {data?.topCountries?.map((c, i) => (
                <div key={i} className="flex items-center justify-between p-2.5 rounded-lg bg-bg hover:bg-bg-raised transition">
                  <span className="text-sm font-semibold text-ink">{c.country}</span>
                  <span className="font-mono text-xs font-bold px-2.5 py-1 rounded bg-bg-border text-ink-muted">
                    {c.count} relays
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Live Incident Stream */}
        <div className="mt-8 rounded-xl border border-bg-border bg-bg-surface overflow-hidden shadow-sm">
          <div className="border-b border-bg-border px-6 py-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-trace" />
              <h3 className="font-display text-base font-semibold text-ink">Recent Real-Time Alerts</h3>
            </div>
            <Link href="/reports" className="text-xs text-trace hover:underline font-semibold">
              View All History →
            </Link>
          </div>
          <div className="divide-y divide-bg-border">
            {data?.recentAlerts?.map((a) => {
              const isPhish = a.verdict === "phishing";
              return (
                <div key={a.id} className="p-4 flex items-center justify-between gap-4 hover:bg-bg-raised transition">
                  <div className="min-w-0 max-w-xl">
                    <p className="truncate text-sm font-semibold text-ink">{a.subject}</p>
                    <p className="truncate text-xs font-mono text-ink-muted mt-0.5">{a.sender}</p>
                  </div>
                  <div className="flex items-center gap-4 flex-shrink-0">
                    <span className={`px-2.5 py-1 rounded text-xs font-mono font-bold uppercase ${
                      isPhish ? "bg-red-500/20 text-red-400 border border-red-500/30" : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                    }`}>
                      {a.verdict} ({a.score}/100)
                    </span>
                    <Link
                      href={`/investigation/${a.id}`}
                      className="p-1 text-ink-muted hover:text-trace transition"
                    >
                      <ExternalLink className="h-4 w-4" />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </main>
    </div>
  );
}
