"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Navbar } from "@/components/Navbar";
import { api } from "@/services/api";
import { Users, ShieldAlert, Target, Terminal, ChevronRight, Globe, Layers } from "lucide-react";

export default function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listCampaigns()
      .then((res) => {
        setCampaigns(res);
        if (res && res.length > 0) {
          setSelectedId(res[0].id);
        }
      })
      .catch((err) => console.error("Failed to load campaigns:", err))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    if (selectedId) {
      api.getCampaignDetail(selectedId)
        .then(setDetail)
        .catch((err) => console.error("Failed to load campaign detail:", err));
    }
  }, [selectedId]);

  return (
    <div className="min-h-screen bg-bg">
      <Navbar />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
        <div className="border-b border-bg-border pb-6">
          <div className="flex items-center gap-2">
            <Layers className="h-5 w-5 text-trace" />
            <h1 className="font-display text-2xl font-bold text-ink">Campaign Intelligence & Correlation 2.0</h1>
          </div>
          <p className="mt-1 text-sm text-ink-muted">
            Proactive attack wave clustering grouping distributed phishing incidents by targeted brand, domain homoglyphs, and threat actors.
          </p>
        </div>

        <div className="mt-8 grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Campaign List */}
          <div className="space-y-3">
            <h3 className="font-display text-sm font-semibold text-ink-muted uppercase tracking-wider">Identified Attack Waves</h3>
            {loading && <div className="p-4 text-xs text-ink-muted">Correlating investigation telemetry…</div>}
            {campaigns.map((c) => {
              const isSelected = selectedId === c.id;
              const isPhish = c.verdict === "phishing";
              return (
                <button
                  key={c.id}
                  onClick={() => setSelectedId(c.id)}
                  className={`w-full text-left p-4 rounded-xl border transition-all ${
                    isSelected
                      ? "border-trace bg-trace/10 shadow-sm"
                      : "border-bg-border bg-bg-surface hover:bg-bg-raised"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-bold text-sm text-ink">{c.name}</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                      isPhish ? "bg-red-500/20 text-red-400 border border-red-500/30" : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                    }`}>
                      {c.risk_level}
                    </span>
                  </div>
                  <p className="text-xs text-ink-muted mt-1 font-mono">Actor: {c.threat_actor}</p>
                  <div className="mt-3 flex items-center justify-between text-xs text-ink-faint font-mono">
                    <span>{c.total_emails} Correlated Incidents</span>
                    <span className="text-trace font-bold">Threat: {c.threat_score}/100</span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Campaign Detail View */}
          <div className="lg:col-span-2">
            {detail ? (
              <div className="rounded-xl border border-bg-border bg-bg-surface p-6 shadow-sm">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-bg-border pb-4">
                  <div>
                    <h2 className="font-display text-lg font-bold text-ink">{detail.name}</h2>
                    <p className="text-xs text-ink-muted font-mono mt-0.5">Target Brand: <span className="text-ink font-bold">{detail.target_brand}</span> | Threat Actor: {detail.threat_actor}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-3 py-1 rounded-full text-xs font-bold font-mono bg-red-500/10 text-red-400 border border-red-500/20">
                      Severity: {detail.threat_score}/100
                    </span>
                  </div>
                </div>

                {/* Prescriptive Playbook */}
                <div className="mt-6 rounded-lg border border-trace/30 bg-trace/5 p-4">
                  <div className="flex items-center gap-2 text-xs font-bold uppercase font-mono text-trace">
                    <Terminal className="h-4 w-4" /> Incident Response Playbook (SOC Directive)
                  </div>
                  <ul className="mt-3 space-y-1.5 text-xs text-ink list-disc list-inside">
                    {detail.playbook?.map((p: string, idx: number) => (
                      <li key={idx} className="leading-relaxed">{p}</li>
                    ))}
                  </ul>
                </div>

                {/* Associated Incidents */}
                <div className="mt-6">
                  <h4 className="font-display text-sm font-semibold text-ink">Correlated Attack Wave Timeline</h4>
                  <div className="mt-3 divide-y divide-bg-border rounded-lg border border-bg-border">
                    {detail.timeline?.map((t: any, idx: number) => (
                      <div key={idx} className="p-3 text-xs flex items-center justify-between hover:bg-bg-raised transition">
                        <div>
                          <span className="font-semibold text-ink">{t.event}</span>
                          <p className="text-ink-muted font-mono mt-0.5 text-[11px]">{t.detail}</p>
                        </div>
                        <span className="text-[10px] font-mono text-ink-faint">{t.timestamp ? new Date(t.timestamp).toLocaleTimeString() : ""}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            ) : (
              <div className="rounded-xl border border-bg-border bg-bg-surface p-8 text-center text-sm text-ink-muted">
                Select a campaign on the left to view comprehensive forensic dossier and threat actor correlation.
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
}
