"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Loader2, ArrowLeft, Map as MapIcon, Clock, Share2, Shield, ShieldCheck, Activity, ListOrdered } from "lucide-react";
import { clsx } from "clsx";
import { Navbar } from "@/components/Navbar";
import { ThreatSummaryCard } from "@/components/ThreatSummaryCard";
import { ThreatIntelCards } from "@/components/ThreatIntelCards";
import { AISummaryCard } from "@/components/AISummaryCard";
import { IOCChips } from "@/components/IOCChips";
import { MapPanel } from "@/components/MapPanel";
import { TimelinePanel } from "@/components/TimelinePanel";
import { GraphPanel } from "@/components/GraphPanel";
import { AttackGraph } from "@/components/AttackGraph";
import { ExplainabilityMeter } from "@/components/ExplainabilityMeter";
import { ReportButton } from "@/components/ReportButton";
import { useAuth } from "@/hooks/useAuth";
import { useInvestigation } from "@/hooks/useInvestigation";
import Link from "next/link";

const TABS = [
  { key: "map", label: "Geospatial Attack Path", icon: MapIcon },
  { key: "timeline", label: "Investigation Timeline", icon: Clock },
  { key: "graph", label: "Attack Topology Graph", icon: Share2 }
] as const;

export default function InvestigationPage() {
  const { id } = useParams<{ id: string }>();
  const { isAuthenticated, ready } = useAuth();
  const router = useRouter();
  const [tab, setTab] = useState<(typeof TABS)[number]["key"]>("map");
  const { data: inv, isLoading, isError } = useInvestigation(id);

  useEffect(() => {
    if (ready && !isAuthenticated) router.replace("/login");
  }, [ready, isAuthenticated, router]);

  if (!ready || !isAuthenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-ink-muted" />
      </div>
    );
  }

  const score = inv?.threat_score ?? inv?.threatScore ?? inv?.aiResult?.phishingScore ?? 0;
  const risk = inv?.risk_level ?? inv?.riskLevel ?? (score >= 85 ? "Critical" : score >= 65 ? "High" : score >= 35 ? "Medium" : "Low");
  const originCity = inv?.origin_city || inv?.city || inv?.threat_intel?.geoip?.city || (score < 30 ? "Origin Host" : "Suspicious Node");
  const originCountry = inv?.origin_country || inv?.country || inv?.threat_intel?.geoip?.country || (score < 30 ? "Verified Origin" : "External Network");
  const originIp = inv?.origin_ip || inv?.ip || inv?.threat_intel?.geoip?.ip || "127.0.0.1";
  const originLat = inv?.latitude ?? inv?.threat_intel?.geoip?.latitude ?? 20.5937;
  const originLon = inv?.longitude ?? inv?.threat_intel?.geoip?.longitude ?? 78.9629;

  return (
    <div className="min-h-screen bg-bg">
      <Navbar />
      <main className="mx-auto max-w-6xl px-6 py-10">
        <div className="flex items-center justify-between">
          <Link href="/dashboard" className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-ink-muted hover:text-trace transition">
            <ArrowLeft className="h-3.5 w-3.5" /> Back to Upload Dashboard
          </Link>
          {inv && <ReportButton investigationId={inv.id} />}
        </div>

        {isLoading && (
          <div className="mt-16 flex flex-col items-center justify-center gap-3 text-ink-muted">
            <Loader2 className="h-8 w-8 animate-spin text-trace" />
            <p className="font-mono text-sm">Retrieving full telemetry and investigation details…</p>
          </div>
        )}

        {isError && (
          <div className="mt-10 rounded-xl border border-red-500/30 bg-red-500/10 p-6 text-center text-red-400">
            <h3 className="font-bold text-sm">Could not load investigation {id}</h3>
            <p className="mt-1 text-xs">Verify backend server status or network connection.</p>
          </div>
        )}

        {inv && (
          <div className="mt-6 space-y-8">
            {/* 1. Master Threat Summary Card */}
            <ThreatSummaryCard investigation={inv} />

            {inv.status !== "complete" ? (
              <div className="flex items-center gap-3 rounded-xl border border-bg-border bg-bg-raised px-6 py-6 text-sm text-ink-muted">
                <Loader2 className="h-5 w-5 animate-spin text-trace" />
                <div>
                  <p className="font-medium text-ink">Investigation status: <span className="font-mono text-trace">{inv.status}</span></p>
                  <p className="text-xs text-ink-muted mt-0.5">Deep telemetry analysis in progress. Indicators and scores will refresh dynamically.</p>
                </div>
              </div>
            ) : (
              <>
                {/* 2. Threat Intelligence Live Feeds Grid */}
                <ThreatIntelCards
                  threatIntel={inv.threat_intel || inv.threatIntel}
                  originCity={originCity}
                  originCountry={originCountry}
                  originIp={originIp}
                  domain={inv.sender ? inv.sender.split("@")[1] : undefined}
                />

                {/* 3. AI Forensic Reasoning Summary */}
                <AISummaryCard
                  aiAnalysis={inv.ai_analysis || inv.aiAnalysis}
                  verdict={inv.aiResult?.verdict}
                  explanation={inv.aiResult?.explanation}
                  confidence={inv.ai_analysis?.confidence}
                />

                {/* 4. Extracted Indicators of Compromise (IOC Chips) */}
                <IOCChips
                  iocs={inv.iocs}
                  fallbackEntities={inv.entities || inv.aiResult?.entities}
                />

                {/* 4.5 AI Explainability Breakdown (SIH 26106 Master Plan v2) */}
                <ExplainabilityMeter investigationId={inv.id} />

                {/* 4.6 Incident Response Remediation Plan & Chain of Custody (SIH 26106 Root Causes 13 & 15) */}
                {inv.action_items && inv.action_items.length > 0 && (
                  <div className="rounded-xl border border-trace/20 bg-bg-surface/40 p-6 shadow-lg">
                    <div className="flex items-center justify-between border-b border-bg-border pb-3">
                      <h3 className="text-sm font-bold uppercase tracking-wider text-ink flex items-center gap-2">
                        <ShieldCheck className="h-4 w-4 text-trace" />
                        Incident Response Remediation Plan
                      </h3>
                      {inv.evidence_hash && (
                        <span className="font-mono text-[10px] text-ink-muted bg-bg-raised px-2.5 py-1 rounded border border-bg-border">
                          SHA-256: {inv.evidence_hash.substring(0, 16)}...{inv.evidence_hash.substring(inv.evidence_hash.length - 8)}
                        </span>
                      )}
                    </div>
                    <ul className="mt-4 space-y-2 text-xs">
                      {inv.action_items.map((item: string, idx: number) => (
                        <li key={idx} className="flex items-start gap-2.5 text-ink-muted">
                          <span className="text-trace font-mono font-bold">{idx + 1}.</span>
                          <span className="text-ink">{item}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* 5. Visualization Workspace (Map / Timeline / Attack Graph) */}
                <div className="rounded-xl border border-bg-border bg-bg-surface/30 p-6 shadow-lg">
                  <div className="flex gap-2 border-b border-bg-border pb-2">
                    {TABS.map((t) => (
                      <button
                        key={t.key}
                        onClick={() => setTab(t.key)}
                        className={clsx(
                          "flex items-center gap-2 rounded-lg px-4 py-2.5 text-xs font-semibold uppercase tracking-wider transition-all",
                          tab === t.key
                            ? "border border-trace/30 bg-trace/10 text-trace shadow-sm"
                            : "text-ink-muted hover:bg-bg-raised hover:text-ink"
                        )}
                      >
                        <t.icon className="h-4 w-4" />
                        {t.label}
                      </button>
                    ))}
                  </div>
                  <div className="pt-6">
                    {tab === "map" && (
                      <MapPanel
                        investigationId={inv.id}
                        originLat={originLat}
                        originLon={originLon}
                        originCity={originCity}
                        originCountry={originCountry}
                        threatScore={score}
                        riskLevel={risk}
                        originIp={originIp}
                      />
                    )}
                    {tab === "timeline" && (
                      <TimelinePanel
                        investigationId={inv.id}
                        timeline={inv.timeline}
                      />
                    )}
                    {tab === "graph" && (
                      <div className="space-y-6">
                        <AttackGraph graph={inv.attack_graph as any} />
                        <GraphPanel investigationId={inv.id} />
                      </div>
                    )}
                  </div>
                </div>
              </>
            )}
          </div>

        )}
      </main>
    </div>
  );
}
