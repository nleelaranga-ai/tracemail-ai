"use client";
import { useEffect, useState } from "react";
import { ShieldAlert, CheckCircle2, AlertTriangle, Info, Sparkles, Scale } from "lucide-react";
import { api } from "@/services/api";
import type { ExplainabilityResponse } from "@/types";

interface ExplainabilityMeterProps {
  investigationId: string;
}

export function ExplainabilityMeter({ investigationId }: ExplainabilityMeterProps) {
  const [data, setData] = useState<ExplainabilityResponse | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let mounted = true;
    api.getExplainability(investigationId)
      .then((res) => {
        if (mounted) setData(res);
      })
      .catch((err) => console.warn("Failed to load AI explainability:", err))
      .finally(() => {
        if (mounted) setLoading(false);
      });
    return () => {
      mounted = false;
    };
  }, [investigationId]);

  if (loading) {
    return (
      <div className="rounded-xl border border-bg-border bg-bg-surface p-6">
        <div className="flex items-center gap-2 text-ink-muted text-sm animate-pulse">
          <Sparkles className="h-4 w-4 text-trace" /> Computing AI signal weights and explainability matrix…
        </div>
      </div>
    );
  }

  if (!data || !data.reasons || data.reasons.length === 0) return null;

  const isPhish = data.score >= 65;
  const isSafe = data.score <= 35;

  return (
    <div className="rounded-xl border border-bg-border bg-bg-surface p-6 shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-bg-border pb-4">
        <div className="flex items-center gap-2.5">
          <div className={`p-2 rounded-lg ${isPhish ? "bg-red-500/10 text-red-400" : isSafe ? "bg-emerald-500/10 text-emerald-400" : "bg-amber-500/10 text-amber-400"}`}>
            <Scale className="h-5 w-5" />
          </div>
          <div>
            <h3 className="font-display text-base font-semibold text-ink">AI Decision Transparency & Weights</h3>
            <p className="text-xs text-ink-muted">Mathematically grounded signals contributing to overall verdict</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <span className="text-xs font-mono text-ink-muted">Confidence Model: </span>
            <span className="font-mono text-xs font-semibold text-trace">{(data.confidence * 100).toFixed(0)}% Certainty</span>
          </div>
          <div className={`px-3 py-1 rounded-full text-xs font-bold font-mono ${isPhish ? "bg-red-500/20 text-red-400 border border-red-500/30" : isSafe ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-amber-500/20 text-amber-400 border border-amber-500/30"}`}>
            Score: {data.score}/100
          </div>
        </div>
      </div>

      <p className="mt-4 text-xs sm:text-sm text-ink-muted">{data.summary}</p>

      <div className="mt-5 space-y-3.5">
        {data.reasons.map((r, i) => (
          <div key={i} className="rounded-lg border border-bg-border/60 bg-bg/60 p-3.5 transition-colors hover:bg-bg-raised/80">
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase tracking-wider bg-bg-border text-ink-muted">
                  {r.category}
                </span>
                <p className="truncate text-xs sm:text-sm font-semibold text-ink">{r.label}</p>
              </div>
              <span className={`font-mono text-xs font-bold px-2 py-0.5 rounded ${r.weight > 0 ? "text-red-400 bg-red-500/10" : "text-emerald-400 bg-emerald-500/10"}`}>
                {r.weight > 0 ? `+${r.weight}` : r.weight} pts
              </span>
            </div>
            <p className="mt-1 text-xs text-ink-muted leading-relaxed">{r.description}</p>
            <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-bg-border/40">
              <div
                className={`h-full rounded-full ${isPhish ? "bg-gradient-to-r from-amber-500 to-red-500" : "bg-emerald-500"}`}
                style={{ width: `${Math.min(100, Math.max(10, Math.abs(r.weight) * 3))}%` }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
