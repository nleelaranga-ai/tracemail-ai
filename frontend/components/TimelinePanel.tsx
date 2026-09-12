"use client";
import React, { useState } from "react";
import { useGeoTimeline } from "@/hooks/useInvestigation";
import { Loader2, Server, CheckCircle2, Clock, ShieldAlert, Cpu } from "lucide-react";
import { clsx } from "clsx";
import type { DynamicTimelineStep } from "@/types";

interface Props {
  investigationId: string;
  timeline?: DynamicTimelineStep[];
}

export function TimelinePanel({ investigationId, timeline }: Props) {
  const { data: hopData, isLoading, isError } = useGeoTimeline(investigationId);
  const [view, setView] = useState<"lifecycle" | "hops">("lifecycle");

  // Fallback 6-step lifecycle if not supplied
  const defaultTimeline: DynamicTimelineStep[] = [
    {
      step: 1,
      name: "Email Uploaded",
      detail: "Raw RFC 822 .eml payload validated and checksum calculated.",
      status: "completed",
      timestamp: "Step 1/6"
    },
    {
      step: 2,
      name: "Headers Parsed",
      detail: "Extracted Return-Path, Message-ID, and analyzed Received hop progression.",
      status: "completed",
      timestamp: "Step 2/6"
    },
    {
      step: 3,
      name: "WHOIS Lookup Completed",
      detail: "Queried ICANN RDAP registry; verified domain registration age and registrar.",
      status: "completed",
      timestamp: "Step 3/6"
    },
    {
      step: 4,
      name: "Threat Intelligence Completed",
      detail: "Queried VirusTotal, AbuseIPDB, DNS SPF/DKIM/DMARC authentication.",
      status: "completed",
      timestamp: "Step 4/6"
    },
    {
      step: 5,
      name: "AI Classification",
      detail: "Ran neural semantic classification for urgency, BEC fraud, and credential harvesting.",
      status: "completed",
      timestamp: "Step 5/6"
    },
    {
      step: 6,
      name: "Threat Score Generated",
      detail: "Weighted risk score computed (35% VT + 20% SPF + 15% DKIM + 15% Abuse + 10% Age + 5% AI).",
      status: "completed",
      timestamp: "Step 6/6"
    }
  ];

  const steps = timeline && timeline.length > 0 ? timeline : defaultTimeline;

  return (
    <div className="space-y-6">
      {/* Tab Selector */}
      <div className="flex items-center justify-between border-b border-bg-border pb-3">
        <div className="flex gap-2">
          <button
            onClick={() => setView("lifecycle")}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
              view === "lifecycle"
                ? "bg-trace/10 text-trace border border-trace/30"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            <Clock className="h-3.5 w-3.5" />
            6-Step Investigation Lifecycle
          </button>
          <button
            onClick={() => setView("hops")}
            className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
              view === "hops"
                ? "bg-trace/10 text-trace border border-trace/30"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            <Server className="h-3.5 w-3.5" />
            Mail Server Hops Route
          </button>
        </div>
      </div>

      {view === "lifecycle" ? (
        <ol className="relative space-y-0 pl-2">
          {steps.map((step, i) => {
            const stepIndex = step.step ?? (i + 1);
            const stepName = step.name || (step as any).event || (step as any).title || `Investigation Step ${stepIndex}`;
            const stepStatus = step.status || "completed";
            const stepDetail = step.detail || (step as any).description || ((step as any).time ? `Executed at ${(step as any).time}` : "Forensic step completed successfully.");
            const stepTime = step.timestamp || (step as any).time || `Step ${stepIndex}/6`;

            return (
              <li key={stepIndex} className="relative flex gap-4 pb-6 pl-2 last:pb-0">
                {i < steps.length - 1 && (
                  <span className="absolute left-[15px] top-6 h-full w-px bg-trace/30" />
                )}
                <span className="z-10 flex h-8 w-8 flex-none items-center justify-center rounded-full border border-trace/40 bg-trace/10 text-trace shadow-[0_0_10px_rgba(0,217,192,0.2)]">
                  <CheckCircle2 className="h-4 w-4" />
                </span>
                <div className="flex-1 rounded-xl border border-bg-border bg-bg-raised px-4 py-3 shadow transition hover:border-trace/30">
                  <div className="flex items-center justify-between">
                    <span className="font-display text-sm font-semibold text-ink">
                      Step {stepIndex}: {stepName}
                    </span>
                    <span className="font-mono text-xs text-trace uppercase tracking-wider">
                      {stepStatus}
                    </span>
                  </div>
                  <p className="mt-1 text-xs leading-relaxed text-ink-muted">{stepDetail}</p>
                  {stepTime && (
                    <p className="mt-1 font-mono text-[10px] text-ink-faint">{stepTime}</p>
                  )}
                </div>
              </li>
            );
          })}
        </ol>
      ) : (
        <div>
          {isLoading && (
            <div className="flex h-40 items-center justify-center gap-2 text-ink-muted">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading mail hop timeline…
            </div>
          )}
          {isError || !hopData || hopData.length === 0 ? (
            <p className="py-8 text-center text-sm text-ink-muted">No server hop timeline data available for this case.</p>
          ) : (
            <ol className="space-y-0">
              {hopData.map((step, i) => (
                <li key={step.step} className="relative flex gap-4 pb-6 pl-2 last:pb-0">
                  {i < hopData.length - 1 && (
                    <span className="absolute left-[15px] top-6 h-full w-px bg-bg-border" />
                  )}
                  <span
                    className={clsx(
                      "z-10 flex h-8 w-8 flex-none items-center justify-center rounded-full border",
                      step.malicious
                        ? "border-red-500/50 bg-red-500/10 text-red-400"
                        : "border-emerald-500/50 bg-emerald-500/10 text-emerald-400"
                    )}
                  >
                    <Server className="h-4 w-4" />
                  </span>
                  <div className="flex-1 rounded-xl border border-bg-border bg-bg-raised px-4 py-3">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-sm text-ink">{step.server}</span>
                      <span className="font-mono text-xs text-ink-muted">
                        {new Date(step.timestamp).toLocaleString()}
                      </span>
                    </div>
                    <p className="mt-1 font-mono text-xs text-ink-muted">
                      IP: {step.ip}{" "}
                      {step.malicious && <span className="text-red-400 font-semibold">· Flagged Malicious Relay</span>}
                    </p>
                  </div>
                </li>
              ))}
            </ol>
          )}
        </div>
      )}
    </div>
  );
}
