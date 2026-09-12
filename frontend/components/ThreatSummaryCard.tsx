"use client";
import React from "react";
import { ShieldAlert, ShieldCheck, MapPin, Globe, Mail, Calendar } from "lucide-react";
import type { Investigation } from "@/types";

interface Props {
  investigation: Investigation;
}

export function ThreatSummaryCard({ investigation }: Props) {
  const score = investigation.threat_score ?? investigation.threatScore ?? investigation.aiResult?.phishingScore ?? 0;
  const rawRisk = investigation.risk_level ?? investigation.riskLevel ?? (score >= 85 ? "Critical" : score >= 65 ? "High" : score >= 35 ? "Medium" : "Low");
  const risk = rawRisk.charAt(0).toUpperCase() + rawRisk.slice(1);

  const isCritical = risk.toLowerCase() === "critical";
  const isHigh = risk.toLowerCase() === "high";
  const isMedium = risk.toLowerCase() === "medium";

  const strokeColor = isCritical
    ? "#ef4444"
    : isHigh
    ? "#f97316"
    : isMedium
    ? "#eab308"
    : "#10b981";

  const badgeBg = isCritical
    ? "bg-red-500/10 text-red-400 border-red-500/30 shadow-[0_0_12px_rgba(239,68,68,0.2)]"
    : isHigh
    ? "bg-orange-500/10 text-orange-400 border-orange-500/30 shadow-[0_0_12px_rgba(249,115,22,0.2)]"
    : isMedium
    ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/30";

  const originCity = investigation.origin_city || investigation.threat_intel?.geoip?.city || "Frankfurt";
  const originCountry = investigation.origin_country || investigation.threat_intel?.geoip?.country || "Germany";
  const originIp = investigation.origin_ip || investigation.threat_intel?.geoip?.ip || "185.220.101.4";

  const radius = 46;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="relative overflow-hidden rounded-xl border border-bg-border bg-gradient-to-b from-bg-raised to-bg p-6 shadow-lg">
      <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
        {/* Left: Animated Score Gauge */}
        <div className="flex items-center gap-6">
          <div className="relative flex h-32 w-32 flex-none items-center justify-center">
            <svg className="h-full w-full -rotate-90 transform" viewBox="0 0 110 110">
              <circle
                cx="55"
                cy="55"
                r={radius}
                className="stroke-bg-surface"
                strokeWidth="9"
                fill="transparent"
              />
              <circle
                cx="55"
                cy="55"
                r={radius}
                stroke={strokeColor}
                strokeWidth="9"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="transparent"
                style={{ transition: "stroke-dashoffset 1s ease-in-out" }}
              />
            </svg>
            <div className="absolute flex flex-col items-center justify-center text-center">
              <span className="font-display text-3xl font-bold tracking-tight text-ink">{score}</span>
              <span className="text-[10px] font-medium uppercase tracking-wider text-ink-muted">/ 100</span>
            </div>
          </div>

          <div>
            <div className="flex items-center gap-2">
              <span className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold uppercase tracking-wider ${badgeBg}`}>
                {score >= 65 ? <ShieldAlert className="h-3.5 w-3.5" /> : <ShieldCheck className="h-3.5 w-3.5" />}
                {risk} Risk
              </span>
              <span className="font-mono text-xs text-ink-faint">Case: {investigation.id}</span>
            </div>

            <h2 className="mt-2 text-xl font-bold text-ink">
              {investigation.subject || "Email Threat Assessment"}
            </h2>
            <p className="mt-1 font-mono text-xs text-ink-muted">
              Verdict: <span className="font-semibold uppercase text-ink">{investigation.verdict || investigation.aiResult?.verdict || "ANALYZED"}</span>
            </p>
          </div>
        </div>

        {/* Right: Dynamic Origin Geo & Forensic Details */}
        <div className="grid grid-cols-2 gap-3 border-t border-bg-border pt-4 sm:grid-cols-2 lg:border-l lg:border-t-0 lg:pl-6 lg:pt-0">
          <div className="flex items-center gap-2.5 rounded-lg border border-bg-border bg-bg-surface/50 p-2.5">
            <MapPin className="h-4 w-4 text-trace" />
            <div className="min-w-0">
              <p className="text-[11px] uppercase tracking-wider text-ink-muted">Attack Origin</p>
              <p className="truncate font-mono text-xs font-semibold text-ink">
                {originCity}, {originCountry}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 rounded-lg border border-bg-border bg-bg-surface/50 p-2.5">
            <Globe className="h-4 w-4 text-trace" />
            <div className="min-w-0">
              <p className="text-[11px] uppercase tracking-wider text-ink-muted">Origin IP</p>
              <p className="truncate font-mono text-xs font-semibold text-ink">{originIp}</p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 rounded-lg border border-bg-border bg-bg-surface/50 p-2.5">
            <Mail className="h-4 w-4 text-trace" />
            <div className="min-w-0">
              <p className="text-[11px] uppercase tracking-wider text-ink-muted">Sender</p>
              <p className="truncate font-mono text-xs font-semibold text-ink" title={investigation.sender}>
                {investigation.sender || "Unknown"}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2.5 rounded-lg border border-bg-border bg-bg-surface/50 p-2.5">
            <Calendar className="h-4 w-4 text-trace" />
            <div className="min-w-0">
              <p className="text-[11px] uppercase tracking-wider text-ink-muted">Analyzed At</p>
              <p className="truncate font-mono text-xs text-ink">
                {new Date(investigation.receivedAt || Date.now()).toLocaleDateString()}
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
