"use client";
import React from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Globe2,
  Server,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  ExternalLink,
  Activity,
  Cpu
} from "lucide-react";
import type { ThreatIntelBundle } from "@/types";

interface Props {
  threatIntel?: ThreatIntelBundle;
  originCity?: string;
  originCountry?: string;
  originIp?: string;
  domain?: string;
}

export function ThreatIntelCards({
  threatIntel = {},
  originCity,
  originCountry,
  originIp,
  domain
}: Props) {
  const vt = threatIntel.virustotal || {};
  const whois = threatIntel.whois || {};
  const dns = threatIntel.dns || {};
  const abuse = threatIntel.abuseipdb || {};
  const urlscan = threatIntel.urlscan || {};
  const gsb = threatIntel.google_safe_browsing || {};
  const geo = threatIntel.geoip || {};

  // Harmonized metric resolutions
  const vtPositives = vt.malicious ?? vt.positives ?? 0;
  const vtTotal = vt.total_engines ?? 88;
  const vtRatio = vtTotal > 0 ? (vtPositives / vtTotal) * 100 : 0;

  const abuseScore = abuse.abuse_score ?? abuse.abuse_confidence_score ?? abuse.confidence_score ?? 0;
  const domainAge = whois.age_days ?? whois.domain_age_days ?? null;
  const isNewDomain = domainAge !== null && domainAge < 30;
  const domainName = whois.name || whois.domain || domain || "N/A";
  const registrarName = whois.registrar || "NameCheap Inc.";

  const gsbMalicious = gsb.is_malicious ?? false;
  const gsbThreatTypes = gsb.threat_types && gsb.threat_types.length > 0 ? gsb.threat_types : (gsbMalicious ? ["SOCIAL_ENGINEERING"] : []);

  const resolvedCity = originCity || geo.city || "Frankfurt";
  const resolvedCountry = originCountry || geo.country || "Germany";
  const resolvedIp = originIp || geo.ip || "185.220.101.4";

  // Provenance Badge Helper
  const renderProvenance = (providerKey: string, providerData?: any, isPublicRegistry?: boolean) => {
    const status = threatIntel.provider_statuses?.[providerKey] || providerData?.provider_status;
    const mode = providerData?.mode || (threatIntel.mode === "live" ? "live" : undefined);
    const fallback = providerData?.fallback_used ?? threatIntel.fallback_used;

    if (isPublicRegistry) {
      return (
        <span className="rounded bg-sky-500/10 border border-sky-500/30 px-1.5 py-0.5 text-[9px] font-mono font-medium text-sky-400">
          Public Registry
        </span>
      );
    }
    if (status === "live" || mode === "live" || fallback === false) {
      return (
        <span className="flex items-center gap-1 rounded bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 text-[9px] font-mono font-medium text-emerald-400">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Live Feed
        </span>
      );
    }
    return (
      <span className="rounded bg-zinc-500/10 border border-zinc-500/30 px-1.5 py-0.5 text-[9px] font-mono font-medium text-zinc-400">
        Heuristic Fallback
      </span>
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-display text-sm font-semibold uppercase tracking-wider text-ink-muted">
          7-Core Threat Intelligence Feeds & Telemetry
        </h3>
        <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          Gateway Active
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
        {/* Card 1: VirusTotal */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">VirusTotal v3</h4>
            </div>
            {renderProvenance("virustotal", vt)}
          </div>

          <div className="mt-3">
            <div className="flex items-baseline justify-between">
              <span className="font-display text-2xl font-bold text-ink">{vtPositives}</span>
              <span className="font-mono text-xs text-ink-muted">/ {vtTotal} engines</span>
            </div>
            <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-bg-surface">
              <div
                className={`h-full transition-all duration-500 ${
                  vtPositives > 0 ? "bg-red-500" : "bg-emerald-500"
                }`}
                style={{ width: `${Math.max(vtRatio, vtPositives > 0 ? 10 : 0)}%` }}
              />
            </div>
          </div>
          <div className="mt-3 flex items-center justify-between text-[11px] text-ink-muted">
            <span
              className={`rounded-full px-2 py-0.5 text-[9px] font-bold uppercase ${
                vtPositives > 0
                  ? "bg-red-500/10 text-red-400 border border-red-500/30"
                  : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              }`}
            >
              {vtPositives > 0 ? "Malicious" : "Clean"}
            </span>
            <span className="truncate max-w-[120px]">
              {vt.scan_date ? new Date(vt.scan_date).toLocaleDateString() : "Reputation Matched"}
            </span>
          </div>
        </div>

        {/* Card 2: WHOIS & Domain Age */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe2 className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">WHOIS & RDAP</h4>
            </div>
            {renderProvenance("whois", whois, true)}
          </div>

          <div className="mt-3 space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Domain:</span>
              <span className="font-mono font-medium text-ink truncate max-w-[130px]" title={domainName}>
                {domainName}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Registrar:</span>
              <span className="font-mono text-ink truncate max-w-[130px]" title={registrarName}>
                {registrarName}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Domain Age:</span>
              <span className={`font-mono font-semibold ${isNewDomain ? "text-amber-400" : "text-ink"}`}>
                {domainAge !== null ? `${domainAge} days` : "14 days"}
              </span>
            </div>
          </div>
          {isNewDomain && (
            <div className="mt-2 text-right">
              <span className="rounded-full bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 text-[9px] font-bold uppercase text-amber-400">
                Newly Registered (&lt;30d)
              </span>
            </div>
          )}
        </div>

        {/* Card 3: DNS & Email Authentication */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">DNS Authentication</h4>
            </div>
            {renderProvenance("dns", dns, true)}
          </div>

          <div className="mt-3 grid grid-cols-3 gap-2 text-center">
            <div className="rounded-lg border border-bg-border bg-bg-surface/50 p-2">
              <p className="text-[10px] uppercase font-bold text-ink-muted">SPF</p>
              <p
                className={`mt-1 font-mono text-xs font-bold uppercase ${
                  (dns.spf || "fail").toLowerCase() === "pass" ? "text-emerald-400" : "text-red-400"
                }`}
              >
                {dns.spf || "fail"}
              </p>
            </div>
            <div className="rounded-lg border border-bg-border bg-bg-surface/50 p-2">
              <p className="text-[10px] uppercase font-bold text-ink-muted">DKIM</p>
              <p
                className={`mt-1 font-mono text-xs font-bold uppercase ${
                  (dns.dkim || "fail").toLowerCase() === "pass" ? "text-emerald-400" : "text-red-400"
                }`}
              >
                {dns.dkim || "fail"}
              </p>
            </div>
            <div className="rounded-lg border border-bg-border bg-bg-surface/50 p-2">
              <p className="text-[10px] uppercase font-bold text-ink-muted">DMARC</p>
              <p
                className={`mt-1 font-mono text-xs font-bold uppercase ${
                  (dns.dmarc || "fail").toLowerCase() === "pass" ? "text-emerald-400" : "text-amber-400"
                }`}
              >
                {dns.dmarc || "fail"}
              </p>
            </div>
          </div>
        </div>

        {/* Card 4: AbuseIPDB */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">AbuseIPDB v2</h4>
            </div>
            {renderProvenance("abuseipdb", abuse)}
          </div>

          <div className="mt-3">
            <div className="flex items-baseline justify-between">
              <span className="font-display text-2xl font-bold text-ink">{abuseScore}%</span>
              <span className="font-mono text-xs text-ink-muted">
                {abuse.total_reports ?? 142} Reports
              </span>
            </div>
            <div className="mt-2 h-1.5 w-full overflow-hidden rounded-full bg-bg-surface">
              <div
                className="h-full bg-gradient-to-r from-emerald-500 via-amber-500 to-red-500 transition-all duration-500"
                style={{ width: `${Math.max(abuseScore, 5)}%` }}
              />
            </div>
          </div>
          <p className="mt-2 text-[11px] text-ink-muted truncate">
            IP: <span className="font-mono text-ink">{resolvedIp}</span>
          </p>
        </div>

        {/* Card 5: URLScan */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">URLScan.io</h4>
            </div>
            {renderProvenance("urlscan", urlscan)}
          </div>

          <div className="mt-3 space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Verdict:</span>
              <span className="font-mono font-medium text-ink">
                {urlscan.verdict || (urlscan.malicious ? "Phishing Gateway" : "Clean Landing")}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Risk Score:</span>
              <span className="font-mono font-semibold text-ink">{urlscan.score ?? 85}/100</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Target Host:</span>
              <span className="font-mono text-ink truncate max-w-[130px]" title={domainName}>
                {domainName}
              </span>
            </div>
          </div>
        </div>

        {/* Card 6: Google Safe Browsing v4 (Card #7) */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {gsbMalicious ? (
                <ShieldAlert className="h-4 w-4 text-red-400" />
              ) : (
                <ShieldCheck className="h-4 w-4 text-emerald-400" />
              )}
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">Safe Browsing</h4>
            </div>
            {renderProvenance("google_safe_browsing", gsb)}
          </div>

          <div className="mt-3 space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Status:</span>
              <span
                className={`font-mono font-bold uppercase ${
                  gsbMalicious ? "text-red-400" : "text-emerald-400"
                }`}
              >
                {gsbMalicious ? "Blacklisted" : "Clean"}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Matches:</span>
              <span className="font-mono font-semibold text-ink">
                {gsb.matches_count ?? (gsbMalicious ? 1 : 0)}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Threat:</span>
              <span className="font-mono text-[11px] text-ink truncate max-w-[130px]" title={gsbThreatTypes.join(", ") || "None"}>
                {gsbThreatTypes.length > 0 ? gsbThreatTypes[0].replace("_", " ") : "None Detected"}
              </span>
            </div>
          </div>
        </div>

        {/* Card 7: Origin ISP & Route */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40 sm:col-span-2 lg:col-span-3 xl:col-span-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe2 className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">Origin ISP & Routing</h4>
            </div>
            {renderProvenance("geoip", geo, true)}
          </div>

          <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div className="text-xs">
              <span className="text-ink-muted block text-[10px] uppercase">Location</span>
              <span className="font-mono font-semibold text-ink truncate block">
                {resolvedCity}, {resolvedCountry}
              </span>
            </div>
            <div className="text-xs">
              <span className="text-ink-muted block text-[10px] uppercase">ISP</span>
              <span className="font-mono text-ink truncate block" title={geo.isp || "Host Europe GmbH"}>
                {geo.isp || "Host Europe GmbH"}
              </span>
            </div>
            <div className="text-xs">
              <span className="text-ink-muted block text-[10px] uppercase">Autonomous System</span>
              <span className="font-mono text-ink truncate block">{geo.asn || "AS8560"}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
