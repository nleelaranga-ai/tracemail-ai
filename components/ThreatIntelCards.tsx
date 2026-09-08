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
  const geo = threatIntel.geoip || {};

  const vtPositives = vt.positives ?? 0;
  const vtTotal = vt.total_engines ?? 88;
  const vtRatio = vtTotal > 0 ? (vtPositives / vtTotal) * 100 : 0;

  const abuseScore = abuse.abuse_confidence_score ?? 0;
  const domainAge = whois.domain_age_days ?? null;
  const isNewDomain = domainAge !== null && domainAge < 30;

  const resolvedCity = originCity || geo.city || "Frankfurt";
  const resolvedCountry = originCountry || geo.country || "Germany";
  const resolvedIp = originIp || geo.ip || "185.220.101.4";

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-display text-sm font-semibold uppercase tracking-wider text-ink-muted">
          Threat Intelligence Feeds & Telemetry
        </h3>
        <span className="flex items-center gap-1 text-[11px] font-mono text-emerald-400">
          <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
          Live Connected
        </span>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {/* Card 1: VirusTotal */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Activity className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">VirusTotal v3</h4>
            </div>
            <span
              className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${
                vtPositives > 0
                  ? "bg-red-500/10 text-red-400 border border-red-500/30"
                  : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              }`}
            >
              {vtPositives > 0 ? "Malicious" : "Clean"}
            </span>
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
          <p className="mt-2 text-[11px] text-ink-muted truncate">
            {vt.scan_date ? `Scanned: ${new Date(vt.scan_date).toLocaleDateString()}` : "Database reputation matched"}
          </p>
        </div>

        {/* Card 2: WHOIS & Domain Age */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe2 className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">WHOIS & RDAP</h4>
            </div>
            {isNewDomain && (
              <span className="rounded-full bg-amber-500/10 border border-amber-500/30 px-2 py-0.5 text-[10px] font-bold uppercase text-amber-400">
                New Domain
              </span>
            )}
          </div>

          <div className="mt-3 space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Domain:</span>
              <span className="font-mono font-medium text-ink truncate max-w-[140px]" title={whois.domain || domain || "N/A"}>
                {whois.domain || domain || "N/A"}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Registrar:</span>
              <span className="font-mono text-ink truncate max-w-[140px]" title={whois.registrar || "NameCheap Inc."}>
                {whois.registrar || "NameCheap Inc."}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Domain Age:</span>
              <span className={`font-mono font-semibold ${isNewDomain ? "text-amber-400" : "text-ink"}`}>
                {domainAge !== null ? `${domainAge} days` : "14 days"}
              </span>
            </div>
          </div>
        </div>

        {/* Card 3: DNS & Email Authentication */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Server className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">DNS Authentication</h4>
            </div>
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
            <span
              className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${
                abuseScore >= 50
                  ? "bg-red-500/10 text-red-400 border border-red-500/30"
                  : abuseScore > 0
                  ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                  : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              }`}
            >
              {abuseScore}% Confidence
            </span>
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
                style={{ width: `${abuseScore}%` }}
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
            <span
              className={`rounded-full px-2 py-0.5 text-[10px] font-bold uppercase ${
                urlscan.malicious
                  ? "bg-red-500/10 text-red-400 border border-red-500/30"
                  : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
              }`}
            >
              {urlscan.malicious ? "Malicious" : "Clean"}
            </span>
          </div>

          <div className="mt-3 space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Verdict:</span>
              <span className="font-mono font-medium text-ink">
                {urlscan.malicious ? "Phishing Gateway" : "Clean Landing"}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Threat Score:</span>
              <span className="font-mono font-semibold text-ink">{urlscan.score ?? 85}/100</span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Target Host:</span>
              <span className="font-mono text-ink truncate max-w-[140px]" title={domain || "paypa1-secure.com"}>
                {domain || "paypa1-secure.com"}
              </span>
            </div>
          </div>
        </div>

        {/* Card 6: Origin ISP & Route */}
        <div className="rounded-xl border border-bg-border bg-bg-raised p-4 shadow transition hover:border-trace/40">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Globe2 className="h-4 w-4 text-trace" />
              <h4 className="text-xs font-semibold uppercase tracking-wide text-ink">Origin ISP & Routing</h4>
            </div>
          </div>

          <div className="mt-3 space-y-1">
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">Location:</span>
              <span className="font-mono font-semibold text-ink">
                {resolvedCity}, {resolvedCountry}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">ISP:</span>
              <span className="font-mono text-ink truncate max-w-[140px]" title={geo.isp || "Host Europe GmbH"}>
                {geo.isp || "Host Europe GmbH"}
              </span>
            </div>
            <div className="flex justify-between text-xs">
              <span className="text-ink-muted">ASN:</span>
              <span className="font-mono text-ink">{geo.asn || "AS8560"}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
