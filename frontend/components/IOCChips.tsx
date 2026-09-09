"use client";
import React, { useState } from "react";
import { Link2, Globe2, Network, Hash, Paperclip, Copy, Check } from "lucide-react";
import type { IOCChipItem } from "@/types";

interface Props {
  iocs?: IOCChipItem[];
  fallbackEntities?: { urls?: string[]; ips?: string[]; domains?: string[] } | any[];
}

export function IOCChips({ iocs = [], fallbackEntities }: Props) {
  const [copiedValue, setCopiedValue] = useState<string | null>(null);

  // Normalize IOC list
  let items: IOCChipItem[] = [...iocs];

  if (items.length === 0 && fallbackEntities) {
    if (Array.isArray(fallbackEntities)) {
      items = fallbackEntities.map((e) => ({
        type: e.type || "url",
        value: e.value || "",
        malicious: e.malicious ?? (e.type === "url" || e.type === "ip")
      }));
    } else if (typeof fallbackEntities === "object") {
      const urls = fallbackEntities.urls || [];
      const ips = fallbackEntities.ips || [];
      const domains = fallbackEntities.domains || [];

      urls.forEach((u: string) => items.push({ type: "url", value: u, malicious: true }));
      ips.forEach((ip: string) => items.push({ type: "ip", value: ip, malicious: true }));
      domains.forEach((d: string) => items.push({ type: "domain", value: d, malicious: false }));
    }
  }

  const handleCopy = (value: string) => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(value);
      setCopiedValue(value);
      setTimeout(() => setCopiedValue(null), 2000);
    }
  };

  const getIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "url":
        return <Link2 className="h-3.5 w-3.5" />;
      case "ip":
        return <Network className="h-3.5 w-3.5" />;
      case "domain":
        return <Globe2 className="h-3.5 w-3.5" />;
      case "hash":
        return <Hash className="h-3.5 w-3.5" />;
      case "attachment":
        return <Paperclip className="h-3.5 w-3.5" />;
      default:
        return <Link2 className="h-3.5 w-3.5" />;
    }
  };

  return (
    <div className="rounded-xl border border-bg-border bg-bg-raised p-6 shadow-lg">
      <div className="flex items-center justify-between border-b border-bg-border pb-3">
        <h3 className="font-display text-sm font-semibold uppercase tracking-wider text-ink-muted">
          Extracted Indicators of Compromise (IOCs)
        </h3>
        <span className="font-mono text-xs text-ink-muted">{items.length} indicators extracted</span>
      </div>

      {items.length === 0 ? (
        <p className="mt-4 text-center text-sm text-ink-muted">No external indicators extracted for this case.</p>
      ) : (
        <div className="mt-4 flex flex-wrap gap-2.5">
          {items.map((ioc, idx) => {
            const isCopied = copiedValue === ioc.value;
            const isMalicious = ioc.malicious;

            return (
              <div
                key={idx}
                className={`group flex items-center gap-2 rounded-lg border px-3 py-1.5 transition-colors ${
                  isMalicious
                    ? "border-red-500/30 bg-red-500/5 hover:bg-red-500/10 text-red-300"
                    : "border-bg-border bg-bg-surface hover:bg-bg-surface/80 text-ink"
                }`}
              >
                <span className={isMalicious ? "text-red-400" : "text-trace"}>
                  {getIcon(ioc.type)}
                </span>
                <span className="text-[10px] font-bold uppercase tracking-wider text-ink-faint">
                  {ioc.type}
                </span>
                <span className="font-mono text-xs font-medium max-w-[280px] truncate" title={ioc.value}>
                  {ioc.value}
                </span>
                {isMalicious && (
                  <span className="rounded bg-red-500/20 px-1.5 py-0.5 text-[9px] font-bold uppercase text-red-400">
                    FLAGGED
                  </span>
                )}
                <button
                  onClick={() => handleCopy(ioc.value)}
                  className="ml-1 text-ink-faint hover:text-ink transition-colors"
                  title="Copy indicator"
                >
                  {isCopied ? (
                    <Check className="h-3 w-3 text-emerald-400" />
                  ) : (
                    <Copy className="h-3 w-3 opacity-60 group-hover:opacity-100" />
                  )}
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
