"use client";
import { useGeoTimeline } from "@/hooks/useInvestigation";
import { Loader2, Server } from "lucide-react";
import { clsx } from "clsx";

export function TimelinePanel({ investigationId }: { investigationId: string }) {
  const { data, isLoading, isError } = useGeoTimeline(investigationId);

  if (isLoading) {
    return (
      <div className="flex h-40 items-center justify-center gap-2 text-ink-muted">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading mail hop timeline…
      </div>
    );
  }
  if (isError || !data || data.length === 0) {
    return <p className="py-8 text-center text-sm text-ink-muted">No timeline data available for this case yet.</p>;
  }

  return (
    <ol className="space-y-0">
      {data.map((step, i) => (
        <li key={step.step} className="relative flex gap-4 pb-6 pl-2 last:pb-0">
          {i < data.length - 1 && (
            <span className="absolute left-[15px] top-6 h-full w-px bg-bg-border" />
          )}
          <span
            className={clsx(
              "z-10 flex h-8 w-8 flex-none items-center justify-center rounded-full border",
              step.malicious
                ? "border-verdict-phishing/50 bg-verdict-phishing/10 text-verdict-phishing"
                : "border-verdict-safe/50 bg-verdict-safe/10 text-verdict-safe"
            )}
          >
            <Server className="h-4 w-4" />
          </span>
          <div className="flex-1 rounded border border-bg-border bg-bg-raised px-4 py-3">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm">{step.server}</span>
              <span className="font-mono text-xs text-ink-muted">
                {new Date(step.timestamp).toLocaleString()}
              </span>
            </div>
            <p className="mt-1 font-mono text-xs text-ink-muted">
              {step.ip} {step.malicious && <span className="text-verdict-phishing">· flagged malicious</span>}
            </p>
          </div>
        </li>
      ))}
    </ol>
  );
}
