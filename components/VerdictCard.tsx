import { AlertTriangle } from "lucide-react";
import type { AiResult } from "@/types";
import { VerdictBadge } from "./StatusBadge";

export function VerdictCard({ aiResult }: { aiResult: AiResult }) {
  return (
    <div className="rounded border border-bg-border bg-bg-raised p-5">
      <div className="flex items-center justify-between">
        <h3 className="font-display text-sm font-semibold uppercase tracking-wide text-ink-muted">
          Phishing verdict
        </h3>
        <VerdictBadge verdict={aiResult.verdict} score={aiResult.phishingScore} />
      </div>
      <div className="mt-4 flex items-start gap-3 rounded border border-bg-border bg-bg px-4 py-3">
        <AlertTriangle className="mt-0.5 h-4 w-4 flex-none text-ink-faint" />
        <p className="text-sm leading-relaxed text-ink-muted">{aiResult.explanation}</p>
      </div>
    </div>
  );
}
