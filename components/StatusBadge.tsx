import { clsx } from "clsx";
import type { Verdict } from "@/types";

const CONFIG: Record<Verdict, { label: string; classes: string }> = {
  phishing: { label: "Phishing", classes: "bg-verdict-phishing/10 text-verdict-phishing border-verdict-phishing/40" },
  suspicious: { label: "Suspicious", classes: "bg-verdict-suspicious/10 text-verdict-suspicious border-verdict-suspicious/40" },
  safe: { label: "Safe", classes: "bg-verdict-safe/10 text-verdict-safe border-verdict-safe/40" }
};

export function VerdictBadge({ verdict, score }: { verdict: Verdict; score: number }) {
  const c = CONFIG[verdict];
  return (
    <span className={clsx("inline-flex items-center gap-2 rounded border px-3 py-1 font-mono text-sm", c.classes)}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {c.label.toUpperCase()} · {score}%
    </span>
  );
}
