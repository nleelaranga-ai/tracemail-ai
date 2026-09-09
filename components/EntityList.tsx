import { Link2, Globe2, Network } from "lucide-react";
import type { AiResult, ThreatResult } from "@/types";

const ICON = { url: Link2, ip: Network, domain: Globe2 } as const;

export function EntityList({
  entities,
  threatResults
}: {
  entities: AiResult["entities"];
  threatResults: ThreatResult[];
}) {
  function threatFor(value: string) {
    return threatResults.find((t) => t.value === value);
  }

  return (
    <div className="rounded border border-bg-border bg-bg-raised p-5">
      <h3 className="font-display text-sm font-semibold uppercase tracking-wide text-ink-muted">
        Extracted entities
      </h3>
      <ul className="mt-4 space-y-2">
        {entities.map((e, i) => {
          const Icon = ICON[e.type];
          const threat = threatFor(e.value);
          return (
            <li
              key={i}
              className="flex items-center justify-between gap-3 rounded border border-bg-border px-3 py-2"
            >
              <div className="flex min-w-0 items-center gap-2">
                <Icon className="h-3.5 w-3.5 flex-none text-ink-faint" />
                <span className="truncate font-mono text-xs">{e.value}</span>
              </div>
              {threat && (
                <span
                  className={`flex-none rounded px-2 py-0.5 font-mono text-[10px] uppercase ${
                    threat.malicious
                      ? "bg-verdict-phishing/10 text-verdict-phishing"
                      : threat.reputation === "suspicious"
                      ? "bg-verdict-suspicious/10 text-verdict-suspicious"
                      : "bg-verdict-safe/10 text-verdict-safe"
                  }`}
                >
                  {threat.reputation}
                </span>
              )}
            </li>
          );
        })}
        {entities.length === 0 && (
          <li className="text-sm text-ink-muted">No entities extracted for this case.</li>
        )}
      </ul>
    </div>
  );
}
