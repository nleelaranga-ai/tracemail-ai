"use client";
import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { Loader2, ArrowLeft, Map as MapIcon, Clock, Share2 } from "lucide-react";
import { clsx } from "clsx";
import { Navbar } from "@/components/Navbar";
import { VerdictCard } from "@/components/VerdictCard";
import { EntityList } from "@/components/EntityList";
import { MapPanel } from "@/components/MapPanel";
import { TimelinePanel } from "@/components/TimelinePanel";
import { GraphPanel } from "@/components/GraphPanel";
import { ReportButton } from "@/components/ReportButton";
import { useAuth } from "@/hooks/useAuth";
import { useInvestigation } from "@/hooks/useInvestigation";
import Link from "next/link";

const TABS = [
  { key: "map", label: "Map", icon: MapIcon },
  { key: "timeline", label: "Timeline", icon: Clock },
  { key: "graph", label: "Attack graph", icon: Share2 }
] as const;

export default function InvestigationPage() {
  const { id } = useParams<{ id: string }>();
  const { isAuthenticated, ready } = useAuth();
  const router = useRouter();
  const [tab, setTab] = useState<(typeof TABS)[number]["key"]>("map");
  const { data: inv, isLoading, isError } = useInvestigation(id);

  useEffect(() => {
    if (ready && !isAuthenticated) router.replace("/login");
  }, [ready, isAuthenticated, router]);

  if (!ready || !isAuthenticated) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-5 w-5 animate-spin text-ink-muted" />
      </div>
    );
  }

  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="mx-auto max-w-6xl px-6 py-10">
        <Link href="/dashboard" className="flex items-center gap-1.5 text-sm text-ink-muted hover:text-ink">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to upload
        </Link>

        {isLoading && (
          <div className="mt-10 flex items-center gap-2 text-ink-muted">
            <Loader2 className="h-4 w-4 animate-spin" /> Loading investigation…
          </div>
        )}

        {isError && (
          <p className="mt-10 text-sm text-verdict-phishing">
            Could not load this investigation. It may not exist, or the backend is unreachable.
          </p>
        )}

        {inv && (
          <>
            <div className="mt-6 flex flex-wrap items-start justify-between gap-4">
              <div>
                <h1 className="font-display text-2xl font-semibold">{inv.subject}</h1>
                <p className="mt-1 font-mono text-sm text-ink-muted">
                  From {inv.sender} · {new Date(inv.receivedAt).toLocaleString()}
                </p>
              </div>
              <ReportButton investigationId={inv.id} />
            </div>

            {inv.status !== "complete" ? (
              <div className="mt-8 flex items-center gap-2 rounded border border-bg-border bg-bg-raised px-4 py-4 text-sm text-ink-muted">
                <Loader2 className="h-4 w-4 animate-spin" />
                Investigation status: <span className="font-mono">{inv.status}</span> — results will appear once processing completes.
              </div>
            ) : (
              <>
                <div className="mt-8 grid gap-6 md:grid-cols-2">
                  {inv.aiResult && <VerdictCard aiResult={inv.aiResult} />}
                  {inv.aiResult && <EntityList entities={inv.aiResult.entities} threatResults={inv.threatResults} />}
                </div>

                <div className="mt-10">
                  <div className="flex gap-1 border-b border-bg-border">
                    {TABS.map((t) => (
                      <button
                        key={t.key}
                        onClick={() => setTab(t.key)}
                        className={clsx(
                          "flex items-center gap-1.5 border-b-2 px-4 py-2.5 text-sm transition-colors",
                          tab === t.key
                            ? "border-trace text-ink"
                            : "border-transparent text-ink-muted hover:text-ink"
                        )}
                      >
                        <t.icon className="h-3.5 w-3.5" />
                        {t.label}
                      </button>
                    ))}
                  </div>
                  <div className="pt-6">
                    {tab === "map" && <MapPanel investigationId={inv.id} />}
                    {tab === "timeline" && <TimelinePanel investigationId={inv.id} />}
                    {tab === "graph" && <GraphPanel investigationId={inv.id} />}
                  </div>
                </div>
              </>
            )}
          </>
        )}
      </main>
    </div>
  );
}
