"use client";
import Link from "next/link";
import { useEffect } from "react";
import { useRouter } from "next/navigation";
import { Loader2, ChevronRight } from "lucide-react";
import { Navbar } from "@/components/Navbar";
import { UploadBox } from "@/components/UploadBox";
import { VerdictBadge } from "@/components/StatusBadge";
import { useAuth } from "@/hooks/useAuth";
import { useInvestigations } from "@/hooks/useInvestigation";

export default function DashboardPage() {
  const { isAuthenticated, ready } = useAuth();
  const router = useRouter();
  const { data, isLoading } = useInvestigations();

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
        <h1 className="font-display text-2xl font-semibold">New investigation</h1>
        <p className="mt-1 text-sm text-ink-muted">
          Upload a raw <span className="font-mono">.eml</span> file to trace, analyze, and score it.
        </p>

        <div className="mt-6 max-w-xl">
          <UploadBox />
        </div>

        <div className="mt-12">
          <h2 className="font-display text-sm font-semibold uppercase tracking-wide text-ink-muted">
            Recent cases
          </h2>
          <div className="mt-4 divide-y divide-bg-border rounded border border-bg-border">
            {isLoading && (
              <div className="flex items-center gap-2 px-4 py-6 text-ink-muted">
                <Loader2 className="h-4 w-4 animate-spin" /> Loading cases…
              </div>
            )}
            {!isLoading && data?.length === 0 && (
              <p className="px-4 py-6 text-sm text-ink-muted">No investigations yet — upload your first email above.</p>
            )}
            {data?.slice(0, 5).map((inv) => (
              <Link
                key={inv.id}
                href={`/investigation/${inv.id}`}
                className="flex items-center justify-between gap-4 px-4 py-3 transition-colors hover:bg-bg-raised"
              >
                <div className="min-w-0">
                  <p className="truncate text-sm">{inv.subject}</p>
                  <p className="truncate font-mono text-xs text-ink-muted">{inv.sender}</p>
                </div>
                <div className="flex flex-none items-center gap-3">
                  {inv.aiResult && <VerdictBadge verdict={inv.aiResult.verdict} score={inv.aiResult.phishingScore} />}
                  <ChevronRight className="h-4 w-4 text-ink-faint" />
                </div>
              </Link>
            ))}
          </div>
          {data && data.length > 5 && (
            <Link href="/reports" className="mt-3 inline-block text-sm text-trace hover:underline">
              View all {data.length} cases →
            </Link>
          )}
        </div>
      </main>
    </div>
  );
}
