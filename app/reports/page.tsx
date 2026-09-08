"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Loader2, ChevronRight, Search } from "lucide-react";
import { Navbar } from "@/components/Navbar";
import { VerdictBadge } from "@/components/StatusBadge";
import { ReportButton } from "@/components/ReportButton";
import { useAuth } from "@/hooks/useAuth";
import { useInvestigations } from "@/hooks/useInvestigation";

export default function ReportsPage() {
  const { isAuthenticated, ready } = useAuth();
  const router = useRouter();
  const { data, isLoading } = useInvestigations();
  const [query, setQuery] = useState("");

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

  const filtered = (data || []).filter(
    (i) =>
      i.subject.toLowerCase().includes(query.toLowerCase()) ||
      i.sender.toLowerCase().includes(query.toLowerCase())
  );

  return (
    <div className="min-h-screen">
      <Navbar />
      <main className="mx-auto max-w-6xl px-6 py-10">
        <h1 className="font-display text-2xl font-semibold">Investigation history</h1>
        <p className="mt-1 text-sm text-ink-muted">Every case you've traced, with one-click report downloads.</p>

        <div className="relative mt-6 max-w-sm">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-faint" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by sender or subject…"
            className="w-full rounded border border-bg-border bg-bg-surface py-2 pl-9 pr-3 text-sm outline-none focus:border-trace"
          />
        </div>

        <div className="mt-6 overflow-hidden rounded border border-bg-border">
          <table className="w-full text-left text-sm">
            <thead className="bg-bg-surface text-xs uppercase tracking-wide text-ink-muted">
              <tr>
                <th className="px-4 py-3 font-medium">Subject</th>
                <th className="px-4 py-3 font-medium">Sender</th>
                <th className="px-4 py-3 font-medium">Received</th>
                <th className="px-4 py-3 font-medium">Verdict</th>
                <th className="px-4 py-3 font-medium">Report</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody className="divide-y divide-bg-border">
              {isLoading && (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-ink-muted">
                    <Loader2 className="mr-2 inline h-4 w-4 animate-spin" /> Loading history…
                  </td>
                </tr>
              )}
              {!isLoading && filtered.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-ink-muted">
                    No matching investigations.
                  </td>
                </tr>
              )}
              {filtered.map((inv) => (
                <tr key={inv.id} className="hover:bg-bg-raised">
                  <td className="max-w-[220px] truncate px-4 py-3">{inv.subject}</td>
                  <td className="max-w-[200px] truncate px-4 py-3 font-mono text-xs text-ink-muted">{inv.sender}</td>
                  <td className="px-4 py-3 font-mono text-xs text-ink-muted">
                    {new Date(inv.receivedAt).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-3">
                    <VerdictBadge
                      verdict={inv.aiResult?.verdict || "phishing"}
                      score={inv.threat_score ?? inv.threatScore ?? inv.aiResult?.phishingScore ?? 0}
                    />
                  </td>
                  <td className="px-4 py-3">
                    <ReportButton investigationId={inv.id} />
                  </td>
                  <td className="px-4 py-3 text-right">
                    <Link href={`/investigation/${inv.id}`} className="inline-flex items-center gap-1 text-trace hover:underline">
                      Open <ChevronRight className="h-3.5 w-3.5" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </main>
    </div>
  );
}
