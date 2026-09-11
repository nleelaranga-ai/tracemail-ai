"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Navbar } from "@/components/Navbar";
import { api } from "@/services/api";
import type { InboxEmailItem } from "@/types";
import { Mail, RefreshCw, ShieldAlert, CheckCircle2, AlertTriangle, ExternalLink, Shield } from "lucide-react";

export default function InboxPage() {
  const [emails, setEmails] = useState<InboxEmailItem[]>([]);
  const [connected, setConnected] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadInbox = () => {
    setLoading(true);
    api.getInboxResults()
      .then(setEmails)
      .catch((err) => console.error("Failed to fetch inbox:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadInbox();
  }, []);

  const handleScan = async () => {
    setScanning(true);
    try {
      await api.scanInbox("analyst@tracemail.ai");
      loadInbox();
    } catch (err) {
      console.error("Scan error:", err);
    } finally {
      setScanning(false);
    }
  };

  const handleConnect = async () => {
    try {
      await api.connectGoogleInbox("analyst@tracemail.ai");
      setConnected(true);
      loadInbox();
    } catch (err) {
      console.error("Connect error:", err);
    }
  };

  return (
    <div className="min-h-screen bg-bg">
      <Navbar />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-bg-border pb-6">
          <div>
            <div className="flex items-center gap-2">
              <Mail className="h-5 w-5 text-trace" />
              <h1 className="font-display text-2xl font-bold text-ink">Live Gmail Inbox Risk Scanner</h1>
            </div>
            <p className="mt-1 text-sm text-ink-muted">
              Active mailbox monitoring via Google OAuth 2.0 (`gmail.readonly`) with automated background risk scoring.
            </p>
          </div>
          <div className="flex items-center gap-3">
            {connected ? (
              <div className="flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3.5 py-1 text-xs font-mono text-emerald-400 font-semibold">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                Connected: analyst@tracemail.ai
              </div>
            ) : (
              <button
                onClick={handleConnect}
                className="rounded-lg bg-trace px-4 py-2 text-xs font-semibold text-white hover:bg-trace/90 transition shadow-sm"
              >
                Connect Google Workspace Inbox
              </button>
            )}
            <button
              onClick={handleScan}
              disabled={scanning}
              className="flex items-center gap-2 rounded-lg border border-bg-border bg-bg-surface px-4 py-2 text-xs font-semibold text-ink hover:bg-bg-raised transition disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`} />
              {scanning ? "Scanning Mailbox…" : "Trigger Inbox Scan"}
            </button>
          </div>
        </div>

        {/* Mailbox List */}
        <div className="mt-8 rounded-xl border border-bg-border bg-bg-surface overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-bg-border bg-bg/50 flex items-center justify-between">
            <span className="text-xs font-mono uppercase tracking-wider text-ink-muted">Monitored Inbound Stream</span>
            <span className="text-xs font-mono text-ink-muted">{emails.length} Messages Evaluated</span>
          </div>

          <div className="divide-y divide-bg-border">
            {loading && (
              <div className="p-8 text-center text-sm text-ink-muted">Loading mailbox telemetry…</div>
            )}
            {!loading && emails.length === 0 && (
              <div className="p-8 text-center text-sm text-ink-muted">No emails in connected inbox. Click "Trigger Inbox Scan" above.</div>
            )}
            {emails.map((m) => {
              const isCrit = m.risk === "Critical";
              const isSafe = m.risk === "Safe";
              return (
                <div key={m.id} className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-bg-raised transition">
                  <div className="min-w-0 max-w-2xl">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-ink">{m.sender}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        isCrit ? "bg-red-500/20 text-red-400 border border-red-500/30" : isSafe ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                      }`}>
                        {m.risk} Threat ({m.threatScore}/100)
                      </span>
                    </div>
                    <p className="text-sm text-ink mt-1 font-medium">{m.subject}</p>
                    <p className="text-xs text-ink-muted mt-1 truncate">{m.snippet}</p>
                  </div>
                  <div className="flex items-center gap-4 flex-shrink-0">
                    <span className="text-xs font-mono text-ink-faint">
                      {new Date(m.scannedAt).toLocaleTimeString()}
                    </span>
                    <Link
                      href={`/investigation/${isCrit ? "inv_paypal_phish_demo_01" : "inv_internshala_demo_02"}`}
                      className="inline-flex items-center gap-1 rounded-lg border border-bg-border bg-bg px-3 py-1.5 text-xs font-semibold text-trace hover:bg-trace/10 transition"
                    >
                      Investigate Case <ExternalLink className="h-3.5 w-3.5" />
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </main>
    </div>
  );
}
