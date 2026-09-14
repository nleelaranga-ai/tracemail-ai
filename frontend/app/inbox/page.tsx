"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Navbar } from "@/components/Navbar";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/services/api";
import type { InboxEmailItem } from "@/types";
import {
  Mail,
  RefreshCw,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Shield,
  KeyRound,
  LogOut,
  Sparkles,
  Info
} from "lucide-react";

export default function InboxPage() {
  const router = useRouter();
  const { user, ready } = useAuth();
  const [emails, setEmails] = useState<InboxEmailItem[]>([]);
  const [connected, setConnected] = useState(false);
  const [accountEmail, setAccountEmail] = useState("");
  const [connectionMode, setConnectionMode] = useState<"live" | "demo" | "disconnected">("disconnected");
  const [clientConfigured, setClientConfigured] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [loading, setLoading] = useState(true);
  const [connecting, setConnecting] = useState(false);
  const [investigatingId, setInvestigatingId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const loadInbox = async (email?: string) => {
    setLoading(true);
    try {
      const results = await api.getInboxResults(email);
      setEmails(results);
    } catch (err) {
      console.error("Failed to fetch inbox:", err);
    } finally {
      setLoading(false);
    }
  };

  const checkStatusAndHandleCallback = async () => {
    if (typeof window === "undefined") return;

    // 1. Check if OAuth redirected back with ?connected=true, error, or ?code=...
    const urlParams = new URLSearchParams(window.location.search);
    const authCode = urlParams.get("code");
    const isConnectedParam = urlParams.get("connected");
    const emailParam = urlParams.get("email");
    const modeParam = urlParams.get("mode");
    const errorParam = urlParams.get("error");

    if (errorParam) {
      setActionError(`OAuth Connection Issue: ${decodeURIComponent(errorParam)}`);
    }

    if (isConnectedParam === "true") {
      const targetEmail = emailParam || user?.email || "";
      setConnected(true);
      setAccountEmail(targetEmail);
      setConnectionMode(modeParam === "live" ? "live" : "demo");
      setNotice(`Successfully connected ${targetEmail} via Google Workspace OAuth 2.0! Fetching live emails...`);
      window.history.replaceState({}, document.title, window.location.pathname);

      setScanning(true);
      try {
        await api.scanInbox(targetEmail);
      } catch (scanErr) {
        console.error("Initial mailbox scan failed:", scanErr);
      } finally {
        setScanning(false);
      }

      await loadInbox(targetEmail);
      return;
    } else if (authCode) {
      setConnecting(true);
      setNotice("Exchanging Google authorization code for live tokens...");
      try {
        const res = await api.connectGoogleInboxWithCode(authCode);
        const targetEmail = res.email || user?.email || "";
        setConnected(true);
        setAccountEmail(targetEmail);
        setConnectionMode(res.live_oauth ? "live" : "demo");
        setNotice(`Successfully connected ${targetEmail} via Google Workspace OAuth 2.0! Fetching live emails...`);

        // Clean query string from browser address bar
        window.history.replaceState({}, document.title, window.location.pathname);

        setScanning(true);
        try {
          await api.scanInbox(targetEmail);
        } catch (scanErr) {
          console.error("Initial mailbox scan failed:", scanErr);
        } finally {
          setScanning(false);
        }

        await loadInbox(targetEmail);
        return;
      } catch (err) {
        console.error("Google OAuth exchange error:", err);
        setNotice("OAuth exchange failed; connected via local fallback mode.");
      } finally {
        setConnecting(false);
      }
    }

    // 2. Fetch current status from backend for the authenticated user
    let activeEmail: string | undefined;
    try {
      const status = await api.getGoogleInboxStatus();
      if (status.connected) {
        setConnected(true);
        activeEmail = status.email || "";
        setAccountEmail(activeEmail);
        setConnectionMode(status.mode === "live" ? "live" : "demo");
      } else {
        setConnected(false);
        setAccountEmail("");
        setConnectionMode("disconnected");
      }
      setClientConfigured(Boolean(status.client_configured));
    } catch (err) {
      console.error("Status check failed:", err);
    }

    if (activeEmail) {
      await loadInbox(activeEmail);
    } else {
      setEmails([]);
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!ready) return;
    checkStatusAndHandleCallback();
  }, [ready, user?.email]);

  const handleConnect = async () => {
    setConnecting(true);
    try {
      const { authUrl, configured } = await api.getGoogleLoginUrl();
      if (configured && authUrl && typeof window !== "undefined") {
        // Redirect browser directly to Google's official consent screen
        window.location.href = authUrl;
        return;
      }

      // If credentials not configured in environment, prompt user or fall back to demo mode
      const targetEmail = user?.email || "";
      const res = await api.connectGoogleInbox(targetEmail);
      setConnected(true);
      setAccountEmail(targetEmail);
      setConnectionMode("demo");
      setNotice("Connected in Demo Simulation Mode (Configure GOOGLE_CLIENT_ID for live OAuth).");
      if (targetEmail) {
        loadInbox(targetEmail);
      }
    } catch (err) {
      console.error("Connect error:", err);
      setNotice("Connection error occurred.");
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    try {
      await api.disconnectGoogleInbox(accountEmail || user?.email);
      setConnected(false);
      setAccountEmail("");
      setConnectionMode("disconnected");
      setEmails([]);
      setNotice("Mailbox disconnected.");
    } catch (err) {
      console.error("Disconnect error:", err);
    }
  };

  const handleScan = async () => {
    const scanTarget = accountEmail || user?.email;
    if (!scanTarget) {
      setActionError("No connected mailbox available to scan. Please connect your account first.");
      return;
    }
    setScanning(true);
    setNotice(null);
    setActionError(null);
    try {
      const res = await api.scanInbox(scanTarget);
      setNotice(
        `Mailbox scan complete: ${res.emailsScanned || 0} messages evaluated (${res.threatsFound || 0} threats detected). Mode: ${res.mode || "demo"}`
      );
      loadInbox(scanTarget);
    } catch (err: any) {
      console.error("Scan error:", err);
      setActionError(err?.message || "Scan encountered an error.");
    } finally {
      setScanning(false);
    }
  };

  const handleInvestigateMessage = async (m: InboxEmailItem) => {
    setActionError(null);
    if (m.investigationId) {
      router.push(`/investigation/${m.investigationId}`);
      return;
    }

    setInvestigatingId(m.messageId);
    try {
      const res = await api.investigateMailboxMessage(accountEmail, m.messageId);
      if (res.investigationId) {
        setEmails((prev) =>
          prev.map((item) =>
            item.messageId === m.messageId ? { ...item, investigationId: res.investigationId } : item
          )
        );
        router.push(`/investigation/${res.investigationId}`);
      } else {
        setActionError("Failed to extract forensics: No investigation ID returned.");
      }
    } catch (err: any) {
      console.error("Investigate message error:", err);
      setActionError(err.message || "Failed to extract forensics for this email.");
    } finally {
      setInvestigatingId(null);
    }
  };

  return (
    <div className="min-h-screen bg-bg">
      <Navbar />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
        {/* Header Bar */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-bg-border pb-6">
          <div>
            <div className="flex items-center gap-2">
              <Mail className="h-5 w-5 text-trace" />
              <h1 className="font-display text-2xl font-bold text-ink">Live Gmail Inbox Risk Scanner</h1>
            </div>
            <p className="mt-1 text-sm text-ink-muted">
              Active mailbox monitoring via Google OAuth 2.0 (<code>gmail.readonly</code>) with automated background risk scoring.
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex flex-wrap items-center gap-3">
            {!ready ? (
              <div className="h-8 w-44 rounded-lg bg-bg-surface border border-bg-border animate-pulse" />
            ) : connected && accountEmail ? (
              <div className="flex items-center gap-2">
                <div
                  className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-mono font-semibold ${
                    connectionMode === "live"
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                      : "border-amber-500/30 bg-amber-500/10 text-amber-300"
                  }`}
                >
                  <span
                    className={`h-2 w-2 rounded-full animate-pulse ${
                      connectionMode === "live" ? "bg-emerald-400" : "bg-amber-400"
                    }`}
                  />
                  {connectionMode === "live" ? "Live OAuth:" : "Demo:"} {accountEmail}
                </div>

                <button
                  onClick={handleDisconnect}
                  className="flex items-center gap-1 rounded-lg border border-bg-border bg-bg-surface px-2.5 py-1 text-xs text-ink-muted hover:text-red-400 hover:border-red-500/30 transition"
                  title="Disconnect mailbox"
                >
                  <LogOut className="h-3 w-3" />
                </button>
              </div>
            ) : (
              <button
                onClick={handleConnect}
                disabled={connecting}
                className="flex items-center gap-2 rounded-lg bg-trace px-4 py-2 text-xs font-semibold text-white hover:bg-trace/90 transition shadow-sm disabled:opacity-50"
              >
                <KeyRound className="h-3.5 w-3.5" />
                {connecting ? "Connecting..." : "Connect Google Workspace / Gmail"}
              </button>
            )}

            <button
              onClick={handleScan}
              disabled={scanning || !connected || !accountEmail}
              className="flex items-center gap-2 rounded-lg border border-bg-border bg-bg-surface px-4 py-2 text-xs font-semibold text-ink hover:bg-bg-raised transition disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${scanning ? "animate-spin" : ""}`} />
              {scanning ? "Scanning Mailbox…" : "Trigger Inbox Scan"}
            </button>
          </div>
        </div>

        {/* Feedback Alert Notice */}
        {notice && (
          <div className="mt-4 rounded-lg border border-blue-500/30 bg-blue-500/10 p-3 text-xs text-blue-300 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Info className="h-4 w-4 text-blue-400 flex-shrink-0" />
              <span>{notice}</span>
            </div>
            <button onClick={() => setNotice(null)} className="text-blue-400 hover:text-white font-bold ml-2">
              &times;
            </button>
          </div>
        )}

        {/* Action Error Banner */}
        {actionError && (
          <div className="mt-4 rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs text-red-300 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400 flex-shrink-0" />
              <span>{actionError}</span>
            </div>
            <button onClick={() => setActionError(null)} className="text-red-400 hover:text-white font-bold ml-2">
              &times;
            </button>
          </div>
        )}

        {/* Mailbox List */}
        <div className="mt-6 rounded-xl border border-bg-border bg-bg-surface overflow-hidden shadow-sm">
          <div className="px-6 py-4 border-b border-bg-border bg-bg/50 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono uppercase tracking-wider text-ink-muted">Monitored Inbound Stream</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-bg-raised border border-bg-border text-ink-faint">
                {connectionMode === "live" ? "Live Google Workspace Telemetry" : "Deterministic Benchmark Corpus"}
              </span>
            </div>
            <span className="text-xs font-mono text-ink-muted">{emails.length} Messages Evaluated</span>
          </div>

          <div className="divide-y divide-bg-border">
            {loading && (
              <div className="p-8 text-center text-sm text-ink-muted">Loading mailbox telemetry…</div>
            )}
            {!loading && emails.length === 0 && (
              <div className="p-8 text-center text-sm text-ink-muted">
                No emails found. Click "Trigger Inbox Scan" above to evaluate messages.
              </div>
            )}
            {emails.map((m) => {
              const isCrit = m.risk === "Critical";
              const isSafe = m.risk === "Safe";
              return (
                <div
                  key={m.id}
                  className="p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-bg-raised transition"
                >
                  <div className="min-w-0 max-w-2xl">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-ink">{m.sender}</span>
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                          isCrit
                            ? "bg-red-500/20 text-red-400 border border-red-500/30"
                            : isSafe
                            ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                            : "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                        }`}
                      >
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
                    {m.investigationId ? (
                      <Link
                        href={`/investigation/${m.investigationId}`}
                        className="inline-flex items-center gap-1 rounded-lg border border-bg-border bg-bg px-3 py-1.5 text-xs font-semibold text-trace hover:bg-trace/10 transition"
                      >
                        View Investigation <ExternalLink className="h-3.5 w-3.5" />
                      </Link>
                    ) : (
                      <button
                        onClick={() => handleInvestigateMessage(m)}
                        disabled={investigatingId === m.messageId}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-trace/30 bg-trace/10 px-3 py-1.5 text-xs font-semibold text-trace hover:bg-trace/20 transition disabled:opacity-50"
                      >
                        {investigatingId === m.messageId ? (
                          <>
                            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                            Extracting Forensics…
                          </>
                        ) : (
                          <>
                            <Sparkles className="h-3.5 w-3.5" />
                            Extract &amp; Investigate
                          </>
                        )}
                      </button>
                    )}
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
