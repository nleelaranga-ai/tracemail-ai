"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { Navbar } from "@/components/Navbar";
import { api } from "@/services/api";
import type { EvidenceRecordItem } from "@/types";
import { Scale, CheckCircle2, AlertTriangle, ShieldCheck, RefreshCw, FileText } from "lucide-react";

export default function EvidencePage() {
  const [records, setRecords] = useState<EvidenceRecordItem[]>([]);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [verifyStatus, setVerifyStatus] = useState<Record<string, { status: string; message: string }>>({});
  const [loading, setLoading] = useState(true);

  const loadEvidence = () => {
    setLoading(true);
    api.listEvidence()
      .then(setRecords)
      .catch((err) => console.error("Error loading evidence:", err))
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadEvidence();
  }, []);

  const handleVerify = async (id: string, simulatedCorrupt = false) => {
    setVerifyingId(id);
    try {
      const res = await api.verifyEvidence(id, simulatedCorrupt);
      setVerifyStatus((prev) => ({
        ...prev,
        [id]: { status: res.status, message: res.message }
      }));
      loadEvidence();
    } catch (err) {
      console.error("Verification failed:", err);
    } finally {
      setVerifyingId(null);
    }
  };

  return (
    <div className="min-h-screen bg-bg">
      <Navbar />
      <main className="mx-auto max-w-7xl px-4 py-8 sm:px-6">
        <div className="border-b border-bg-border pb-6">
          <div className="flex items-center gap-2">
            <Scale className="h-5 w-5 text-trace" />
            <h1 className="font-display text-2xl font-bold text-ink">Court-Admissible Evidence Locker</h1>
          </div>
          <p className="mt-1 text-sm text-ink-muted">
            Cryptographic SHA-256 integrity verification, chain of custody logs, and anti-tamper detection for legal compliance.
          </p>
        </div>

        <div className="mt-8 space-y-6">
          {loading && <div className="p-8 text-center text-xs text-ink-muted">Querying evidence ledger…</div>}
          {records.map((r) => {
            const isVerified = r.status === "Verified";
            const vState = verifyStatus[r.investigationId];
            return (
              <div key={r.id} className="rounded-xl border border-bg-border bg-bg-surface p-6 shadow-sm">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-bg-border pb-4">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm text-ink">{r.subject || "Electronic Forensic Payload"}</span>
                      <span className={`px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase ${
                        isVerified ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" : "bg-red-500/20 text-red-400 border border-red-500/30"
                      }`}>
                        {r.status}
                      </span>
                    </div>
                    <p className="text-xs font-mono text-ink-muted mt-1">Investigator Sign-off: {r.investigator}</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => handleVerify(r.investigationId, false)}
                      disabled={verifyingId === r.investigationId}
                      className="rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-semibold text-emerald-400 hover:bg-emerald-500/20 transition disabled:opacity-50"
                    >
                      {verifyingId === r.investigationId ? "Verifying..." : "Verify Hash Integrity"}
                    </button>
                    <button
                      onClick={() => handleVerify(r.investigationId, true)}
                      title="Simulates deliberate bit alteration to demonstrate tamper alert to judges"
                      className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-1.5 text-xs font-semibold text-red-400 hover:bg-red-500/20 transition"
                    >
                      Test Tamper Detection
                    </button>
                  </div>
                </div>

                {vState && (
                  <div className={`mt-3 p-3 rounded-lg text-xs font-mono border ${
                    vState.status === "Verified" ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400" : "bg-red-500/10 border-red-500/30 text-red-400 font-bold"
                  }`}>
                    {vState.message}
                  </div>
                )}

                <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                  <div className="rounded-lg border border-bg-border bg-bg p-3">
                    <span className="text-[10px] uppercase text-ink-muted">Acquired SHA-256 Checksum</span>
                    <p className="text-trace break-all mt-1">{r.originalHash}</p>
                  </div>
                  <div className="rounded-lg border border-bg-border bg-bg p-3">
                    <span className="text-[10px] uppercase text-ink-muted">Audit State & Seal</span>
                    <p className="text-ink mt-1">Sealed on {r.createdAt ? new Date(r.createdAt).toLocaleString() : "N/A"}</p>
                  </div>
                </div>

                {/* Custody Log Timeline */}
                <div className="mt-4">
                  <span className="text-xs font-semibold text-ink uppercase tracking-wider font-mono">Chain of Custody Timeline</span>
                  <div className="mt-2 divide-y divide-bg-border rounded-lg border border-bg-border">
                    {r.custodyLog?.map((c, i) => (
                      <div key={i} className="p-3 text-xs flex items-center justify-between">
                        <div>
                          <span className="font-semibold text-ink">{c.action}</span>
                          <p className="text-[11px] text-ink-muted font-mono">{c.actor}</p>
                        </div>
                        <span className="text-[10px] font-mono text-ink-faint">{new Date(c.timestamp).toLocaleTimeString()}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </main>
    </div>
  );
}
