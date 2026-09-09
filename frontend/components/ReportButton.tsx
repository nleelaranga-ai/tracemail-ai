"use client";
import { useState } from "react";
import { Download, Loader2, Check, FileText, Code2, Globe } from "lucide-react";
import { api } from "@/services/api";

export function ReportButton({ investigationId }: { investigationId: string }) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const [open, setOpen] = useState(false);

  async function handleDownload(format: "pdf" | "html" | "json") {
    setState("loading");
    setOpen(false);
    try {
      const blob = await api.downloadReport(investigationId, format);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `TraceMail_Forensic_Report_${investigationId}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setState("done");
      setTimeout(() => setState("idle"), 2000);
    } catch {
      setState("error");
      setTimeout(() => setState("idle"), 2500);
    }
  }

  return (
    <div className="relative inline-block text-left">
      <div className="flex items-center rounded-lg border border-trace/40 bg-trace/10 shadow-sm">
        <button
          onClick={() => handleDownload("pdf")}
          disabled={state === "loading"}
          className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold uppercase tracking-wider text-trace transition hover:bg-trace/20 disabled:cursor-wait"
        >
          {state === "loading" && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
          {state === "done" && <Check className="h-3.5 w-3.5" />}
          {state === "idle" && <Download className="h-3.5 w-3.5" />}
          {state === "error" ? "Error — Retry" : state === "done" ? "Downloaded" : "Download PDF"}
        </button>
        <button
          onClick={() => setOpen(!open)}
          className="border-l border-trace/30 px-2 py-2 text-trace hover:bg-trace/20 transition"
          title="Other formats (HTML, JSON)"
        >
          <span className="text-[10px]">▼</span>
        </button>
      </div>

      {open && (
        <div className="absolute right-0 z-50 mt-2 w-48 rounded-xl border border-bg-border bg-bg-raised p-1 shadow-2xl backdrop-blur-md">
          <button
            onClick={() => handleDownload("pdf")}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-xs font-medium text-ink hover:bg-bg-surface hover:text-trace transition"
          >
            <FileText className="h-4 w-4 text-red-400" />
            <span>Forensic PDF Report</span>
          </button>
          <button
            onClick={() => handleDownload("html")}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-xs font-medium text-ink hover:bg-bg-surface hover:text-trace transition"
          >
            <Globe className="h-4 w-4 text-blue-400" />
            <span>Interactive HTML Report</span>
          </button>
          <button
            onClick={() => handleDownload("json")}
            className="flex w-full items-center gap-2.5 rounded-lg px-3 py-2 text-left text-xs font-medium text-ink hover:bg-bg-surface hover:text-trace transition"
          >
            <Code2 className="h-4 w-4 text-emerald-400" />
            <span>CERT-In JSON Export</span>
          </button>
        </div>
      )}
    </div>
  );
}
