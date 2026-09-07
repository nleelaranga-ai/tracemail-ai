"use client";
import { useState } from "react";
import { Download, Loader2, Check } from "lucide-react";
import { api } from "@/services/api";

export function ReportButton({ investigationId }: { investigationId: string }) {
  const [state, setState] = useState<"idle" | "loading" | "done" | "error">("idle");

  async function handleDownload() {
    setState("loading");
    try {
      const blob = await api.downloadReport(investigationId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `tracemail-report-${investigationId}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      setState("done");
      setTimeout(() => setState("idle"), 2000);
    } catch {
      setState("error");
      setTimeout(() => setState("idle"), 2000);
    }
  }

  return (
    <button
      onClick={handleDownload}
      disabled={state === "loading"}
      className="flex items-center gap-2 rounded border border-trace/40 bg-trace/10 px-4 py-2 text-sm font-medium text-trace transition-colors hover:bg-trace/20 disabled:cursor-wait"
    >
      {state === "loading" && <Loader2 className="h-4 w-4 animate-spin" />}
      {state === "done" && <Check className="h-4 w-4" />}
      {state === "idle" && <Download className="h-4 w-4" />}
      {state === "error" ? "Failed — retry" : state === "done" ? "Downloaded" : "Download report"}
    </button>
  );
}
