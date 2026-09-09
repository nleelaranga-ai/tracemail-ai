"use client";
import { useCallback, useRef, useState } from "react";
import { UploadCloud, FileText, Loader2 } from "lucide-react";
import { clsx } from "clsx";
import { api } from "@/services/api";
import { useRouter } from "next/navigation";

export function UploadBox() {
  const [isDragging, setIsDragging] = useState(false);
  const [file, setFile] = useState<File | null>(null);
  const [status, setStatus] = useState<"idle" | "uploading" | "error">("idle");
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const pickFile = useCallback((f: File | undefined | null) => {
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".eml")) {
      setError("Only .eml files are supported.");
      return;
    }
    setError(null);
    setFile(f);
  }, []);

  async function handleUpload() {
    if (!file) return;
    setStatus("uploading");
    setError(null);
    try {
      const res = await api.createInvestigation(file);
      router.push(`/investigation/${res.investigationId}`);
    } catch (e) {
      setStatus("error");
      setError(e instanceof Error ? e.message : "Upload failed. Try again.");
    }
  }

  return (
    <div className="w-full">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setIsDragging(false);
          pickFile(e.dataTransfer.files?.[0]);
        }}
        onClick={() => inputRef.current?.click()}
        className={clsx(
          "flex cursor-pointer flex-col items-center justify-center gap-3 rounded border-2 border-dashed px-6 py-16 text-center transition-colors",
          isDragging ? "border-trace bg-trace/5" : "border-bg-border hover:border-ink-faint"
        )}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".eml"
          className="hidden"
          onChange={(e) => pickFile(e.target.files?.[0])}
        />
        {file ? (
          <>
            <FileText className="h-8 w-8 text-trace" />
            <p className="font-mono text-sm">{file.name}</p>
            <p className="text-xs text-ink-muted">{(file.size / 1024).toFixed(1)} KB — click to replace</p>
          </>
        ) : (
          <>
            <UploadCloud className="h-8 w-8 text-ink-faint" />
            <p className="text-sm text-ink">Drag and drop a .eml file, or click to browse</p>
            <p className="text-xs text-ink-muted">Raw email header/body only — nothing is sent anywhere but your own backend</p>
          </>
        )}
      </div>

      {error && <p className="mt-3 text-sm text-verdict-phishing">{error}</p>}

      <button
        onClick={handleUpload}
        disabled={!file || status === "uploading"}
        className="mt-4 flex w-full items-center justify-center gap-2 rounded bg-trace py-2.5 font-medium text-bg transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
      >
        {status === "uploading" ? (
          <>
            <Loader2 className="h-4 w-4 animate-spin" /> Analyzing email…
          </>
        ) : (
          "Start investigation"
        )}
      </button>
    </div>
  );
}
