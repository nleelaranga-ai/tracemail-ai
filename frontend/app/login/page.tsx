"use client";
import { useState } from "react";
import { Radar, Loader2 } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { api } from "@/services/api";

export default function LoginPage() {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const { login, register } = useAuth();

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (mode === "login") await login(email, password);
      else await register(email, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Something went wrong.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="scanline-bg flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-sm rounded border border-bg-border bg-bg-surface p-8">
        <div className="mb-8 flex flex-col items-center gap-2 text-center">
          <Radar className="h-7 w-7 text-trace" />
          <h1 className="font-display text-xl font-semibold">TraceMail AI</h1>
          <p className="text-xs text-ink-muted">Trace. Analyze. Investigate. Protect.</p>
        </div>

        <div className="mb-6 flex rounded border border-bg-border p-1">
          {(["login", "register"] as const).map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setMode(m)}
              className={`flex-1 rounded py-1.5 text-sm capitalize transition-colors ${
                mode === m ? "bg-bg-raised text-ink" : "text-ink-muted"
              }`}
            >
              {m === "login" ? "Sign in" : "Register"}
            </button>
          ))}
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="mb-1 block text-xs text-ink-muted">Email</label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="analyst@cert-in.gov.in"
              className="w-full rounded border border-bg-border bg-bg px-3 py-2 text-sm outline-none focus:border-trace"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs text-ink-muted">Password</label>
            <input
              type="password"
              required
              minLength={6}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
              className="w-full rounded border border-bg-border bg-bg px-3 py-2 text-sm outline-none focus:border-trace"
            />
          </div>

          {error && <p className="text-sm text-verdict-phishing">{error}</p>}

          <button
            type="submit"
            disabled={loading}
            className="flex w-full items-center justify-center gap-2 rounded bg-trace py-2.5 font-medium text-bg disabled:opacity-50"
          >
            {loading && <Loader2 className="h-4 w-4 animate-spin" />}
            {mode === "login" ? "Sign in" : "Create account"}
          </button>
        </form>

        {api.isMockMode && (
          <p className="mt-5 rounded border border-trace/30 bg-trace/5 px-3 py-2 text-center font-mono text-[11px] text-trace">
            Mock mode: any email + 6-char password works
          </p>
        )}
      </div>
    </div>
  );
}
