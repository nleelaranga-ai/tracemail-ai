"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Radar, LogOut } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { clsx } from "clsx";

const links = [
  { href: "/dashboard", label: "Upload" },
  { href: "/reports", label: "History" }
];

export function Navbar() {
  const pathname = usePathname();
  const { user, signOut } = useAuth();

  return (
    <header className="border-b border-bg-border bg-bg-surface">
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/dashboard" className="flex items-center gap-2">
          <Radar className="h-5 w-5 text-trace" strokeWidth={2} />
          <span className="font-display text-lg font-semibold tracking-tight">TraceMail AI</span>
        </Link>
        <nav className="flex items-center gap-1">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={clsx(
                "rounded px-3 py-1.5 text-sm transition-colors",
                pathname === l.href
                  ? "bg-bg-raised text-ink"
                  : "text-ink-muted hover:bg-bg-raised hover:text-ink"
              )}
            >
              {l.label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-4">
          {user && <span className="font-mono text-xs text-ink-muted">{user.email}</span>}
          <button
            onClick={signOut}
            className="flex items-center gap-1.5 rounded border border-bg-border px-3 py-1.5 text-sm text-ink-muted transition-colors hover:border-verdict-phishing/50 hover:text-verdict-phishing"
          >
            <LogOut className="h-3.5 w-3.5" />
            Sign out
          </button>
        </div>
      </div>
    </header>
  );
}
