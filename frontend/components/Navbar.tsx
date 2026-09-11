"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Radar, LogOut } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { clsx } from "clsx";

const links = [
  { href: "/dashboard", label: "Investigate" },
  { href: "/soc", label: "SOC Command" },
  { href: "/inbox", label: "Live Inbox" },
  { href: "/campaigns", label: "Campaigns" },
  { href: "/evidence", label: "Evidence Locker" },
  { href: "/org", label: "Org Heatmap" },
  { href: "/reports", label: "Reports" }
];

export function Navbar() {
  const pathname = usePathname();
  const { user, signOut } = useAuth();

  return (
    <header className="border-b border-bg-border bg-bg-surface sticky top-0 z-40">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">
        <Link href="/dashboard" className="flex items-center gap-2 flex-shrink-0">
          <Radar className="h-5 w-5 text-trace" strokeWidth={2} />
          <span className="font-display text-base sm:text-lg font-semibold tracking-tight">TraceMail AI</span>
        </Link>
        <nav className="flex items-center gap-1 overflow-x-auto py-1 px-2 no-scrollbar">
          {links.map((l) => (
            <Link
              key={l.href}
              href={l.href}
              className={clsx(
                "rounded px-2.5 py-1 text-xs sm:text-sm font-medium transition-colors whitespace-nowrap",
                pathname === l.href
                  ? "bg-trace/15 text-trace border border-trace/30"
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
