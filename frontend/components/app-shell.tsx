"use client";

import { ReactNode, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAppSession } from "@/components/session-provider";
import { terminateSession } from "@/lib/api";

const navigation = [
  { href: "/",          label: "Home" },
  { href: "/analyze",   label: "Repository" },
  { href: "/issues",    label: "Issues" },
  { href: "/scan",      label: "Security" },
  { href: "/pr-review", label: "PR Review" },
  { href: "/logs",      label: "Logs" },
  { href: "/result",    label: "Result" },
  { href: "/approval",  label: "Approval" },
];

export function AppShell({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { state, resetState } = useAppSession();
  const [terminating, setTerminating] = useState(false);
  const [terminateError, setTerminateError] = useState<string | null>(null);
  const [theme, setTheme] = useState<"light" | "dark">("light");
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  // Initialize theme from localStorage
  useEffect(() => {
    const saved = localStorage.getItem("opendev-theme");
    if (saved === "dark") {
      setTheme("dark");
      document.documentElement.setAttribute("data-theme", "dark");
    }
  }, []);

  const toggleTheme = useCallback(() => {
    const next = theme === "light" ? "dark" : "light";
    setTheme(next);
    localStorage.setItem("opendev-theme", next);
    if (next === "dark") {
      document.documentElement.setAttribute("data-theme", "dark");
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  }, [theme]);

  async function handleTerminateSession() {
    if (terminating || !state.sessionId) return;
    setTerminating(true);
    setTerminateError(null);
    try {
      await terminateSession(state.sessionId);
    } catch (error) {
      setTerminateError(
        error instanceof Error ? error.message : "Unable to terminate session."
      );
    } finally {
      resetState();
      setTerminating(false);
      router.push("/");
    }
  }

  return (
    <div className="min-h-screen bg-bg text-text">
      <div className="mx-auto flex min-h-screen max-w-7xl flex-col gap-6 px-4 py-6 md:px-6 md:py-8">
        {/* Header */}
        <header className="relative overflow-hidden rounded-2xl border-2 border-border bg-surface p-5 shadow-[6px_6px_0px_0px] shadow-shadow-color md:p-6">
          <div className="pointer-events-none absolute -right-8 -top-10 h-28 w-28 rounded-full bg-primary-soft blur-2xl opacity-60" />
          <div className="pointer-events-none absolute -left-8 bottom-0 h-24 w-24 rounded-full bg-accent-soft blur-2xl opacity-60" />

          <div className="relative flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            {/* Left: Branding */}
            <div className="space-y-1.5 flex-1">
              <div className="flex items-center gap-3">
                <svg className="h-6 w-6 text-primary" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" /></svg>
                <p className="font-mono text-sm uppercase tracking-[0.4em] text-muted">
                  OpenDev AI
                </p>
              </div>
              <h1 className="text-2xl font-semibold tracking-tight md:text-3xl">
                Autonomous GitHub Agent
              </h1>
              <p className="max-w-2xl font-mono text-xs text-muted leading-5 hidden md:block">
                Analyse code, fix issues via fork PR, scan secrets &amp;
                vulnerabilities, review pull requests.
              </p>
            </div>

            {/* Right: Controls */}
            <div className="flex items-center gap-3 shrink-0">
              {/* Session info */}
              <div className="hidden lg:flex flex-col items-end gap-1 rounded-xl border-2 border-border bg-card/70 px-4 py-2.5 font-mono text-xs text-muted backdrop-blur">
                <p>
                  Session:{" "}
                  {state.sessionId
                    ? state.sessionId.slice(0, 10) + "..."
                    : "not started"}
                </p>
                <p className="truncate max-w-[180px]">
                  Repo: {state.repo?.full_name ?? "none"}
                </p>
              </div>

              {/* Theme toggle */}
              <button
                type="button"
                onClick={toggleTheme}
                className="theme-toggle"
                aria-label="Toggle dark mode"
                title={
                  theme === "light"
                    ? "Switch to dark mode"
                    : "Switch to light mode"
                }
              >
                {theme === "light" ? (
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" /></svg>
                ) : (
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M12 3v2.25m6.364.386l-1.591 1.591M21 12h-2.25m-.386 6.364l-1.591-1.591M12 18.75V21m-4.773-4.227l-1.591 1.591M5.25 12H3m4.227-4.773L5.636 5.636M15.75 12a3.75 3.75 0 11-7.5 0 3.75 3.75 0 017.5 0z" /></svg>
                )}
              </button>

              {/* Terminate button */}
              <button
                type="button"
                disabled={!state.sessionId || terminating}
                onClick={handleTerminateSession}
                className="rounded-full border-2 border-border bg-danger px-4 py-2 font-mono text-xs uppercase tracking-[0.15em] text-white transition hover:-translate-y-0.5 hover:shadow-lg disabled:cursor-not-allowed disabled:opacity-40"
              >
                {terminating ? "Ending..." : "End session"}
              </button>

              {/* Mobile menu toggle */}
              <button
                type="button"
                onClick={() => setMobileNavOpen(!mobileNavOpen)}
                className="lg:hidden theme-toggle"
                aria-label="Toggle navigation"
              >
                {mobileNavOpen ? (
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
                ) : (
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor"><path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25h16.5" /></svg>
                )}
              </button>
            </div>
          </div>

          {terminateError && (
            <p className="mt-3 font-mono text-xs text-danger">
              {terminateError}
            </p>
          )}
        </header>

        {/* Navigation */}
        <nav
          className={`flex flex-wrap gap-2 ${
            mobileNavOpen ? "" : "hidden lg:flex"
          }`}
        >
          {navigation.map((item) => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileNavOpen(false)}
                className={`rounded-full border-2 px-4 py-2 font-mono text-xs uppercase tracking-[0.15em] transition-all hover:-translate-y-0.5 ${
                  active
                    ? "border-primary bg-primary text-white shadow-[3px_3px_0px_0px] shadow-shadow-color"
                    : "border-border bg-card text-text hover:border-primary hover:text-primary"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </nav>

        {/* Main Content */}
        <main className="flex-1">{children}</main>

        {/* Footer */}
        <footer className="border-t-2 border-border/30 pt-4 pb-2 text-center font-mono text-xs text-muted">
          OpenDev AI - Autonomous GitHub maintenance powered by LLMs &amp;
          Q-learning
        </footer>
      </div>
    </div>
  );
}
