"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { Panel } from "@/components/panel";
import { StatusPill } from "@/components/status-pill";
import { TerminalLog } from "@/components/terminal-log";
import { useAppSession } from "@/components/session-provider";
import { fetchLogs } from "@/lib/api";

type LogFilter = "all" | "info" | "warn" | "error";

export default function LogsPage() {
  const { state, hydrateComplete, mergeState } = useAppSession();
  const bottomRef = useRef<HTMLDivElement>(null);
  const [isFullScreen, setIsFullScreen] = useState(false);
  const [logFilter, setLogFilter] = useState<LogFilter>("all");

  useEffect(() => {
    if (!state.sessionId) return;
    const id = state.sessionId;
    let active = true;
    async function poll() {
      try {
        const data = await fetchLogs(id);
        if (!active) return;
        mergeState({ logs: data.logs, pendingApproval: data.pending_action });
      } catch {
        /* ignore */
      }
    }
    poll();
    const t = setInterval(poll, 3000);
    return () => {
      active = false;
      clearInterval(t);
    };
  }, [state.sessionId, mergeState]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [state.logs]);

  // Handle keyboard escape for fullscreen
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape" && isFullScreen) setIsFullScreen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [isFullScreen]);

  if (!hydrateComplete) {
    return (
      <Panel title="Loading session" eyebrow="Logs">
        <p className="font-mono text-sm text-muted">Restoring session…</p>
      </Panel>
    );
  }

  if (!state.sessionId) {
    return (
      <Panel title="No logs available" eyebrow="Logs">
        <div className="space-y-4 font-mono text-sm text-muted">
          <p>Start a session and run an action to see logs here.</p>
          <Link
            href="/"
            className="inline-flex rounded-full border-2 border-border bg-primary px-4 py-2 font-mono text-sm uppercase tracking-[0.15em] text-white shadow-[4px_4px_0px_0px] shadow-shadow-color"
          >
            Go home
          </Link>
        </div>
      </Panel>
    );
  }

  const filteredLogs =
    logFilter === "all"
      ? state.logs
      : state.logs.filter((entry) => {
          if (logFilter === "warn")
            return entry.level === "warn" || entry.level === "warning";
          return entry.level === logFilter;
        });

  const logTerminal = (
    <div className="space-y-3">
      {/* Controls */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex gap-2">
          {(["all", "info", "warn", "error"] as LogFilter[]).map((f) => (
            <button
              key={f}
              type="button"
              onClick={() => setLogFilter(f)}
              className={`rounded-full border-2 px-3 py-1 font-mono text-xs uppercase tracking-[0.15em] transition ${
                logFilter === f
                  ? "border-primary bg-primary text-white"
                  : "border-border bg-card text-muted hover:border-primary"
              }`}
            >
              {f === "all" ? "All" : f}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <span className="font-mono text-xs text-muted self-center">
            {filteredLogs.length} entries
          </span>
          <button
            type="button"
            onClick={() => setIsFullScreen(!isFullScreen)}
            className="rounded-full border-2 border-border bg-card px-3 py-1 font-mono text-xs uppercase tracking-[0.15em] text-muted transition hover:border-primary hover:text-primary"
          >
            {isFullScreen ? "✕ Exit" : "⛶ Fullscreen"}
          </button>
        </div>
      </div>

      {/* Terminal */}
      <TerminalLog
        logs={filteredLogs}
        maxHeight={isFullScreen ? "calc(100vh - 140px)" : "42rem"}
      />
      <div ref={bottomRef} />
    </div>
  );

  // Fullscreen mode
  if (isFullScreen) {
    return (
      <div
        className="fullscreen-overlay"
        onClick={() => setIsFullScreen(false)}
      >
        <div
          className="fullscreen-content p-6 bg-bg"
          onClick={(e) => e.stopPropagation()}
        >
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-xl font-semibold text-text">
              Execution Logs — Fullscreen
            </h2>
            <button
              type="button"
              onClick={() => setIsFullScreen(false)}
              className="rounded-full border-2 border-border bg-card px-4 py-2 font-mono text-xs uppercase tracking-[0.15em] text-muted transition hover:border-danger hover:text-danger"
            >
              ✕ Close
            </button>
          </div>
          {logTerminal}
        </div>
      </div>
    );
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[1.15fr_0.85fr]">
      {/* Terminal log */}
      <Panel
        title="Execution logs"
        eyebrow={`${state.logs.length} entries · auto-refreshing`}
      >
        {logTerminal}
      </Panel>

      {/* Sidebar */}
      <div className="space-y-6">
        <Panel title="Run state" eyebrow="Summary">
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              <StatusPill
                label={state.result?.action ?? "idle"}
                tone="neutral"
              />
              <StatusPill
                label={state.result?.status ?? "waiting"}
                tone={
                  state.result?.status === "failed"
                    ? "danger"
                    : state.pendingApproval
                    ? "warning"
                    : state.result?.status === "approved"
                    ? "success"
                    : "neutral"
                }
              />
            </div>
            <p className="font-mono text-sm leading-7 text-muted">
              {state.result?.summary ??
                "Trigger a fix or scan from the issues or security pages."}
            </p>
            {state.pendingApproval && (
              <div className="rounded-xl border-2 border-accent bg-accent-soft p-4">
                <p className="font-mono text-xs uppercase tracking-[0.15em] text-text mb-2">
                  ⚠ Action pending approval
                </p>
                <p className="font-mono text-sm text-muted">
                  Review the diff and approve or reject the PR.
                </p>
              </div>
            )}
          </div>
        </Panel>

        <Panel title="Navigation" eyebrow="Quick links">
          <div className="flex flex-wrap gap-2">
            {state.pendingApproval && (
              <Link
                href="/approval"
                className="rounded-full border-2 border-border bg-accent px-4 py-2 font-mono text-xs uppercase tracking-[0.15em] text-text shadow-[3px_3px_0px_0px] shadow-shadow-color transition hover:-translate-y-0.5"
              >
                Approve PR
              </Link>
            )}
            <Link
              href="/result"
              className="rounded-full border-2 border-border bg-card px-4 py-2 font-mono text-xs uppercase tracking-[0.15em] text-text transition hover:-translate-y-0.5 hover:border-primary"
            >
              View result
            </Link>
            <Link
              href="/approval"
              className="rounded-full border-2 border-border bg-primary px-4 py-2 font-mono text-xs uppercase tracking-[0.15em] text-white transition hover:-translate-y-0.5"
            >
              Approval
            </Link>
            <Link
              href="/issues"
              className="rounded-full border-2 border-border bg-card px-4 py-2 font-mono text-xs uppercase tracking-[0.15em] text-text transition hover:-translate-y-0.5 hover:border-primary"
            >
              Issues
            </Link>
            <Link
              href="/scan"
              className="rounded-full border-2 border-border bg-card px-4 py-2 font-mono text-xs uppercase tracking-[0.15em] text-text transition hover:-translate-y-0.5 hover:border-primary"
            >
              Security
            </Link>
          </div>
        </Panel>
      </div>
    </div>
  );
}
