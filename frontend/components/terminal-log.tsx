"use client";

import { LogEntry } from "@/lib/types";

type TerminalLogProps = {
  logs: LogEntry[];
  maxHeight?: string;
};

const levelStyles: Record<string, { cls: string; badge: string }> = {
  info:    { cls: "log-info",  badge: "INFO" },
  warn:    { cls: "log-warn",  badge: "WARN" },
  warning: { cls: "log-warn",  badge: "WARN" },
  error:   { cls: "log-error", badge: "ERR " },
  debug:   { cls: "log-debug", badge: "DBG " },
};

export function TerminalLog({ logs, maxHeight = "36rem" }: TerminalLogProps) {
  if (logs.length === 0) {
    return (
      <div
        className="terminal rounded-xl p-5 font-mono text-sm"
        style={{ maxHeight }}
      >
        <span className="log-debug">$ waiting for agent output…</span>
        <span className="ml-1 animate-pulse">▊</span>
      </div>
    );
  }

  return (
    <pre
      className="terminal overflow-auto rounded-xl p-5 font-mono text-xs leading-7"
      style={{ maxHeight }}
    >
      {logs.map((entry, i) => {
        const ts = new Date(entry.timestamp).toLocaleTimeString();
        const style = levelStyles[entry.level] ?? levelStyles.info;

        return (
          <span key={i} className="block">
            <span className="log-timestamp">[{ts}]</span>{" "}
            <span className={style.cls + " font-bold"}>
              [{style.badge}]
            </span>{" "}
            <span className="log-step">[{entry.step}]</span>{" "}
            <span className="text-terminal-text">{entry.message}</span>
          </span>
        );
      })}
      <span className="log-debug animate-pulse">▊</span>
    </pre>
  );
}
