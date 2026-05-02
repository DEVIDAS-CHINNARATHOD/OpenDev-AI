"use client";

import { useMemo, useState } from "react";

type DiffViewerProps = {
  diff: string;
};

type DiffLine = {
  type: "add" | "del" | "ctx" | "hunk" | "header";
  oldNum: number | null;
  newNum: number | null;
  content: string;
};

type DiffFile = {
  filename: string;
  lines: DiffLine[];
};

function parseDiff(raw: string): DiffFile[] {
  if (!raw || !raw.trim()) return [];

  const files: DiffFile[] = [];
  const diffLines = raw.split("\n");
  let currentFile: DiffFile | null = null;
  let oldLine = 0;
  let newLine = 0;

  for (const line of diffLines) {
    // New file header
    if (line.startsWith("diff --git")) {
      const match = line.match(/b\/(.+)$/);
      currentFile = {
        filename: match?.[1] ?? "unknown",
        lines: [],
      };
      files.push(currentFile);
      continue;
    }

    if (!currentFile) continue;

    // Skip --- and +++ headers
    if (line.startsWith("---") || line.startsWith("+++")) {
      currentFile.lines.push({
        type: "header",
        oldNum: null,
        newNum: null,
        content: line,
      });
      continue;
    }

    // Hunk header
    if (line.startsWith("@@")) {
      const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
      if (match) {
        oldLine = parseInt(match[1], 10);
        newLine = parseInt(match[2], 10);
      }
      currentFile.lines.push({
        type: "hunk",
        oldNum: null,
        newNum: null,
        content: line,
      });
      continue;
    }

    // Addition
    if (line.startsWith("+")) {
      currentFile.lines.push({
        type: "add",
        oldNum: null,
        newNum: newLine,
        content: line.slice(1),
      });
      newLine++;
      continue;
    }

    // Deletion
    if (line.startsWith("-")) {
      currentFile.lines.push({
        type: "del",
        oldNum: oldLine,
        newNum: null,
        content: line.slice(1),
      });
      oldLine++;
      continue;
    }

    // Context line
    if (line.startsWith(" ") || line === "") {
      currentFile.lines.push({
        type: "ctx",
        oldNum: oldLine,
        newNum: newLine,
        content: line.startsWith(" ") ? line.slice(1) : line,
      });
      oldLine++;
      newLine++;
    }
  }

  return files;
}

type SideLine = {
  num: number | null;
  content: string;
  type: "add" | "del" | "ctx" | "empty";
};

function buildSideBySide(
  lines: DiffLine[]
): Array<{ left: SideLine; right: SideLine }> {
  const result: Array<{ left: SideLine; right: SideLine }> = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    if (line.type === "hunk" || line.type === "header") {
      i++;
      continue;
    }

    if (line.type === "ctx") {
      result.push({
        left: { num: line.oldNum, content: line.content, type: "ctx" },
        right: { num: line.newNum, content: line.content, type: "ctx" },
      });
      i++;
      continue;
    }

    // Collect consecutive deletions and additions for pairing
    const dels: DiffLine[] = [];
    const adds: DiffLine[] = [];

    while (i < lines.length && lines[i].type === "del") {
      dels.push(lines[i]);
      i++;
    }
    while (i < lines.length && lines[i].type === "add") {
      adds.push(lines[i]);
      i++;
    }

    const maxLen = Math.max(dels.length, adds.length);
    for (let j = 0; j < maxLen; j++) {
      result.push({
        left: j < dels.length
          ? { num: dels[j].oldNum, content: dels[j].content, type: "del" }
          : { num: null, content: "", type: "empty" },
        right: j < adds.length
          ? { num: adds[j].newNum, content: adds[j].content, type: "add" }
          : { num: null, content: "", type: "empty" },
      });
    }
  }

  return result;
}

function lineClass(type: string): string {
  switch (type) {
    case "add":
      return "diff-add";
    case "del":
      return "diff-del";
    case "empty":
      return "opacity-30";
    default:
      return "";
  }
}

export function DiffViewer({ diff }: DiffViewerProps) {
  const [viewMode, setViewMode] = useState<"split" | "unified">("split");
  const [isFullScreen, setIsFullScreen] = useState(false);

  const files = useMemo(() => parseDiff(diff), [diff]);

  if (!diff || !diff.trim()) {
    return (
      <div className="rounded-xl border-2 border-border bg-card p-6 text-center font-mono text-sm text-muted">
        No diff available for this action.
      </div>
    );
  }

  const diffContent = (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex gap-2">
          <button
            type="button"
            onClick={() => setViewMode("split")}
            className={`rounded-full border-2 px-3 py-1.5 font-mono text-xs uppercase tracking-[0.15em] transition ${
              viewMode === "split"
                ? "border-primary bg-primary text-white"
                : "border-border bg-card text-muted hover:border-primary"
            }`}
          >
            Split View
          </button>
          <button
            type="button"
            onClick={() => setViewMode("unified")}
            className={`rounded-full border-2 px-3 py-1.5 font-mono text-xs uppercase tracking-[0.15em] transition ${
              viewMode === "unified"
                ? "border-primary bg-primary text-white"
                : "border-border bg-card text-muted hover:border-primary"
            }`}
          >
            Unified
          </button>
        </div>

        <button
          type="button"
          onClick={() => setIsFullScreen(!isFullScreen)}
          className="rounded-full border-2 border-border bg-card px-3 py-1.5 font-mono text-xs uppercase tracking-[0.15em] text-muted transition hover:border-primary hover:text-primary"
        >
          {isFullScreen ? "✕ Exit Fullscreen" : "⛶ Fullscreen"}
        </button>
      </div>

      {/* Files */}
      {files.map((file, fi) => (
        <div
          key={fi}
          className="overflow-hidden rounded-xl border-2 border-border"
        >
          {/* File header */}
          <div className="flex items-center gap-2 border-b-2 border-border bg-surface px-4 py-2.5">
            <span className="text-sm">📄</span>
            <span className="font-mono text-xs font-medium text-text">
              {file.filename}
            </span>
          </div>

          {viewMode === "split" ? (
            <SplitView lines={file.lines} />
          ) : (
            <UnifiedView lines={file.lines} />
          )}
        </div>
      ))}
    </div>
  );

  if (isFullScreen) {
    return (
      <div className="fullscreen-overlay" onClick={() => setIsFullScreen(false)}>
        <div
          className="fullscreen-content p-4 bg-bg"
          onClick={(e) => e.stopPropagation()}
        >
          {diffContent}
        </div>
      </div>
    );
  }

  return diffContent;
}

function SplitView({ lines }: { lines: DiffLine[] }) {
  const pairs = useMemo(() => buildSideBySide(lines), [lines]);

  // Show hunk headers
  const hunks = lines.filter((l) => l.type === "hunk");

  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse font-mono text-xs leading-6">
        <thead>
          <tr className="bg-surface-strong text-muted">
            <th className="w-12 px-2 py-1 text-right font-normal border-r border-border/30">
              old
            </th>
            <th className="px-2 py-1 text-left font-normal border-r-2 border-border/50 w-1/2">
              removed
            </th>
            <th className="w-12 px-2 py-1 text-right font-normal border-r border-border/30">
              new
            </th>
            <th className="px-2 py-1 text-left font-normal w-1/2">added</th>
          </tr>
        </thead>
        <tbody>
          {hunks.length > 0 && (
            <tr>
              <td
                colSpan={4}
                className="diff-hunk px-3 py-1 font-mono text-xs"
              >
                {hunks[0].content}
              </td>
            </tr>
          )}
          {pairs.map((pair, i) => (
            <tr key={i} className="border-b border-border/10">
              {/* Left side */}
              <td
                className={`diff-line-num w-12 select-none px-2 py-0.5 text-right border-r border-border/20 ${lineClass(pair.left.type)}`}
              >
                {pair.left.num ?? ""}
              </td>
              <td
                className={`px-3 py-0.5 whitespace-pre-wrap break-all border-r-2 border-border/30 ${lineClass(pair.left.type)}`}
              >
                {pair.left.type === "del" && (
                  <span className="mr-1 font-bold text-danger">−</span>
                )}
                {pair.left.content}
              </td>

              {/* Right side */}
              <td
                className={`diff-line-num w-12 select-none px-2 py-0.5 text-right border-r border-border/20 ${lineClass(pair.right.type)}`}
              >
                {pair.right.num ?? ""}
              </td>
              <td
                className={`px-3 py-0.5 whitespace-pre-wrap break-all ${lineClass(pair.right.type)}`}
              >
                {pair.right.type === "add" && (
                  <span className="mr-1 font-bold text-success">+</span>
                )}
                {pair.right.content}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function UnifiedView({ lines }: { lines: DiffLine[] }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse font-mono text-xs leading-6">
        <tbody>
          {lines.map((line, i) => {
            if (line.type === "header") return null;

            if (line.type === "hunk") {
              return (
                <tr key={i}>
                  <td
                    colSpan={3}
                    className="diff-hunk px-3 py-1 font-mono text-xs"
                  >
                    {line.content}
                  </td>
                </tr>
              );
            }

            const prefix =
              line.type === "add"
                ? "+"
                : line.type === "del"
                ? "-"
                : " ";

            return (
              <tr key={i} className="border-b border-border/10">
                <td
                  className={`diff-line-num w-12 select-none px-2 py-0.5 text-right border-r border-border/20 ${lineClass(line.type)}`}
                >
                  {line.oldNum ?? ""}
                </td>
                <td
                  className={`diff-line-num w-12 select-none px-2 py-0.5 text-right border-r border-border/20 ${lineClass(line.type)}`}
                >
                  {line.newNum ?? ""}
                </td>
                <td
                  className={`px-3 py-0.5 whitespace-pre-wrap break-all ${lineClass(line.type)}`}
                >
                  <span
                    className={`mr-2 inline-block w-3 font-bold ${
                      line.type === "add"
                        ? "text-success"
                        : line.type === "del"
                        ? "text-danger"
                        : "text-muted"
                    }`}
                  >
                    {prefix}
                  </span>
                  {line.content}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
