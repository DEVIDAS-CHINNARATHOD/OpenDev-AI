"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { Panel } from "@/components/panel";
import { StatusPill } from "@/components/status-pill";
import { useAppSession } from "@/components/session-provider";
import { createRepoSession } from "@/lib/api";
import { initialAppState } from "@/lib/types";

export default function HomePage() {
  const router = useRouter();
  const { state, hydrateComplete, replaceState } = useAppSession();
  const [repoUrl, setRepoUrl] = useState(state.repoUrl);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (hydrateComplete) setRepoUrl(state.repoUrl);
  }, [hydrateComplete, state.repoUrl]);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoading(true);
    setError(null);
    setStep("Connecting to GitHub…");
    try {
      setStep("Fetching repository & analyzing codebase…");
      const payload = await createRepoSession(repoUrl);
      replaceState({
        ...initialAppState,
        sessionId: payload.session_id,
        repoUrl,
        repo: payload.repo,
        repoAnalysis: payload.repo_analysis,
        issues: payload.issues,
        logs: payload.logs,
      });
      router.push("/analyze");
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Unable to load repository."
      );
      setStep("");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-8">
      <section className="rounded-2xl border-2 border-border bg-card/80 p-6 shadow-[6px_6px_0px_0px] shadow-shadow-color backdrop-blur md:p-8">
        <div className="grid gap-8 lg:grid-cols-[1.1fr_0.9fr] lg:items-start">
          <div className="space-y-6">
            <div className="space-y-3">
              <p className="font-handwritten text-2xl text-primary">
                AI workflow for GitHub maintenance
              </p>
              <h2 className="max-w-3xl text-3xl font-bold tracking-tight md:text-5xl">
                Fix issues, scan secrets, review PRs — with AI.
              </h2>
              <p className="max-w-2xl text-base leading-7 text-muted">
                Paste any GitHub repository URL. OpenDev AI analyses the
                codebase, fixes open issues via cross-fork PR, scans for
                vulnerabilities and exposed secrets, and reviews pull requests —
                all in one workflow.
              </p>
            </div>

            <form
              onSubmit={handleSubmit}
              className="space-y-5 rounded-2xl border-2 border-border bg-surface p-5 shadow-[4px_4px_0px_0px] shadow-shadow-color"
            >
              <label className="block space-y-2">
                <span className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
                  GitHub repository URL
                </span>
                <input
                  required
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/owner/repository"
                  className="w-full rounded-xl border-2 border-border bg-card px-4 py-3.5 font-mono text-sm text-text outline-none transition focus:border-primary"
                  disabled={loading}
                />
              </label>

              <button
                type="submit"
                disabled={loading || !repoUrl}
                className="rounded-full border-2 border-border bg-accent px-6 py-3 font-mono text-sm uppercase tracking-[0.15em] text-text shadow-[4px_4px_0px_0px] shadow-shadow-color transition hover:-translate-x-0.5 hover:-translate-y-0.5 hover:bg-[#ffd24d] disabled:cursor-not-allowed disabled:opacity-50"
              >
                {loading ? step || "Loading…" : "Analyse repository →"}
              </button>

              {error && (
                <p className="rounded-xl border-2 border-danger bg-danger-soft p-4 font-mono text-sm text-danger">
                  {error}
                </p>
              )}

              <div className="space-y-1">
                <p className="font-mono text-xs uppercase tracking-[0.2em] text-muted">
                  Try these:
                </p>
                <div className="flex flex-wrap gap-2">
                  {[
                    "https://github.com/tiangolo/fastapi",
                    "https://github.com/vercel/next.js",
                  ].map((ex) => (
                    <button
                      key={ex}
                      type="button"
                      onClick={() => setRepoUrl(ex)}
                      className="rounded-full border border-border bg-card px-3 py-1 font-mono text-xs text-muted transition hover:border-primary hover:text-primary"
                    >
                      {ex.replace("https://github.com/", "")}
                    </button>
                  ))}
                </div>
              </div>
            </form>
          </div>

          <Panel title="Workflow" eyebrow="Capabilities">
            <div className="grid gap-3">
              {[
                {
                  label: "Repository Analysis",
                  tone: "primary" as const,
                  text: "Detects language, framework, tech stack, dependencies, and code quality grade before any action is taken.",
                },
                {
                  label: "Fork & Fix Issue",
                  tone: "primary" as const,
                  text: "Forks the repo, generates an LLM patch, runs tests, then opens a cross-fork PR to the original owner.",
                },
                {
                  label: "Security Scan",
                  tone: "danger" as const,
                  text: "Finds SQL injection, XSS, SSRF, prototype pollution, hardcoded secrets, Firebase configs, MongoDB URIs, AWS keys, and 25+ secret types.",
                },
                {
                  label: "Scan → GitHub Issues",
                  tone: "neutral" as const,
                  text: "One click opens a labelled GitHub issue for every finding — with de-duplication to avoid re-creating existing issues.",
                },
                {
                  label: "PR Reviewer",
                  tone: "neutral" as const,
                  text: "AI reviews any pull request — detects bugs, security issues, and style problems. Recommends MERGE, REQUEST_CHANGES, or COMMENT.",
                },
              ].map(({ label, tone, text }) => (
                <div
                  key={label}
                  className="space-y-2 rounded-xl border-2 border-border bg-card p-4"
                >
                  <StatusPill label={label} tone={tone} />
                  <p className="font-mono text-xs leading-6 text-muted">
                    {text}
                  </p>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      </section>
    </div>
  );
}
