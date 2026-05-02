import { ReactNode } from "react";

type PanelProps = {
  title: string;
  eyebrow?: string;
  actions?: ReactNode;
  children: ReactNode;
};

export function Panel({ title, eyebrow, actions, children }: PanelProps) {
  return (
    <section className="rounded-2xl border-2 border-border bg-surface p-5 shadow-[5px_5px_0px_0px] shadow-shadow-color">
      <div className="mb-5 flex flex-col gap-3 border-b-2 border-primary/40 pb-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="space-y-1">
          {eyebrow ? (
            <p className="font-mono text-xs uppercase tracking-[0.25em] text-muted">
              {eyebrow}
            </p>
          ) : null}
          <h2 className="text-xl font-semibold tracking-tight text-text">
            {title}
          </h2>
        </div>
        {actions}
      </div>
      {children}
    </section>
  );
}
