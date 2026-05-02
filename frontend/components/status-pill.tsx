type StatusPillProps = {
  label: string;
  tone?: "primary" | "danger" | "neutral" | "warning" | "success";
};

export function StatusPill({ label, tone = "neutral" }: StatusPillProps) {
  const cls =
    tone === "primary"
      ? "border-primary bg-primary text-white"
      : tone === "danger"
      ? "border-danger bg-danger text-white"
      : tone === "warning"
      ? "border-accent bg-accent-soft text-text"
      : tone === "success"
      ? "border-success bg-success-soft text-text"
      : "border-border bg-card text-text";

  return (
    <span
      className={`inline-flex rounded-full border-2 px-3 py-0.5 font-mono text-xs uppercase tracking-[0.15em] ${cls}`}
    >
      {label}
    </span>
  );
}
