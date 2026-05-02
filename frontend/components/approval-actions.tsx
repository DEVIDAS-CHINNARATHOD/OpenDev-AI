type ApprovalActionsProps = {
  disabled?: boolean;
  loading?: boolean;
  onApprove: () => void;
  onReject: () => void;
};

export function ApprovalActions({
  disabled,
  loading,
  onApprove,
  onReject,
}: ApprovalActionsProps) {
  return (
    <div className="flex flex-wrap gap-3">
      <button
        type="button"
        disabled={disabled || loading}
        onClick={onApprove}
        className="rounded-full border-2 border-primary bg-primary px-6 py-3 font-mono text-sm uppercase tracking-[0.15em] text-white shadow-[3px_3px_0px_0px] shadow-shadow-color transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-40 disabled:shadow-none"
      >
        {loading ? "Processing…" : "✓ Approve"}
      </button>
      <button
        type="button"
        disabled={disabled || loading}
        onClick={onReject}
        className="rounded-full border-2 border-danger bg-danger px-6 py-3 font-mono text-sm uppercase tracking-[0.15em] text-white shadow-[3px_3px_0px_0px] shadow-shadow-color transition hover:-translate-y-0.5 disabled:cursor-not-allowed disabled:opacity-40 disabled:shadow-none"
      >
        ✗ Reject
      </button>
    </div>
  );
}
