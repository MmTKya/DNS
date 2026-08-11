import type { ComponentStatus } from "../api";

interface StatusCardProps {
  label: string;
  value: string;
  status?: ComponentStatus;
  detail?: string;
  /** Rendered dimmed with a note when the feature needs gateway mode. */
  unavailable?: string;
}

const statusColor: Record<ComponentStatus, string> = {
  ok: "bg-safe",
  degraded: "bg-threat",
};

/**
 * The base tile of the panel: a glass card with one number and one status dot.
 * Phase 1's KPI row, and later the per-client cards, are built from this.
 */
export function StatusCard({ label, value, status, detail, unavailable }: StatusCardProps) {
  return (
    <div
      className={`rounded-xl border border-base-700/70 bg-base-850/60 p-4 backdrop-blur-sm ${
        unavailable ? "opacity-60" : ""
      }`}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">{label}</span>
        {status && (
          <span
            className={`size-2 rounded-full ${statusColor[status]} ${status === "ok" ? "pulse-dot" : ""}`}
            aria-label={status}
          />
        )}
      </div>

      <div className="mt-2 font-mono text-2xl text-ink tabular-nums">{value}</div>

      {detail && <div className="mt-1 text-xs text-ink-faint">{detail}</div>}

      {unavailable && (
        <div className="mt-2 border-t border-base-700/70 pt-2 text-xs text-warn">{unavailable}</div>
      )}
    </div>
  );
}
