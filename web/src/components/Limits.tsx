import { useState } from "react";
import { api, type DeviceLimit } from "../api";

/**
 * A speed limit for one device.
 *
 * Entered in megabits because that is the unit on everyone's internet bill and
 * in every speed test; stored in kilobits because that is what the kernel
 * takes. Nobody should have to do that conversion to cap a tablet.
 */
export function LimitControl({
  clientKey,
  limit,
  enforced,
  onChanged,
}: {
  clientKey: string;
  limit?: DeviceLimit;
  enforced: boolean;
  onChanged: () => void | Promise<void>;
}) {
  const [open, setOpen] = useState(false);
  const [down, setDown] = useState(limit ? String(limit.download_kbps / 1000) : "");
  const [up, setUp] = useState(limit ? String(limit.upload_kbps / 1000) : "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="text-xs text-ink-faint transition-colors hover:text-accent"
        title={enforced ? undefined : "Saved now, enforced in gateway mode"}
      >
        {limit
          ? `${mbps(limit.download_kbps)} ↓ / ${mbps(limit.upload_kbps)} ↑`
          : "set a speed limit"}
      </button>
    );
  }

  const save = async () => {
    setError(null);
    setBusy(true);

    try {
      await api.setLimit(clientKey, toKbps(down), toKbps(up));
      setOpen(false);
      await onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const clear = async () => {
    setBusy(true);

    try {
      await api.removeLimit(clientKey);
      setOpen(false);
      await onChanged();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mt-2 w-full rounded-lg border border-base-700/70 bg-base-900/60 p-3">
      <div className="flex flex-wrap items-end gap-3">
        <label className="w-28 text-[0.65rem] font-medium tracking-wide text-ink-muted uppercase">
          Download
          <div className="mt-1 flex items-baseline gap-1">
            <input
              value={down}
              onChange={(e) => setDown(e.target.value)}
              placeholder="0"
              inputMode="decimal"
              className="w-full rounded-md border border-base-700 bg-base-900/80 px-2 py-1.5 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
            />
            <span className="text-[0.65rem] normal-case text-ink-faint">Mbps</span>
          </div>
        </label>

        <label className="w-28 text-[0.65rem] font-medium tracking-wide text-ink-muted uppercase">
          Upload
          <div className="mt-1 flex items-baseline gap-1">
            <input
              value={up}
              onChange={(e) => setUp(e.target.value)}
              placeholder="0"
              inputMode="decimal"
              className="w-full rounded-md border border-base-700 bg-base-900/80 px-2 py-1.5 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
            />
            <span className="text-[0.65rem] normal-case text-ink-faint">Mbps</span>
          </div>
        </label>

        <button
          onClick={() => void save()}
          disabled={busy}
          className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          Save
        </button>
        {limit && (
          <button
            onClick={() => void clear()}
            disabled={busy}
            className="text-xs text-ink-faint transition-colors hover:text-threat"
          >
            remove
          </button>
        )}
        <button onClick={() => setOpen(false)} className="text-xs text-ink-faint transition-colors hover:text-ink">
          cancel
        </button>
      </div>

      <p className="mt-2 text-xs text-ink-faint">
        Leave a box empty to leave that direction alone.
      </p>
      {error && <p className="mt-1 text-xs text-threat">{error}</p>}
    </div>
  );
}

function mbps(kbps: number): string {
  if (kbps === 0) return "—";

  return `${(kbps / 1000).toFixed(kbps % 1000 === 0 ? 0 : 1)} Mbps`;
}

function toKbps(value: string): number {
  const n = Number.parseFloat(value.replace(",", "."));
  if (!Number.isFinite(n) || n <= 0) return 0;

  return Math.round(n * 1000);
}
