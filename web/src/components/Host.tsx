import { useCallback, useEffect, useState } from "react";
import { api, formatBytes, type HostInfo } from "../api";
import { Notice } from "./Panels";

/**
 * The machine itself: disk, memory, processor, heat.
 *
 * This is the screen someone opens when the node has gone slow, and the point
 * of it is to separate two faults that look identical from the sofa. A full
 * card, a hot processor and an underpowered board all present as "the internet
 * is slow", and none of them show up anywhere else in this panel.
 *
 * Nothing here is estimated. A machine that does not publish its temperature
 * gets no temperature — not a zero, and not a guess.
 */
export function HostPanel() {
  const [host, setHost] = useState<HostInfo | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setHost(await api.hostInfo());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();

    // Often enough that a processor spike is visible, rarely enough that the
    // measuring is not itself the load.
    const timer = window.setInterval(() => void load(), 5000);

    return () => window.clearInterval(timer);
  }, [load]);

  if (error && !host) return <Notice tone="threat">{error}</Notice>;
  if (!host) return <Notice>Loading…</Notice>;

  return (
    <div className="space-y-5">
      {(host.throttling?.length ?? 0) > 0 && (
        <div className="rounded-xl border border-threat/50 bg-threat/10 p-4">
          <h3 className="text-sm font-medium text-threat">
            The board is reporting a problem
          </h3>
          <ul className="mt-2 space-y-1">
            {host.throttling?.map((line) => (
              <li key={line} className="text-xs text-ink">
                {line}
              </li>
            ))}
          </ul>
          <p className="mt-2 max-w-prose text-xs text-ink-muted">
            An underpowered board does not stop — it runs at a fraction of its
            speed, and the household experiences that as a slow connection with
            nothing in any log to explain it. The usual cause is a phone charger
            being used as a power supply.
          </p>
        </div>
      )}

      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h3 className="text-sm font-medium text-ink">
            {host.model || "This machine"}
          </h3>
          <span className="font-mono text-[0.7rem] text-ink-faint">
            up {formatUptime(host.uptime_seconds)}
          </span>
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Gauge
            title="Processor"
            detail={`${host.cpu.cores} core${host.cpu.cores === 1 ? "" : "s"} · load ${host.cpu.load
              .map((l) => l.toFixed(2))
              .join("  ")}`}
            percent={host.cpu.busy_percent}
            reading={`${host.cpu.busy_percent.toFixed(0)}%`}
            warnAt={80}
            alarmAt={95}
          />

          <Gauge
            title="Memory"
            detail={`${formatBytes(host.memory.used_bytes)} of ${formatBytes(host.memory.total_bytes)} in use`}
            percent={percent(host.memory.used_bytes, host.memory.total_bytes)}
            reading={`${percent(host.memory.used_bytes, host.memory.total_bytes).toFixed(0)}%`}
            warnAt={85}
            alarmAt={95}
          />

          {host.disks.map((disk) => (
            <Gauge
              key={disk.path}
              title={disk.label}
              detail={`${formatBytes(disk.total_bytes - disk.used_bytes)} free of ${formatBytes(disk.total_bytes)} · ${disk.path}`}
              percent={percent(disk.used_bytes, disk.total_bytes)}
              reading={`${percent(disk.used_bytes, disk.total_bytes).toFixed(0)}%`}
              warnAt={80}
              alarmAt={92}
            />
          ))}

          {host.swap && (
            <Gauge
              title="Swap"
              detail={`${formatBytes(host.swap.used_bytes)} of ${formatBytes(host.swap.total_bytes)} in use`}
              percent={percent(host.swap.used_bytes, host.swap.total_bytes)}
              reading={`${percent(host.swap.used_bytes, host.swap.total_bytes).toFixed(0)}%`}
              warnAt={50}
              alarmAt={80}
            />
          )}

          {host.temperature_c !== undefined && (
            <Gauge
              title="Temperature"
              detail="a board slows itself down rather than overheat"
              percent={Math.min((host.temperature_c / 85) * 100, 100)}
              reading={`${host.temperature_c.toFixed(1)} °C`}
              warnAt={82}
              alarmAt={94}
            />
          )}
        </div>

        {(host.cpu.per_core_percent?.length ?? 0) > 1 && (
          <div className="mt-4">
            <span className="text-[0.65rem] tracking-wide text-ink-faint uppercase">
              Each core
            </span>
            <div className="mt-2 flex flex-wrap gap-2">
              {host.cpu.per_core_percent?.map((core, index) => (
                <div
                  key={index}
                  className="flex min-w-[4.5rem] items-baseline justify-between gap-2 rounded-md border border-base-800/80 bg-base-900/40 px-2 py-1"
                >
                  <span className="font-mono text-[0.65rem] text-ink-faint">
                    {index}
                  </span>
                  <span className="font-mono text-xs text-ink tabular-nums">
                    {core.toFixed(0)}%
                  </span>
                </div>
              ))}
            </div>
            <p className="mt-2 max-w-prose text-xs text-ink-faint">
              One core at a hundred while the rest are idle is one job stuck,
              not a machine that is too small.
            </p>
          </div>
        )}
      </div>

      <p className="max-w-prose text-xs text-ink-faint">
        Memory in use is the total minus what is available, not minus what is
        free. Linux fills the spare with cache and hands it back when something
        asks — reading free would put a healthy machine at 97% and send you
        looking for a problem that is not there.
      </p>

      {error && <Notice tone="threat">{error}</Notice>}
    </div>
  );
}

function percent(used: number, total: number): number {
  return total > 0 ? (used / total) * 100 : 0;
}

/**
 * One measurement, as a bar.
 *
 * The colour carries the state as well as the number does, so a card that
 * needs attention is visible without reading any of them.
 */
function Gauge({
  title,
  detail,
  percent: value,
  reading,
  warnAt,
  alarmAt,
}: {
  title: string;
  detail: string;
  percent: number;
  reading: string;
  warnAt: number;
  alarmAt: number;
}) {
  const clamped = Math.max(0, Math.min(value, 100));

  // Written out rather than composed, because Tailwind only ships the classes
  // it can see in the source: a class built from a variable is a bar with no
  // colour at all.
  const tone =
    clamped >= alarmAt
      ? { text: "text-threat", bar: "bg-threat" }
      : clamped >= warnAt
        ? { text: "text-warn", bar: "bg-warn" }
        : { text: "text-safe", bar: "bg-safe" };

  return (
    <div className="rounded-lg border border-base-800/80 bg-base-900/40 p-3">
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-sm text-ink">{title}</span>
        <span className={`font-mono text-sm tabular-nums ${tone.text}`}>
          {reading}
        </span>
      </div>

      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-base-800">
        <div
          className={`h-full rounded-full ${tone.bar} transition-[width] duration-500`}
          style={{ width: `${clamped}%` }}
        />
      </div>

      <p className="mt-1.5 font-mono text-[0.7rem] break-all text-ink-faint">
        {detail}
      </p>
    </div>
  );
}

function formatUptime(seconds: number): string {
  if (seconds <= 0) return "not known";

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;

  return `${minutes}m`;
}
