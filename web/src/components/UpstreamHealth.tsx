import { useEffect, useState } from "react";
import { api, type UpstreamHealthReport } from "../api";

/**
 * How the resolvers behind this node are behaving.
 *
 * On the dashboard because of the question people actually arrive with: a page
 * will not load, and they want to know whether it is this node, the resolvers
 * behind it, or the internet. That is answerable in one glance, and answering
 * it anywhere else means a terminal.
 */
export function UpstreamHealthCard() {
  const [report, setReport] = useState<UpstreamHealthReport | null>(null);

  useEffect(() => {
    const load = () => void api.upstreamHealth().then(setReport).catch(() => undefined);

    load();
    // The node probes every 30 s, so asking more often would show the same
    // numbers with more requests.
    const timer = window.setInterval(load, 15_000);

    return () => window.clearInterval(timer);
  }, []);

  if (!report?.available) return null;

  const upstreams = report.upstreams ?? [];
  const unhealthy = upstreams.filter((u) => !u.healthy);
  const rescues = report.rescues ?? 0;

  return (
    <section className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h2 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          Resolvers behind this node
        </h2>
        {rescues > 0 && (
          <span className={`text-xs ${rescues > 50 ? "text-warn" : "text-ink-faint"}`}>
            {rescues.toLocaleString()} lookup{rescues === 1 ? "" : "s"} needed a second resolver
          </span>
        )}
      </div>

      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        {upstreams.map((u) => (
          <div
            key={u.address}
            className="flex items-center justify-between gap-3 rounded-lg border border-base-800/80 bg-base-900/40 px-3 py-2"
          >
            <div className="flex min-w-0 items-center gap-2">
              <span
                className={`size-2 shrink-0 rounded-full ${u.healthy ? "bg-safe" : "bg-threat"}`}
                aria-label={u.healthy ? "answering" : "not answering"}
              />
              <span className="truncate font-mono text-xs text-ink">{u.address}</span>
              {u.role === "fallback" && (
                <span className="shrink-0 text-[0.65rem] text-ink-faint">fallback</span>
              )}
            </div>

            <span
              className={`shrink-0 font-mono text-xs tabular-nums ${
                u.healthy ? latencyTone(u.latency_ms) : "text-threat"
              }`}
            >
              {u.healthy ? `${u.latency_ms} ms` : (u.error ?? "no answer").slice(0, 24)}
            </span>
          </div>
        ))}
      </div>

      {unhealthy.length > 0 && (
        <p className="mt-2 max-w-prose text-xs text-warn">
          {unhealthy.length === upstreams.length
            ? "None of them are answering. That is the internet connection or the network, not this node."
            : "One is not answering. Queries still work through the others; replace it under System → Resolvers."}
        </p>
      )}

      {rescues > 50 && unhealthy.length === 0 && (
        <p className="mt-2 max-w-prose text-xs text-warn">
          A lot of lookups are only succeeding on the second resolver, which means the first one is
          failing quietly. Measure them under System → Resolvers.
        </p>
      )}
    </section>
  );
}

/** Latency in the terms someone cares about, not a gradient. */
function latencyTone(ms: number): string {
  if (ms < 50) return "text-safe";
  if (ms < 150) return "text-ink-muted";

  return "text-warn";
}
