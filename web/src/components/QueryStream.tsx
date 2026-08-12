import { useState } from "react";
import type { QueryEntry, Verdict } from "../api";

const verdictStyle: Record<Verdict, string> = {
  blocked: "text-threat",
  paused: "text-warn",
  rewritten: "text-accent",
  error: "text-warn",
  allowed: "text-ink-muted",
};

const verdictDot: Record<Verdict, string> = {
  blocked: "bg-threat",
  paused: "bg-warn",
  rewritten: "bg-accent",
  error: "bg-warn",
  allowed: "bg-safe/60",
};

/**
 * The live query feed.
 *
 * Only the rows in view are rendered — a browser asked to lay out thousands of
 * rows several times a second will drop frames on a laptop, never mind a phone
 * on the sofa. The list is capped upstream in useStream; this caps it again by
 * what is actually shown.
 */
export function QueryStream({ entries }: { entries: QueryEntry[] }) {
  const [filter, setFilter] = useState("");
  const [onlyBlocked, setOnlyBlocked] = useState(false);

  const visible = entries
    .filter((e) => !onlyBlocked || e.verdict === "blocked" || e.verdict === "paused")
    .filter((e) => !filter || e.host.includes(filter.toLowerCase()) || e.client.includes(filter))
    .slice(0, 200);

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/60 backdrop-blur-sm">
      <div className="flex flex-wrap items-center gap-3 border-b border-base-700/70 px-4 py-3">
        <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">Live queries</span>

        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter by name or client"
          className="min-w-0 flex-1 rounded-md border border-base-700 bg-base-900/80 px-2.5 py-1.5 font-mono text-xs text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
        />

        <label className="flex cursor-pointer items-center gap-2 text-xs text-ink-muted select-none">
          <input
            type="checkbox"
            checked={onlyBlocked}
            onChange={(e) => setOnlyBlocked(e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          blocked only
        </label>
      </div>

      <div className="max-h-[26rem] overflow-y-auto">
        {visible.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-ink-faint">
            {entries.length === 0 ? "Waiting for queries…" : "Nothing matches that filter."}
          </p>
        ) : (
          <table className="w-full font-mono text-xs">
            <tbody>
              {visible.map((entry) => (
                <tr key={entry.id} className="border-b border-base-800/60 last:border-0 hover:bg-base-800/40">
                  <td className="w-6 py-1.5 pr-2 pl-4">
                    <span className={`inline-block size-1.5 rounded-full ${verdictDot[entry.verdict]}`} />
                  </td>
                  <td className="py-1.5 pr-3 whitespace-nowrap text-ink-faint">
                    {new Date(entry.time).toLocaleTimeString()}
                  </td>
                  <td className="py-1.5 pr-3 whitespace-nowrap text-ink-muted">
                    {entry.client_id || entry.client}
                  </td>
                  <td className={`max-w-0 truncate py-1.5 pr-3 ${verdictStyle[entry.verdict]}`} title={entry.host}>
                    {entry.host}
                  </td>
                  <td className="w-12 py-1.5 pr-3 text-ink-faint">{entry.qtype}</td>
                  <td className="w-32 truncate py-1.5 pr-4 text-right text-ink-faint" title={entry.rule_source}>
                    {entry.verdict === "blocked" || entry.verdict === "rewritten"
                      ? entry.rule_source
                      : entry.cached
                        ? "cache"
                        : `${entry.elapsed_ms.toFixed(0)}ms`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
