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
          <div className="divide-y divide-base-800/60">
            {visible.map((entry) => (
              <div
                key={entry.id}
                className="flex items-baseline gap-2.5 px-4 py-1.5 hover:bg-base-800/40"
              >
                <span
                  className={`mt-1.5 size-1.5 shrink-0 rounded-full ${verdictDot[entry.verdict]}`}
                  aria-label={entry.verdict}
                />

                {/* The name comes first and takes the room. It is the only
                    thing on this screen anyone is reading: what was asked
                    for, and whether it got through. Everything else was
                    pushing it into whatever space was left over. */}
                <span
                  className={`min-w-0 flex-1 truncate font-mono text-sm ${verdictStyle[entry.verdict]}`}
                  title={entry.host}
                >
                  {entry.host}
                </span>

                {/* Why, when it was stopped — the second question, right
                    next to the first. */}
                {(entry.verdict === "blocked" || entry.verdict === "rewritten") && entry.rule_source && (
                  <span className="hidden shrink-0 truncate font-mono text-[0.7rem] text-ink-faint sm:inline sm:max-w-[9rem]">
                    {entry.rule_source}
                  </span>
                )}

                <span className="shrink-0 font-mono text-[0.7rem] whitespace-nowrap text-ink-faint">
                  {entry.client_id || entry.client}
                </span>
                <span className="hidden shrink-0 font-mono text-[0.7rem] text-ink-faint sm:inline">
                  {entry.qtype}
                </span>
                <span className="shrink-0 font-mono text-[0.7rem] whitespace-nowrap text-ink-faint tabular-nums">
                  {new Date(entry.time).toLocaleTimeString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
