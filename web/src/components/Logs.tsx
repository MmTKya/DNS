import { useCallback, useEffect, useState } from "react";
import { api, type NodeEvent, type QueryEntry } from "../api";
import { Notice } from "./Panels";

/**
 * Everything the node can tell you about why something happened.
 *
 * This screen replaces a shell session. The answer to "why did that page not
 * open" used to be journalctl, which means the only people who could diagnose
 * their own network were the ones who did not need this product.
 *
 * Two lists rather than one merged stream: queries are what devices asked for
 * and there are hundreds of thousands of them, while events are the handful of
 * moments that explain a failure. Putting them together would bury the second
 * kind in the first.
 */
export function LogsPanel() {
  const [view, setView] = useState<"queries" | "events">("queries");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap gap-1">
        {(
          [
            ["queries", "Queries"],
            ["events", "What the node noticed"],
          ] as const
        ).map(([id, label]) => (
          <button
            key={id}
            onClick={() => setView(id)}
            className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
              view === id ? "bg-accent text-base-950" : "border border-base-700 text-ink-muted hover:text-ink"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {view === "queries" ? <QueryHistory /> : <NodeEvents />}
    </div>
  );
}

const verdictFilters: { id: string; label: string; hint: string }[] = [
  { id: "", label: "Everything", hint: "every query this node answered" },
  { id: "blocked", label: "Blocked", hint: "stopped by a blocklist or one of your rules" },
  { id: "allowed", label: "Allowed", hint: "resolved normally" },
  { id: "rewritten", label: "Rewritten", hint: "answered with an address you chose" },
  { id: "error", label: "Failed", hint: "the node could not answer at all" },
  { id: "paused", label: "Paused device", hint: "refused because the device is paused" },
];

function QueryHistory() {
  const [verdict, setVerdict] = useState("");
  const [host, setHost] = useState("");
  const [entries, setEntries] = useState<QueryEntry[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setEntries(await api.queryHistory({ verdict, host: host.trim(), limit: 200 }));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [verdict, host]);

  useEffect(() => {
    void load();
  }, [load]);

  const active = verdictFilters.find((f) => f.id === verdict);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-1">
        {verdictFilters.map((f) => (
          <button
            key={f.id || "all"}
            onClick={() => setVerdict(f.id)}
            title={f.hint}
            className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
              verdict === f.id
                ? "bg-base-700 text-ink"
                : "border border-base-700 text-ink-muted hover:text-ink"
            }`}
          >
            {f.label}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <input
          value={host}
          onChange={(e) => setHost(e.target.value)}
          placeholder="filter by name, e.g. gib.gov.tr"
          className="min-w-[16rem] flex-1 rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
        />
        <button
          onClick={() => void load()}
          className="rounded-md border border-base-700 px-3 py-2 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
        >
          Refresh
        </button>
      </div>

      {active && <p className="text-xs text-ink-faint">{active.hint}</p>}
      {error && <Notice tone="threat">{error}</Notice>}

      <div className="rounded-xl border border-base-700/70 bg-base-850/60">
        {!entries ? (
          <p className="px-4 py-8 text-center text-sm text-ink-faint">Loading…</p>
        ) : entries.length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-ink-faint">
            Nothing matches. {verdict === "error" && "No failed lookups is the good outcome here."}
          </p>
        ) : (
          <div className="divide-y divide-base-800/60">
            {entries.map((e) => (
              <div key={e.id} className="px-4 py-3">
                {/* The name first and at full size: it is what someone came
                    here to read. Everything else is context for it. */}
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <VerdictTag verdict={e.verdict} />
                  <span className="font-mono text-sm break-all text-ink">{e.host}</span>
                  <span className="font-mono text-[0.7rem] text-ink-faint">{e.qtype}</span>
                </div>

                <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-ink-faint">
                  <span>{new Date(e.time).toLocaleString()}</span>
                  <span>from {e.client_id || e.client}</span>
                  <span>{e.elapsed_ms} ms</span>
                  {e.cached && <span>from cache</span>}
                  {e.upstream && <span>via {e.upstream}</span>}
                </div>

                {/* Why it was blocked, which is the whole question when
                    something legitimate stops working. */}
                {e.verdict === "blocked" && (
                  <p className="mt-1.5 text-xs text-threat">
                    Blocked by {e.rule_source || "a rule"}
                    {e.matched_domain && e.matched_domain !== e.host && (
                      <> — matched on <span className="font-mono">{e.matched_domain}</span></>
                    )}
                  </p>
                )}
                {e.verdict === "rewritten" && (
                  <p className="mt-1.5 text-xs text-accent">
                    Answered with an address from {e.rule_source || "one of your rules"}
                  </p>
                )}
                {e.error && <p className="mt-1.5 text-xs text-warn">{e.error}</p>}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function VerdictTag({ verdict }: { verdict: string }) {
  const tone =
    verdict === "blocked"
      ? "border-threat/50 bg-threat/10 text-threat"
      : verdict === "error"
        ? "border-warn/50 bg-warn/10 text-warn"
        : verdict === "rewritten"
          ? "border-accent-dim/60 bg-accent/10 text-accent"
          : verdict === "paused"
            ? "border-base-600 bg-base-800 text-ink-muted"
            : "border-safe/40 bg-safe/10 text-safe";

  return (
    <span className={`rounded-full border px-2 py-0.5 text-[0.65rem] whitespace-nowrap ${tone}`}>
      {verdict === "error" ? "failed" : verdict}
    </span>
  );
}

/** What each kind means, in the words of someone whose page did not load. */
const eventKinds: Record<string, { label: string; meaning: string }> = {
  rescued: {
    label: "Needed a second resolver",
    meaning:
      "The first resolver could not answer this name and another one could. Occasional is normal; a lot of these means the resolver in front is failing while the answers still arrive.",
  },
  rebind_blocked: {
    label: "Answer dropped",
    meaning:
      "A public name was answered with an address inside your own network, which is how a page on the internet gets a browser to talk to your router. If something legitimate stopped working, look here first.",
  },
  feed_failed: {
    label: "Blocklist not updated",
    meaning:
      "A list could not be downloaded. Blocking still works from the last copy, but it stops improving, and nothing else would tell you.",
  },
  upstream_down: { label: "Resolver stopped answering", meaning: "One of the resolvers behind this node went quiet." },
  upstream_recovered: { label: "Resolver back", meaning: "It is answering again." },
};

function NodeEvents() {
  const [kind, setKind] = useState("");
  const [data, setData] = useState<{ events: NodeEvent[] | null; counts: Record<string, number> } | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.events(kind));
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, [kind]);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 20_000);

    return () => window.clearInterval(timer);
  }, [load]);

  if (error) return <Notice tone="threat">{error}</Notice>;
  if (!data) return <Notice>Loading…</Notice>;

  const list = data.events ?? [];
  const counts = data.counts ?? {};
  // Only offer filters that would return something, rather than a row of
  // buttons that all lead to an empty list.
  const available = Object.keys(eventKinds).filter((k) => (counts[k] ?? 0) > 0);

  return (
    <div className="space-y-3">
      {available.length > 0 && (
        <div className="flex flex-wrap gap-1">
          <button
            onClick={() => setKind("")}
            className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
              kind === "" ? "bg-base-700 text-ink" : "border border-base-700 text-ink-muted hover:text-ink"
            }`}
          >
            Everything
          </button>
          {available.map((k) => (
            <button
              key={k}
              onClick={() => setKind(k)}
              className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
                kind === k ? "bg-base-700 text-ink" : "border border-base-700 text-ink-muted hover:text-ink"
              }`}
            >
              {eventKinds[k].label}
              <span className="ml-1.5 text-ink-faint">{counts[k]}</span>
            </button>
          ))}
        </div>
      )}

      {kind && <p className="max-w-prose text-xs text-ink-faint">{eventKinds[kind]?.meaning}</p>}

      <div className="rounded-xl border border-base-700/70 bg-base-850/60">
        {list.length === 0 ? (
          <div className="px-4 py-10 text-center">
            <p className="text-sm text-ink">Nothing to report.</p>
            <p className="mx-auto mt-1 max-w-prose text-xs text-ink-faint">
              Lookups that needed a second resolver, answers dropped for pointing into your network,
              and blocklists that failed to update all appear here. An empty list is the node working.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-base-800/60">
            {list.map((e) => (
              <div key={e.id} className="px-4 py-3">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <span
                    className={`rounded-full border px-2 py-0.5 text-[0.65rem] whitespace-nowrap ${
                      e.severity === "warning"
                        ? "border-warn/50 bg-warn/10 text-warn"
                        : e.severity === "error"
                          ? "border-threat/50 bg-threat/10 text-threat"
                          : "border-base-600 text-ink-muted"
                    }`}
                  >
                    {eventKinds[e.kind]?.label ?? e.kind}
                  </span>
                  <span className="font-mono text-sm break-all text-ink">{e.subject}</span>
                </div>

                {e.detail && <p className="mt-1.5 max-w-prose text-xs text-ink-muted">{e.detail}</p>}
                <p className="mt-1 text-xs text-ink-faint">{new Date(e.at).toLocaleString()}</p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
