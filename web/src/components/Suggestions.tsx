import { useCallback, useEffect, useState } from "react";
import { api, type Suggestion, type IntelSource } from "../api";

/**
 * The "should I block this?" queue.
 *
 * This is the screen the product exists for: the node did the research, and a
 * person makes the call. Every card says which sources agreed and why, because
 * a block nobody can explain is a block nobody will trust.
 */
export function SuggestionsPanel() {
  const [suggestions, setSuggestions] = useState<Suggestion[] | null>(null);
  const [sources, setSources] = useState<IntelSource[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await api.suggestions();
      setSuggestions(result.suggestions ?? []);
      setSources(result.sources ?? []);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 30_000);

    return () => window.clearInterval(timer);
  }, [load]);

  const decide = async (domain: string, decision: "blocked" | "allowed" | "ignored") => {
    setBusy(domain);
    try {
      await api.decideSuggestion(domain, decision);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(null);
    }
  };

  const unconfigured = sources.filter((s) => !s.configured);

  return (
    <div className="space-y-4">
      {error && (
        <div className="rounded-lg border border-threat/40 bg-threat/10 px-4 py-3 text-sm text-ink">{error}</div>
      )}

      {/* Saying which sources are silent is the difference between "nothing is
          suspicious" and "nothing was actually checked". */}
      {unconfigured.length > 0 && (
        <div className="rounded-lg border border-base-700/70 bg-base-850/60 px-4 py-3 text-sm text-ink-muted">
          Only {sources.length - unconfigured.length} of {sources.length} threat sources are active.{" "}
          <span className="font-mono text-xs text-ink-faint">
            {unconfigured.map((s) => s.name).join(", ")}
          </span>{" "}
          need a free API key before they can be consulted.
        </div>
      )}

      {suggestions === null ? (
        <p className="text-sm text-ink-faint">Loading…</p>
      ) : suggestions.length === 0 ? (
        <div className="rounded-xl border border-base-700/70 bg-base-850/40 px-4 py-10 text-center">
          <p className="text-sm text-ink">Nothing to review.</p>
          <p className="mt-1 text-xs text-ink-faint">
            Names your network resolves are checked against the threat sources in the background. Anything
            worth a second opinion will appear here.
          </p>
        </div>
      ) : (
        <div className="grid gap-3">
          {suggestions.map((s) => (
            <article
              key={s.domain}
              className="rounded-xl border border-base-700/70 bg-base-850/60 p-4 backdrop-blur-sm"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-sm text-ink">{s.domain}</span>
                    <ScoreBadge score={s.score} />
                  </div>

                  <p className="mt-1.5 text-xs text-ink-muted">{s.reason}</p>

                  <div className="mt-2 flex flex-wrap gap-3 text-[0.7rem] text-ink-faint">
                    <span>{s.query_count} queries</span>
                    {s.clients.length > 0 && <span className="font-mono">asked by {s.clients.join(", ")}</span>}
                    <span>first seen {new Date(s.first_seen).toLocaleString()}</span>
                  </div>

                  {s.findings.length > 0 && (
                    <ul className="mt-3 space-y-1">
                      {s.findings.map((f, i) => (
                        <li key={i} className="text-xs">
                          <span className="font-mono text-accent">{f.source}</span>
                          <span className="text-ink-muted"> — {f.detail || f.category}</span>
                          {f.reference && (
                            <a
                              href={f.reference}
                              target="_blank"
                              rel="noreferrer noopener"
                              className="ml-2 text-ink-faint underline decoration-dotted hover:text-accent"
                            >
                              check
                            </a>
                          )}
                        </li>
                      ))}
                    </ul>
                  )}
                </div>

                <div className="flex shrink-0 gap-2">
                  <button
                    disabled={busy === s.domain}
                    onClick={() => void decide(s.domain, "blocked")}
                    className="rounded-md bg-threat px-3 py-1.5 text-xs font-medium text-base-950 transition-opacity hover:opacity-90 disabled:opacity-50"
                  >
                    Block
                  </button>
                  <button
                    disabled={busy === s.domain}
                    onClick={() => void decide(s.domain, "allowed")}
                    className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-safe hover:text-safe disabled:opacity-50"
                  >
                    Allow
                  </button>
                  <button
                    disabled={busy === s.domain}
                    onClick={() => void decide(s.domain, "ignored")}
                    className="rounded-md px-2 py-1.5 text-xs text-ink-faint transition-colors hover:text-ink disabled:opacity-50"
                  >
                    Ignore
                  </button>
                </div>
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  );
}

function ScoreBadge({ score }: { score: number }) {
  const tone =
    score >= 70
      ? "border-threat/50 bg-threat/15 text-threat"
      : "border-warn/50 bg-warn/15 text-warn";

  return (
    <span className={`rounded-full border px-2 py-0.5 font-mono text-[0.65rem] ${tone}`}>
      {score >= 70 ? "malicious" : "suspect"} · {score}
    </span>
  );
}
