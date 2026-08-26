import { useCallback, useEffect, useState } from "react";
import {
  api,
  type Suggestion,
  type IntelSource,
  type EnforcementMode,
} from "../api";
import { OwnedDomainsPanel } from "./OwnedDomains";

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
  const [mode, setMode] = useState<EnforcementMode>("transparent");
  const [modeBusy, setModeBusy] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await api.suggestions();
      setSuggestions(result.suggestions ?? []);
      setSources(result.sources ?? []);
      setMode(result.mode ?? "transparent");
    } catch (err) {
      setError(String(err));
    }
  }, []);

  const changeMode = async (next: EnforcementMode) => {
    if (next === mode) return;

    setModeBusy(true);
    setError(null);
    try {
      await api.saveIntelKeys({ mode: next });
      setMode(next);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setModeBusy(false);
    }
  };

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 30_000);

    return () => window.clearInterval(timer);
  }, [load]);

  const decide = async (
    domain: string,
    decision: "blocked" | "allowed" | "ignored",
  ) => {
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
        <div className="rounded-lg border border-threat/40 bg-threat/10 px-4 py-3 text-sm text-ink">
          {error}
        </div>
      )}

      <OwnedDomainsPanel />

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          Mod
        </h3>
        <div className="mt-2 flex flex-wrap gap-2">
          <ModeButton
            active={mode === "transparent"}
            disabled={modeBusy}
            onClick={() => void changeMode("transparent")}
            title="Şeffaf Mod"
            description="Yalnızca izler ve kaydeder, hiçbir şeyi otomatik engellemez."
          />
          <ModeButton
            active={mode === "defense"}
            disabled={modeBusy}
            onClick={() => void changeMode("defense")}
            title="Defans Mod"
            description="Araştırır ve bildirir; geçerli SSL sertifikası olan bir alan adını asla otomatik engellemez."
          />
        </div>
      </div>

      {/* Saying which sources are silent is the difference between "nothing is
          suspicious" and "nothing was actually checked". */}
      {unconfigured.length > 0 && (
        <div className="rounded-lg border border-base-700/70 bg-base-850/60 px-4 py-3 text-sm text-ink-muted">
          Only {sources.length - unconfigured.length} of {sources.length} threat
          sources are active.{" "}
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
            Names your network resolves are checked against the threat sources
            in the background. Anything worth a second opinion will appear here.
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
                    <span className="font-mono text-sm text-ink">
                      {s.domain}
                    </span>
                    <ScoreBadge
                      score={s.score}
                      reputable={
                        s.reason.startsWith("a widely used name") ||
                        Boolean(s.protected)
                      }
                    />
                  </div>

                  <p className="mt-1.5 text-xs text-ink-muted">{s.reason}</p>

                  <div className="mt-2 flex flex-wrap gap-2">
                    <TLSBadge hasValidTLS={s.has_valid_tls} note={s.tls_note} />
                    <AgeBadge
                      ageDays={s.domain_age_days}
                      highRisk={s.high_risk}
                    />
                  </div>
                  {s.high_risk && s.high_risk_note && (
                    <p className="mt-1.5 text-xs text-warn">
                      {s.high_risk_note}
                    </p>
                  )}

                  <div className="mt-2 flex flex-wrap gap-3 text-[0.7rem] text-ink-faint">
                    <span>{s.query_count} queries</span>
                    {s.clients.length > 0 && (
                      <span className="font-mono">
                        asked by {s.clients.join(", ")}
                      </span>
                    )}
                    <span>
                      first seen {new Date(s.first_seen).toLocaleString()}
                    </span>
                  </div>

                  {s.findings.length > 0 && (
                    <ul className="mt-3 space-y-1">
                      {s.findings.map((f, i) => (
                        <li key={i} className="text-xs">
                          <span className="font-mono text-accent">
                            {f.source}
                          </span>
                          {f.official && (
                            <span className="ml-1.5 rounded-full border border-safe/50 bg-safe/10 px-1.5 py-0.5 text-[0.6rem] text-safe">
                              resmi kaynak
                            </span>
                          )}
                          <span className="text-ink-muted">
                            {" "}
                            — {f.detail || f.category}
                          </span>
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

function ModeButton({
  active,
  disabled,
  onClick,
  title,
  description,
}: {
  active: boolean;
  disabled: boolean;
  onClick: () => void;
  title: string;
  description: string;
}) {
  return (
    <button
      disabled={disabled}
      onClick={onClick}
      className={`max-w-xs rounded-lg border px-3 py-2 text-left transition-colors disabled:opacity-50 ${
        active
          ? "border-accent-dim bg-accent/10"
          : "border-base-700 hover:border-accent-dim/60"
      }`}
    >
      <span
        className={`block text-xs font-medium ${active ? "text-accent" : "text-ink"}`}
      >
        {title}
      </span>
      <span className="mt-0.5 block text-[0.7rem] text-ink-faint">
        {description}
      </span>
    </button>
  );
}

function TLSBadge({
  hasValidTLS,
  note,
}: {
  hasValidTLS?: boolean | null;
  note?: string;
}) {
  if (hasValidTLS === undefined || hasValidTLS === null) {
    return (
      <span className="rounded-full border border-base-700 px-2 py-0.5 text-[0.65rem] text-ink-faint">
        SSL kontrol edilmedi
      </span>
    );
  }

  if (hasValidTLS) {
    return (
      <span className="rounded-full border border-safe/50 bg-safe/10 px-2 py-0.5 text-[0.65rem] text-safe">
        geçerli SSL
      </span>
    );
  }

  const label =
    note === "cert_invalid"
      ? "geçersiz sertifika"
      : note === "hostname_mismatch"
        ? "sertifika uyuşmuyor"
        : "web sunucusu yanıt vermiyor";

  return (
    <span className="rounded-full border border-base-700 px-2 py-0.5 text-[0.65rem] text-ink-faint">
      {label}
    </span>
  );
}

function AgeBadge({
  ageDays,
  highRisk,
}: {
  ageDays?: number | null;
  highRisk?: boolean;
}) {
  if (ageDays === undefined || ageDays === null) {
    return (
      <span className="rounded-full border border-base-700 px-2 py-0.5 text-[0.65rem] text-ink-faint">
        yaş bilinmiyor
      </span>
    );
  }

  const years = ageDays / 365;
  const text =
    years >= 1
      ? `${years.toFixed(1)} yıllık domain`
      : `${ageDays} gün önce kaydedildi`;

  return (
    <span
      className={`rounded-full border px-2 py-0.5 text-[0.65rem] ${
        highRisk
          ? "border-warn/50 bg-warn/10 text-warn"
          : "border-base-700 text-ink-faint"
      }`}
    >
      {highRisk ? "yeni ve doğrulanmamış · " : ""}
      {text}
    </span>
  );
}

function ScoreBadge({
  score,
  reputable,
}: {
  score: number;
  reputable?: boolean;
}) {
  // A widely used name is never blocked on a report alone, so labelling it
  // "malicious" beside a button that blocks it would be a lie about what the
  // node was prepared to do on its own.
  if (reputable) {
    return (
      <span className="rounded-full border border-warn/50 bg-warn/10 px-2 py-0.5 text-[0.65rem] whitespace-nowrap text-warn">
        reported · your call
      </span>
    );
  }

  const tone =
    score >= 70
      ? "border-threat/50 bg-threat/15 text-threat"
      : "border-warn/50 bg-warn/15 text-warn";

  return (
    <span
      className={`rounded-full border px-2 py-0.5 font-mono text-[0.65rem] ${tone}`}
    >
      {score >= 70 ? "malicious" : "suspect"} · {score}
    </span>
  );
}
