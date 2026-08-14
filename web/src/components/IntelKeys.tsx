import { useCallback, useEffect, useState } from "react";
import { api, type IntelFinding, type IntelSource } from "../api";
import { Notice } from "./Panels";

/**
 * Keys for the services that say whether a domain is dangerous.
 *
 * Without them the review queue still works, but on far less: it can see that
 * a name is new and odd-looking, not that somebody has already reported it
 * hosting malware. The screen says which sources are missing rather than
 * quietly doing less than someone expects.
 *
 * Keys go in and never come back out. The endpoint that stores them cannot
 * read them, so a borrowed session cannot walk off with them — which is why
 * the fields are always empty even when a key is set.
 */
export function IntelKeysPanel() {
  const [sources, setSources] = useState<IntelSource[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);

  const [abuseCh, setAbuseCh] = useState("");
  const [safeBrowsing, setSafeBrowsing] = useState("");
  const [otx, setOTX] = useState("");

  const load = useCallback(async () => {
    try {
      setSources(await api.intelSources());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      await api.saveIntelKeys({
        abusech_key: abuseCh.trim() || undefined,
        safebrowsing_key: safeBrowsing.trim() || undefined,
        otx_key: otx.trim() || undefined,
      });
      setAbuseCh("");
      setSafeBrowsing("");
      setOTX("");
      setSaved(true);
      window.setTimeout(() => setSaved(false), 2500);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const fields: { label: string; value: string; set: (v: string) => void; where: string; free: string }[] = [
    {
      label: "abuse.ch",
      value: abuseCh,
      set: setAbuseCh,
      where: "auth.abuse.ch",
      free: "Free. Malware and command-and-control domains, reported by researchers.",
    },
    {
      label: "Google Safe Browsing",
      value: safeBrowsing,
      set: setSafeBrowsing,
      where: "console.cloud.google.com",
      free: "Free tier. What Chrome checks against — phishing and compromised sites.",
    },
    {
      label: "AlienVault OTX",
      value: otx,
      set: setOTX,
      where: "otx.alienvault.com",
      free: "Free. Community-reported indicators, broad and noisier than the other two.",
    },
  ];

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Sources in use</h3>
        {!sources ? (
          <p className="mt-2 text-xs text-ink-faint">Loading…</p>
        ) : (
          <div className="mt-3 flex flex-wrap gap-2">
            {sources.map((s) => (
              <span
                key={s.name}
                className={`rounded-full border px-2.5 py-1 text-xs ${
                  s.configured
                    ? "border-safe/50 bg-safe/10 text-safe"
                    : "border-base-600 text-ink-faint"
                }`}
              >
                {s.name}
                {!s.configured && " — no key"}
              </span>
            ))}
          </div>
        )}
        <p className="mt-3 max-w-prose text-xs text-ink-faint">
          Without these the review queue still works, but on much less: it can tell that a name is
          newly registered and looks like a typo of something real, not that somebody has already
          reported it serving malware.
        </p>
      </div>

      <DomainLookup />

      {error && <Notice tone="threat">{error}</Notice>}

      <form onSubmit={save} className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Add or replace a key</h3>
          <span className={`text-xs text-safe transition-opacity ${saved ? "opacity-100" : "opacity-0"}`}>
            Saved
          </span>
        </div>

        <div className="mt-3 space-y-3">
          {fields.map((f) => (
            <label key={f.label} className="block text-xs font-medium tracking-wide text-ink-muted uppercase">
              {f.label}
              <input
                type="password"
                value={f.value}
                onChange={(e) => f.set(e.target.value)}
                placeholder="leave empty to keep the current key"
                autoComplete="off"
                className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
              />
              <span className="mt-1 block text-[0.7rem] normal-case text-ink-faint">
                {f.free} <span className="font-mono">{f.where}</span>
              </span>
            </label>
          ))}
        </div>

        <button
          type="submit"
          disabled={busy || (!abuseCh.trim() && !safeBrowsing.trim() && !otx.trim())}
          className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          {busy ? "…" : "Save keys"}
        </button>

        <p className="mt-2 max-w-prose text-xs text-ink-faint">
          Keys are stored and never shown again — nothing here can read them back, so a borrowed
          session cannot take them. That is also why these fields are empty when a key is already
          set.
        </p>
      </form>
    </div>
  );
}

/**
 * Asking the sources about one name.
 *
 * Two jobs. It answers a question people genuinely have — is this thing
 * dangerous — and it is the only way to find out whether the keys above are
 * working: a source that refuses its key otherwise looks exactly like a source
 * that found nothing.
 */
function DomainLookup() {
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{
    domain: string;
    score: number;
    verdict: string;
    findings: IntelFinding[];
  } | null>(null);

  const run = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      setResult(await api.lookup(domain.trim()));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Ask about a name</h3>
      <p className="mt-1 max-w-prose text-xs text-ink-faint">
        Puts a name to every source at once. Also the quickest way to see whether the keys above
        work: a source that refuses its key looks the same as one that found nothing.
      </p>

      <form onSubmit={run} className="mt-3 flex flex-wrap gap-3">
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder="example.com"
          required
          className="min-w-[16rem] flex-1 rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
        />
        <button
          type="submit"
          disabled={busy || !domain.trim()}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          {busy ? "Asking…" : "Look up"}
        </button>
      </form>

      {error && <p className="mt-2 text-xs text-threat">{error}</p>}

      {result && (
        <div className="mt-4">
          <div className="flex flex-wrap items-baseline gap-3">
            <span className="font-mono text-sm break-all text-ink">{result.domain}</span>
            <span
              className={`rounded-full border px-2 py-0.5 text-[0.65rem] ${
                result.score >= 70
                  ? "border-threat/50 bg-threat/10 text-threat"
                  : result.score >= 40
                    ? "border-warn/50 bg-warn/10 text-warn"
                    : "border-safe/40 bg-safe/10 text-safe"
              }`}
            >
              {result.verdict} · {result.score}
            </span>
          </div>

          {result.findings?.length ? (
            <div className="mt-3 space-y-2">
              {result.findings.map((f, i) => (
                <div key={`${f.source}-${i}`} className="rounded-lg border border-base-800/80 bg-base-900/40 px-3 py-2">
                  <div className="flex flex-wrap items-baseline gap-2">
                    <span className="font-mono text-xs text-ink">{f.source}</span>
                    {f.malicious && (
                      <span className="rounded-full border border-threat/50 bg-threat/10 px-2 py-0.5 text-[0.65rem] text-threat">
                        flagged
                      </span>
                    )}
                    {f.category && <span className="text-xs text-ink-muted">{f.category}</span>}
                  </div>
                  {f.detail && <p className="mt-1 text-xs text-ink-faint">{f.detail}</p>}
                </div>
              ))}
            </div>
          ) : (
            <p className="mt-2 text-xs text-ink-faint">
              Nothing was reported about it. With keys configured that is a real answer; without
              them it is what every name looks like.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
