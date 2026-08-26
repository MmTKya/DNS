import { useCallback, useEffect, useState } from "react";
import {
  api,
  type BenchmarkResult,
  type Upstream,
  type UpstreamList,
} from "../api";
import { Notice, Toggle } from "./Panels";
import { useLang } from "../i18n/context";

/**
 * Where this node forwards the queries it does not answer itself.
 *
 * The shipped resolvers are a guess about the whole world; which one is
 * actually fastest depends on the country and the line. So the screen leads
 * with what is in use right now, and the list is empty until someone decides
 * otherwise — with nothing configured, the defaults apply, which is also what
 * removing the last one goes back to.
 */
export function UpstreamsPanel() {
  const { t } = useLang();
  const [data, setData] = useState<UpstreamList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [applied, setApplied] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await api.upstreams());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  // There is no save button because there is nothing to save: each change is
  // sent as it is made and the resolver is rebuilt around it. Without saying
  // so the screen looks like a form someone forgot to finish, so it says so —
  // and confirms, because a change with no visible effect is indistinguishable
  // from one that did not happen.
  const changed = useCallback(async () => {
    await load();
    setApplied(true);
    window.setTimeout(() => setApplied(false), 2500);
  }, [load]);

  useEffect(() => {
    void load();
  }, [load]);

  if (error && !data) return <Notice tone="threat">{error}</Notice>;
  if (!data) return <Notice>{t("common.loading")}</Notice>;

  const list = data.upstreams ?? [];
  const primaries = list.filter((u) => u.role === "primary");
  const fallbacks = list.filter((u) => u.role === "fallback");

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">
            {t("upstreams.resolvingThrough")}
          </span>
          <span
            className={`text-xs transition-opacity ${applied ? "text-safe opacity-100" : "opacity-0"}`}
            aria-live="polite"
          >
            {t("upstreams.applied")}
          </span>
        </div>
        <div className="mt-2 flex flex-wrap gap-2">
          {(data.in_use ?? []).map((address) => (
            <span
              key={address}
              className="rounded-md border border-base-700 bg-base-900/60 px-2.5 py-1 font-mono text-xs text-ink"
            >
              {address}
            </span>
          ))}
        </div>
        {(data.fallbacks_used ?? []).length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="text-[0.65rem] tracking-wide text-ink-faint uppercase">
              {t("upstreams.ifThoseFail")}
            </span>
            {(data.fallbacks_used ?? []).map((address) => (
              <span
                key={address}
                className="rounded-md border border-base-700/60 px-2.5 py-1 font-mono text-xs text-ink-muted"
              >
                {address}
              </span>
            ))}
          </div>
        )}

        <p className="mt-3 max-w-prose text-xs text-ink-faint">
          {data.using_defaults
            ? t("upstreams.usingDefaultsDetail")
            : t("upstreams.usingCustomDetail")}{" "}
          {t("upstreams.effectImmediately")}
        </p>
      </div>

      {error && <Notice tone="threat">{error}</Notice>}

      <Measure onAdopted={changed} onError={setError} />

      <AddUpstream onAdded={changed} onError={setError} />

      <Group
        title={t("upstreams.primary")}
        blurb={t("upstreams.primaryBlurb")}
        items={primaries}
        empty={t("upstreams.primaryEmpty")}
        onChanged={changed}
      />

      <Group
        title={t("upstreams.fallback")}
        blurb={t("upstreams.fallbackBlurb")}
        items={fallbacks}
        empty={t("upstreams.fallbackEmpty")}
        onChanged={changed}
      />
    </div>
  );
}

/**
 * Measuring the candidates from the node itself.
 *
 * Correctness is checked before speed, and that ordering is the whole reason
 * this exists: the resolver that shipped as the default answers fastest to a
 * reachability check and cannot resolve a Turkish government domain at all.
 * A benchmark that only timed queries would have kept recommending it.
 */
function Measure({
  onAdopted,
  onError,
}: {
  onAdopted: () => void | Promise<void>;
  onError: (message: string | null) => void;
}) {
  const { t } = useLang();
  const [results, setResults] = useState<BenchmarkResult[] | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (adopt: boolean) => {
    onError(null);
    setBusy(true);

    try {
      const result = await api.benchmarkUpstreams(adopt);
      setResults(result.results);
      if (adopt) await onAdopted();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
            {t("upstreams.findBest")}
          </h3>
          <p className="mt-1 max-w-prose text-xs text-ink-faint">
            {t("upstreams.findBestDetail")}
          </p>
        </div>
        <button
          onClick={() => void run(false)}
          disabled={busy}
          className="rounded-md border border-base-700 px-3 py-2 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent disabled:opacity-50"
        >
          {busy ? t("upstreams.measuring") : t("upstreams.measure")}
        </button>
      </div>

      {results && (
        <>
          <table className="mt-3 w-full text-sm">
            <tbody>
              {results.map((row) => (
                <tr
                  key={row.address}
                  className="border-b border-base-800/60 last:border-0"
                >
                  <td className="py-2 font-mono text-ink">{row.address}</td>
                  <td className="py-2 text-right font-mono tabular-nums text-ink-muted">
                    {row.resolved === 0 ? "—" : `${row.median_ms} ms`}
                  </td>
                  <td className="py-2 pl-4 text-xs">
                    {row.usable ? (
                      <span className="text-safe">
                        {t("upstreams.resolvedEverything")}
                      </span>
                    ) : (
                      <span className="text-threat">
                        {row.resolved}/{row.probes} — {row.error}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <button
            onClick={() => void run(true)}
            disabled={busy || !results.some((r) => r.usable)}
            className="mt-3 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
          >
            {t("upstreams.useBestTwo")}
          </button>
          <p className="mt-2 max-w-prose text-xs text-ink-faint">
            {t("upstreams.useBestTwoDetail")}
          </p>
        </>
      )}
    </div>
  );
}

function Group({
  title,
  blurb,
  items,
  empty,
  onChanged,
}: {
  title: string;
  blurb: string;
  items: Upstream[];
  empty: string;
  onChanged: () => void | Promise<void>;
}) {
  const { t } = useLang();

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
        {title}
      </h3>
      <p className="mt-1 max-w-prose text-xs text-ink-faint">{blurb}</p>

      {items.length === 0 ? (
        <p className="mt-3 text-xs text-ink-faint">{empty}</p>
      ) : (
        <div className="mt-3 grid gap-2">
          {items.map((item) => (
            <div
              key={item.id}
              className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-base-800/80 bg-base-900/40 px-3 py-2"
            >
              <div className="min-w-0">
                <span
                  className={`font-mono text-sm ${item.enabled ? "text-ink" : "text-ink-faint line-through"}`}
                >
                  {item.address}
                </span>
                {item.note && (
                  <span className="ml-2 text-xs text-ink-faint">
                    {item.note}
                  </span>
                )}
              </div>

              <div className="flex shrink-0 items-center gap-3">
                <button
                  onClick={async () => {
                    await api.updateUpstream(item.id, {
                      role: item.role === "primary" ? "fallback" : "primary",
                    });
                    await onChanged();
                  }}
                  className="text-xs text-ink-faint transition-colors hover:text-accent"
                >
                  {item.role === "primary"
                    ? t("upstreams.makeFallback")
                    : t("upstreams.makePrimary")}
                </button>
                <Toggle
                  on={item.enabled}
                  onChange={async (on) => {
                    await api.updateUpstream(item.id, { enabled: on });
                    await onChanged();
                  }}
                />
                <button
                  onClick={async () => {
                    await api.deleteUpstream(item.id);
                    await onChanged();
                  }}
                  className="text-xs text-ink-faint transition-colors hover:text-threat"
                >
                  {t("upstreams.remove")}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/** A few that are worth suggesting, with what each one costs you. */
const suggestions: { address: string; label: string; noteKey: string }[] = [
  {
    address: "1.1.1.1",
    label: "Cloudflare",
    noteKey: "upstreams.suggestionCloudflare",
  },
  {
    address: "8.8.8.8",
    label: "Google",
    noteKey: "upstreams.suggestionGoogle",
  },
  { address: "9.9.9.9", label: "Quad9", noteKey: "upstreams.suggestionQuad9" },
  {
    address: "tls://dns.quad9.net",
    label: "Quad9 over TLS",
    noteKey: "upstreams.suggestionQuad9TLS",
  },
];

function AddUpstream({
  onAdded,
  onError,
}: {
  onAdded: () => void | Promise<void>;
  onError: (message: string | null) => void;
}) {
  const { t } = useLang();
  const [address, setAddress] = useState("");
  const [role, setRole] = useState<"primary" | "fallback">("primary");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    onError(null);
    setBusy(true);

    try {
      await api.addUpstream(address.trim(), role, note.trim() || undefined);
      setAddress("");
      setNote("");
      await onAdded();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={submit}
      className="rounded-xl border border-base-700/70 bg-base-850/40 p-4"
    >
      <div className="flex flex-wrap items-end gap-3">
        <label className="min-w-[16rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("upstreams.resolver")}
          <input
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="1.1.1.1  or  tls://dns.quad9.net"
            required
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
          />
        </label>

        <label className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("upstreams.role")}
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as "primary" | "fallback")}
            className="mt-1.5 w-32 rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink focus:border-accent-dim focus:outline-none"
          >
            <option value="primary">{t("upstreams.primary")}</option>
            <option value="fallback">{t("upstreams.fallback")}</option>
          </select>
        </label>

        <label className="min-w-[10rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("upstreams.note")}
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder={t("upstreams.notePlaceholder")}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
          />
        </label>

        <button
          type="submit"
          disabled={busy || !address.trim()}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          {busy ? "…" : t("upstreams.add")}
        </button>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className="text-[0.65rem] tracking-wide text-ink-faint uppercase">
          {t("upstreams.try")}
        </span>
        {suggestions.map((item) => (
          <button
            key={item.address}
            type="button"
            title={t(item.noteKey)}
            onClick={() => setAddress(item.address)}
            className="rounded-md border border-base-700 px-2 py-1 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
          >
            {item.label}
          </button>
        ))}
      </div>

      <p className="mt-2 max-w-prose text-xs text-ink-faint">
        {t("upstreams.addressHint")} <span className="font-mono">tls://</span>,{" "}
        <span className="font-mono">https://</span> {t("common.and")}{" "}
        <span className="font-mono">quic://</span>{" "}
        {t("upstreams.addressHintSuffix")}
      </p>
    </form>
  );
}
