import { useCallback, useEffect, useState } from "react";
import { api, type BenchmarkResult, type Upstream, type UpstreamList } from "../api";
import { Notice, Toggle } from "./Panels";

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
  const [data, setData] = useState<UpstreamList | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.upstreams());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (error && !data) return <Notice tone="threat">{error}</Notice>;
  if (!data) return <Notice>Loading…</Notice>;

  const list = data.upstreams ?? [];
  const primaries = list.filter((u) => u.role === "primary");
  const fallbacks = list.filter((u) => u.role === "fallback");

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          Resolving through
        </span>
        <div className="mt-2 flex flex-wrap gap-2">
          {(data.in_use ?? []).map((address) => (
            <span key={address} className="rounded-md border border-base-700 bg-base-900/60 px-2.5 py-1 font-mono text-xs text-ink">
              {address}
            </span>
          ))}
        </div>
        {(data.fallbacks_used ?? []).length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <span className="text-[0.65rem] tracking-wide text-ink-faint uppercase">if those fail</span>
            {(data.fallbacks_used ?? []).map((address) => (
              <span key={address} className="rounded-md border border-base-700/60 px-2.5 py-1 font-mono text-xs text-ink-muted">
                {address}
              </span>
            ))}
          </div>
        )}

        <p className="mt-3 max-w-prose text-xs text-ink-faint">
          {data.using_defaults
            ? "These are the resolvers that shipped. Add your own below and they take over; remove them all and these come back."
            : "Your own resolvers are in use. Remove them all and the ones that shipped come back automatically."}
        </p>
      </div>

      {error && <Notice tone="threat">{error}</Notice>}

      <Measure onAdopted={load} onError={setError} />

      <AddUpstream onAdded={load} onError={setError} />

      <Group
        title="Primary"
        blurb="Asked for every query. Several are load-balanced by response time, so the fastest one gets most of the traffic."
        items={primaries}
        empty="Nothing configured — the shipped resolvers are in use."
        onChanged={load}
      />

      <Group
        title="Fallback"
        blurb="Only asked once every primary has failed. A plain, always-reachable resolver here means an outage at an encrypted provider does not take the house offline."
        items={fallbacks}
        empty="None. If every primary fails, queries fail with them."
        onChanged={load}
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
          <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Find the best one</h3>
          <p className="mt-1 max-w-prose text-xs text-ink-faint">
            Times the well-known public resolvers from this node, and checks each one can actually
            resolve — including a domain in your own country, which is where a fast resolver most
            often turns out to be useless.
          </p>
        </div>
        <button
          onClick={() => void run(false)}
          disabled={busy}
          className="rounded-md border border-base-700 px-3 py-2 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent disabled:opacity-50"
        >
          {busy ? "Measuring…" : "Measure"}
        </button>
      </div>

      {results && (
        <>
          <table className="mt-3 w-full text-sm">
            <tbody>
              {results.map((row) => (
                <tr key={row.address} className="border-b border-base-800/60 last:border-0">
                  <td className="py-2 font-mono text-ink">{row.address}</td>
                  <td className="py-2 text-right font-mono tabular-nums text-ink-muted">
                    {row.resolved === 0 ? "—" : `${row.median_ms} ms`}
                  </td>
                  <td className="py-2 pl-4 text-xs">
                    {row.usable ? (
                      <span className="text-safe">resolved everything</span>
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
            Use the best two
          </button>
          <p className="mt-2 max-w-prose text-xs text-ink-faint">
            Two, not one: the runner-up costs nothing until the first is slow. This replaces
            whatever is configured now.
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
  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">{title}</h3>
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
                <span className={`font-mono text-sm ${item.enabled ? "text-ink" : "text-ink-faint line-through"}`}>
                  {item.address}
                </span>
                {item.note && <span className="ml-2 text-xs text-ink-faint">{item.note}</span>}
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
                  make {item.role === "primary" ? "fallback" : "primary"}
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
                  remove
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
const suggestions: { address: string; label: string; note: string }[] = [
  { address: "1.1.1.1", label: "Cloudflare", note: "fast, no filtering of its own" },
  { address: "8.8.8.8", label: "Google", note: "fast and everywhere; Google sees the queries" },
  { address: "9.9.9.9", label: "Quad9", note: "blocks known-malicious names itself" },
  { address: "tls://dns.quad9.net", label: "Quad9 over TLS", note: "encrypted, so your ISP cannot read the names" },
];

function AddUpstream({
  onAdded,
  onError,
}: {
  onAdded: () => void | Promise<void>;
  onError: (message: string | null) => void;
}) {
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
    <form onSubmit={submit} className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="min-w-[16rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          Resolver
          <input
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="1.1.1.1  or  tls://dns.quad9.net"
            required
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
          />
        </label>

        <label className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          Role
          <select
            value={role}
            onChange={(e) => setRole(e.target.value as "primary" | "fallback")}
            className="mt-1.5 w-32 rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink focus:border-accent-dim focus:outline-none"
          >
            <option value="primary">primary</option>
            <option value="fallback">fallback</option>
          </select>
        </label>

        <label className="min-w-[10rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          Note (optional)
          <input
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="why this one"
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
          />
        </label>

        <button
          type="submit"
          disabled={busy || !address.trim()}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          {busy ? "…" : "Add"}
        </button>
      </div>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <span className="text-[0.65rem] tracking-wide text-ink-faint uppercase">try</span>
        {suggestions.map((item) => (
          <button
            key={item.address}
            type="button"
            title={item.note}
            onClick={() => setAddress(item.address)}
            className="rounded-md border border-base-700 px-2 py-1 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
          >
            {item.label}
          </button>
        ))}
      </div>

      <p className="mt-2 max-w-prose text-xs text-ink-faint">
        A plain address, or an encrypted one — <span className="font-mono">tls://</span>,{" "}
        <span className="font-mono">https://</span> and <span className="font-mono">quic://</span> all work. A bare
        hostname does not: resolving it would need the DNS it is meant to provide.
      </p>
    </form>
  );
}
