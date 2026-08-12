import { useCallback, useEffect, useState } from "react";
import {
  api,
  formatBytes,
  formatCount,
  type Client,
  type ClientList,
  type Feed,
  type UserRule,
} from "../api";

/** Clients: what has been asking, and what policy applies to it. */
export function ClientsPanel() {
  const [data, setData] = useState<ClientList | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.clients());
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const update = async (client: Client, patch: Partial<Client>) => {
    await api.updateClient(client.key, patch);
    await load();
  };

  if (error) return <Notice tone="threat">{error}</Notice>;
  if (!data) return <Notice>Loading…</Notice>;

  const clients = data.clients ?? [];

  return (
    <div className="space-y-4">
      {/* What "pause" means depends on the deployment mode, and the panel must
          not imply a kill switch it cannot deliver. */}
      {!data.pause_is_enforced && (
        <Notice tone="warn">
          In DNS-only mode, pausing a device stops it resolving names through this node. It keeps its network
          access, and a device with hardcoded addresses or its own encrypted DNS will get around it. Gateway
          mode makes this enforceable.
        </Notice>
      )}

      <div className="overflow-x-auto rounded-xl border border-base-700/70 bg-base-850/60">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-base-700/70 text-left text-xs tracking-wide text-ink-muted uppercase">
              <th className="px-4 py-3 font-medium">Device</th>
              <th className="px-4 py-3 font-medium">Queries</th>
              <th className="px-4 py-3 font-medium">Last seen</th>
              <th className="px-4 py-3 font-medium">Filtering</th>
              <th className="px-4 py-3 font-medium">Paused</th>
            </tr>
          </thead>
          <tbody>
            {clients.length === 0 && (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-ink-faint">
                  No devices have asked yet.
                </td>
              </tr>
            )}
            {clients.map((client) => (
              <tr key={client.key} className="border-b border-base-800/60 last:border-0">
                <td className="px-4 py-2.5">
                  <div className="text-ink">{client.name || client.key}</div>
                  {client.name && <div className="font-mono text-xs text-ink-faint">{client.key}</div>}
                </td>
                <td className="px-4 py-2.5 font-mono text-ink-muted tabular-nums">
                  {formatCount(client.query_count)}
                </td>
                <td className="px-4 py-2.5 text-xs text-ink-faint">
                  {client.last_seen ? new Date(client.last_seen).toLocaleString() : "—"}
                </td>
                <td className="px-4 py-2.5">
                  <Toggle
                    on={client.filtering_enabled}
                    onChange={(on) => update(client, { filtering_enabled: on })}
                  />
                </td>
                <td className="px-4 py-2.5">
                  <Toggle on={client.paused} tone="threat" onChange={(on) => update(client, { paused: on })} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** Feeds: the blocklists, with the metadata that makes enabling one a
 *  decision rather than a guess. */
export function FeedsPanel() {
  const [feeds, setFeeds] = useState<Feed[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const load = useCallback(async () => {
    try {
      const result = await api.feeds();
      setFeeds(result.feeds ?? []);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const refresh = async () => {
    setRefreshing(true);
    try {
      await api.refreshFeeds();
      // The download runs in the background; give it a moment before showing
      // the result rather than pretending it is instant.
      setTimeout(() => void load().finally(() => setRefreshing(false)), 3000);
    } catch (err) {
      setError(String(err));
      setRefreshing(false);
    }
  };

  if (error) return <Notice tone="threat">{error}</Notice>;
  if (!feeds) return <Notice>Loading…</Notice>;

  return (
    <div className="space-y-4">
      <div className="flex justify-end">
        <button
          onClick={refresh}
          disabled={refreshing}
          className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent disabled:opacity-50"
        >
          {refreshing ? "Refreshing…" : "Refresh now"}
        </button>
      </div>

      <div className="grid gap-3">
        {feeds.map((feed) => (
          <div key={feed.id} className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm text-ink">{feed.name}</span>
                  {feed.catalog?.high_false_positives && (
                    <span className="rounded-full border border-warn/40 bg-warn/10 px-2 py-0.5 text-[0.65rem] text-warn">
                      blocks aggressively
                    </span>
                  )}
                  {feed.catalog && !feed.catalog.commercial_use && (
                    <span className="rounded-full border border-base-600 px-2 py-0.5 text-[0.65rem] text-ink-faint">
                      non-commercial licence
                    </span>
                  )}
                </div>
                {feed.catalog && <p className="mt-1 text-xs text-ink-muted">{feed.catalog.description}</p>}
                <div className="mt-2 flex flex-wrap gap-3 font-mono text-[0.7rem] text-ink-faint">
                  {feed.rule_count > 0 && <span>{formatCount(feed.rule_count)} rules</span>}
                  {feed.bytes > 0 && <span>{formatBytes(feed.bytes)}</span>}
                  {feed.catalog && <span>{feed.catalog.license}</span>}
                  {feed.last_success_at && (
                    <span>updated {new Date(feed.last_success_at).toLocaleString()}</span>
                  )}
                </div>
                {feed.last_error && <p className="mt-2 text-xs text-threat">{feed.last_error}</p>}
              </div>

              <Toggle
                on={feed.enabled}
                onChange={async (on) => {
                  await api.setFeedEnabled(feed.id, on);
                  await load();
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/** Your own rules, which win over anything a feed says. */
export function RulesPanel() {
  const [rules, setRules] = useState<UserRule[] | null>(null);
  const [draft, setDraft] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await api.rules();
      setRules(result.rules ?? []);
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const add = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);

    try {
      await api.addRule(draft);
      setDraft("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="space-y-4">
      <form onSubmit={add} className="flex gap-2">
        <input
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="||ads.example.com^   or   @@||needed.example.com^"
          className="min-w-0 flex-1 rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
        />
        <button
          type="submit"
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90"
        >
          Add
        </button>
      </form>

      <p className="text-xs text-ink-faint">
        <span className="font-mono">||name^</span> blocks a name and everything under it.{" "}
        <span className="font-mono">@@||name^</span> allows one back, and beats every blocklist.
      </p>

      {error && <Notice tone="threat">{error}</Notice>}

      <div className="rounded-xl border border-base-700/70 bg-base-850/60">
        {(rules ?? []).length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-ink-faint">No rules of your own yet.</p>
        ) : (
          <table className="w-full text-sm">
            <tbody>
              {(rules ?? []).map((rule) => (
                <tr key={rule.id} className="border-b border-base-800/60 last:border-0">
                  <td className="px-4 py-2.5 font-mono text-ink">{rule.rule}</td>
                  <td className="px-4 py-2.5 text-xs text-ink-faint">{rule.comment}</td>
                  <td className="px-4 py-2.5 text-right">
                    <button
                      onClick={async () => {
                        await api.deleteRule(rule.id);
                        await load();
                      }}
                      className="text-xs text-ink-faint transition-colors hover:text-threat"
                    >
                      remove
                    </button>
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

function Toggle({
  on,
  onChange,
  tone = "accent",
}: {
  on: boolean;
  onChange: (on: boolean) => void | Promise<void>;
  tone?: "accent" | "threat";
}) {
  const active = tone === "threat" ? "bg-threat" : "bg-accent";

  return (
    <button
      onClick={() => void onChange(!on)}
      role="switch"
      aria-checked={on}
      className={`relative h-5 w-9 shrink-0 rounded-full transition-colors ${on ? active : "bg-base-700"}`}
    >
      <span
        className={`absolute top-0.5 size-4 rounded-full bg-base-950 transition-all ${on ? "left-4.5" : "left-0.5"}`}
      />
    </button>
  );
}

function Notice({
  children,
  tone = "muted",
}: {
  children: React.ReactNode;
  tone?: "muted" | "warn" | "threat";
}) {
  const styles = {
    muted: "border-base-700/70 bg-base-850/60 text-ink-muted",
    warn: "border-warn/40 bg-warn/10 text-ink",
    threat: "border-threat/40 bg-threat/10 text-ink",
  };

  return <div className={`rounded-lg border px-4 py-3 text-sm ${styles[tone]}`}>{children}</div>;
}
