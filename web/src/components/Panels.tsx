import { Fragment, useCallback, useEffect, useState } from "react";
import { LimitControl } from "./Limits";
import {
  api,
  deviceName,
  formatBytes,
  formatCount,
  formatDuration,
  type ActivityReport,
  type Client,
  type ClientList,
  type Feed,
  type LimitList,
  type UserRule,
} from "../api";

/** Clients: what has been asking, and what policy applies to it. */
export function ClientsPanel() {
  const [data, setData] = useState<ClientList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  const [limits, setLimits] = useState<LimitList | null>(null);

  const loadLimits = useCallback(async () => {
    try {
      setLimits(await api.limits());
    } catch {
      // Limits are an extra: the device list is useful without them.
    }
  }, []);

  const load = useCallback(async () => {
    try {
      setData(await api.clients());
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
    void loadLimits();
  }, [load, loadLimits]);

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
          {data.enforcement?.explanation ??
            "In DNS-only mode, pausing a device stops it resolving names through this node. It keeps its network access."}{" "}
          Gateway mode makes this enforceable.
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
              <Fragment key={client.key}>
              <tr className="border-b border-base-800/60 last:border-0">
                <td className="px-4 py-2.5">
                  <button
                    onClick={() => setOpen(open === client.key ? null : client.key)}
                    className="text-left text-ink transition-colors hover:text-accent"
                  >
                    {deviceName(client)}
                  </button>
                  <div className="font-mono text-xs text-ink-faint">
                    {deviceName(client) !== client.key && <span>{client.key}</span>}
                    {client.mac && (
                      <span className={deviceName(client) !== client.key ? "ml-2" : ""}>
                        {client.mac}
                        {client.vendor && <span className="text-ink-muted"> · {client.vendor}</span>}
                        {client.mac_randomised && (
                          <span className="ml-2 text-warn">randomised — not a stable handle</span>
                        )}
                      </span>
                    )}
                  </div>
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
              {open === client.key && (
                <tr className="border-b border-base-800/60">
                  <td colSpan={5} className="bg-base-900/40 px-4 py-4">
                    <ClientActivity clientKey={client.key} />
                    <LimitControl
                      clientKey={client.key}
                      limit={limits?.limits?.find((l) => l.client_key === client.key)}
                      enforced={limits?.enforced ?? false}
                      onChanged={loadLimits}
                    />
                  </td>
                </tr>
              )}
              </Fragment>
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

      <AddFeedForm onAdded={load} />

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
                {feed.catalog ? (
                  <p className="mt-1 text-xs text-ink-muted">{feed.catalog.description}</p>
                ) : (
                  !feed.custom && (
                    <p className="mt-1 text-xs text-warn">
                      No longer in the catalogue. It keeps running from the URL stored here, but
                      nothing maintains that entry any more — check it still updates, or remove it.
                    </p>
                  )
                )}
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

              <div className="flex shrink-0 items-center gap-3">
                <Toggle
                  on={feed.enabled}
                  onChange={async (on) => {
                    await api.setFeedEnabled(feed.id, on);
                    await load();
                  }}
                />
                {/* Sources you added, and catalogue entries that have since
                    been withdrawn — a published list whose repository
                    disappears would otherwise sit here failing forever with no
                    way to remove it. A catalogue entry that still exists is
                    only switched off, never deleted, so it can be switched
                    back on with its description and licence intact. */}
                {(feed.custom || !feed.catalog) && (
                  <button
                    onClick={async () => {
                      await api.deleteFeed(feed.id);
                      await load();
                    }}
                    className="text-xs text-ink-faint transition-colors hover:text-threat"
                  >
                    remove
                  </button>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

/**
 * Adding a list the catalogue does not carry.
 *
 * The id is what the node files the source under, so it is derived from the
 * name rather than asked for separately — one less field to explain, and one
 * less way to end up with two sources fighting over the same slot.
 */
function AddFeedForm({ onAdded }: { onAdded: () => void | Promise<void> }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const id = name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="rounded-md border border-dashed border-base-700 px-3 py-2 text-xs text-ink-faint transition-colors hover:border-accent-dim hover:text-accent"
      >
        + Add a source
      </button>
    );
  }

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      await api.addFeed(id, name.trim(), url.trim());
      setName("");
      setUrl("");
      setOpen(false);
      await onAdded();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-end gap-3">
        <label className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          Name
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="My list"
            required
            className="mt-1.5 w-48 rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
          />
        </label>

        <label className="min-w-[18rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          URL
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.org/hosts.txt"
            type="url"
            required
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
          />
        </label>

        <button
          type="submit"
          disabled={busy || !id || !url}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          {busy ? "…" : "Add"}
        </button>
        <button
          type="button"
          onClick={() => setOpen(false)}
          className="pb-2 text-xs text-ink-faint transition-colors hover:text-ink"
        >
          cancel
        </button>
      </div>

      <p className="mt-2 text-xs text-ink-faint">
        Hosts files and Adblock-syntax lists both work; the format is detected from the content. The
        source is downloaded and compiled as soon as you add it{id && <> and filed as <span className="font-mono">{id}</span></>}.
      </p>

      {error && <p className="mt-2 text-xs text-threat">{error}</p>}
    </form>
  );
}

/** Your own rules, which win over anything a feed says. */
export function RulesPanel() {
  const [rules, setRules] = useState<UserRule[] | null>(null);
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

  return (
    <div className="space-y-4">
      <RuleComposer onAdded={load} onError={setError} />

      {error && <Notice tone="threat">{error}</Notice>}

      <div className="rounded-xl border border-base-700/70 bg-base-850/60">
        {(rules ?? []).length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-ink-faint">No rules of your own yet.</p>
        ) : (
          <table className="w-full text-sm">
            <tbody>
              {(rules ?? []).map((rule) => (
                <tr key={rule.id} className="border-b border-base-800/60 last:border-0 align-top">
                  <td className="px-4 py-3 w-24">
                    <ActionBadge rule={rule} />
                  </td>
                  <td className="px-2 py-3">
                    <div className="font-mono text-ink">{rule.domain || rule.rule}</div>
                    <div className="mt-0.5 text-xs text-ink-faint">
                      {describeRule(rule)}
                      {rule.comment && <> · {rule.comment}</>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-right">
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

function ActionBadge({ rule }: { rule: UserRule }) {
  const tone =
    rule.action === "allow"
      ? "border-safe/50 bg-safe/10 text-safe"
      : rule.action === "rewrite"
        ? "border-accent-dim/60 bg-accent/10 text-accent"
        : "border-threat/50 bg-threat/10 text-threat";

  return (
    <span className={`rounded-full border px-2 py-0.5 text-[0.65rem] ${tone}`}>
      {rule.action}
      {rule.important && " !"}
    </span>
  );
}

/** Says what the rule does in the words someone would use to ask for it. */
function describeRule(rule: UserRule): string {
  const scope = rule.subdomains ? "and everything under it" : "exactly";
  const parts: string[] = [];

  switch (rule.action) {
    case "allow":
      parts.push(`always resolves ${scope}, beating every blocklist`);
      break;
    case "rewrite":
      parts.push(rule.rewrite === "NXDOMAIN" ? `answers "does not exist" ${scope}` : `answers ${rule.rewrite} ${scope}`);
      break;
    default:
      parts.push(rule.important ? `blocked ${scope}, overriding allow rules` : `blocked ${scope}`);
  }

  if (rule.qtypes) parts.push(`only ${rule.qtypes} queries`);
  if (rule.client) parts.push(`only for ${rule.client}`);

  return parts.join(" · ");
}

type ComposerAction = "block" | "allow" | "rewrite" | "nxdomain";

const actionHelp: Record<ComposerAction, string> = {
  block: "The name stops resolving, along with everything under it.",
  allow: "The name resolves even if a blocklist carries it. Allow beats block, so this is how you get a site back.",
  rewrite: "The name answers with an address you choose — pointing a device at a local server, for instance.",
  nxdomain: 'The name answers "does not exist" rather than an address. Some apps handle that better than 0.0.0.0.',
};

/**
 * Writing a rule without having to know the syntax.
 *
 * The old form took a raw line, which meant the only people who could add an
 * allow rule were the ones who already knew that @@ meant allow. The syntax is
 * still shown — and still accepted directly — because seeing what was written
 * is how you learn it, and how you check it did what you meant.
 */
function RuleComposer({
  onAdded,
  onError,
}: {
  onAdded: () => void | Promise<void>;
  onError: (message: string | null) => void;
}) {
  const [action, setAction] = useState<ComposerAction>("block");
  const [domain, setDomain] = useState("");
  const [address, setAddress] = useState("");
  const [comment, setComment] = useState("");
  const [important, setImportant] = useState(false);
  const [raw, setRaw] = useState(false);
  const [rawRule, setRawRule] = useState("");
  const [busy, setBusy] = useState(false);

  const name = domain.trim().toLowerCase().replace(/^\*\./, "");

  const composed = (() => {
    if (!name) return "";

    switch (action) {
      case "allow":
        return `@@||${name}^`;
      case "rewrite":
        return address.trim() ? `||${name}^$dnsrewrite=${address.trim()}` : "";
      case "nxdomain":
        return `||${name}^$dnsrewrite=NXDOMAIN`;
      default:
        return important ? `||${name}^$important` : `||${name}^`;
    }
  })();

  const rule = raw ? rawRule.trim() : composed;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    onError(null);
    setBusy(true);

    try {
      await api.addRule(rule, comment.trim() || undefined);
      setDomain("");
      setAddress("");
      setComment("");
      setRawRule("");
      await onAdded();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      {raw ? (
        <label className="block text-xs font-medium tracking-wide text-ink-muted uppercase">
          Rule
          <input
            value={rawRule}
            onChange={(e) => setRawRule(e.target.value)}
            placeholder="||ads.example.com^$important"
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
          />
        </label>
      ) : (
        <>
          <div className="flex flex-wrap gap-1">
            {(["block", "allow", "rewrite", "nxdomain"] as ComposerAction[]).map((option) => (
              <button
                key={option}
                type="button"
                onClick={() => setAction(option)}
                className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
                  action === option
                    ? "bg-accent text-base-950"
                    : "border border-base-700 text-ink-muted hover:text-ink"
                }`}
              >
                {option === "nxdomain" ? "Say it does not exist" : option}
              </button>
            ))}
          </div>

          <p className="mt-2 max-w-prose text-xs text-ink-faint">{actionHelp[action]}</p>

          <div className="mt-3 flex flex-wrap items-end gap-3">
            <label className="min-w-[16rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
              Domain
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="ads.example.com"
                required
                className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
              />
            </label>

            {action === "rewrite" && (
              <label className="w-44 text-xs font-medium tracking-wide text-ink-muted uppercase">
                Answer with
                <input
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  placeholder="192.168.1.10"
                  required
                  className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
                />
              </label>
            )}

            <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
              Note (optional)
              <input
                value={comment}
                onChange={(e) => setComment(e.target.value)}
                placeholder="why you added this"
                className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
              />
            </label>
          </div>

          {action === "block" && (
            <label className="mt-3 flex items-center gap-2 text-xs text-ink-muted">
              <input
                type="checkbox"
                checked={important}
                onChange={(e) => setImportant(e.target.checked)}
                className="accent-[var(--color-accent)]"
              />
              beat allow rules as well — use when something keeps getting through
            </label>
          )}
        </>
      )}

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={busy || !rule}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          {busy ? "…" : "Add rule"}
        </button>

        {!raw && composed && (
          <span className="font-mono text-xs text-ink-faint">{composed}</span>
        )}

        <button
          type="button"
          onClick={() => setRaw(!raw)}
          className="ml-auto text-xs text-ink-faint transition-colors hover:text-accent"
        >
          {raw ? "use the form" : "write the syntax myself"}
        </button>
      </div>
    </form>
  );
}

/** Where a device has been spending its time. */
function ClientActivity({ clientKey }: { clientKey: string }) {
  const [data, setData] = useState<{ report: ActivityReport; measured: boolean } | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .activity(clientKey)
      .then(setData)
      .catch((err) => setError(String(err)));
  }, [clientKey]);

  if (error) return <Notice tone="threat">{error}</Notice>;
  if (!data) return <p className="text-xs text-ink-faint">Loading…</p>;

  const sites = data.report.sites ?? [];

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-baseline gap-2">
        <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">Last 24 hours</span>
        {/* The distinction the whole product rests on: inferred or measured. */}
        <span
          className={`rounded-full border px-2 py-0.5 font-mono text-[0.65rem] ${
            data.measured
              ? "border-safe/50 bg-safe/10 text-safe"
              : "border-warn/50 bg-warn/10 text-warn"
          }`}
        >
          {data.measured ? "measured" : "estimated from DNS"}
        </span>
      </div>

      {sites.length === 0 ? (
        <p className="text-xs text-ink-faint">Nothing recorded for this device yet.</p>
      ) : (
        <table className="w-full text-xs">
          <tbody>
            {sites.slice(0, 10).map((site) => (
              <tr key={site.site}>
                <td className="py-1 pr-4 font-mono text-ink">{site.site}</td>
                <td className="w-24 py-1 pr-4 text-right text-ink-muted tabular-nums">
                  {formatDuration(site.duration_ns)}
                </td>
                <td className="w-28 py-1 text-right text-ink-faint tabular-nums">
                  {site.sessions} visit{site.sessions === 1 ? "" : "s"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* Caveats travel with the numbers. A figure whose limits the reader does
          not know is worse than no figure. */}
      <ul className="space-y-0.5 border-t border-base-800 pt-2">
        {data.report.caveats.map((c) => (
          <li key={c} className="text-[0.7rem] text-ink-faint">
            {c}
          </li>
        ))}
      </ul>
    </div>
  );
}

export function Toggle({
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

export function Notice({
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
