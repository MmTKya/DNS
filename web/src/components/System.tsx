import { useCallback, useEffect, useRef, useState } from "react";
import {
  api,
  type AlertHistory,
  type AuditEntry,
  type ClusterStatus,
  type NotifyChannel,
  type RestoreResult,
  type UpdateStatus,
} from "../api";
import { Notice, Toggle } from "./Panels";
import { IntelKeysPanel } from "./IntelKeys";
import { LogsPanel } from "./Logs";
import { PairingGuide } from "./Pairing";
import { UpstreamsPanel } from "./Upstreams";

type Section = "logs" | "upstreams" | "intel" | "cluster" | "backup" | "alerts" | "audit" | "updates";

const sections: { id: Section; label: string }[] = [
  { id: "logs", label: "Logs" },
  { id: "upstreams", label: "Resolvers" },
  { id: "intel", label: "Threat sources" },
  { id: "cluster", label: "Cluster" },
  { id: "backup", label: "Backup" },
  { id: "alerts", label: "Alerts" },
  { id: "audit", label: "Audit" },
  { id: "updates", label: "Updates" },
];

/**
 * The things you touch rarely.
 *
 * These live behind one tab rather than five of their own: a household sets up
 * alerts once and looks at the audit trail when something is wrong, and putting
 * them beside the daily screens would push the daily screens off the edge.
 */
export function SystemPanel() {
  const [section, setSection] = useState<Section>("logs");

  return (
    <div className="space-y-5">
      <nav className="flex flex-wrap gap-1 rounded-lg border border-base-700/70 bg-base-850/40 p-1">
        {sections.map((s) => (
          <button
            key={s.id}
            onClick={() => setSection(s.id)}
            className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
              section === s.id ? "bg-base-700/70 text-ink" : "text-ink-muted hover:text-ink"
            }`}
          >
            {s.label}
          </button>
        ))}
      </nav>

      {section === "logs" && <LogsPanel />}
      {section === "upstreams" && <UpstreamsPanel />}
      {section === "intel" && <IntelKeysPanel />}
      {section === "cluster" && <ClusterSection />}
      {section === "backup" && <BackupSection />}
      {section === "alerts" && <AlertsSection />}
      {section === "audit" && <AuditSection />}
      {section === "updates" && <UpdatesSection />}
    </div>
  );
}

/** Who is primary, who is reachable, and whether they agree. */
function ClusterSection() {
  const [status, setStatus] = useState<ClusterStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pairing, setPairing] = useState(false);

  const load = useCallback(async () => {
    try {
      setStatus(await api.clusterStatus());
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 10_000);

    return () => window.clearInterval(timer);
  }, [load]);

  if (error) return <Notice tone="threat">{error}</Notice>;
  if (!status) return <Notice>Loading…</Notice>;

  if (!status.enabled) {
    if (pairing) return <PairingGuide onClose={() => setPairing(false)} />;

    return (
      <div className="space-y-4">
        <div className="rounded-xl border border-base-700/70 bg-base-850/40 px-4 py-8 text-center">
          <p className="text-sm text-ink">This node is running on its own.</p>
          <p className="mx-auto mt-1 max-w-prose text-xs text-ink-faint">
            A second node keeps the house resolving when this one is rebooting, updating or simply
            unplugged — it follows this one's configuration and takes over if it goes quiet. Until
            then everything here is idle and costs nothing.
          </p>
          <button
            onClick={() => setPairing(true)}
            className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90"
          >
            Set up a second node
          </button>
        </div>
        {status.self && <SelfCard self={status.self} />}
      </div>
    );
  }

  const peers = status.peers ?? [];

  return (
    <div className="space-y-4">
      {/* The moment a person cares about: a replica that has lost its primary. */}
      {status.primary_reachable === false && (
        <Notice tone="threat">
          No primary is reachable. This node will promote itself if that does not change shortly.
        </Notice>
      )}
      {status.last_sync_error && <Notice tone="warn">Last replication attempt failed: {status.last_sync_error}</Notice>}

      {status.self && <SelfCard self={status.self} onDemote={load} />}

      <div className="grid gap-3">
        {peers.map((peer) => (
          <div key={peer.url} className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`size-2 rounded-full ${peer.reachable ? "bg-safe pulse-dot" : "bg-threat"}`} />
              <span className="text-sm text-ink">{peer.id || peer.url}</span>
              {peer.role && (
                <span className="rounded-full border border-base-600 px-2 py-0.5 font-mono text-[0.65rem] text-ink-muted">
                  {peer.role}
                </span>
              )}
            </div>

            <div className="mt-2 flex flex-wrap gap-3 font-mono text-[0.7rem] text-ink-faint">
              <span>{peer.url}</span>
              <span>revision {peer.revision}</span>
              {peer.version && <span>{peer.version}</span>}
              {peer.last_seen && <span>seen {new Date(peer.last_seen).toLocaleTimeString()}</span>}
            </div>

            {peer.error && <p className="mt-2 text-xs text-threat">{peer.error}</p>}
          </div>
        ))}
      </div>

      {status.last_sync && (
        <p className="text-xs text-ink-faint">
          Last replicated {new Date(status.last_sync).toLocaleString()}.
        </p>
      )}

      {pairing ? (
        <PairingGuide onClose={() => setPairing(false)} />
      ) : (
        <button
          onClick={() => setPairing(true)}
          className="text-xs text-ink-faint transition-colors hover:text-accent"
        >
          show the pairing configuration
        </button>
      )}
    </div>
  );
}

function SelfCard({
  self,
  onDemote,
}: {
  self: NonNullable<ClusterStatus["self"]>;
  onDemote?: () => void | Promise<void>;
}) {
  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span className={`size-2 rounded-full ${self.healthy ? "bg-safe pulse-dot" : "bg-threat"}`} />
          <span className="text-sm text-ink">{self.node_id}</span>
          <span className="rounded-full border border-accent-dim/60 bg-accent/10 px-2 py-0.5 font-mono text-[0.65rem] text-accent">
            {self.role}
          </span>
          <span className="text-xs text-ink-faint">this node</span>
        </div>

        {onDemote && self.role === "primary" && (
          <button
            onClick={() => void api.demote().then(onDemote)}
            className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-warn hover:text-warn"
          >
            Step down to replica
          </button>
        )}
      </div>

      <div className="mt-2 flex flex-wrap gap-3 font-mono text-[0.7rem] text-ink-faint">
        <span>revision {self.revision}</span>
        {self.hash && <span>{self.hash.slice(0, 12)}</span>}
        <span>{self.version}</span>
      </div>
    </div>
  );
}

/** Everything the node is, in one file. */
function BackupSection() {
  const [result, setResult] = useState<RestoreResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState<ArrayBuffer | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);

  const inspect = async (file: File) => {
    setError(null);
    setResult(null);

    try {
      const buffer = await file.arrayBuffer();
      // Dry run first: a restore replaces rules, feeds and devices, and seeing
      // what is in the archive beforehand is the difference between a restore
      // and a surprise.
      setResult(await api.restore(buffer, true));
      setPending(buffer);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const apply = async () => {
    if (!pending) return;

    setError(null);
    try {
      setResult(await api.restore(pending, false));
      setPending(null);
      if (fileInput.current) fileInput.current.value = "";
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Download</h3>
        <p className="mt-1.5 max-w-prose text-xs text-ink-muted">
          Settings, blocklist choices, your own rules and your devices. The query log is not included: it is
          large and it is a record of what this network did, not of how it is configured.
        </p>

        <div className="mt-3 flex flex-wrap gap-2">
          <a
            href="/api/backup"
            className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-base-950 transition-colors hover:bg-accent/90"
          >
            Download backup
          </a>
          <a
            href="/api/backup?secrets=true"
            className="rounded-md border border-warn/50 px-3 py-1.5 text-xs text-warn transition-colors hover:bg-warn/10"
          >
            Include logins and API keys
          </a>
        </div>

        <p className="mt-2 text-xs text-warn">
          The second file contains password hashes, two-factor secrets and your threat-source keys. Treat it
          like the node itself.
        </p>
      </div>

      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Restore</h3>
        <p className="mt-1.5 max-w-prose text-xs text-ink-muted">
          The archive is inspected first and applied only when you confirm. Your configuration file is never
          overwritten from here — an archive from another node carries its listeners, and restoring those could
          leave this one unreachable.
        </p>

        <input
          ref={fileInput}
          type="file"
          accept=".gz,.tar.gz,application/gzip"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) void inspect(file);
          }}
          className="mt-3 block w-full text-xs text-ink-muted file:mr-3 file:rounded-md file:border-0 file:bg-base-700 file:px-3 file:py-1.5 file:text-xs file:text-ink hover:file:bg-base-600"
        />

        {error && (
          <div className="mt-3">
            <Notice tone="threat">{error}</Notice>
          </div>
        )}

        {result && (
          <div className="mt-3 rounded-lg border border-base-700 bg-base-900/60 p-3">
            <p className="text-xs text-ink">
              {result.dry_run ? "This archive contains:" : "Restored:"}
            </p>
            <ul className="mt-2 grid gap-1 font-mono text-[0.7rem] text-ink-muted sm:grid-cols-2">
              {Object.entries(result.manifest.tables).map(([table, count]) => (
                <li key={table}>
                  {table}: {count}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[0.7rem] text-ink-faint">
              taken {new Date(result.manifest.created_at).toLocaleString()}
              {result.manifest.contains_secrets && " · includes logins and keys"}
            </p>

            {result.dry_run && pending && (
              <button
                onClick={() => void apply()}
                className="mt-3 rounded-md bg-threat px-3 py-1.5 text-xs font-medium text-base-950 transition-opacity hover:opacity-90"
              >
                Replace this node's settings
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

const channelKinds = [
  { id: "smtp", label: "Email", fields: ["host", "port", "from", "to", "username", "password"] },
  { id: "ntfy", label: "ntfy", fields: ["server", "topic", "token"] },
  { id: "webhook", label: "Webhook", fields: ["url", "authorization"] },
  { id: "telegram", label: "Telegram", fields: ["token", "chat_id"] },
  { id: "discord", label: "Discord", fields: ["url"] },
];

/** Where alerts go, and what has already been sent. */
function AlertsSection() {
  const [channels, setChannels] = useState<NotifyChannel[] | null>(null);
  const [history, setHistory] = useState<AlertHistory[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [kind, setKind] = useState("ntfy");
  const [name, setName] = useState("");
  const [severity, setSeverity] = useState("warning");
  const [fields, setFields] = useState<Record<string, string>>({});
  const [tested, setTested] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await api.notifyChannels();
      setChannels(result.channels ?? []);
      setHistory(result.history ?? []);
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

    const config: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(fields)) {
      if (value.trim() === "") continue;
      config[key] = key === "port" ? Number(value) : value;
    }

    try {
      await api.addChannel(kind, name, severity, config);
      setName("");
      setFields({});
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const test = async (id: number) => {
    setError(null);
    try {
      await api.testChannel(id);
      setTested(id);
      window.setTimeout(() => setTested(null), 3000);
    } catch (err) {
      // The failure is the useful part of a test button.
      setError(err instanceof Error ? err.message : String(err));
    }
    await load();
  };

  const active = channelKinds.find((k) => k.id === kind) ?? channelKinds[0];

  return (
    <div className="space-y-4">
      {error && <Notice tone="threat">{error}</Notice>}

      <div className="grid gap-3">
        {(channels ?? []).map((channel) => (
          <div key={channel.id} className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm text-ink">{channel.name}</span>
                  <span className="rounded-full border border-base-600 px-2 py-0.5 font-mono text-[0.65rem] text-ink-muted">
                    {channel.kind}
                  </span>
                  <span className="text-[0.65rem] text-ink-faint">{channel.min_severity} and above</span>
                </div>
                {channel.last_error ? (
                  <p className="mt-1.5 text-xs text-threat">{channel.last_error}</p>
                ) : (
                  channel.last_sent && (
                    <p className="mt-1.5 text-[0.7rem] text-ink-faint">
                      last delivered {new Date(channel.last_sent).toLocaleString()}
                    </p>
                  )
                )}
              </div>

              <div className="flex shrink-0 items-center gap-3">
                <button
                  onClick={() => void test(channel.id)}
                  className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
                >
                  {tested === channel.id ? "Sent" : "Send a test"}
                </button>
                <Toggle
                  on={channel.enabled}
                  onChange={async (on) => {
                    await api.setChannelEnabled(channel.id, on);
                    await load();
                  }}
                />
                <button
                  onClick={async () => {
                    await api.deleteChannel(channel.id);
                    await load();
                  }}
                  className="text-xs text-ink-faint transition-colors hover:text-threat"
                >
                  remove
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      <form onSubmit={add} className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Add a destination</h3>

        <div className="mt-3 flex flex-wrap gap-2">
          {channelKinds.map((k) => (
            <button
              key={k.id}
              type="button"
              onClick={() => {
                setKind(k.id);
                setFields({});
              }}
              className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
                kind === k.id ? "bg-accent text-base-950" : "border border-base-700 text-ink-muted hover:text-ink"
              }`}
            >
              {k.label}
            </button>
          ))}
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <label className="text-xs text-ink-muted">
            Name
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              placeholder="My phone"
              className="mt-1 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
            />
          </label>

          <label className="text-xs text-ink-muted">
            Send when severity is
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="mt-1 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink focus:border-accent-dim focus:outline-none"
            >
              <option value="info">info and above — everything</option>
              <option value="warning">warning and above</option>
              <option value="critical">critical only</option>
            </select>
          </label>

          {active.fields.map((field) => (
            <label key={field} className="text-xs text-ink-muted">
              {field.replace("_", " ")}
              <input
                type={field === "password" || field === "token" ? "password" : "text"}
                value={fields[field] ?? ""}
                onChange={(e) => setFields({ ...fields, [field]: e.target.value })}
                className="mt-1 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-xs text-ink focus:border-accent-dim focus:outline-none"
              />
            </label>
          ))}
        </div>

        <button
          type="submit"
          className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90"
        >
          Add
        </button>
      </form>

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Recent alerts</h3>
        {history.length === 0 ? (
          <p className="mt-2 text-xs text-ink-faint">Nothing has needed your attention.</p>
        ) : (
          <ul className="mt-3 space-y-2">
            {history.map((alert, i) => (
              <li key={`${alert.key}-${i}`} className="flex flex-wrap items-baseline gap-2 text-xs">
                <span
                  className={`size-1.5 rounded-full ${
                    alert.severity === "critical"
                      ? "bg-threat"
                      : alert.severity === "warning"
                        ? "bg-warn"
                        : "bg-ink-faint"
                  }`}
                />
                <span className="text-ink">{alert.title}</span>
                <span className="text-ink-faint">
                  {new Date(alert.sent_at).toLocaleString()} · {alert.delivered} sent
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

/** Who changed what. */
function AuditSection() {
  const [entries, setEntries] = useState<AuditEntry[] | null>(null);
  const [days, setDays] = useState(7);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .audit(days, 200)
      .then((r) => setEntries(r.entries ?? []))
      .catch((err) => setError(String(err)));
  }, [days]);

  if (error) return <Notice tone="threat">{error}</Notice>;

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        {[1, 7, 30, 365].map((d) => (
          <button
            key={d}
            onClick={() => setDays(d)}
            className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
              days === d ? "bg-base-700/70 text-ink" : "border border-base-700 text-ink-muted hover:text-ink"
            }`}
          >
            {d === 1 ? "Today" : d === 365 ? "This year" : `${d} days`}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto rounded-xl border border-base-700/70 bg-base-850/60">
        {(entries ?? []).length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-ink-faint">
            {entries === null ? "Loading…" : "Nothing was changed in this period."}
          </p>
        ) : (
          <table className="w-full text-xs">
            <tbody>
              {(entries ?? []).map((entry) => (
                <tr key={entry.id} className="border-b border-base-800/60 last:border-0">
                  <td className="w-6 py-2 pr-2 pl-4">
                    <span className={`inline-block size-1.5 rounded-full ${entry.success ? "bg-safe/60" : "bg-threat"}`} />
                  </td>
                  <td className="py-2 pr-3 font-mono whitespace-nowrap text-ink-faint">
                    {new Date(entry.at).toLocaleString()}
                  </td>
                  <td className="py-2 pr-3 whitespace-nowrap text-ink-muted">{entry.username || "—"}</td>
                  <td className="py-2 pr-3 font-mono text-ink">{entry.action}</td>
                  <td className="max-w-0 truncate py-2 pr-4 font-mono text-ink-faint" title={entry.detail}>
                    {entry.target}
                    {entry.detail && ` · ${entry.detail}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <p className="text-xs text-ink-faint">
        Only changes are recorded. A trail that logged every dashboard refresh would bury the entries that
        matter.
      </p>
    </div>
  );
}

/** What version this is, and whether there is a newer one. */
/**
 * What is on offer, and what it changes.
 *
 * The notes come before the button on purpose: replacing the binary that
 * resolves every name in the house is not something to agree to without
 * reading what changed. An update with no notes says so rather than showing an
 * empty box, because "nothing is written here" and "nothing changed" are
 * different claims.
 */
function UpdateOffer({ status }: { status: UpdateStatus }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [installed, setInstalled] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  if (installed) {
    return <Restarting expected={installed} />;
  }

  return (
    <div className="mt-4 rounded-lg border border-accent-dim/60 bg-accent/5 p-3">
      <p className="text-sm text-ink">Version {status.latest} is available.</p>

      <div className="mt-2">
        <span className="text-[0.65rem] font-medium tracking-wide text-ink-faint uppercase">
          What changed
        </span>
        {status.notes ? (
          <pre className="mt-1 max-h-56 overflow-auto rounded-md border border-base-700/70 bg-base-950/40 p-3 text-xs leading-relaxed whitespace-pre-wrap text-ink-muted">
            {status.notes}
          </pre>
        ) : (
          <p className="mt-1 text-xs text-ink-faint">
            This release was published without notes.
          </p>
        )}
      </div>

      {error && <p className="mt-2 text-xs text-threat">{error}</p>}

      {confirming ? (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <span className="text-xs text-warn">
            Install {status.latest} and restart the resolver?
          </span>
          <button
            disabled={busy}
            onClick={async () => {
              setError(null);
              setBusy(true);
              try {
                const result = await api.applyUpdate();
                setInstalled(result.installed);
              } catch (err) {
                setError(err instanceof Error ? err.message : String(err));
                setConfirming(false);
              } finally {
                setBusy(false);
              }
            }}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-50"
          >
            {busy ? "Verifying and installing…" : "Yes, install it"}
          </button>
          <button
            onClick={() => setConfirming(false)}
            className="text-xs text-ink-faint transition-colors hover:text-ink"
          >
            cancel
          </button>
        </div>
      ) : (
        <button
          disabled={!status.managed}
          onClick={() => setConfirming(true)}
          className="mt-3 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          Install {status.latest}
        </button>
      )}
    </div>
  );
}

/**
 * The gap between "installed" and "running".
 *
 * The node exits and the service manager starts the new binary, so the panel
 * is talking to nothing for a second or two. Watching health come back is the
 * only honest way to report the outcome: the request that installed the update
 * cannot know whether the process that replaced it came up.
 */
function Restarting({ expected }: { expected: string }) {
  const [live, setLive] = useState<string | null>(null);
  const [waited, setWaited] = useState(0);

  useEffect(() => {
    const started = Date.now();
    const timer = window.setInterval(() => {
      setWaited(Math.round((Date.now() - started) / 1000));

      void api
        .health()
        .then((health) => {
          if (health.version) setLive(health.version);
        })
        .catch(() => {
          // Expected while the listener is down. Silence here is the normal
          // case, not a failure to report.
        });
    }, 1500);

    return () => window.clearInterval(timer);
  }, []);

  if (live === expected) {
    return (
      <div className="mt-4 rounded-lg border border-safe/50 bg-safe/5 p-3">
        <p className="text-sm text-ink">Running {expected}.</p>
        <p className="mt-1 text-xs text-ink-muted">
          Verified, installed and back up. The previous binary is kept as{" "}
          <span className="font-mono">seddns.old</span>.
        </p>
      </div>
    );
  }

  // Long enough that a slow Pi is not accused of failing, short enough that a
  // node which is genuinely not coming back is not waited on in silence.
  const slow = waited > 45;

  return (
    <div className={`mt-4 rounded-lg border p-3 ${slow ? "border-warn/50 bg-warn/5" : "border-accent-dim/60 bg-accent/5"}`}>
      <p className="text-sm text-ink">
        {expected} is installed and verified. Waiting for the node to come back…
      </p>
      <p className="mt-1 max-w-prose text-xs text-ink-muted">
        DNS is unavailable for a second or two while it restarts; devices retry, so this is usually
        invisible.
        {live && live !== expected && <> Still answering as {live}.</>}
      </p>
      {slow && (
        <p className="mt-2 max-w-prose text-xs text-warn">
          It has been {waited} seconds. The previous binary is still on disk as{" "}
          <span className="font-mono">seddns.old</span> — check{" "}
          <span className="font-mono">journalctl -u seddns</span> on the node.
        </p>
      )}
    </div>
  );
}

function UpdatesSection() {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [checking, setChecking] = useState(false);

  const check = useCallback(async () => {
    setChecking(true);
    try {
      setStatus(await api.updateStatus());
    } catch {
      // The endpoint reports its own failures in the payload.
    } finally {
      setChecking(false);
    }
  }, []);

  useEffect(() => {
    void check();
  }, [check]);

  if (!status) return <Notice>Loading…</Notice>;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <div>
            <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">Running</span>
            <div className="mt-1 font-mono text-2xl text-ink tabular-nums">{status.current}</div>
          </div>

          <button
            onClick={() => void check()}
            disabled={checking}
            className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent disabled:opacity-50"
          >
            {checking ? "Checking…" : "Check again"}
          </button>
        </div>

        {status.update_available ? (
          <UpdateOffer status={status} />
        ) : (
          !status.error && <p className="mt-3 text-xs text-ink-muted">This is the current release.</p>
        )}

        {status.error && <p className="mt-3 text-xs text-warn">{status.error}</p>}

        {!status.managed && (
          <p className="mt-3 text-xs text-ink-faint">
            This binary was not installed by the updater, so it will not replace itself. Update it the way you
            installed it.
          </p>
        )}
      </div>

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">How an update is applied</h3>
        <ol className="mt-3 space-y-2 text-xs text-ink-muted">
          <li>
            <span className="text-ink">Verify.</span> The archive is checked against a signed checksum file
            before it is unpacked. A valid TLS connection says nothing about what is inside a download.
          </li>
          <li>
            <span className="text-ink">Snapshot.</span> Your settings are exported first, so a bad release can
            be undone rather than mourned.
          </li>
          <li>
            <span className="text-ink">Swap and prove.</span> The old binary is kept while the new one has to
            start and validate its configuration. If it cannot, the old one comes back.
          </li>
        </ol>
      </div>
    </div>
  );
}
