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
import { GatewayPanel } from "./Gateway";
import { HostPanel } from "./Host";
import { IntelKeysPanel } from "./IntelKeys";
import { LogsPanel } from "./Logs";
import { PairingGuide } from "./Pairing";
import { UpstreamsPanel } from "./Upstreams";
import { useLang } from "../i18n/context";

type Section =
  | "machine"
  | "logs"
  | "upstreams"
  | "intel"
  | "gateway"
  | "cluster"
  | "backup"
  | "alerts"
  | "audit"
  | "updates";

const sections: { id: Section; labelKey: string }[] = [
  { id: "machine", labelKey: "system.nav.machine" },
  { id: "logs", labelKey: "system.nav.logs" },
  { id: "upstreams", labelKey: "system.nav.upstreams" },
  { id: "intel", labelKey: "system.nav.intel" },
  { id: "gateway", labelKey: "system.nav.gateway" },
  { id: "cluster", labelKey: "system.nav.cluster" },
  { id: "backup", labelKey: "system.nav.backup" },
  { id: "alerts", labelKey: "system.nav.alerts" },
  { id: "audit", labelKey: "system.nav.audit" },
  { id: "updates", labelKey: "system.nav.updates" },
];

/**
 * The things you touch rarely.
 *
 * These live behind one tab rather than five of their own: a household sets up
 * alerts once and looks at the audit trail when something is wrong, and putting
 * them beside the daily screens would push the daily screens off the edge.
 */
export function SystemPanel() {
  const { t } = useLang();
  const [section, setSection] = useState<Section>("machine");

  return (
    <div className="space-y-5">
      <nav className="flex flex-wrap gap-1 rounded-lg border border-base-700/70 bg-base-850/40 p-1">
        {sections.map((s) => (
          <button
            key={s.id}
            onClick={() => setSection(s.id)}
            className={`rounded-md px-3 py-1.5 text-xs transition-colors ${
              section === s.id
                ? "bg-base-700/70 text-ink"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            {t(s.labelKey)}
          </button>
        ))}
      </nav>

      {section === "machine" && <HostPanel />}
      {section === "logs" && <LogsPanel />}
      {section === "upstreams" && <UpstreamsPanel />}
      {section === "intel" && <IntelKeysPanel />}
      {section === "gateway" && <GatewayPanel />}
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
  const { t } = useLang();
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
  if (!status) return <Notice>{t("common.loading")}</Notice>;

  if (!status.enabled) {
    if (pairing) return <PairingGuide onClose={() => setPairing(false)} />;

    return (
      <div className="space-y-4">
        <div className="rounded-xl border border-base-700/70 bg-base-850/40 px-4 py-8 text-center">
          <p className="text-sm text-ink">
            {t("system.cluster.standaloneTitle")}
          </p>
          <p className="mx-auto mt-1 max-w-prose text-xs text-ink-faint">
            {t("system.cluster.standaloneDetail")}
          </p>
          <button
            onClick={() => setPairing(true)}
            className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90"
          >
            {t("system.cluster.setupSecondNode")}
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
        <Notice tone="threat">{t("system.cluster.noPrimary")}</Notice>
      )}
      {status.last_sync_error && (
        <Notice tone="warn">
          {t("system.cluster.syncFailed", { error: status.last_sync_error })}
        </Notice>
      )}

      {status.self && <SelfCard self={status.self} onDemote={load} />}

      <div className="grid gap-3">
        {peers.map((peer) => (
          <div
            key={peer.url}
            className="rounded-xl border border-base-700/70 bg-base-850/60 p-4"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`size-2 rounded-full ${peer.reachable ? "bg-safe pulse-dot" : "bg-threat"}`}
              />
              <span className="text-sm text-ink">{peer.id || peer.url}</span>
              {peer.role && (
                <span className="rounded-full border border-base-600 px-2 py-0.5 font-mono text-[0.65rem] text-ink-muted">
                  {peer.role}
                </span>
              )}
            </div>

            <div className="mt-2 flex flex-wrap gap-3 font-mono text-[0.7rem] text-ink-faint">
              <span>{peer.url}</span>
              <span>
                {t("system.cluster.revision", { rev: peer.revision })}
              </span>
              {peer.version && <span>{peer.version}</span>}
              {peer.last_seen && (
                <span>
                  {t("system.cluster.seen", {
                    when: new Date(peer.last_seen).toLocaleTimeString(),
                  })}
                </span>
              )}
            </div>

            {peer.error && (
              <p className="mt-2 text-xs text-threat">{peer.error}</p>
            )}
          </div>
        ))}
      </div>

      {status.last_sync && (
        <p className="text-xs text-ink-faint">
          {t("system.cluster.lastReplicated", {
            when: new Date(status.last_sync).toLocaleString(),
          })}
        </p>
      )}

      {pairing ? (
        <PairingGuide onClose={() => setPairing(false)} />
      ) : (
        <button
          onClick={() => setPairing(true)}
          className="text-xs text-ink-faint transition-colors hover:text-accent"
        >
          {t("system.cluster.showPairing")}
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
  const { t } = useLang();

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`size-2 rounded-full ${self.healthy ? "bg-safe pulse-dot" : "bg-threat"}`}
          />
          <span className="text-sm text-ink">{self.node_id}</span>
          <span className="rounded-full border border-accent-dim/60 bg-accent/10 px-2 py-0.5 font-mono text-[0.65rem] text-accent">
            {self.role}
          </span>
          <span className="text-xs text-ink-faint">
            {t("system.cluster.thisNode")}
          </span>
        </div>

        {onDemote && self.role === "primary" && (
          <button
            onClick={() => void api.demote().then(onDemote)}
            className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-warn hover:text-warn"
          >
            {t("system.cluster.stepDown")}
          </button>
        )}
      </div>

      <div className="mt-2 flex flex-wrap gap-3 font-mono text-[0.7rem] text-ink-faint">
        <span>{t("system.cluster.revision", { rev: self.revision })}</span>
        {self.hash && <span>{self.hash.slice(0, 12)}</span>}
        <span>{self.version}</span>
      </div>
    </div>
  );
}

/** Everything the node is, in one file. */
function BackupSection() {
  const { t } = useLang();
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
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("system.backup.download")}
        </h3>
        <p className="mt-1.5 max-w-prose text-xs text-ink-muted">
          {t("system.backup.downloadDetail")}
        </p>

        <div className="mt-3 flex flex-wrap gap-2">
          <a
            href="/api/backup"
            className="rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-base-950 transition-colors hover:bg-accent/90"
          >
            {t("system.backup.downloadBackup")}
          </a>
          <a
            href="/api/backup?secrets=true"
            className="rounded-md border border-warn/50 px-3 py-1.5 text-xs text-warn transition-colors hover:bg-warn/10"
          >
            {t("system.backup.includeSecrets")}
          </a>
        </div>

        <p className="mt-2 text-xs text-warn">
          {t("system.backup.secretsWarning")}
        </p>
      </div>

      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("system.backup.restore")}
        </h3>
        <p className="mt-1.5 max-w-prose text-xs text-ink-muted">
          {t("system.backup.restoreDetail")}
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
              {result.dry_run
                ? t("system.backup.contains")
                : t("system.backup.restored")}
            </p>
            <ul className="mt-2 grid gap-1 font-mono text-[0.7rem] text-ink-muted sm:grid-cols-2">
              {Object.entries(result.manifest.tables).map(([table, count]) => (
                <li key={table}>
                  {table}: {count}
                </li>
              ))}
            </ul>
            <p className="mt-2 text-[0.7rem] text-ink-faint">
              {t("system.backup.taken", {
                when: new Date(result.manifest.created_at).toLocaleString(),
              })}
              {result.manifest.contains_secrets && (
                <> · {t("system.backup.includesSecrets")}</>
              )}
            </p>

            {result.dry_run && pending && (
              <button
                onClick={() => void apply()}
                className="mt-3 rounded-md bg-threat px-3 py-1.5 text-xs font-medium text-base-950 transition-opacity hover:opacity-90"
              >
                {t("system.backup.replaceSettings")}
              </button>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

const channelKinds = [
  {
    id: "smtp",
    labelKey: "system.alerts.kinds.smtp",
    fields: ["host", "port", "from", "to", "username", "password"],
  },
  {
    id: "ntfy",
    labelKey: "system.alerts.kinds.ntfy",
    fields: ["server", "topic", "token"],
  },
  {
    id: "webhook",
    labelKey: "system.alerts.kinds.webhook",
    fields: ["url", "authorization"],
  },
  {
    id: "telegram",
    labelKey: "system.alerts.kinds.telegram",
    fields: ["token", "chat_id"],
  },
  { id: "discord", labelKey: "system.alerts.kinds.discord", fields: ["url"] },
];

/** Where alerts go, and what has already been sent. */
function AlertsSection() {
  const { t } = useLang();
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
          <div
            key={channel.id}
            className="rounded-xl border border-base-700/70 bg-base-850/60 p-4"
          >
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-sm text-ink">{channel.name}</span>
                  <span className="rounded-full border border-base-600 px-2 py-0.5 font-mono text-[0.65rem] text-ink-muted">
                    {channel.kind}
                  </span>
                  <span className="text-[0.65rem] text-ink-faint">
                    {t("system.alerts.andAbove", {
                      severity: channel.min_severity,
                    })}
                  </span>
                </div>
                {channel.last_error ? (
                  <p className="mt-1.5 text-xs text-threat">
                    {channel.last_error}
                  </p>
                ) : (
                  channel.last_sent && (
                    <p className="mt-1.5 text-[0.7rem] text-ink-faint">
                      {t("system.alerts.lastDelivered", {
                        when: new Date(channel.last_sent).toLocaleString(),
                      })}
                    </p>
                  )
                )}
              </div>

              <div className="flex shrink-0 items-center gap-3">
                <button
                  onClick={() => void test(channel.id)}
                  className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
                >
                  {tested === channel.id
                    ? t("system.alerts.sent")
                    : t("system.alerts.sendTest")}
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
                  {t("system.alerts.remove")}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      <form
        onSubmit={add}
        className="rounded-xl border border-base-700/70 bg-base-850/40 p-4"
      >
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("system.alerts.addDestination")}
        </h3>

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
                kind === k.id
                  ? "bg-accent text-base-950"
                  : "border border-base-700 text-ink-muted hover:text-ink"
              }`}
            >
              {t(k.labelKey)}
            </button>
          ))}
        </div>

        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <label className="text-xs text-ink-muted">
            {t("system.alerts.name")}
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
              placeholder={t("system.alerts.namePlaceholder")}
              className="mt-1 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
            />
          </label>

          <label className="text-xs text-ink-muted">
            {t("system.alerts.severityLabel")}
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="mt-1 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink focus:border-accent-dim focus:outline-none"
            >
              <option value="info">{t("system.alerts.severityInfo")}</option>
              <option value="warning">
                {t("system.alerts.severityWarning")}
              </option>
              <option value="critical">
                {t("system.alerts.severityCritical")}
              </option>
            </select>
          </label>

          {active.fields.map((field) => (
            <label key={field} className="text-xs text-ink-muted">
              {field.replace("_", " ")}
              <input
                type={
                  field === "password" || field === "token"
                    ? "password"
                    : "text"
                }
                value={fields[field] ?? ""}
                onChange={(e) =>
                  setFields({ ...fields, [field]: e.target.value })
                }
                className="mt-1 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-xs text-ink focus:border-accent-dim focus:outline-none"
              />
            </label>
          ))}
        </div>

        <button
          type="submit"
          className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90"
        >
          {t("system.alerts.add")}
        </button>
      </form>

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("system.alerts.recent")}
        </h3>
        {history.length === 0 ? (
          <p className="mt-2 text-xs text-ink-faint">
            {t("system.alerts.none")}
          </p>
        ) : (
          <ul className="mt-3 space-y-2">
            {history.map((alert, i) => (
              <li
                key={`${alert.key}-${i}`}
                className="flex flex-wrap items-baseline gap-2 text-xs"
              >
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
                  {new Date(alert.sent_at).toLocaleString()} ·{" "}
                  {t("system.alerts.delivered", { count: alert.delivered })}
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
  const { t } = useLang();
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
              days === d
                ? "bg-base-700/70 text-ink"
                : "border border-base-700 text-ink-muted hover:text-ink"
            }`}
          >
            {d === 1
              ? t("system.audit.today")
              : d === 365
                ? t("system.audit.thisYear")
                : t("system.audit.daysCount", { days: d })}
          </button>
        ))}
      </div>

      <div className="overflow-x-auto rounded-xl border border-base-700/70 bg-base-850/60">
        {(entries ?? []).length === 0 ? (
          <p className="px-4 py-8 text-center text-sm text-ink-faint">
            {entries === null ? t("common.loading") : t("system.audit.none")}
          </p>
        ) : (
          <table className="w-full text-xs">
            <tbody>
              {(entries ?? []).map((entry) => (
                <tr
                  key={entry.id}
                  className="border-b border-base-800/60 last:border-0"
                >
                  <td className="w-6 py-2 pr-2 pl-4">
                    <span
                      className={`inline-block size-1.5 rounded-full ${entry.success ? "bg-safe/60" : "bg-threat"}`}
                    />
                  </td>
                  <td className="py-2 pr-3 font-mono whitespace-nowrap text-ink-faint">
                    {new Date(entry.at).toLocaleString()}
                  </td>
                  <td className="py-2 pr-3 whitespace-nowrap text-ink-muted">
                    {entry.username || "—"}
                  </td>
                  <td className="py-2 pr-3 font-mono text-ink">
                    {entry.action}
                  </td>
                  <td
                    className="max-w-0 truncate py-2 pr-4 font-mono text-ink-faint"
                    title={entry.detail}
                  >
                    {entry.target}
                    {entry.detail && ` · ${entry.detail}`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <p className="text-xs text-ink-faint">{t("system.audit.onlyChanges")}</p>
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
  const { t } = useLang();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [installed, setInstalled] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);

  if (installed) {
    return <Restarting expected={installed} />;
  }

  return (
    <div className="mt-4 rounded-lg border border-accent-dim/60 bg-accent/5 p-3">
      <p className="text-sm text-ink">
        {t("system.updates.versionAvailable", { version: status.latest ?? "" })}
      </p>

      <div className="mt-2">
        <span className="text-[0.65rem] font-medium tracking-wide text-ink-faint uppercase">
          {t("system.updates.whatChanged")}
        </span>
        {status.notes ? (
          <pre className="mt-1 max-h-56 overflow-auto rounded-md border border-base-700/70 bg-base-950/40 p-3 text-xs leading-relaxed whitespace-pre-wrap text-ink-muted">
            {status.notes}
          </pre>
        ) : (
          <p className="mt-1 text-xs text-ink-faint">
            {t("system.updates.noNotes")}
          </p>
        )}
      </div>

      {error && <p className="mt-2 text-xs text-threat">{error}</p>}

      {confirming ? (
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <span className="text-xs text-warn">
            {t("system.updates.installConfirm", {
              version: status.latest ?? "",
            })}
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
            {busy
              ? t("system.updates.verifyingInstalling")
              : t("system.updates.yesInstall")}
          </button>
          <button
            onClick={() => setConfirming(false)}
            className="text-xs text-ink-faint transition-colors hover:text-ink"
          >
            {t("system.updates.cancel")}
          </button>
        </div>
      ) : (
        <button
          disabled={!status.managed}
          onClick={() => setConfirming(true)}
          className="mt-3 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          {t("system.updates.install", { version: status.latest ?? "" })}
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
  const { t } = useLang();
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
        <p className="text-sm text-ink">
          {t("system.updates.runningVersion", { version: expected })}
        </p>
        <p className="mt-1 text-xs text-ink-muted">
          {t("system.updates.verifiedBackUp")}{" "}
          <span className="font-mono">seddns.old</span>.
        </p>
      </div>
    );
  }

  // Long enough that a slow Pi is not accused of failing, short enough that a
  // node which is genuinely not coming back is not waited on in silence.
  const slow = waited > 45;

  return (
    <div
      className={`mt-4 rounded-lg border p-3 ${slow ? "border-warn/50 bg-warn/5" : "border-accent-dim/60 bg-accent/5"}`}
    >
      <p className="text-sm text-ink">
        {t("system.updates.waitingBack", { version: expected })}
      </p>
      <p className="mt-1 max-w-prose text-xs text-ink-muted">
        {t("system.updates.dnsUnavailable")}
        {live && live !== expected && (
          <>{t("system.updates.stillAnswering", { live })}</>
        )}
      </p>
      {slow && (
        <p className="mt-2 max-w-prose text-xs text-warn">
          {t("system.updates.tookSeconds", { seconds: waited })}{" "}
          <span className="font-mono">seddns.old</span>{" "}
          {t("system.updates.checkJournal")}{" "}
          <span className="font-mono">journalctl -u seddns</span>{" "}
          {t("system.updates.onTheNode")}
        </p>
      )}
    </div>
  );
}

function UpdatesSection() {
  const { t } = useLang();
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

  if (!status) return <Notice>{t("common.loading")}</Notice>;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <div>
            <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">
              {t("system.updates.running")}
            </span>
            <div className="mt-1 font-mono text-2xl text-ink tabular-nums">
              {status.current}
            </div>
          </div>

          <button
            onClick={() => void check()}
            disabled={checking}
            className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent disabled:opacity-50"
          >
            {checking
              ? t("system.updates.checking")
              : t("system.updates.checkAgain")}
          </button>
        </div>

        {status.update_available ? (
          <UpdateOffer status={status} />
        ) : (
          !status.error && (
            <p className="mt-3 text-xs text-ink-muted">
              {t("system.updates.currentRelease")}
            </p>
          )
        )}

        {status.error && (
          <p className="mt-3 text-xs text-warn">{status.error}</p>
        )}

        {!status.managed && (
          <p className="mt-3 text-xs text-ink-faint">
            {t("system.updates.notManaged")}
          </p>
        )}
      </div>

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("system.updates.howApplied")}
        </h3>
        <ol className="mt-3 space-y-2 text-xs text-ink-muted">
          <li>
            <span className="text-ink">{t("system.updates.verifyTitle")}</span>{" "}
            {t("system.updates.verifyDetail")}
          </li>
          <li>
            <span className="text-ink">
              {t("system.updates.snapshotTitle")}
            </span>{" "}
            {t("system.updates.snapshotDetail")}
          </li>
          <li>
            <span className="text-ink">{t("system.updates.swapTitle")}</span>{" "}
            {t("system.updates.swapDetail")}
          </li>
        </ol>
      </div>
    </div>
  );
}
