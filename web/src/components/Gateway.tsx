import { useCallback, useEffect, useState } from "react";
import { api, type GatewayStatus } from "../api";
import { Notice } from "./Panels";
import { useLang } from "../i18n/context";

/**
 * Gateway mode: what it is, what this machine is missing, and the settings it
 * would take.
 *
 * Nothing here switches it on. The mode has never run on real hardware, and
 * the failure it produces is not a DNS outage — it is the household with no
 * internet at all. So the screen checks the machine in front of it, says
 * plainly what is not ready, and stores the settings for when it is.
 */
export function GatewayPanel() {
  const { t } = useLang();
  const [status, setStatus] = useState<GatewayStatus | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    try {
      setStatus(await api.gatewayStatus());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (error && !status) return <Notice tone="threat">{error}</Notice>;
  if (!status) return <Notice>{t("common.loading")}</Notice>;

  const blocking = (status.readiness?.checks ?? []).filter(
    (c) => !c.passed && c.blocking,
  );

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h3 className="text-sm font-medium text-ink">
            {t("gateway.whatChanges")}
          </h3>
          <span className="rounded-full border border-base-600 px-2 py-0.5 font-mono text-[0.65rem] text-ink-muted">
            {t("gateway.now", { mode: status.mode })}
          </span>
        </div>

        <p className="mt-2 max-w-prose text-xs text-ink-muted">
          {t("gateway.todayDetail")}
        </p>
        <p className="mt-2 max-w-prose text-xs text-ink-muted">
          {t("gateway.gatewayDetail")}
        </p>
        <p className="mt-2 max-w-prose text-xs text-warn">
          {t("gateway.tradeoffDetail")}
        </p>
      </div>

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
            {t("gateway.whatMissing")}
          </h3>
          <span
            className={`text-xs ${status.readiness?.ready ? "text-safe" : "text-warn"}`}
          >
            {status.readiness?.ready
              ? t("gateway.allInPlace")
              : t("gateway.notReady")}
          </span>
        </div>

        <div className="mt-3 space-y-2">
          {(status.readiness?.checks ?? []).map((c) => (
            <div
              key={c.name}
              className="rounded-lg border border-base-800/80 bg-base-900/40 px-3 py-2"
            >
              <div className="flex flex-wrap items-baseline gap-2">
                <span
                  className={`size-1.5 shrink-0 rounded-full ${c.passed ? "bg-safe" : c.blocking ? "bg-threat" : "bg-warn"}`}
                />
                <span className="text-sm text-ink">{c.name}</span>
                <span className="font-mono text-[0.7rem] text-ink-faint">
                  {c.detail}
                </span>
              </div>
              {c.remedy && (
                <p className="mt-1 max-w-prose text-xs text-ink-muted">
                  {c.remedy}
                </p>
              )}
            </div>
          ))}
        </div>

        {blocking.length > 0 && (
          <p className="mt-3 max-w-prose text-xs text-threat">
            {t(
              blocking.length === 1
                ? "gateway.oneRequirement"
                : "gateway.manyRequirements",
              { count: blocking.length },
            )}{" "}
            {t("gateway.requirementsSuffix")}
          </p>
        )}
      </div>

      <Ports status={status} />
      <Settings
        status={status}
        onSaved={() => {
          setSaved(true);
          window.setTimeout(() => setSaved(false), 2500);
          void load();
        }}
        onError={setError}
        saved={saved}
      />

      {error && <Notice tone="threat">{error}</Notice>}
    </div>
  );
}

function Ports({ status }: { status: GatewayStatus }) {
  const { t } = useLang();

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
        {t("gateway.networkPorts")}
      </h3>
      {status.current_route?.interface && (
        <p className="mt-1 text-xs text-ink-faint">
          {t("gateway.wayOutToday")}{" "}
          <span className="font-mono">{status.current_route.interface}</span>{" "}
          {t("gateway.via")}{" "}
          <span className="font-mono">{status.current_route.gateway}</span>.
        </p>
      )}

      <div className="mt-3 grid gap-2 sm:grid-cols-2">
        {(status.readiness?.interfaces ?? []).map((i) => (
          <div
            key={i.name}
            className="flex flex-wrap items-baseline justify-between gap-2 rounded-lg border border-base-800/80 bg-base-900/40 px-3 py-2"
          >
            <div className="flex items-baseline gap-2">
              <span className="font-mono text-xs text-ink">{i.name}</span>
              <span className="text-[0.65rem] text-ink-faint">{i.kind}</span>
            </div>
            <span className="font-mono text-[0.7rem] text-ink-faint">
              {i.addresses?.join(", ") ||
                (i.up ? t("gateway.noAddress") : t("gateway.down"))}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

function Settings({
  status,
  onSaved,
  onError,
  saved,
}: {
  status: GatewayStatus;
  onSaved: () => void;
  onError: (m: string | null) => void;
  saved: boolean;
}) {
  const { t } = useLang();
  const s = status.settings;
  const [wan, setWAN] = useState(s?.wan_interface ?? "");
  const [lan, setLAN] = useState(s?.lan_interface ?? "");
  const [pppoe, setPPPoE] = useState(s?.pppoe_enabled ?? false);
  const [user, setUser] = useState(s?.pppoe_username ?? "");
  const [pass, setPass] = useState("");
  const [from, setFrom] = useState(s?.dhcp_from ?? "192.168.10.100");
  const [to, setTo] = useState(s?.dhcp_to ?? "192.168.10.200");
  const [busy, setBusy] = useState(false);

  const wired = (status.readiness?.interfaces ?? []).filter(
    (i) => i.kind === "wired",
  );

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    onError(null);
    setBusy(true);

    try {
      await api.saveGateway({
        wan_interface: wan,
        lan_interface: lan,
        pppoe_enabled: pppoe,
        pppoe_username: user,
        pppoe_password: pass || undefined,
        dhcp_from: from,
        dhcp_to: to,
      });
      setPass("");
      onSaved();
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
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("gateway.settings")}
        </h3>
        <span
          className={`text-xs text-safe transition-opacity ${saved ? "opacity-100" : "opacity-0"}`}
        >
          {t("gateway.saved")}
        </span>
      </div>
      <p className="mt-1 max-w-prose text-xs text-ink-faint">
        {t("gateway.storedNotApplied")}
      </p>

      <div className="mt-3 flex flex-wrap gap-3">
        <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("gateway.wanPort")}
          <select
            value={wan}
            onChange={(e) => setWAN(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          >
            <option value="">{t("gateway.notChosen")}</option>
            {wired.map((i) => (
              <option key={i.name} value={i.name}>
                {i.name}
              </option>
            ))}
          </select>
        </label>

        <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("gateway.lanPort")}
          <select
            value={lan}
            onChange={(e) => setLAN(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          >
            <option value="">{t("gateway.notChosen")}</option>
            {wired.map((i) => (
              <option key={i.name} value={i.name}>
                {i.name}
              </option>
            ))}
          </select>
        </label>
      </div>

      <div className="mt-4 rounded-lg border border-base-800/80 bg-base-900/40 p-3">
        <label className="flex items-center gap-2 text-sm text-ink">
          <input
            type="checkbox"
            checked={pppoe}
            onChange={(e) => setPPPoE(e.target.checked)}
            className="accent-[var(--color-accent)]"
          />
          {t("gateway.pppoeLabel")}
        </label>
        <p className="mt-1.5 max-w-prose text-xs text-ink-muted">
          {t("gateway.pppoeDetail")}
        </p>
        <p className="mt-1.5 max-w-prose text-xs text-ink-faint">
          {t("gateway.pppoeOffDetail")}
        </p>

        {pppoe && (
          <div className="mt-3 flex flex-wrap gap-3">
            <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
              {t("gateway.providerUsername")}
              <input
                value={user}
                onChange={(e) => setUser(e.target.value)}
                autoComplete="off"
                className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
              />
            </label>
            <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
              {t("gateway.providerPassword")}
              <input
                type="password"
                value={pass}
                onChange={(e) => setPass(e.target.value)}
                placeholder={t("gateway.keepStored")}
                autoComplete="off"
                className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
              />
            </label>
          </div>
        )}
      </div>

      <div className="mt-4 flex flex-wrap gap-3">
        <label className="w-44 text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("gateway.handOutFrom")}
          <input
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          />
        </label>
        <label className="w-44 text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("gateway.to")}
          <input
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          />
        </label>
      </div>
      <p className="mt-1.5 max-w-prose text-xs text-ink-faint">
        {t("gateway.dhcpRangeNote")}
      </p>

      <button
        type="submit"
        disabled={busy}
        className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
      >
        {busy ? "…" : t("gateway.saveForLater")}
      </button>
    </form>
  );
}
