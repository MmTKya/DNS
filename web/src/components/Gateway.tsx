import { useCallback, useEffect, useState } from "react";
import { api, type GatewayStatus } from "../api";
import { Notice } from "./Panels";

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
  if (!status) return <Notice>Loading…</Notice>;

  const blocking = (status.readiness?.checks ?? []).filter((c) => !c.passed && c.blocking);

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <h3 className="text-sm font-medium text-ink">What gateway mode changes</h3>
          <span className="rounded-full border border-base-600 px-2 py-0.5 font-mono text-[0.65rem] text-ink-muted">
            now: {status.mode}
          </span>
        </div>

        <p className="mt-2 max-w-prose text-xs text-ink-muted">
          Today this node answers questions about names. Your devices ask it where a site is, and
          then talk to that site directly — down a path this node never sees. That is why there are
          no byte counters here and why pausing a device filters its lookups rather than cutting it
          off.
        </p>
        <p className="mt-2 max-w-prose text-xs text-ink-muted">
          In gateway mode every packet passes through this machine on its way out of the house. It
          can count what each device actually used, see which one is uploading, and stop a device by
          dropping its traffic rather than by declining to look up an address.
        </p>
        <p className="mt-2 max-w-prose text-xs text-warn">
          It also becomes the way out. If this machine stops — a failed card, a pulled cable, an
          update that goes wrong — the house loses the internet, not just its DNS. With one node and
          no second to take over, that is the whole trade in one sentence.
        </p>
      </div>

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
            What this machine is missing
          </h3>
          <span className={`text-xs ${status.readiness?.ready ? "text-safe" : "text-warn"}`}>
            {status.readiness?.ready ? "everything is in place" : "not ready"}
          </span>
        </div>

        <div className="mt-3 space-y-2">
          {(status.readiness?.checks ?? []).map((c) => (
            <div key={c.name} className="rounded-lg border border-base-800/80 bg-base-900/40 px-3 py-2">
              <div className="flex flex-wrap items-baseline gap-2">
                <span
                  className={`size-1.5 shrink-0 rounded-full ${c.passed ? "bg-safe" : c.blocking ? "bg-threat" : "bg-warn"}`}
                />
                <span className="text-sm text-ink">{c.name}</span>
                <span className="font-mono text-[0.7rem] text-ink-faint">{c.detail}</span>
              </div>
              {c.remedy && <p className="mt-1 max-w-prose text-xs text-ink-muted">{c.remedy}</p>}
            </div>
          ))}
        </div>

        {blocking.length > 0 && (
          <p className="mt-3 max-w-prose text-xs text-threat">
            {blocking.length === 1 ? "One requirement is" : `${blocking.length} requirements are`} not
            something a setting can fix. Until that changes, the rest of this screen is preparation.
          </p>
        )}
      </div>

      <Ports status={status} />
      <Settings status={status} onSaved={() => { setSaved(true); window.setTimeout(() => setSaved(false), 2500); void load(); }} onError={setError} saved={saved} />

      {error && <Notice tone="threat">{error}</Notice>}
    </div>
  );
}

function Ports({ status }: { status: GatewayStatus }) {
  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Network ports</h3>
      {status.current_route?.interface && (
        <p className="mt-1 text-xs text-ink-faint">
          The way out today is <span className="font-mono">{status.current_route.interface}</span> via{" "}
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
              {i.addresses?.join(", ") || (i.up ? "no address" : "down")}
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
  const s = status.settings;
  const [wan, setWAN] = useState(s?.wan_interface ?? "");
  const [lan, setLAN] = useState(s?.lan_interface ?? "");
  const [pppoe, setPPPoE] = useState(s?.pppoe_enabled ?? false);
  const [user, setUser] = useState(s?.pppoe_username ?? "");
  const [pass, setPass] = useState("");
  const [from, setFrom] = useState(s?.dhcp_from ?? "192.168.10.100");
  const [to, setTo] = useState(s?.dhcp_to ?? "192.168.10.200");
  const [busy, setBusy] = useState(false);

  const wired = (status.readiness?.interfaces ?? []).filter((i) => i.kind === "wired");

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
    <form onSubmit={submit} className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Settings</h3>
        <span className={`text-xs text-safe transition-opacity ${saved ? "opacity-100" : "opacity-0"}`}>
          Saved
        </span>
      </div>
      <p className="mt-1 max-w-prose text-xs text-ink-faint">
        Stored, not applied. Nothing on this screen changes the network — the mode has never run on
        real hardware, and a save button that reconfigured your house on that basis would be the
        most expensive mistake in this project.
      </p>

      <div className="mt-3 flex flex-wrap gap-3">
        <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          Port facing the modem
          <select
            value={wan}
            onChange={(e) => setWAN(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          >
            <option value="">not chosen</option>
            {wired.map((i) => (
              <option key={i.name} value={i.name}>{i.name}</option>
            ))}
          </select>
        </label>

        <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
          Port facing the house
          <select
            value={lan}
            onChange={(e) => setLAN(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          >
            <option value="">not chosen</option>
            {wired.map((i) => (
              <option key={i.name} value={i.name}>{i.name}</option>
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
          This machine dials the connection itself (PPPoE)
        </label>
        <p className="mt-1.5 max-w-prose text-xs text-ink-muted">
          Only if your modem is put into bridge mode. Then the internet connection terminates here
          and this machine needs the username and password your provider gave you — the same ones
          in the modem now.
        </p>
        <p className="mt-1.5 max-w-prose text-xs text-ink-faint">
          Leave it off to keep the modem dialling. This machine then sits behind it and does its own
          address translation: no provider credentials, one more layer of translation, and one less
          thing to get wrong.
        </p>

        {pppoe && (
          <div className="mt-3 flex flex-wrap gap-3">
            <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
              Provider username
              <input
                value={user}
                onChange={(e) => setUser(e.target.value)}
                autoComplete="off"
                className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
              />
            </label>
            <label className="min-w-[12rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
              Provider password
              <input
                type="password"
                value={pass}
                onChange={(e) => setPass(e.target.value)}
                placeholder="leave empty to keep the stored one"
                autoComplete="off"
                className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
              />
            </label>
          </div>
        )}
      </div>

      <div className="mt-4 flex flex-wrap gap-3">
        <label className="w-44 text-xs font-medium tracking-wide text-ink-muted uppercase">
          Hand out addresses from
          <input
            value={from}
            onChange={(e) => setFrom(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          />
        </label>
        <label className="w-44 text-xs font-medium tracking-wide text-ink-muted uppercase">
          to
          <input
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          />
        </label>
      </div>
      <p className="mt-1.5 max-w-prose text-xs text-ink-faint">
        Whatever is the gateway has to hand out addresses, and your Deco stops doing it once it is
        put into access point mode. This range must not overlap the one it uses now.
      </p>

      <button
        type="submit"
        disabled={busy}
        className="mt-4 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
      >
        {busy ? "…" : "Save for later"}
      </button>
    </form>
  );
}
