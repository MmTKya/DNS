import { useCallback, useEffect, useState } from "react";
import {
  api,
  formatBytes,
  type NewPeer,
  type Peer,
  type PeerList,
} from "../api";
import { CopyButton } from "./Copy";
import { Notice, Toggle } from "./Panels";
import { RemoteAccessPanel } from "./RemoteAccess";
import { useLang } from "../i18n/context";

/**
 * The tunnel: devices that carry the household's filtering with them.
 *
 * The screen is built around one moment — enrolling a device — because that is
 * the only time the private key exists. Everything else here is maintenance.
 */
export function TunnelPanel() {
  const { t } = useLang();
  const [data, setData] = useState<PeerList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [fullTunnel, setFullTunnel] = useState(false);
  const [busy, setBusy] = useState(false);
  const [created, setCreated] = useState<NewPeer | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await api.vpnPeers());
    } catch (err) {
      setError(String(err));
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 20_000);

    return () => window.clearInterval(timer);
  }, [load]);

  const add = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      setCreated(await api.addPeer(name, fullTunnel));
      setName("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (error && !data) return <Notice tone="threat">{error}</Notice>;
  if (!data) return <Notice>{t("common.loading")}</Notice>;

  const peers = data.peers ?? [];

  return (
    <div className="space-y-5">
      {error && <Notice tone="threat">{error}</Notice>}

      {!data.enabled ? (
        <Notice tone="warn">
          {t("tunnel.disabled")} <span className="font-mono">vpn.enabled</span>{" "}
          {t("tunnel.disabledSuffix")}
        </Notice>
      ) : (
        !data.available && (
          <Notice tone="warn">{t("tunnel.notAvailable")}</Notice>
        )
      )}

      {created && (
        <EnrolmentCard created={created} onDismiss={() => setCreated(null)} />
      )}

      {data.enabled && (
        <form onSubmit={add} className="flex flex-wrap items-end gap-3">
          <label className="flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
            {t("tunnel.addDevice")}
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={t("tunnel.addDevicePlaceholder")}
              required
              className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
            />
          </label>

          <label className="flex items-center gap-2 pb-2.5 text-xs text-ink-muted">
            <input
              type="checkbox"
              checked={fullTunnel}
              onChange={(e) => setFullTunnel(e.target.checked)}
              className="accent-[var(--color-accent)]"
            />
            {t("tunnel.routeAll")}
          </label>

          <button
            type="submit"
            disabled={busy}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-50"
          >
            {busy ? "…" : t("tunnel.create")}
          </button>
        </form>
      )}

      <p className="text-xs text-ink-faint">{t("tunnel.routeAllHint")}</p>

      <div className="grid gap-3">
        {peers.length === 0 ? (
          <div className="rounded-xl border border-base-700/70 bg-base-850/40 px-4 py-10 text-center">
            <p className="text-sm text-ink">{t("tunnel.noneEnrolled")}</p>
            <p className="mt-1 text-xs text-ink-faint">
              {t("tunnel.noneEnrolledDetail")}
            </p>
          </div>
        ) : (
          peers.map((peer) => (
            <PeerCard
              key={peer.id}
              peer={peer}
              onToggle={async (on) => {
                await api.setPeerEnabled(peer.id, on);
                await load();
              }}
              onDelete={async () => {
                await api.deletePeer(peer.id);
                await load();
              }}
            />
          ))
        )}
      </div>

      <RemoteAccessPanel />
    </div>
  );
}

function PeerCard({
  peer,
  onToggle,
  onDelete,
}: {
  peer: Peer;
  onToggle: (on: boolean) => void | Promise<void>;
  onDelete: () => void | Promise<void>;
}) {
  const { t } = useLang();
  const online =
    peer.last_handshake &&
    Date.now() - new Date(peer.last_handshake).getTime() < 180_000;

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4 backdrop-blur-sm">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={`size-2 rounded-full ${online ? "bg-safe pulse-dot" : "bg-base-600"}`}
              aria-label={online ? t("tunnel.connected") : t("tunnel.idle")}
            />
            <span className="text-sm text-ink">{peer.name}</span>
            <span className="font-mono text-xs text-ink-faint">
              {peer.address}
            </span>
          </div>

          <div className="mt-2 flex flex-wrap gap-3 font-mono text-[0.7rem] text-ink-faint">
            <span>
              {peer.last_handshake
                ? t("tunnel.lastHandshake", {
                    when: new Date(peer.last_handshake).toLocaleString(),
                  })
                : t("tunnel.neverConnected")}
            </span>
            {(peer.rx_bytes > 0 || peer.tx_bytes > 0) && (
              <span>
                ↓ {formatBytes(peer.rx_bytes)} · ↑ {formatBytes(peer.tx_bytes)}
              </span>
            )}
            {peer.has_preshared_key && (
              <span className="text-ink-muted">{t("tunnel.presharedKey")}</span>
            )}
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-3">
          <Toggle on={peer.enabled} onChange={onToggle} />
          <button
            onClick={() => void onDelete()}
            className="text-xs text-ink-faint transition-colors hover:text-threat"
          >
            {t("tunnel.remove")}
          </button>
        </div>
      </div>
    </div>
  );
}

/**
 * Shown once, immediately after enrolment.
 *
 * The private key in this configuration was generated for the device and is
 * not stored on the node, so this panel is the only chance to capture it —
 * which the copy says plainly rather than leaving someone to discover it.
 */
function EnrolmentCard({
  created,
  onDismiss,
}: {
  created: NewPeer;
  onDismiss: () => void;
}) {
  const { t } = useLang();

  return (
    <div className="rounded-xl border border-accent-dim/60 bg-accent/5 p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h3 className="text-sm font-medium text-ink">
            {t("tunnel.readyTitle", { name: created.peer.name })}
          </h3>
          <p className="mt-1 max-w-prose text-xs text-warn">
            {t("tunnel.scanNow")}
          </p>
        </div>
        <button
          onClick={onDismiss}
          className="text-xs text-ink-faint transition-colors hover:text-ink"
        >
          {t("tunnel.done")}
        </button>
      </div>

      <div className="mt-4 flex flex-wrap gap-5">
        {created.qr_png && (
          <img
            src={`data:image/png;base64,${created.qr_png}`}
            alt="WireGuard enrolment QR code"
            className="size-[210px] shrink-0 rounded-lg bg-white p-2"
          />
        )}

        <div className="min-w-[18rem] flex-1">
          <pre className="max-h-[210px] overflow-auto rounded-lg border border-base-700 bg-base-950/60 p-3 font-mono text-[0.7rem] leading-relaxed text-ink-muted">
            {created.config}
          </pre>

          <CopyButton
            value={created.config}
            label={t("tunnel.copyConfiguration")}
            className="mt-2 rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
          />
        </div>
      </div>
    </div>
  );
}
