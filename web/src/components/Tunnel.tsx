import { useCallback, useEffect, useState } from "react";
import { api, formatBytes, type NewPeer, type Peer, type PeerList } from "../api";
import { Notice, Toggle } from "./Panels";
import { RemoteAccessPanel } from "./RemoteAccess";

/**
 * The tunnel: devices that carry the household's filtering with them.
 *
 * The screen is built around one moment — enrolling a device — because that is
 * the only time the private key exists. Everything else here is maintenance.
 */
export function TunnelPanel() {
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
  if (!data) return <Notice>Loading…</Notice>;

  const peers = data.peers ?? [];

  return (
    <div className="space-y-5">
      {error && <Notice tone="threat">{error}</Notice>}

      {!data.enabled ? (
        <Notice tone="warn">
          The tunnel is switched off. Set <span className="font-mono">vpn.enabled</span> and an endpoint your
          devices can dial in the configuration file, then reload the node.
        </Notice>
      ) : (
        !data.available && (
          <Notice tone="warn">
            The tunnel is enabled but its network interface does not exist yet. Bring it up with wg-quick or
            systemd-networkd and restart — until then peers can be enrolled but nothing will connect.
          </Notice>
        )
      )}

      {created && <EnrolmentCard created={created} onDismiss={() => setCreated(null)} />}

      {data.enabled && (
        <form onSubmit={add} className="flex flex-wrap items-end gap-3">
          <label className="flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
            Add a device
            <input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Kids phone"
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
            route all traffic
          </label>

          <button
            type="submit"
            disabled={busy}
            className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-50"
          >
            {busy ? "…" : "Create"}
          </button>
        </form>
      )}

      <p className="text-xs text-ink-faint">
        Leaving “route all traffic” off sends only DNS and your home network through the tunnel: the device keeps
        its own path to the internet and still resolves here. Turning it on routes everything through the house.
      </p>

      <div className="grid gap-3">
        {peers.length === 0 ? (
          <div className="rounded-xl border border-base-700/70 bg-base-850/40 px-4 py-10 text-center">
            <p className="text-sm text-ink">No devices enrolled.</p>
            <p className="mt-1 text-xs text-ink-faint">
              A device added here resolves through this node wherever it is, so the filtering does not stop at
              the front door.
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
  const online = peer.last_handshake && Date.now() - new Date(peer.last_handshake).getTime() < 180_000;

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4 backdrop-blur-sm">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span
              className={`size-2 rounded-full ${online ? "bg-safe pulse-dot" : "bg-base-600"}`}
              aria-label={online ? "connected" : "idle"}
            />
            <span className="text-sm text-ink">{peer.name}</span>
            <span className="font-mono text-xs text-ink-faint">{peer.address}</span>
          </div>

          <div className="mt-2 flex flex-wrap gap-3 font-mono text-[0.7rem] text-ink-faint">
            <span>
              {peer.last_handshake
                ? `last handshake ${new Date(peer.last_handshake).toLocaleString()}`
                : "never connected"}
            </span>
            {(peer.rx_bytes > 0 || peer.tx_bytes > 0) && (
              <span>
                ↓ {formatBytes(peer.rx_bytes)} · ↑ {formatBytes(peer.tx_bytes)}
              </span>
            )}
            {peer.has_preshared_key && <span className="text-ink-muted">preshared key</span>}
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-3">
          <Toggle on={peer.enabled} onChange={onToggle} />
          <button
            onClick={() => void onDelete()}
            className="text-xs text-ink-faint transition-colors hover:text-threat"
          >
            remove
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
function EnrolmentCard({ created, onDismiss }: { created: NewPeer; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);

  return (
    <div className="rounded-xl border border-accent-dim/60 bg-accent/5 p-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h3 className="text-sm font-medium text-ink">{created.peer.name} is ready</h3>
          <p className="mt-1 max-w-prose text-xs text-warn">
            Scan this now. The private key was generated for this device and is not kept on the node — close
            this and the only way to enrol it is to create the device again.
          </p>
        </div>
        <button onClick={onDismiss} className="text-xs text-ink-faint transition-colors hover:text-ink">
          done
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

          <button
            onClick={() => {
              void navigator.clipboard?.writeText(created.config);
              setCopied(true);
              window.setTimeout(() => setCopied(false), 2000);
            }}
            className="mt-2 rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
          >
            {copied ? "Copied" : "Copy configuration"}
          </button>
        </div>
      </div>
    </div>
  );
}
