import { useCallback, useEffect, useState } from "react";
import { api, type TunnelStatus } from "../api";
import { Notice } from "./Panels";

/**
 * Reaching the panel from outside the house.
 *
 * This screen used to be three paragraphs describing three options and
 * configuring none of them. The description was the easy half: what someone
 * actually needs is the fiddly part done for them, and the fiddly part here is
 * a cloudflared configuration file with a catch-all rule it refuses to start
 * without.
 *
 * What the node deliberately does not do is install cloudflared or manage its
 * service. It runs unprivileged, and a resolver that could install system
 * software would be a worse trade than the convenience is worth — so it writes
 * the file and shows the two commands.
 */
export function RemoteAccessPanel() {
  const [status, setStatus] = useState<TunnelStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setStatus(await api.tunnelStatus());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (error && !status) return <Notice tone="threat">{error}</Notice>;
  if (!status) return <Notice>Loading…</Notice>;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          Three ways in, and what each one costs
        </h3>
        <div className="mt-3 grid gap-3">
          {(status.exposures ?? []).map((e) => (
            <div key={e.method} className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
              <span className="font-mono text-xs text-ink">{e.method}</span>
              {e.recommended && (
                <span className="rounded-full border border-safe/50 bg-safe/10 px-2 py-0.5 text-[0.65rem] text-safe">
                  recommended
                </span>
              )}
              {!e.available && (
                <span className="rounded-full border border-base-600 px-2 py-0.5 text-[0.65rem] text-ink-faint">
                  not set up
                </span>
              )}
              <p className="w-full text-xs text-ink-muted">{e.tradeoff}</p>
            </div>
          ))}
        </div>
      </div>

      {error && <Notice tone="threat">{error}</Notice>}

      <Cloudflare status={status} onSaved={load} onError={setError} />

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Port forwarding</h3>
        <p className="mt-1 max-w-prose text-xs text-ink-muted">
          Nothing here can set this up: it is a rule on your router, and this node has no way to
          reach into it. If you do it anyway, forward to{" "}
          <span className="font-mono">{status.cloudflare?.service ?? "this node, port 8080"}</span>{" "}
          and switch on two-factor first — you are putting a box that can redirect every name in
          your house on the public internet, behind one password.
        </p>
      </div>
    </div>
  );
}

function Cloudflare({
  status,
  onSaved,
  onError,
}: {
  status: TunnelStatus;
  onSaved: () => void | Promise<void>;
  onError: (message: string | null) => void;
}) {
  const cf = status.cloudflare;
  const [tunnelID, setTunnelID] = useState(cf?.tunnel_id ?? "");
  const [credentials, setCredentials] = useState(cf?.credentials_file ?? "");
  const [hostname, setHostname] = useState(cf?.hostname ?? "");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ config: string; path: string; writeError?: string } | null>(null);

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    onError(null);
    setBusy(true);

    try {
      const saved = await api.saveCloudflare(tunnelID.trim(), credentials.trim(), hostname.trim());
      setResult({ config: saved.config, path: saved.config_path, writeError: saved.write_error });
      await onSaved();
    } catch (err) {
      onError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const config = result?.config ?? cf?.config ?? "";
  const path = result?.path ?? cf?.config_path ?? "";

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Cloudflare Tunnel</h3>
        <span className="text-xs text-ink-faint">
          {cf?.installed ? cf.version || "cloudflared installed" : "cloudflared is not installed here"}
        </span>
      </div>

      <p className="mt-1 max-w-prose text-xs text-ink-muted">
        No inbound port and your address stays hidden, but Cloudflare terminates TLS and can see the
        panel traffic. Pair it with Cloudflare Access so a password is not the only thing in front of
        your network.
      </p>

      {!cf?.installed && (
        <div className="mt-3 rounded-lg border border-base-700 bg-base-950/60 p-3">
          <p className="text-xs text-ink-muted">Install it first, then create a tunnel:</p>
          <pre className="mt-2 overflow-x-auto font-mono text-[0.7rem] leading-relaxed text-ink-faint">
{`sudo apt install cloudflared
cloudflared tunnel login
cloudflared tunnel create seddns`}
          </pre>
          <p className="mt-2 text-xs text-ink-faint">
            The last command prints the tunnel id and the path of the credentials file. Those are the
            two values below.
          </p>
        </div>
      )}

      <form onSubmit={save} className="mt-3 space-y-3">
        <div className="flex flex-wrap gap-3">
          <label className="min-w-[14rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
            Tunnel id
            <input
              value={tunnelID}
              onChange={(e) => setTunnelID(e.target.value)}
              placeholder="6ff42ae2-765d-4adf-8112-31c55c1551ef"
              required
              className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
            />
          </label>

          <label className="min-w-[14rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
            Public hostname
            <input
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="dns.example.org"
              required
              className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
            />
          </label>
        </div>

        <label className="block text-xs font-medium tracking-wide text-ink-muted uppercase">
          Credentials file
          <input
            value={credentials}
            onChange={(e) => setCredentials(e.target.value)}
            placeholder="/root/.cloudflared/6ff42ae2-….json"
            required
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
          />
        </label>

        <button
          type="submit"
          disabled={busy}
          className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
        >
          {busy ? "…" : "Write the configuration"}
        </button>
      </form>

      {result?.writeError && (
        <p className="mt-3 text-xs text-warn">
          Saved, but the file could not be written: {result.writeError}. Copy it from below instead.
        </p>
      )}

      {config && (
        <div className="mt-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <span className="text-[0.65rem] tracking-wide text-ink-faint uppercase">
              {result && !result.writeError ? `Written to ${path}` : "Configuration"}
            </span>
            <button
              onClick={() => void navigator.clipboard?.writeText(config)}
              className="rounded-md border border-base-700 px-2.5 py-1 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
            >
              Copy
            </button>
          </div>
          <pre className="mt-1.5 overflow-x-auto rounded-lg border border-base-700/70 bg-base-950/60 p-3 font-mono text-[0.7rem] leading-relaxed text-ink-muted">
            {config}
          </pre>

          <p className="mt-3 text-xs text-ink-muted">Then, on this machine:</p>
          <pre className="mt-1.5 overflow-x-auto rounded-lg border border-base-700/70 bg-base-950/60 p-3 font-mono text-[0.7rem] leading-relaxed text-ink-faint">
{`sudo cloudflared --config ${path} service install
sudo systemctl status cloudflared`}
          </pre>
          <p className="mt-2 max-w-prose text-xs text-ink-faint">
            The node writes the file and stops there: it runs unprivileged and installing system
            services is not something a resolver should be able to do.
          </p>
        </div>
      )}
    </div>
  );
}
