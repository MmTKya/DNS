import { useMemo, useState } from "react";

/**
 * Setting up the second node.
 *
 * The panel cannot write the configuration file, and should not: it carries
 * the listen addresses, and a node that rewrote them on the strength of a
 * form on another machine could put itself off the network with no way back
 * except a keyboard. So this screen does the part a person should not have to
 * do by hand — generating a shared secret and working out which node needs
 * which lines — and hands over two blocks to paste.
 *
 * Both nodes get the same token. That token is the only thing standing between
 * the replication port and a configuration that turns filtering off, so it is
 * generated here rather than left to whatever someone would have typed.
 */
export function PairingGuide({ onClose }: { onClose: () => void }) {
  const [peerHost, setPeerHost] = useState("");
  const [role, setRole] = useState<"primary" | "replica">("primary");
  const [token, setToken] = useState(() => generateToken());

  const thisNode = window.location.origin;
  const peer = normaliseHost(peerHost);

  const thisConfig = useMemo(
    () => configBlock(role, token, peer || "http://OTHER-NODE:8080"),
    [role, token, peer],
  );
  const peerConfig = useMemo(
    () => configBlock(role === "primary" ? "replica" : "primary", token, thisNode),
    [role, token, thisNode],
  );

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-medium text-ink">Pair a second node</h3>
            <p className="mt-1 max-w-prose text-xs text-ink-muted">
              Two nodes, not a quorum. One holds the configuration and the other follows it; if the
              first stops answering for fifteen seconds the second promotes itself. Three machines
              would let you vote, but two cannot — so this is failover, deliberately.
            </p>
          </div>
          <button onClick={onClose} className="text-xs text-ink-faint transition-colors hover:text-ink">
            close
          </button>
        </div>

        <div className="mt-4 flex flex-wrap items-end gap-3">
          <label className="min-w-[16rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
            The other node's panel address
            <input
              value={peerHost}
              onChange={(e) => setPeerHost(e.target.value)}
              placeholder="192.168.1.11:8080"
              className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
            />
          </label>

          <label className="text-xs font-medium tracking-wide text-ink-muted uppercase">
            This node is
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as "primary" | "replica")}
              className="mt-1.5 w-36 rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink focus:border-accent-dim focus:outline-none"
            >
              <option value="primary">the primary</option>
              <option value="replica">the replica</option>
            </select>
          </label>

          <button
            onClick={() => setToken(generateToken())}
            className="rounded-md border border-base-700 px-3 py-2 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
          >
            new token
          </button>
        </div>

        <p className="mt-2 max-w-prose text-xs text-ink-faint">
          Edit configuration on the primary. A replica's own changes are overwritten the next time it
          syncs, which is a confusing way to lose an afternoon's work.
        </p>
      </div>

      <ConfigCard
        title={`On this node (${new URL(thisNode).host})`}
        note={
          peer
            ? "Paste into /etc/seddns/seddns.yaml, then run: systemctl restart seddns"
            : "Fill in the other node's address above to complete this block."
        }
        body={thisConfig}
      />

      <ConfigCard
        title={peer ? `On the other node (${new URL(peer).host})` : "On the other node"}
        note="Same file, same restart. Both nodes need the same token or neither will accept the other's snapshots."
        body={peerConfig}
      />

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h4 className="text-xs font-medium tracking-wide text-ink-muted uppercase">Then</h4>
        <ol className="mt-2 space-y-1.5 text-xs text-ink-muted">
          <li>
            <span className="text-ink">1.</span> Restart both. This screen starts showing the other
            node within a few seconds.
          </li>
          <li>
            <span className="text-ink">2.</span> Hand both addresses out over DHCP, primary first.
            Failover only helps if devices know where to go.
          </li>
          <li>
            <span className="text-ink">3.</span> Never give the router itself as a secondary. Devices
            drift onto it the moment the first is slow, and filtering stops without anything saying
            so.
          </li>
        </ol>
      </div>
    </div>
  );
}

function ConfigCard({ title, note, body }: { title: string; note: string; body: string }) {
  const [copied, setCopied] = useState(false);

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h4 className="text-xs font-medium tracking-wide text-ink-muted uppercase">{title}</h4>
        <button
          onClick={() => {
            void navigator.clipboard?.writeText(body);
            setCopied(true);
            window.setTimeout(() => setCopied(false), 2000);
          }}
          className="rounded-md border border-base-700 px-2.5 py-1 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
        >
          {copied ? "Copied" : "Copy"}
        </button>
      </div>

      <pre className="mt-2 overflow-x-auto rounded-lg border border-base-700/70 bg-base-950/60 p-3 font-mono text-[0.7rem] leading-relaxed text-ink-muted">
        {body}
      </pre>
      <p className="mt-2 text-xs text-ink-faint">{note}</p>
    </div>
  );
}

function configBlock(role: string, token: string, peer: string): string {
  return `cluster:
  enabled: true
  role: ${role}
  token: "${token}"
  peers:
    - "${peer}"`;
}

/**
 * 32 bytes from the browser's CSPRNG.
 *
 * Long enough that guessing it is not a strategy, and generated rather than
 * invited: a token someone thinks up is the one part of this that would
 * otherwise be weak.
 */
function generateToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Accepts "192.168.1.11", "192.168.1.11:8080" or a full URL. */
function normaliseHost(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";

  const withScheme = /^https?:\/\//.test(trimmed) ? trimmed : `http://${trimmed}`;

  try {
    const url = new URL(withScheme);
    if (!url.port && !/^https:/.test(withScheme)) url.port = "8080";

    return url.origin;
  } catch {
    return "";
  }
}
