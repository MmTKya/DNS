import { useMemo, useState } from "react";
import { CopyButton } from "./Copy";
import { useLang } from "../i18n/context";

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
  const { t } = useLang();
  const [peerHost, setPeerHost] = useState("");
  const [role, setRole] = useState<"primary" | "replica">("primary");
  const [token, setToken] = useState(() => generateToken());
  const [regenerated, setRegenerated] = useState(false);

  const thisNode = window.location.origin;
  const peer = normaliseHost(peerHost);

  const thisConfig = useMemo(
    () => configBlock(role, token, peer || "http://OTHER-NODE:8080"),
    [role, token, peer],
  );
  const peerConfig = useMemo(
    () =>
      configBlock(role === "primary" ? "replica" : "primary", token, thisNode),
    [role, token, thisNode],
  );

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-5">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-medium text-ink">
              {t("pairing.title")}
            </h3>
            <p className="mt-1 max-w-prose text-xs text-ink-muted">
              {t("pairing.detail")}
            </p>
          </div>
          <button
            onClick={onClose}
            className="text-xs text-ink-faint transition-colors hover:text-ink"
          >
            {t("pairing.close")}
          </button>
        </div>

        <div className="mt-4 flex flex-wrap items-end gap-3">
          <label className="min-w-[16rem] flex-1 text-xs font-medium tracking-wide text-ink-muted uppercase">
            {t("pairing.peerAddress")}
            <input
              value={peerHost}
              onChange={(e) => setPeerHost(e.target.value)}
              placeholder="192.168.1.11:8080"
              className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
            />
          </label>

          <label className="text-xs font-medium tracking-wide text-ink-muted uppercase">
            {t("pairing.thisNodeIs")}
            <select
              value={role}
              onChange={(e) => setRole(e.target.value as "primary" | "replica")}
              className="mt-1.5 w-36 rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink focus:border-accent-dim focus:outline-none"
            >
              <option value="primary">{t("pairing.thePrimary")}</option>
              <option value="replica">{t("pairing.theReplica")}</option>
            </select>
          </label>
        </div>

        {/* The token gets a line of its own.
            It used to exist only inside the two configuration blocks further
            down, so pressing "new token" changed something nobody was looking
            at and the button read as broken. A control has to show its own
            effect where the hand that pressed it is looking. */}
        <div className="mt-3">
          <span className="text-xs font-medium tracking-wide text-ink-muted uppercase">
            {t("pairing.sharedSecret")}
          </span>
          <div className="mt-1.5 flex flex-wrap items-center gap-2">
            <code className="min-w-0 flex-1 overflow-x-auto rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-xs break-all text-ink">
              {token || t("pairing.couldNotGenerate")}
            </code>
            <CopyButton value={token} />
            <button
              onClick={() => {
                setToken(generateToken());
                setRegenerated(true);
                window.setTimeout(() => setRegenerated(false), 1500);
              }}
              className="rounded-md border border-base-700 px-3 py-2 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
            >
              {regenerated ? t("pairing.newOneBelow") : t("pairing.newToken")}
            </button>
          </div>
          {!token && (
            <p className="mt-1.5 max-w-prose text-xs text-warn">
              {t("pairing.noRandomBytes")}{" "}
              <code className="font-mono">openssl rand -hex 32</code>{" "}
              {t("pairing.noRandomBytesSuffix")}
            </p>
          )}

          <p className="mt-1.5 max-w-prose text-xs text-ink-faint">
            {t("pairing.sameValue")}
          </p>
        </div>

        <p className="mt-2 max-w-prose text-xs text-ink-faint">
          {t("pairing.editOnPrimary")}
        </p>
      </div>

      <ConfigCard
        title={t("pairing.onThisNode", { host: new URL(thisNode).host })}
        note={peer ? t("pairing.pasteRestart") : t("pairing.fillOtherAddress")}
        body={thisConfig}
      />

      <ConfigCard
        title={
          peer
            ? t("pairing.onOtherNodeWithHost", { host: new URL(peer).host })
            : t("pairing.onOtherNode")
        }
        note={t("pairing.sameFileNote")}
        body={peerConfig}
      />

      <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
        <h4 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {t("pairing.then")}
        </h4>
        <ol className="mt-2 space-y-1.5 text-xs text-ink-muted">
          <li>
            <span className="text-ink">1.</span> {t("pairing.step1")}
          </li>
          <li>
            <span className="text-ink">2.</span> {t("pairing.step2")}
          </li>
          <li>
            <span className="text-ink">3.</span> {t("pairing.step3")}
          </li>
        </ol>
      </div>
    </div>
  );
}

function ConfigCard({
  title,
  note,
  body,
}: {
  title: string;
  note: string;
  body: string;
}) {
  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h4 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          {title}
        </h4>
        <CopyButton
          value={body}
          className="rounded-md border border-base-700 px-2.5 py-1 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
        />
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
  // Checked rather than assumed: a button that throws is a button that
  // silently does nothing, which is exactly how this screen looked before.
  //
  // And when it is missing, this returns nothing rather than falling back to
  // Math.random. That fallback is tempting and wrong: this value is the only
  // thing between the replication port and a configuration that switches
  // filtering off, and a predictable secret protecting it is worse than an
  // empty box that says so, because it looks protected.
  if (typeof crypto === "undefined" || !crypto.getRandomValues) return "";

  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);

  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** Accepts "192.168.1.11", "192.168.1.11:8080" or a full URL. */
function normaliseHost(input: string): string {
  const trimmed = input.trim();
  if (!trimmed) return "";

  const withScheme = /^https?:\/\//.test(trimmed)
    ? trimmed
    : `http://${trimmed}`;

  try {
    const url = new URL(withScheme);
    if (!url.port && !/^https:/.test(withScheme)) url.port = "8080";

    return url.origin;
  } catch {
    return "";
  }
}
