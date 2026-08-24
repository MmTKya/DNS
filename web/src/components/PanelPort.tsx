import { useCallback, useEffect, useState } from "react";
import { api, type PanelPort } from "../api";
import { Notice } from "./Panels";

/**
 * Moving the panel to a different port.
 *
 * This is the one setting that can destroy the thing editing it. Type the
 * wrong number and the way back is a keyboard attached to the machine, which
 * for a box in a cupboard means taking it out of the cupboard.
 *
 * So it happens in two halves. Pressing the button opens the new port and
 * changes nothing else — the panel you are looking at keeps working and
 * nothing is written down. Then you open the new address yourself and confirm
 * there. That confirmation is the only evidence that counts, because it is the
 * only thing that proves the new port is reachable from where you actually
 * are. Walk away and in two minutes it is as though you never pressed it.
 */
export function PanelPortPanel() {
  const [state, setState] = useState<PanelPort | null>(null);
  const [port, setPort] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const next = await api.panelPort();
      setState(next);
      setPort((current) => current || String(next.pending_port ?? next.port));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => void load(), 5000);

    return () => window.clearInterval(timer);
  }, [load]);

  const move = async () => {
    setError(null);
    setBusy(true);

    try {
      setState(await api.movePanelPort(Number(port)));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const cancel = async () => {
    setError(null);
    setBusy(true);

    try {
      await api.cancelPanelPort();
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!state) return <Notice>Loading…</Notice>;

  const pending = state.pending_port !== undefined;

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          Where this panel listens
        </h3>
        <span className="font-mono text-xs text-ink">port {state.port}</span>
      </div>

      <p className="mt-1 max-w-prose text-xs text-ink-muted">
        Worth changing when something else on this machine wants the same port.
        Port 53, which is what devices actually ask for names on, is not
        affected.
      </p>

      {pending ? (
        <div className="mt-3 rounded-lg border border-warn/50 bg-warn/10 p-3">
          <p className="text-sm text-warn">
            Port {state.pending_port} is open. Nothing has been saved yet.
          </p>
          <p className="mt-1.5 max-w-prose text-xs text-ink-muted">
            Open the address below and confirm from there. It has to be
            confirmed on the new port — that is what proves the port works from
            where you are sitting, which is the one thing this node cannot check
            for you.
          </p>

          <a
            href={state.confirm_url}
            target="_blank"
            rel="noreferrer noopener"
            className="mt-2 inline-block rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90"
          >
            Open {state.confirm_url}
          </a>

          <p className="mt-2 text-xs text-ink-faint">
            Do nothing and the port closes on its own
            {state.confirm_by
              ? ` at ${new Date(state.confirm_by).toLocaleTimeString()}`
              : " shortly"}
            , leaving the panel exactly where it is now.
          </p>

          <button
            onClick={() => void cancel()}
            disabled={busy}
            className="mt-2 text-xs text-ink-faint underline transition-colors hover:text-ink disabled:opacity-40"
          >
            cancel now
          </button>
        </div>
      ) : (
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <label className="w-40 text-xs font-medium tracking-wide text-ink-muted uppercase">
            Move to port
            <input
              value={port}
              onChange={(e) => setPort(e.target.value.replace(/[^0-9]/g, ""))}
              inputMode="numeric"
              className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
            />
          </label>

          <button
            onClick={() => void move()}
            disabled={busy || !port || Number(port) === state.port}
            className="rounded-md border border-base-700 px-4 py-2 text-sm text-ink-muted transition-colors hover:border-accent-dim hover:text-accent disabled:opacity-40"
          >
            {busy ? "…" : "Open that port"}
          </button>

          <p className="w-full max-w-prose text-xs text-ink-faint">
            1024 or above. Lower ports need a privilege this node deliberately
            does not hold — it is the part exposed to the network, and the one
            exception it already has is for port 53.
          </p>
        </div>
      )}

      {error && <p className="mt-3 text-xs text-threat">{error}</p>}
    </div>
  );
}

/**
 * The confirmation, shown on the new port.
 *
 * Deliberately its own thing rather than a state of the panel above: whoever
 * sees this arrived here by opening the new address, and that arrival is the
 * evidence. Pressing the button just records what already happened.
 */
export function ConfirmPortBanner() {
  const [state, setState] = useState<PanelPort | null>(null);
  const [done, setDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void api
      .panelPort()
      .then(setState)
      .catch(() => undefined);
  }, []);

  if (done) {
    return (
      <div className="rounded-xl border border-safe/50 bg-safe/10 px-4 py-3 text-sm text-safe">
        Saved. The panel will be here after a restart too.
      </div>
    );
  }

  // Only when a move is waiting and this page is the new port.
  if (
    !state?.pending_port ||
    String(state.pending_port) !== window.location.port
  )
    return null;

  const confirm = async () => {
    try {
      await fetch("/api/panel/port/confirm", {
        method: "POST",
        credentials: "same-origin",
      }).then((r) => {
        if (!r.ok) throw new Error("could not confirm");
      });
      setDone(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <div className="rounded-xl border border-safe/50 bg-safe/10 p-4">
      <h3 className="text-sm font-medium text-safe">
        You reached the panel on port {state.pending_port}
      </h3>
      <p className="mt-1 max-w-prose text-xs text-ink-muted">
        That is the proof. Confirm and this becomes the port the panel uses from
        now on, including after a restart. Do nothing and it goes back to where
        it was.
      </p>

      <button
        onClick={() => void confirm()}
        className="mt-3 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90"
      >
        Keep this port
      </button>

      {error && <p className="mt-2 text-xs text-threat">{error}</p>}
    </div>
  );
}
