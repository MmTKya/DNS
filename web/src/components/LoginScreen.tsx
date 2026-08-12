import { useState } from "react";
import { api, ApiError } from "../api";

/**
 * The first screen anyone sees.
 *
 * A node with no administrator hands the keys to whoever arrives first, so the
 * setup form says as much rather than presenting itself as a routine sign-up.
 */
export function LoginScreen({ needsSetup, onDone }: { needsSetup: boolean; onDone: () => void }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [needsCode, setNeedsCode] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      if (needsSetup) {
        await api.setup(username, password);
      } else {
        const result = await api.login(username, password, code || undefined);
        if (result?.totp_required) {
          setNeedsCode(true);
          setBusy(false);

          return;
        }
      }
      onDone();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
      setBusy(false);
    }
  };

  return (
    <div className="grid min-h-full place-items-center px-6">
      <form
        onSubmit={submit}
        className="w-full max-w-sm rounded-xl border border-base-700/70 bg-base-850/60 p-6 backdrop-blur-sm"
      >
        <h1 className="text-lg font-semibold tracking-tight text-ink">
          Aegis<span className="text-accent">DNS</span>
        </h1>

        <p className="mt-1 mb-6 text-sm text-ink-muted">
          {needsSetup
            ? "This node has no administrator yet. Whoever creates one holds the keys — do it now, before anything else can reach the panel."
            : "Sign in to manage this node."}
        </p>

        <label className="block text-xs font-medium tracking-wide text-ink-muted uppercase">
          Username
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          />
        </label>

        <label className="mt-4 block text-xs font-medium tracking-wide text-ink-muted uppercase">
          Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete={needsSetup ? "new-password" : "current-password"}
            required
            minLength={needsSetup ? 12 : undefined}
            className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm text-ink focus:border-accent-dim focus:outline-none"
          />
        </label>
        {needsSetup && (
          <p className="mt-1.5 text-xs text-ink-faint">At least 12 characters. A passphrase is fine.</p>
        )}

        {needsCode && (
          <label className="mt-4 block text-xs font-medium tracking-wide text-ink-muted uppercase">
            Two-factor code
            <input
              value={code}
              onChange={(e) => setCode(e.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              autoFocus
              className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 font-mono text-sm tracking-[0.3em] text-ink focus:border-accent-dim focus:outline-none"
            />
            <span className="mt-1.5 block text-xs font-normal tracking-normal text-ink-faint normal-case">
              A recovery code works here too.
            </span>
          </label>
        )}

        {error && (
          <p className="mt-4 rounded-md border border-threat/40 bg-threat/10 px-3 py-2 text-sm text-ink">{error}</p>
        )}

        <button
          type="submit"
          disabled={busy}
          className="mt-6 w-full rounded-md bg-accent px-3 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-50"
        >
          {busy ? "…" : needsSetup ? "Create administrator" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
