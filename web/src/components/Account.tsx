import { useCallback, useEffect, useState } from "react";
import { api, type Account, type TOTPEnrollment } from "../api";
import { CopyButton } from "./Copy";
import { Notice } from "./Panels";

/**
 * The account: the password, and the second factor in front of it.
 *
 * Both actions here end the session on purpose — changing a password revokes
 * every session including this one, and that is the point. The screen says so
 * before you act rather than dropping you at the login screen unexplained.
 */
export function AccountPanel({ onSignedOut }: { onSignedOut: () => void }) {
  const [account, setAccount] = useState<Account | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setAccount(await api.me());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  if (error && !account) return <Notice tone="threat">{error}</Notice>;
  if (!account) return <Notice>Loading…</Notice>;

  return (
    <div className="space-y-5">
      <div className="rounded-xl border border-base-700/70 bg-base-850/60 p-4">
        <div className="flex flex-wrap items-baseline justify-between gap-3">
          <div>
            <span className="text-sm text-ink">{account.username}</span>
            <span className="ml-2 rounded-full border border-base-600 px-2 py-0.5 text-[0.65rem] text-ink-faint">
              {account.role}
            </span>
          </div>
          <span className="font-mono text-[0.7rem] text-ink-faint">
            {account.last_login_at
              ? `last signed in ${new Date(account.last_login_at).toLocaleString()}`
              : "first session"}
          </span>
        </div>
      </div>

      <PasswordSection onDone={onSignedOut} />
      <TwoFactorSection account={account} onChanged={load} />
    </div>
  );
}

function PasswordSection({ onDone }: { onDone: () => void }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const tooShort = next.length > 0 && next.length < 12;
  const mismatch = again.length > 0 && next !== again;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setError(null);
    setBusy(true);

    try {
      await api.changePassword(current, next);
      // Every session was revoked server-side, including this one. Going
      // straight to the login screen is the honest end to this action.
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setBusy(false);
    }
  };

  return (
    <form
      onSubmit={submit}
      className="rounded-xl border border-base-700/70 bg-base-850/40 p-4"
    >
      <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
        Password
      </h3>
      <p className="mt-1 max-w-prose text-xs text-ink-faint">
        Changing it signs out every browser and device, including this one — so
        a stolen session cannot outlive the password it came from. You will be
        asked to sign in again.
      </p>

      <div className="mt-3 grid gap-3 sm:grid-cols-3">
        <Field label="Current password" value={current} onChange={setCurrent} />
        <Field
          label="New password"
          value={next}
          onChange={setNext}
          hint="at least 12 characters"
        />
        <Field label="Repeat new password" value={again} onChange={setAgain} />
      </div>

      {tooShort && (
        <p className="mt-2 text-xs text-warn">
          A password needs at least 12 characters.
        </p>
      )}
      {mismatch && (
        <p className="mt-2 text-xs text-warn">
          The two new passwords do not match.
        </p>
      )}
      {error && <p className="mt-2 text-xs text-threat">{error}</p>}

      <button
        type="submit"
        disabled={busy || !current || next.length < 12 || next !== again}
        className="mt-3 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
      >
        {busy ? "…" : "Change password and sign out"}
      </button>
    </form>
  );
}

function TwoFactorSection({
  account,
  onChanged,
}: {
  account: Account;
  onChanged: () => void | Promise<void>;
}) {
  const [enrolment, setEnrolment] = useState<TOTPEnrollment | null>(null);
  const [code, setCode] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = async (action: () => Promise<void>) => {
    setError(null);
    setBusy(true);

    try {
      await action();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (codes) {
    return (
      <div className="rounded-xl border border-accent-dim/60 bg-accent/5 p-4">
        <h3 className="text-sm font-medium text-ink">
          Two-factor is on. Save these now.
        </h3>
        <p className="mt-1 max-w-prose text-xs text-warn">
          Each code signs you in once if you lose the authenticator. They are
          shown here and nowhere else — the node stores only their hashes, so no
          one, including this panel, can show them to you again.
        </p>

        <div className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 font-mono text-sm text-ink sm:grid-cols-3">
          {codes.map((c) => (
            <span key={c}>{c}</span>
          ))}
        </div>

        <CopyButton
          value={codes.join("\n")}
          label="Copy codes"
          className="mt-3 rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
        />
        <button
          onClick={() => {
            setCodes(null);
            void onChanged();
          }}
          className="mt-3 ml-2 rounded-md px-3 py-1.5 text-xs text-ink-faint transition-colors hover:text-ink"
        >
          I have saved them
        </button>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
          Two-factor
        </h3>
        <span
          className={`text-xs ${account.totp_enabled ? "text-safe" : "text-ink-faint"}`}
        >
          {account.totp_enabled
            ? `on · ${account.recovery_codes_left} recovery codes left`
            : "off"}
        </span>
      </div>

      {account.totp_enabled ? (
        <>
          <p className="mt-1 max-w-prose text-xs text-ink-faint">
            Turning it off needs your password, so someone holding an open
            session cannot quietly remove it.
          </p>
          <div className="mt-3 flex flex-wrap items-end gap-3">
            <Field label="Password" value={password} onChange={setPassword} />
            <button
              disabled={busy || !password}
              onClick={() =>
                void run(async () => {
                  await api.totpDisable(password);
                  setPassword("");
                  await onChanged();
                })
              }
              className="rounded-md border border-base-700 px-3 py-2 text-sm text-ink-muted transition-colors hover:border-threat hover:text-threat disabled:opacity-40"
            >
              Turn off
            </button>
          </div>
        </>
      ) : enrolment ? (
        <>
          <p className="mt-1 max-w-prose text-xs text-ink-faint">
            Add this to your authenticator, then type the six digits it shows.
            Two-factor only turns on once a code proves the secret arrived
            intact.
          </p>
          <p className="mt-3 font-mono text-xs break-all text-ink-muted">
            {enrolment.secret}
          </p>

          <div className="mt-3 flex flex-wrap items-end gap-3">
            <Field
              label="Code from the app"
              value={code}
              onChange={setCode}
              type="text"
            />
            <button
              disabled={busy || code.length < 6}
              onClick={() =>
                void run(async () => {
                  const result = await api.totpConfirm(code);
                  setCode("");
                  setEnrolment(null);
                  setCodes(result.recovery_codes);
                })
              }
              className="rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
            >
              Confirm
            </button>
            <button
              onClick={() => setEnrolment(null)}
              className="pb-2 text-xs text-ink-faint transition-colors hover:text-ink"
            >
              cancel
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="mt-1 max-w-prose text-xs text-ink-faint">
            A second factor matters most here: this panel can redirect every
            name your household resolves, so a guessed password should not be
            the only thing in the way.
          </p>
          <button
            disabled={busy}
            onClick={() =>
              void run(async () => setEnrolment(await api.totpBegin()))
            }
            className="mt-3 rounded-md bg-accent px-4 py-2 text-sm font-medium text-base-950 transition-colors hover:bg-accent/90 disabled:opacity-40"
          >
            Set up two-factor
          </button>
        </>
      )}

      {error && <p className="mt-2 text-xs text-threat">{error}</p>}
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  hint,
  type = "password",
}: {
  label: string;
  value: string;
  onChange: (v: string) => void;
  hint?: string;
  type?: string;
}) {
  return (
    <label className="text-xs font-medium tracking-wide text-ink-muted uppercase">
      {label}
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={type === "password" ? "off" : "one-time-code"}
        className="mt-1.5 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-2 text-sm text-ink placeholder:text-ink-faint focus:border-accent-dim focus:outline-none"
      />
      {hint && (
        <span className="mt-1 block text-[0.65rem] normal-case text-ink-faint">
          {hint}
        </span>
      )}
    </label>
  );
}
