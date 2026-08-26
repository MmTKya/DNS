import { useCallback, useEffect, useState } from "react";
import { api, type OwnedDomain } from "../api";
import { useLang } from "../i18n/context";

/**
 * Domains the household runs itself.
 *
 * A name in this list never reaches the review queue at all — not shown and
 * not blocked — because a self-hosted server is not an unknown third-party
 * name the node needs an opinion about, and treating it like one is exactly
 * what caused the outages this panel exists to prevent.
 */
export function OwnedDomainsPanel() {
  const { t } = useLang();
  const [domains, setDomains] = useState<OwnedDomain[] | null>(null);
  const [domain, setDomain] = useState("");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);

  const load = useCallback(async () => {
    try {
      setDomains(await api.ownedDomains());
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const add = async () => {
    if (!domain.trim()) return;

    setBusy(true);
    setError(null);
    try {
      await api.addOwnedDomain(domain.trim(), label.trim());
      setDomain("");
      setLabel("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const remove = async (d: string) => {
    setBusy(true);
    setError(null);
    try {
      await api.removeOwnedDomain(d);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded-xl border border-base-700/70 bg-base-850/40 p-4">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center justify-between gap-2 text-left"
      >
        <div>
          <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">
            {t("ownedDomains.title")}
          </h3>
          <p className="mt-1 text-xs text-ink-faint">
            {t("ownedDomains.description")}
          </p>
        </div>
        <span className="shrink-0 font-mono text-xs text-ink-faint">
          {domains?.length ?? 0} {open ? "▲" : "▼"}
        </span>
      </button>

      {open && (
        <div className="mt-3 space-y-3 border-t border-base-700/60 pt-3">
          {error && <p className="text-xs text-threat">{error}</p>}

          {domains === null ? (
            <p className="text-xs text-ink-faint">
              {t("ownedDomains.loading")}
            </p>
          ) : domains.length === 0 ? (
            <p className="text-xs text-ink-faint">{t("ownedDomains.empty")}</p>
          ) : (
            <ul className="space-y-1.5">
              {domains.map((d) => (
                <li
                  key={d.domain}
                  className="flex items-center justify-between gap-2 rounded-md bg-base-900/60 px-3 py-1.5"
                >
                  <div className="min-w-0">
                    <span className="font-mono text-xs text-ink">
                      {d.domain}
                    </span>
                    {d.label && (
                      <span className="ml-2 text-xs text-ink-faint">
                        {d.label}
                      </span>
                    )}
                  </div>
                  <button
                    disabled={busy}
                    onClick={() => void remove(d.domain)}
                    className="shrink-0 text-xs text-ink-faint underline decoration-dotted transition-colors hover:text-threat disabled:opacity-40"
                  >
                    {t("ownedDomains.remove")}
                  </button>
                </li>
              ))}
            </ul>
          )}

          <div className="flex flex-wrap items-end gap-2">
            <label className="flex-1 text-xs text-ink-muted">
              {t("ownedDomains.domainLabel")}
              <input
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder={t("ownedDomains.domainPlaceholder")}
                className="mt-1 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-1.5 font-mono text-xs text-ink focus:border-accent-dim focus:outline-none"
              />
            </label>
            <label className="w-32 text-xs text-ink-muted">
              {t("ownedDomains.labelLabel")}
              <input
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder={t("ownedDomains.labelPlaceholder")}
                className="mt-1 w-full rounded-md border border-base-700 bg-base-900/80 px-3 py-1.5 text-xs text-ink focus:border-accent-dim focus:outline-none"
              />
            </label>
            <button
              disabled={busy || !domain.trim()}
              onClick={() => void add()}
              className="rounded-md border border-base-700 px-3 py-1.5 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent disabled:opacity-40"
            >
              {t("ownedDomains.add")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
