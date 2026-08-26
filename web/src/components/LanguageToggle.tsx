import { useLang, type Lang } from "../i18n/context";

/**
 * The two-language switch, kept as small as the sign-out button beside it —
 * this is a preference someone sets once and forgets, not a feature to make
 * room for.
 */
export function LanguageToggle() {
  const { lang, setLang, t } = useLang();

  const other: Lang = lang === "en" ? "tr" : "en";

  return (
    <button
      onClick={() => setLang(other)}
      title={t("language.label")}
      className="flex items-center gap-1 rounded-md border border-base-700 px-2 py-1 font-mono text-[0.65rem] text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
    >
      <span className={lang === "en" ? "text-accent" : undefined}>EN</span>
      <span className="text-ink-faint">/</span>
      <span className={lang === "tr" ? "text-accent" : undefined}>TR</span>
    </button>
  );
}
