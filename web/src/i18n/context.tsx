import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { en, type Dictionary } from "./en";
import { tr } from "./tr";

export type Lang = "en" | "tr";

const dictionaries: Record<Lang, Dictionary> = { en, tr };

const STORAGE_KEY = "seddns.lang";

/**
 * A stored choice always wins. Absent one, the browser's own language is a
 * better first guess than defaulting to English for a household that never
 * asked for it — but it is only ever a guess, which is why the toggle exists
 * at all.
 */
function detectDefault(): Lang {
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored === "en" || stored === "tr") return stored;

  return navigator.language.toLowerCase().startsWith("tr") ? "tr" : "en";
}

type Vars = Record<string, string | number>;

interface LanguageContextValue {
  lang: Lang;
  setLang: (lang: Lang) => void;
  t: (path: string, vars?: Vars) => string;
}

const LanguageContext = createContext<LanguageContextValue | null>(null);

function resolve(dict: unknown, path: string): unknown {
  return path
    .split(".")
    .reduce<unknown>(
      (acc, key) =>
        acc && typeof acc === "object"
          ? (acc as Record<string, unknown>)[key]
          : undefined,
      dict,
    );
}

function interpolate(template: string, vars?: Vars): string {
  if (!vars) return template;

  return Object.entries(vars).reduce(
    (text, [key, value]) => text.replaceAll(`{${key}}`, String(value)),
    template,
  );
}

export function LanguageProvider({ children }: { children: ReactNode }) {
  const [lang, setLang] = useState<Lang>(detectDefault);

  useEffect(() => {
    window.localStorage.setItem(STORAGE_KEY, lang);
    document.documentElement.lang = lang;
  }, [lang]);

  const value = useMemo<LanguageContextValue>(
    () => ({
      lang,
      setLang,
      // Falls back to English rather than the raw key: a translation still
      // in progress should read as slightly inconsistent, not broken.
      t: (path, vars) => {
        const found = resolve(dictionaries[lang], path);
        const fallback = resolve(dictionaries.en, path);
        const value = typeof found === "string" ? found : fallback;

        return typeof value === "string"
          ? interpolate(value, vars)
          : `[${path}]`;
      },
    }),
    [lang],
  );

  return (
    <LanguageContext.Provider value={value}>
      {children}
    </LanguageContext.Provider>
  );
}

export function useLang() {
  const ctx = useContext(LanguageContext);
  if (!ctx) {
    throw new Error("useLang must be used inside a LanguageProvider");
  }

  return ctx;
}
