import { useState } from "react";

/**
 * A copy button that tells the truth about whether it copied.
 *
 * The browser's clipboard API only exists on a secure connection, and this
 * panel is plain HTTP on the local network by design. Every copy button here
 * was written as `navigator.clipboard?.writeText(...)`, which on this setup
 * does nothing at all — no copy, no error, no clue.
 *
 * The worst of them sat under the recovery codes: press it, believe the codes
 * are safe, close the dialog, and lose the only way back into an account
 * locked behind a second factor.
 *
 * So there are three layers. The modern API when it is available; the old
 * selection-based command, which works without a secure connection, when it is
 * not; and when both fail, saying so, because a button that has not copied
 * anything must never look like one that has.
 */
export function CopyButton({
  value,
  className,
  label = "Copy",
}: {
  value: string;
  className?: string;
  label?: string;
}) {
  const [state, setState] = useState<"idle" | "done" | "failed">("idle");

  const copy = async () => {
    const ok = await copyText(value);
    setState(ok ? "done" : "failed");

    // Long enough to read, short enough that the button is ready again before
    // anyone reaches for it a second time.
    window.setTimeout(() => setState("idle"), 2500);
  };

  return (
    <button
      type="button"
      onClick={() => void copy()}
      className={
        className ??
        "rounded-md border border-base-700 px-2.5 py-1 text-xs text-ink-muted transition-colors hover:border-accent-dim hover:text-accent"
      }
      title={
        state === "failed" ? "Select the text and copy it by hand" : undefined
      }
    >
      {state === "done"
        ? "Copied"
        : state === "failed"
          ? "Select it by hand"
          : label}
    </button>
  );
}

/**
 * copyText puts a string on the clipboard, or reports that it could not.
 *
 * The fallback is deprecated and works anyway, which is the whole reason it is
 * here: it predates the secure-context rule and browsers still honour it.
 */
export async function copyText(value: string): Promise<boolean> {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value);

      return true;
    } catch {
      // Permission refused, or the page lost focus. Fall through and try the
      // older route rather than giving up.
    }
  }

  try {
    const field = document.createElement("textarea");
    field.value = value;

    // Off-screen rather than hidden: a field that is not rendered cannot be
    // selected, and selection is what this method copies.
    field.setAttribute("readonly", "");
    field.style.position = "fixed";
    field.style.top = "-1000px";
    field.style.opacity = "0";

    document.body.appendChild(field);
    field.select();
    field.setSelectionRange(0, value.length);

    const copied = document.execCommand("copy");
    document.body.removeChild(field);

    return copied;
  } catch {
    return false;
  }
}
