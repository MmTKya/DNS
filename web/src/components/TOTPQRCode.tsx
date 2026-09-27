import { useEffect, useState } from "react";
import QRCode from "qrcode";

/**
 * Renders an otpauth:// URI as a scannable QR code, entirely client-side —
 * the URI carries the TOTP secret, so it must never be sent anywhere to be
 * turned into an image.
 */
export function TOTPQRCode({ url }: { url: string }) {
  const [dataUrl, setDataUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    void QRCode.toDataURL(url, { margin: 1, width: 176 }).then((generated) => {
      if (!cancelled) setDataUrl(generated);
    });

    return () => {
      cancelled = true;
    };
  }, [url]);

  if (!dataUrl) {
    return (
      <div className="h-[176px] w-[176px] animate-pulse rounded-md bg-base-800" />
    );
  }

  return (
    <img
      src={dataUrl}
      alt="QR code for the authenticator app"
      className="h-[176px] w-[176px] rounded-md border border-base-700 bg-white p-2"
    />
  );
}
