import { useEffect, useState } from "react";
import { Button, Input } from "@proxyshard/shardx-ui-kit";
import { useT } from "../../../../shared/i18n";
import { PropertyRow } from "../../../../shared/ui/peek";
import {
  xrayBulkParse, xrayTestLink,
  type XrayImportResult,
} from "../../../../entities/proxy/model/xray";
import type { ProxyTestSnapshot } from "../../../../entities/proxy/model/types";

/// One profile's Xray node, in the profile form's Proxy tab. Nothing is
/// written here: a pasted link is bound only when the form is saved, an
/// unbind likewise, and a bound link is never shown in full — only its
/// masked `scheme://host:port` from the backend. Each profile binds its
/// own link; binding one never touches another profile's.
export function XrayRow({ bound, unbinding, newLink, onNewLink, onUnbind }: {
  /** Masked display of the link already bound to this profile, if any. */
  bound: string | null;
  /** The operator chose to drop the bound link on Save. */
  unbinding: boolean;
  /** A link typed in this form, to bind on Save. */
  newLink: string;
  onNewLink: (link: string) => void;
  onUnbind: (unbind: boolean) => void;
}) {
  const t = useT();
  const [parsing, setParsing] = useState(false);
  const [testing, setTesting] = useState(false);
  const [parsed, setParsed] = useState<XrayImportResult | null>(null);
  const [tested, setTested] = useState<ProxyTestSnapshot | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Donut's proxy form validates a share link as it is typed (300 ms
  // debounce, matched to the link it was validated for, so a stale
  // answer never describes a newer keystroke), and the type shown
  // follows the accepted link. The Parse button stays for an explicit
  // re-check; a link only counts once the backend has accepted it.
  useEffect(() => {
    const link = newLink.trim();
    if (!link) { setParsed(null); setError(null); return; }
    let cancelled = false;
    const timer = window.setTimeout(() => {
      void xrayBulkParse(link)
        .then((rows) => {
          if (cancelled) return;
          const row = rows[0] ?? null;
          setParsed(row);
          setError(row && !row.ok ? row.error : null);
        })
        .catch((e) => { if (!cancelled) setError(String(e)); });
    }, 300);
    return () => { cancelled = true; window.clearTimeout(timer); };
  }, [newLink]);

  const parse = async () => {
    const link = newLink.trim();
    if (!link) return;
    setParsing(true); setError(null); setTested(null);
    try {
      const rows = await xrayBulkParse(link);
      const row = rows[0] ?? null;
      setParsed(row);
      if (row && !row.ok) setError(row.error);
    } catch (e) { setError(String(e)); }
    setParsing(false);
  };

  const test = async () => {
    const link = newLink.trim();
    if (!link) return;
    setTesting(true); setError(null);
    try {
      const snap = await xrayTestLink(link);
      setTested(snap);
      if (snap.geo_error) setError(snap.geo_error);
    } catch (e) { setError(String(e)); }
    setTesting(false);
  };

  return (
    <PropertyRow id="xray" label={t("profileForm.xrayTitle")}>
      {() => (
        <div className="flex w-full flex-col gap-2">
          {bound && !unbinding && !newLink.trim() && (
            <div className="flex items-center gap-2">
              <span className="min-w-0 truncate">{t("profileForm.xrayBound", { masked: bound })}</span>
              <Button variant="neutral" mode="ghost" size="3xsmall" onClick={() => onUnbind(true)}>
                {t("profileForm.xrayUnbind")}
              </Button>
            </div>
          )}
          {bound && unbinding && !newLink.trim() && (
            <div className="flex items-center gap-2">
              <span className="min-w-0 truncate text-secondary">{t("profileForm.xrayUnbinding")}</span>
              <Button variant="neutral" mode="ghost" size="3xsmall" onClick={() => onUnbind(false)}>
                {t("profileForm.xrayKeep")}
              </Button>
            </div>
          )}
          <Input
            inputSize="xsmall"
            className="mono"
            aria-label={t("profileForm.xrayLinkLabel")}
            value={newLink}
            onChange={(e) => { onNewLink(e.target.value); setParsed(null); setTested(null); setError(null); }}
            placeholder="vless://… / vmess://… / trojan://… / ss://… / hysteria2://…"
          />
          <div className="flex items-center gap-2">
            <Button variant="neutral" mode="ghost" size="3xsmall" disabled={!newLink.trim() || parsing} onClick={parse}>
              {t("profileForm.xrayParse")}
            </Button>
            <Button variant="neutral" mode="ghost" size="3xsmall" disabled={!newLink.trim() || testing} onClick={test}>
              {t("profileForm.xrayTest")}
            </Button>
            {parsed?.ok && (
              <span className="min-w-0 truncate text-secondary">
                {parsed.name ? `${parsed.name} · ` : ""}{parsed.protocol} · {parsed.masked}
              </span>
            )}
          </div>
          {tested && (
            <span className="text-secondary">
              {t("profileForm.xrayTestOk", {
                ip: tested.ip, country: tested.country, city: tested.city,
                ms: tested.tcp_ms ?? "?",
              })}
            </span>
          )}
          {error && <span className="text-warning-text">{error}</span>}
          <p className="m-0 text-secondary text-text-soft-400">{t("profileForm.xrayHelp")}</p>
        </div>
      )}
    </PropertyRow>
  );
}
