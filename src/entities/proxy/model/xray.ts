import { invoke } from "../../../shared/api/invoke";
import type { ProxyTestSnapshot } from "./types";

/** One line of a bulk Xray import. Never carries a full link or credential. */
export interface XrayImportResult {
  line: number;
  ok: boolean;
  name: string | null;
  protocol: string | null;
  masked: string | null;
  error: string | null;
}

/** Parse pasted share links without saving; per-line success/failure. */
export const xrayBulkParse = (text: string) =>
  invoke<XrayImportResult[]>("xray_bulk_parse", { text });

/** Bind a share link to a personal profile; returns masked display. */
export const xrayBindToProfile = (profileId: string, link: string) =>
  invoke<string>("xray_bind_to_profile", { profileId, link });

export const xrayUnbindFromProfile = (profileId: string) =>
  invoke("xray_unbind_from_profile", { profileId });

/** Masked display of a profile's bound link, if any; never the link. */
export const xrayBoundForProfile = (profileId: string) =>
  invoke<string | null>("xray_bound_for_profile", { profileId });

/** Test a link through a temporary Xray sidecar; exit IP is upstream's. */
export const xrayTestLink = (link: string) =>
  invoke<ProxyTestSnapshot>("xray_test_link", { link });
