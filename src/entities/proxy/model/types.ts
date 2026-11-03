export type ProxyEntry = {
  id: string;
  name: string;
  kind: "socks5" | "http" | "https" | "xray";
  host: string;
  port: number;
  username: string;
  password: string;
  /** Full Xray share link, for kind "xray" only; never shown in full. */
  xray_link?: string | null;
  country: string;
  notes: string;
};

export type ProxyTestSnapshot = {
  first_seen: string;
  last_seen: string;
  ip: string;
  country_code: string;
  country: string;
  region: string;
  city: string;
  isp: string;
  timezone: string;
  latitude: number;
  longitude: number;
  tcp_ms: number | null;
  udp_ms: number | null;
  udp_error: string | null;
  /** Why this snapshot has no location. */
  geo_error: string | null;
  provider: string;
};

export type BulkRowState = {
  entry: ProxyEntry;
  selected: boolean;
  status: "idle" | "testing" | "ok" | "fail";
  tcp_ms?: number | null;
  udp_ms?: number | null;
  country?: string;
  error?: string;
};
