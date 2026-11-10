//! Share-link parsing for Xray proxies (Module 1 of the Xray fork).
//!
//! This module is launcher-only and does not change the existing
//! SOCKS5 / HTTP / HTTPS proxy path. It only knows how to turn a
//! VLESS / VMess / Trojan / Shadowsocks / Hysteria2 share link into a
//! normalized record that Module 3 (Xray config builder) can consume.
//!
//! Security notes, kept deliberately in code:
//! - Never log a full link, password or UUID. Use `masked_display()`.
//! - Test fixtures use `example.invalid` hosts and test UUIDs only.
//! - A malformed link is an error for that one line, never a panic and
//!   never a silent fallback to a direct connection.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum XrayProtocol {
    Vless,
    Vmess,
    Trojan,
    Shadowsocks,
    Hysteria2,
}

impl XrayProtocol {
    pub fn as_str(&self) -> &'static str {
        match self {
            XrayProtocol::Vless => "vless",
            XrayProtocol::Vmess => "vmess",
            XrayProtocol::Trojan => "trojan",
            XrayProtocol::Shadowsocks => "ss",
            XrayProtocol::Hysteria2 => "hysteria2",
        }
    }
}

/// A parsed Xray share link. `credential` is the UUID (VLESS/VMess),
/// password (Trojan/Hysteria2/Shadowsocks), depending on `protocol`.
/// `method` is only set for Shadowsocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedShareLink {
    pub protocol: XrayProtocol,
    pub name: String,
    pub host: String,
    pub port: u16,
    pub credential: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default)]
    pub params: BTreeMap<String, String>,
}

impl ParsedShareLink {
    /// Safe for logs and UI: scheme + host + port only, never credentials.
    pub fn masked_display(&self) -> String {
        format!("{}://{}:{}", self.protocol.as_str(), self.host, self.port)
    }
}

fn err(msg: impl Into<String>) -> String {
    msg.into()
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                out.push((hi * 16 + lo) as u8);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

fn decode_base64(input: &str) -> Result<Vec<u8>, String> {
    use base64::engine::general_purpose::{STANDARD, URL_SAFE};
    use base64::Engine;
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    let padded = {
        let rem = cleaned.len() % 4;
        if rem == 0 {
            cleaned.clone()
        } else {
            format!("{}{}", cleaned, "=".repeat(4 - rem))
        }
    };
    STANDARD
        .decode(&padded)
        .or_else(|_| URL_SAFE.decode(&padded))
        .or_else(|_| STANDARD.decode(&cleaned))
        .or_else(|_| URL_SAFE.decode(&cleaned))
        .map_err(|_| err("invalid base64 in share link"))
}

fn query_params(url: &url::Url) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (k, v) in url.query_pairs() {
        map.insert(k.into_owned(), v.into_owned());
    }
    map
}

fn require_port(url: &url::Url) -> Result<u16, String> {
    match url.port() {
        Some(0) | None => Err(err("share link is missing a valid port")),
        Some(p) => Ok(p),
    }
}

fn require_host(url: &url::Url) -> Result<String, String> {
    url.host_str()
        .filter(|h| !h.is_empty())
        .map(|h| h.to_string())
        .ok_or_else(|| err("share link is missing a host"))
}

fn split_fragment(input: &str) -> (&str, String) {
    match input.split_once('#') {
        Some((before, frag)) => (before, percent_decode(frag)),
        None => (input, String::new()),
    }
}

/// Is `host` a private/loopback IP literal? A domain name is not a
/// literal: the core resolves it and decides at runtime (and a failed
/// start fails closed), so only a literal public IP is rejected below.
fn is_private_ip_literal(host: &str) -> bool {
    use std::net::IpAddr;
    let Ok(ip) = host.parse::<IpAddr>() else {
        return false;
    };
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            v6.is_loopback() || (s[0] & 0xfe00) == 0xfc00 || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Security-first import rules for the current Xray core (26.7.11+).
/// These reject links the core itself would refuse, with a message
/// that says why, instead of letting the sidecar die at launch:
/// - plaintext VLESS (no TLS, no VLESS Encryption) or Trojan to a
///   public IP literal: the core refuses to start at all;
/// - Shadowsocks method `none`/`plain`: removed from the core;
/// - REALITY over WebSocket/HTTPUpgrade/mKCP: the docs support REALITY
///   only on raw (tcp) / xhttp / gRPC.
/// Note CGNAT 100.64/10 is deliberately NOT private here: core 26.10.31
/// tightened the private list and it needs TLS/REALITY too.
fn validate_for_current_core(link: &ParsedShareLink) -> Result<(), String> {
    // Trojan is TLS-only by definition (same default as the builder).
    let security = match link.protocol {
        XrayProtocol::Trojan => link
            .params
            .get("security")
            .map(|s| s.as_str())
            .unwrap_or("tls"),
        _ => link
            .params
            .get("security")
            .map(|s| s.as_str())
            .unwrap_or("none"),
    };
    let public_ip =
        link.host.parse::<std::net::IpAddr>().is_ok() && !is_private_ip_literal(&link.host);
    match link.protocol {
        XrayProtocol::Vless => {
            let encryption = link
                .params
                .get("encryption")
                .map(|s| s.as_str())
                .unwrap_or("none");
            if security == "none" && encryption == "none" && public_ip {
                return Err(err(
                    "plaintext VLESS to a public address is refused by Xray 26.7.11+: use TLS, REALITY, or VLESS Encryption",
                ));
            }
        }
        XrayProtocol::Trojan => {
            if security == "none" && public_ip {
                return Err(err(
                    "plaintext Trojan to a public address is refused by Xray 26.7.11+: Trojan needs TLS",
                ));
            }
        }
        XrayProtocol::Shadowsocks => {
            if let Some(m) = link.method.as_deref() {
                if m == "none" || m == "plain" {
                    return Err(err(
                        "Shadowsocks method 'none'/'plain' was removed from Xray 26.7.11+",
                    ));
                }
            }
        }
        _ => {}
    }
    if security == "reality" {
        let network = link
            .params
            .get("type")
            .map(|s| s.as_str())
            .unwrap_or("tcp");
        if !matches!(network, "tcp" | "raw" | "xhttp" | "splithttp" | "grpc") {
            return Err(err(
                "REALITY only works over TCP (raw), xhttp or gRPC, not over this transport",
            ));
        }
    }
    Ok(())
}

/// Parse one share link. Returns an error for:
/// - empty input, unknown scheme (including socks5/http/https, which stay
///   on the existing proxy path and must fall back to the caller),
/// - missing host/port/credential, malformed base64/JSON.
pub fn parse_share_link(input: &str) -> Result<ParsedShareLink, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(err("empty share link"));
    }
    let (before_fragment, name) = split_fragment(trimmed);
    let scheme = before_fragment
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .ok_or_else(|| err("share link must start with scheme://"))?;

    let parsed = match scheme.as_str() {
        "vmess" => parse_vmess(before_fragment, name),
        "vless" | "trojan" | "hysteria2" | "hy2" | "ss" | "shadowsocks" => {
            parse_url_form(&scheme, before_fragment, name)
        }
        other => Err(err(format!(
            "not an Xray share link (scheme: {other}); use the existing SOCKS5/HTTP path"
        ))),
    }?;
    validate_for_current_core(&parsed)?;
    Ok(parsed)
}

fn parse_url_form(
    scheme: &str,
    before_fragment: &str,
    name: String,
) -> Result<ParsedShareLink, String> {
    // Shadowsocks has a whole-link base64 form: ss://<base64(method:pass@host:port)>
    if scheme == "ss" || scheme == "shadowsocks" {
        if let Some(decoded) = try_ss_whole_base64(before_fragment)? {
            return Ok(decoded);
        }
    }
    let url = url::Url::parse(before_fragment)
        .map_err(|_| err("invalid share link URL"))?;
    let host = require_host(&url)?;
    let port = require_port(&url)?;
    let params = query_params(&url);
    let user = percent_decode(url.username());
    let pass = url.password().map(percent_decode).unwrap_or_default();

    let (protocol, credential, method) = match scheme {
        "vless" => {
            if user.is_empty() {
                return Err(err("vless link is missing a UUID"));
            }
            (XrayProtocol::Vless, user, None)
        }
        "trojan" => {
            let cred = if !pass.is_empty() {
                pass
            } else {
                user
            };
            if cred.is_empty() {
                return Err(err("trojan link is missing a password"));
            }
            (XrayProtocol::Trojan, cred, None)
        }
        "hysteria2" | "hy2" => {
            let cred = if !pass.is_empty() {
                pass
            } else {
                user
            };
            if cred.is_empty() {
                return Err(err("hysteria2 link is missing a password"));
            }
            (XrayProtocol::Hysteria2, cred, None)
        }
        "ss" | "shadowsocks" => {
            // Forms: ss://method:password@host:port  OR
            //        ss://<base64(method:password)>@host:port
            if let Ok((method, password)) = decode_ss_userinfo(&user) {
                if password.is_empty() {
                    return Err(err("shadowsocks link is missing a password"));
                }
                (XrayProtocol::Shadowsocks, password, Some(method))
            } else if !pass.is_empty() {
                (XrayProtocol::Shadowsocks, pass, Some(user))
            } else {
                return Err(err("shadowsocks link is missing method/password"));
            }
        }
        _ => unreachable!(),
    };

    Ok(ParsedShareLink {
        protocol,
        name,
        host,
        port,
        credential,
        method,
        params,
    })
}

/// ss://<base64(method:password@host:port)> — returns Some only when the
/// remainder (after ss://) decodes to something containing '@' and a port.
/// Otherwise returns None so the caller falls through to URL parsing.
fn try_ss_whole_base64(before_fragment: &str) -> Result<Option<ParsedShareLink>, String> {
    let rest = before_fragment
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or("");
    if rest.contains('@') {
        return Ok(None);
    }
    let (body, query) = match rest.split_once('?') {
        Some((b, q)) => (b, Some(q)),
        None => (rest, None),
    };
    if body.is_empty() {
        return Ok(None);
    }
    let decoded = match decode_base64(body) {
        Ok(d) => String::from_utf8(d).map_err(|_| err("invalid shadowsocks base64"))?,
        Err(_) => return Ok(None),
    };
    if !decoded.contains('@') {
        return Ok(None);
    }
    // Re-parse the decoded form as a normal ss:// link.
    let rebuilt = match query {
        Some(q) => format!("ss://{decoded}?{q}"),
        None => format!("ss://{decoded}"),
    };
    let url = url::Url::parse(&rebuilt).map_err(|_| err("invalid shadowsocks link"))?;
    let host = require_host(&url)?;
    let port = require_port(&url)?;
    let method = percent_decode(url.username());
    let password = url.password().map(percent_decode).unwrap_or_default();
    if method.is_empty() || password.is_empty() {
        return Err(err("shadowsocks link is missing method/password"));
    }
    let mut params = query_params(&url);
    // Keep the decoded form's params; query was already in the rebuilt URL.
    let _ = &mut params;
    Ok(Some(ParsedShareLink {
        protocol: XrayProtocol::Shadowsocks,
        name: String::new(),
        host,
        port,
        credential: password,
        method: Some(method),
        params,
    }))
}

fn decode_ss_userinfo(user: &str) -> Result<(String, String), String> {
    let decoded = decode_base64(user)?;
    let text = String::from_utf8(decoded).map_err(|_| err("invalid shadowsocks userinfo"))?;
    let (method, password) = text
        .split_once(':')
        .ok_or_else(|| err("invalid shadowsocks userinfo"))?;
    Ok((method.to_string(), password.to_string()))
}

fn parse_vmess(before_fragment: &str, name: String) -> Result<ParsedShareLink, String> {
    let rest = before_fragment
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or("");
    // Form A: vmess://<base64 JSON>, no '@' in the remainder.
    if !rest.contains('@') {
        let (body, _) = match rest.split_once('?') {
            Some((b, q)) => (b, q),
            None => (rest, ""),
        };
        let decoded = decode_base64(body)?;
        let text = String::from_utf8(decoded).map_err(|_| err("invalid vmess base64 JSON"))?;
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| err("invalid vmess JSON"))?;
        let get_str = |k: &str| -> Option<String> {
            v.get(k).and_then(|x| {
                x.as_str()
                    .map(|s| s.to_string())
                    .or_else(|| x.as_u64().map(|n| n.to_string()))
            })
        };
        let host = get_str("add").filter(|h| !h.is_empty()).ok_or_else(|| err("vmess JSON is missing add"))?;
        let port: u16 = get_str("port")
            .and_then(|p| p.parse().ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| err("vmess JSON is missing a valid port"))?;
        let credential = get_str("id").filter(|s| !s.is_empty()).ok_or_else(|| err("vmess JSON is missing id"))?;
        let mut params = BTreeMap::new();
        for k in ["net", "host", "path", "tls", "sni", "alpn", "security", "fp", "scy", "aid"] {
            if let Some(val) = get_str(k) {
                if !val.is_empty() {
                    params.insert(k.to_string(), val);
                }
            }
        }
        // VMess JSON names differ from the builder's: `net` is the
        // transport (the builder reads `type`), `tls` is the TLS switch
        // (the builder reads `security`), `scy` is the user security.
        // The JSON `type` field is the header type ("none"/"http"),
        // not a transport, and must not land in `type` — before this
        // fix a JSON link silently fell back to plaintext (`security`
        // defaulted to "none") with no fingerprint.
        if let Some(net) = params.remove("net") {
            params.insert("type".to_string(), net);
        }
        if let Some(tls) = params.remove("tls") {
            if tls == "tls" {
                params
                    .entry("security".to_string())
                    .or_insert_with(|| "tls".to_string());
            }
        }
        let display_name = if name.is_empty() {
            get_str("ps").unwrap_or_default()
        } else {
            name
        };
        return Ok(ParsedShareLink {
            protocol: XrayProtocol::Vmess,
            name: display_name,
            host,
            port,
            credential,
            method: None,
            params,
        });
    }
    // Form B: vmess://uuid@host:port?params
    let url = url::Url::parse(before_fragment).map_err(|_| err("invalid vmess link URL"))?;
    let host = require_host(&url)?;
    let port = require_port(&url)?;
    let credential = percent_decode(url.username());
    if credential.is_empty() {
        return Err(err("vmess link is missing a UUID"));
    }
    Ok(ParsedShareLink {
        protocol: XrayProtocol::Vmess,
        name,
        host,
        port,
        credential,
        method: None,
        params: query_params(&url),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn vless_valid() {
        let p = parse_share_link(&format!(
            "vless://{UUID}@example.invalid:443?encryption=none&security=tls&sni=example.invalid&type=ws&host=example.invalid&path=%2Fws#TestNode"
        ))
        .unwrap();
        assert_eq!(p.protocol, XrayProtocol::Vless);
        assert_eq!(p.host, "example.invalid");
        assert_eq!(p.port, 443);
        assert_eq!(p.credential, UUID);
        assert_eq!(p.name, "TestNode");
        assert_eq!(p.params.get("security").map(|s| s.as_str()), Some("tls"));
        assert!(!p.masked_display().contains(UUID));
    }

    #[test]
    fn vless_missing_port_is_error() {
        assert!(parse_share_link(&format!("vless://{UUID}@example.invalid?security=tls")).is_err());
    }

    #[test]
    fn trojan_valid() {
        let p = parse_share_link("trojan://testpass@example.invalid:443?sni=example.invalid#TrojanNode").unwrap();
        assert_eq!(p.protocol, XrayProtocol::Trojan);
        assert_eq!(p.credential, "testpass");
        assert_eq!(p.name, "TrojanNode");
    }

    #[test]
    fn shadowsocks_plain_valid() {
        let p = parse_share_link("ss://aes-256-gcm:testpass@example.invalid:8388#SSNode").unwrap();
        assert_eq!(p.protocol, XrayProtocol::Shadowsocks);
        assert_eq!(p.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(p.credential, "testpass");
    }

    #[test]
    fn shadowsocks_base64_userinfo_valid() {
        // base64("aes-256-gcm:testpass") = YWVzLTI1Ni1nY206dGVzdHBhc3M=
        let p = parse_share_link("ss://YWVzLTI1Ni1nY206dGVzdHBhc3M=@example.invalid:8388").unwrap();
        assert_eq!(p.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(p.credential, "testpass");
    }

    #[test]
    fn vmess_base64_json_valid() {
        // JSON: {"v":"2","ps":"VMessNode","add":"example.invalid","port":"443","id":"<UUID>","net":"ws","tls":"tls"}
        let json = format!(
            "{{\"v\":\"2\",\"ps\":\"VMessNode\",\"add\":\"example.invalid\",\"port\":\"443\",\"id\":\"{UUID}\",\"net\":\"ws\",\"tls\":\"tls\"}}"
        );
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let p = parse_share_link(&format!("vmess://{b64}")).unwrap();
        assert_eq!(p.protocol, XrayProtocol::Vmess);
        assert_eq!(p.host, "example.invalid");
        assert_eq!(p.port, 443);
        assert_eq!(p.credential, UUID);
        assert_eq!(p.name, "VMessNode");
    }

    #[test]
    fn vmess_uuid_form_valid() {
        let p = parse_share_link(&format!("vmess://{UUID}@example.invalid:443?security=tls")).unwrap();
        assert_eq!(p.protocol, XrayProtocol::Vmess);
        assert_eq!(p.credential, UUID);
    }

    #[test]
    fn vmess_json_maps_tls_net_fp_scy_aid() {
        // JSON: {"v":"2","ps":"VMessNode","add":"example.invalid","port":"443","id":"<UUID>","aid":"0","net":"ws","type":"none","host":"example.invalid","path":"/ws","tls":"tls","sni":"example.invalid","fp":"chrome","scy":"auto"}
        let json = format!(
            "{{\"v\":\"2\",\"ps\":\"VMessNode\",\"add\":\"example.invalid\",\"port\":\"443\",\"id\":\"{UUID}\",\"aid\":\"0\",\"net\":\"ws\",\"type\":\"none\",\"host\":\"example.invalid\",\"path\":\"/ws\",\"tls\":\"tls\",\"sni\":\"example.invalid\",\"fp\":\"chrome\",\"scy\":\"auto\"}}"
        );
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.as_bytes());
        let p = parse_share_link(&format!("vmess://{b64}")).unwrap();
        // `net` is the transport, `tls` the TLS switch; the JSON header
        // `type` ("none") must not overwrite the transport.
        assert_eq!(p.params.get("type").map(|s| s.as_str()), Some("ws"));
        assert_eq!(p.params.get("security").map(|s| s.as_str()), Some("tls"));
        assert_eq!(p.params.get("fp").map(|s| s.as_str()), Some("chrome"));
        assert_eq!(p.params.get("scy").map(|s| s.as_str()), Some("auto"));
        assert_eq!(p.params.get("aid").map(|s| s.as_str()), Some("0"));
    }

    #[test]
    fn plaintext_vless_to_public_ip_is_rejected() {
        assert!(parse_share_link(&format!(
            "vless://{UUID}@8.8.8.8:443?encryption=none&security=none#x"
        ))
        .is_err());
        // A private address is still allowed: the core permits it.
        assert!(parse_share_link(&format!(
            "vless://{UUID}@192.168.1.10:443?encryption=none&security=none#x"
        ))
        .is_ok());
        // VLESS Encryption satisfies the core rule even in plaintext.
        assert!(parse_share_link(&format!(
            "vless://{UUID}@8.8.8.8:443?encryption=mlkem768x25519plus.native.0rtt.0.0&security=none#x"
        ))
        .is_ok());
    }

    #[test]
    fn plaintext_trojan_and_ss_none_are_rejected() {
        assert!(parse_share_link("trojan://testpass@8.8.8.8:443?security=none#t").is_err());
        // No security param: Trojan defaults to TLS, so this is fine.
        assert!(parse_share_link("trojan://testpass@8.8.8.8:443#t").is_ok());
        assert!(parse_share_link("ss://none:testpass@example.invalid:8388#s").is_err());
    }

    #[test]
    fn reality_over_websocket_is_rejected() {
        let pbk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(parse_share_link(&format!(
            "vless://{UUID}@example.invalid:443?security=reality&sni=example.com&fp=chrome&pbk={pbk}&sid=aa11&type=ws#r"
        ))
        .is_err());
        assert!(parse_share_link(&format!(
            "vless://{UUID}@example.invalid:443?security=reality&sni=example.com&fp=chrome&pbk={pbk}&sid=aa11&type=tcp#r"
        ))
        .is_ok());
    }

    #[test]
    fn vmess_bad_base64_is_error() {
        assert!(parse_share_link("vmess://!!!not-base64!!!").is_err());
    }

    #[test]
    fn hysteria2_valid() {
        let p = parse_share_link("hysteria2://testpass@example.invalid:443?sni=example.invalid#Hy2Node").unwrap();
        assert_eq!(p.protocol, XrayProtocol::Hysteria2);
        assert_eq!(p.credential, "testpass");
        let p2 = parse_share_link("hy2://testpass@example.invalid:443").unwrap();
        assert_eq!(p2.protocol, XrayProtocol::Hysteria2);
    }

    #[test]
    fn hysteria2_missing_password_is_error() {
        assert!(parse_share_link("hysteria2://@example.invalid:443").is_err());
    }

    #[test]
    fn socks5_is_not_xray_and_errors() {
        assert!(parse_share_link("socks5://user:pass@example.invalid:1080").is_err());
    }

    #[test]
    fn empty_and_garbage_are_errors() {
        assert!(parse_share_link("").is_err());
        assert!(parse_share_link("not-a-link").is_err());
    }
}
