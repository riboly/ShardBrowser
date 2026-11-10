//! Xray config builder + lifecycle (Module 3 of the Xray fork).
//!
//! Module 4 (launch integration) will call this, but this module does
//! not touch launch.rs / runner.rs itself, so it can be tested alone:
//!
//! - `build_client_config`: ParsedShareLink + local port -> Xray JSON.
//!   The engine only ever sees the local SOCKS5 inbound; the upstream
//!   address lives only in the outbound, never in `--proxy-server`.
//! - `free_port`: allocate a per-profile local port at launch, not at import.
//! - `XraySidecar`: start (write config, spawn, health-check, fail closed),
//!   stop (kill, wait, remove config, keep the log for diagnosis).
//! - `cleanup_orphans`: on launcher start, kill Xray processes that were
//!   started by this launcher (tracked by pid file) and are still alive.
//!
//! Security notes:
//! - The config file contains the upstream credential, so it lives in the
//!   OS temp dir, is removed on stop, and must never be committed or logged.
//! - If Xray fails to start or the health check times out, `start` returns
//!   an error and the caller must NOT launch the profile with a direct
//!   connection or no proxy. Fail closed.

use super::xray_share::{ParsedShareLink, XrayProtocol};
use serde_json::{json, Map, Value};
use std::fs::{self, File};
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Donut (`xray_worker_runner.rs`) gives a first start 30 s, because a
/// first start on Windows can wait for antivirus to scan xray.exe. The
/// old 5 s here was too short for exactly that case.
pub const XRAY_HEALTH_TIMEOUT: Duration = Duration::from_secs(30);

pub fn temp_file_stem(profile_id: &str) -> String {
    let safe: String = profile_id
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect();
    format!("shard-xray-{safe}")
}

pub fn config_path(profile_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}.json", temp_file_stem(profile_id)))
}

pub fn log_path(profile_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}.log", temp_file_stem(profile_id)))
}

pub fn pid_path(profile_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{}.pid", temp_file_stem(profile_id)))
}

/// Allocate a free local port. The listener is dropped immediately, so
/// the caller must health-check the port after Xray starts (see
/// `XraySidecar::start`); a race where another process grabs the port
/// in between is caught there as a health-check failure, not silently
/// accepted.
pub fn free_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

fn stream_settings(link: &ParsedShareLink) -> Value {
    let p = &link.params;
    let network = p.get("type").cloned().unwrap_or_else(|| "tcp".to_string());
    let security = p.get("security").cloned().unwrap_or_else(|| {
        // Trojan is TLS-only by definition: a trojan:// link that
        // carries no security param still negotiates TLS.
        if link.protocol == XrayProtocol::Trojan {
            "tls".to_string()
        } else {
            "none".to_string()
        }
    });
    let mut settings = Map::new();
    settings.insert("network".to_string(), json!(network));
    settings.insert("security".to_string(), json!(security));
    match network.as_str() {
        "ws" => {
            let mut ws = Map::new();
            ws.insert(
                "path".to_string(),
                json!(p.get("path").cloned().unwrap_or_else(|| "/".to_string())),
            );
            if let Some(host) = p.get("host") {
                ws.insert("headers".to_string(), json!({ "Host": host }));
            }
            settings.insert("wsSettings".to_string(), Value::Object(ws));
        }
        "grpc" => {
            settings.insert(
                "grpcSettings".to_string(),
                json!({ "serviceName": p.get("serviceName").cloned().unwrap_or_default() }),
            );
        }
        _ => {}
    }
    if security == "tls" {
        let mut tls = Map::new();
        if let Some(sni) = p.get("sni").or_else(|| p.get("host")) {
            tls.insert("serverName".to_string(), json!(sni));
        }
        if let Some(alpn) = p.get("alpn") {
            tls.insert(
                "alpn".to_string(),
                json!(alpn.split(',').map(str::trim).collect::<Vec<_>>()),
            );
        }
        // Always emitted: empty defaults to Chrome_Auto in the core,
        // but an explicit chrome keeps the handshake identical across
        // cores (and, for REALITY, guarantees ML-KEM support).
        tls.insert(
            "fingerprint".to_string(),
            json!(p.get("fp").cloned().unwrap_or_else(|| "chrome".to_string())),
        );
        settings.insert("tlsSettings".to_string(), Value::Object(tls));
    }
    if security == "reality" {
        let mut reality = Map::new();
        if let Some(sni) = p.get("sni") {
            reality.insert("serverName".to_string(), json!(sni));
        }
        // Always emitted (see TLS above): only chrome, firefox and
        // safari are guaranteed ML-KEM support by the REALITY docs.
        reality.insert(
            "fingerprint".to_string(),
            json!(p.get("fp").cloned().unwrap_or_else(|| "chrome".to_string())),
        );
        // Canonical field name: the core renamed publicKey to password;
        // both are still accepted, password wins if both are set.
        if let Some(pk) = p.get("pbk") {
            reality.insert("password".to_string(), json!(pk));
        }
        if let Some(sid) = p.get("sid") {
            reality.insert("shortId".to_string(), json!(sid));
        }
        // v2rayN link param `spx`: the initial crawler path. The core
        // defaults to "/" when absent, but the docs recommend a
        // per-client value, so a link that carries one must reach the
        // core verbatim instead of being dropped.
        if let Some(spx) = p.get("spx") {
            reality.insert("spiderX".to_string(), json!(spx));
        }
        if let Some(mldsa) = p.get("mldsa65Verify") {
            reality.insert("mldsa65Verify".to_string(), json!(mldsa));
        }
        settings.insert("realitySettings".to_string(), Value::Object(reality));
    }
    Value::Object(settings)
}

fn outbound(link: &ParsedShareLink) -> Value {
    let stream = stream_settings(link);
    match link.protocol {
        XrayProtocol::Vless => {
            let mut user = Map::new();
            user.insert("id".to_string(), json!(link.credential));
            if let Some(flow) = link.params.get("flow") {
                user.insert("flow".to_string(), json!(flow));
            }
            user.insert(
                "encryption".to_string(),
                json!(link.params.get("encryption").cloned().unwrap_or_else(|| "none".to_string())),
            );
            json!({
                "protocol": "vless",
                "settings": { "vnext": [{ "address": link.host, "port": link.port, "users": [user] }] },
                "streamSettings": stream,
                "tag": "proxy",
            })
        }
        XrayProtocol::Vmess => {
            let mut user = Map::new();
            user.insert("id".to_string(), json!(link.credential));
            if let Some(aid) = link.params.get("aid") {
                user.insert("alterId".to_string(), json!(aid.parse::<u16>().unwrap_or(0)));
            }
            user.insert(
                "security".to_string(),
                json!(link.params.get("scy").cloned().unwrap_or_else(|| "auto".to_string())),
            );
            json!({
                "protocol": "vmess",
                "settings": { "vnext": [{ "address": link.host, "port": link.port, "users": [user] }] },
                "streamSettings": stream,
                "tag": "proxy",
            })
        }
        XrayProtocol::Trojan => json!({
            "protocol": "trojan",
            "settings": { "servers": [{ "address": link.host, "port": link.port, "password": link.credential }] },
            "streamSettings": stream,
            "tag": "proxy",
        }),
        XrayProtocol::Shadowsocks => json!({
            "protocol": "shadowsocks",
            "settings": { "servers": [{
                "address": link.host,
                "port": link.port,
                "method": link.method.clone().unwrap_or_else(|| "aes-256-gcm".to_string()),
                "password": link.credential,
            }] },
            "tag": "proxy",
        }),
        XrayProtocol::Hysteria2 => {
            // Xray's Hysteria2 is protocol "hysteria" with version 2, not
            // "hysteria2": the latter is not a protocol Xray knows, so a
            // config built with it fails to load and the sidecar exits
            // before it ever dials. TLS and auth live in streamSettings,
            // not in settings: tlsSettings carries SNI/ALPN/pin, and
            // hysteriaSettings carries the password as `auth`.
            let qp = &link.params;
            let mut tls = Map::new();
            tls.insert(
                "serverName".to_string(),
                json!(qp.get("sni").cloned().unwrap_or_else(|| link.host.clone())),
            );
            let alpn: Vec<&str> = qp
                .get("alpn")
                .map(|a| a.split(',').map(str::trim).filter(|s| !s.is_empty()).collect())
                .unwrap_or_else(|| vec!["h3"]);
            tls.insert("alpn".to_string(), json!(alpn));
            // No allowInsecure here: it is deprecated in the current
            // docs and newer cores offer no way to skip certificate
            // verification at all — the documented replacement is
            // pinnedPeerCertSha256. A link's insecure=1 is honoured
            // only through its pin: the pin replaces CA verification
            // for that certificate. A link with insecure=1 and no pin
            // gets plain CA verification — the core offers no other
            // skip, and inventing one would be a config Xray rejects
            // anyway.
            if let Some(pin) = qp.get("pinSHA256") {
                // Xray hex-decodes this at config load: anything but
                // exactly 64 hex chars fails the whole config, so a bad
                // value is left out rather than breaking the node.
                if pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()) {
                    tls.insert("pinnedPeerCertSha256".to_string(), json!(pin));
                }
            }
            let mut hyst = Map::new();
            hyst.insert("version".to_string(), json!(2));
            hyst.insert("auth".to_string(), json!(link.credential));
            json!({
                "protocol": "hysteria",
                "settings": { "version": 2, "address": link.host, "port": link.port },
                "streamSettings": {
                    "network": "hysteria",
                    "security": "tls",
                    "tlsSettings": Value::Object(tls),
                    "hysteriaSettings": Value::Object(hyst),
                },
                "tag": "proxy",
            })
        }
    }
}

/// Build a complete Xray client config. Inbound is always a local SOCKS5
/// (UDP enabled, for the QUIC/WebRTC probe in Module 4); outbound is the
/// parsed upstream. No direct-connection fallback is configured.
///
/// Donut (`xray/client.rs`) puts a random username/password on the
/// local inbound (`auth: "password"`), so any other local process cannot
/// just use the profile's tunnel. `auth` carries that pair; `None` keeps
/// the old open inbound, and is only for tests that do not start a
/// sidecar. Production always passes `Some`.
pub fn build_client_config(link: &ParsedShareLink, local_port: u16) -> Value {
    build_client_config_auth(link, local_port, None)
}

pub fn build_client_config_auth(
    link: &ParsedShareLink,
    local_port: u16,
    auth: Option<(&str, &str)>,
) -> Value {
    let settings = match auth {
        Some((user, pass)) => json!({
            "auth": "password",
            "accounts": [{ "user": user, "pass": pass }],
            "udp": true,
            "ip": "127.0.0.1",
        }),
        None => json!({ "auth": "noauth", "udp": true }),
    };
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "socks-in",
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": settings,
        }],
        "outbounds": [outbound(link)],
    })
}

/// Random local SOCKS credentials, per sidecar start (Donut's
/// `XrayWorkerConfig` does the same per worker). They never leave this
/// machine: they go into the Xray config and into the engine's
/// `--proxy-server` arg, and are dropped when the sidecar stops.
fn random_local_credential() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    (0..16)
        .map(|_| {
            let n = rng.gen_range(0..62);
            (b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[n as usize]) as char
        })
        .collect()
}

pub fn write_config(profile_id: &str, config: &Value) -> std::io::Result<PathBuf> {
    let path = config_path(profile_id);
    let mut file = File::create(&path)?;
    file.write_all(serde_json::to_string_pretty(config).unwrap().as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    Ok(path)
}

pub fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Donut's `authenticated_socks_ready`: a TCP connect alone proves
/// nothing — another process could own the port, or Xray could still be
/// loading. Do the SOCKS5 handshake with the local credentials and only
/// return true when Xray itself answers the auth.
fn try_socks_auth_once(port: u16, user: &str, pass: &str) -> bool {
    use std::io::{Read, Write};
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    if stream.write_all(&[5, 1, 2]).is_err() {
        return false;
    }
    let mut method = [0u8; 2];
    if stream.read_exact(&mut method).is_err() || method != [5, 2] {
        return false;
    }
    let mut auth = vec![1, user.len() as u8];
    auth.extend_from_slice(user.as_bytes());
    auth.push(pass.len() as u8);
    auth.extend_from_slice(pass.as_bytes());
    if stream.write_all(&auth).is_err() {
        return false;
    }
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).is_ok() && resp == [1, 0]
}

pub fn wait_for_socks_auth(port: u16, user: &str, pass: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if try_socks_auth_once(port, user, pass) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// The startup wait, but a dead sidecar ends it at once with its exit
/// status instead of burning the whole timeout on a process that will
/// never answer.
pub fn wait_for_socks_auth_or_exit(
    port: u16,
    user: &str,
    pass: &str,
    timeout: Duration,
    child: &mut Child,
) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if try_socks_auth_once(port, user, pass) {
            return Ok(());
        }
        if let Ok(Some(status)) = child.try_wait() {
            return Err(format!("Xray exited during startup (status: {status})"));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!(
        "Xray did not answer SOCKS auth on 127.0.0.1:{port} within {timeout:?}"
    ))
}

pub struct XraySidecar {
    pub profile_id: String,
    pub local_port: u16,
    /// Random per-start local SOCKS credentials (Donut-style). The
    /// launcher hands them to the engine via the local proxy entry;
    /// they are never written to the profile or logged.
    pub local_user: String,
    pub local_pass: String,
    pub config: PathBuf,
    pub log: PathBuf,
    child: Child,
}

impl XraySidecar {
    pub fn start(
        binary_path: &std::path::Path,
        link: &ParsedShareLink,
        profile_id: &str,
        local_port: u16,
    ) -> Result<Self, String> {
        let local_user = random_local_credential();
        let local_pass = random_local_credential();
        let config = build_client_config_auth(link, local_port, Some((&local_user, &local_pass)));
        let config_path = write_config(profile_id, &config)
            .map_err(|e| format!("failed to write Xray config: {e}"))?;
        let log_path = log_path(profile_id);
        let log_file = File::create(&log_path)
            .map_err(|e| format!("failed to create Xray log: {e}"))?;
        let log_file2 = log_file
            .try_clone()
            .map_err(|e| format!("failed to clone Xray log handle: {e}"))?;
        let mut cmd = Command::new(binary_path);
        cmd.arg("-c")
            .arg(&config_path)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file2));
        #[cfg(target_os = "windows")]
        {
            // The sidecar is a console program: without this, every
            // profile start flashes a black console window.
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        let mut child = cmd
            .spawn()
            .map_err(|e| {
                let _ = fs::remove_file(&config_path);
                format!("failed to start Xray ({}): {e}", link.masked_display())
            })?;
        let _ = fs::write(pid_path(profile_id), child.id().to_string());
        // A bad config kills the sidecar at once; waiting out the full
        // 30 s for a dead process is what made the last failure look
        // like a network timeout. Fail on the exit itself instead.
        if let Err(e) = wait_for_socks_auth_or_exit(
            local_port,
            &local_user,
            &local_pass,
            XRAY_HEALTH_TIMEOUT,
            &mut child,
        ) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&config_path);
            return Err(format!("{e}; see log {}", log_path.display()));
        }
        Ok(Self {
            profile_id: profile_id.to_string(),
            local_port,
            local_user,
            local_pass,
            config: config_path,
            log: log_path,
            child,
        })
    }

    pub fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = fs::remove_file(&self.config);
        let _ = fs::remove_file(pid_path(&self.profile_id));
    }
}

impl Drop for XraySidecar {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Kill launcher-tracked orphan Xray processes (pid files in the temp dir).
/// Only pids whose command line still references a shard-xray config are
/// killed on Unix; other pids are left alone, and stale pid files are removed.
pub fn cleanup_orphans() -> Vec<String> {
    let mut cleaned = Vec::new();
    let Ok(entries) = fs::read_dir(std::env::temp_dir()) else {
        return cleaned;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("shard-xray-") || !name.ends_with(".pid") {
            continue;
        }
        let Ok(pid_text) = fs::read_to_string(entry.path()) else {
            continue;
        };
        let Ok(pid) = pid_text.trim().parse::<u32>() else {
            let _ = fs::remove_file(entry.path());
            continue;
        };
        #[cfg(unix)]
        {
            let cmdline = fs::read_to_string(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            if cmdline.contains("shard-xray-") {
                libc_kill(pid);
            }
        }
        #[cfg(not(unix))]
        {
            let _ = pid;
        }
        let _ = fs::remove_file(entry.path());
        cleaned.push(name);
    }
    cleaned
}

#[cfg(unix)]
fn libc_kill(pid: u32) {
    // SIGTERM first; the caller (launcher start) does not wait for exit.
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::space::local::xray_share::parse_share_link;

    fn vless() -> ParsedShareLink {
        parse_share_link("vless://11111111-2222-3333-4444-555555555555@example.invalid:443?security=tls&sni=example.com&type=ws&path=%2Fws#test").unwrap()
    }

    #[test]
    fn config_inbound_is_local_and_outbound_is_upstream() {
        let cfg = build_client_config(&vless(), 18080);
        assert_eq!(cfg["inbounds"][0]["port"], 18080);
        assert_eq!(cfg["inbounds"][0]["listen"], "127.0.0.1");
        assert_eq!(cfg["inbounds"][0]["protocol"], "socks");
        assert_eq!(cfg["outbounds"][0]["protocol"], "vless");
        assert_eq!(cfg["outbounds"][0]["settings"]["vnext"][0]["address"], "example.invalid");
        assert_eq!(cfg["outbounds"][0]["settings"]["vnext"][0]["port"], 443);
        assert_eq!(cfg["outbounds"][0]["streamSettings"]["network"], "ws");
        assert_eq!(cfg["outbounds"][0]["streamSettings"]["tlsSettings"]["serverName"], "example.com");
    }

    #[test]
    fn reality_config_is_complete_per_latest_docs() {
        let link = parse_share_link("vless://11111111-2222-3333-4444-555555555555@example.invalid:443?security=reality&sni=example.com&fp=chrome&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=aa11&spx=%2Fproxy&flow=xtls-rprx-vision&encryption=none#r").unwrap();
        let cfg = build_client_config(&link, 18085);
        let reality = &cfg["outbounds"][0]["streamSettings"]["realitySettings"];
        // Canonical field name is `password`, not the old `publicKey`.
        assert_eq!(reality["password"], "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        assert!(reality["publicKey"].is_null());
        assert_eq!(reality["serverName"], "example.com");
        assert_eq!(reality["fingerprint"], "chrome");
        assert_eq!(reality["shortId"], "aa11");
        assert_eq!(reality["spiderX"], "/proxy");
        assert_eq!(
            cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0]["flow"],
            "xtls-rprx-vision"
        );
    }

    #[test]
    fn reality_fingerprint_defaults_to_chrome() {
        let link = parse_share_link("vless://11111111-2222-3333-4444-555555555555@example.invalid:443?security=reality&sni=example.com&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#r").unwrap();
        let cfg = build_client_config(&link, 18086);
        assert_eq!(
            cfg["outbounds"][0]["streamSettings"]["realitySettings"]["fingerprint"],
            "chrome"
        );
    }

    #[test]
    fn hysteria2_config_shape() {
        // The shape a real hy2 link (SNI, insecure, cert pin) must land in.
        let pin = "0123456789abcdef".repeat(4);
        let link = format!(
            "hysteria2://testpass@example.invalid:443?sni=sni.invalid&insecure=1&pinSHA256={pin}#h"
        );
        let parsed = parse_share_link(&link).unwrap();
        let cfg = build_client_config(&parsed, 18082);
        let out = &cfg["outbounds"][0];
        assert_eq!(out["protocol"], "hysteria");
        assert_eq!(out["settings"]["version"], 2);
        assert_eq!(out["settings"]["address"], "example.invalid");
        assert_eq!(out["streamSettings"]["network"], "hysteria");
        assert_eq!(out["streamSettings"]["tlsSettings"]["serverName"], "sni.invalid");
        assert_eq!(out["streamSettings"]["tlsSettings"]["alpn"][0], "h3");
        assert!(out["streamSettings"]["tlsSettings"]["allowInsecure"].is_null());
        assert_eq!(out["streamSettings"]["tlsSettings"]["pinnedPeerCertSha256"], pin);
        assert_eq!(out["streamSettings"]["hysteriaSettings"]["version"], 2);
        assert_eq!(out["streamSettings"]["hysteriaSettings"]["auth"], "testpass");
    }

    #[test]
    fn hysteria2_insecure_without_pin_gets_no_skip() {
        // insecure=1 without a pin cannot be expressed in newer cores:
        // allowInsecure is gone, and there is nothing to pin to.
        let parsed =
            parse_share_link("hysteria2://testpass@example.invalid:443?insecure=1#h").unwrap();
        let cfg = build_client_config(&parsed, 18084);
        let tls = &cfg["outbounds"][0]["streamSettings"]["tlsSettings"];
        assert!(tls["allowInsecure"].is_null());
        assert!(tls["pinnedPeerCertSha256"].is_null());
        assert_eq!(tls["serverName"], "example.invalid");
    }

    #[test]
    fn config_covers_all_protocols() {
        let cases = [
            ("trojan://pass@example.invalid:443#t", "trojan"),
            ("ss://YWVzLTI1Ni1nY206cGFzcw==@example.invalid:8388#s", "shadowsocks"),
            ("hysteria2://pass@example.invalid:443#h", "hysteria"),
        ];
        for (link, protocol) in cases {
            let parsed = parse_share_link(link).unwrap();
            let cfg = build_client_config(&parsed, 18081);
            assert_eq!(cfg["outbounds"][0]["protocol"], protocol);
            assert_eq!(cfg["inbounds"][0]["port"], 18081);
        }
    }

    #[test]
    fn free_port_is_usable_and_health_check_works() {
        let port = free_port().unwrap();
        assert!(port > 0);
        assert!(!wait_for_port(port, Duration::from_millis(200)));
        let listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        assert!(wait_for_port(port, Duration::from_secs(2)));
        drop(listener);
    }

    /// Launch-layer isolation: two profiles built from different links
    /// get different local ports and different upstream outbounds, so
    /// starting profile A never routes through profile B's node.
    #[test]
    fn two_profiles_get_different_ports_and_outbounds() {
        let a = parse_share_link("vless://11111111-2222-3333-4444-555555555555@node-a.invalid:443#node-a").unwrap();
        let b = parse_share_link("trojan://pass@node-b.invalid:8443#node-b").unwrap();
        let port_a = free_port().unwrap();
        let port_b = free_port().unwrap();
        assert_ne!(port_a, port_b);
        let cfg_a = build_client_config(&a, port_a);
        let cfg_b = build_client_config(&b, port_b);
        assert_eq!(cfg_a["inbounds"][0]["port"], port_a);
        assert_eq!(cfg_b["inbounds"][0]["port"], port_b);
        assert_eq!(cfg_a["outbounds"][0]["settings"]["vnext"][0]["address"], "node-a.invalid");
        assert_eq!(cfg_b["outbounds"][0]["settings"]["servers"][0]["address"], "node-b.invalid");
    }

    #[test]
    fn auth_config_puts_random_credentials_on_local_inbound_only() {
        let link = vless();
        let cfg = build_client_config_auth(&link, 18083, Some(("local-user", "local-pass")));
        let inbound = &cfg["inbounds"][0];
        assert_eq!(inbound["settings"]["auth"], "password");
        assert_eq!(inbound["settings"]["accounts"][0]["user"], "local-user");
        assert_eq!(inbound["settings"]["accounts"][0]["pass"], "local-pass");
        // The local credential must not leak into the outbound.
        let out = serde_json::to_string(&cfg["outbounds"]).unwrap();
        assert!(!out.contains("local-user"));
        assert!(!out.contains("local-pass"));
        // Noauth delegate keeps the old shape for tests that do not start a sidecar.
        let plain = build_client_config(&link, 18083);
        assert_eq!(plain["inbounds"][0]["settings"]["auth"], "noauth");
    }

    #[test]
    fn config_write_roundtrip_and_start_fails_closed() {
        let link = vless();
        let cfg = build_client_config(&link, 18082);
        let path = write_config("test-profile", &cfg).unwrap();
        let back: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(back, cfg);
        let err = match XraySidecar::start(
            std::path::Path::new("/nonexistent/xray"),
            &link,
            "test-profile",
            18082,
        ) {
            Err(e) => e,
            Ok(_) => panic!("starting a nonexistent Xray binary must fail"),
        };
        assert!(err.contains("failed to start Xray"));
        assert!(!config_path("test-profile").exists());
        let _ = fs::remove_file(&path);
    }
}
