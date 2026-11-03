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

pub const XRAY_HEALTH_TIMEOUT: Duration = Duration::from_secs(5);

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
    let security = p
        .get("security")
        .cloned()
        .unwrap_or_else(|| "none".to_string());
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
        if let Some(fp) = p.get("fp") {
            tls.insert("fingerprint".to_string(), json!(fp));
        }
        settings.insert("tlsSettings".to_string(), Value::Object(tls));
    }
    if security == "reality" {
        let mut reality = Map::new();
        if let Some(sni) = p.get("sni") {
            reality.insert("serverName".to_string(), json!(sni));
        }
        if let Some(fp) = p.get("fp") {
            reality.insert("fingerprint".to_string(), json!(fp));
        }
        if let Some(pk) = p.get("pbk") {
            reality.insert("publicKey".to_string(), json!(pk));
        }
        if let Some(sid) = p.get("sid") {
            reality.insert("shortId".to_string(), json!(sid));
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
        XrayProtocol::Hysteria2 => json!({
            "protocol": "hysteria2",
            "settings": { "servers": [{ "address": link.host, "port": link.port, "password": link.credential }] },
            "streamSettings": stream,
            "tag": "proxy",
        }),
    }
}

/// Build a complete Xray client config. Inbound is always a local SOCKS5
/// (UDP enabled, for the QUIC/WebRTC probe in Module 4); outbound is the
/// parsed upstream. No direct-connection fallback is configured.
pub fn build_client_config(link: &ParsedShareLink, local_port: u16) -> Value {
    json!({
        "log": { "loglevel": "warning" },
        "inbounds": [{
            "tag": "socks-in",
            "port": local_port,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": { "auth": "noauth", "udp": true },
        }],
        "outbounds": [outbound(link)],
    })
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

pub struct XraySidecar {
    pub profile_id: String,
    pub local_port: u16,
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
        let config = build_client_config(link, local_port);
        let config_path = write_config(profile_id, &config)
            .map_err(|e| format!("failed to write Xray config: {e}"))?;
        let log_path = log_path(profile_id);
        let log_file = File::create(&log_path)
            .map_err(|e| format!("failed to create Xray log: {e}"))?;
        let log_file2 = log_file
            .try_clone()
            .map_err(|e| format!("failed to clone Xray log handle: {e}"))?;
        let mut child = Command::new(binary_path)
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(log_file2))
            .spawn()
            .map_err(|e| {
                let _ = fs::remove_file(&config_path);
                format!("failed to start Xray ({}): {e}", link.masked_display())
            })?;
        let _ = fs::write(pid_path(profile_id), child.id().to_string());
        if !wait_for_port(local_port, XRAY_HEALTH_TIMEOUT) {
            let _ = child.kill();
            let _ = child.wait();
            let _ = fs::remove_file(&config_path);
            return Err(format!(
                "Xray did not listen on 127.0.0.1:{} within {:?}; see log {}",
                local_port, XRAY_HEALTH_TIMEOUT, log_path.display()
            ));
        }
        Ok(Self {
            profile_id: profile_id.to_string(),
            local_port,
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
    fn config_covers_all_protocols() {
        let cases = [
            ("trojan://pass@example.invalid:443#t", "trojan"),
            ("ss://YWVzLTI1Ni1nY206cGFzcw==@example.invalid:8388#s", "shadowsocks"),
            ("hysteria2://pass@example.invalid:443#h", "hysteria2"),
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
