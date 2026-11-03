//! Launch integration helpers (Module 4 of the Xray fork).
//!
//! The integration point in launch.rs is deliberately small:
//!
//! 1. At the start of `start_browser`, if the profile's `_meta.xray_link`
//!    is set, `start_xray_for_profile` parses it, allocates a local port,
//!    starts the Xray sidecar, and returns a local SOCKS5 `ProxyEntry`.
//!    The caller replaces `input.proxy` with that entry, so every existing
//!    step after it — UDP probe, geo check, `--proxy-server` arg, QUIC /
//!    WebRTC gating — works on the LOCAL port, unchanged. Geo through the
//!    local SOCKS5 resolves the UPSTREAM exit IP, never 127.0.0.1, because
//!    the geo request itself travels through Xray.
//! 2. If Xray fails to start, the caller returns an error and the profile
//!    is NOT launched. Fail closed: no direct connection, no fallback to a
//!    bound proxy.
//! 3. The sidecar is kept in a registry keyed by profile_id until the
//!    browser stops (the caller spawns a watcher that calls
//!    `stop_xray_for_profile` when the Tracker entry disappears). Dropping
//!    the registry entry kills the sidecar; a launcher crash leaves a pid
//!    file for `cleanup_orphans` on the next start.

use super::xray_binary::sidecar_binary_name;
use super::xray_runtime::{free_port, XraySidecar};
use super::xray_share::parse_share_link;
use super::proxy::{ProxyEntry, ProxyKind};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

fn registry() -> &'static Mutex<HashMap<String, XraySidecar>> {
    static REGISTRY: OnceLock<Mutex<HashMap<String, XraySidecar>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Local SOCKS5 entry for an Xray sidecar. Its id is fixed so the
/// existing proxy-test cache never mixes it up with a real upstream proxy.
pub fn local_proxy_entry(local_port: u16) -> ProxyEntry {
    ProxyEntry {
        id: "xray-local".to_string(),
        name: "Xray (local)".to_string(),
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".to_string(),
        port: local_port,
        username: String::new(),
        password: String::new(),
        country: String::new(),
        notes: String::new(),
    }
}

/// The `--proxy-server` arg the engine must receive for an Xray profile.
/// Always local; the upstream address must never reach the engine here.
pub fn local_proxy_server_arg(local_port: u16) -> String {
    format!("socks5://127.0.0.1:{local_port}")
}

/// Resolve the Xray sidecar binary: explicit env override first, then
/// next to the launcher executable, then the dev checkout layout.
/// Tauri packages sidecars next to the app binary; the dev fallback is
/// only for running from a source checkout.
pub fn resolve_xray_binary() -> Result<PathBuf, String> {
    if let Ok(p) = std::env::var("SHARD_XRAY_BIN") {
        let pb = PathBuf::from(&p);
        if pb.exists() {
            return Ok(pb);
        }
        return Err(format!("SHARD_XRAY_BIN points to a missing file: {p}"));
    }
    let target = std::env::consts::ARCH;
    let _ = target;
    // Rust target triple is not std::env::consts; use the host triple via
    // the download script's naming for the common cases, and fall back to
    // scanning the binaries dir for any xray-* file.
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("binaries"));
            candidates.push(dir.to_path_buf());
        }
    }
    candidates.push(PathBuf::from("src-tauri/binaries"));
    for dir in candidates {
        if let Ok(entries) = std::fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with("xray-") && !name.ends_with(".json") && !name.ends_with(".txt") {
                    return Ok(entry.path());
                }
            }
        }
        // Also try the exact sidecar name for this platform's common triple.
        for triple in ["x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-unknown-linux-gnu"] {
            let p = dir.join(sidecar_binary_name(triple));
            if p.exists() {
                return Ok(p);
            }
        }
    }
    Err(
        "Xray sidecar binary not found. Run `node src-tauri/tools/download-xray.mjs` \
         first, or set SHARD_XRAY_BIN to the binary path."
            .to_string(),
    )
}

pub fn start_xray_for_profile(profile_id: &str, link: &str) -> Result<ProxyEntry, String> {
    let parsed = parse_share_link(link).map_err(|e| format!("invalid Xray share link: {e}"))?;
    let binary = resolve_xray_binary()?;
    let port = free_port().map_err(|e| format!("no free local port for Xray: {e}"))?;
    // Stop a previous sidecar for this profile first, so a relaunch cannot
    // leave two Xray processes behind.
    stop_xray_for_profile(profile_id);
    let sidecar = XraySidecar::start(&binary, &parsed, profile_id, port)?;
    let entry = local_proxy_entry(port);
    if let Ok(mut g) = registry().lock() {
        g.insert(profile_id.to_string(), sidecar);
    }
    Ok(entry)
}

pub fn stop_xray_for_profile(profile_id: &str) {
    if let Ok(mut g) = registry().lock() {
        if let Some(mut sidecar) = g.remove(profile_id) {
            sidecar.stop();
        }
    }
}

pub fn xray_running_for(profile_id: &str) -> bool {
    registry()
        .lock()
        .map(|g| g.contains_key(profile_id))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_entry_is_socks5_localhost_and_arg_is_local() {
        let entry = local_proxy_entry(18080);
        assert_eq!(entry.host, "127.0.0.1");
        assert_eq!(entry.port, 18080);
        assert!(matches!(entry.kind, ProxyKind::Socks5));
        assert_eq!(entry.to_proxy_server_arg(), "socks5://127.0.0.1:18080");
        assert_eq!(local_proxy_server_arg(18080), "socks5://127.0.0.1:18080");
    }

    #[test]
    fn start_with_bad_link_fails_without_sidecar() {
        let err = start_xray_for_profile("test-no-xray", "not-a-link").unwrap_err();
        assert!(err.contains("invalid Xray share link"));
        assert!(!xray_running_for("test-no-xray"));
    }

    #[test]
    fn missing_binary_reports_download_step() {
        std::env::remove_var("SHARD_XRAY_BIN");
        // In a checkout without binaries/, resolve must explain itself.
        // This test only asserts the error is actionable, not the exact path.
        if let Err(e) = resolve_xray_binary() {
            assert!(e.contains("download-xray") || e.contains("SHARD_XRAY_BIN"));
        }
    }
}
