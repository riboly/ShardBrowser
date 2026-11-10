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
/// Donut-style: it carries the sidecar's random local credentials, so
/// the engine's `--proxy-server` arg (built by `to_proxy_server_arg`,
/// which percent-encodes userinfo) authenticates to the local inbound.
/// An unauthenticated local SOCKS would let any local process use the
/// profile's tunnel.
pub fn local_proxy_entry(local_port: u16, username: &str, password: &str) -> ProxyEntry {
    ProxyEntry {
        id: "xray-local".to_string(),
        name: "Xray (local)".to_string(),
        kind: ProxyKind::Socks5,
        host: "127.0.0.1".to_string(),
        port: local_port,
        username: username.to_string(),
        password: password.to_string(),
        xray_link: None,
        country: String::new(),
        notes: String::new(),
    }
}

/// The `--proxy-server` arg the engine must receive for an Xray profile.
/// Always local; the upstream address must never reach the engine here.
pub fn local_proxy_server_arg(local_port: u16) -> String {
    format!("socks5://127.0.0.1:{local_port}")
}

/// Where a downloaded sidecar lives when no bundled one is found
/// (a portable copy has no bundle). The launcher's own data dir, never
/// v2rayN's or any other tool's folder: this launcher must not read,
/// write or run another tool's Xray, and must not be mistaken for it.
fn downloaded_dir() -> PathBuf {
    let base = dirs::data_dir()
        .or_else(dirs::data_local_dir)
        .unwrap_or_else(std::env::temp_dir);
    base.join("shardbrowser-xray")
}

/// The host's Rust target triple, for the pinned asset table.
fn host_triple() -> Option<&'static str> {
    if cfg!(target_os = "windows") {
        Some("x86_64-pc-windows-msvc")
    } else if cfg!(target_os = "macos") {
        if cfg!(target_arch = "aarch64") {
            Some("aarch64-apple-darwin")
        } else {
            Some("x86_64-apple-darwin")
        }
    } else if cfg!(target_arch = "aarch64") {
        Some("aarch64-unknown-linux-gnu")
    } else {
        Some("x86_64-unknown-linux-gnu")
    }
}

/// A binary is ours only if it reports the pinned Xray version. This
/// is the v2rayN guard: a user who already runs v2rayN has an xray.exe
/// of its own, possibly in a folder this launcher also looks in. A
/// different version is never run as this launcher's sidecar, whatever
/// its name; the pinned one is downloaded instead.
fn binary_version_ok(path: &PathBuf) -> bool {
    let mut cmd = std::process::Command::new(path);
    cmd.arg("version");
    #[cfg(target_os = "windows")]
    {
        // The version probe runs on every test and launch: without this
        // it flashes a console window just like the sidecar did.
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let Ok(out) = cmd.output() else {
        return false;
    };
    let text = String::from_utf8_lossy(&out.stdout);
    // `xray version` prints "Xray 26.11.9 (...)", with no "v": checking
    // for the tag form "v26.11.9" rejected every genuine binary, so
    // every Xray test fell through to a download that then failed the
    // same check. Compare the bare number.
    let pinned = super::xray_binary::XRAY_VERSION
        .strip_prefix('v')
        .unwrap_or(super::xray_binary::XRAY_VERSION);
    out.status.success() && text.starts_with("Xray ") && text.contains(pinned)
}

/// Candidate binaries, most launcher-controlled first: an env override,
/// a previously downloaded one, the dev checkout, then the bundled
/// sidecar next to the app. Tauri bundles the sidecar under its bare
/// name (`xray.exe`) next to the app binary — the previous lookup only
/// accepted `xray-<triple>.exe`, which is why an installed build
/// reported "binary not found" while the file was right there.
fn candidate_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(p) = std::env::var("SHARD_XRAY_BIN") {
        out.push(PathBuf::from(p));
    }
    if let Some(triple) = host_triple() {
        out.push(downloaded_dir().join(super::xray_binary::sidecar_binary_name(triple)));
    }
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.join("binaries"));
            dirs.push(dir.to_path_buf());
        }
    }
    dirs.push(PathBuf::from("src-tauri/binaries"));
    let bare = if cfg!(windows) { "xray.exe" } else { "xray" };
    for dir in &dirs {
        for triple in ["x86_64-pc-windows-msvc", "x86_64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-apple-darwin", "aarch64-unknown-linux-gnu"] {
            out.push(dir.join(super::xray_binary::sidecar_binary_name(triple)));
        }
        out.push(dir.join(bare));
    }
    out
}

/// Resolve the Xray sidecar binary: explicit env override first, then
/// the launcher's own download dir, then next to the launcher
/// executable, then the dev checkout layout. A candidate counts only
/// if it exists and reports the pinned version.
pub fn resolve_xray_binary() -> Result<PathBuf, String> {
    for cand in candidate_paths() {
        if cand.exists() && binary_version_ok(&cand) {
            return Ok(cand);
        }
    }
    Err(
        "Xray sidecar binary not found. Run `node src-tauri/tools/download-xray.mjs`          first, or set SHARD_XRAY_BIN to the binary path."
            .to_string(),
    )
}

/// One download attempt: direct when `direct` is set, otherwise
/// through whatever proxy the system environment names.
async fn fetch_archive(url: &str, direct: bool) -> Result<Vec<u8>, String> {
    let builder = reqwest::Client::builder();
    let builder = if direct { builder.no_proxy() } else { builder };
    let client = builder
        .build()
        .map_err(|e| format!("failed to build download client: {e}"))?;
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("failed to download Xray: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("failed to download Xray: HTTP {}", resp.status()));
    }
    // Vec, not bytes::Bytes: naming that type would need `bytes` as a
    // direct dependency, and it is only in the tree via reqwest.
    resp.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("failed to read Xray download: {e}"))
}

/// Ensure a pinned sidecar exists, downloading it on first use when
/// no bundled one is found (the portable copy's case). The archive is
/// verified by SHA256 in memory before anything is written, only the
/// `xray` binary is extracted, and it is version-checked before use.
/// Download tries direct first, then the system proxy: direct GitHub
/// is unreachable from some networks, and a failed download must not
/// be the reason an installed build's tests all fail. This is only a
/// one-off file fetch, never proxy traffic through another tool.
pub async fn ensure_xray_binary() -> Result<PathBuf, String> {
    if let Ok(p) = resolve_xray_binary() {
        return Ok(p);
    }
    let triple = host_triple().ok_or_else(|| "no pinned Xray asset for this platform".to_string())?;
    let asset = super::xray_binary::asset_for_target(triple)
        .ok_or_else(|| format!("no pinned Xray asset for target {triple}"))?;
    let url = super::xray_binary::download_url(&asset);
    let bytes = match fetch_archive(&url, true).await {
        Ok(b) => b,
        Err(direct_err) => fetch_archive(&url, false).await.map_err(|proxy_err| {
            format!("failed to download Xray {triple}: direct failed ({direct_err}); via system proxy also failed ({proxy_err})")
        })?,
    };
    {
        use sha2::Digest;
        let actual = format!("{:x}", sha2::Sha256::digest(&bytes));
        if actual != asset.sha256 {
            return Err("Xray download checksum mismatch; refusing to run it".to_string());
        }
    }
    let reader = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| format!("bad Xray archive: {e}"))?;
    let want = if cfg!(windows) { "xray.exe" } else { "xray" };
    let mut found: Option<Vec<u8>> = None;
    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| format!("bad Xray archive entry: {e}"))?;
        if entry.name() == want {
            let mut buf = Vec::new();
            use std::io::Read;
            entry.read_to_end(&mut buf).map_err(|e| format!("failed to extract Xray: {e}"))?;
            found = Some(buf);
            break;
        }
    }
    let bin = found.ok_or_else(|| format!("Xray archive has no {want} binary"))?;
    let dir = downloaded_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("failed to create Xray dir: {e}"))?;
    let dest = dir.join(super::xray_binary::sidecar_binary_name(triple));
    std::fs::write(&dest, &bin).map_err(|e| format!("failed to write Xray binary: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755));
    }
    if !binary_version_ok(&dest) {
        let _ = std::fs::remove_file(&dest);
        return Err("downloaded Xray did not report the pinned version; refusing to run it".to_string());
    }
    Ok(dest)
}

pub fn start_xray_for_profile_with_binary(profile_id: &str, link: &str, binary: &PathBuf) -> Result<ProxyEntry, String> {
    let parsed = parse_share_link(link).map_err(|e| format!("invalid Xray share link: {e}"))?;
    let binary = binary.clone();
    let port = free_port().map_err(|e| format!("no free local port for Xray: {e}"))?;
    // Stop a previous sidecar for this profile first, so a relaunch cannot
    // leave two Xray processes behind.
    stop_xray_for_profile(profile_id);
    let sidecar = XraySidecar::start(&binary, &parsed, profile_id, port)?;
    let entry = local_proxy_entry(port, &sidecar.local_user, &sidecar.local_pass);
    if let Ok(mut g) = registry().lock() {
        g.insert(profile_id.to_string(), sidecar);
    }
    Ok(entry)
}

/// Synchronous start for callers that already resolved a binary
/// (tests, and any path that ran `ensure_xray_binary` first and kept
/// the path). Production launch and test paths await `ensure` and
/// call `start_xray_for_profile_with_binary` with its result.
pub fn start_xray_for_profile(profile_id: &str, link: &str) -> Result<ProxyEntry, String> {
    let binary = resolve_xray_binary()?;
    start_xray_for_profile_with_binary(profile_id, link, &binary)
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
        let entry = local_proxy_entry(18080, "u1", "p1");
        assert_eq!(entry.host, "127.0.0.1");
        assert_eq!(entry.port, 18080);
        assert!(matches!(entry.kind, ProxyKind::Socks5));
        // Donut-style local auth travels in the engine arg, percent-encoded.
        assert_eq!(entry.to_proxy_server_arg(), "socks5://u1:p1@127.0.0.1:18080");
        assert_eq!(local_proxy_server_arg(18080), "socks5://127.0.0.1:18080");
    }

    #[test]
    fn start_with_bad_link_fails_without_sidecar() {
        let err = start_xray_for_profile("test-no-xray", "not-a-link").unwrap_err();
        assert!(err.contains("invalid Xray share link"));
        assert!(!xray_running_for("test-no-xray"));
    }

    #[test]
    fn non_xray_binary_fails_version_guard() {
        // A v2rayN binary of another version, or any other executable
        // in a scanned folder, must never be accepted as this
        // launcher's pinned sidecar.
        let dir = std::env::temp_dir();
        let path = dir.join("shard-xray-version-guard-test.txt");
        std::fs::write(&path, b"not an xray binary").unwrap();
        assert!(!binary_version_ok(&path));
        let _ = std::fs::remove_file(&path);
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
