//! Xray-core binary packaging (Module 2 of the Xray fork).
//!
//! The binary itself is NEVER committed to git. At build time
//! `tools/download-xray.mjs` downloads the pinned release asset from
//! XTLS/Xray-core, verifies its SHA256 in memory, and extracts only the
//! `xray` binary + LICENSE into `src-tauri/binaries/`, where Tauri
//! packages it as a sidecar. This module is the Rust side of that
//! contract: the pinned version, the per-target asset table, and
//! checksum verification for an already-downloaded binary.
//!
//! Version pin rationale: pinned to the latest stable, not to an old
//! release. v26.3.27 was the pin until 2026-11-10, when three of the
//! user's servers were blocked: a 26.3.27 client sends the old-style
//! REALITY handshake (no X25519MLKEM768 key share, old client version
//! in the session id), which current traffic analysis can tell apart
//! from a real browser. The current pin is v26.11.9 (2026-11-09).
//! Trade-off, enforced at import (see xray_share.rs): since core
//! 26.7.11 a plaintext VLESS (no TLS, no VLESS Encryption) or Trojan
//! to a public address is refused by the core itself, so such links
//! are rejected at import instead of killing the sidecar at launch.
//! Upgrading Xray is a separate, explicitly approved task, never a
//! side effect of an upstream sync.

use std::path::Path;

pub const XRAY_VERSION: &str = "v26.11.9";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XrayAsset {
    pub target: &'static str,
    pub file_name: &'static str,
    pub sha256: &'static str,
}

/// Assets verified against Donut's pinned table for the same version.
/// SHA256 values are for the release ZIP archives, not the extracted binary.
pub fn asset_for_target(target: &str) -> Option<XrayAsset> {
    let asset = match target {
        "aarch64-apple-darwin" => XrayAsset {
            target: "aarch64-apple-darwin",
            file_name: "Xray-macos-arm64-v8a.zip",
            sha256: "233f0c66681cd0726f81a6b2b6ed6a5710869e312047b522e46ed53035bebd26",
        },
        "x86_64-apple-darwin" => XrayAsset {
            target: "x86_64-apple-darwin",
            file_name: "Xray-macos-64.zip",
            sha256: "488963e676e06f5e48547f9dd38116aaca8de4234959b4272ae8f284e658dfd0",
        },
        "x86_64-unknown-linux-gnu" => XrayAsset {
            target: "x86_64-unknown-linux-gnu",
            file_name: "Xray-linux-64.zip",
            sha256: "b651f7e1d9966ee2c1b1ee1bf8b52c72771824d3065dce96bbc8bcc19ed95f82",
        },
        "aarch64-unknown-linux-gnu" => XrayAsset {
            target: "aarch64-unknown-linux-gnu",
            file_name: "Xray-linux-arm64-v8a.zip",
            sha256: "64ed6858982a7f5eb85d88b811089063bd4f17561f4c8f44e0f1dc8e6f6430be",
        },
        "x86_64-pc-windows-msvc" => XrayAsset {
            target: "x86_64-pc-windows-msvc",
            file_name: "Xray-windows-64.zip",
            sha256: "1262522266337b824f07beb8e1375786b437683b3890105469088f8e17e0a69d",
        },
        _ => return None,
    };
    Some(asset)
}

pub fn download_url(asset: &XrayAsset) -> String {
    format!(
        "https://github.com/XTLS/Xray-core/releases/download/{}/{}",
        XRAY_VERSION, asset.file_name
    )
}

/// Tauri sidecar binary name for a target, as placed in `src-tauri/binaries/`.
pub fn sidecar_binary_name(target: &str) -> String {
    if target.contains("windows") {
        format!("xray-{target}.exe")
    } else {
        format!("xray-{target}")
    }
}

/// Verify a file's SHA256 against `expected` (lowercase hex).
/// Returns Ok(true) on match, Ok(false) on mismatch, Err on I/O failure.
/// A mismatch must fail the build; never fall back to an unverified binary.
pub fn verify_sha256(path: &Path, expected: &str) -> std::io::Result<bool> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual = format!("{:x}", hasher.finalize());
    Ok(actual.eq_ignore_ascii_case(expected))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn all_pinned_targets_resolve() {
        for target in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "x86_64-unknown-linux-gnu",
            "aarch64-unknown-linux-gnu",
            "x86_64-pc-windows-msvc",
        ] {
            let asset = asset_for_target(target).expect("pinned target must resolve");
            assert_eq!(asset.sha256.len(), 64);
            assert!(asset.file_name.ends_with(".zip"));
            assert!(download_url(&asset).contains(XRAY_VERSION));
        }
    }

    #[test]
    fn unknown_target_resolves_to_none() {
        assert!(asset_for_target("wasm32-unknown-unknown").is_none());
        assert!(asset_for_target("").is_none());
    }

    #[test]
    fn windows_sidecar_has_exe_suffix() {
        assert_eq!(
            sidecar_binary_name("x86_64-pc-windows-msvc"),
            "xray-x86_64-pc-windows-msvc.exe"
        );
        assert_eq!(
            sidecar_binary_name("x86_64-unknown-linux-gnu"),
            "xray-x86_64-unknown-linux-gnu"
        );
    }

    #[test]
    fn verify_sha256_matches_and_mismatches() {
        let dir = std::env::temp_dir();
        let path = dir.join("shard-xray-sha-test.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"test").unwrap();
        }
        // SHA256("test")
        assert!(verify_sha256(
            &path,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        )
        .unwrap());
        assert!(!verify_sha256(&path, "0000000000000000000000000000000000000000000000000000000000000000").unwrap());
        let _ = std::fs::remove_file(&path);
    }
}
