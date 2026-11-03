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
//! Version pin rationale (same as Donut): held at v26.3.27 because
//! from v26.10.21 Xray-core refuses VLESS without TLS/encryption and
//! Trojan without TLS to a public address, which would break old
//! share links. Upgrading Xray is a separate, explicitly approved
//! task, never a side effect of an upstream sync.

use std::path::Path;

pub const XRAY_VERSION: &str = "v26.3.27";

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
            sha256: "2e93a67e8aa1936ecefb307e120830fcbd4c643ab9b1c46a2d0838d5f8409eaf",
        },
        "x86_64-apple-darwin" => XrayAsset {
            target: "x86_64-apple-darwin",
            file_name: "Xray-macos-64.zip",
            sha256: "f5e0471d3459eff1b82e48af0aeac186abcc3298210070afbbbd8437a4e8b203",
        },
        "x86_64-unknown-linux-gnu" => XrayAsset {
            target: "x86_64-unknown-linux-gnu",
            file_name: "Xray-linux-64.zip",
            sha256: "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
        },
        "aarch64-unknown-linux-gnu" => XrayAsset {
            target: "aarch64-unknown-linux-gnu",
            file_name: "Xray-linux-arm64-v8a.zip",
            sha256: "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
        },
        "x86_64-pc-windows-msvc" => XrayAsset {
            target: "x86_64-pc-windows-msvc",
            file_name: "Xray-windows-64.zip",
            sha256: "d004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad",
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
