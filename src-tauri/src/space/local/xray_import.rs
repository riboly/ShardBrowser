//! Bulk import + profile binding for Xray share links (Module 5).
//!
//! This module is deliberately pure where it can be:
//! - `import_lines` parses one link per line, never aborts the whole
//!   batch on one bad line, and never returns a full link, password or
//!   UUID. Results carry only the line number, display name, protocol
//!   and masked `scheme://host:port` (or an error for that line).
//! - `bind_link` validates a link and writes it into a profile's
//!   `_meta.xray_link`. Binding an Xray link clears any bound proxy
//!   (`proxy_id` / `inline_proxy`): at launch, Xray takes precedence,
//!   and keeping both would make the launch path ambiguous.
//! - `unbind_link` clears `_meta.xray_link` again.
//!
//! The actual save to disk lives in `space::xray` (personal space only),
//! because `save_raw` is `pub(in crate::space)`. The test-through-Xray
//! path also lives there, because it needs `space::proxy::full_test`.

use super::xray_share::{parse_share_link, ParsedShareLink, XrayProtocol};
use super::profile::StoredProfile;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XrayImportResult {
    pub line: usize,
    pub ok: bool,
    pub name: Option<String>,
    pub protocol: Option<String>,
    pub masked: Option<String>,
    pub error: Option<String>,
}

pub fn import_lines(text: &str) -> Vec<XrayImportResult> {
    let mut out = Vec::new();
    for (i, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        match parse_share_link(line) {
            Ok(parsed) => out.push(XrayImportResult {
                line: i + 1,
                ok: true,
                name: if parsed.name.is_empty() { None } else { Some(parsed.name.clone()) },
                protocol: Some(parsed.protocol.as_str().to_string()),
                masked: Some(parsed.masked_display()),
                error: None,
            }),
            Err(e) => out.push(XrayImportResult {
                line: i + 1,
                ok: false,
                name: None,
                protocol: None,
                masked: None,
                error: Some(e),
            }),
        }
    }
    out
}

/// Validate `link` and bind it to `stored`. Returns the masked display.
pub fn bind_link(stored: &mut StoredProfile, link: &str) -> Result<String, String> {
    let parsed: ParsedShareLink =
        parse_share_link(link.trim()).map_err(|e| format!("invalid Xray share link: {e}"))?;
    stored.meta.xray_link = Some(link.trim().to_string());
    stored.meta.proxy_id = None;
    stored.meta.inline_proxy = None;
    Ok(parsed.masked_display())
}

pub fn unbind_link(stored: &mut StoredProfile) {
    stored.meta.xray_link = None;
}

#[allow(dead_code)]
fn _protocol_name(p: &XrayProtocol) -> &'static str {
    p.as_str()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored() -> StoredProfile {
        StoredProfile::default()
    }

    #[test]
    fn bulk_import_mixes_valid_and_bad_lines() {
        let text = "vless://11111111-2222-3333-4444-555555555555@example.invalid:443#one\n\nnot-a-link\ntrojan://pass@example.invalid:443#two\n";
        let results = import_lines(text);
        assert_eq!(results.len(), 3);
        assert!(results[0].ok);
        assert_eq!(results[0].line, 1);
        assert_eq!(results[0].masked.as_deref(), Some("vless://example.invalid:443"));
        assert!(!results[1].ok);
        assert_eq!(results[1].line, 3);
        assert!(results[2].ok);
        // No result may ever carry a credential.
        let json = serde_json::to_string(&results).unwrap();
        assert!(!json.contains("11111111-2222-3333-4444"));
        assert!(!json.contains("pass@"));
    }

    #[test]
    fn bind_clears_bound_proxy_and_unbind_clears_link() {
        let mut s = stored();
        s.meta.proxy_id = Some("old-proxy".to_string());
        let masked = bind_link(
            &mut s,
            "vless://11111111-2222-3333-4444-555555555555@example.invalid:443#x",
        )
        .unwrap();
        assert_eq!(masked, "vless://example.invalid:443");
        assert!(s.meta.xray_link.is_some());
        assert!(s.meta.proxy_id.is_none());
        assert!(s.meta.inline_proxy.is_none());
        unbind_link(&mut s);
        assert!(s.meta.xray_link.is_none());
    }

    #[test]
    fn bind_rejects_bad_link_without_changing_profile() {
        let mut s = stored();
        assert!(bind_link(&mut s, "socks5://example.invalid:1080").is_err());
        assert!(s.meta.xray_link.is_none());
    }
}
