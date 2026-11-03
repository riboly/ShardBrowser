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

    /// Per-profile isolation: two profiles bind different nodes, and
    /// neither one's link, masked display or proxy state leaks into the
    /// other. This is the test the "one node per profile" claim rests on.
    #[test]
    fn two_profiles_keep_different_links() {
        let mut a = stored();
        let mut b = stored();
        a.meta.id = "profile-a".to_string();
        b.meta.id = "profile-b".to_string();
        let masked_a = bind_link(
            &mut a,
            "vless://11111111-2222-3333-4444-555555555555@node-a.invalid:443#node-a",
        )
        .unwrap();
        let masked_b = bind_link(&mut b, "trojan://secret-pass@node-b.invalid:8443#node-b").unwrap();
        assert_eq!(masked_a, "vless://node-a.invalid:443");
        assert_eq!(masked_b, "trojan://node-b.invalid:8443");
        assert_ne!(a.meta.xray_link, b.meta.xray_link);
        assert!(a.meta.xray_link.as_deref().unwrap().contains("node-a.invalid"));
        assert!(b.meta.xray_link.as_deref().unwrap().contains("node-b.invalid"));
        // Neither masked display may carry the other profile's credential.
        assert!(!masked_a.contains("secret-pass"));
        assert!(!masked_b.contains("11111111"));
    }

    #[test]
    fn binding_one_profile_leaves_the_other_untouched() {
        let mut a = stored();
        let mut b = stored();
        b.meta.proxy_id = Some("b-proxy".to_string());
        bind_link(&mut b, "trojan://pass@node-b.invalid:443#node-b").unwrap();
        // A is bound afterwards: B keeps its link and its proxy state
        // (bind clears only the profile it is called on, and B's proxy
        // was already cleared by its own bind, not by A's).
        bind_link(
            &mut a,
            "vless://11111111-2222-3333-4444-555555555555@node-a.invalid:443#node-a",
        )
        .unwrap();
        assert_eq!(b.meta.xray_link.as_deref(), Some("trojan://pass@node-b.invalid:443#node-b"));
        assert!(b.meta.proxy_id.is_none());
        assert_eq!(a.meta.xray_link.as_deref(), Some("vless://11111111-2222-3333-4444-555555555555@node-a.invalid:443#node-a"));
    }

    #[test]
    fn unbinding_one_profile_leaves_the_other_bound() {
        let mut a = stored();
        let mut b = stored();
        bind_link(
            &mut a,
            "vless://11111111-2222-3333-4444-555555555555@node-a.invalid:443#node-a",
        )
        .unwrap();
        bind_link(&mut b, "trojan://pass@node-b.invalid:443#node-b").unwrap();
        unbind_link(&mut a);
        assert!(a.meta.xray_link.is_none());
        assert!(b.meta.xray_link.is_some());
    }

    #[test]
    fn rebinding_replaces_only_that_profiles_link() {
        let mut a = stored();
        let mut b = stored();
        bind_link(
            &mut a,
            "vless://11111111-2222-3333-4444-555555555555@node-a.invalid:443#old",
        )
        .unwrap();
        bind_link(&mut b, "trojan://pass@node-b.invalid:443#node-b").unwrap();
        bind_link(
            &mut a,
            "vless://99999999-8888-7777-6666-555555555555@node-a2.invalid:443#new",
        )
        .unwrap();
        assert!(a.meta.xray_link.as_deref().unwrap().contains("node-a2.invalid"));
        assert_eq!(b.meta.xray_link.as_deref(), Some("trojan://pass@node-b.invalid:443#node-b"));
    }
}
