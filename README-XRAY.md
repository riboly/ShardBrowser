# ShardBrowser Fork: Xray Proxy Support (feature/xray-proxy)

> Fork-only document. This file does NOT exist in upstream ProxyShard/ShardBrowser.
> It is kept separate from upstream README.md on purpose: editing upstream README.md
> on every sync would create a rebase conflict every time upstream touches it.
> Future AI maintenance must read this file first, before touching proxy or launch code.

## Goal

Add Xray-core as a sidecar to the ShardBrowser launcher so a profile can import
proxy share links directly (VLESS / VMess / Trojan / Shadowsocks / Hysteria2),
while keeping the existing SOCKS5 / HTTP / HTTPS proxy path untouched.

Current upstream limitation (verified 2026-11-03):
ProxyEntry only supports kind = socks5 | http | https (host + port + user/pass),
and launch passes it straight to the engine as `--proxy-server`. A VLESS-style
share link cannot be parsed by that model, so import fails before launch.

## Design principle

- Launcher-only change. Do NOT modify the closed patched Chromium engine.
- Xray translates upstream -> local SOCKS5. The engine still receives only a
  local `--proxy-server=socks5://127.0.0.1:<port>`, exactly as today.
- Never commit Xray binaries, never commit real proxy passwords / UUIDs / links.
  Test fixtures must use example.invalid hosts and test UUIDs only.
- Xray version is pinned separately from upstream sync (see Module 2).

## Module 1: Share-link parsing (START HERE)

Status: NOT implemented yet. This is the first task.

1.1 Supported schemes (in order):
  - vless://, vmess://, trojan://, ss://, shadowsocks://, hysteria2://, hy2://
  - socks5://, http://, https:// remain passthrough to the existing path, no change.
1.2 Parse, per scheme:
  - User info: UUID / password, URL-decoded, fragment (#name) -> proxy display name.
  - Query params: security/tls, sni, alpn, host, path, type (ws/grpc/tcp/reality),
    flow, encryption, serviceName, etc. Unknown params must be kept, not dropped silently.
  - VMess: base64 JSON decode (standard + URL-safe, with/without padding),
    fields: address, port, id, aid, net, tls, host, path, sni.
  - Shadowsocks: both plain `ss://method:password@host:port` and base64 forms.
1.3 Validation (fail fast, per link, with a clear error):
  - Missing host, port out of range, missing UUID/password where required.
  - Malformed base64 / JSON must not crash the importer; report the line number.
  - Never log the full link, password or UUID. Logs may show scheme + host + port only.
1.4 Storage model:
  - Keep existing ProxyEntry (socks5/http/https) for backward compatibility.
  - Add a new Xray proxy record: original link (encrypted at rest like other
    proxy passwords, if the launcher already encrypts them), parsed normalized
    fields, upstream type, and a derived local port (assigned at launch, not at import).
  - Import must be idempotent: same link imported twice -> one record, second is a duplicate warning.
1.5 Tests (must pass before moving to Module 2):
  - At least one valid + one malformed case per scheme above.
  - Regression: existing socks5/http/https parsing and bulk import unchanged.

## Module 2: Xray binary packaging

2.1 Pin Xray-core v26.3.27 (same pin as Donut). Do NOT track latest automatically:
  from v26.10.21 Xray refuses VLESS without TLS/encryption and Trojan without TLS
  to a public address, which would break old share links.
2.2 Per-platform assets with SHA256 verification (Windows x64, macOS arm64/x64,
  Linux x64/arm64), downloaded at build time, like Donut `download-xray.mjs`.
2.3 Ship the Xray LICENSE file with the binary. Binary itself goes to .gitignore
  and to the build output only, never to git.
2.4 Build failure if checksum mismatches. No silent fallback to an unverified binary.

## Module 3: Xray config builder + lifecycle

3.1 Build a per-profile Xray client config JSON from the parsed link (Module 1).
3.2 Inbound: local SOCKS5 (and HTTP if needed) on a free port allocated per profile,
  recorded in the profile runtime state, never hard-coded to a single port.
3.3 Lifecycle: start Xray before browser launch, health-check local port listening
  within a timeout, stop Xray when the profile stops, clean up orphan Xray
  processes on launcher start, write per-profile logs to a file (not stdout only).
3.4 Failure mode: if Xray fails to start, the profile must NOT launch with a
  direct connection or with no proxy. Fail closed with the Xray log path shown.

## Module 4: Launch integration

4.1 In launch.rs / runner.rs: if a profile uses an Xray proxy, pass the LOCAL
  Xray SOCKS5 address to `--proxy-server`, not the upstream address.
  Non-Xray profiles keep the current `to_proxy_server_arg()` path unchanged.
4.2 Pre-launch UDP probe (QUIC/WebRTC policy) must probe the LOCAL Xray port
  after Xray is up, not the upstream directly. A failed probe must not silently
  disable UDP for a profile that actually supports it via Xray.
4.3 Timezone / locale / geolocation resolution must use the UPSTREAM exit IP
  (tested through the local Xray port), not 127.0.0.1. Never resolve geo from localhost.
4.4 Profile UI must show: upstream type (e.g. VLESS), upstream host (masked port
  only in logs), local port, and Xray running/stopped status.

## Module 5: Import UI + detection adaptation + tests

5.1 Bulk importer: paste multiple share links, one per line, auto-detect type,
  name from fragment, per-line success/failure list (do not abort the whole batch
  on one bad line).
5.2 Proxy test: test through the local Xray port, show exit IP, country, latency.
  Do not test by connecting the browser directly to the upstream.
5.3 End-to-end checks: create profile with an Xray proxy, launch, verify the
  engine received a local SOCKS5 arg, verify Xray stops on profile stop.
  Real-node E2E requires a user-supplied test node and must never be committed.
5.4 Docs + licenses: update this file when a module lands (status + date),
  keep Xray license notice, keep upstream MIT license unchanged.

## Upstream sync method (for future AI maintenance)

Branch discipline (non-negotiable):
- `main` in this fork = upstream mirror ONLY. Never commit feature code to `main`.
- `feature/xray-proxy` = all Xray work. All future Xray commits go here.
- Fork-only files (this file, Xray download scripts, Xray tests) must never be
  merged into upstream README.md or upstream proxy files by accident.

Sync cycle (run on user request, or at least once a week when upstream moves):
1. Check upstream: fetch ProxyShard/ShardBrowser main, compare HEAD SHA with fork main.
   If unchanged, report nothing and stop (silent is correct).
2. Fast-forward fork `main` to upstream main (Sync fork). Never rebase `main`
   with feature commits, never force-push `main`.
3. Rebase `feature/xray-proxy` onto the new `main`:
   `git rebase upstream/main` (upstream = ProxyShard, not origin).
   Resolve conflicts in this order: proxy model, launch/runner, UI, docs last.
   - For upstream files: prefer upstream, then re-apply the Xray change on top.
   - For fork-only files: keep the fork version.
   - Never accept a whole side blindly, never replace rebase with a merge
     into the feature branch unless the user explicitly approves it.
4. After rebase, verify before pushing:
   - Module 1 unit tests pass, SOCKS5/HTTP regression passes.
   - Build for the Windows portable target at least; do not claim success
     from a typecheck alone.
   - Xray version + SHA in Module 2 unchanged, unless a separate Xray upgrade
     task was explicitly approved.
5. Push ONLY `feature/xray-proxy` with `--force-with-lease` (this branch is
   single-user). Never force-push `main`. Every GitHub push still needs the
   users approval card; a scheduled check alone does NOT authorize a push.
6. Stop conditions (do NOT push a broken branch):
   - Conflict in ProxyEntry / launch arg / Tauri command signatures that changes
     the Xray integration contract and cannot be resolved cleanly.
   - Upstream adds native Xray support itself -> stop and ask the user whether
     to drop this fork feature, keep it, or rebase it onto upstream implementation.
   - Xray binary download or checksum fails -> stop, do not ship an unverified binary.
   In all stop cases, report: upstream SHA, fork SHA, conflict files, and what
   the user needs to decide. Do not silently merge, do not silently skip sync.

AI maintenance limits (state this honestly to the user, every time):
- Fully unattended automatic maintenance is NOT possible: GitHub write
  operations require user approval, and rebase conflicts require human decisions.
- What AI CAN do automatically: check upstream, attempt rebase, run tests,
  and report. What AI CANNOT do alone: push without approval, resolve a
  contract-changing conflict by guessing, or upgrade Xray version silently.

## Current status

- 2026-11-03: Fork created (riboly/ShardBrowser), branch feature/xray-proxy
  created from upstream main (880fef1). No Xray code implemented yet.
  Next task: Module 1, share-link parsing, per the task list above.
