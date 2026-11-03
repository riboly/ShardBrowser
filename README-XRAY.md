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

Status: DONE 2026-11-03. Parser in src-tauri/src/space/local/xray_share.rs, 12 unit tests pass (standalone crate, same deps). Non-Xray schemes error so callers fall back to the existing path.

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

## 2026-11-03 (evening): hy2 test failure, root cause in the log

The test sidecar's own log said it plainly: Xray 26.3.27 refuses
`allowInsecure` at config load ("removed and migrated to
pinnedPeerCertSha256"). The launcher emitted `allowInsecure: true`
for any hy2 link with `insecure=1`, so the sidecar died at once and
the health check burned the full 30 s on a dead process, which is
why the test showed a generic timeout. Fixed: no `allowInsecure`
is emitted at all; a link's `insecure=1` is honoured only through
its `pinSHA256` (the pin replaces CA verification). A link with
`insecure=1` and no pin gets plain CA verification — 26.3.27
offers no other skip. The health check now also fails at once when
the sidecar exits during startup, with its exit status, instead of
waiting out the timeout. The sidecar spawn and the `xray version`
probe both set CREATE_NO_WINDOW on Windows, so no black console
window pops up on profile start.

## Current status

- 2026-11-03: Fork created (riboly/ShardBrowser), branch feature/xray-proxy
  created from upstream main (880fef1).
- 2026-11-03: Module 1 DONE (share-link parsing, 12 tests).
  Module 2 DONE (Xray v26.3.27 pinned, SHA256 table + download script, 4 tests).
  Module 3 DONE (config builder + sidecar lifecycle, fail closed, 4 tests).
  Module 4 DONE in code (launch.rs starts Xray sidecar, engine gets local
  SOCKS5, watcher stops sidecar on profile stop). Full Linux `cargo check`
  is blocked by a missing libclang (system apt lock held by a runtime
  replay process); file parses via rustfmt, but full compile is NOT yet
  verified on Linux. Windows Actions build is the real verification.
- 2026-11-03: Module 5 backend DONE (bulk parse, bind/unbind to profile,
  test-through-Xray, Tauri commands + frontend API, 3 import tests).
  NOT yet done: a button in the profile editor UI that calls these
  commands, and end-to-end launch/stop verification with a real node and
  the Windows build. Those are the remaining steps before claiming the
  feature works end to end.
- 2026-11-03: Per-profile nodes, confirmed in code and tests. Each
  profile stores its own `_meta.xray_link`; launch allocates a free
  local port per profile and starts a sidecar keyed by profile_id, so
  two profiles can use two different nodes at once without sharing a
  port or a tunnel. `save_raw` carries a bound link through a plain
  form edit (a content edit only — a meta-only write with no link is
  an explicit unbind and is respected). Profile editor UI added:
  Proxy tab → Xray row (paste link, backend-validated as typed on a
  300 ms debounce like Donut's proxy form, Parse, Test through a
  temporary sidecar showing exit IP/country/latency, Unbind), in
  zh/en/ru; team profiles show no Xray row (personal-space only).
- 2026-11-03 (supersedes the row above): Xray nodes are first-class
  PROXIES, not profile-form bindings — the profile-form Xray row was
  the wrong place and is removed. An Xray node is added in the proxy
  page like a SOCKS5 entry (Add proxies → paste share links, or the
  edit dialog's Xray share-link field; `ProxyEntry.kind == "xray"`,
  full link in `xray_link`, host/port derived from the link), tested
  in the proxy page (temporary sidecar, exit IP/country/latency
  recorded under the entry's own id), and picked in any profile's
  proxy picker like any other proxy. Two profiles use two nodes by
  picking two entries. Legacy `_meta.xray_link` bindings are migrated
  once at startup into proxy entries (profile re-pointed at the new
  entry); the launch fallback still honours an unmigrated binding.
  Sidecar binary: the previous "binary not found" on an installed
  build was a lookup bug — Tauri bundles the sidecar under its bare
  name (`xray.exe`) next to the app, but the lookup only accepted
  `xray-<triple>.exe`. The lookup now accepts both, version-checks
  the binary against the pinned v26.3.27, and, when no bundled binary
  exists (a portable copy), downloads the pinned archive direct
  (never through a local proxy), verifies SHA256, extracts only the
  binary into the launcher's own data dir. v2rayN coexistence: the
  launcher never reads, writes or runs v2rayN's Xray, never shares a
  port (free local ports only), a config file (shard-xray-* temp
  files only) or a process with it, and orphan cleanup only kills
  pids from pid files this launcher wrote whose command lines
  reference a shard-xray config; a different-version xray.exe found
  in a scanned folder is rejected by the version guard.
- 2026-11-03: Donut reference adopted, UI aside. Donut
  (`donutbrowser/donutbrowser`, `src-tauri/src/xray/`,
  `xray_worker_runner.rs`, `proxy-form-dialog.tsx`) stores an Xray
  node as a proxy object with a `vless_uri` and validates the link
  through the backend before it counts; Shard keeps the different
  shape (a link bound to a profile, not a shared proxy object),
  because Shard profiles already bind one proxy each. What was taken
  from Donut, verbatim in behaviour: (1) the local inbound uses a
  random username/password per start (`auth: "password"`), and the
  engine's `--proxy-server` arg carries those credentials via
  `to_proxy_server_arg()` — an open local SOCKS would let any local
  process use the tunnel; (2) readiness is a SOCKS5 auth handshake,
  not a TCP connect; (3) the start timeout is 30 s, because a first
  start on Windows can wait for antivirus to scan xray.exe.
  NOT taken from Donut: its Hysteria2 mapping (protocol `hysteria`,
  version 2) — Shard keeps `hysteria2` as its protocol name, and a
  real Hysteria2 node test will decide which mapping is right for
  Xray v26.3.27. NOT yet done: end-to-end launch/stop verification
  with a real node and the Windows build (now Windows-only workflow,
  commit 25d7bb8), and a real-node test of the authenticated local
  inbound through the engine's proxy arg.
