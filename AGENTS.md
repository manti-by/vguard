# AGENTS.md

## What this is

`VGuard` — macOS menu-bar kill switch (single Swift file, no Xcode project). Blocks all
network traffic via pf while neither GlobalProtect nor WireGuard is connected. Modelled on
`../archive/keenetic` (same layout/build style).

## Commands

- Build: `make build`; diagnostics (no root): `make check` / `./dist/VGuard --check`
- Bundle / install app: `make bundle`, `make install` (→ `/Applications/VGuard.app`)
- Daemon: `make install-daemon` / `make uninstall-daemon` (sudo)
- No tests. `swiftc` warnings + `make check` + `pfctl -n -a com.apple/vguard -f <rules>` (parse-only, no root) are the verification.

## Layout

- `main.swift` — everything. Modes: no args = tray app; `--daemon` = root pf daemon;
  `--check` = print detection + generated rules.
- `com.vguard.daemon.plist` — LaunchDaemon; binary is copied to
  `/Library/PrivilegedHelperTools/com.vguard.daemon` (root-owned on purpose: a daemon running
  a binary from user-writable `/Applications` would be a privilege escalation).
- `Info.plist` (`LSUIElement`), `media/AppIcon.icns` (rendered from SF Symbol `lock.shield.fill`).

## Facts / gotchas

- GlobalProtect is not an NE VPN — it doesn't appear in `scutil --nc list`; it publishes
  service `gpd.pan` in the dynamic store. WireGuard.app does appear there (`com.wireguard.macos`).
- pf rules live in anchor `com.apple/vguard` so the stock `/etc/pf.conf` (`anchor "com.apple/*"`)
  evaluates them without editing system files. `quick` inside the anchor ends evaluation globally.
- pf is enabled with `pfctl -E` (ref-counted token, saved to `/var/run/vguard.pftoken`) and
  released with `pfctl -X` when unblocking.
- On crash the rules stay loaded (fail closed); on SIGTERM (launchctl bootout) the daemon flushes them.
- IPC: notify(3) names `com.vguard.status|reload|resume` + world-readable `status.json`.
  Privileged writes from the tray (config, pause, daemon install) go through
  `do shell script … with administrator privileges`. Resume is unprivileged (only makes things stricter).
