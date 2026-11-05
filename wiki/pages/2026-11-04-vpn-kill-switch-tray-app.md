---
title: VGuard VPN kill-switch tray app
date: 2026-11-04
type: implementation
status: in-progress
session_id: 6fc4c46a-8653-4363-9a59-d991f99c230f
services: [main]
branch: -
tickets: []
tags: [macos, menubar, pf, firewall, globalprotect, wireguard, launchd, kill-switch]
related: []
---

# VGuard VPN kill-switch tray app

## TL;DR

Built VGuard from scratch: a macOS menu-bar app that blocks all network traffic with pf while
neither GlobalProtect nor WireGuard is connected. The icon is a shield when a VPN is up and a red
alert shield when none is. It follows the layout of `../archive/keenetic` (one Swift file, Makefile,
no Xcode). The firewall work happens in a root LaunchDaemon built from the same binary. A follow-up
bug meant a connected WireGuard tunnel wasn't recognised; that's fixed in the source and the
installed app, but the installed daemon still has to be reinstalled (`make install-daemon`, sudo).
Pause, disable, uninstall and emergency-unblock steps are in the README.

---

## Overview

One binary, three modes (**File:** `main.swift:657`):

- **no args** — tray app, runs as the user. Detects VPNs itself, reads the daemon's status, and
  shows the icon and menu.
- **`--daemon`** — runs as root under launchd (`com.vguard.daemon`). Watches the network state and
  loads or flushes the pf rules.
- **`--check`** — diagnostics that need no root: detected VPNs, allowed endpoints, and the pf rules
  it would load.

Key design decisions:

- **Root is required to change pf**, so the work is split: a daemon at
  `/Library/PrivilegedHelperTools/com.vguard.daemon` (root:wheel) plus an unprivileged tray. The
  daemon deliberately does *not* run the binary inside `/Applications`: that folder is
  user-writable, so running it as root would be a privilege escalation.
- **The pf anchor is `com.apple/vguard`.** The stock `/etc/pf.conf` already evaluates
  `anchor "com.apple/*"`, so no system file is edited. A `quick` rule inside the anchor ends
  evaluation for the whole ruleset.
- **pf is enabled with `pfctl -E`**, which is reference-counted. The token is saved to
  `/var/run/vguard.pftoken` and released with `pfctl -X` when unblocking.
- **Fail closed on a crash.** If the daemon crashes, its rules stay loaded. On SIGTERM
  (`launchctl bootout`) it flushes them.
- **IPC between tray and daemon:**
  - notify(3) names `com.vguard.status`, `com.vguard.reload` and `com.vguard.resume`
  - a world-readable status file, `/Library/Application Support/VGuard/status.json`
  - privileged writes from the tray (config, pause, daemon install) go through
    `do shell script … with administrator privileges`
  - Resume needs no password, because it only makes things stricter

## Step 1 — VPN detection via SCDynamicStore

**File:** `main.swift:120`

- **GlobalProtect** is not a Network Extension VPN, so it doesn't appear in `scutil --nc list`.
  It publishes `State:/Network/Service/gpd.pan/IPv4` (`InterfaceName: utun4`) and sets
  `PrimaryService: gpd.pan`.
- **WireGuard.app** is a Network Extension VPN (`[VPN:com.wireguard.macos]`). See Step 5 for how
  to detect it properly.
- **wg-quick** writes `/var/run/wireguard/<name>.name`, which holds the utun interface name.

Both the tray and the daemon register for notifications on
`State:/Network/Service/.*/IPv4`, `State:/Network/Global/IPv4` and
`State:/Network/Interface/.*/IPv4`, so they react immediately. The daemon coalesces bursts of
notifications with a 0.3 s debounce and also re-checks every 10 s as a heartbeat.

## Step 2 — Endpoint auto-discovery (allowed while blocked)

**File:** `main.swift:161`

These addresses stay reachable while traffic is blocked, so a VPN can reconnect:

- **WireGuard** — `Setup:/Network/Service/<id>/VPN` → `RemoteAddress`
  (here `162.243.170.49:51820`; the port is stripped).
- **GlobalProtect** — read recursively from
  `/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist`:
  - the `Portal` key (`vestwellvpn.gpcloudservice.com`)
  - `gateway-address`, in the form `gateway=<host>,ipv4=<ip>,ipv6=`
- **Hostname resolution** runs in the background every 120 s. If a lookup fails, the last
  known IPs are kept.

## Step 3 — pf rules

**File:** `main.swift:269`

The generated anchor has been checked with `pfctl -n -a com.apple/vguard -f <file>` (parse only,
no root needed; exit 0):

```
table <vguard_allow> persist { 137.83.250.55, 137.83.250.56, 162.243.170.49 }
pass quick on lo0 all
pass quick on { utun0 utun1 utun2 utun3 utun4 } all
pass out quick inet proto udp from any port 68 to any port 67     # DHCP (+ DHCPv6, ND)
pass out quick proto { tcp, udp } from any to any port 53          # allowDNS
pass quick inet from any to { 10/8, 172.16/12, 192.168/16, ... }   # allowLAN
pass out quick from any to <vguard_allow>
block return out quick all
block drop in quick all
```

- `block return` on outbound traffic makes apps fail fast instead of hanging.
- Settings are stored in `/Library/Application Support/VGuard/config.json`:
  `allowLAN`, `allowDNS`, `autoDiscover` and `extraHosts`.

## Step 4 — Tray UI, bundle, install

- **Icons** are SF Symbols: `lock.shield` (a template image) when a VPN is up, and
  `exclamationmark.shield.fill` tinted `systemRed` when none is.
- **Menu:**
  - the VPN(s) and firewall state
  - an "Allowed while blocked" submenu
  - Pause for 5 min / 1 h (admin prompt), or Resume
  - "Install Firewall Daemon…" when no fresh status has been written for 30 s
  - Settings…, Refresh and Quit
- **Make targets:** `build`, `bundle`, `install`, `install-daemon`, `uninstall-daemon`, `check`.
- **App icon:** `media/AppIcon.icns` was rendered from `lock.shield.fill` on a blue rounded square
  with a throwaway Swift script and `iconutil`.

## Step 5 — Bug: WireGuard connected but tray showed the alert icon

The symptom: WireGuard was up and the internet worked, but the tray showed the alert icon and
`status.json` reported `vpns: []` with `blocking: true`.

**Root cause:** a running Network Extension tunnel is published under a *fresh* service ID
(`DCE00D06…`) that isn't linked to the configured one (`3FD83188…`) and has no `Setup:` key. As a
result, `isWireGuardService(runtimeID)` never matched. The internet still worked because the
anchor passes traffic on `utun*`, and the default route was going over `utun5`.

**Fix:** for each configured WireGuard service, ask the connection status directly. This is the
same source `scutil --nc` reads. **File:** `main.swift:134`

```swift
let conn = SCNetworkConnectionCreateWithServiceID(nil, sid as NSString as CFString, nil, nil)
SCNetworkConnectionGetStatus(conn) == .connected
// interface: SCNetworkConnectionCopyExtendedStatus(conn)["IPv4"]["InterfaceName"] → utun5
```

**Second bug:** the log said "traffic allowed" every 10 s. macOS `pfctl` prints ALTQ notices on
stderr, which was merged into the output, so an empty anchor looked non-empty and was flushed on
every tick. The fix adds a `run(..., stderr: false)` option for the `-s rules` and `-s info`
queries (**File:** `main.swift:61`). The `-E` call still merges stderr, because that's where the
`Token :` line is printed.

## Test Results

- `swiftc` builds with no warnings.
- `./dist/VGuard --check` with GlobalProtect up: `Active VPNs: GlobalProtect (utun4)`.
- After the fix, with WireGuard up: `Active VPNs: WireGuard “amon-ra” (utun5)`.
- The generated rules pass the pf parse-only check.
- The tray launches, and the icon was confirmed in a menu-bar screenshot.
- **Not verified in this session:**
  - the daemon running as root after the fix (`sudo` needs a password; the user has to run
    `make install-daemon`)
  - a live GlobalProtect disconnect, to watch the switch to blocking

---

## Follow-ups

- Reinstall the daemon (`make install-daemon`) and confirm `status.json` shows
  `"blocking" : false` while WireGuard is up.
- SSO/SAML identity-provider hosts used by GlobalProtect (Okta / Microsoft login) must be added in
  Settings…, or GlobalProtect can't log in while traffic is blocked.
- GlobalProtect on Prisma Access may pick a gateway other than the last one. Only the last gateway
  is auto-allowed.
- `allowLAN` also covers `10/8`, which overlaps the corporate VPN range, so traffic to those
  addresses goes to the local router while the VPN is down. Consider narrowing this.
- AGENTS.md still says WireGuard is detected by its service in `scutil --nc list`. It should note
  that the running tunnel uses a fresh service ID and is detected via `SCNetworkConnection`.

## References

- Reference app: `../archive/keenetic` (KeeneticTray: layout, Makefile, Info.plist style)
- README.md: install, pause/disable, uninstall, emergency unblock
