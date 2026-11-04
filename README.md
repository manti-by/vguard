# VGuard

macOS menu-bar kill switch: **blocks all network traffic while neither GlobalProtect nor
WireGuard is connected**.

- Tray icon: shield (`lock.shield`) when a VPN is up, red alert shield when none is.
- Menu: active VPN(s), firewall state, hosts allowed while blocked, pause/resume, settings.

## How it works

Two parts, one binary (`main.swift`):

| Part | Runs as | Job |
|------|---------|-----|
| Tray app (`VGuard.app`) | you | icon + menu; detects VPNs itself, reads daemon status |
| Daemon (`VGuard --daemon`) | root, launchd | watches network state, loads/flushes pf rules |

VPN detection uses the SystemConfiguration dynamic store:
- **GlobalProtect** — service `gpd.pan` has an IPv4 address (`State:/Network/Service/gpd.pan/IPv4`).
- **WireGuard.app** — a VPN service with SubType `com.wireguard.macos` has an IPv4 address.
- **wg-quick** — `/var/run/wireguard/*.name` points to an existing interface.

When no VPN is up, the daemon loads rules into pf anchor `com.apple/vguard` (evaluated by
the stock `/etc/pf.conf`). Still allowed while blocked: loopback, tunnel interfaces
(`utun*`, …), DHCP, IPv6 neighbour discovery, DNS, LAN (both optional), and the VPN
endpoints, so the VPN can reconnect. Endpoints are discovered automatically:
- GlobalProtect portal + last gateway from `/Library/Preferences/com.paloaltonetworks.GlobalProtect.settings.plist`
- WireGuard `RemoteAddress` of each tunnel

Add anything else the VPN needs to connect (e.g. your SSO/SAML IdP like
`login.microsoftonline.com` or `<org>.okta.com`) in **Settings…**.

## Build & install

```sh
make install          # build VGuard.app and copy it to /Applications
make install-daemon   # install + start the root daemon (sudo)
open -a VGuard
```

You can also install the daemon from the tray menu (**Install Firewall Daemon…**, asks for
your admin password). Re-run `make install-daemon` after rebuilding.

Diagnostics without root — what's detected and which rules would be loaded:

```sh
make check
```

## Run at login

```sh
osascript -e 'tell application "System Events" to make login item at end with properties {path:"/Applications/VGuard.app", hidden:true}'
```

The daemon starts at boot on its own; the tray app is only the UI.

## Files

- `/Library/Application Support/VGuard/config.json` — settings (root-owned; edit via Settings…)
- `/Library/Application Support/VGuard/status.json` — daemon status read by the tray
- `/Library/Application Support/VGuard/pause` — pause-until epoch (written via admin prompt)
- `/var/log/vguard.log` — daemon log

## Uninstall / emergency unblock

```sh
make uninstall-daemon                       # stops daemon, removes rules
sudo pfctl -a com.apple/vguard -F all       # just flush the rules (daemon re-adds them within 10 s)
```
