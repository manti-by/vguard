---
title: Tray icon resize + empty-palette crash fix
date: 2026-11-05
type: debug
status: resolved
session_id: ses_e5423eaa9ffeqHWNya2Snyq3Ch
services: [main]
branch: -
tickets: []
tags: [macos, menubar, sf-symbols, nsimage, crash, appkit]
related: [2026-11-05-vpn-kill-switch-tray-app.md]
---

# Tray icon resize + empty-palette crash fix

## TL;DR

Made the menu-bar icon bigger (17pt symbol configuration) and in doing so introduced a
`SIGABRT` crash: `configurationWithPaletteColors:` throws when handed an **empty** palette
array. Because `refresh()` runs on launch and on a 5 s timer, the tray app aborted shortly
after startup and the icon vanished. Fixed by applying the palette config only when a tint
color exists. Confirmed the firewall daemon itself was never affected (`blocking: false`,
status fresh) — the reported "can't connect to GlobalProtect" was a red herring.

---

## Symptom

- Tray icon disappeared; `pgrep` showed no VGuard.app process despite the app having launched.
- Crash report `~/Library/Logs/DiagnosticReports/VGuard-2026-11-05-162349.ips`:
  - `SIGABRT`, `abort() called`, pid 15907, version `0.1.1`
  - ~76 s uptime — several `refresh()` ticks after launch
- User also reported "can't connect to GP VPN" (see Step 3 — unrelated).

## Step 1 — the icon change that triggered it

Intent: render the SF Symbols (`lock.shield` / `exclamationmark.shield.fill`) larger than the
menu-bar default (~15pt).

**File:** `main.swift:454` — `symbol(_:color:)`, first (broken) version:

```swift
let cfg = NSImage.SymbolConfiguration(paletteColors: color.map { [$0] } ?? [])
    .applying(.init(pointSize: 17, weight: .medium))
if let scaled = img.withSymbolConfiguration(cfg) { img = scaled }
```

The bug: when there is no tint color (`color == nil`, i.e. the template `lock.shield` path),
`paletteColors` becomes `[]`.

## Step 2 — crash diagnosis

From the `.ips` backtrace:

- `+[NSImageSymbolConfiguration configurationWithPaletteColors:]` →
  `-[NSAssertionHandler handleFailureInMethod:...]` → `objc_exception_throw` → abort
- Called unconditionally from `symbol(_:color:)` ← `App.refresh()` (main queue, dispatch timer)

**Evidence for the *empty* array being the trigger:** the exception fires in the plain
template path too — not only for the red `exclamationmark.shield.fill` — and every refresh
tick would hit it, matching the abort soon after launch with no warning in build output
(`swiftc` compiles clean; AppKit only asserts at runtime).

## Root cause

AppKit requires `paletteColors` to be **non-empty**; `NSImage.SymbolConfiguration(paletteColors: [])`
throws an NSException at runtime. The old pre-resize code happened to avoid it because it
short-circuited with `if let color` and never built the config for the template path.

## Resolution / Fix

**File:** `main.swift:454` — rebuild the configuration so the palette is only attached when a
color exists:

```swift
var cfg = NSImage.SymbolConfiguration(pointSize: 17, weight: .medium) // menu-bar default is ~15pt
if let color { cfg = cfg.applying(.init(paletteColors: [color])) }    // paletteColors must be non-empty!
if let scaled = img.withSymbolConfiguration(cfg) { img = scaled }
img.isTemplate = color == nil // template = adapts to light/dark menu bar
```

Rebuilt and reinstalled via `make install`, relaunched; the process survived well past the
former crash window with no new crash reports.

## Step 3 — "can't connect to GP" was not VGuard

While the tray was down, the user could not connect GlobalProtect. Checked the kill-switch state:

- `/Library/Application Support/VGuard/status.json` fresh (updated seconds before) with
  `"blocking" : false` — daemon alive and **not** blocking (WireGuard connected)
- `scutil --nc list`: WireGuard `amon-ra` connected; GP correctly absent (dynamic-store only:
  see Step 1 VPN detection in [[2026-11-05-vpn-kill-switch-tray-app]])
- GP portals (`vestwellvpn.gpcloudservice.com`, gateway `us-east-g-vestwell.gpocgooy5gc2...`)
  present in the `allowed` whitelist

Conclusion: the tray crash can't affect pf (daemon owns the anchor), and no blocking state was
reached, so GP failure pointed at the GP client/network, not VGuard.

**Deployment gotcha found along the way:** `dist/VGuard` was owned by `root` (from a prior
admin-privileged run) and the linker couldn't overwrite it — `make build` fails with
`ld: can't write output file`. Worked around by moving the root-owned artifact out of the way.

## Known follow-up (not fixed this session)

- Version provenance discussed but not implemented: single-source the version in the Makefile
  (`VERSION` → `plutil`-patched `CFBundleShortVersionString`, build number from
  `git rev-list --count HEAD`), derive the app version from the bundle at runtime, and embed
  `#APP_VERSION` so `--check` can verify the tray/daemon binaries match after an update.

---

## Follow-ups

- None blocking. The daemon health item left open in [[2026-11-05-vpn-kill-switch-tray-app]]
  ("confirm `status.json` shows `blocking: false` while WireGuard is up") is now confirmed:
  status was fresh with `blocking: false` and WireGuard (`utun5`) up.

## References

- Related: [[2026-11-05-vpn-kill-switch-tray-app]] — original VGuard build, VPN detection, pf rules
- Crash report: `~/Library/Logs/DiagnosticReports/VGuard-2026-11-05-162349.ips`
