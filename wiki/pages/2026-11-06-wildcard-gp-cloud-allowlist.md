---
title:          Wildcard GP cloud allowlist + US gateway pinning
date: 2026-11-06
type:               implementation
status:             resolved
session_id:         ses_e4f3a339effeb0F9Ar2AUH8S4Z
services: []        
branch:             -
tickets: []         
tags: [pf, allowlist, dns, globalprotect, deployment]
related: [2026-11-04-vpn-kill-switch-tray-app.md]
---

# Wildcard GP cloud allowlist + US gateway pinning

## TL;DR

Added `*.domain` wildcard host support to the VGuard allowlist and deployed the daemon +
tray app for the first time. Discovered that `gpcloudservice.com` has **no DNS wildcard zone**
at any level, so wildcard support is a generic capability here, not a solution for GlobalProtect
cloud — instead, both US gateways are now explicitly pinned in the allowlist so region switches
in GP never remove them from the reconnect allowlist.

---

## Overview

Goal: allow the tray's block state to connect to *any* `*.gpcloudservice.com` endpoint. pf
tables hold only IPs/CIDRs — never names — so "any wildcard" must be built from DNS. Two
findings shaped the final design:

- Allowlist entries can be *pinned* (config `extraHosts`, survive GP config churn) or
  *auto-discovered* (`discoveredEndpoints` reads GP's settings plist, which only records
  the **current** gateway — switching US South → US East silently removes the old one).
- DNS wildcard zones answer *any* label, so probing random subdomains reveals the service's
  IP pool; works only where a real `*.` record exists. `gpcloudservice.com` has none
  (verified: NXDOMAIN for random labels at `.<tld>`, `.gw.` and the tenant zone
  `gpocgooy5gc2.gw.`).

## Step 1 — wildcard host resolution

**File:** `main.swift:189-211` (`isWildcardHost`, `resolveWildcard`)

- `Config.extraHosts` gains `*.domain` entries; default is `["*.gpcloudservice.com"]`.
- `resolveWildcard(domain)` probes 3 random labels (`vguard-probe-<i>-<rand>.<domain>`) and
  unions the A/AAAA answers, deduped + sorted.
- Wired into `Daemon.resolveAsync` and `--check`; resolution refresh is the pre-existing
  120 s loop (swallowed DNS hiccups honor the stale-IP merge in `resolveAsync`).
- Fails closed: no wildcard zone → empty result → nothing allowed (no-op, no blind holes).

## Step 2 — diagnostics honesty for wildcard entries

**File:** `main.swift` (`--check` block)

Empty wildcard results previously printed a suspicious blank IP list that looked like a DNS
hiccup. Now they carry an explicit hint:

```
Allowed: *.gpcloudservice.com →    (zone has no DNS wildcard — auto-discovered endpoints
                                    and specific hostnames are used instead)
```

Settings dialog text also documents the `*.domain` syntax.

## Step 3 — first-time deployment + gateway pinning

Deployed everything via one admin-privilege `osascript` shell (password prompt;
`make install-daemon` runs the same steps as root):

- Pinned config `/Library/Application Support/VGuard/config.json`:
  - `*.gpcloudservice.com` (generic wildcard entry)
  - `us-east-g-vestwell.gpocgooy5gc2.gw.gpcloudservice.com`
  - `us-south-vestwell.gpocgooy5gc2.gw.gpcloudservice.com` (pinned in a follow-up after
    auto-discovery lost it during the region switch — see Update below)
- Daemon binary → `/Library/PrivilegedHelperTools/com.vguard.daemon`, LaunchDaemon
  `com.vguard.daemon.plist`, bootstrap via `launchctl`. Stale expired `pause` file removed.
- App bundle signed (`codesign -s -`) and copied to `/Applications/VGuard.app`, tray
  launched via `open`.

## Test Results

- `make build` clean, warnings-free.
- `./dist/VGuard --check` confirms the resolved allow pool:
  - `us-east-g-vestwell…gw.gpcloudservice.com` → `137.83.250.80`
  - `us-south-vestwell…gw.gpcloudservice.com` → `208.127.154.52`
  - `vestwellvpn.gpcloudservice.com` (portal) → `137.83.250.56`
  - `74.221.136.175` (auto-discovered US East DEM entry)
- Daemon under launchd: running as root, status.json heartbeats, GP on `utun4` →
  `blocking: false` and the pf anchor correctly flushed (blocking only when both VPNs are down).
- `notifyutil -p com.vguard.reload` applies config changes immediately (or wait ≤10 s).

---

## Follow-ups

- Palo Alto publishes per-tenant cloud IPs only via the Prisma Access API — if either US
  gateway changes its IP pool and stale parse caching becomes a problem, re-resolve covers it
  (120 s loop), but pinned IPs in the config should be re-checked after portal config changes.
- If a future GP portal/domain does use a real DNS wildcard zone, `*.domain` entries start
  working with zero code changes.

## References

- Related: [[2026-11-04-vpn-kill-switch-tray-app]]
- External: https://docs.paloaltonetworks.com/prisma-access/administration/prisma-access-setup/retrieve-ip-addresses-for-prisma-access
