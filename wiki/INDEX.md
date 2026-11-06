# VGuard Wiki - Index

Session knowledge base for the VGuard project - one Markdown page per debugging
chase, investigation, code review, or set of changes. See [README.md](README.md) for conventions
and [TEMPLATE.md](TEMPLATE.md) for the page template. New pages are created or updated on demand
with `/wiki-update`; the plugin only scaffolds the wiki.

## Pages

_Newest first._

- [Wildcard GP cloud allowlist + US gateway pinning](pages/2026-11-06-wildcard-gp-cloud-allowlist.md) — `*.domain` wildcard allowlist support; `gpcloudservice.com` has no DNS wildcard, so both US gateways are pinned in config; first full daemon + tray deployment (2026-11-06)
- [VGuard VPN kill-switch tray app](pages/2026-11-04-vpn-kill-switch-tray-app.md) — menu-bar app + root pf daemon blocking traffic unless GlobalProtect/WireGuard is up; WireGuard NE detection fix (2026-11-05)
- [Tray icon resize + empty-palette crash fix](pages/2026-11-05-tray-icon-crash-fix.md) — 17pt SF Symbol menu-bar icon; fixed `configurationWithPaletteColors:` abort on empty palette array (2026-11-05)

## By topic

_Optional: cluster pages by subject matter here, largest cluster first._
