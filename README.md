# weft-app-osx

macOS menu-bar client for the [Weft](https://github.com/openweft) dashboard.

A status-bar icon (⬡) sits in the menu bar; **Open Dashboard** shows
[`weft-webui`](https://github.com/openweft/weft-webui) in a WKWebView. All
the connection logic — discovering datacenters, reaching them over an
authenticated transport, and failing over between them — lives in
[`weft-app-core`](https://github.com/openweft/weft-app-core); this repo is
the macOS tray + WebView glue.

## How it works

macOS gives a process one main run loop, and both the tray
(`fyne.io/systray`) and the WebView (`webview_go`) want it — so the app is
two processes:

```
weft-app-osx (tray)                         weft-app-osx --dashboard
───────────────────                         ────────────────────────
shell.Shell                                 WKWebView
  ├─ failover.Supervisor  (probes each DC)    loads gateway origin
  ├─ failover.Gateway     (loopback origin) ◀── stable http://127.0.0.1:PORT
  └─ control.Server       (/active) ──poll──▶ control.Client
        ▲                                       └─ on DC change:
        └ OnSwitch publishes active DC             __weftFailoverNotice → banner
```

The WebView loads the gateway's **single stable loopback origin** and
never re-points. When a DC dies the Supervisor re-selects under the
gateway, so the page never reloads — cookies, OIDC session and SPA state
all survive. The control channel only drives the "connection switched"
banner.

## No public web service

The app reaches each DC's `weft-webui` over an **SSH local-forward**
(default) or the **WireGuard mesh**, so the platform exposes no worldwide
web listener — the transport key gates the network, dex OIDC gates the
session. See `config.example.json`.

The WireGuard transport is real and pure-Go (userspace `wireguard-go`
netstack — no `tun` device, no privilege, no cgo). Supply a mesh config
and the `wireguard` endpoints in `app.json` resolve over it:

```sh
./weft-app-osx --config app.json --wg-config wireguard.json
```

See `wireguard.example.json` for the schema (`wg genkey`-style base64 keys).

## Install

Download `Weft.dmg` from the [latest release](https://github.com/openweft/weft-app-osx/releases),
open it, and drag **Weft** onto **Applications**. Weft runs as a menu-bar
icon (no Dock icon). Release builds are code-signed + notarized, so
Gatekeeper opens them without warnings.

## Build

Requires macOS + Xcode command-line tools (cgo).

```sh
cp config.example.json "$HOME/Library/Application Support/weft/app.json"
# edit it for your cluster, then:
task deps    # needs network (webview_go, systray)
task run
```

Packaging:
- `task bundle` → `dist/Weft.app` (menu-bar agent, `LSUIElement=1`).
- `task dmg` → `dist/Weft.dmg` — a **branded** drag-n-drop installer:
  `create-dmg` lays Weft.app + an `Applications` drop-link over a
  background showing the hexagon mark and the project mantra (falls back
  to a plain `hdiutil` image if `create-dmg`/a window server is absent;
  `WEFT_PLAIN_DMG=1` forces it).

The DMG background is generated (reproducibly, from the embedded Go fonts)
by `packaging/mkbg` — run `go run .` in that dir to regenerate
`packaging/dmg-background.png`.

The release workflow code-signs the `.app`, builds the DMG, then
notarizes + staples it (signing steps run only when the signing secrets
are configured).

## Tested logic

The non-UI logic is covered by tests in `weft-app-core`
(`failover`, `shell`, `control`, `discovery`). This repo's `main` package
is the thin cgo shell.
