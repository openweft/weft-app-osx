// Command weft-app-osx is the macOS menu-bar client for the Weft
// dashboard. It lives as a status-bar icon ; clicking "Open Dashboard"
// shows weft-webui in a WKWebView window. All the interesting behaviour
// — discovering datacenters, reaching them over a secure transport, and
// failing over between them — is in github.com/openweft/weft-app-core ;
// this binary is the macOS tray + WebView glue around a shell.Shell.
//
// macOS gives a process exactly one main run loop, and both the tray
// (fyne.io/systray) and the WebView (webview_go) want it. So the binary
// runs in one of two modes :
//
//   - default        : the tray. Owns the supervisor + loopback gateway,
//     and a tiny loopback control server. The main
//     thread runs the systray loop.
//   - --dashboard     : the WebView window (spawned by the tray). The
//     main thread runs the WebView loop ; it loads the
//     gateway origin passed in --url and watches the
//     control server for failover notices.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"path/filepath"
)

// WEFTAuthTokenEnv is the env var the tray uses to pass the
// authenticated session token down to the spawned dashboard
// subprocess, which in turn injects it into the WKWebView fetch
// interceptor as the Bearer credential.
const WEFTAuthTokenEnv = "WEFT_AUTH_TOKEN"

func main() {
	dashboard := flag.Bool("dashboard", false, "run the dashboard WebView window (spawned by the tray)")
	gatewayURL := flag.String("url", "", "gateway origin to load (dashboard mode)")
	controlURL := flag.String("control", "", "control server origin (dashboard mode)")
	configPath := flag.String("config", defaultConfigPath(), "path to the JSON connection config")
	wgConfigPath := flag.String("wg-config", "", "path to a WireGuard mesh config (enables the wireguard transport)")
	flag.Parse()

	if *dashboard {
		runDashboard(*gatewayURL, *controlURL)
		return
	}

	// Authenticate before bringing up the tray, so the operator faces
	// the picker first rather than a tray menu that opens onto an
	// unauthenticated webui. When app.json has no `auth` block this is
	// a no-op (cfg.Enabled() == false) and we keep the dev /
	// SSH-tunnel-only flow exactly as before.
	authCfg, err := LoadAuthConfig(*configPath)
	if err != nil {
		log.Printf("weft-app: load auth config: %v (continuing without auth)", err)
	}
	var token string
	if authCfg.Enabled() {
		tok, err := Authenticate(context.Background(), authCfg, nil, nil)
		if err != nil {
			log.Fatalf("weft-app: authenticate: %v", err)
		}
		token = tok.Bearer()
	}

	runTray(*configPath, *wgConfigPath, token, authCfg)
}

// defaultConfigPath is ~/Library/Application Support/weft/app.json on
// macOS, falling back to ./weft-app.json.
func defaultConfigPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "weft", "app.json")
	}
	return "weft-app.json"
}
