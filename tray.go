package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"fyne.io/systray"

	"github.com/openweft/weft-app-core/control"
	"github.com/openweft/weft-app-core/failover"
	"github.com/openweft/weft-app-core/shell"
)

// runTray is the default mode: own the supervisor + gateway + control
// server, and present the menu-bar item. Blocks on the systray run loop.
// A setup failure (bad config, etc.) shows an error tray rather than
// exiting invisibly — a menu-bar app has no console to print to.
//
// authToken is the Bearer string Authenticate produced (or "" when auth
// is disabled in app.json) ; it gets wired into shell.Options.AuthToken
// (so InitScript stamps the fetch interceptor) and threaded into the
// dashboard subprocess via the WEFT_AUTH_TOKEN env var.
func runTray(configPath, wgConfigPath, authToken string, authCfg AuthConfig) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	sh, controlURL, err := setupShell(ctx, configPath, wgConfigPath, authToken)
	if err != nil {
		log.Printf("weft-app: %v", err)
		systray.Run(onSetupError(ctx, err), cancel)
		return
	}
	systray.Run(onReady(ctx, sh, controlURL, authToken, authCfg), cancel)
}

// setupShell builds the WireGuard dialer (if configured), the shell, and
// the control server, and starts them bound to ctx. Returns the shell and
// the control-server origin. authToken (when non-empty) is wired into
// shell.Options so InitScript layers in the WebView Bearer interceptor.
func setupShell(ctx context.Context, configPath, wgConfigPath, authToken string) (*shell.Shell, string, error) {
	cfg, err := shell.LoadConfig(configPath)
	if err != nil {
		return nil, "", err
	}

	opts := shell.Options{
		AuthToken: authToken,
		// SSHPassphrase reads from macOS Keychain (service=weft-ssh-
		// passphrase, account=<absolute key path>). The operator pre-
		// stages an entry via `weft-app-osx --store-ssh-passphrase
		// <path>` ; the lookup is silent on miss (returns nil), letting
		// the underlying parse error surface a clear next-step message.
		SSHPassphrase: func(keyPath string) ([]byte, error) {
			return sshPassphraseGet(keyPath)
		},
	}
	if wgConfigPath != "" {
		wc, err := LoadWGConfig(wgConfigPath)
		if err != nil {
			return nil, "", err
		}
		dial, closeMesh, err := MeshDialer(wc)
		if err != nil {
			return nil, "", fmt.Errorf("wireguard: %w", err)
		}
		go func() { <-ctx.Done(); _ = closeMesh() }()
		opts.MeshDialer = dial
	}

	ctrl := control.NewServer()
	opts.OnSwitch = ctrl.Publish
	sh, err := shell.New(cfg, opts)
	if err != nil {
		return nil, "", err
	}

	go func() {
		if err := sh.Run(ctx); err != nil {
			log.Printf("weft-app: gateway stopped: %v", err)
		}
	}()

	controlURL, err := ctrl.Listen(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("control server: %w", err)
	}
	return sh, controlURL, nil
}

// onSetupError shows a minimal tray surfacing the startup error, so the
// user can read it and quit (instead of the app silently not appearing).
func onSetupError(ctx context.Context, setupErr error) func() {
	return func() {
		systray.SetTemplateIcon(iconTemplateData, iconData)
		systray.SetTitle("Weft")
		systray.SetTooltip("Weft — configuration error")
		systray.AddMenuItem("⚠ "+setupErr.Error(), "Startup error").Disable()
		systray.AddSeparator()
		mQuit := systray.AddMenuItem("Quit", "Quit Weft")
		select {
		case <-ctx.Done():
		case <-mQuit.ClickedCh:
		}
		systray.Quit()
	}
}

// onReady builds the menu and wires its actions. systray calls it once
// the status item is live. authToken is forwarded to the dashboard
// subprocess via WEFT_AUTH_TOKEN so its WebView fetch interceptor can
// stamp the Bearer header ; authCfg is used by the "Sign out" item to
// locate the right Keychain entry to evict.
func onReady(ctx context.Context, sh *shell.Shell, controlURL, authToken string, authCfg AuthConfig) func() {
	return func() {
		// Template icon on macOS (auto light/dark); colour weave elsewhere.
		systray.SetTemplateIcon(iconTemplateData, iconData)
		// Menubar title shows the active DC name so the operator can
		// tell at a glance which datacenter the dashboard is reading
		// from. refreshStatus updates it whenever the active DC moves.
		systray.SetTitle("Weft")
		systray.SetTooltip("Weft " + version + " — datacenter unknown")

		// Version-line removed : the menubar icon + title carries the
		// active DC and the tooltip carries the version. The version
		// stays accessible via the Datacenters submenu's tooltip too.
		mOpen := systray.AddMenuItem("Open Dashboard", "Open the Weft dashboard")
		// Open Dashboard is disabled until we have a usable token when
		// auth is configured. Without that gate, clicking it would
		// spawn a WKWebView pointed at an origin every request to which
		// would be redirected to the sign-in page by the webui — the
		// dashboard would render OIDC chrome instead of the SPA. When
		// auth isn't configured (omitted from app.json) the item stays
		// enabled — preserves the dev / SSH-tunnel-only flow.
		if authCfg.Enabled() && authToken == "" {
			mOpen.Disable()
		}
		// Loom secondary editor. The menu item is only added when
		// shell.Shell.LoomURL() is non-empty — i.e. at least one DC
		// in app.json declares a loom_addr. Same auth gate as Open
		// Dashboard ; the loom server validates the same OIDC tokens
		// the webui does (dex backed). Loom's gateway runs alongside
		// the primary one ; failover between loom replicas is silent
		// from the user's perspective (the loopback origin is stable).
		var mOpenLoom *systray.MenuItem
		loomURL := sh.LoomURL()
		if loomURL != "" {
			mOpenLoom = systray.AddMenuItem("Open Loom", "Open the collaborative editor (multi-DC HA)")
			if authCfg.Enabled() && authToken == "" {
				mOpenLoom.Disable()
			}
		}
		systray.AddSeparator()
		mDCs := systray.AddMenuItem("Datacenters", "Per-datacenter health")
		mDCs.Disable()
		// "Switch cluster" submenu — only useful when the config
		// declares more than one cluster. Each item calls
		// sh.SwitchCluster(name) ; the supervisor's reselect emits a
		// Switch event that propagates to the chip + menubar title.
		clusterSwitchers := map[string]*systray.MenuItem{}
		if names := sh.Clusters(); len(names) > 1 {
			mSwitch := systray.AddMenuItem("Switch cluster", "Federated clusters — pick which one the WebView reads from")
			for _, name := range names {
				clusterSwitchers[name] = mSwitch.AddSubMenuItem(name, "Switch the WebView to "+name)
			}
		}
		systray.AddSeparator()
		// "Sign in" and "Sign out" are only meaningful when auth is
		// configured. Visibility depends on whether a non-expired token
		// is currently in our in-memory cache : signed in → Sign out
		// visible, signed out → Sign in visible. The toggle is driven
		// by trayState below.
		var mSignIn, mSignOut *systray.MenuItem
		if authCfg.Enabled() {
			mSignIn = systray.AddMenuItem("Sign in", "Open the auth window and sign in to the cluster")
			mSignOut = systray.AddMenuItem("Sign out", "Forget the cached session and re-authenticate")
			if authToken == "" {
				mSignOut.Hide()
			} else {
				mSignIn.Hide()
			}
			systray.AddSeparator()
		}
		mQuit := systray.AddMenuItem("Quit", "Quit Weft")

		go refreshStatus(ctx, sh, mDCs)

		// signInCh / signOutCh are never-firing nil channels when auth
		// isn't configured, so the select below stays valid without an
		// extra branch. live token is kept in `authToken` (loop-local
		// copy of the arg) so openDashboard always sees the latest.
		var signInCh, signOutCh <-chan struct{}
		if mSignIn != nil {
			signInCh = mSignIn.ClickedCh
		}
		if mSignOut != nil {
			signOutCh = mSignOut.ClickedCh
		}

		// Goroutine per cluster switcher so the main select stays clean.
		// Each goroutine forwards its clicks into a single channel the
		// main loop reads ; cluster name flows alongside so we can call
		// sh.SwitchCluster with it.
		switchCh := make(chan string, len(clusterSwitchers))
		for name, item := range clusterSwitchers {
			name := name
			ch := item.ClickedCh
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case <-ch:
						switchCh <- name
					}
				}
			}()
		}

		// loomClickCh : nil when the menu item wasn't added (no loom_addr
		// in any DC). select on a nil channel never selects, so the
		// branch is naturally inert without an extra guard.
		var loomClickCh chan struct{}
		if mOpenLoom != nil {
			loomClickCh = mOpenLoom.ClickedCh
		}
		for {
			select {
			case <-ctx.Done():
				systray.Quit()
				return
			case <-mOpen.ClickedCh:
				openDashboard(sh.URL(), controlURL, authToken)
			case <-loomClickCh:
				openLoom(sh.LoomURL(), controlURL, authToken)
			case name := <-switchCh:
				sh.SwitchCluster(name)
			case <-signInCh:
				if tok, ok := spawnSignInAndReload(authCfg); ok {
					authToken = tok
					if mSignIn != nil {
						mSignIn.Hide()
					}
					if mSignOut != nil {
						mSignOut.Show()
					}
					mOpen.Enable()
				}
			case <-signOutCh:
				if authCfg.Enabled() {
					if err := defaultKeychain().Delete(authCfg.KeychainService, authCfg.KeychainAccount); err != nil {
						log.Printf("weft-app: sign out: %v", err)
					}
				}
				authToken = ""
				if mSignOut != nil {
					mSignOut.Hide()
				}
				if mSignIn != nil {
					mSignIn.Show()
				}
				mOpen.Disable()
			case <-mQuit.ClickedCh:
				systray.Quit()
				return
			}
		}
	}
}

// spawnSignInAndReload runs the auth window in a child process (the
// `--sign-in` mode of this binary) so the modal's main-thread affinity
// doesn't clash with systray's. Blocks until the child exits ; on
// success the new token is in Keychain and we read it back into the
// tray's in-memory cache so openDashboard sees it on the very next
// click. Returns (token, true) on success, ("", false) on failure or
// user-dismissed window.
func spawnSignInAndReload(cfg AuthConfig) (string, bool) {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("weft-app: locate executable: %v", err)
		return "", false
	}
	cmd := exec.Command(exe, "--sign-in")
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		log.Printf("weft-app: sign in subprocess: %v", err)
		return "", false
	}
	tok, ok, err := defaultKeychain().Get(cfg.KeychainService, cfg.KeychainAccount)
	if err != nil || !ok || tok.Expired() || tok.Bearer() == "" {
		log.Printf("weft-app: sign in subprocess returned but no usable token in keychain (err=%v ok=%v)", err, ok)
		return "", false
	}
	return tok.Bearer(), true
}

// signOutAndRelaunch drops the cached Keychain entry, spawns a fresh
// copy of this binary (which will hit Authenticate, find no cached
// token, and raise the auth window) and quits the current tray. Doing
// it via a subprocess keeps the current tray's main thread free to
// shut down cleanly — the systray run loop captured it, so we can't
// re-enter Cocoa's modal here.
//
// Kept for back-compat — not invoked anymore by onReady, which now
// toggles Sign in / Sign out inline using spawnSignInAndReload.
func signOutAndRelaunch(cfg AuthConfig) {
	if cfg.Enabled() {
		if err := defaultKeychain().Delete(cfg.KeychainService, cfg.KeychainAccount); err != nil {
			log.Printf("weft-app: sign out: %v", err)
		}
	}
	exe, err := os.Executable()
	if err == nil {
		cmd := exec.Command(exe)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Start(); err != nil {
			log.Printf("weft-app: relaunch: %v", err)
		}
	}
	systray.Quit()
}

// refreshStatus mirrors the supervisor's per-DC health into submenu items
// (● healthy / ○ down, with "(active)" on the selected DC). It also pushes
// the active DC's name into the menubar title so it's visible without
// opening the menu.
func refreshStatus(ctx context.Context, sh *shell.Shell, parent *systray.MenuItem) {
	// "<cluster>|<dc>" -> tray entry. Per-cluster headers (disabled
	// items used as section separators) are keyed by "@<cluster>".
	items := map[string]*systray.MenuItem{}
	lastActive := ""
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			activeFull := ""
			for _, st := range sh.Status() {
				// Cluster header once per cluster, before its first DC.
				clusterKey := "@" + st.Cluster
				if st.Cluster != "" {
					if _, ok := items[clusterKey]; !ok {
						hdr := parent.AddSubMenuItem(st.ClusterLabelOrName(), st.Cluster)
						hdr.Disable()
						items[clusterKey] = hdr
					}
				}
				dcKey := st.Cluster + "|" + st.Name
				it, ok := items[dcKey]
				if !ok {
					// Two-space indent so the DC line nests visually
					// under its cluster header.
					it = parent.AddSubMenuItem("  "+st.Label(), st.Target)
					items[dcKey] = it
				}
				mark := "○"
				if st.Health == failover.Up {
					mark = "●"
				}
				title := "  " + mark + " " + st.Label()
				if st.DisplayName != "" && st.DisplayName != st.Name {
					title += " (" + st.Name + ")"
				}
				if st.Active {
					title += " — active"
					activeFull = st.FullLabel()
				}
				it.SetTitle(title)
			}
			if activeFull != lastActive {
				if activeFull == "" {
					systray.SetTitle("Weft")
					systray.SetTooltip("Weft " + version + " — no datacenter reachable")
				} else {
					systray.SetTitle(activeFull)
					systray.SetTooltip("Weft " + version + " — connected to " + activeFull)
				}
				lastActive = activeFull
			}
		}
	}
}

// openDashboard spawns this same binary in --dashboard mode, pointed at
// the gateway origin. A separate process so the WebView gets its own main
// run loop (the tray owns this one). authToken is forwarded via the
// WEFT_AUTH_TOKEN env var so the dashboard's WebView fetch interceptor
// stamps Bearer on every API call.
func openDashboard(gatewayURL, controlURL, authToken string) {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("weft-app: locate executable: %v", err)
		return
	}
	cmd := exec.Command(exe, "--dashboard", "--url", gatewayURL, "--control", controlURL)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if authToken != "" {
		cmd.Env = append(cmd.Env, WEFTAuthTokenEnv+"="+authToken)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("weft-app: open dashboard: %v", err)
	}
}

// openLoom mirrors openDashboard but points the spawned subprocess at
// the loom gateway origin via the --loom flag. The subprocess sets the
// window title to "Weft Loom" so the user can tell the two WKWebView
// windows apart in the macOS Dock + Mission Control.
//
// Same authToken pipeline as openDashboard — the loom server validates
// the same dex OIDC tokens the webui does, so a single sign-in covers
// both surfaces.
func openLoom(loomURL, controlURL, authToken string) {
	exe, err := os.Executable()
	if err != nil {
		log.Printf("weft-app: locate executable: %v", err)
		return
	}
	cmd := exec.Command(exe, "--dashboard", "--loom", "--url", loomURL, "--control", controlURL)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	if authToken != "" {
		cmd.Env = append(cmd.Env, WEFTAuthTokenEnv+"="+authToken)
	}
	if err := cmd.Start(); err != nil {
		log.Printf("weft-app: open loom: %v", err)
	}
}
