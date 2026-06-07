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
	"fmt"
	"log"
	"os"
	"path/filepath"

	corauth "github.com/openweft/weft-app-core/auth"
	"golang.org/x/term"
)

// WEFTAuthTokenEnv is the env var the tray uses to pass the
// authenticated session token down to the spawned dashboard
// subprocess, which in turn injects it into the WKWebView fetch
// interceptor as the Bearer credential.
const WEFTAuthTokenEnv = "WEFT_AUTH_TOKEN"

func main() {
	dashboard := flag.Bool("dashboard", false, "run the dashboard WebView window (spawned by the tray)")
	signIn := flag.Bool("sign-in", false, "run the auth window (spawned by the tray on click of the Sign in menu item)")
	gatewayURL := flag.String("url", "", "gateway origin to load (dashboard mode)")
	controlURL := flag.String("control", "", "control server origin (dashboard mode)")
	configPath := flag.String("config", defaultConfigPath(), "path to the JSON connection config")
	wgConfigPath := flag.String("wg-config", "", "path to a WireGuard mesh config (enables the wireguard transport)")
	printPubkey := flag.Bool("print-pubkey", false, "load (or generate) the dev keypair, print the base64 public key to stdout, and exit ; paste the output into the server's --keypair-allowlist file")
	storeSSHPassphrase := flag.String("store-ssh-passphrase", "", "store the passphrase for the given SSH key file in macOS Keychain ; prompts on the controlling TTY ; the tray + dashboard then auto-decrypt the key without further prompts")
	flag.Parse()

	// Route the runKeypair diagnostic ("register this pubkey on the
	// server's keypair allowlist") to the real os.Stderr ; the package
	// default is io.Discard so unit tests don't get noisy output.
	stderr = os.Stderr

	if *dashboard {
		runDashboard(*gatewayURL, *controlURL)
		return
	}

	if *signIn {
		runSignIn(*configPath)
		return
	}

	if *printPubkey {
		if err := printPubkeyAndExit(*configPath); err != nil {
			log.Fatalf("weft-app: --print-pubkey: %v", err)
		}
		return
	}

	if *storeSSHPassphrase != "" {
		if err := storeSSHPassphraseAndExit(*storeSSHPassphrase); err != nil {
			log.Fatalf("weft-app: --store-ssh-passphrase: %v", err)
		}
		return
	}

	// Load the auth config and try the Keychain for a cached, non-expired
	// token. If found, hand it straight to the tray ; otherwise start the
	// tray with an empty token and surface a "Sign in" menu item the
	// operator clicks to spawn the auth window on demand. This avoids the
	// "window closes silently on auth failure" UX trap and lets the tray
	// come up even when the cluster's identity stack is down.
	authCfg, err := LoadAuthConfig(*configPath)
	if err != nil {
		log.Printf("weft-app: load auth config: %v (continuing without auth)", err)
	}
	var token string
	if authCfg.Enabled() {
		if tok, ok, err := defaultKeychain().Get(authCfg.KeychainService, authCfg.KeychainAccount); err != nil {
			log.Printf("weft-app: keychain read: %v (sign in from the tray)", err)
		} else if ok && !tok.Expired() && tok.Bearer() != "" {
			token = tok.Bearer()
		}
	}

	runTray(*configPath, *wgConfigPath, token, authCfg)
}

// runSignIn is the entry the tray spawns when the operator clicks
// "Sign in". It owns the main thread for the duration of the Cocoa
// modal (runModalForWindow needs main-thread affinity) ; the new
// token is written to Keychain by Authenticate, the tray polls
// Keychain after the subprocess exits to refresh its in-memory copy.
func runSignIn(configPath string) {
	authCfg, err := LoadAuthConfig(configPath)
	if err != nil || !authCfg.Enabled() {
		log.Fatalf("weft-app: --sign-in : auth block missing or unreadable in %s", configPath)
	}
	promoteDashboardActivation() // bring this subprocess to the foreground so the NSWindow is visible + key
	if _, err := Authenticate(context.Background(), authCfg, nil, nil); err != nil {
		log.Fatalf("weft-app: sign in: %v", err)
	}
	log.Printf("weft-app: sign in ok")
}

// defaultConfigPath is ~/Library/Application Support/weft/app.json on
// macOS, falling back to ./weft-app.json.
func defaultConfigPath() string {
	if dir, err := os.UserConfigDir(); err == nil {
		return filepath.Join(dir, "weft", "app.json")
	}
	return "weft-app.json"
}

// readPassphraseFromTTY reads a single line from /dev/tty with echo
// disabled (so the passphrase doesn't appear on screen or in scrollback).
// Falls back to os.Stdin when /dev/tty isn't openable (LaunchAgent /
// CI context) — those paths warn that echo isn't muted.
func readPassphraseFromTTY() ([]byte, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err == nil {
		defer tty.Close()
		pp, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(os.Stderr)
		return pp, err
	}
	fmt.Fprintln(os.Stderr, "weft-app: warning : /dev/tty unavailable ; reading from stdin with echo")
	var line []byte
	buf := make([]byte, 1)
	for {
		n, err := os.Stdin.Read(buf)
		if n == 0 || err != nil {
			return line, err
		}
		if buf[0] == '\n' {
			return line, nil
		}
		line = append(line, buf[0])
	}
}

// storeSSHPassphraseAndExit reads a passphrase from the controlling
// terminal (so it doesn't leak through env vars, shell history, or
// pipe-snooping) and stores it under the SSH passphrase Keychain entry
// keyed by the absolute key path. The tray then auto-decrypts the key
// via the Keychain on every launch without prompting again.
//
// Re-running this command for an already-cached key overwrites the
// entry — operators rotate keys this way.
func storeSSHPassphraseAndExit(keyPath string) error {
	abs, err := filepath.Abs(keyPath)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", keyPath, err)
	}
	if _, err := os.Stat(abs); err != nil {
		return fmt.Errorf("ssh key %s: %w", abs, err)
	}
	fmt.Fprintf(os.Stderr, "Enter passphrase for %s (empty if none):\n", abs)
	pp, err := readPassphraseFromTTY()
	if err != nil {
		return err
	}
	if err := sshPassphraseSet(abs, pp); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "weft-app: passphrase cached in Keychain (service=%s account=%s)\n", sshPassphraseService, abs)
	return nil
}

// printPubkeyAndExit loads (or generates) the ed25519 keypair for the
// AuthConfig in configPath and prints the public key in base64-std form
// to stdout. Designed to be paste-friendly into the server's
// --keypair-allowlist JSON file ("pubkey" field).
//
// When the keypair Keychain item is missing this also creates and
// persists a fresh one — same path runKeypair takes during a normal
// dev sign-in. The diagnostic ("generated a new ed25519 keypair…")
// goes to stderr ; only the bare base64 string lands on stdout so
// scripting `weft-app-osx --print-pubkey | jq` stays clean.
func printPubkeyAndExit(configPath string) error {
	cfg, err := LoadAuthConfig(configPath)
	if err != nil {
		// A missing or unreadable config is fine — the keypair Keychain
		// item lives under "default" without it. Log to stderr and
		// continue.
		fmt.Fprintf(os.Stderr, "weft-app: --print-pubkey : %v ; using default keypair account\n", err)
		cfg = AuthConfig{}
	}
	_, pub, _, err := loadOrCreateKeypair(defaultKeypairStore(), keypairAccountFor(cfg))
	if err != nil {
		return err
	}
	fmt.Println(corauth.EncodePubKey(pub))
	return nil
}
