// auth.go — auth window orchestration.
//
// The startup path is :
//
//   1. main.go loads app.json. If the new top-level `auth` block is
//      absent, the app skips auth entirely (preserves the dev /
//      SSH-tunnel-only flow). If present, it calls Authenticate.
//
//   2. Authenticate first checks Keychain for a cached non-expired
//      session ; if found, returns it.
//
//   3. Otherwise, it shows a native Cocoa picker (auth_darwin.go) with
//      two buttons : "Sign in with OpenPubkey" and "Sign in with OIDC".
//      The user clicks one ; the chosen flow runs in a child
//      WKWebView ; the resulting token is persisted in Keychain and
//      returned.
//
//   4. main.go wires the token into shell.Options.AuthToken and into
//      the dashboard subprocess via WEFT_AUTH_TOKEN ; the WebView fetch
//      interceptor (webinject.AuthInterceptor) stamps every same-origin
//      API call.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

// AuthConfig mirrors the `auth` block in app.json. Empty struct = no
// auth (current behaviour).
type AuthConfig struct {
	Issuer      string   `json:"issuer"`
	ClientID    string   `json:"client_id"`
	Scopes      []string `json:"scopes"`
	RedirectURI string   `json:"redirect_uri"`
	// KeychainService overrides the Keychain service name used to
	// persist tokens. Defaults to "weft-app".
	KeychainService string `json:"keychain_service,omitempty"`
	// KeychainAccount overrides the per-issuer Keychain account label.
	// Defaults to the issuer URL.
	KeychainAccount string `json:"keychain_account,omitempty"`
}

// Enabled reports whether the user actually configured auth.
func (c AuthConfig) Enabled() bool { return c.Issuer != "" && c.ClientID != "" }

// TokenKind tags how a Token was acquired.
type TokenKind string

const (
	TokenOIDC       TokenKind = "oidc"
	TokenOpenPubkey TokenKind = "openpubkey"
)

// Token is the in-process session record. Its String() form is what
// gets injected into the WebView as a Bearer header.
type Token struct {
	Kind         TokenKind `json:"kind"`
	IDToken      string    `json:"id_token,omitempty"`
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Issuer       string    `json:"issuer,omitempty"`
	IssuedAt     time.Time `json:"issued_at"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
}

// Bearer returns the opaque token value to inject as
// `Authorization: Bearer <…>`. Prefers the id_token (carries the user's
// identity claims) over the access_token.
func (t Token) Bearer() string {
	if t.IDToken != "" {
		return t.IDToken
	}
	return t.AccessToken
}

// Expired reports whether the token has clocked out. A 30-second skew
// is built in so we don't ship a token that's about to expire mid-call.
func (t Token) Expired() bool {
	if t.ExpiresAt.IsZero() {
		return false // some issuers omit expires_in entirely
	}
	return time.Now().Add(30 * time.Second).After(t.ExpiresAt)
}

// LoadAuthConfig peels the `auth` block out of app.json. Missing block
// returns a zero AuthConfig (Enabled() == false). Returning the zero
// value rather than an error keeps existing app.json files without an
// `auth` block working unchanged.
func LoadAuthConfig(path string) (AuthConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return AuthConfig{}, nil
		}
		return AuthConfig{}, fmt.Errorf("read app.json: %w", err)
	}
	var shadow struct {
		Auth AuthConfig `json:"auth"`
	}
	if err := json.Unmarshal(b, &shadow); err != nil {
		return AuthConfig{}, fmt.Errorf("parse app.json auth block: %w", err)
	}
	if shadow.Auth.KeychainService == "" {
		shadow.Auth.KeychainService = "weft-app"
	}
	if shadow.Auth.KeychainAccount == "" {
		shadow.Auth.KeychainAccount = shadow.Auth.Issuer
	}
	return shadow.Auth, nil
}

// AuthChoice is what the native picker signals back.
type AuthChoice int

const (
	ChoiceCancelled AuthChoice = iota
	ChoiceOIDC
	ChoiceOpenPubkey
)

// Picker is the seam between the platform-agnostic Authenticate
// orchestration and the cgo Cocoa NSWindow. auth_darwin.go provides
// the real implementation ; tests can swap a stub.
type Picker interface {
	// Pick blocks until the user picks an auth kind or closes the
	// window. The window must be raised as a regular foreground app
	// (this is how the operator sees and clicks it before the tray is
	// ready).
	Pick(ctx context.Context) AuthChoice
	// OpenAuthWebView opens a child WKWebView pointed at u and returns
	// the URL it ended up at when the window was either redirected to
	// the configured redirect_uri or closed by the user.
	//
	// Returning "" means the window was dismissed before redirect.
	OpenAuthWebView(ctx context.Context, u, redirectPrefix string) (string, error)
}

// KeychainStore is the seam to macOS Keychain. keychain_darwin.go
// provides the real implementation ; tests can swap an in-memory map.
type KeychainStore interface {
	Get(service, account string) (Token, bool, error)
	Set(service, account string, tok Token) error
	Delete(service, account string) error
}

// Authenticate is the public entry. cfg.Enabled() == false returns the
// zero Token and no error (caller treats that as "no auth wired").
//
// store and picker default to the platform implementations ; pass
// non-nil values to inject test doubles.
func Authenticate(ctx context.Context, cfg AuthConfig, store KeychainStore, picker Picker) (Token, error) {
	if !cfg.Enabled() {
		return Token{}, nil
	}
	if store == nil {
		store = defaultKeychain()
	}
	if picker == nil {
		picker = defaultPicker()
	}

	// 1. Try the cached token.
	if tok, ok, err := store.Get(cfg.KeychainService, cfg.KeychainAccount); err != nil {
		log.Printf("weft-app: keychain read: %v (will re-auth)", err)
	} else if ok && !tok.Expired() && tok.Bearer() != "" {
		return tok, nil
	}

	// 2. Show the picker.
	choice := picker.Pick(ctx)
	switch choice {
	case ChoiceCancelled:
		return Token{}, errors.New("auth: window dismissed")
	case ChoiceOpenPubkey:
		tok, err := runOpenPubkey(ctx, cfg, picker)
		if err == nil {
			if err := store.Set(cfg.KeychainService, cfg.KeychainAccount, tok); err != nil {
				log.Printf("weft-app: keychain write: %v", err)
			}
			return tok, nil
		}
		log.Printf("weft-app: %v", err)
		// fall through to OIDC as the documented fallback
		fallthrough
	case ChoiceOIDC:
		tok, err := runOIDC(ctx, cfg, picker)
		if err != nil {
			return Token{}, err
		}
		if err := store.Set(cfg.KeychainService, cfg.KeychainAccount, tok); err != nil {
			log.Printf("weft-app: keychain write: %v", err)
		}
		return tok, nil
	}
	return Token{}, fmt.Errorf("auth: unknown choice %d", choice)
}

// runOIDC stitches the PKCE state machine together with the WebView +
// local callback listener.
func runOIDC(ctx context.Context, cfg AuthConfig, picker Picker) (Token, error) {
	round, err := startOIDC(ctx, OIDCConfig{
		Issuer:      cfg.Issuer,
		ClientID:    cfg.ClientID,
		Scopes:      cfg.Scopes,
		RedirectURI: cfg.RedirectURI,
	})
	if err != nil {
		return Token{}, fmt.Errorf("oidc start: %w", err)
	}

	// Run the loopback listener and the WebView in parallel ; whichever
	// produces a callback URL first wins.
	cbCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		s, err := awaitCallback(ctx, cfg.RedirectURI, 5*time.Minute)
		if err != nil {
			errCh <- err
			return
		}
		cbCh <- s
	}()
	go func() {
		s, err := picker.OpenAuthWebView(ctx, round.AuthorizeURL(), cfg.RedirectURI)
		if err != nil {
			errCh <- err
			return
		}
		if s != "" {
			cbCh <- s
		}
	}()

	var callbackURL string
	select {
	case <-ctx.Done():
		return Token{}, ctx.Err()
	case err := <-errCh:
		// Don't bail on the first error — the other goroutine may still
		// land the callback. Only bail if the second one also fails.
		select {
		case callbackURL = <-cbCh:
		case err2 := <-errCh:
			return Token{}, fmt.Errorf("oidc: %v ; %v", err, err2)
		case <-time.After(5 * time.Minute):
			return Token{}, errors.New("oidc: timeout")
		}
	case callbackURL = <-cbCh:
	}
	return round.Finish(ctx, callbackURL)
}
