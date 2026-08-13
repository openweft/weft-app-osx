// keychain.go — the session-token store, backed by the host credential vault
// through the go-keyring/keyring façade (see vault.go). It keeps the app-level
// (de)marshalling — one JSON blob per (service, account), the Token struct —
// that the hand-rolled Win32 CredWrite/CredRead code used to carry, and delegates
// the raw credential I/O to keyring.
//
// service defaults to "weft-app", account is the issuer URL, so an operator can
// keep multiple clusters logged in side by side. The type name stays "Keychain"
// so the orchestration in auth.go / tray.go / main.go is unchanged.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
)

// defaultKeychain returns the vault-backed session-token store.
func defaultKeychain() KeychainStore { return keyringKeychain{} }

type keyringKeychain struct{}

func (keyringKeychain) Get(service, account string) (Token, bool, error) {
	blob, err := vaultGet(service, account)
	switch {
	case errors.Is(err, errVaultNotFound), errors.Is(err, errVaultUnavailable):
		// No cached session — or no vault on this host — so the caller falls
		// through to the picker / login WebView, exactly as before.
		return Token{}, false, nil
	case err != nil:
		return Token{}, false, fmt.Errorf("credential vault get: %w", err)
	}
	var tok Token
	if err := json.Unmarshal(blob, &tok); err != nil {
		return Token{}, false, fmt.Errorf("credential vault get: parse blob: %w", err)
	}
	return tok, true, nil
}

func (keyringKeychain) Set(service, account string, tok Token) error {
	blob, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("credential vault set: marshal: %w", err)
	}
	if err := vaultSet(service, account, blob); err != nil {
		return fmt.Errorf("credential vault set: %w", err)
	}
	return nil
}

func (keyringKeychain) Delete(service, account string) error {
	if err := vaultDelete(service, account); err != nil {
		return fmt.Errorf("credential vault delete: %w", err)
	}
	return nil
}
