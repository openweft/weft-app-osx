// keychain_darwin.go — session-token store over the macOS Keychain.
//
// We persist a single JSON blob (the marshalled Token) under one
// kSecClassGenericPassword item per (service, account) pair. service
// defaults to "weft-app", account is the issuer URL so an operator can
// keep multiple clusters logged in side by side.
//
// The raw CoreFoundation + Security binding lives in the pure-Go,
// CGO_ENABLED=0 package github.com/go-macos/keychain (shared with the
// weft-loom twin and the reader apps); this file only marshals the
// Token to/from the opaque byte blob it stores.
package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-macos/keychain"
)

// defaultKeychain returns the real Security-framework backed store.
func defaultKeychain() KeychainStore { return secKeychain{} }

type secKeychain struct{}

func (secKeychain) Get(service, account string) (Token, bool, error) {
	blob, err := keychain.Get(service, account)
	if errors.Is(err, keychain.ErrNotFound) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, fmt.Errorf("keychain get: %w", err)
	}
	var tok Token
	if err := json.Unmarshal(blob, &tok); err != nil {
		return Token{}, false, fmt.Errorf("keychain get: parse blob: %w", err)
	}
	return tok, true, nil
}

func (secKeychain) Set(service, account string, tok Token) error {
	blob, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("keychain set: marshal: %w", err)
	}
	if err := keychain.Set(service, account, blob); err != nil {
		return fmt.Errorf("keychain set: %w", err)
	}
	return nil
}

func (secKeychain) Delete(service, account string) error {
	if err := keychain.Delete(service, account); err != nil {
		return fmt.Errorf("keychain delete: %w", err)
	}
	return nil
}
