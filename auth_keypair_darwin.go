// auth_keypair_darwin.go — Keychain store for the ed25519 private key
// used by the keypair-fallback flow.
//
// We store the raw 64-byte ed25519 private key (the canonical
// seed||pubkey form ed25519.NewKeyFromSeed produces) rather than a PEM
// / JSON wrapper: the item never leaves macOS, the Security framework
// already owns the at-rest protection, and the simpler blob makes the
// Set/Get path obvious.
//
// Service is pinned to KeypairKeychainService ("weft-app-keypair") so
// the keypair item never collides with the session-token store
// ("weft-app"). A different account label per issuer (see
// keypairAccountFor) keeps multiple clusters logged in side-by-side.
//
// The raw CoreFoundation + Security binding lives in the pure-Go,
// CGO_ENABLED=0 package github.com/go-macos/keychain; this file only
// boxes / unboxes the 64-byte private key.
package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/go-macos/keychain"
)

// defaultKeypairStore returns the real Security-framework-backed store.
func defaultKeypairStore() KeypairStore { return secKeypair{} }

type secKeypair struct{}

func (secKeypair) Get(service, account string) (ed25519.PrivateKey, bool, error) {
	blob, err := keychain.Get(service, account)
	if errors.Is(err, keychain.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("keypair keychain get: %w", err)
	}
	if len(blob) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("keypair keychain get: stored blob length = %d, want %d", len(blob), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(blob), true, nil
}

func (secKeypair) Set(service, account string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("keypair keychain set: private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if err := keychain.Set(service, account, priv); err != nil {
		return fmt.Errorf("keypair keychain set: %w", err)
	}
	return nil
}

func (secKeypair) Delete(service, account string) error {
	if err := keychain.Delete(service, account); err != nil {
		return fmt.Errorf("keypair keychain delete: %w", err)
	}
	return nil
}
