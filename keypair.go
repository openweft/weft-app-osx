// keypair.go — the ed25519 private-key store for the keypair-fallback sign-in
// flow, backed by the host credential vault through the go-keyring/keyring
// façade (see vault.go). It keeps the app-level marshalling — the raw 64-byte
// ed25519 private key (the canonical seed||pubkey form ed25519.NewKeyFromSeed
// produces) and its length validation — that the hand-rolled Win32 code carried,
// and delegates the raw credential I/O to keyring.
//
// A distinct "account" (issuer) per cluster keeps multiple clusters' keypairs
// side by side. The vault provides the at-rest protection (DPAPI under the
// Windows Credential Manager, the Keychain/Secret Service elsewhere).
package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
)

// defaultKeypairStore returns the vault-backed ed25519 keypair store.
func defaultKeypairStore() KeypairStore { return keyringKeypair{} }

type keyringKeypair struct{}

func (keyringKeypair) Get(service, account string) (ed25519.PrivateKey, bool, error) {
	blob, err := vaultGet(service, account)
	switch {
	case errors.Is(err, errVaultNotFound), errors.Is(err, errVaultUnavailable):
		return nil, false, nil
	case err != nil:
		return nil, false, fmt.Errorf("keypair credential vault get: %w", err)
	}
	if len(blob) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("keypair credential vault get: stored blob length = %d, want %d", len(blob), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(blob), true, nil
}

func (keyringKeypair) Set(service, account string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("keypair credential vault set: private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	if err := vaultSet(service, account, []byte(priv)); err != nil {
		return fmt.Errorf("keypair credential vault set: %w", err)
	}
	return nil
}

func (keyringKeypair) Delete(service, account string) error {
	if err := vaultDelete(service, account); err != nil {
		return fmt.Errorf("keypair credential vault delete: %w", err)
	}
	return nil
}
