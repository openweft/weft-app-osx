//go:build darwin

package main

import (
	"crypto/ed25519"
	"fmt"
	"testing"
	"time"
)

// These tests exercise the migrated secKeychain / secKeypair stores against
// the real login Keychain on this machine, proving the go-macos/keychain
// delegation preserves the pre-migration behaviour (add, overwrite, read
// back, miss reports ok=false, delete is idempotent). Unique per-run
// service/account values keep them clear of any real credential.

func uniqueSuffix() string { return fmt.Sprintf("%d", time.Now().UnixNano()) }

func TestSecKeychainRoundTrip(t *testing.T) {
	store := defaultKeychain()
	svc := "weft-app-test-" + uniqueSuffix()
	acct := "issuer-" + uniqueSuffix()
	t.Cleanup(func() { _ = store.Delete(svc, acct) })

	if _, ok, err := store.Get(svc, acct); err != nil || ok {
		t.Fatalf("pre-set Get = (ok=%v, err=%v), want (false, nil)", ok, err)
	}

	want := Token{Kind: TokenOIDC, IDToken: "id-abc", AccessToken: "acc-xyz", Issuer: "https://issuer.example", IssuedAt: time.Now().UTC().Truncate(time.Second)}
	if err := store.Set(svc, acct, want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := store.Get(svc, acct)
	if err != nil || !ok {
		t.Fatalf("Get after Set = (ok=%v, err=%v)", ok, err)
	}
	if got.Bearer() != want.Bearer() || got.Kind != want.Kind || got.Issuer != want.Issuer {
		t.Fatalf("round-tripped Token = %+v, want %+v", got, want)
	}

	// Overwrite in place.
	want2 := want
	want2.IDToken = "id-rotated"
	if err := store.Set(svc, acct, want2); err != nil {
		t.Fatalf("Set (overwrite): %v", err)
	}
	got, _, err = store.Get(svc, acct)
	if err != nil || got.IDToken != "id-rotated" {
		t.Fatalf("Get after overwrite = (%q, %v), want id-rotated", got.IDToken, err)
	}

	if err := store.Delete(svc, acct); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, err := store.Get(svc, acct); err != nil || ok {
		t.Fatalf("post-delete Get = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
	if err := store.Delete(svc, acct); err != nil {
		t.Fatalf("Delete of absent item = %v, want nil", err)
	}
}

func TestSecKeypairRoundTrip(t *testing.T) {
	store := defaultKeypairStore()
	svc := KeypairKeychainService + "-test-" + uniqueSuffix()
	acct := "cluster-" + uniqueSuffix()
	t.Cleanup(func() { _ = store.Delete(svc, acct) })

	if _, ok, err := store.Get(svc, acct); err != nil || ok {
		t.Fatalf("pre-set Get = (ok=%v, err=%v), want (false, nil)", ok, err)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.Set(svc, acct, priv); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := store.Get(svc, acct)
	if err != nil || !ok {
		t.Fatalf("Get after Set = (ok=%v, err=%v)", ok, err)
	}
	if !got.Equal(priv) {
		t.Fatalf("round-tripped private key differs from stored key")
	}

	if err := store.Delete(svc, acct); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok, _ := store.Get(svc, acct); ok {
		t.Fatalf("post-delete Get ok = true, want false")
	}
}
