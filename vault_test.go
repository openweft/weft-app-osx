package main

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/go-keyring/keyring"
)

// fakeVault is an in-memory stand-in for the go-keyring/keyring façade, wired in
// by swapping the vaultSet/vaultGet/vaultDelete seams (vault.go). It lets the
// credential stores be exercised across every branch without a live vault.
type fakeVault struct {
	m              map[string][]byte
	setErr, getErr error
	delErr         error
	getSentinel    error // returned by Get instead of errVaultNotFound on a miss
}

func newFakeVault() *fakeVault { return &fakeVault{m: map[string][]byte{}} }

func vkey(service, account string) string { return service + "\x00" + account }

// install swaps the package seams to this fake for the duration of the test.
// vaultSet accepts the façade's variadic options (the token/keypair stores pass
// none — they are plain items with no user-presence gate).
func (f *fakeVault) install(t *testing.T) {
	t.Helper()
	os, og, od := vaultSet, vaultGet, vaultDelete
	vaultSet = func(service, account string, secret []byte, _ ...keyring.Option) error {
		if f.setErr != nil {
			return f.setErr
		}
		f.m[vkey(service, account)] = append([]byte(nil), secret...)
		return nil
	}
	vaultGet = func(service, account string) ([]byte, error) {
		if f.getErr != nil {
			return nil, f.getErr
		}
		b, ok := f.m[vkey(service, account)]
		if !ok {
			if f.getSentinel != nil {
				return nil, f.getSentinel
			}
			return nil, errVaultNotFound
		}
		return b, nil
	}
	vaultDelete = func(service, account string) error {
		if f.delErr != nil {
			return f.delErr
		}
		delete(f.m, vkey(service, account))
		return nil
	}
	t.Cleanup(func() { vaultSet, vaultGet, vaultDelete = os, og, od })
}

// ---- keychain (session Token) -------------------------------------------

func TestKeychainRoundTrip(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	kc := keyringKeychain{}
	want := Token{Kind: TokenOIDC, AccessToken: "abc", RefreshToken: "r"}
	if err := kc.Set("weft-app", "https://issuer", want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := kc.Get("weft-app", "https://issuer")
	if err != nil || !ok {
		t.Fatalf("Get = (%v, %v, %v)", got, ok, err)
	}
	if got.AccessToken != "abc" || got.Kind != TokenOIDC {
		t.Fatalf("round-trip token = %+v", got)
	}
}

func TestKeychainGetMiss(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	_, ok, err := (keyringKeychain{}).Get("weft-app", "absent")
	if ok || err != nil {
		t.Fatalf("miss = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

func TestKeychainGetUnavailableIsMiss(t *testing.T) {
	f := newFakeVault()
	f.getSentinel = errVaultUnavailable
	f.install(t)
	_, ok, err := (keyringKeychain{}).Get("weft-app", "x")
	if ok || err != nil {
		t.Fatalf("unavailable = (ok=%v, err=%v), want (false, nil)", ok, err)
	}
}

func TestKeychainGetError(t *testing.T) {
	f := newFakeVault()
	f.getErr = errors.New("vault boom")
	f.install(t)
	if _, _, err := (keyringKeychain{}).Get("s", "a"); err == nil || !strings.Contains(err.Error(), "vault boom") {
		t.Fatalf("Get err = %v", err)
	}
}

func TestKeychainGetBadBlob(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	f.m[vkey("s", "a")] = []byte("{not json")
	if _, _, err := (keyringKeychain{}).Get("s", "a"); err == nil || !strings.Contains(err.Error(), "parse blob") {
		t.Fatalf("Get bad blob err = %v", err)
	}
}

func TestKeychainSetError(t *testing.T) {
	f := newFakeVault()
	f.setErr = errors.New("write denied")
	f.install(t)
	if err := (keyringKeychain{}).Set("s", "a", Token{}); err == nil || !strings.Contains(err.Error(), "write denied") {
		t.Fatalf("Set err = %v", err)
	}
}

func TestKeychainDeleteAndError(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	if err := (keyringKeychain{}).Delete("s", "a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	f.delErr = errors.New("del fail")
	if err := (keyringKeychain{}).Delete("s", "a"); err == nil || !strings.Contains(err.Error(), "del fail") {
		t.Fatalf("Delete err = %v", err)
	}
}

func TestDefaultKeychainType(t *testing.T) {
	if _, ok := defaultKeychain().(keyringKeychain); !ok {
		t.Fatalf("defaultKeychain = %T", defaultKeychain())
	}
}

// ---- keypair (ed25519) ---------------------------------------------------

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	return priv
}

func TestKeypairRoundTrip(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	kp := keyringKeypair{}
	priv := newKey(t)
	if err := kp.Set("weft-app-keypair", "iss", priv); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, ok, err := kp.Get("weft-app-keypair", "iss")
	if err != nil || !ok {
		t.Fatalf("Get = (ok=%v, err=%v)", ok, err)
	}
	if !got.Equal(priv) {
		t.Fatalf("round-trip key mismatch")
	}
}

func TestKeypairGetMissAndUnavailable(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	if _, ok, err := (keyringKeypair{}).Get("s", "absent"); ok || err != nil {
		t.Fatalf("miss = (ok=%v, err=%v)", ok, err)
	}
	f.getSentinel = errVaultUnavailable
	if _, ok, err := (keyringKeypair{}).Get("s", "absent"); ok || err != nil {
		t.Fatalf("unavailable = (ok=%v, err=%v)", ok, err)
	}
}

func TestKeypairGetError(t *testing.T) {
	f := newFakeVault()
	f.getErr = errors.New("kp boom")
	f.install(t)
	if _, _, err := (keyringKeypair{}).Get("s", "a"); err == nil || !strings.Contains(err.Error(), "kp boom") {
		t.Fatalf("Get err = %v", err)
	}
}

func TestKeypairGetWrongSize(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	f.m[vkey("s", "a")] = []byte("too short")
	if _, _, err := (keyringKeypair{}).Get("s", "a"); err == nil || !strings.Contains(err.Error(), "blob length") {
		t.Fatalf("Get wrong-size err = %v", err)
	}
}

func TestKeypairSetWrongSize(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	if err := (keyringKeypair{}).Set("s", "a", ed25519.PrivateKey("short")); err == nil || !strings.Contains(err.Error(), "private key length") {
		t.Fatalf("Set wrong-size err = %v", err)
	}
}

func TestKeypairSetError(t *testing.T) {
	f := newFakeVault()
	f.setErr = errors.New("kp write")
	f.install(t)
	if err := (keyringKeypair{}).Set("s", "a", newKey(t)); err == nil || !strings.Contains(err.Error(), "kp write") {
		t.Fatalf("Set err = %v", err)
	}
}

func TestKeypairDeleteAndError(t *testing.T) {
	f := newFakeVault()
	f.install(t)
	if err := (keyringKeypair{}).Delete("s", "a"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	f.delErr = errors.New("kp del")
	if err := (keyringKeypair{}).Delete("s", "a"); err == nil || !strings.Contains(err.Error(), "kp del") {
		t.Fatalf("Delete err = %v", err)
	}
}

func TestDefaultKeypairStoreType(t *testing.T) {
	if _, ok := defaultKeypairStore().(keyringKeypair); !ok {
		t.Fatalf("defaultKeypairStore = %T", defaultKeypairStore())
	}
}
