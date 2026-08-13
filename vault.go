// vault.go — the single seam onto the host credential vault, the pure-Go
// (CGO=0) cross-platform façade github.com/go-keyring/keyring. keyring itself
// dispatches to the Windows Credential Manager (via danieljoos/wincred) on
// windows, the macOS Keychain on darwin, and the freedesktop Secret Service on
// linux, so this app no longer hand-rolls Win32 CredWrite/CredRead/CredDelete.
//
// The three functions are kept as package-level variables so tests can swap in
// in-memory fakes and reach every branch of the credential stores without a live
// vault. The sentinel errors are re-exported for callers and tests.
package main

import "github.com/go-keyring/keyring"

var (
	// vaultSet stores secret under (service, account) in the host vault.
	vaultSet = keyring.Set
	// vaultGet reads the secret stored under (service, account); it returns
	// errVaultNotFound when absent and errVaultUnavailable on a host with no
	// reachable vault.
	vaultGet = keyring.Get
	// vaultDelete removes the secret under (service, account); deleting an
	// absent entry is not an error.
	vaultDelete = keyring.Delete
)

// errVaultNotFound and errVaultUnavailable alias the façade sentinels so the
// credential stores can classify a result with errors.Is.
var (
	errVaultNotFound    = keyring.ErrNotFound
	errVaultUnavailable = keyring.ErrUnavailable
)
