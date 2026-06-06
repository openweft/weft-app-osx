// auth_keypair_darwin.go — Keychain Get/Set/Delete for the ed25519
// private key used by the keypair-fallback flow.
//
// We deliberately store the raw 64-byte ed25519 private key (the
// canonical seed||pubkey form ed25519.NewKeyFromSeed produces) rather
// than a PEM / JSON wrapper : the keypair Keychain item never leaves
// macOS, the Security framework already owns the at-rest protection,
// and the simpler blob makes the Set/Get path obvious.
//
// Service is pinned to KeypairKeychainService ("weft-app-keypair") so
// the keypair item never collides with the session-token store
// ("weft-app"). A different account label per issuer (see
// keypairAccountFor) keeps multiple clusters logged in side-by-side.
package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// The keychain helpers in keychain_darwin.go work on opaque CFData
// blobs ; we reuse them via a thin Go-side wrapper rather than copying
// the C code. The two stores carry different schemas (one is a Token
// JSON, the other is raw 64 bytes) so the wrappers in this file box /
// unbox the bytes accordingly.

static OSStatus kpSet(const char *service, const char *account,
                     const void *data, int dataLen) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFDataRef payload = CFDataCreate(NULL, (const UInt8 *)data, dataLen);

    const void *qkeys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *qvals[] = { kSecClassGenericPassword, svc, acc };
    CFDictionaryRef query = CFDictionaryCreate(NULL, qkeys, qvals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    const void *ukeys[] = { kSecValueData };
    const void *uvals[] = { payload };
    CFDictionaryRef upd = CFDictionaryCreate(NULL, ukeys, uvals, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemUpdate(query, upd);
    if (st == errSecItemNotFound) {
        const void *akeys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData };
        const void *avals[] = { kSecClassGenericPassword, svc, acc, payload };
        CFDictionaryRef add = CFDictionaryCreate(NULL, akeys, avals, 4,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        st = SecItemAdd(add, NULL);
        CFRelease(add);
    }
    CFRelease(upd);
    CFRelease(query);
    CFRelease(payload);
    CFRelease(svc);
    CFRelease(acc);
    return st;
}

static OSStatus kpGet(const char *service, const char *account,
                     void **outData, int *outLen) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit };
    const void *vals[] = { kSecClassGenericPassword, svc, acc, kCFBooleanTrue, kSecMatchLimitOne };
    CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef out = NULL;
    OSStatus st = SecItemCopyMatching(query, &out);
    CFRelease(query);
    CFRelease(svc);
    CFRelease(acc);
    if (st != errSecSuccess) {
        if (out) CFRelease(out);
        return st;
    }
    CFDataRef d = (CFDataRef)out;
    CFIndex n = CFDataGetLength(d);
    void *buf = malloc((size_t)n);
    if (!buf) { CFRelease(out); return -1; }
    memcpy(buf, CFDataGetBytePtr(d), (size_t)n);
    *outData = buf;
    *outLen = (int)n;
    CFRelease(out);
    return errSecSuccess;
}

static OSStatus kpDelete(const char *service, const char *account) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *vals[] = { kSecClassGenericPassword, svc, acc };
    CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus st = SecItemDelete(query);
    CFRelease(query);
    CFRelease(svc);
    CFRelease(acc);
    return st;
}
*/
import "C"

import (
	"crypto/ed25519"
	"fmt"
	"unsafe"
)

// defaultKeypairStore returns the real Security-framework-backed store.
func defaultKeypairStore() KeypairStore { return secKeypair{} }

type secKeypair struct{}

func (secKeypair) Get(service, account string) (ed25519.PrivateKey, bool, error) {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))

	var data unsafe.Pointer
	var n C.int
	st := C.kpGet(cs, ca, &data, &n)
	if int(st) == errSecItemNotFound {
		return nil, false, nil
	}
	if int(st) != 0 {
		return nil, false, fmt.Errorf("keypair keychain get: OSStatus %d", int(st))
	}
	defer C.free(data)
	buf := C.GoBytes(data, n)
	if len(buf) != ed25519.PrivateKeySize {
		return nil, false, fmt.Errorf("keypair keychain get: stored blob length = %d, want %d", len(buf), ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(buf), true, nil
}

func (secKeypair) Set(service, account string, priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("keypair keychain set: private key length = %d, want %d", len(priv), ed25519.PrivateKeySize)
	}
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	st := C.kpSet(cs, ca, unsafe.Pointer(&priv[0]), C.int(len(priv)))
	if int(st) != 0 {
		return fmt.Errorf("keypair keychain set: OSStatus %d", int(st))
	}
	return nil
}

func (secKeypair) Delete(service, account string) error {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	st := C.kpDelete(cs, ca)
	if int(st) != 0 && int(st) != errSecItemNotFound {
		return fmt.Errorf("keypair keychain delete: OSStatus %d", int(st))
	}
	return nil
}
