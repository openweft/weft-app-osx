// keychain_darwin.go — macOS Keychain Get/Set/Delete via the Security
// framework, no third-party deps.
//
// We persist a single JSON blob (the marshalled Token) under one
// kSecClassGenericPassword item per (service, account) pair. service
// defaults to "weft-app", account is the issuer URL so an operator
// can keep multiple clusters logged in side by side.
package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>
#include <string.h>

// kcSet writes (or replaces) a Generic Password item with the given
// service + account + data. Returns 0 on success, a Security error
// code otherwise.
static OSStatus kcSet(const char *service, const char *account,
                     const void *data, int dataLen) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFDataRef payload = CFDataCreate(NULL, (const UInt8 *)data, dataLen);

    const void *qkeys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *qvals[] = { kSecClassGenericPassword, svc, acc };
    CFDictionaryRef query = CFDictionaryCreate(NULL, qkeys, qvals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    // Try update first ; if not found, add.
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

// kcGet reads the Generic Password for service+account. On success
// returns 0 and *outData/*outLen point to a malloc'd buffer the caller
// must free(). On miss returns errSecItemNotFound. Other errors return
// the Security status.
static OSStatus kcGet(const char *service, const char *account,
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

static OSStatus kcDelete(const char *service, const char *account) {
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
	"encoding/json"
	"fmt"
	"unsafe"
)

const errSecItemNotFound = -25300

// defaultKeychain returns the real Security-framework backed store.
func defaultKeychain() KeychainStore { return secKeychain{} }

type secKeychain struct{}

func (secKeychain) Get(service, account string) (Token, bool, error) {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))

	var data unsafe.Pointer
	var n C.int
	st := C.kcGet(cs, ca, &data, &n)
	if int(st) == errSecItemNotFound {
		return Token{}, false, nil
	}
	if int(st) != 0 {
		return Token{}, false, fmt.Errorf("keychain get: OSStatus %d", int(st))
	}
	defer C.free(data)
	buf := C.GoBytes(data, n)
	var tok Token
	if err := json.Unmarshal(buf, &tok); err != nil {
		return Token{}, false, fmt.Errorf("keychain get: parse blob: %w", err)
	}
	return tok, true, nil
}

func (secKeychain) Set(service, account string, tok Token) error {
	blob, err := json.Marshal(tok)
	if err != nil {
		return fmt.Errorf("keychain set: marshal: %w", err)
	}
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	st := C.kcSet(cs, ca, unsafe.Pointer(&blob[0]), C.int(len(blob)))
	if int(st) != 0 {
		return fmt.Errorf("keychain set: OSStatus %d", int(st))
	}
	return nil
}

func (secKeychain) Delete(service, account string) error {
	cs := C.CString(service)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(account)
	defer C.free(unsafe.Pointer(ca))
	st := C.kcDelete(cs, ca)
	if int(st) != 0 && int(st) != errSecItemNotFound {
		return fmt.Errorf("keychain delete: OSStatus %d", int(st))
	}
	return nil
}
