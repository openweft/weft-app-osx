// ssh_passphrase_darwin.go — Keychain getter/setter for SSH key
// passphrases. Separate Security framework service ("weft-ssh-
// passphrase") from the session-token store (keychain_darwin.go) so
// removing one doesn't affect the other.
//
// Cgo mirror of the keychain_darwin.go pattern : SecKeychainItem
// generic-password add / find / delete keyed by service + account
// (the canonical SSH key file path). macOS gates Read via its
// standard authentication UI ; the value never lands on disk
// outside the Keychain database, which is itself encrypted.
package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security

#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

static OSStatus sshKCSet(const char *service, const char *account,
                          const void *data, int dataLen) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFDataRef    val = CFDataCreate(NULL, data, dataLen);
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *vals[] = { kSecClassGenericPassword, svc, acc };
    CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    // First try to update an existing item.
    const void *updKeys[] = { kSecValueData };
    const void *updVals[] = { val };
    CFDictionaryRef upd = CFDictionaryCreate(NULL, updKeys, updVals, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus s = SecItemUpdate(query, upd);
    if (s == errSecItemNotFound) {
        const void *addKeys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecValueData };
        const void *addVals[] = { kSecClassGenericPassword, svc, acc, val };
        CFDictionaryRef add = CFDictionaryCreate(NULL, addKeys, addVals, 4,
            &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        s = SecItemAdd(add, NULL);
        CFRelease(add);
    }
    CFRelease(upd); CFRelease(query); CFRelease(val);
    CFRelease(acc); CFRelease(svc);
    return s;
}

static OSStatus sshKCGet(const char *service, const char *account,
                          void **outData, int *outLen) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount, kSecReturnData, kSecMatchLimit };
    const void *vals[] = { kSecClassGenericPassword, svc, acc, kCFBooleanTrue, kSecMatchLimitOne };
    CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 5,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef result = NULL;
    OSStatus s = SecItemCopyMatching(query, &result);
    CFRelease(query); CFRelease(svc); CFRelease(acc);
    if (s != errSecSuccess) {
        return s;
    }
    CFDataRef d = (CFDataRef)result;
    int len = (int)CFDataGetLength(d);
    void *buf = malloc(len);
    memcpy(buf, CFDataGetBytePtr(d), len);
    CFRelease(d);
    *outData = buf;
    *outLen = len;
    return errSecSuccess;
}

static OSStatus sshKCDelete(const char *service, const char *account) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *vals[] = { kSecClassGenericPassword, svc, acc };
    CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus s = SecItemDelete(query);
    CFRelease(query); CFRelease(svc); CFRelease(acc);
    return s;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// sshPassphraseService is the Keychain service identifier under
// which every passphrase entry lives.
const sshPassphraseService = "weft-ssh-passphrase"

// sshPassphraseGet returns the passphrase bytes stored for the
// given key path, or an empty slice if no entry exists (the caller
// can then prompt the user via --store-ssh-passphrase).
func sshPassphraseGet(keyPath string) ([]byte, error) {
	cs := C.CString(sshPassphraseService)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(keyPath)
	defer C.free(unsafe.Pointer(ca))
	var outData unsafe.Pointer
	var outLen C.int
	if rc := C.sshKCGet(cs, ca, &outData, &outLen); rc != 0 {
		// errSecItemNotFound = -25300
		if rc == -25300 {
			return nil, nil
		}
		return nil, fmt.Errorf("keychain get (service=%s account=%s): OSStatus %d", sshPassphraseService, keyPath, int(rc))
	}
	defer C.free(outData)
	return C.GoBytes(outData, outLen), nil
}

// sshPassphraseSet stores or replaces the passphrase for the given
// key path. The macOS Keychain gates subsequent reads through its
// standard authentication UI.
func sshPassphraseSet(keyPath string, passphrase []byte) error {
	cs := C.CString(sshPassphraseService)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(keyPath)
	defer C.free(unsafe.Pointer(ca))
	cd := unsafe.Pointer(&passphrase[0])
	if len(passphrase) == 0 {
		// Pass a single null byte to keep the Security API happy ;
		// we'll still record a zero-length payload.
		var z byte
		cd = unsafe.Pointer(&z)
	}
	if rc := C.sshKCSet(cs, ca, cd, C.int(len(passphrase))); rc != 0 {
		return fmt.Errorf("keychain set (service=%s account=%s): OSStatus %d", sshPassphraseService, keyPath, int(rc))
	}
	return nil
}

// sshPassphraseDelete removes the passphrase entry for the given
// key path (no-op when nothing is cached).
func sshPassphraseDelete(keyPath string) error {
	cs := C.CString(sshPassphraseService)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(keyPath)
	defer C.free(unsafe.Pointer(ca))
	rc := C.sshKCDelete(cs, ca)
	if rc != 0 && rc != -25300 {
		return fmt.Errorf("keychain delete (service=%s account=%s): OSStatus %d", sshPassphraseService, keyPath, int(rc))
	}
	return nil
}
