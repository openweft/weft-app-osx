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

// sshKCSet writes a passphrase under (service, account) with
// kSecAccessControlUserPresence — surfaces the unified LocalAuthentication
// prompt that offers Touch ID as the primary action and the user's
// account password as a fallback. Without this access control the prompt
// is the legacy 'enter your password' modal that NEVER offers Touch ID
// even when the system is configured for it.
//
// SecItemUpdate cannot change access control retrospectively, so we
// always DELETE then ADD (Keychain accepts this even on miss).
static OSStatus sshKCSet(const char *service, const char *account,
                          const void *data, int dataLen,
                          const char *prompt) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFStringRef pmt = CFStringCreateWithCString(NULL, prompt, kCFStringEncodingUTF8);
    CFDataRef    val = CFDataCreate(NULL, data, dataLen);

    // 1. Best-effort delete of any prior entry — re-running
    //    --store-ssh-passphrase replaces.
    const void *delKeys[] = { kSecClass, kSecAttrService, kSecAttrAccount };
    const void *delVals[] = { kSecClassGenericPassword, svc, acc };
    CFDictionaryRef del = CFDictionaryCreate(NULL, delKeys, delVals, 3,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    (void)SecItemDelete(del);
    CFRelease(del);

    // 2. Build access control : User Presence = Touch ID OR password.
    //    Stays usable on Macs without a biometric sensor.
    CFErrorRef acErr = NULL;
    SecAccessControlRef ac = SecAccessControlCreateWithFlags(NULL,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlUserPresence,
        &acErr);
    if (ac == NULL) {
        if (acErr) CFRelease(acErr);
        CFRelease(val); CFRelease(acc); CFRelease(svc); CFRelease(pmt);
        return errSecAuthFailed;
    }

    // 3. Add the item carrying the access control.
    const void *addKeys[] = { kSecClass, kSecAttrService, kSecAttrAccount,
                               kSecValueData, kSecAttrAccessControl,
                               kSecUseOperationPrompt };
    const void *addVals[] = { kSecClassGenericPassword, svc, acc,
                               val, ac, pmt };
    CFDictionaryRef add = CFDictionaryCreate(NULL, addKeys, addVals, 6,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    OSStatus s = SecItemAdd(add, NULL);
    CFRelease(add); CFRelease(ac);
    CFRelease(val); CFRelease(acc); CFRelease(svc); CFRelease(pmt);
    return s;
}

// sshKCGet reads the passphrase ; kSecUseOperationPrompt is the string
// the system places under the Touch ID prompt ("weft-app wants to use
// your SSH key passphrase to connect to the cluster"), so the user
// knows why they're being authenticated.
static OSStatus sshKCGet(const char *service, const char *account,
                          const char *prompt,
                          void **outData, int *outLen) {
    CFStringRef svc = CFStringCreateWithCString(NULL, service, kCFStringEncodingUTF8);
    CFStringRef acc = CFStringCreateWithCString(NULL, account, kCFStringEncodingUTF8);
    CFStringRef pmt = CFStringCreateWithCString(NULL, prompt, kCFStringEncodingUTF8);
    const void *keys[] = { kSecClass, kSecAttrService, kSecAttrAccount,
                            kSecReturnData, kSecMatchLimit,
                            kSecUseOperationPrompt };
    const void *vals[] = { kSecClassGenericPassword, svc, acc,
                            kCFBooleanTrue, kSecMatchLimitOne, pmt };
    CFDictionaryRef query = CFDictionaryCreate(NULL, keys, vals, 6,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFTypeRef result = NULL;
    OSStatus s = SecItemCopyMatching(query, &result);
    CFRelease(query); CFRelease(svc); CFRelease(acc); CFRelease(pmt);
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
// given key path, or nil if no entry exists (the caller can then
// prompt the user via --store-ssh-passphrase). Reads from a
// User-Presence-gated Keychain item, so the macOS LocalAuthentication
// prompt offers Touch ID as the primary action with the account
// password as fallback.
func sshPassphraseGet(keyPath string) ([]byte, error) {
	cs := C.CString(sshPassphraseService)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(keyPath)
	defer C.free(unsafe.Pointer(ca))
	pmt := C.CString("Unlock your SSH key passphrase to connect to the Weft cluster")
	defer C.free(unsafe.Pointer(pmt))
	var outData unsafe.Pointer
	var outLen C.int
	if rc := C.sshKCGet(cs, ca, pmt, &outData, &outLen); rc != 0 {
		// errSecItemNotFound = -25300
		if rc == -25300 {
			return nil, nil
		}
		// errSecUserCanceled = -128 : the user dismissed the Touch ID /
		// password prompt — propagate as a plain error so the caller can
		// retry.
		if rc == -128 {
			return nil, fmt.Errorf("keychain : user cancelled the authentication prompt")
		}
		return nil, fmt.Errorf("keychain get (service=%s account=%s): OSStatus %d", sshPassphraseService, keyPath, int(rc))
	}
	defer C.free(outData)
	return C.GoBytes(outData, outLen), nil
}

// sshPassphraseSet stores or replaces the passphrase for the given
// key path with kSecAccessControlUserPresence — the item is bound to
// the local device and reads require Touch ID or the user's password.
func sshPassphraseSet(keyPath string, passphrase []byte) error {
	cs := C.CString(sshPassphraseService)
	defer C.free(unsafe.Pointer(cs))
	ca := C.CString(keyPath)
	defer C.free(unsafe.Pointer(ca))
	pmt := C.CString("Save your SSH key passphrase to the Weft Keychain entry")
	defer C.free(unsafe.Pointer(pmt))
	cd := unsafe.Pointer(&passphrase[0])
	if len(passphrase) == 0 {
		// Pass a single null byte to keep the Security API happy ;
		// we'll still record a zero-length payload.
		var z byte
		cd = unsafe.Pointer(&z)
	}
	if rc := C.sshKCSet(cs, ca, cd, C.int(len(passphrase)), pmt); rc != 0 {
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
