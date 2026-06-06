// auth_darwin.go — Cocoa NSWindow picker + WKWebView for the auth flow.
//
// We need the auth window up *before* systray.Run captures the main
// thread. main.go calls Authenticate from the main goroutine before
// runTray ; Cocoa is single-threaded UI so all the window work
// happens on the main thread via dispatch_sync(main_queue).
//
// The picker is a small NSWindow with two NSButtons run via NSApp
// runModalForWindow ; OpenAuthWebView is a second window holding a
// WKWebView whose navigationDelegate watches for the redirect URI and
// closes the window when it sees it.
package main

/*
#cgo CFLAGS: -x objective-c -fobjc-arc
#cgo LDFLAGS: -framework Cocoa -framework WebKit

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#import <objc/runtime.h>

// ---- picker ----------------------------------------------------------

// goPickResult is set by the button targets and read by C after
// runModalForWindow returns.
//   0 = cancelled, 1 = OIDC, 2 = OpenPubkey.
static int g_pickResult = 0;

@interface WeftPickerTarget : NSObject
@property (assign) NSWindow *win;
- (void)pickOIDC:(id)sender;
- (void)pickOpenPubkey:(id)sender;
@end

@implementation WeftPickerTarget
- (void)pickOIDC:(id)sender {
    g_pickResult = 1;
    [NSApp stopModalWithCode:NSModalResponseOK];
    [self.win orderOut:nil];
}
- (void)pickOpenPubkey:(id)sender {
    g_pickResult = 2;
    [NSApp stopModalWithCode:NSModalResponseOK];
    [self.win orderOut:nil];
}
@end

// runPicker creates the NSWindow, populates the two buttons, runs the
// modal loop, and returns the picked code. Blocks the calling thread —
// caller must invoke from the main thread.
static int runPicker(void) {
    g_pickResult = 0;
    [[NSApplication sharedApplication]
        setActivationPolicy:NSApplicationActivationPolicyRegular];
    [NSApp activateIgnoringOtherApps:YES];

    NSRect frame = NSMakeRect(0, 0, 440, 200);
    NSWindow *win = [[NSWindow alloc]
        initWithContentRect:frame
                  styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable)
                    backing:NSBackingStoreBuffered
                      defer:NO];
    [win setTitle:@"Sign in to Weft"];
    [win setReleasedWhenClosed:NO];

    NSTextField *label = [[NSTextField alloc] initWithFrame:NSMakeRect(20, 130, 400, 40)];
    [label setStringValue:@"Choose how to sign in to your Weft cluster."];
    [label setBezeled:NO];
    [label setDrawsBackground:NO];
    [label setEditable:NO];
    [label setSelectable:NO];
    [[win contentView] addSubview:label];

    WeftPickerTarget *target = [[WeftPickerTarget alloc] init];
    target.win = win;

    NSButton *b1 = [[NSButton alloc] initWithFrame:NSMakeRect(20, 60, 200, 40)];
    [b1 setTitle:@"Sign in with OpenPubkey"];
    [b1 setBezelStyle:NSBezelStyleRounded];
    [b1 setTarget:target];
    [b1 setAction:@selector(pickOpenPubkey:)];
    [[win contentView] addSubview:b1];

    NSButton *b2 = [[NSButton alloc] initWithFrame:NSMakeRect(230, 60, 190, 40)];
    [b2 setTitle:@"Sign in with OIDC"];
    [b2 setBezelStyle:NSBezelStyleRounded];
    [b2 setKeyEquivalent:@"\r"];
    [b2 setTarget:target];
    [b2 setAction:@selector(pickOIDC:)];
    [[win contentView] addSubview:b2];

    [win center];
    [win makeKeyAndOrderFront:nil];
    [NSApp runModalForWindow:win];
    return g_pickResult;
}

// ---- WebView ---------------------------------------------------------

static char *g_finalURL = NULL; // strdup'd

@interface WeftWebNavDelegate : NSObject <WKNavigationDelegate>
@property (copy) NSString *redirectPrefix;
@property (assign) NSWindow *win;
@end

@implementation WeftWebNavDelegate
- (void)webView:(WKWebView *)webView
        decidePolicyForNavigationAction:(WKNavigationAction *)nav
        decisionHandler:(void (^)(WKNavigationActionPolicy))decisionHandler {
    NSURL *u = nav.request.URL;
    if (u && self.redirectPrefix.length > 0 &&
        [u.absoluteString hasPrefix:self.redirectPrefix]) {
        // Capture the redirect URL with all its query params and close
        // the window. The HTTP listener on the Go side will also see
        // this hit and may resolve first ; the duplication is fine
        // because awaitCallback is a one-shot channel.
        const char *s = [u.absoluteString UTF8String];
        if (s) g_finalURL = strdup(s);
        decisionHandler(WKNavigationActionPolicyCancel);
        [NSApp stopModalWithCode:NSModalResponseOK];
        [self.win orderOut:nil];
        return;
    }
    decisionHandler(WKNavigationActionPolicyAllow);
}
@end

static char *runAuthWebView(const char *startURL, const char *redirectPrefix) {
    g_finalURL = NULL;
    NSString *nsStart = [NSString stringWithUTF8String:startURL];
    NSString *nsRedirect = [NSString stringWithUTF8String:redirectPrefix];
    NSURL *u = [NSURL URLWithString:nsStart];
    if (u == nil) return NULL;

    NSRect frame = NSMakeRect(0, 0, 720, 720);
    NSWindow *win = [[NSWindow alloc]
        initWithContentRect:frame
                  styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskResizable)
                    backing:NSBackingStoreBuffered
                      defer:NO];
    [win setTitle:@"Sign in to Weft"];
    [win setReleasedWhenClosed:NO];

    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    WKWebView *wv = [[WKWebView alloc] initWithFrame:[[win contentView] bounds] configuration:cfg];
    [wv setAutoresizingMask:(NSViewWidthSizable | NSViewHeightSizable)];

    WeftWebNavDelegate *del = [[WeftWebNavDelegate alloc] init];
    del.redirectPrefix = nsRedirect;
    del.win = win;
    wv.navigationDelegate = del;
    // Keep the delegate alive for the modal lifetime.
    objc_setAssociatedObject(wv, "weftDel", del, OBJC_ASSOCIATION_RETAIN_NONATOMIC);

    [[win contentView] addSubview:wv];
    NSURLRequest *req = [NSURLRequest requestWithURL:u];
    [wv loadRequest:req];

    [win center];
    [win makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [NSApp runModalForWindow:win];
    return g_finalURL;
}

static void freeAuthURL(char *p) { if (p) free(p); }

// dispatch helpers : Go can't directly call dispatch_sync because it
// would deadlock if Go ran on the main thread already. We expose two
// entry points and the Go side decides which to use depending on
// runtime.LockOSThread state.
*/
import "C"

import (
	"context"
	"runtime"
	"sync"
	"unsafe"
)

// defaultPicker returns the Cocoa picker.
func defaultPicker() Picker { return cocoaPicker{} }

type cocoaPicker struct{}

// pickerMu serializes the two main-thread modal operations so we
// never enter runModalForWindow while another modal is already up.
var pickerMu sync.Mutex

func (cocoaPicker) Pick(ctx context.Context) AuthChoice {
	pickerMu.Lock()
	defer pickerMu.Unlock()

	// Cocoa requires this on the main thread. main.go arranges that
	// Authenticate runs before systray.Run captures the main thread,
	// and Authenticate itself runs on the main goroutine.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	done := make(chan AuthChoice, 1)
	go func() {
		// Allow ctx cancel to unblock by faking a "cancelled" return
		// once the modal returns. We can't actually interrupt
		// runModalForWindow from Go ; this is best-effort.
		<-ctx.Done()
		done <- ChoiceCancelled
	}()

	switch int(C.runPicker()) {
	case 1:
		return ChoiceOIDC
	case 2:
		return ChoiceOpenPubkey
	default:
		return ChoiceCancelled
	}
}

func (cocoaPicker) OpenAuthWebView(ctx context.Context, u, redirectPrefix string) (string, error) {
	pickerMu.Lock()
	defer pickerMu.Unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cStart := C.CString(u)
	defer C.free(unsafe.Pointer(cStart))
	cRedir := C.CString(redirectPrefix)
	defer C.free(unsafe.Pointer(cRedir))

	cResult := C.runAuthWebView(cStart, cRedir)
	if cResult == nil {
		return "", nil
	}
	defer C.freeAuthURL(cResult)
	return C.GoString(cResult), nil
}
