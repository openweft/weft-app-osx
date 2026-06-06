// promoteDashboardActivation flips the dashboard subprocess from
// accessory (no Dock, no menu, windows can't activate cleanly under
// the parent's LSUIElement Info.plist) to a regular foreground app —
// gives it a Dock entry with the bundle icon, a main menu, and the
// ability to bring its WKWebView window to the front when the tray
// clicks "Open Dashboard".
//
// macOS-only ; the cgo equivalent of :
//
//   [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
//   [NSApp activateIgnoringOtherApps:YES];
package main

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Cocoa

#import <Cocoa/Cocoa.h>

static void promoteToRegular(void) {
    [[NSApplication sharedApplication]
        setActivationPolicy:NSApplicationActivationPolicyRegular];
    [[NSApplication sharedApplication]
        activateIgnoringOtherApps:YES];
}
*/
import "C"

func promoteDashboardActivation() {
	C.promoteToRegular()
}
