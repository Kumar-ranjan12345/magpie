// Test program for Magpie's ProtectedApp fixture: the usual runtime protections.
#import <DeviceCheck/DeviceCheck.h>
#import <Foundation/Foundation.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <string.h>

typedef int (*ptrace_fn)(int, int, void *, int);

static BOOL isJailbroken(void) {
    NSArray *paths = @[ @"/Applications/Cydia.app", @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                        @"/private/var/lib/apt", @"/var/jb" ];
    for (NSString *p in paths) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:p]) return YES;
    }
    return [[NSFileManager defaultManager] fileExistsAtPath:@"/private/jailbreak.txt"];
}

static BOOL isHooked(void) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (strstr(name, "FridaGadget") || strstr(name, "MobileSubstrate") || strstr(name, "libhooker")) return YES;
    }
    return NO;
}

static void denyDebugger(void) {
    ptrace_fn ptrace = (ptrace_fn)dlsym(RTLD_SELF, "ptrace");
    if (ptrace) ptrace(31, 0, 0, 0); // PT_DENY_ATTACH
}

int main(void) {
    @autoreleasepool {
        denyDebugger();
        if (@available(iOS 14.0, *)) {
            NSLog(@"%d", [DCAppAttestService sharedService].isSupported);
        }
        return isJailbroken() || isHooked();
    }
}
