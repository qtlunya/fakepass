#include <dlfcn.h>
#include <stdlib.h>

@import CommonCrypto;
@import Foundation;
@import UIKit;

#import <SpringBoard/SpringBoard.h>

#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>

#import "util.h"

@interface LASecureData
- (NSData *)data;
@end

@interface MCProfileConnection
+ (instancetype)sharedConnection;
- (id)effectiveValueForSetting:(NSString *)setting;
@end

@interface SBFDeviceLockOutController
- (BOOL)isPermanentlyBlocked;
- (BOOL)isTemporarilyBlocked;
- (void)temporaryBlockStatusChanged;
@end

@interface SBFMobileKeyBagUnlockOptions : NSObject
@property (nonatomic,copy,readonly) NSData *passcode;
@end

@interface SBLockScreenManager
@property (getter=_lockOutController,nonatomic,retain) SBFDeviceLockOutController *lockOutController;
+ (instancetype)sharedInstance;
- (void)lockScreenViewControllerRequestsUnlock;
@end

HBPreferences *prefs;
BOOL isUnlocked;
BOOL isInternalUnlock = NO;
BOOL isResetting = NO;
BOOL didStartBlock = NO;
BOOL creatingPasscode = NO;
int lastLockTime = 0;

BOOL isPasscodeSet() {
    return [[prefs objectForKey:@"passcodeHash"] length] > 0;
}

BOOL checkPasscode(NSString *passcode) {
    if (isInternalUnlock && [passcode isEqualToString:@"__FAKEPASS_INTERNAL_UNLOCK"]) {
        return YES;
    }

    prefs = [[HBPreferences alloc] initWithIdentifier:@"net.cadoth.fakepass"];
    NSString *salt = [prefs objectForKey:@"passcodeSalt"];
    return [generateHashFor(passcode, salt) isEqualToString:[prefs objectForKey:@"passcodeHash"]];
}

BOOL doUnlock(NSString *passcode) {
    if (checkPasscode(passcode)) {
        NSLog(@"Successful unlock with passcode: %@", passcode);
        isUnlocked = YES;
        [prefs removeObjectForKey:@"blockTime"];
        [prefs setInteger:0 forKey:@"failedAttempts"];
        return YES;
    } else {
        NSLog(@"Failed unlock with passcode: %@", passcode);
        int failedAttempts = [prefs integerForKey:@"failedAttempts"] + 1;
        [prefs setInteger:failedAttempts forKey:@"failedAttempts"];
        if (failedAttempts >= 6) {
            [prefs setInteger:[NSDate date].timeIntervalSince1970 forKey:@"blockTime"];
            SBLockScreenManager *lockScreenManager = [%c(SBLockScreenManager) sharedInstance];
            SBFDeviceLockOutController *lockOutController = lockScreenManager.lockOutController;
            if (lockOutController != NULL) {
                NSLog(@"Triggering device lockout due to too many failed attempts");
                [lockOutController temporaryBlockStatusChanged];
            }
        }
        return NO;
    }
}

%hook DevicePINController
- (int)pinLength {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    if (creatingPasscode) {
        %log(@"passcode is being created, ignoring");
        return %orig;
    }
    %log(@"hooked");

    int passcodeType = [prefs integerForKey:@"passcodeType"];
    int length;

    switch (passcodeType) {
        case 0:
            length = 4;
            break;
        case 1:
            length = 6;
            break;
        default:
            return %orig;
    }

    NSLog(@"Spoofing passcode length: %d", length);
    return length;
}

- (BOOL)isNumericPIN {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    if (creatingPasscode) {
        %log(@"passcode is being created, ignoring");
        return %orig;
    }
    %log(@"hooked");

    return [prefs integerForKey:@"passcodeType"] < 3;
}

- (BOOL)simplePIN {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    if (creatingPasscode) {
        %log(@"passcode is being created, ignoring");
        return %orig;
    }
    %log(@"hooked");

    int passcodeType = [prefs integerForKey:@"passcodeType"];

    return passcodeType < 2;
}
%end

%hook DevicePINPane
- (void)slideToNewPasscodeField:(BOOL)fixedLength  // false if custom numeric code is selected
               requiresKeyboard:(BOOL)requiresKeyboard
                    numericOnly:(BOOL)numericOnly
                     transition:(BOOL)transition
             showsOptionsButton:(BOOL)showsOptionsButton {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    creatingPasscode = YES;
    %orig;
}
%end

%hook MCPasscodeManager
- (BOOL)isPasscodeSet {
    %log(@"hooked");
    return isPasscodeSet();
}
%end

%hook MCProfileConnection
- (BOOL)changePasscodeFrom:(NSString *)oldPasscode to:(NSString *)newPasscode outError:(id *)outError {
    creatingPasscode = NO;

    prefs = [[HBPreferences alloc] initWithIdentifier:@"net.cadoth.fakepass"];

    if (oldPasscode.length > 0 && !checkPasscode(oldPasscode)) {
        %log(@"old passcode incorrect");
        return NO;
    }

    if (newPasscode.length > 0) {
        %log(@"got new passcode");

        NSString *salt = generateSalt();
        [prefs setObject:generateHashFor(newPasscode, salt) forKey:@"passcodeHash"];
        [prefs setObject:salt forKey:@"passcodeSalt"];

        NSInteger passcodeType;

        if ([newPasscode rangeOfString:@"^[0-9]+$" options:NSRegularExpressionSearch].location != NSNotFound) {
            switch (newPasscode.length) {
                case 4:
                    passcodeType = 0;
                    break;
                case 6:
                    passcodeType = 1;
                    break;
                default:
                    passcodeType = 2;
                    break;
            }
        } else {
            passcodeType = 3;
        }

        [prefs setInteger:passcodeType forKey:@"passcodeType"];
    } else {
        %log(@"no new passcode");

        [prefs removeObjectForKey:@"blockTime"];
        [prefs removeObjectForKey:@"failedAttempts"];
        [prefs removeObjectForKey:@"passcodeHash"];
        [prefs removeObjectForKey:@"passcodeSalt"];
        [prefs removeObjectForKey:@"passcodeType"];
    }

    if (!oldPasscode) {
        // respring to work around bug where it's impossible to unlock
        [HBRespringController respring];
    }

    return true;
}

- (BOOL)unlockDeviceWithPasscode:(id)passcode outError:(id *)error {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    if (checkPasscode(passcode)) {
        NSLog(@"Successful authentication with passcode: %@", passcode);
        return YES;
    } else {
        NSLog(@"Failed authentication with passcode: %@", passcode);
        return NO;
    }
}

- (id)effectiveValueForSetting:(NSString *)setting {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    NSInteger maxGracePeriod = [prefs integerForKey:@"maxGracePeriod" default:-1];

    if ([setting isEqualToString:@"maxGracePeriod"] && maxGracePeriod > -1) {
        return @(maxGracePeriod);
    }

    return %orig;
}

- (void)setValue:(id)value forSetting:(NSString *)setting passcode:(id)passcode {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    if ([setting isEqualToString:@"maxGracePeriod"]) {
        [prefs setInteger:[value integerValue] forKey:@"maxGracePeriod"];
    }

    %orig;
}
%end

%hook NSBundle
- (NSString *)localizedStringForKey:(NSString *)key value:(NSString *)value table:(NSString *)tableName {
    NSString *ret = %orig;

    if ([self.bundleIdentifier isEqualToString:@"com.apple.preferences-ui-framework"]
            && [tableName isEqualToString:@"Passcode Lock"]
            && [key isEqualToString:@"PASSCODE_ON"]) {
        return [NSString stringWithFormat:@"%@ (FakePass)", ret];
    }

    return ret;
}
%end

%hook SBBacklightController
- (void)_startFadeOutAnimationFromLockSource:(int)arg1 {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    if (isUnlocked) {
        [[%c(SBLockScreenManager) sharedInstance] lockScreenViewControllerRequestsUnlock];
    }
    %orig;
}
%end

%hook SBDoubleClickSleepWakeHardwareButtonInteraction
- (void)_performSleep {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    if (isUnlocked) {
        [[%c(SBLockScreenManager) sharedInstance] lockScreenViewControllerRequestsUnlock];
    }
    %orig;
}
%end

%hook SBFDeviceBlockTimer
- (NSString *)subtitleText {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    int failedAttempts = [prefs integerForKey:@"failedAttempts"];
    NSTimeInterval blockTime = [prefs integerForKey:@"blockTime"];
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    NSTimeInterval lockoutTime;

    if (failedAttempts >= 10) {
        lockoutTime = 3600;
    } else if (failedAttempts >= 8) {
        lockoutTime = 900;
    } else if (failedAttempts >= 7) {
        lockoutTime = 300;
    } else if (failedAttempts >= 6) {
        lockoutTime = 60;
    } else {
        return %orig;
    }

    NSTimeInterval remainingSecs = (blockTime + lockoutTime) - now;

    NSDateComponents *dateComponents = [NSDateComponents new];
    dateComponents.minute = ceil(remainingSecs / 60);

    if (failedAttempts <= 10) {
        NSString *localizedString = NSLocalizedStringFromTableInBundle(
            @"TRY_AGAIN_AFTER_TIMEOUT",
            @"DeviceBlock",
            [NSBundle bundleWithIdentifier:@"com.apple.SpringBoardFoundation"],
            nil
        );
        NSString *time = [
            NSDateComponentsFormatter localizedStringFromDateComponents:dateComponents
                                                             unitsStyle:NSDateComponentsFormatterUnitsStyleFull
        ];
        return [NSString stringWithFormat:localizedString, time];
    } else {
        return NSLocalizedStringFromTableInBundle(
            @"CONNECT_TO_ITUNES",
            @"DeviceBlock",
            [NSBundle bundleWithIdentifier:@"com.apple.SpringBoardFoundation"],
            nil
        );
    }
}
%end

%hook SBFDeviceLockOutController
- (BOOL)isPermanentlyBlocked {
    if (!isPasscodeSet()) {
        //%log(@"no passcode set, ignoring");
        return %orig;
    }
    //%log(@"hooked");

    BOOL ret = [prefs integerForKey:@"failedAttempts"] > 10;

    if (ret && !isResetting) {
        HBPreferences *sbPrefs = [[HBPreferences alloc] initWithIdentifier:@"com.apple.springboard"];

        if ([sbPrefs boolForKey:@"SBDeviceWipeEnabled"]) {
            void *UIKit = dlopen("/System/Library/Framework/UIKit.framework/UIKit", RTLD_LAZY);
            mach_port_t *(*SBSSpringBoardServerPort)() = (mach_port_t * (*)()) dlsym(UIKit, "SBSSpringBoardServerPort");

            void *SpringBoardServices = dlopen(
                "/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY
            );
            int (*SBDataReset)(mach_port_t* port, int wipeMode) = (
                (int (*)(mach_port_t *, int)) dlsym(SpringBoardServices, "SBDataReset")
            );

            isResetting = YES;
            SBDataReset(SBSSpringBoardServerPort(), 5);
            // respring seems to be needed to kickstart the process
            [HBRespringController respring];
        }
    }

    return ret;
}

- (BOOL)isTemporarilyBlocked {
    if (!isPasscodeSet()) {
        //%log(@"no passcode set, ignoring");
        return %orig;
    }
    //%log(@"hooked");

    NSTimeInterval blockTime = [prefs integerForKey:@"blockTime"];
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;

    int failedAttempts = [prefs integerForKey:@"failedAttempts"];
    NSTimeInterval lockoutTime = 0;

    if (failedAttempts <= 10) {
        if (failedAttempts >= 10) {
            lockoutTime = 3600;
        } else if (failedAttempts >= 8) {
            lockoutTime = 900;
        } else if (failedAttempts >= 7) {
            lockoutTime = 300;
        } else if (failedAttempts >= 6) {
            lockoutTime = 60;
        } else {
            return NO;
        }
    }

    return now < blockTime + lockoutTime;
}
%end

%hook SBFMobileKeyBag
// iOS 14
- (BOOL)unlockWithPasscode:(NSString *)passcode error:(id *)error {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    return doUnlock(passcode);
}

// iOS 15
- (BOOL)unlockWithOptions:(SBFMobileKeyBagUnlockOptions *)options error:(id *)error {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    return doUnlock([[NSString alloc] initWithData:options.passcode encoding:NSUTF8StringEncoding]);
}
%end

%hook SBFMobileKeyBagState
- (NSInteger)lockState {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    return isUnlocked ? 0 : 2;
}
%end

%hook SBFUserAuthenticationController
- (BOOL)isAuthenticated {
    if (!isPasscodeSet()) {
        //%log(@"no passcode set, ignoring");
        return %orig;
    }
    //%log(@"hooked");

    return isUnlocked;
}

- (BOOL)isAuthenticatedCached {
    if (!isPasscodeSet()) {
        //%log(@"no passcode set, ignoring");
        return %orig;
    }
    //%log(@"hooked");

    return isUnlocked;
}
%end

%hook SBCoverSheetSystemGesturesDelegate
- (id)dismissGestureRecognizer {
    //%log(@"hooked");
    return %orig;
}
%end

%hook SBLockScreenManager
- (void)lockUIFromSource:(int)source withOptions:(id)options {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    NSLog(@"Screen locked from source: %d", source);

    if ([[prefs objectForKey:@"passcodeHash"] length] > 0) {
        NSLog(@"Locking device");
        isUnlocked = NO;
        lastLockTime = [NSDate date].timeIntervalSince1970;
    }

    %orig;
}

- (void)unlockUIFromSource:(int)source withOptions:(id)options {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    NSLog(@"Screen unlocked from source: %d", source);

    SBLockScreenManager *lockScreenManager = [%c(SBLockScreenManager) sharedInstance];
    SBFDeviceLockOutController *lockOutController = lockScreenManager.lockOutController;
    if (lockOutController != NULL) {
        NSLog(@"Clearing device lockout");
        int blockTime = [prefs integerForKey:@"blockTime"];
        [prefs removeObjectForKey:@"blockTime"];
        [prefs setInteger:blockTime forKey:@"blockTime"];
        [lockOutController temporaryBlockStatusChanged];
    }

    if (!isUnlocked) {
        NSTimeInterval maxGracePeriod = [prefs integerForKey:@"maxGracePeriod"];
        NSTimeInterval now = [NSDate date].timeIntervalSince1970;

        if (lastLockTime > 0 && maxGracePeriod > 0 && lastLockTime + maxGracePeriod > now) {
            NSLog(@"Unlocking due to grace period");
            isUnlocked = YES;
        }
    }

    %orig;
}
%end

%hook SBMainWorkspace
- (void)dismissPowerDownTransientOverlayWithCompletion:(id)arg1 {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    if ([[prefs objectForKey:@"passcodeHash"] length] > 0) {
        if (isUnlocked) {
            [[%c(SBLockScreenManager) sharedInstance] lockScreenViewControllerRequestsUnlock];
        }

        isUnlocked = NO;
    }

    %orig;
}
%end

%hookf(NSInteger, SBUICurrentPasscodeStyleForUser) {
    if (!isPasscodeSet()) {
        NSLog(@"SBUICurrentPasscodeStyleForUser: no passcode set, ignoring");
        return %orig;
    }

    if (creatingPasscode) {
        NSLog(@"SBUICurrentPasscodeStyleForUser: passcode is being created, ignoring");
        return %orig;
    }

    NSLog(@"SBUICurrentPasscodeStyleForUser: hooked");

    return [prefs integerForKey:@"passcodeType"];
}

%hook SOSManager
- (void)didDismissClientSOSBeforeSOSCall:(id)arg1 {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }
    %log(@"hooked");

    if ([[prefs objectForKey:@"passcodeHash"] length] > 0) {
        if (isUnlocked) {
            [[%c(SBLockScreenManager) sharedInstance] lockScreenViewControllerRequestsUnlock];
        }

        isUnlocked = NO;
    }

    %orig;
}
%end

%ctor {
    @autoreleasepool {
        NSString *bundleId = [NSBundle mainBundle].bundleIdentifier;
        NSString *bundlePath = [NSBundle mainBundle].bundlePath;

        // skip injection into problematic processes
        if (!bundleId || ([bundleId hasPrefix:@"com.apple."]
                          && ![bundlePath hasSuffix:@".app"])) {
            return;
        }

        NSLog(@"Injected into %@ (%@)", bundleId, bundlePath);

        prefs = [[HBPreferences alloc] initWithIdentifier:@"net.cadoth.fakepass"];

        [prefs registerDefaults:@{
            @"lockOnRespring": @YES,
            @"maxGracePeriod": [[%c(MCProfileConnection) sharedConnection] effectiveValueForSetting:@"maxGracePeriod"],
        }];

        isUnlocked = !isPasscodeSet() || ![prefs boolForKey:@"lockOnRespring"];

        void *SpringBoardUIServices = dlopen(
            "/System/Library/PrivateFrameworks/SpringBoardUIServices.framework/SpringBoardUIServices", RTLD_LAZY
        );
        %init(SBUICurrentPasscodeStyleForUser = dlsym(SpringBoardUIServices, "SBUICurrentPasscodeStyleForUser"));
    }
}
