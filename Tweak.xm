#include <dlfcn.h>
#include <stdlib.h>

@import CommonCrypto;
@import Foundation;
@import UIKit;

#import <FrontBoardServices/FBSSystemService.h>
#import <SpringBoard/SBApplication.h>
#import <SpringBoard/SpringBoard.h>
#import <SpringBoardServices/SBSRelaunchAction.h>

#import <Cephei/HBPreferences.h>

#import "util.h"

@interface SBCoverSheetPresentationManager
+ (id)sharedInstance;
@end

@interface SBFDeviceLockOutController
- (void)temporaryBlockStatusChanged;
@end

@interface SBFMobileKeyBagUnlockOptions : NSObject
@property (nonatomic,copy,readonly) NSData *passcode;
@end

@interface SBLockScreenManager
+ (id)sharedInstance;
- (void)lockScreenViewControllerRequestsUnlock;
@end

HBPreferences *prefs;
BOOL isUnlocked;
BOOL didStartBlock = NO;
int lastLockTime = 0;
__weak SBFDeviceLockOutController *lockOutController = NULL;

BOOL isPasscodeEnabled() {
    return [[prefs objectForKey:@"passcodeHash"] length] > 0;
}

BOOL checkPasscode(NSString *passcode) {
    HBPreferences *prefs = [[HBPreferences alloc] initWithIdentifier:@"me.alexia.fakepass"];
    NSString *salt = [prefs objectForKey:@"passcodeSalt"];
    return [generateHashFor(passcode, salt) isEqualToString:[prefs objectForKey:@"passcodeHash"]];
}

BOOL doUnlock(NSString *passcode) {
    if (checkPasscode(passcode)) {
        NSLog(@"Successful unlock with passcode: %@", passcode);
        isUnlocked = YES;
        [prefs setInteger:0 forKey:@"failedAttempts"];
        return YES;
    } else {
        NSLog(@"Failed unlock with passcode: %@", passcode);
        int failedAttempts = [prefs integerForKey:@"failedAttempts"] + 1;
        [prefs setInteger:failedAttempts forKey:@"failedAttempts"];
        if (failedAttempts >= 6 && [prefs boolForKey:@"blockAfterTooManyFailures"]) {
            [prefs setInteger:[NSDate date].timeIntervalSince1970 forKey:@"blockTime"];
            if (lockOutController != NULL) {
                NSLog(@"Triggering device lockout due to too many failed attempts");
                [lockOutController temporaryBlockStatusChanged];
            }
        }
        return NO;
    }
}

%group FakePassUIKit

%hook DevicePINController
- (int)pinLength {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
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
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    int passcodeType = [prefs integerForKey:@"passcodeType"];
    BOOL forceAlphanumeric = [prefs boolForKey:@"forceAlphanumeric"];

    if (forceAlphanumeric) {
        return NO;
    }

    return passcodeType < 3;
}

- (BOOL)simplePIN {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    int passcodeType = [prefs integerForKey:@"passcodeType"];
    BOOL hideLength = [prefs boolForKey:@"hideLength"];
    BOOL forceAlphanumeric = [prefs boolForKey:@"forceAlphanumeric"];

    if (hideLength || forceAlphanumeric) {
        return NO;
    }

    return passcodeType < 3;
}
%end

%hook MCPasscodeManager
- (BOOL)isPasscodeSet {
    %log(@"hooked");

    if (((NSString *)[prefs objectForKey:@"passcodeHash"]).length > 0) {
        %log(@"Spoofing passcode state");
        return YES;
    }

    return NO;
}
%end

%hook MCProfileConnection
- (BOOL)unlockDeviceWithPasscode:(id)passcode outError:(id *)error {
    if (!isPasscodeEnabled()) {
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

- (BOOL)changePasscodeFrom:(NSString *)oldPasscode to:(NSString *)newPasscode outError:(id *)outError {
    NSLog(@"hooked");
    NSLog(@"hello???");
    NSLog(@"test2");

    HBPreferences *prefs = [[HBPreferences alloc] initWithIdentifier:@"me.alexia.fakepass"];

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

        if ([newPasscode rangeOfString:@"^\\d+$" options:NSRegularExpressionSearch].location != NSNotFound) {
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

        [prefs removeObjectForKey:@"passcodeHash"];
        [prefs removeObjectForKey:@"passcodeSalt"];
        [prefs removeObjectForKey:@"passcodeType"];
    }

    return true;
}

%end

%hookf(NSInteger, SBUICurrentPasscodeStyleForUser) {
    if (!isPasscodeEnabled()) {
        NSLog(@"SBUICurrentPasscodeStyleForUser: no passcode set, ignoring");
        return %orig;
    }

    NSLog(@"SBUICurrentPasscodeStyleForUser: hooked");

    int passcodeType = [prefs integerForKey:@"passcodeType"];
    BOOL hideLength = [prefs boolForKey:@"hideLength"];
    BOOL forceAlphanumeric = [prefs boolForKey:@"forceAlphanumeric"];

    if (forceAlphanumeric) {
        return 3;
    }

    if (passcodeType < 2 && hideLength) {
        return 2;
    }

    return passcodeType;
}

%end

%group FakePassSB

%hook SBBacklightController
- (void) _startFadeOutAnimationFromLockSource:(int)arg1 {
    if (!isPasscodeEnabled()) {
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
    if (!isPasscodeEnabled()) {
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
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    int failedAttempts = [prefs integerForKey:@"failedAttempts"];
    NSTimeInterval blockTime = [prefs integerForKey:@"blockTime"];
    NSTimeInterval now = [NSDate date].timeIntervalSince1970;
    NSTimeInterval lockoutTime;

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
            return %orig;
        }
    } else {
        return %orig;
    }

    NSTimeInterval remainingSecs = (blockTime + lockoutTime) - now;
    int remainingMins = ceil(remainingSecs / 60);
    NSString *s = (remainingMins == 1) ? @"" : @"s";

    return [NSString stringWithFormat:@"try again in %d minute%@", remainingMins, s];
}
%end

%hook SBFDeviceLockOutController
- (id)initWithThermalController:(id)arg1 authenticationController:(id)arg2 {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    lockOutController = self;

    return %orig;
}

- (BOOL)isPermanentlyBlocked {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    return [prefs integerForKey:@"failedAttempts"] > 10;
}

- (BOOL)isTemporarilyBlocked {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    if (![prefs boolForKey:@"blockAfterTooManyFailures"]) {
        return NO;
    }

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
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    return doUnlock(passcode);
}

// iOS 15
- (BOOL)unlockWithOptions:(SBFMobileKeyBagUnlockOptions *)options error:(id *)error {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    return doUnlock([[NSString alloc] initWithData:[options passcode] encoding:NSUTF8StringEncoding]);
}
%end

%hook SBFMobileKeyBagState
- (NSInteger)lockState {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    return isUnlocked ? 0 : 2;
}
%end

%hook SBFUserAuthenticationController
- (BOOL)isAuthenticated {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    return isUnlocked;
}

- (BOOL)isAuthenticatedCached {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    return isUnlocked;
}
%end

%hook SBLockScreenManager
- (void)lockUIFromSource:(int)source withOptions:(id)options {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    NSLog(@"Screen locked from source: %d", source);

    if (((NSString *)[prefs objectForKey:@"passcodeHash"]).length > 0) {
        NSLog(@"Locking device");
        isUnlocked = NO;
        lastLockTime = [NSDate date].timeIntervalSince1970;
    }

    %orig;
}

- (void)unlockUIFromSource:(int)source withOptions:(id)options {
    if (!isPasscodeEnabled()/* || source == 24*/) {
        // 24 = screen already unlocked, swiping up on the lock screen
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    NSLog(@"Screen unlocked from source: %d", source);

    if (lockOutController != NULL) {
        NSLog(@"Clearing device lockout");
        int blockTime = [prefs integerForKey:@"blockTime"];
        [prefs removeObjectForKey:@"blockTime"];
        [lockOutController temporaryBlockStatusChanged];
        [prefs setInteger:blockTime forKey:@"blockTime"];
        [lockOutController temporaryBlockStatusChanged];
    }

    if (!isUnlocked) {
        NSTimeInterval lockAfter = [prefs integerForKey:@"lockAfter"];
        NSTimeInterval now = [NSDate date].timeIntervalSince1970;

        if (lastLockTime > 0 && lockAfter > 0 && lastLockTime + (lockAfter * 60) > now) {
            NSLog(@"Unlocking due to grace period");
            isUnlocked = YES;
        }
    }

    %orig;
}
%end

%hook SBMainWorkspace
- (void)dismissPowerDownTransientOverlayWithCompletion:(id)arg1 {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    if (((NSString *)[prefs objectForKey:@"passcodeHash"]).length > 0) {
        if (isUnlocked) {
            [[%c(SBLockScreenManager) sharedInstance] lockScreenViewControllerRequestsUnlock];
        }

        isUnlocked = NO;
    }

    %orig;
}
%end

%hook SOSManager
- (void)didDismissClientSOSBeforeSOSCall:(id)arg1 {
    if (!isPasscodeEnabled()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    if (((NSString *)[prefs objectForKey:@"passcodeHash"]).length > 0) {
        if (isUnlocked) {
            [[%c(SBLockScreenManager) sharedInstance] lockScreenViewControllerRequestsUnlock];
        }

        isUnlocked = NO;
    }

    %orig;
}
%end

%end

%ctor {
    @autoreleasepool {
        NSString *bundleId = [NSBundle mainBundle].bundleIdentifier;

        if ([bundleId isEqualToString:@"com.apple.coreauthd"]) {
            // TODO: Figure out how to make coreauthd passcode prompt accept our passcode
            return;
        }

        NSLog(@"Injected into %@", bundleId);

        prefs = [[HBPreferences alloc] initWithIdentifier:@"me.alexia.fakepass"];

        [prefs registerDefaults:@{
            @"lockOnRespring": @YES,
            @"hideLength": @NO,
            @"forceAlphanumeric": @NO,
            @"blockAfterTooManyFailures": @YES,
            @"lockAfter": @0,
        }];

        isUnlocked = ((NSString *)[prefs objectForKey:@"passcodeHash"]).length == 0 || ![prefs boolForKey:@"lockOnRespring"];

        NSLog(@"Loading FakePassUIKit");
        void *handle = dlopen("/System/Library/PrivateFrameworks/SpringBoardUIServices.framework/SpringBoardUIServices", RTLD_LAZY);
        %init(FakePassUIKit, SBUICurrentPasscodeStyleForUser = dlsym(handle, "SBUICurrentPasscodeStyleForUser"));

        if ([[NSBundle mainBundle].bundleIdentifier isEqualToString:@"com.apple.springboard"]) {
            NSLog(@"Loading FakePassSB");
            %init(FakePassSB);
        }
    }
}
