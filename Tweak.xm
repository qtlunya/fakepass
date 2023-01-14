#include <dlfcn.h>
#include <stdlib.h>

@import CommonCrypto;
@import Foundation;
@import UIKit;

#import <SpringBoard/SpringBoard.h>
//#import <SpringBoard/SBLockScreenManager.h>

#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>

#import "util.h"

@interface CSCoverSheetViewController
- (BOOL)isMainPageVisible;
- (BOOL)isShowingTodayView;
@end

@interface LASecureData
- (NSData *)data;
@end

@interface MCProfileConnection
+ (instancetype)sharedConnection;
- (id)effectiveValueForSetting:(NSString *)setting;
@end

@interface SBCoverSheetPresentationManager
+ (instancetype)sharedInstance;
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
+ (instancetype)sharedInstance;
- (BOOL)_attemptUnlockWithPasscode:(NSString *)passcode
                              mesa:(BOOL)mesa
                    finishUIUnlock:(BOOL)finishUIUnlock
                        completion:(id)completion;
- (BOOL)_shouldUnlockUIOnKeyDownEvent;
- (CSCoverSheetViewController *)coverSheetViewController;
- (void)lockScreenViewControllerRequestsUnlock;
@end

@interface SBUIBiometricResource
@property (nonatomic,readonly) BOOL hasMesaSupport;
@property (nonatomic,readonly) BOOL hasPearlSupport;
+ (instancetype)sharedInstance;
- (NSUInteger)biometricLockoutState;
@end

HBPreferences *prefs;
BOOL isUnlocked;
BOOL isInternalUnlock = NO;
BOOL isResetting = NO;
BOOL didStartBlock = NO;
BOOL creatingPasscode = NO;
int lastLockTime = 0;
__weak SBFDeviceLockOutController *lockOutController = NULL;

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
        [prefs setBool:NO forKey:@"inBioLockout"];
        [prefs setInteger:0 forKey:@"failedAttempts"];
        [prefs removeObjectForKey:@"blockTime"];
        return YES;
    } else {
        NSLog(@"Failed unlock with passcode: %@", passcode);
        int failedAttempts = [prefs integerForKey:@"failedAttempts"] + 1;
        [prefs setInteger:failedAttempts forKey:@"failedAttempts"];
        if (failedAttempts >= 6) {
            [prefs setInteger:[NSDate date].timeIntervalSince1970 forKey:@"blockTime"];
            if (lockOutController != NULL) {
                NSLog(@"Triggering device lockout due to too many failed attempts");
                [lockOutController temporaryBlockStatusChanged];
            }
        }
        return NO;
    }
}

%hook CSUserPresenceMonitor
- (BOOL)_handleBiometricEvent:(NSUInteger)eventType {
    NSLog(@"handleBiometricEvent: %lu", eventType);

    if (
        [[%c(SBUIBiometricResource) sharedInstance] biometricLockoutState] == 1
        || [lockOutController isTemporarilyBlocked]
        || [lockOutController isPermanentlyBlocked]
    ) {
        return %orig;
    }

    if (eventType == 1 || eventType == 13) { // 1 = Touch ID scan, 13 = Face ID scan
        SBLockScreenManager *lockScreenManager = [%c(SBLockScreenManager) sharedInstance];

        isInternalUnlock = YES;
        [lockScreenManager _attemptUnlockWithPasscode:@"__FAKEPASS_INTERNAL_UNLOCK"
                                                 mesa:NO
                                       finishUIUnlock:NO
                                           completion:^{
            isInternalUnlock = NO;
        }];
    }

    return %orig;
}
%end

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
    creatingPasscode = YES;
    %orig;
}
%end

%hook LAContext
- (NSInteger)biometryType {
    %log(@"hooked");

    SBUIBiometricResource *resource = [%c(SBUIBiometricResource) sharedInstance];

    // TODO: figure out how to detect if Face ID/Touch ID is enrolled
    if (resource.hasMesaSupport) {
        return 1;
    }
    if (resource.hasPearlSupport) {
        return 2;
    }
    return 0;
}

- (BOOL)canEvaluatePolicy:(NSInteger)policy error:(id *)error {
    %log(@"hooked");
    return YES;
}

- (void)evaluatePolicy:(NSInteger)policy
       localizedReason:(NSString *)localizedReason
                 reply:(void (^)(BOOL, NSError *))reply {
    void (^callback)(BOOL, NSError *) = ^(BOOL success, NSError *error) {
        // HACK: bypass ACM validation errors for in-app authentication
        // -4 is for biometrics, -1000 is for passcode
        if (success || (
            [error.domain isEqualToString:@"com.apple.LocalAuthentication"] && (error.code == -4 || error.code == -1000)
        )) {
            reply(YES, nil);
        } else {
            reply(NO, error);
        }
    };
    %orig(policy, localizedReason, callback);
}
%end

%hook LAPasscodeHelper
- (NSInteger)verifyPasswordUsingAKS:(LASecureData *)secureData
                         acmContext:(id)acmContext
                             userId:(unsigned int)userId
                             policy:(NSInteger)policy
                            options:(NSDictionary *)options {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    return checkPasscode([[NSString alloc] initWithData:secureData.data encoding:NSUTF8StringEncoding]) ? 0 : 1;
}
%end

%hook MCPasscodeManager
- (BOOL)isPasscodeSet {
    %log(@"hooked");

    if ([[prefs objectForKey:@"passcodeHash"] length] > 0) {
        %log(@"Spoofing passcode state");
        return YES;
    }

    return NO;
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
        [prefs setInteger:newPasscode.length forKey:@"passcodeLength"];

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

        [prefs removeObjectForKey:@"blockTime"];
        [prefs removeObjectForKey:@"failedAttempts"];
        [prefs removeObjectForKey:@"inBioLockout"];
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
    //NSInteger maxGracePeriod = [prefs integerForKey:@"maxGracePeriod" default:-1];
    NSInteger maxGracePeriod = -1;
    if ([prefs objectForKey:@"maxGracePeriod"] != nil) {
        maxGracePeriod = [prefs integerForKey:@"maxGracePeriod"];
    }

    if ([setting isEqualToString:@"maxGracePeriod"] && maxGracePeriod > -1) {
        return @(maxGracePeriod);
    }

    return %orig;
}

- (void)setValue:(id)value forSetting:(NSString *)setting passcode:(id)passcode {
    %log(@"hooked");

    if ([setting isEqualToString:@"maxGracePeriod"]) {
        [prefs setInteger:[value integerValue] forKey:@"maxGracePeriod"];
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

%hook SBBacklightController
- (void) _startFadeOutAnimationFromLockSource:(int)arg1 {
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

    NSDateComponents *dateComponents = [[NSDateComponents alloc] init];
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
- (id)initWithThermalController:(id)arg1 authenticationController:(id)arg2 {
    if (!isPasscodeSet()) {
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    lockOutController = self;

    return %orig;
}

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
    if (!isPasscodeSet()/* || source == 24*/) {
        // 24 = screen already unlocked, swiping up on the lock screen
        %log(@"no passcode set, ignoring");
        return %orig;
    }

    %log(@"hooked");

    NSLog(@"Screen unlocked from source: %d", source);

    if (!isUnlocked) {
        NSTimeInterval maxGracePeriod = [prefs integerForKey:@"maxGracePeriod"];
        NSTimeInterval now = [NSDate date].timeIntervalSince1970;

        if (lastLockTime > 0 && maxGracePeriod > 0 && lastLockTime + maxGracePeriod > now) {
            NSLog(@"Unlocking due to grace period");
            isUnlocked = YES;
            [prefs setBool:NO forKey:@"inBioLockout"];
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
        [prefs setBool:YES forKey:@"inBioLockout"];
    }

    %orig;
}
%end

%hook SBUIBiometricResource
- (NSUInteger)biometricLockoutState {
    %log(@"hooked");

    return [prefs boolForKey:@"inBioLockout"] ? 1 : 0;
}
%end

%hook SBUIPasscodeLockViewBase
- (BOOL)_isBiometricAuthenticationAllowed {
    %log(@"hooked");
    return YES;
}
%end

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
        [prefs setBool:YES forKey:@"inBioLockout"];
    }

    %orig;
}
%end

%hook SBUIProudLockIconView
- (NSInteger)state {
    return 1;
}
%end

%ctor {
    @autoreleasepool {
        NSString *bundleId = [NSBundle mainBundle].bundleIdentifier;

        // backboardd seems to hang when restarted if we inject into it
        if ([bundleId isEqualToString:@"com.apple.backboardd"]) {
            return;
        }

        NSLog(@"Injected into %@", bundleId);

        prefs = [[HBPreferences alloc] initWithIdentifier:@"net.cadoth.fakepass"];

        [prefs registerDefaults:@{
            @"inBioLockout": @NO,
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
