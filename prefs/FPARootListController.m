@import CommonCrypto;
@import CoreFoundation;

#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>

#import "../util.m"
#import "FPARootListController.h"

@implementation FPARootListController

- (void)handlePasscodeChange {
    NSLog(@"handlePasscodeChange called");

    HBPreferences *prefs = [[HBPreferences alloc] initWithIdentifier:@"net.cadoth.fakepass"];
    NSString *passcode = [prefs objectForKey:@"passcode"];

    if (passcode.length > 0) {
        HBPreferences *prefs = [[HBPreferences alloc] initWithIdentifier:@"net.cadoth.fakepass"];

        NSString *salt = generateSalt();
        [prefs setObject:generateHashFor(passcode, salt) forKey:@"passcodeHash"];
        [prefs setObject:salt forKey:@"passcodeSalt"];

        [prefs removeObjectForKey:@"passcode"];

        NSInteger passcodeType;

        if ([passcode rangeOfString:@"^\\d+$" options:NSRegularExpressionSearch].location != NSNotFound) {
            switch (passcode.length) {
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

        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Passcode saved"
                                                      message:nil
                                                      preferredStyle:UIAlertControllerStyleAlert];

        [self presentViewController:alert animated:YES completion:nil];

        [NSTimer scheduledTimerWithTimeInterval:1 repeats:NO block:^(NSTimer *timer) {
            [alert dismissViewControllerAnimated:YES completion:nil];
        }];
    }
}

- (void)reloadPrefs {
    NSLog(@"reloadPrefs called");
    HBPreferences *prefs = [[HBPreferences alloc] initWithIdentifier:@"net.cadoth.fakepass"];
    NSLog(@"Passcode: %@", [prefs objectForKey:@"passcode"]);
    [self reloadSpecifierID:@"passcode"];
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("net.cadoth.fakepass/ReloadPrefs"), NULL, NULL, YES);
}

- (instancetype)init {
    self = [super init];

    if (self) {
        HBPreferences *prefs = [[HBPreferences alloc] initWithIdentifier:@"net.cadoth.fakepass"];
        [prefs registerPreferenceChangeBlockForKey:@"passcode" block:^(NSString *key, id value) { [self handlePasscodeChange]; }];
    }

    return self;
}

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }

    return _specifiers;
}

- (void)loadView {
    [super loadView];
    ((UITableView *)[self table]).keyboardDismissMode = UIScrollViewKeyboardDismissModeOnDrag;
}

- (void)_returnKeyPressed:(id)arg1 {
    [self.view endEditing:YES];
    [self handlePasscodeChange];
}

- (void)respring {
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("net.cadoth.fakepass/Respring"), NULL, NULL, YES);
}

- (void)respringPrompt {
    NSURL *relaunchURL;
    if ([[NSFileManager defaultManager] fileExistsAtPath:@"/Library/MobileSubstrate/DynamicLibraries/shuffle.dylib"]) {
        relaunchURL = [NSURL URLWithString:@"prefs:root=Tweaks&path=FakePass"];
    } else {
        relaunchURL = [NSURL URLWithString:@"prefs:root=FakePass"];
    }

    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Confirm respring"
                                                  message:@"Are you sure you want to respring? This is only required to enable/disable the tweak."
                                                  preferredStyle:UIAlertControllerStyleAlert];

    UIAlertAction* okAction = [UIAlertAction actionWithTitle:@"Respring"
                                                       style:UIAlertActionStyleDestructive
                                                     handler:^(UIAlertAction *action) { [HBRespringController respringAndReturnTo:relaunchURL]; }];

    UIAlertAction* cancelAction = [UIAlertAction actionWithTitle:@"Cancel"
                                                 style:UIAlertActionStyleCancel
                                                 handler:^(UIAlertAction *action) {}];

    [alert addAction:cancelAction];
    [alert addAction:okAction];

    [self presentViewController:alert animated:YES completion:nil];
}

@end
