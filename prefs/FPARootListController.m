@import CommonCrypto;
@import CoreFoundation;

#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>

#import "../util.m"
#import "FPARootListController.h"

@implementation FPARootListController

- (void)reloadPrefs {
    NSLog(@"reloadPrefs called");
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("net.cadoth.fakepass/ReloadPrefs"), NULL, NULL, YES);
}

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }

    return _specifiers;
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
                                                                   message:@"Are you sure you want to respring?"
                                                            preferredStyle:UIAlertControllerStyleAlert];

    UIAlertAction* cancelAction = [UIAlertAction actionWithTitle:@"Cancel"
                                                           style:UIAlertActionStyleCancel
                                                         handler:^(UIAlertAction *action) {}];

    UIAlertAction* okAction = [UIAlertAction actionWithTitle:@"Respring"
                                                       style:UIAlertActionStyleDestructive
                                                     handler:^(UIAlertAction *action) { [HBRespringController respringAndReturnTo:relaunchURL]; }];

    [alert addAction:cancelAction];
    [alert addAction:okAction];

    [self presentViewController:alert animated:YES completion:nil];
}

@end
