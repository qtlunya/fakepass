@import CommonCrypto;
@import CoreFoundation;

#import <Cephei/HBPreferences.h>
#import <Cephei/HBRespringController.h>

#import "../util.m"
#import "FPARootListController.h"

@implementation FPARootListController

- (void)reloadPrefs {
    NSLog(@"reloadPrefs called");
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("me.alexia.fakepass/ReloadPrefs"), NULL, NULL, YES);
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
}

- (void)respring {
    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("me.alexia.fakepass/Respring"), NULL, NULL, YES);
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
