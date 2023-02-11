TARGET := iphone:clang:14.5:14.0

ARCHS = arm64

include $(THEOS)/makefiles/common.mk

BUNDLE_NAME = FakePassPrefs

FakePassPrefs_FILES = FPARootListController.m
FakePassPrefs_FRAMEWORKS = UIKit
FakePassPrefs_PRIVATE_FRAMEWORKS = Preferences
FakePassPrefs_EXTRA_FRAMEWORKS += Cephei
FakePassPrefs_INSTALL_PATH = /Library/PreferenceBundles
FakePassPrefs_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/bundle.mk
