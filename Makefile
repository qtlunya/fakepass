TARGET := iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = backboardd

ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FakePass

FakePass_FILES = Tweak.xm util.m
FakePass_CFLAGS = -fobjc-arc -Wno-error
FakePass_LIBRARIES = Sandy
FakePass_PRIVATE_FRAMEWORKS = FrontBoardServices SpringBoardServices

include $(THEOS_MAKE_PATH)/tweak.mk
SUBPROJECTS += prefs
include $(THEOS_MAKE_PATH)/aggregate.mk
