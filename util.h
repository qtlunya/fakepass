#import <Foundation/Foundation.h>

#ifdef __cplusplus
extern "C" {
#endif

NS_RETURNS_RETAINED NSString *generateHashFor(NSString *input, NSString *salt);

NS_RETURNS_RETAINED NSString *generateSalt();

#ifdef __cplusplus
}
#endif

/* vim: set ft=objc */
