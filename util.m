@import CommonCrypto;
@import Foundation;

#ifdef __cplusplus
extern "C" {
#endif

NS_RETURNS_RETAINED NSString *generateHashFor(NSString *input, NSString *salt) {
    NSLog(@"Digest length is %d", CC_SHA512_DIGEST_LENGTH);

    NSLog(@"Input pass: %@", input);
    NSLog(@"Input salt: %@", salt);

    NSString *salted = [NSMutableString stringWithFormat:@"%@%@", input, salt];
    NSLog(@"Salted output: %@", salted);

    const char *str = salted.UTF8String;
    unsigned char hash[CC_SHA512_DIGEST_LENGTH];
    CC_SHA512(str, strlen(str), hash);

    NSMutableString *hexHash = [NSMutableString stringWithCapacity:CC_SHA512_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA512_DIGEST_LENGTH; i++) {
        [hexHash appendFormat:@"%02x", hash[i]];
    }

    NSLog(@"Hash: %@", hexHash);
    return hexHash;
}

NS_RETURNS_RETAINED NSString *generateSalt() {
    NSLog(@"Hello");
    NSMutableString *salt = [NSMutableString stringWithCapacity:128];
    NSLog(@"World");
    for (int i = 0; i < 64; i++) {
        NSLog(@"Salt so far: %@", salt);
        unsigned char rand = arc4random_uniform(256);
        [salt appendFormat:@"%02x", rand];
        NSLog(@"Salt so far: %@", salt);
    }
    NSLog(@"Salt: %@", salt);
    return salt;
}

#ifdef __cplusplus
}
#endif

/* vim: set ft=objc: */
