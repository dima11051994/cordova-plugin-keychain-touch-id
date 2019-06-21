/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
 */

#import "TouchID.h"
#include <sys/types.h>
#include <sys/sysctl.h>
#include <CommonCrypto/CommonDigest.h>
#import <Cordova/CDV.h>

@implementation TouchID

- (void)isAvailable:(CDVInvokedUrlCommand*)command{
    self.laContext = [[LAContext alloc] init];
    BOOL touchIDAvailable = [self.laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
    if(touchIDAvailable){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    else{
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Touch ID not availalbe"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (void)setLocale:(CDVInvokedUrlCommand*)command{
  CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
  [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

- (void)has:(CDVInvokedUrlCommand*)command{
    self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    BOOL hasLoginKey = [[NSUserDefaults standardUserDefaults] boolForKey:self.TAG];
    if(hasLoginKey){
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    else{
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"No Password in chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

- (void)save:(CDVInvokedUrlCommand*)command{
    self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    NSString* message = (NSString*)[command.arguments objectAtIndex:1];
    BOOL touchIDAvailable = [self.laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
    
    if(touchIDAvailable){
        [self.laContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:message reply:^(BOOL success, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                
                if(success){
                    @try {
                        OSStatus sanityCheck = noErr;
                        SecKeyRef publicKey = NULL;
                        SecKeyRef privateKey = NULL;
                        
                        // Container dictionaries.
                        NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
                        NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
                        NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
                        
                        //Public and private keys have different tags
                        NSString* publicTag = [self.TAG stringByAppendingString:@"-public"];
                        
                        // Encryption type RSA
                        [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
                        //Key size 1024 bits
                        [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:1024] forKey:(__bridge id)kSecAttrKeySizeInBits];
                        [keyPairAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
                        
                        // Private key parameters
                        [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
                        [privateKeyAttr setObject:self.TAG forKey:(__bridge id)kSecAttrApplicationTag];
                        
                        // Public key parameters
                        [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
                        [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
                        
                        [keyPairAttr setObject:privateKeyAttr forKey:(id)kSecPrivateKeyAttrs];
                        [keyPairAttr setObject:publicKeyAttr forKey:(id)kSecPublicKeyAttrs];
                        // Generate key pair
                        sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);
                        if(sanityCheck == noErr  && publicKey != NULL && privateKey != NULL)
                        {
                            //Now we need to get public key bits from KeyChain
                            NSData * publicKeyBits = nil;
                            CFTypeRef pk;
                            NSMutableDictionary * queryPublicKey = [[NSMutableDictionary alloc] init];
                            
                            // Set the public key query parameters
                            [queryPublicKey setObject:(__bridge_transfer id)kSecClassKey forKey:(__bridge_transfer id)kSecClass];
                            [queryPublicKey setObject:publicTag forKey:(__bridge_transfer id)kSecAttrApplicationTag];
                            [queryPublicKey setObject:(__bridge_transfer id)kSecAttrKeyTypeRSA forKey:(__bridge_transfer id)kSecAttrKeyType];
                            [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge_transfer id)kSecReturnData];
                            
                            // Get the key bits.
                            sanityCheck = SecItemCopyMatching((__bridge_retained CFDictionaryRef)queryPublicKey, &pk);
                            if (sanityCheck != noErr)
                            {
                                CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Enexpexted error occured on getting public key from KeyStorage."];
                                [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                                return;
                            }
                            publicKeyBits = (__bridge_transfer NSData*)pk;
                            //base64 encode public key and send it as result
                            NSString* publicKeyBase64 =[publicKeyBits base64EncodedStringWithOptions:0];
                            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:publicKeyBase64];
                            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                        }
                        else
                        {
                            CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Key pair could not be generated."];
                            [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                        }
                    }
                    @catch(NSException *exception){
                        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Key pair could not be generated."];
                        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                    }
                }
                if(error != nil) {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: [NSString stringWithFormat:@"%li", (long)error.code]];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            });
        }];
        
    }
    else{
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"-1"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}

-(void)delete:(CDVInvokedUrlCommand*)command{
    self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    @try {
        [[NSUserDefaults standardUserDefaults] removeObjectForKey:self.TAG];
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    @catch(NSException *exception) {
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"Could not delete password from chain"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
    
    
}

-(void)verify:(CDVInvokedUrlCommand*)command{
    self.TAG = (NSString*)[command.arguments objectAtIndex:0];
    NSString* message = (NSString*)[command.arguments objectAtIndex:1];
    self.laContext = [[LAContext alloc] init];
    self.MyKeychainWrapper = [[KeychainWrapper alloc]init];
    BOOL touchIDAvailable = [self.laContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:nil];
    
    if(touchIDAvailable){
        [self.laContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:message reply:^(BOOL success, NSError *error) {
            dispatch_async(dispatch_get_main_queue(), ^{
                
                if(success){
                    //We need to get reference on private key from KeyChain
                    OSStatus sanityCheck = noErr;
                    SecKeyRef privateKey;
                    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
                    
                    // Set the private key query parameters
                    [queryPrivateKey setObject:(__bridge_transfer id)kSecClassKey forKey:(__bridge_transfer id)kSecClass];
                    
                    [queryPrivateKey setObject:self.TAG forKey:(__bridge_transfer id)kSecAttrApplicationTag];
                    [queryPrivateKey setObject:(__bridge_transfer id)kSecAttrKeyTypeRSA forKey:(__bridge_transfer id)kSecAttrKeyType];
                    //Return type will be ref
                    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge_transfer id)kSecReturnRef];
                    
                    sanityCheck = SecItemCopyMatching((__bridge_retained CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKey);
                    if (sanityCheck != noErr)
                    {
                        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"There is no key in KeyStorage for given tag."];
                        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                        return;
                    }
                    //Get token that will be signed using private key
                    NSData* token = [[command.arguments objectAtIndex:2] dataUsingEncoding:NSUTF8StringEncoding];
                    
                    NSData *signedHash = nil;
                    uint8_t *signedHashBytes = NULL;
                    size_t signedHashBytesSize = 0;
                    signedHashBytesSize = SecKeyGetBlockSize(privateKey);
                    
                    // Malloc a buffer to hold signature.
                    signedHashBytes = malloc(signedHashBytesSize * sizeof(uint8_t));
                    memset((void *) signedHashBytes, 0x0, signedHashBytesSize);
                    size_t hashBytesSize = CC_SHA256_DIGEST_LENGTH;
                    uint8_t* hashBytes = malloc(hashBytesSize);
                    if (!CC_SHA256([token bytes], (CC_LONG)[token length], hashBytes)) {
                        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"-1"];
                        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                        return;
                    }
                    // Sign the token
                    sanityCheck = SecKeyRawSign(privateKey,
                                                kSecPaddingPKCS1SHA256,
                                                hashBytes,
                                                hashBytesSize,
                                                signedHashBytes,
                                                &signedHashBytesSize
                                                );
                    signedHash = [NSData dataWithBytes:(const void *) signedHashBytes length:(NSUInteger) signedHashBytesSize];
                    //send base64 encoded signed bits of the given token
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString: [signedHash base64EncodedStringWithOptions:0]];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
                if(error != nil) {
                    CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: [NSString stringWithFormat:@"%li", (long)error.code]];
                    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
                }
            });
        }];
    }
    else{
        CDVPluginResult* pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString: @"-1"];
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }
}
@end
