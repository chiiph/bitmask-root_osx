//
//  Firewall.h
//  bitmask-root
//
//  Created by chiiph on 5/5/14.
//  Copyright (c) 2014 chiiph. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface Firewall : NSObject

- (id) init;

- (void) start:(NSArray *)gateways;
- (void) stop;

@end
