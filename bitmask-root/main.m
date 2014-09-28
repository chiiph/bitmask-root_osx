//
//  main.m
//  bitmask-root
//
//  Created by chiiph on 5/2/14.
//  Copyright (c) 2014 chiiph. All rights reserved.
//

#import <Foundation/Foundation.h>

#import "Firewall.h"

int main(int argc, const char * argv[])
{

    @autoreleasepool
    {
        NSUserDefaults *standardDefaults = [NSUserDefaults standardUserDefaults];

        NSString *firewallCmd = [standardDefaults stringForKey:@"firewall"];

        Firewall *firewall;
        firewall = [[Firewall alloc] init];

        if ([firewallCmd isEqualToString:@"start"])
        {
            NSLog(@"Bringing the firewall up...");
            NSString *gatewaysString = [standardDefaults stringForKey:@"gateways"];
            NSArray *gateways = [gatewaysString componentsSeparatedByString:@","];
            [firewall start:[NSArray arrayWithObjects:gateways, nil]];
        }
        else if ([firewallCmd isEqualToString:@"stop"])
        {
            NSLog(@"Bringing the firewall down...");
            [firewall stop];
        }
    }
    return 0;
}

