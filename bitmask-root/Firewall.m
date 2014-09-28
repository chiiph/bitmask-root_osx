//
//  Firewall.m
//  bitmask-root
//
//  Created by chiiph on 5/5/14.
//  Copyright (c) 2014 chiiph. All rights reserved.
//

#import "Firewall.h"

#include <ifaddrs.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>

@interface Firewall ()

@property (nonatomic, strong) NSString *pfctl;
@property (nonatomic, strong) NSMutableArray *rules;

@end

@implementation Firewall

@synthesize pfctl;
@synthesize rules;

- (id) init
{
    if (self = [super init])
    {
        self.pfctl = @"/sbin/pfctl";

        self.rules = [[NSMutableArray alloc] init];
    }
    
    return self;
}

- (void)dealloc
{
    
}

- (NSString *)runCmd:(NSString*)cmd withArgs:(NSArray *)args
{
    NSTask *task;
    task = [[NSTask alloc] init];
    [task setLaunchPath: cmd];
    
    [task setArguments: args];
    
    NSPipe *pipe;
    pipe = [NSPipe pipe];
    [task setStandardOutput: pipe];
    
    NSFileHandle *file;
    file = [pipe fileHandleForReading];
    
    [task launch];
    
    NSData *data;
    data = [file readDataToEndOfFile];
    
    NSString *output;
    output = [[NSString alloc] initWithData: data encoding: NSUTF8StringEncoding];
    
    return output;
}

- (NSString *)runCmd:(NSString*)cmd withArgs:(NSArray*)args
           andPipeTo:(NSString*)cmd2 withArgs:(NSArray*)args2
{
    NSTask *task;
    task = [[NSTask alloc] init];
    [task setLaunchPath: cmd];
    NSTask *task2;
    task2 = [[NSTask alloc] init];
    [task2 setLaunchPath: cmd2];

    [task setArguments: args];
    [task2 setArguments: args2];

    /* cmd ==> cmd2 */
    NSPipe *pipeBetween = [NSPipe pipe];
    [task setStandardOutput: pipeBetween];
    [task2 setStandardInput: pipeBetween];

    /* cmd2 ==> me */
    NSPipe *pipeToMe = [NSPipe pipe];
    [task2 setStandardOutput: pipeToMe];

    NSFileHandle *file;
    file = [pipeToMe fileHandleForReading];

    [task launch];
    [task2 launch];

    NSData *data;
    data = [file readDataToEndOfFile];

    NSString *output;
    output = [[NSString alloc] initWithData: data encoding: NSUTF8StringEncoding];

    return output;
}

- (NSString *)writeToStdin:(NSString*)inputString
                     toCmd:(NSString*)cmd2 withArgs:(NSArray*)args2
{
    NSTask *task2;
    task2 = [[NSTask alloc] init];
    [task2 setLaunchPath: cmd2];
    [task2 setArguments: args2];

    NSPipe *pipeToMe = [NSPipe pipe];
    [task2 setStandardOutput:pipeToMe];
    NSPipe *pipeInput = [NSPipe pipe];
    [task2 setStandardInput:pipeInput];

    NSFileHandle *file;
    file = [pipeToMe fileHandleForReading];

    [task2 launch];

    NSFileHandle* taskInput = [[task2 standardInput] fileHandleForWriting];

    const char* cStringToSendToTask = [inputString UTF8String];
    unsigned long cStringToSendToTaskLength = strlen(cStringToSendToTask);

    [taskInput writeData:[NSData dataWithBytes:cStringToSendToTask
                                        length:cStringToSendToTaskLength]];

    [taskInput closeFile];

    NSData *data;
    data = [file readDataToEndOfFile];

    NSString *output;
    output = [[NSString alloc] initWithData: data encoding: NSUTF8StringEncoding];

    return output;
}

- (void)addRule:(NSString *)rule
{
    [self.rules addObject:rule];
}

- (void)applyRules
{
    // echo -e $rules | $pfctl -a bitmask -mf -

    NSString *allRules = [NSString stringWithFormat:@"%@\n",
                          [self.rules componentsJoinedByString:@"\n"]];
    [self writeToStdin:allRules
                 toCmd:self.pfctl
              withArgs:[NSArray arrayWithObjects:@"-a", @"bitmask", @"-mf", @"-", nil]];
}

- (NSString *)defaultDevice
{
    struct ifaddrs* interfaces = NULL;
    struct ifaddrs* temp_addr = NULL;

    // retrieve the current interfaces - returns 0 on success
    NSInteger success = getifaddrs(&interfaces);
    NSString* name = @"";

    if (success == 0)
    {
        // Loop through linked list of interfaces
        temp_addr = interfaces;
        while (temp_addr != NULL)
        {
            if (temp_addr->ifa_addr->sa_family == AF_INET &&
                !(temp_addr->ifa_flags & IFF_LOOPBACK))
            {
                name = [NSString stringWithUTF8String:temp_addr->ifa_name];
            }

            temp_addr = temp_addr->ifa_next;
        }
    }
    
    // Free memory
    freeifaddrs(interfaces);

    return name;
}

- (void) enableFirewall
{
    NSLog(@"[-] Enabling firewall...");
    [self runCmd:self.pfctl withArgs:[NSArray arrayWithObjects:@"-e", nil]];
    NSLog(@"[-] Done enabling firewall");
}

- (void) establishPFConfig
{
    // echo -e "set skip on lo0\n`$cat /etc/pf.conf`\nanchor \"bitmask\"" | $pfctl -f -
    NSMutableString *pfconfig = [NSMutableString stringWithString:@"set skip on lo0\n"];
    [pfconfig appendString:[NSString stringWithContentsOfFile:@"/etc/pf.conf"
                                                     encoding:NSUTF8StringEncoding error:NULL]];
    [pfconfig appendString:@"anchor \"bitmask\"\n"];

    NSLog(@"psfconfig: %@", pfconfig);
    NSLog(@"-----------------------------------");
    [self writeToStdin:pfconfig
                 toCmd:self.pfctl
              withArgs:[NSArray arrayWithObjects:@"-f", @"-", nil]];
    NSLog(@"----------------------------------- end pfconfig");
}

- (void) resetGateways:(NSArray *)gateways
{
    [self runCmd:self.pfctl withArgs:[NSArray arrayWithObjects:@"-a", @"bitmask", @"-t", @"gateways", @"-T", @"delete", nil]];

    for (NSString *gateway in gateways)
    {
        [self runCmd:self.pfctl withArgs:[NSArray arrayWithObjects:@"-a", @"bitmask", @"-t", @"gateways", @"-T", @"add", gateway, nil]];
    }
}

- (void) start:(NSArray *)gateways
{
    NSString *defaultDevice = [self defaultDevice];

    NSLog(@"[-] Using default device: %@", defaultDevice);

    [self enableFirewall];

    // load a pf config equal to "set skip on lo0" + /etc/pf.conf + 'anchor "bitmask"'
    [self establishPFConfig];

    // reset the 'gateways' table
    [self resetGateways:gateways];
    NSLog(@"----------------------------------- end reset gateways");
    // block all traffic on default device
    [self addRule:[NSString stringWithFormat:@"block out on %@ all", defaultDevice]];

    // allow traffic to gateways
    [self addRule:[NSString stringWithFormat:@"pass out on %@ to <gateways>", defaultDevice]];

    // allow traffic to local networks over the default device
    [self addRule:[NSString stringWithFormat:@"pass out on %@ to %@:network", defaultDevice, defaultDevice]];

    // block all DNS, except to the gateways
    [self addRule:@"block out proto udp to any port 53"];
    [self addRule:@"pass out proto udp to <gateways> port 53"];

    [self applyRules];
    NSLog(@"----------------------------------- end applyrules");
}

- (void) stop
{
    // flush everything from anchor 'bitmask'
    [self runCmd:self.pfctl withArgs:[NSArray arrayWithObjects:@"-a", @"bitmask", @"-F", @"all", nil]];
}

@end
