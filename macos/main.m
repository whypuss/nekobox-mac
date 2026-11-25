// SPDX-License-Identifier: GPL-3.0-or-later
// Nekobox-Mac Native macOS Shell (Universal arm64 + x86_64)
// AppKit + WebKit + NSStatusItem (Cat-in-Box vector icon) + Core Process Supervisor

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

static int findFreeLocalPort(int preferred) {
    for (int port = preferred; port < preferred + 64; port++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons((uint16_t)port);
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
            close(fd);
            return port;
        }
        close(fd);
    }
    return preferred;
}

// Crisp monochrome template image of Nekobox-Next's 24x24 Cat-in-Box icon (ic_service_active.xml)
static NSImage *createCatInBoxTrayIcon(void) {
    NSSize size = NSMakeSize(18.0, 18.0);
    NSImage *img = [NSImage imageWithSize:size flipped:YES drawingHandler:^BOOL(NSRect dstRect) {
        CGFloat scale = 18.0 / 24.0;
        NSAffineTransform *tx = [NSAffineTransform transform];
        [tx scaleBy:scale];
        [tx concat];

        [[NSColor blackColor] setFill];

        // Cat head peeking above box with negative-space oval eyes (even-odd)
        NSBezierPath *cat = [NSBezierPath bezierPath];
        [cat setWindingRule:NSWindingRuleNonZero];
        [cat moveToPoint:NSMakePoint(5.4, 11.7)];
        [cat lineToPoint:NSMakePoint(5.3, 8.9)];
        [cat curveToPoint:NSMakePoint(6.3, 3.2) controlPoint1:NSMakePoint(5.3, 6.4) controlPoint2:NSMakePoint(5.7, 4.1)];
        [cat curveToPoint:NSMakePoint(8.1, 3.1) controlPoint1:NSMakePoint(6.7, 2.6) controlPoint2:NSMakePoint(7.4, 2.6)];
        [cat lineToPoint:NSMakePoint(10.2, 4.9)];
        [cat curveToPoint:NSMakePoint(13.8, 4.9) controlPoint1:NSMakePoint(11.3, 4.6) controlPoint2:NSMakePoint(12.7, 4.6)];
        [cat lineToPoint:NSMakePoint(15.9, 3.1)];
        [cat curveToPoint:NSMakePoint(17.7, 3.2) controlPoint1:NSMakePoint(16.6, 2.6) controlPoint2:NSMakePoint(17.3, 2.6)];
        [cat curveToPoint:NSMakePoint(18.7, 8.9) controlPoint1:NSMakePoint(18.3, 4.1) controlPoint2:NSMakePoint(18.7, 6.4)];
        [cat lineToPoint:NSMakePoint(18.6, 11.7)];
        [cat closePath];

        NSBezierPath *leftEye = [NSBezierPath bezierPathWithOvalInRect:NSMakeRect(7.9, 7.5, 2.4, 3.4)];
        NSBezierPath *rightEye = [NSBezierPath bezierPathWithOvalInRect:NSMakeRect(13.7, 7.5, 2.4, 3.4)];
        [cat appendBezierPath:leftEye];
        [cat appendBezierPath:rightEye];
        [cat setWindingRule:NSWindingRuleEvenOdd];
        [cat fill];

        // Parcel flaps + rounded box base
        NSBezierPath *box = [NSBezierPath bezierPath];
        [box moveToPoint:NSMakePoint(4.6, 12.6)];
        [box lineToPoint:NSMakePoint(11.4, 12.6)];
        [box lineToPoint:NSMakePoint(11.4, 15.3)];
        [box lineToPoint:NSMakePoint(2.9, 15.3)];
        [box lineToPoint:NSMakePoint(2.4, 14.1)];
        [box lineToPoint:NSMakePoint(4.0, 12.8)];
        [box closePath];

        [box moveToPoint:NSMakePoint(12.6, 12.6)];
        [box lineToPoint:NSMakePoint(19.4, 12.6)];
        [box lineToPoint:NSMakePoint(21.6, 14.1)];
        [box lineToPoint:NSMakePoint(21.1, 15.3)];
        [box lineToPoint:NSMakePoint(12.6, 15.3)];
        [box closePath];

        NSBezierPath *base = [NSBezierPath bezierPathWithRoundedRect:NSMakeRect(4.6, 16.4, 14.8, 5.0) xRadius:2.2 yRadius:2.2];
        [box appendBezierPath:base];
        [box fill];

        return YES;
    }];
    [img setTemplate:YES];
    return img;
}

@interface NekoAppDelegate : NSObject <NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate>
@property (strong) NSWindow *window;
@property (strong) WKWebView *webView;
@property (strong) NSStatusItem *statusItem;
@property (strong) NSMenuItem *statusTitleItem;
@property (strong) NSMenuItem *toggleConnectItem;
@property (strong) NSTask *coreTask;
@property (assign) int corePort;
@property (assign) BOOL isConnected;
@property (copy) NSString *activeProfileName;
@property (strong) NSTimer *pollTimer;
@end

@implementation NekoAppDelegate

- (void)setupMainMenu {
    NSMenu *menubar = [[NSMenu alloc] init];

    // App Menu
    NSMenuItem *appItem = [[NSMenuItem alloc] init];
    NSMenu *appMenu = [[NSMenu alloc] initWithTitle:@"Nekobox-Mac"];
    [appMenu addItemWithTitle:@"关于 Nekobox-Mac" action:@selector(showMainWindow:) keyEquivalent:@""];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"隐藏 Nekobox-Mac" action:@selector(hide:) keyEquivalent:@"h"];
    [appMenu addItem:[NSMenuItem separatorItem]];
    [appMenu addItemWithTitle:@"退出 Nekobox-Mac" action:@selector(terminate:) keyEquivalent:@"q"];
    [appItem setSubmenu:appMenu];
    [menubar addItem:appItem];

    // Edit Menu (enables Cmd+C/V/X/A/Z inside WKWebView inputs)
    NSMenuItem *editItem = [[NSMenuItem alloc] init];
    NSMenu *editMenu = [[NSMenu alloc] initWithTitle:@"编辑"];
    [editMenu addItemWithTitle:@"撤销" action:@selector(undo:) keyEquivalent:@"z"];
    [editMenu addItemWithTitle:@"重做" action:@selector(redo:) keyEquivalent:@"Z"];
    [editMenu addItem:[NSMenuItem separatorItem]];
    [editMenu addItemWithTitle:@"剪切" action:@selector(cut:) keyEquivalent:@"x"];
    [editMenu addItemWithTitle:@"拷贝" action:@selector(copy:) keyEquivalent:@"c"];
    [editMenu addItemWithTitle:@"粘贴" action:@selector(paste:) keyEquivalent:@"v"];
    [editMenu addItemWithTitle:@"全选" action:@selector(selectAll:) keyEquivalent:@"a"];
    [editItem setSubmenu:editMenu];
    [menubar addItem:editItem];

    // Window Menu
    NSMenuItem *winItem = [[NSMenuItem alloc] init];
    NSMenu *winMenu = [[NSMenu alloc] initWithTitle:@"窗口"];
    [winMenu addItemWithTitle:@"关闭窗口" action:@selector(performClose:) keyEquivalent:@"w"];
    [winMenu addItemWithTitle:@"最小化" action:@selector(performMiniaturize:) keyEquivalent:@"m"];
    [winMenu addItemWithTitle:@"重新加载界面" action:@selector(reloadWebView:) keyEquivalent:@"r"];
    [winItem setSubmenu:winMenu];
    [menubar addItem:winItem];

    [NSApp setMainMenu:menubar];
}

- (void)setupStatusBar {
    self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSSquareStatusItemLength];
    self.statusItem.button.image = createCatInBoxTrayIcon();
    self.statusItem.button.toolTip = @"Nekobox-Mac";

    NSMenu *menu = [[NSMenu alloc] init];
    self.statusTitleItem = [[NSMenuItem alloc] initWithTitle:@"状态：未连接" action:nil keyEquivalent:@""];
    self.statusTitleItem.enabled = NO;
    [menu addItem:self.statusTitleItem];
    [menu addItem:[NSMenuItem separatorItem]];

    self.toggleConnectItem = [[NSMenuItem alloc] initWithTitle:@"连接代理" action:@selector(menuToggleConnect:) keyEquivalent:@""];
    self.toggleConnectItem.target = self;
    [menu addItem:self.toggleConnectItem];

    NSMenuItem *openItem = [[NSMenuItem alloc] initWithTitle:@"打开 Nekobox-Mac" action:@selector(showMainWindow:) keyEquivalent:@""];
    openItem.target = self;
    [menu addItem:openItem];

    NSMenuItem *dashItem = [[NSMenuItem alloc] initWithTitle:@"打开 MetaCubeXD 面板" action:@selector(openDashboardInBrowser:) keyEquivalent:@""];
    dashItem.target = self;
    [menu addItem:dashItem];

    [menu addItem:[NSMenuItem separatorItem]];
    NSMenuItem *quitItem = [[NSMenuItem alloc] initWithTitle:@"退出 Nekobox-Mac" action:@selector(terminate:) keyEquivalent:@"q"];
    [menu addItem:quitItem];

    self.statusItem.menu = menu;
}

- (void)startCoreProcess {
    self.corePort = findFreeLocalPort(19850);
    NSString *execDir = [[[NSBundle mainBundle] executablePath] stringByDeletingLastPathComponent];
    NSString *coreBin = [execDir stringByAppendingPathComponent:@"nekobox-core"];
    NSString *yacdZip = [[[NSBundle mainBundle] resourcePath] stringByAppendingPathComponent:@"yacd.zip"];
    NSString *bundlePath = [[NSBundle mainBundle] bundlePath];

    if (![[NSFileManager defaultManager] isExecutableFileAtPath:coreBin]) {
        NSAlert *alert = [[NSAlert alloc] init];
        alert.messageText = @"未找到 nekobox-core 内核程序";
        alert.informativeText = coreBin;
        [alert runModal];
        [NSApp terminate:nil];
        return;
    }

    NSTask *task = [[NSTask alloc] init];
    task.launchPath = coreBin;
    NSMutableArray *args = [NSMutableArray arrayWithArray:@[
        @"--listen", [NSString stringWithFormat:@"127.0.0.1:%d", self.corePort],
        @"--app-path", bundlePath
    ]];
    if ([[NSFileManager defaultManager] fileExistsAtPath:yacdZip]) {
        [args addObject:@"--yacd-zip"];
        [args addObject:yacdZip];
    }
    task.arguments = args;
    task.standardOutput = [NSFileHandle fileHandleWithNullDevice];
    task.standardError = [NSFileHandle fileHandleWithNullDevice];
    [task launch];
    self.coreTask = task;
}

- (void)waitForCoreAndLoad {
    NSURL *statusURL = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d/api/status", self.corePort]];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        for (int i = 0; i < 80; i++) {
            NSData *data = [NSData dataWithContentsOfURL:statusURL];
            if (data != nil && data.length > 2) {
                break;
            }
            usleep(100000);
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            NSURL *uiURL = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d/", self.corePort]];
            [self.webView loadRequest:[NSURLRequest requestWithURL:uiURL]];
            [self pollCoreStatus];
        });
    });
}

- (void)setupWindow {
    NSRect frame = NSMakeRect(0, 0, 1020, 720);
    NSWindowStyleMask style = NSWindowStyleMaskTitled |
                              NSWindowStyleMaskClosable |
                              NSWindowStyleMaskMiniaturizable |
                              NSWindowStyleMaskResizable |
                              NSWindowStyleMaskFullSizeContentView;
    self.window = [[NSWindow alloc] initWithContentRect:frame
                                              styleMask:style
                                                backing:NSBackingStoreBuffered
                                                  defer:NO];
    self.window.title = @"Nekobox-Mac";
    self.window.titleVisibility = NSWindowTitleHidden;
    self.window.titlebarAppearsTransparent = YES;
    self.window.minSize = NSMakeSize(420, 560);
    self.window.delegate = self;
    [self.window center];

    WKWebViewConfiguration *cfg = [[WKWebViewConfiguration alloc] init];
    [cfg.preferences setValue:@YES forKey:@"developerExtrasEnabled"];
    self.webView = [[WKWebView alloc] initWithFrame:frame configuration:cfg];
    self.webView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    self.webView.navigationDelegate = self;
    self.webView.UIDelegate = self;
    [self.webView setValue:@NO forKey:@"drawsBackground"];

    self.window.contentView = self.webView;
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)postAPI:(NSString *)path body:(NSString *)jsonBody completion:(void (^)(void))done {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d%@", self.corePort, path]];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    if (jsonBody) {
        req.HTTPBody = [jsonBody dataUsingEncoding:NSUTF8StringEncoding];
    }
    [[[NSURLSession sharedSession] dataTaskWithRequest:req completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
        if (done) dispatch_async(dispatch_get_main_queue(), done);
    }] resume];
}

- (void)pollCoreStatus {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d/api/status", self.corePort]];
    [[[NSURLSession sharedSession] dataTaskWithURL:url completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
        if (!data || err) return;
        NSDictionary *obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (![obj isKindOfClass:[NSDictionary class]]) return;
        NSString *state = obj[@"state"] ?: @"stopped";
        NSString *name = obj[@"activeName"] ?: @"";
        BOOL conn = [state isEqualToString:@"connected"];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.isConnected = conn;
            self.activeProfileName = name;
            if (conn) {
                self.statusTitleItem.title = [NSString stringWithFormat:@"已连接：%@", name.length > 0 ? name : @"代理中"];
                self.toggleConnectItem.title = @"断开代理";
            } else {
                self.statusTitleItem.title = @"状态：未连接";
                self.toggleConnectItem.title = @"连接代理";
            }
        });
    }] resume];
}

- (void)menuToggleConnect:(id)sender {
    NSString *path = self.isConnected ? @"/api/disconnect" : @"/api/connect";
    [self postAPI:path body:@"{}" completion:^{
        [self pollCoreStatus];
    }];
}

- (void)showMainWindow:(id)sender {
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
    [self postAPI:@"/api/power/polling" body:@"{\"paused\":false}" completion:nil];
}

- (void)openDashboardInBrowser:(id)sender {
    NSURL *url = [NSURL URLWithString:[NSString stringWithFormat:@"http://127.0.0.1:%d/ui/", self.corePort]];
    [[NSWorkspace sharedWorkspace] openURL:url];
}

- (void)reloadWebView:(id)sender {
    [self.webView reload];
}

// Keep core alive in menu bar when window red close button is clicked
- (BOOL)windowShouldClose:(NSWindow *)sender {
    [self.window orderOut:nil];
    [self postAPI:@"/api/power/polling" body:@"{\"paused\":true}" completion:nil];
    return NO;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication *)sender hasVisibleWindows:(BOOL)flag {
    [self showMainWindow:nil];
    return YES;
}

- (void)onSystemSleep:(NSNotification *)note {
    [self postAPI:@"/api/power/sleep" body:@"{}" completion:nil];
}

- (void)onSystemWake:(NSNotification *)note {
    [self postAPI:@"/api/power/wake" body:@"{}" completion:nil];
}

- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    [self setupMainMenu];
    [self setupStatusBar];
    [self startCoreProcess];
    [self setupWindow];
    [self waitForCoreAndLoad];

    NSNotificationCenter *wsCenter = [[NSWorkspace sharedWorkspace] notificationCenter];
    [wsCenter addObserver:self selector:@selector(onSystemSleep:) name:NSWorkspaceWillSleepNotification object:nil];
    [wsCenter addObserver:self selector:@selector(onSystemWake:) name:NSWorkspaceDidWakeNotification object:nil];

    self.pollTimer = [NSTimer scheduledTimerWithTimeInterval:3.0
                                                      target:self
                                                    selector:@selector(pollCoreStatus)
                                                    userInfo:nil
                                                     repeats:YES];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
    [self.pollTimer invalidate];
    if (self.coreTask && self.coreTask.isRunning) {
        pid_t pid = self.coreTask.processIdentifier;
        kill(pid, SIGTERM);
        for (int i = 0; i < 25; i++) {
            if (!self.coreTask.isRunning) break;
            usleep(100000);
        }
        if (self.coreTask.isRunning) {
            [self.coreTask terminate];
        }
    }
}

@end

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSApplication *app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        NekoAppDelegate *delegate = [[NekoAppDelegate alloc] init];
        [app setDelegate:delegate];
        [app run];
    }
    return 0;
}
