
#ifdef SDLMAME_MACOSX

#include "emu.h"
#include "natkeyboard.h"
#include "dipty.h"
#include "emuopts.h"

#include "modules/lib/osdobj_common.h"
#include "sdl/window.h"

#include <cstdio>

#include <Cocoa/Cocoa.h>


@interface FFButton : NSButton
@property BOOL active;
@end



@interface MenuDelegate : NSObject<NSMenuItemValidation> {
	NSMenuItem *_specialMenuItem;
	NSMenuItem *_speedMenuItem;
	NSMenuItem *_videoMenu;

	running_machine *_machine;
	ioport_field *_speed;
}

-(instancetype)initWithMachine: (running_machine *)machine;

-(void)preferences:(id)sender;
-(void)togglePause:(id)sender;
-(void)toggleMouse:(id)sender;
-(void)toggleThrottle:(id)sender;
-(void)toggleKeyboard:(id)sender;

-(void)softReset:(id)sender;
-(void)hardReset:(id)sender;
-(void)setSpeed:(id)sender;

@end

@implementation MenuDelegate

-(instancetype)initWithMachine: (running_machine *)machine {
	_machine = machine;
	return self;
}


- (BOOL)validateMenuItem:(NSMenuItem *)menuItem {
	SEL cmd = [menuItem action];
	if (cmd == @selector(togglePause:)) {
		[menuItem setState: _machine->paused() ? NSControlStateValueOn : NSControlStateValueOff];
		return YES;
	}
	if (cmd == @selector(toggleThrottle:)) {
		[menuItem setState: _machine->video().throttled() ? NSControlStateValueOn : NSControlStateValueOff];
		return YES;
	}
	if (cmd == @selector(toggleKeyboard:)) {
		[menuItem setState: _machine->ui_active() ? NSControlStateValueOn : NSControlStateValueOff];
		return YES;
	}
	if (cmd == @selector(toggleFastForward:)) {
		[menuItem setState: _machine->video().fastforward() ? NSControlStateValueOn : NSControlStateValueOff];
		return YES;
	}

	if (cmd == @selector(setSpeed:)) {

		if (!_speed) {
			return NO;
		} else {

			unsigned tag = [menuItem tag];

			[menuItem setState: tag == _speed->live().value ? NSControlStateValueOn : NSControlStateValueOff];
			return YES;
		}
	}

	if (cmd == @selector(toggleMouse:)) {
		bool on = _machine->options().mouse();
		[menuItem setState: on ? NSControlStateValueOn : NSControlStateValueOff];
		return YES;
	}


	if (cmd == @selector(recordAVI:) || cmd == @selector(recordMNG:) || cmd == @selector(recordStop:)) {
		bool on = _machine->video().is_recording();
		if (cmd == @selector(recordStop:))
			return on;
		else
			return !on;
	}

	#if 0
	if (cmd == @selector(paste:)) {
		return osd_get_clipboard_text().empty() ? NO : YES;
	}
	#endif

	return YES;

}


-(void)preferences:(id)sender {
}

-(void)togglePause:(id)sender {
	_machine->toggle_pause();
}
-(void)toggleThrottle:(id)sender {
	_machine->video().set_throttled(!_machine->video().throttled());
}
-(void)toggleFastForward:(id)sender {
	_machine->video().set_fastforward(!_machine->video().fastforward());
}
-(void)toggleKeyboard:(id)sender {
	_machine->set_ui_active(!_machine->ui_active());
}

-(void)toggleFullScreen:(id)sender {
	for (auto win : osd_common_t::s_window_list)
		std::static_pointer_cast<sdl_window_info>(win)->toggle_full_screen();
}


-(void)toggleMute:(id)sender {
	_machine->sound().ui_mute(!_machine->sound().ui_mute());
}

-(void)tbFastForward:(id)sender {
#if 0
	NSLog(@"%@ - state: %u highlight: %u tag: %u",
		sender, (int)[sender state], (int)[sender isHighlighted], (int)[sender tag]);
#endif
	_machine->video().set_fastforward([(FFButton *)sender active]);
}

-(void)softReset:(id)sender {
	_machine->schedule_soft_reset();
}
-(void)hardReset:(id)sender {
	_machine->schedule_hard_reset();
}

-(void)paste:(id)sender {
	_machine->natkeyboard().paste();
}

-(void)setSpeed:(id)sender {

	if (!_speed) return;
	unsigned tag = [(NSMenuItem *)sender tag];
	_speed->live().value = tag;
}

-(void)toggleMouse:(id)sender {

	bool on = _machine->options().mouse();
	_machine->options().set_value(OPTION_MOUSE, !on, OPTION_PRIORITY_MAXIMUM);
}

-(void)recordMNG:(id)sender {
	_machine->video().toggle_record_movie(movie_recording::format::MNG);
}

-(void)recordAVI:(id)sender {
	_machine->video().toggle_record_movie(movie_recording::format::AVI);
}

-(void)recordStop:(id)sender {
	_machine->video().end_recording();
}

-(void)snapshot:(id)sender {
	_machine->video().save_active_screen_snapshots();
}

-(void)buildSpeedMenu {


	NSMenu *mainMenu = [NSApp mainMenu];

	NSMenu *menu = [[NSMenu alloc] initWithTitle: @"Speed"];

	{
		NSMenuItem *item = [menu addItemWithTitle: @"Throttle" action: @selector(toggleThrottle:) keyEquivalent: @"t"];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}
	{
		NSMenuItem *item = [menu addItemWithTitle: @"Fast Forward" action: @selector(toggleFastForward:) keyEquivalent: @"f"];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}


	// is speed clobbered by a reset?
	for (auto &port : _machine->ioport().ports()) {
		if (port.first != ":a2_config") continue;
		for (ioport_field &field : port.second->fields()) {
			const char *name = field.name();
			if (!name) continue;
			if (strcmp("CPU type", name))  continue;
			_speed = &field;

			{
				NSMenuItem *item = [NSMenuItem separatorItem]; [menu addItem: item];
			}

			for (auto &setting : field.settings()) {

				NSString *title = [NSString stringWithUTF8String: setting.name()];
				NSMenuItem *item = [menu addItemWithTitle: title action: @selector(setSpeed:) keyEquivalent: @""];
				[item setTag: setting.value()];
				[item setTarget: self];
			}


		}

	}

	NSMenuItem *item = [mainMenu addItemWithTitle: @"Speed" action: NULL keyEquivalent: @""];
	_speedMenuItem = [item retain];
	[item setSubmenu: menu];
	[menu setAutoenablesItems: YES];
	[menu release];

}

-(void)buildSpecialMenu {


	NSMenu *mainMenu = [NSApp mainMenu];

	NSMenu *menu = [[NSMenu alloc] initWithTitle: @"Special"];

	{
		NSMenuItem *item = [menu addItemWithTitle: @"Pause" action: @selector(togglePause:) keyEquivalent: @"p"];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}
	{
		NSMenuItem *item = [menu addItemWithTitle: @"Capture Mouse" action: @selector(toggleMouse:) keyEquivalent: @" "];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}

	{
		NSMenuItem *item = [menu addItemWithTitle: @"UI Keyboard" action: @selector(toggleKeyboard:) keyEquivalent: @"k"];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}
	{
		NSMenuItem *item = [NSMenuItem separatorItem]; [menu addItem: item];
	}
	{
		NSMenuItem *item = [menu addItemWithTitle: @"Soft Reset" action: @selector(softReset:) keyEquivalent: @""];
		[item setTarget: self];
	}
	{
		NSMenuItem *item = [menu addItemWithTitle: @"Hard Reset" action: @selector(hardReset:) keyEquivalent: @""];
		[item setTarget: self];
	}
	{
		NSMenuItem *item = [NSMenuItem separatorItem]; [menu addItem: item];
	}
	{
		NSMenuItem *item = [menu addItemWithTitle: @"Paste Text" action: @selector(paste:) keyEquivalent: @"v"];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}

	NSMenuItem *item  = [mainMenu addItemWithTitle: @"Special" action: NULL keyEquivalent: @""];
	_specialMenuItem = [item retain];
	[item setSubmenu: menu];
	[menu setAutoenablesItems: YES];
	[menu release];
}


-(void)buildVideoMenu {


	NSMenu *mainMenu = [NSApp mainMenu];

	NSMenu *menu = [[NSMenu alloc] initWithTitle: @"Video"];

	{
		NSMenuItem *item = [menu addItemWithTitle: @"Save Snapshot" action: @selector(snapshot:) keyEquivalent: @""];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}

	{
		NSMenuItem *item = [menu addItemWithTitle: @"Record MNG" action: @selector(recordMNG:) keyEquivalent: @""];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}
	{
		NSMenuItem *item = [menu addItemWithTitle: @"Record AVI" action: @selector(recordAVI:) keyEquivalent: @""];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}

	{
		NSMenuItem *item = [menu addItemWithTitle: @"Stop" action: @selector(recordStop:) keyEquivalent: @""];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: self];
	}


	NSMenuItem *item  = [mainMenu addItemWithTitle: @"Video" action: NULL keyEquivalent: @""];
	_videoMenu = [item retain];
	[item setSubmenu: menu];
	[menu setAutoenablesItems: YES];
	[menu release];
}


-(void)dealloc {

	NSMenu *mainMenu = [NSApp mainMenu];
	if (_speedMenuItem) [mainMenu removeItem: _speedMenuItem];
	if (_specialMenuItem) [mainMenu removeItem: _specialMenuItem];
	if (_videoMenu) [mainMenu removeItem: _videoMenu];

	[_speedMenuItem release];
	[_specialMenuItem release];
	[_videoMenu release];

	[NSApp setTouchBar: nil];

	[super dealloc];
}

-(void)fixMenus {


	NSMenu *menu = [NSApp mainMenu];
	if (!menu) return;

	for (NSMenuItem *a in [menu itemArray]) {
		for (NSMenuItem *b in [[a submenu] itemArray]) {
			unsigned m = [b keyEquivalentModifierMask];
			if (m & NSEventModifierFlagCommand)
				[b setKeyEquivalentModifierMask: m | NSEventModifierFlagOption];

			/* optional-command-, preferences. */
			if ([@"," isEqualToString: [b keyEquivalent]]) {
				[b setTarget: self];
				[b setAction: @selector(preferences:)];
			}
		}
	}

}

-(void)buildTouchBar {

	NSTouchBar *tb = [NSTouchBar new];
	[tb setDefaultItemIdentifiers: @[@"mame.pause", @"mame.ff", @"mame.mouse", @"mame.fullscreen", @"mame.mute"]];

	NSMutableSet *templates = [NSMutableSet set];
	NSCustomTouchBarItem *item;
	NSButton *button;

	item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.pause"];
	button = [NSButton buttonWithTitle: @"Pause" target: self action: @selector(togglePause:)];
	[item setView: button];

	[templates addObject: item];
	[item release];


	// NSTouchBarFastForwardTemplate
	item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.ff"];
	button = [FFButton buttonWithTitle: @"Fast Forward" target: self action: @selector(tbFastForward:)];
	[button sendActionOn: NSLeftMouseDownMask|NSLeftMouseUpMask];
	// [button setButtonType: NSButtonTypeMomentaryLight];
	[item setView: button];

	[templates addObject: item];
	[item release];


	// NSTouchBarEnterFullScreenTemplate / NSTouchBarExitFullScreenTemplate ...
	item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.fullscreen"];
	button = [NSButton buttonWithTitle: @"Full Screen" target: self action: @selector(toggleFullScreen:)];
	[item setView: button];

	[templates addObject: item];
	[item release];


	// NSTouchBarAudioOutputMuteTemplate / NSTouchBarAudioOutputVolumeHighTemplate
	item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.mute"];
	button = [NSButton buttonWithTitle: @"Mute" target: self action: @selector(toggleMute:)];
	[item setView: button];

	[templates addObject: item];
	[item release];



	item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.mouse"];
	button = [NSButton buttonWithTitle: @"Mouse" target: self action: @selector(toggleMouse:)];
	[item setView: button];

	[templates addObject: item];
	[item release];



	[tb setTemplateItems: templates];
	[NSApp setTouchBar: tb];
	[tb release];
}

@end

/* NSCell stuff is "deprecated" */
#if 0
@interface FFButtonCell : NSButtonCell
@end


/* fast forward while button is pressed - need extra logic to keep track of mouse down state */
@implementation FFButtonCell

// ??
+ (BOOL)prefersTrackingUntilMouseUp {
  return YES;
}


- (BOOL)startTrackingAt:(NSPoint)startPoint inView:(NSView *)controlView {
	// [controlView setTag: 1];
	// [self setState: ]
	//return [super startTrackingAt: startPoint inView: controlView];
	[self setState: 1];
	return YES;
}

- (BOOL)continueTracking:(NSPoint)lastPoint at:(NSPoint)currentPoint inView:(NSView *)controlView {
	return YES;
}


- (void)stopTracking:(NSPoint)lastPoint at:(NSPoint)stopPoint inView:(NSView *)controlView mouseIsUp:(BOOL)flag {

	[self setState: 0];

	// [controlView setTag: 0];
	// [super stopTracking: lastPoint at: stopPoint inView: controlView mouseIsUp: flag];
}

@end

#endif

@implementation FFButton

#if 0
-(void)mouseDown:(NSEvent *)event {
	NSLog(@"mouseDown: %@", event);
	[self setState: 1];
	[super mouseDown: event];
	[self setState: 0];
}
#endif

- (void)touchesBeganWithEvent:(NSEvent *)event {
	//NSLog(@"touchesBeganWithEvent: %@", event);
	[self setActive: YES];
	// [self setTag: 1];
	// [self setState: 0];
	[super touchesBeganWithEvent: event];
}

- (void)touchesEndedWithEvent:(NSEvent *)event {
	//NSLog(@"touchesEndedWithEvent: %@", event);
	[self setActive: NO];
	// [self setTag: 0];
	// [self setState: 1];
	[super touchesEndedWithEvent: event];
}


@end


/* called after a hard reset, etc, in which case the existing delegate and menus should be destroyed */

void ample_update_machine(running_machine *machine) {

static MenuDelegate *target = nil;

	if (target) [target release];
	target = [[MenuDelegate alloc] initWithMachine: machine];

	@autoreleasepool {

		[target fixMenus];
		[target buildSpecialMenu];
		[target buildSpeedMenu];
		[target buildVideoMenu];
		[target buildTouchBar];
	}


	/* ample - auto-select the first network interface */
	for (device_network_interface &network : network_interface_enumerator(machine->root_device()))
	{
		network.set_interface(0);
		break;
	}

	/* print any active ptys */
	for (device_pty_interface &pty : pty_interface_enumerator(machine->root_device()))
	{
		const char *port_name = pty.device().owner()->tag() + 1;
		if (pty.is_open())
			std::printf("%s: %s\n", port_name, pty.slave_name());
	}

}


#endif
