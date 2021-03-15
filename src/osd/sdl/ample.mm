
#ifdef SDLMAME_MACOSX

#include "emu.h"
#include "natkeyboard.h"
#include "dipty.h"
#include "emuopts.h"


#include <cstdio>

#include <Cocoa/Cocoa.h>

@interface MenuDelegate : NSObject<NSMenuItemValidation> {
	NSMenuItem *_specialMenuItem;
	NSMenuItem *_speedMenuItem;

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
			[menuItem setEnabled: NO];
		} else {

			unsigned tag = [menuItem tag];

			[menuItem setEnabled: YES];
			[menuItem setState: tag == _speed->live().value ? NSControlStateValueOn : NSControlStateValueOff];
		}
		return YES;
	}

	if (cmd == @selector(toggleMouse:)) {
		bool on = _machine->options().mouse();
		[menuItem setState: on ? NSControlStateValueOn : NSControlStateValueOff];
		return YES;
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

-(void)dealloc {

	NSMenu *mainMenu = [NSApp mainMenu];
	if (_speedMenuItem) [mainMenu removeItem: _speedMenuItem];
	if (_specialMenuItem) [mainMenu removeItem: _specialMenuItem];

	[_speedMenuItem release];
	[_specialMenuItem release];

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
