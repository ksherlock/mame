
#ifdef SDLMAME_MACOSX

#include "emu.h"

#include <Cocoa/Cocoa.h>

@interface MenuDelegate : NSObject<NSMenuItemValidation> {
	running_machine *_machine;
}

-(instancetype)initWithMachine: (running_machine *)machine;

-(void)preferences:(id)sender;
-(void)togglePause:(id)sender;
-(void)toggleThrottle:(id)sender;
-(void)toggleKeyboard:(id)sender;

-(void)softReset:(id)sender;
-(void)hardReset:(id)sender;

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

	return YES;
}


-(void)preferences:(id)sender {
}

-(void)togglePause:(id)sender {
	_machine->toggle_pause();
}
-(void)toggleThrottle:(id)sender {
	_machine->video().toggle_throttle();	
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

@end



static NSMenuItem *BuildSpecialMenu(id target){
	NSMenu *menu = [[NSMenu alloc] initWithTitle: @"Special"];
	NSMenuItem *item = [[NSMenuItem alloc] initWithTitle: @"Special" action: NULL keyEquivalent: @""];

	NSMutableArray *array = [NSMutableArray new];
	{
		NSMenuItem *item = [[NSMenuItem alloc] initWithTitle: @"Pause" action: @selector(togglePause:) keyEquivalent: @"p"];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: target];
		[array addObject: item];
		[item release];
	}
	{
		NSMenuItem *item = [[NSMenuItem alloc] initWithTitle: @"Throttle" action: @selector(toggleThrottle:) keyEquivalent: @"t"];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: target];
		[array addObject: item];
		[item release];
	}
	{
		NSMenuItem *item = [[NSMenuItem alloc] initWithTitle: @"UI Keyboard" action: @selector(toggleKeyboard:) keyEquivalent: @"k"];
		[item setKeyEquivalentModifierMask: NSEventModifierFlagOption|NSEventModifierFlagCommand];
		[item setTarget: target];
		[array addObject: item];
		[item release];
	}
	{
		NSMenuItem *item = [NSMenuItem separatorItem]; [array addObject: item];
	}
	{
		NSMenuItem *item = [[NSMenuItem alloc] initWithTitle: @"Soft Reset" action: @selector(softReset:) keyEquivalent: @""];
		[item setTarget: target];
		[array addObject: item];
		[item release];
	}
	{
		NSMenuItem *item = [[NSMenuItem alloc] initWithTitle: @"Hard Reset" action: @selector(hardReset:) keyEquivalent: @""];
		[item setTarget: target];
		[array addObject: item];
		[item release];
	}
	[menu setItemArray: array];
	[menu setAutoenablesItems: YES];
	[item setSubmenu: menu];
	[menu release];
	[item autorelease];

	return item;
}


void sdl_macos_menus(running_machine &machine) {

	static MenuDelegate *target = nil;

	target = [[MenuDelegate alloc] initWithMachine: &machine];

	@autoreleasepool {
		if (NSApp) {
			NSMenu *menu = [NSApp mainMenu];

			for (NSMenuItem *a in [menu itemArray]) {
				for (NSMenuItem *b in [[a submenu] itemArray]) {
					unsigned m = [b keyEquivalentModifierMask];
					if (m & NSEventModifierFlagCommand)
						[b setKeyEquivalentModifierMask: m | NSEventModifierFlagOption];

					/* optional-command-, preferences. */
					if ([@"," isEqualToString: [b keyEquivalent]]) {
						[b setTarget: target];
						[b setAction: @selector(preferences:)];
					}
				}
			}
			[menu addItem: BuildSpecialMenu(target)];
		}
	}
}

#endif
