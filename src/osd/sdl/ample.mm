
#ifdef SDLMAME_MACOSX

#include "emu.h"
#include "natkeyboard.h"
#include "dipty.h"
#include "dinetwork.h"
#include "emuopts.h"

#include "modules/lib/osdobj_common.h"
#include "sdl/window.h"

#include <cstdio>

#include <Cocoa/Cocoa.h>


enum {
	kTagPause =1,
	kTagFastForward,
	kTagMouse,
	kTagFullScreen,
	kTagMute
};


@interface FFButton : NSButton
@property BOOL active;
@end



@interface MenuDelegate : NSObject<NSMenuItemValidation> {
	NSMenuItem *_specialMenuItem;
	NSMenuItem *_speedMenuItem;
	NSMenuItem *_videoMenu;

	NSArray *_touchBarButtons;
	NSTimer *_timer;

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

-(void)updateButtons;

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


-(void)updateButtons {

	// mouse capture, full screen not available w/ debugger.

	for (NSButton *b in _touchBarButtons) {
		if ([b isHighlighted]) continue;
		switch ([b tag]) {
			case kTagPause:
				[b setState: _machine->paused() ? NSControlStateValueOn : NSControlStateValueOff];
				break;
			case kTagMouse:
				[b setState: _machine->options().mouse() ? NSControlStateValueOn : NSControlStateValueOff];
				break;
			case kTagMute:
				[b setState: _machine->sound().ui_mute() ? NSControlStateValueOn : NSControlStateValueOff];
				break;
			case kTagFullScreen:
				#if 0
				if (_machine->debug_flags & DEBUG_FLAG_OSD_ENABLED) {
					[b setEnabled: NO];
				} else {
					[b setEnabled: YES];
				}
				#endif
				if (!osd_common_t::s_window_list.empty()) {
					auto window = osd_common_t::s_window_list.front();
					[b setState: window->fullscreen() ? NSControlStateValueOn : NSControlStateValueOff];
				}
				break;
			case kTagFastForward:
				/* nothing */
				break;
		}

	}
}

-(void)preferences:(id)sender {
}

-(void)togglePause:(id)sender {
	_machine->toggle_pause();
	[self updateButtons];
}
-(void)toggleThrottle:(id)sender {
	_machine->video().set_throttled(!_machine->video().throttled());
	// [self updateButtons];
}
-(void)toggleFastForward:(id)sender {
	_machine->video().set_fastforward(!_machine->video().fastforward());
	// [self updateButtons];
}
-(void)toggleKeyboard:(id)sender {
	_machine->set_ui_active(!_machine->ui_active());
}

-(void)toggleFullScreen:(id)sender {
	for (auto win : osd_common_t::s_window_list)
		std::static_pointer_cast<sdl_window_info>(win)->toggle_full_screen();

	[self updateButtons];
}


-(void)toggleMute:(id)sender {
	_machine->sound().ui_mute(!_machine->sound().ui_mute());
	[self updateButtons];
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

	//downcast<sdl_osd_interface &>(_machine->osd()).release_keys();
	_machine->natkeyboard().paste();
}


-(void)releaseKeys:(id)sender {
	downcast<sdl_osd_interface &>(_machine->osd()).release_keys();
}

-(void)setSpeed:(id)sender {

	if (!_speed) return;
	unsigned tag = [(NSMenuItem *)sender tag];
	_speed->live().value = tag;
}

-(void)toggleMouse:(id)sender {

	bool on = _machine->options().mouse();
	_machine->options().set_value(OPTION_MOUSE, !on, OPTION_PRIORITY_MAXIMUM);
	[self updateButtons];
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
			std::string name = field.name();
			if (name != "CPU type")  continue;
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
		NSMenuItem *item = [menu addItemWithTitle: @"Reset Keyboard" action: @selector(releaseKeys:) keyEquivalent: @""];
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

	[_timer invalidate];
	[_timer release];

	if (_speedMenuItem) [mainMenu removeItem: _speedMenuItem];
	if (_specialMenuItem) [mainMenu removeItem: _specialMenuItem];
	if (_videoMenu) [mainMenu removeItem: _videoMenu];

	[_speedMenuItem release];
	[_specialMenuItem release];
	[_videoMenu release];
	[_touchBarButtons release];

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


static NSImage *MouseOnImage(void) {

	unsigned char ___Ample_images_mouse_on_png[] = {
	  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	  0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x30,
	  0x08, 0x06, 0x00, 0x00, 0x00, 0x57, 0x02, 0xf9, 0x87, 0x00, 0x00, 0x00,
	  0x04, 0x67, 0x41, 0x4d, 0x41, 0x00, 0x00, 0xb1, 0x8f, 0x0b, 0xfc, 0x61,
	  0x05, 0x00, 0x00, 0x01, 0x68, 0x49, 0x44, 0x41, 0x54, 0x68, 0x05, 0xed,
	  0x95, 0x31, 0x6a, 0x02, 0x41, 0x14, 0x86, 0x57, 0x48, 0x99, 0x4a, 0x30,
	  0x45, 0x8a, 0x34, 0x21, 0xa4, 0x48, 0x99, 0x90, 0x0b, 0xc4, 0x23, 0x98,
	  0x2b, 0x78, 0x05, 0xa3, 0xc6, 0x98, 0x6b, 0x98, 0x23, 0xe8, 0x11, 0xf4,
	  0x06, 0xda, 0x58, 0x49, 0x24, 0x85, 0x8d, 0x16, 0x96, 0xb6, 0x82, 0xf1,
	  0xff, 0xc1, 0x81, 0x61, 0xd8, 0x4c, 0x54, 0x96, 0xdd, 0xf7, 0xe0, 0x0d,
	  0x3c, 0x76, 0xe7, 0xcd, 0xdb, 0x99, 0xff, 0xfb, 0xdf, 0x2e, 0x9b, 0x24,
	  0x36, 0xcc, 0x01, 0x73, 0xc0, 0x1c, 0x30, 0x07, 0xcc, 0x01, 0x73, 0x40,
	  0xb7, 0x03, 0x9f, 0xba, 0xe5, 0x27, 0xc9, 0x2f, 0x00, 0xba, 0x9a, 0x21,
	  0x08, 0xc0, 0xf8, 0xd0, 0x0a, 0xe1, 0x00, 0xd4, 0x42, 0xf8, 0x00, 0xbc,
	  0xef, 0x68, 0xeb, 0x44, 0x08, 0xa0, 0x0e, 0x22, 0x0d, 0x80, 0xb9, 0x77,
	  0x2d, 0x9d, 0xf8, 0x0b, 0x80, 0xf9, 0xb6, 0x06, 0x88, 0x18, 0x80, 0x0a,
	  0x88, 0xff, 0x00, 0xb8, 0xde, 0x92, 0xdc, 0x89, 0x63, 0x00, 0x44, 0x43,
	  0x1c, 0x0b, 0xc0, 0xba, 0xa6, 0xc4, 0x4e, 0x9c, 0x02, 0xc0, 0xda, 0x37,
	  0x69, 0x10, 0xa7, 0x02, 0x88, 0x83, 0x38, 0x07, 0x80, 0xcf, 0x34, 0xa4,
	  0x74, 0xe2, 0x5c, 0x80, 0x4c, 0x20, 0x2e, 0x72, 0x70, 0x61, 0x8b, 0x33,
	  0x9e, 0x11, 0xab, 0x94, 0xb3, 0x08, 0x51, 0xf8, 0x08, 0x3b, 0xb0, 0x84,
	  0x22, 0x8a, 0xf5, 0xf3, 0xbd, 0xc2, 0x55, 0x46, 0x04, 0xf8, 0x42, 0x17,
	  0xa8, 0xbb, 0x45, 0xd4, 0x11, 0x7e, 0x9e, 0x5d, 0xb8, 0x43, 0x88, 0x1c,
	  0x4e, 0xe8, 0x0f, 0xd4, 0xdd, 0x1c, 0x14, 0xf2, 0xd5, 0x9c, 0x23, 0xdc,
	  0x1a, 0xaf, 0xfd, 0xc3, 0x9a, 0xb8, 0x0b, 0xc5, 0xcd, 0x10, 0xd7, 0x81,
	  0xb2, 0x57, 0xcc, 0x7d, 0x80, 0x1d, 0xe6, 0x8f, 0x41, 0x8d, 0x88, 0xe9,
	  0x14, 0x2a, 0xae, 0x52, 0x94, 0x94, 0x90, 0x9b, 0x20, 0x7c, 0x88, 0x61,
	  0x4a, 0x5d, 0xe1, 0xa9, 0x72, 0x44, 0x41, 0x35, 0x00, 0x20, 0xcc, 0x4b,
	  0xa4, 0x5e, 0xe4, 0xd2, 0x28, 0x80, 0x18, 0x8b, 0x54, 0x19, 0x11, 0xf5,
	  0x14, 0x00, 0xb0, 0x0b, 0xb5, 0x48, 0xbd, 0xc8, 0xa5, 0x41, 0x00, 0xf1,
	  0x8d, 0x79, 0x1e, 0x3f, 0xd1, 0xcc, 0xcc, 0xb8, 0xc7, 0x4e, 0xfc, 0x17,
	  0xb8, 0x0f, 0x7a, 0x8d, 0xfb, 0x87, 0xcc, 0x76, 0xcf, 0x69, 0xa3, 0x2f,
	  0x9c, 0xb3, 0x41, 0x74, 0x11, 0x97, 0x39, 0x9d, 0x99, 0xe9, 0x31, 0x15,
	  0xec, 0xc6, 0xb0, 0x61, 0x0e, 0x98, 0x03, 0xe6, 0x80, 0x39, 0x60, 0x0e,
	  0x98, 0x03, 0xce, 0x81, 0x3d, 0x92, 0xa3, 0xc0, 0x29, 0x7d, 0x60, 0x35,
	  0xb5, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60,
	  0x82
	};
	unsigned int ___Ample_images_mouse_on_png_len = 433;


	NSImage *img;
	NSData *data;

	data = [NSData dataWithBytesNoCopy: ___Ample_images_mouse_on_png length: ___Ample_images_mouse_on_png_len freeWhenDone: NO];
	img = [[NSImage alloc] initWithSize: NSMakeSize(24, 24)];
	img = [[NSImage alloc] initWithData: data];
	[img setSize: NSMakeSize(24, 24)];
	[img setTemplate: YES];

	return [img autorelease];
}

static NSImage *MouseOffImage(void) {

	unsigned char ___Ample_images_mouse_off_png[] = {
	  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	  0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x30,
	  0x08, 0x06, 0x00, 0x00, 0x00, 0x57, 0x02, 0xf9, 0x87, 0x00, 0x00, 0x00,
	  0x04, 0x67, 0x41, 0x4d, 0x41, 0x00, 0x00, 0xb1, 0x8f, 0x0b, 0xfc, 0x61,
	  0x05, 0x00, 0x00, 0x02, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x68, 0x05, 0xed,
	  0x97, 0x4b, 0x4a, 0xc5, 0x30, 0x14, 0x86, 0xaf, 0x28, 0xe2, 0x40, 0x74,
	  0xa4, 0x3b, 0xd0, 0x89, 0x43, 0xdd, 0x81, 0x22, 0x2e, 0x40, 0x41, 0x1d,
	  0xf8, 0xde, 0x83, 0x03, 0x1f, 0xd7, 0x75, 0xb8, 0x03, 0x71, 0x07, 0xe2,
	  0xd0, 0x81, 0xa2, 0x1b, 0x70, 0x26, 0x17, 0x1f, 0xe0, 0xd0, 0xa9, 0xf8,
	  0xf8, 0x7f, 0xe8, 0x81, 0x43, 0x6f, 0xd2, 0x9a, 0xda, 0xe6, 0x71, 0xe9,
	  0x81, 0x9f, 0xa4, 0x49, 0xda, 0x7e, 0xff, 0x69, 0x12, 0xd2, 0x4e, 0x27,
	  0xbd, 0x58, 0x07, 0xf2, 0x0b, 0xd4, 0x83, 0x56, 0x52, 0xc3, 0xdf, 0x03,
	  0xf0, 0x17, 0xf4, 0x93, 0x89, 0x26, 0x92, 0x09, 0xc2, 0x7f, 0x43, 0x02,
	  0xcf, 0xf2, 0x2d, 0x15, 0xfa, 0x7c, 0xe6, 0x09, 0x4f, 0x33, 0x9b, 0x29,
	  0x18, 0xd8, 0x05, 0xa4, 0x9e, 0x36, 0x02, 0x7f, 0xd0, 0xc2, 0x37, 0x9c,
	  0x81, 0x81, 0xcc, 0xfc, 0x7e, 0xc3, 0x49, 0xab, 0xe5, 0xf1, 0xb6, 0xcc,
	  0xb7, 0xf0, 0xb6, 0xf4, 0x9e, 0xd9, 0x3a, 0x1c, 0xdb, 0x83, 0x65, 0x9e,
	  0xdb, 0x5a, 0xd7, 0x11, 0x36, 0x3f, 0x3c, 0x18, 0x3c, 0x41, 0x68, 0x80,
	  0x3a, 0xe5, 0x45, 0x85, 0x08, 0x0a, 0x4f, 0x5e, 0x31, 0xc0, 0xf2, 0xc4,
	  0xd1, 0x00, 0xe1, 0xf3, 0xc7, 0x03, 0x5e, 0x7b, 0x5d, 0xb0, 0xda, 0x80,
	  0x8b, 0x09, 0xd3, 0xd9, 0x86, 0xf0, 0x6c, 0xf7, 0x1a, 0x79, 0x03, 0xbc,
	  0x3e, 0x2e, 0x21, 0x88, 0x06, 0x9e, 0x9c, 0x26, 0x03, 0x45, 0x26, 0xa2,
	  0x82, 0x2f, 0x32, 0x40, 0x13, 0x47, 0x1c, 0xa0, 0x22, 0x3a, 0x78, 0xb2,
	  0xd9, 0xbe, 0x00, 0xdb, 0x6f, 0xa1, 0x51, 0x0e, 0x42, 0x44, 0x09, 0x4f,
	  0x30, 0x9b, 0x01, 0xc2, 0x4f, 0x70, 0x00, 0x22, 0x5a, 0x78, 0xc2, 0x99,
	  0x0c, 0x24, 0x03, 0x6f, 0x32, 0x50, 0x06, 0xcf, 0x9f, 0x13, 0xee, 0xff,
	  0xd1, 0x84, 0xfe, 0x02, 0xc9, 0xc1, 0x33, 0x8b, 0x62, 0xc0, 0x05, 0x5e,
	  0x16, 0x76, 0x14, 0x5f, 0x81, 0x06, 0x5c, 0xe0, 0x27, 0xb3, 0xf1, 0x87,
	  0x51, 0xd0, 0x57, 0x80, 0xbf, 0xc3, 0x3d, 0xf2, 0xd5, 0xa2, 0x30, 0x51,
	  0xb4, 0x55, 0xe6, 0x17, 0xec, 0x18, 0xe0, 0xa7, 0x95, 0xa6, 0x50, 0x8f,
	  0x22, 0x4c, 0xfb, 0xbc, 0x86, 0x1f, 0x8e, 0x82, 0xd2, 0x02, 0x51, 0x06,
	  0xcf, 0x39, 0x7f, 0x03, 0xcd, 0x58, 0xee, 0x0f, 0xda, 0x6c, 0x83, 0xdf,
	  0xc9, 0xa8, 0x64, 0xc1, 0x72, 0xce, 0x5f, 0x04, 0x25, 0x35, 0xbc, 0xbc,
	  0x0c, 0x9e, 0xf3, 0x5d, 0x2f, 0x58, 0x9e, 0xf5, 0xe7, 0x0d, 0xcf, 0x09,
	  0xd2, 0x54, 0x06, 0x4f, 0xa8, 0x21, 0xe8, 0x01, 0x92, 0x1d, 0x87, 0xe5,
	  0x15, 0x14, 0x3c, 0xfe, 0x02, 0x2f, 0x90, 0x4b, 0xa8, 0x68, 0x03, 0xac,
	  0x2f, 0x4a, 0x67, 0x88, 0xd2, 0x05, 0x5e, 0xf8, 0xae, 0x51, 0xd1, 0x26,
	  0xee, 0xa5, 0xc3, 0x77, 0x59, 0x05, 0x9e, 0x8c, 0x0b, 0x90, 0x36, 0xc0,
	  0xfa, 0x2a, 0x3b, 0x7c, 0x46, 0x55, 0x78, 0x61, 0xbc, 0x44, 0x45, 0x9b,
	  0x78, 0xc4, 0xf5, 0x88, 0x74, 0x36, 0x5d, 0xda, 0xe0, 0xb7, 0x1d, 0x5e,
	  0x3c, 0x8b, 0xb1, 0x9f, 0x90, 0x98, 0x78, 0x47, 0x7d, 0xce, 0xe1, 0xfe,
	  0xca, 0x43, 0xeb, 0x80, 0x97, 0x97, 0x9f, 0xa3, 0xf2, 0x01, 0x75, 0xa1,
	  0x71, 0x69, 0x6c, 0xb2, 0xac, 0x13, 0x9e, 0x9c, 0x3c, 0xf7, 0x78, 0x3b,
	  0xfb, 0xd4, 0x0d, 0xdf, 0x64, 0xa2, 0xfb, 0x9e, 0xdd, 0xc2, 0xf7, 0xa5,
	  0xc4, 0x53, 0xc3, 0x40, 0x66, 0x7e, 0xcb, 0x53, 0xf2, 0xfe, 0xf5, 0x9a,
	  0x0d, 0xdc, 0xcd, 0x93, 0xa2, 0xec, 0xd1, 0x2c, 0xf9, 0x33, 0x92, 0x04,
	  0x3c, 0x38, 0x3b, 0xaf, 0x50, 0xb2, 0xf0, 0x34, 0xf0, 0xa4, 0x0c, 0x24,
	  0x95, 0x79, 0xc2, 0x33, 0x96, 0xa1, 0x1e, 0xf4, 0x0c, 0xad, 0x41, 0x49,
	  0xc5, 0x2f, 0xd8, 0xc1, 0x74, 0x5c, 0xc7, 0xc4, 0x24, 0x81, 0x00, 0x00,
	  0x00, 0x00, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82
	};
	unsigned int ___Ample_images_mouse_off_png_len = 598;

	NSImage *img;
	NSData *data;

	data = [NSData dataWithBytesNoCopy: ___Ample_images_mouse_off_png length: ___Ample_images_mouse_off_png_len freeWhenDone: NO];
	img = [[NSImage alloc] initWithData: data];
	[img setSize: NSMakeSize(24, 24)];
	[img setTemplate: YES];

	return [img autorelease];
}

-(void)buildTouchBar {

	if (@available(macOS 10.12.2, *)) {

		NSMutableArray *buttons = [NSMutableArray new];

		NSTouchBar *tb = [NSTouchBar new];
		[tb setDefaultItemIdentifiers: @[@"mame.pause", @"mame.ff", @"mame.mouse", @"mame.fullscreen", @"mame.mute"]];

		NSMutableSet *templates = [NSMutableSet set];
		NSCustomTouchBarItem *item;
		NSButton *button;

		button = [NSButton buttonWithTitle: @"Pause" target: self action: @selector(togglePause:)];
		[button setTag: kTagPause];
		[button setButtonType: NSButtonTypeToggle];
		[button setImage: [NSImage imageNamed: NSImageNameTouchBarPauseTemplate]];
		[button setAlternateImage: [NSImage imageNamed: NSImageNameTouchBarPlayTemplate]];
		[buttons addObject: button];

		item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.pause"];
		[item setCustomizationLabel: @"Pause"];
		[item setView: button];
		[templates addObject: item];
		[item release];


		// NSTouchBarFastForwardTemplate
		button = [FFButton buttonWithTitle: @"Fast Forward" target: self action: @selector(tbFastForward:)];
		[button setTag: kTagFastForward];
		[button setImage: [NSImage imageNamed: NSImageNameTouchBarFastForwardTemplate]];

		[button sendActionOn: NSLeftMouseDownMask|NSLeftMouseUpMask];
		[buttons addObject: button];

		item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.ff"];
		[item setCustomizationLabel: @"Fast Forward"];
		[item setView: button];
		[templates addObject: item];
		[item release];


		// NSTouchBarEnterFullScreenTemplate / NSTouchBarExitFullScreenTemplate ...
		button = [NSButton buttonWithTitle: @"Full Screen" target: self action: @selector(toggleFullScreen:)];
		[button setTag: kTagFullScreen];
		[button setButtonType: NSButtonTypeToggle];
		[button setImage: [NSImage imageNamed: NSImageNameTouchBarEnterFullScreenTemplate]];
		[button setAlternateImage: [NSImage imageNamed: NSImageNameTouchBarExitFullScreenTemplate]];
		[buttons addObject: button];

		item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.fullscreen"];
		[item setCustomizationLabel: @"Fullscreen"];
		[item setView: button];
		[templates addObject: item];
		[item release];


		// NSTouchBarAudioOutputMuteTemplate / NSTouchBarAudioOutputVolumeHighTemplate
		button = [NSButton buttonWithTitle: @"Mute" target: self action: @selector(toggleMute:)];
		[button setTag: kTagMute];
		[button setButtonType: NSButtonTypeToggle];
		[button setImage: [NSImage imageNamed: NSImageNameTouchBarAudioOutputMuteTemplate]];
		[button setAlternateImage: [NSImage imageNamed: NSImageNameTouchBarAudioOutputVolumeHighTemplate]];
		[buttons addObject: button];

		item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.mute"];
		[item setCustomizationLabel: @"Mute"];
		[item setView: button];
		[templates addObject: item];
		[item release];


		button = [NSButton buttonWithTitle: @"Mouse" target: self action: @selector(toggleMouse:)];
		[button setTag: kTagMouse];
		[button setButtonType: NSButtonTypeToggle];
		[button setImage: MouseOnImage()];
		[button setAlternateImage: MouseOffImage()];

		[buttons addObject: button];

		item = [[NSCustomTouchBarItem alloc] initWithIdentifier: @"mame.mouse"];
		[item setCustomizationLabel: @"Mouse Capture"];
		[item setView: button];
		[templates addObject: item];
		[item release];


		_touchBarButtons = buttons;
		[tb setTemplateItems: templates];
		[NSApp setTouchBar: tb];
		[NSApp setAutomaticCustomizeTouchBarMenuItemEnabled: YES];
		[tb release];

		NSTimer *t = [NSTimer scheduledTimerWithTimeInterval: 10.0 target: self selector: @selector(updateButtons) userInfo: nil repeats: YES];
		[t setTolerance: 5.0];

		_timer = [t retain];

	}
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
			std::printf("%s: %s\n", port_name, pty.slave_name().c_str());
	}

}


#endif
