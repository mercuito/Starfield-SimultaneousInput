#pragma once

#include "REL/Relocation.h"

// Address Library IDs the plugin hooks. IDs were originally captured against
// Starfield 1.8.86 by Parapets. They remain valid for any subsequent runtime
// where Bethesda did not refactor the underlying function: the AL DB shipped
// alongside each game patch maps the same ID to the new offset.
//
// Verifying these IDs against a fresh runtime requires the Address Library
// database file for that runtime (versionlib-1-15-216.bin or similar). That
// file is not in this repo. The plugin treats each hook as best-effort at
// load time (see SFSEPlugin.cpp): if an ID resolves to code that no longer
// matches the expected byte pattern, that hook is skipped with a logged
// warning instead of crashing the host.
namespace RE
{
	namespace Offset
	{
		// Predicate: bool IsUsingGamepad(BSInputDeviceManager*).
		// Used as the call target in the look/cursor patches; we substitute
		// our own predicates by rewriting those E8 call instructions.
		namespace BSInputDeviceManager
		{
			constexpr REL::ID IsUsingGamepad{ 178879 };
		}

		// BSPCGamepadDevice::Poll. We NOP a single mov byte ptr [rbx+8], 1
		// (4 bytes at +0x2A0) so that left-stick movement no longer flags
		// the active device as gamepad.
		namespace BSPCGamepadDevice
		{
			constexpr REL::ID Poll{ 179249 };
		}

		// IMenu::ShowCursor. Call at +0x14 decides whether to draw the
		// gamepad-style cursor for menus; we redirect it to IsGamepadCursor
		// so mouse + gamepad held simultaneously still shows the mouse cursor.
		namespace IMenu
		{
			constexpr REL::ID ShowCursor{ 187256 };
		}

		// Main::Run_WindowsMessageLoop. Call at +0x39 governs window cursor
		// capture; we redirect to IsUsingThumbstickLook so the OS cursor is
		// only confined to the window when the user is actually doing
		// thumbstick look (not just because a controller is plugged in).
		namespace Main
		{
			constexpr REL::ID Run_WindowsMessageLoop{ 149028 };
		}

		// PlayerControls::LookHandler. Vtbl is the class vtable; slot 1 is
		// the per-event entry point we replace with a shim that splits look
		// input by event type. Func10 +0xE is a call that gates a slow-
		// movement-on-2-quadrants behavior.
		namespace PlayerControls
		{
			namespace LookHandler
			{
				constexpr REL::ID Vtbl{ 407288 };
				constexpr REL::ID Func10{ 129152 };
			}

			// ProcessLookInput +0x68 selects the sensitivity curve based on
			// device. We redirect to IsUsingThumbstickLook so each device
			// keeps its own tuned sensitivity instead of the active-device
			// curve overriding both.
			namespace Manager
			{
				constexpr REL::ID ProcessLookInput{ 129407 };
			}
		}

		// ShipHudDataModel::PerformInputProcessing has two call sites
		// (+0x7AF and +0x82A) that branch ship-reticle behavior on input
		// device. Same redirect to IsUsingThumbstickLook.
		namespace ShipHudDataModel
		{
			constexpr REL::ID PerformInputProcessing{ 137087 };
		}

		// UI::SetCursorStyle +0x98: pick pointer-style vs gamepad-style.
		// Same IsGamepadCursor redirect as IMenu::ShowCursor.
		namespace UI
		{
			constexpr REL::ID SetCursorStyle{ 187051 };
		}

		// UserEvents::QLook used to be looked up via AL ID and called to get
		// the BSFixedString "Look". libxse/CommonLibSF doesn't surface
		// RE::UserEvents, so we compare event->QUserEvent() directly against
		// "Look"sv in SFSEPlugin.cpp instead. The function still exists in the
		// runtime, we just don't need to call it ourselves.
	}
}
