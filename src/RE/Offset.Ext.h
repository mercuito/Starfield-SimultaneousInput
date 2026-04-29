#pragma once

#include "REL/Relocation.h"

// Address Library IDs and in-function offsets used by the SimultaneousInput
// hook plugin. The original table was captured by Parapets against Starfield
// 1.8.86. Bethesda has since refactored several of the hosting functions on
// 1.16.236, so the table here records the post-refactor IDs and offsets
// derived via tools/derive_function_ids.py with --exe Starfield.exe and
// --db versionlib-1-16-236-0.bin. See MAINTAINING.md section 7 for the
// per-hook derivation status, and tools/derived_1.16.236.json for the
// raw E8-destination dump backing every offset choice.
//
// The plugin treats each hook as best-effort at load time (see
// SFSEPlugin.cpp): if an ID resolves to code that no longer matches the
// expected byte pattern, that hook is skipped with a logged warning instead
// of crashing the host.
namespace RE
{
	namespace Offset
	{
		// Predicate: bool IsUsingGamepad(BSInputDeviceManager*).
		//
		// Earlier tooling treated RVA 0x28cef30 (AL 139340) as the
		// 1.16.236 look predicate because it was called from several
		// input host bodies. IDA verification later showed it is
		// BSStringPool-style refcount cleanup code, not IsUsingGamepad.
		// Keep this ID only as a historical marker; SFSEPlugin.cpp does not
		// dispatch through it or rewrite calls that target it.
		//
		// Was 178879 (Parapets, 1.8.86). On 1.16.236 that ID resolves to a
		// debug log stub at 0x3552490 (TLS singleton accessor + format/log
		// path), not the predicate. Re-derived as the destination shared by
		// 4 of 6 input-related host bodies via
		// tools/derive_function_ids.py.
		namespace BSInputDeviceManager
		{
			constexpr REL::ID IsUsingGamepad{ 139340 };
		}

		// BSPCGamepadDevice poll/update paths. We NOP direct
		// mov byte ptr [rbx+8], 1 writes so stick movement no longer forces
		// the active device to gamepad. Pattern: C6 43 08 01.
		//
		// Was 179249 (Parapets, 1.8.86). On 1.16.236 that ID resolves to a
		// 42-byte thunk at 0x356e720 with no anchor pattern. The real Poll
		// in 1.16.236 is at vtable[470133][1] = RVA 0x2302bc0, which is AL
		// ID 124384, with anchors at offsets +0x51d and +0x5dc.
		//
		// IDA also shows an adjacent extended poll/update path at
		// RVA 0x2302390 with the same active-device writes at +0x409 and
		// +0x4a8. This path is not currently mapped to an Address Library ID
		// in the local metadata, so keep it as an RVA offset.
		namespace BSPCGamepadDevice
		{
			constexpr REL::ID Poll{ 124384 };
			constexpr REL::Offset ExtendedPoll{ 0x2302390 };
		}

		// IMenu::ShowCursor. Original Parapets +0x14 hook redirected the
		// menu's gamepad-cursor decision to IsGamepadCursor.
		//
		// AL 187256 still resolves to IMenu::ShowCursor on 1.16.236
		// (RVA 0x37d31f0). The function body has 7 calls to the cursor
		// predicate 0x2c4b50; the first one at +0xa1 is the analog of the
		// original +0x14 anchor.
		//
		// Note: an earlier session mistakenly migrated this to AL 42816
		// based on a libxse vtable table read. AL 42816 resolves to a tiny
		// 8-byte getter (lea rax, [rcx+0x98]; ret) that has an E8 byte at
		// +0x14 only because the scan crossed into the next function in
		// the .text padding. Reverting to 187256 with the new derived
		// offset is correct.
		namespace IMenu
		{
			constexpr REL::ID ShowCursor{ 187256 };
		}

		// Main::Run_WindowsMessageLoop. Original +0x39 hook redirected an
		// IsUsingGamepad call gating window-cursor capture.
		//
		// On 1.16.236 the function (AL 149028, RVA 0x2c803b0) is ~24 KB
		// long and contains 775 E8 calls, NONE of which target either
		// predicate variant (look 0x28cef30 or cursor 0x2c4b50). The
		// cursor-capture predicate call has been refactored away,
		// presumably inlined into the message handler or moved to a
		// different function. We retain the AL ID for diagnostic purposes
		// but the corresponding TryWriteCall in SFSEPlugin.cpp has been
		// removed; the runtime impact is that the OS cursor may be
		// confined to the window whenever a gamepad is plugged in, which
		// is the engine's default behavior. See MAINTAINING.md section 7.
		namespace Main
		{
			constexpr REL::ID Run_WindowsMessageLoop{ 149028 };
		}

		// PlayerControls::LookHandler. Vtbl is the class vtable; slot 1 is
		// the per-event entry point we replace with a shim that splits look
		// input by event type. Func10 is gated on IsUsingGamepad to enable
		// the slow-movement-on-2-quadrants behavior.
		//
		// Vtbl was 407288 (Parapets, 1.8.86). On 1.16.236 that ID resolves
		// to a non-vtable address; write_vfunc(1, ...) silently overwrites
		// slot 1 of whatever struct lives there. The libxse-canonical value
		// for 1.16.236, sourced from
		// external/CommonLibSF/include/RE/IDs_VTABLE.h, is 433589.
		//
		// Func10 was originally hooked at +0xE on 1.8.86. On 1.16.236 the
		// previous +0x196 candidate targets RVA 0x28cef30. IDA verification
		// showed that target is refcount cleanup code, not a gamepad
		// predicate, so SFSEPlugin.cpp no longer rewrites this call site.
		namespace PlayerControls
		{
			namespace LookHandler
			{
				constexpr REL::ID Vtbl{ 433589 };
				constexpr REL::ID Func10{ 129152 };
			}

			// ProcessLookInput +0x68 originally selected the sensitivity
			// curve based on device. On 1.16.236 this AL ID resolves to a
			// 12-byte public thunk:
			//   mov rdx, rcx; mov rcx, [rcx+58h]; jmp sub_1424E9F20
			// The earlier 129407+0x33F candidate crossed into neighboring
			// sub_1424E6620, and the later absolute RVA experiment still
			// targeted non-predicate code. SFSEPlugin.cpp leaves this call
			// site untouched and relies on the byte_145F67820 event mirror.
			namespace Manager
			{
				constexpr REL::ID ProcessLookInput{ 129407 };
			}
		}

		// ShipHudDataModel::PerformInputProcessing. Originally had two
		// call sites at +0x7AF and +0x82A that branch ship-reticle
		// behavior on input device. The 1.16.236 +0x2C7/+0x2E4 candidates
		// target the same non-predicate cleanup routine as Func10, so the
		// plugin currently leaves them untouched.
		namespace ShipHudDataModel
		{
			constexpr REL::ID PerformInputProcessing{ 137087 };
		}

		// UI::SetCursorStyle. Originally +0x98 picked pointer-style vs
		// gamepad-style. On 1.16.236 the host body (AL 187051,
		// RVA 0x37c3b00) has 11 calls to the cursor predicate 0x2c4b50,
		// the first at +0x4ce. Same IsGamepadCursor redirect.
		namespace UI
		{
			constexpr REL::ID SetCursorStyle{ 187051 };
		}

		// UserEvents::QLook used to be looked up via AL ID and called to
		// get the BSFixedString "Look". libxse/CommonLibSF doesn't surface
		// RE::UserEvents, so we compare event->QUserEvent() directly
		// against "Look"sv in SFSEPlugin.cpp instead.
	}
}
