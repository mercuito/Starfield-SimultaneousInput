#include "Plugin.h"
#include "RE/Offset.Ext.h"

// libxse/CommonLibSF surface. The umbrella SFSE/SFSE.h pulls in PCH (which
// includes REL::, REX::, and the SFSE/RE namespaces), API, Interfaces, Logger,
// Trampoline, and Version, which is everything we need for a hook plugin.
#include "SFSE/SFSE.h"

#include "REL/Pattern.h"
#include "REL/Relocation.h"

#include "REX/LOG.h"

#include "RE/B/BSFixedString.h"
#include "RE/B/BSInputEventUser.h"

#include <atomic>
#include <exception>
#include <source_location>
#include <utility>

using namespace std::string_view_literals;

#define DLLEXPORT __declspec(dllexport)
#define SFSEAPI   __cdecl

namespace
{
	// Counted number of hooks installed; surfaced in startup log so a runtime
	// mismatch is debuggable from the plugin log alone (no need to attach a
	// debugger).
	std::atomic<unsigned> g_hooksInstalled{ 0 };
	std::atomic<unsigned> g_hooksSkipped{ 0 };
}

extern "C" DLLEXPORT constinit auto SFSEPlugin_Version = []() {
	SFSE::PluginVersionData v{};
	v.PluginVersion(Plugin::VERSION);
	v.PluginName(Plugin::NAME);

	// Original author. Maintained fork credit lives in the README and version
	// resource.
	v.AuthorName("Parapets");

	// We resolve all engine functions through the Address Library at runtime,
	// so we want SFSE to grant load on any runtime the AL DB covers.
	// libxse/CommonLibSF's UsesAddressLibrary() sets bit 1<<2 (Address Library
	// v2), which SFSE 0.2.17+ requires for plugin loads to be accepted on
	// Starfield 1.10.31+ runtimes (per sfse_whatsnew.txt). Validated on
	// Starfield 1.16.236 + SFSE 0.2.19: without the v2 bit SFSE silently hangs
	// the in-process LoadLibrary on the plugin and never logs the rejection;
	// with the v2 bit set SFSE writes "loaded correctly".
	v.UsesAddressLibrary(true);

	// We touch engine struct layouts (vtable slot 1, BSPCGamepadDevice +0x2A0,
	// LookHandler::Func10 +0xE, etc.). IsLayoutDependent() in libxse sets bit
	// 1<<3, which SFSE reads as "compatible with runtime 1.14.70+ struct
	// layout". Builds against the old fork (f2ea130) set 1<<2 (1.8.86 layout),
	// which is why SFSE 0.2.19 rejected the prior DLL on Starfield 1.14+.
	v.IsLayoutDependent(true);

	// Empty compatibleVersions[] (zero-terminated) means "any runtime that
	// satisfies the address/layout flags above". We deliberately do NOT pin a
	// version here so future Steam patches don't auto-disable the plugin; if a
	// future runtime breaks layout, SFSE will reject us via the layout bit
	// instead.
	return v;
}();

namespace RE
{
	// Forward decls so we can reference these as opaque pointer types in our
	// hook signatures without depending on libxse modeling either class. The
	// LookHandler vtable shim and the IsUsingGamepad() trampoline only ever
	// see these as raw `Cls*` arguments.
	class BSInputDeviceManager;

	namespace PlayerControls
	{
		class LookHandler;
	}
}

// Original engine predicate: returns true when the active input device is the
// gamepad.
bool IsUsingGamepad(RE::BSInputDeviceManager* a_inputDeviceManager)
{
	using func_t = decltype(IsUsingGamepad);
	REL::Relocation<func_t> func{ RE::Offset::BSInputDeviceManager::IsUsingGamepad };
	return func(a_inputDeviceManager);
}

// Latched state set by the LookHandler vtable shim below. True when the most
// recent QLook event came from a thumbstick; false when it came from MouseMove.
// This is the core of the mod: the engine treats look input as a single-source
// stream, but we split it on event type so mouse and gamepad coexist.
static bool UsingThumbstickLook = false;

// Drop-in replacement for IsUsingGamepad in look-related call sites. The
// original engine code uses "is current device the gamepad" to switch
// sensitivity curves, quadrant-fix, and window-cursor capture. For our
// purposes those code paths should key off "is the user currently looking
// with the stick", not "did the user touch the stick at all".
bool IsUsingThumbstickLook(RE::BSInputDeviceManager*)
{
	return UsingThumbstickLook;
}

// For cursor visibility/style hooks: the cursor should follow the gamepad
// rules only when both (a) we're in thumbstick-look mode and (b) gamepad is
// the currently-held active device. Mouse + gamepad held simultaneously falls
// through to mouse cursor handling.
bool IsGamepadCursor(RE::BSInputDeviceManager* a_inputDeviceManager)
{
	return UsingThumbstickLook && IsUsingGamepad(a_inputDeviceManager);
}

namespace
{
	// Wraps a single trampoline call-site replacement so a single broken AL ID
	// or pattern mismatch logs and skips that hook, instead of crashing the
	// whole plugin load. The original code used REL::Pattern<...>().match_or_fail(),
	// which calls REX::FAIL (terminate the host). That made every Starfield
	// patch a hard-fail. With granular logging we still get a clear diagnostic
	// in the plugin log but other hooks continue to install.
	template <std::size_t N, class F>
	bool TryWriteCall(
		const REL::ID&              a_id,
		std::ptrdiff_t              a_offset,
		F                           a_dst,
		std::string_view            a_label,
		const std::source_location& a_loc = std::source_location::current())
	{
		try {
			REL::Relocation<std::uintptr_t> hook(a_id, a_offset);
			if (!REL::Pattern<"E8">().match(hook.address())) {
				REX::WARN(
					"hook '{}' skipped: AL id {} (rva {:#x}) +{:#x} did not start with "
					"E8 (call). function was refactored on this runtime; see MAINTAINING.md "
					"section 7 for the per-hook 1.16.236 derivation status.",
					a_label,
					a_id.id(),
					a_id.offset(),
					a_offset);
				++g_hooksSkipped;
				return false;
			}
			REL::GetTrampoline().write_call<N>(hook.address(), a_dst);
			REX::INFO(
				"hook '{}' installed: AL id {} (rva {:#x}) +{:#x} -> {:#x}",
				a_label,
				a_id.id(),
				a_id.offset(),
				a_offset,
				hook.address());
			++g_hooksInstalled;
			return true;
		} catch (const std::exception& ex) {
			REX::ERROR(
				"hook '{}' failed: {} (at {}:{})",
				a_label,
				ex.what(),
				a_loc.file_name(),
				a_loc.line());
			++g_hooksSkipped;
			return false;
		}
	}

	void LogRuntimeProbe(const SFSE::LoadInterface* a_sfse)
	{
		const auto runtimeVer = a_sfse->RuntimeVersion();
		const auto sfseVer = REL::Version::unpack(a_sfse->SFSEVersion());

		REX::INFO(
			"{} v{} (build {} {})",
			Plugin::NAME,
			Plugin::VERSION.string("."sv),
			Plugin::BUILD_SHA,
			Plugin::BUILD_DATE);

		REX::INFO(
			"SFSE {} loaded against Starfield runtime {}",
			sfseVer.string("."sv),
			runtimeVer.string("."sv));

		// Highest runtime CommonLibSF advertises support for. Out-of-range is
		// not a hard failure (AL IDs are evaluated at runtime against the
		// installed AL DB), but it's a useful signal in the log.
		constexpr auto knownLatest = SFSE::RUNTIME_LATEST;
		if (runtimeVer > knownLatest) {
			REX::WARN(
				"runtime {} is newer than the latest tested ({}). "
				"hooks will still be attempted; if any fail look for "
				"'hook ... skipped' lines below.",
				runtimeVer.string("."sv),
				knownLatest.string("."sv));
		}
	}
}

extern "C" DLLEXPORT bool SFSEAPI SFSEPlugin_Load(const SFSE::LoadInterface* a_sfse)
{
	// libxse's SFSE::Init does spdlog setup itself when InitInfo.log is true,
	// and (when trampoline=true) reserves trampoline space from SFSE's
	// branch pool, falling back to a self-allocated trampoline.
	//
	// Trampoline budget: 28 bytes = 5 (write_call) per replacement, rounded
	// up. We install 7 trampoline calls below; 5 * 7 = 35, but several share
	// targets and the trampoline only needs unique 5-byte stubs per call
	// site, so 28 is enough. Bump this if we add hooks. We deliberately use
	// the InitInfo path instead of the deprecated SFSE::AllocTrampoline to
	// stay /WX-clean (C4996 with the prior call).
	//
	// Logs land in %USERPROFILE%/Documents/My Games/Starfield/SFSE/Logs/
	// SimultaneousInput.log, the same dir SFSE writes sfse.log, so users
	// get one consolidated log folder.
	SFSE::Init(a_sfse, SFSE::InitInfo{
		.trampoline = true,
		.trampolineSize = 28,
	});
	LogRuntimeProbe(a_sfse);

	// === Vtable shim: split look input by event type ===
	// LookHandler vtable slot 1 is the per-event handler. We replace it with a
	// closure that latches UsingThumbstickLook based on event type, and only
	// returns true when the event is actually a look event. Without this the
	// engine collapses mouse + gamepad into a single "current device" channel.
	try {
		REL::Relocation<std::uintptr_t> vtbl(RE::Offset::PlayerControls::LookHandler::Vtbl);
		vtbl.write_vfunc(
			1,
			+[](RE::PlayerControls::LookHandler*, RE::InputEvent* event) -> bool {
				// QUserEvent() returns the user-event name as a BSFixedString;
				// "Look" is the canonical look-input name. The old code went
				// through RE::UserEvents::QLook() (an AL-id-resolved function
				// returning the same string), which libxse does not surface;
				// the literal compare is functionally identical and avoids the
				// extra runtime lookup.
				if (event->QUserEvent() != "Look"sv) {
					return false;
				}
				if (event->eventType == RE::InputEvent::EventType::kMouseMove) {
					UsingThumbstickLook = false;
				} else if (event->eventType == RE::InputEvent::EventType::kThumbstick) {
					UsingThumbstickLook = true;
				}
				return true;
			});
		REX::INFO("vtable shim installed: LookHandler slot 1");
		++g_hooksInstalled;
	} catch (const std::exception& ex) {
		REX::ERROR("vtable shim failed: {}", ex.what());
		++g_hooksSkipped;
	}

	// === Direct byte patch: stop left-stick from claiming the device ===
	// Inside BSPCGamepadDevice::Poll at +0x2A0 the engine writes 1 to a byte
	// indicating "left stick moved -> active device is gamepad". We NOP the
	// 4-byte store so simply moving the stick doesn't kick the cursor.
	// Pattern: C6 43 08 01  (mov byte ptr [rbx+8], 1)
	try {
		REL::Relocation<std::uintptr_t> hook(RE::Offset::BSPCGamepadDevice::Poll, 0x2A0);
		if (REL::Pattern<"C6 43 08 01">().match(hook.address())) {
			hook.write_fill(REL::NOP, 0x4);
			REX::INFO("byte patch installed: BSPCGamepadDevice::Poll +0x2A0");
			++g_hooksInstalled;
		} else {
			REX::WARN(
				"byte patch skipped: BSPCGamepadDevice::Poll AL id {} (rva {:#x}) +0x2A0 "
				"pattern 'C6 43 08 01' not found on this runtime; Poll body refactored. "
				"left thumbstick will still device-switch. see MAINTAINING.md section 7.",
				RE::Offset::BSPCGamepadDevice::Poll.id(),
				RE::Offset::BSPCGamepadDevice::Poll.offset());
			++g_hooksSkipped;
		}
	} catch (const std::exception& ex) {
		REX::ERROR("BSPCGamepadDevice::Poll patch failed: {}", ex.what());
		++g_hooksSkipped;
	}

	// === Look-input call replacements (predicate IsUsingGamepad -> IsUsingThumbstickLook) ===
	TryWriteCall<5>(
		RE::Offset::PlayerControls::LookHandler::Func10, 0xE,
		IsUsingThumbstickLook,
		"LookHandler::Func10 (2-quadrant slow-movement fix)");

	TryWriteCall<5>(
		RE::Offset::PlayerControls::Manager::ProcessLookInput, 0x68,
		IsUsingThumbstickLook,
		"PlayerControls::Manager::ProcessLookInput (look sensitivity)");

	TryWriteCall<5>(
		RE::Offset::Main::Run_WindowsMessageLoop, 0x39,
		IsUsingThumbstickLook,
		"Main::Run_WindowsMessageLoop (cursor window-capture)");

	TryWriteCall<5>(
		RE::Offset::ShipHudDataModel::PerformInputProcessing, 0x7AF,
		IsUsingThumbstickLook,
		"ShipHudDataModel::PerformInputProcessing+0x7AF (ship reticle)");

	TryWriteCall<5>(
		RE::Offset::ShipHudDataModel::PerformInputProcessing, 0x82A,
		IsUsingThumbstickLook,
		"ShipHudDataModel::PerformInputProcessing+0x82A (ship reticle)");

	// === Cursor visibility/style call replacements (-> IsGamepadCursor) ===
	TryWriteCall<5>(
		RE::Offset::IMenu::ShowCursor, 0x14,
		IsGamepadCursor,
		"IMenu::ShowCursor (menu cursor visibility)");

	TryWriteCall<5>(
		RE::Offset::UI::SetCursorStyle, 0x98,
		IsGamepadCursor,
		"UI::SetCursorStyle (pointer vs gamepad cursor)");

	const auto installed = g_hooksInstalled.load();
	const auto skipped = g_hooksSkipped.load();
	if (skipped == 0) {
		REX::INFO("all {} hooks installed", installed);
	} else {
		REX::WARN(
			"{}/{} hooks installed, {} skipped. plugin will run with reduced behavior.",
			installed,
			installed + skipped,
			skipped);
	}

	// We always return true: even if some hooks failed, partial functionality
	// is better than refusing to load. Logged warnings tell the user what's
	// off.
	return true;
}
