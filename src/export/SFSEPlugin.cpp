#include "Plugin.h"
#include "RE/Offset.Ext.h"

#include "REL/ID.h"
#include "REL/Pattern.h"
#include "REL/Relocation.h"
#include "REL/Trampoline.h"
#include "REL/Utility.h"
#include "REX/LOG.h"

#include "SFSE/API.h"
#include "SFSE/Interfaces.h"
#include "SFSE/Version.h"

#include "RE/B/BSFixedString.h"
#include "RE/MouseMoveEvent.h"
#include "RE/UserEvents.h"

#include <atomic>
#include <source_location>

using namespace std::string_view_literals;

#define DLLEXPORT __declspec(dllexport)

namespace
{
	// Counted hooks installed; surfaced in startup log so a runtime mismatch
	// is debuggable from SimultaneousInput.log alone.
	std::atomic<unsigned> g_hooksInstalled{ 0 };
	std::atomic<unsigned> g_hooksSkipped{ 0 };
}

extern "C" DLLEXPORT constexpr auto SFSEPlugin_Version = []()
{
	SFSE::PluginVersionData v{};

	v.PluginVersion(Plugin::VERSION);
	v.PluginName(Plugin::NAME);
	// Original author. Maintained fork credit lives in the README and version resource.
	v.AuthorName("Parapets");

	// libxse's UsesAddressLibrary already sets bit 1<<2 (Address Library v2),
	// which SFSE 0.2.17+ requires. Address Library DB format 5 (Starfield 1.15+)
	// is parsed by libxse's IDDB::load_v5; format 2 binaries are also supported.
	v.UsesAddressLibrary(true);

	// We patch engine struct layouts (vtable slot 1, BSPCGamepadDevice +0x2A0,
	// LookHandler::Func10 +0xE, etc.). Bit 1<<3 = "compatible with runtime
	// 1.14.70+ struct layout" per SFSE 0.2.17+.
	v.IsLayoutDependent(true);

	// Empty compatibleVersions[] (zero-terminated) means "any runtime that
	// satisfies the address/layout flags above". Future Steam patches do not
	// auto-disable the plugin; if a future runtime breaks layout SFSE will
	// reject via the layout bit instead.
	return v;
}();

namespace RE
{
	class BSInputDeviceManager;

	namespace PlayerControls
	{
		class LookHandler;
	}
}

// Original engine predicate: returns true when the active input device is the gamepad.
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

// Drop-in replacement for IsUsingGamepad in look-related call sites.
bool IsUsingThumbstickLook(RE::BSInputDeviceManager*)
{
	return UsingThumbstickLook;
}

// For cursor visibility/style hooks: cursor follows gamepad rules only when
// thumbstick-look mode is active AND gamepad is the currently-held device.
bool IsGamepadCursor(RE::BSInputDeviceManager* a_inputDeviceManager)
{
	return UsingThumbstickLook && IsUsingGamepad(a_inputDeviceManager);
}

namespace
{
	// Wraps a single trampoline call-site replacement so a single broken AL ID
	// or pattern mismatch logs and skips that hook, instead of crashing the
	// whole plugin load. Original upstream used REL::Pattern<...>().match_or_fail()
	// which terminates the host. With granular logging we still get a clear
	// diagnostic in the log file but other hooks continue to install.
	template <std::size_t N, class F>
	bool TryWriteCall(
		const REL::ID&   a_id,
		std::ptrdiff_t   a_offset,
		F                a_dst,
		std::string_view a_label)
	{
		try {
			REL::Relocation<std::uintptr_t> hook(a_id, a_offset);
			if (!REL::Pattern<"E8">().match(hook.address())) {
				REX::WARN(
					"hook '{}' skipped: AL id {} +{:#x} did not start with E8 (call). "
					"function may have been refactored on this runtime.",
					a_label,
					a_id.id(),
					a_offset);
				++g_hooksSkipped;
				return false;
			}
			REL::GetTrampoline().write_call<N>(hook.address(), a_dst);
			REX::INFO("hook '{}' installed at {:#x}", a_label, hook.address());
			++g_hooksInstalled;
			return true;
		} catch (const std::exception& ex) {
			REX::ERROR("hook '{}' failed: {}", a_label, ex.what());
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
	}
}

extern "C" DLLEXPORT bool __cdecl SFSEPlugin_Load(const SFSE::LoadInterface* a_sfse)
{
	// libxse's SFSE::Init handles logger setup (REX::INFO/WARN/ERROR backed by
	// spdlog) and trampoline allocation in one call. trampolineSize=28 covers
	// 7 trampoline call replacements at 5 bytes each (with reuse).
	SFSE::Init(a_sfse, SFSE::InitInfo{
		.log = true,
		.logName = "SimultaneousInput",
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
			+[](RE::PlayerControls::LookHandler*, RE::InputEvent* event) -> bool
			{
				if (RE::UserEvents::QLook() != event->QUserEvent()) {
					return false;
				}

				if (event->eventType == RE::INPUT_EVENT_TYPE::MouseMove) {
					UsingThumbstickLook = false;
				} else if (event->eventType == RE::INPUT_EVENT_TYPE::Thumbstick) {
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
	// Inside BSPCGamepadDevice::Poll at +0x2A0 the engine writes 1 to a
	// byte indicating "left stick moved -> active device is gamepad". We NOP
	// the 4-byte store so simply moving the stick does not kick the cursor.
	// Pattern: C6 43 08 01  (mov byte ptr [rbx+8], 1)
	try {
		REL::Relocation<std::uintptr_t> hook(RE::Offset::BSPCGamepadDevice::Poll, 0x2A0);
		if (REL::Pattern<"C6 43 08 01">().match(hook.address())) {
			REL::WriteSafeFill(hook.address(), REL::NOP, 0x4);
			REX::INFO("byte patch installed: BSPCGamepadDevice::Poll +0x2A0");
			++g_hooksInstalled;
		} else {
			REX::WARN(
				"byte patch skipped: BSPCGamepadDevice::Poll +0x2A0 pattern mismatch. "
				"left thumbstick will still device-switch on this runtime.");
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

	return true;
}
