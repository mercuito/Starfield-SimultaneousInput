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
#include <cstdint>
#include <cstring>

using namespace std::string_view_literals;

#define DLLEXPORT __declspec(dllexport)

namespace
{
	std::atomic<unsigned> g_hooksInstalled{ 0 };
	std::atomic<unsigned> g_hooksSkipped{ 0 };
}

extern "C" DLLEXPORT constexpr auto SFSEPlugin_Version = []()
{
	SFSE::PluginVersionData v{};

	v.PluginVersion(Plugin::VERSION);
	v.PluginName(Plugin::NAME);
	v.AuthorName("Parapets");

	// libxse's UsesAddressLibrary sets bit 1<<2 (Address Library v2),
	// the only flag SFSE 0.2.17+ honors. Format 5 AL DB parsed by libxse IDDB.
	v.UsesAddressLibrary(true);
	v.IsLayoutDependent(true);
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

bool IsUsingGamepad(RE::BSInputDeviceManager* a_inputDeviceManager)
{
	using func_t = decltype(IsUsingGamepad);
	REL::Relocation<func_t> func{ RE::Offset::BSInputDeviceManager::IsUsingGamepad };
	return func(a_inputDeviceManager);
}

static bool UsingThumbstickLook = false;

bool IsUsingThumbstickLook(RE::BSInputDeviceManager*)
{
	return UsingThumbstickLook;
}

bool IsGamepadCursor(RE::BSInputDeviceManager* a_inputDeviceManager)
{
	return UsingThumbstickLook && IsUsingGamepad(a_inputDeviceManager);
}

namespace
{
	// === Dynamic call-site discovery ===
	// The original upstream plugin patched hard-coded byte offsets within each
	// hooked function (e.g., LookHandler::Func10 +0xE). When Bethesda recompiles
	// the engine those offsets shift. Rather than relying on fixed offsets we
	// scan the function body looking for an `E8 RR RR RR RR` call instruction
	// whose 4-byte rel32 displacement resolves to the address we want to
	// replace. This survives compiler reorderings and instruction shifts as
	// long as the call is still in the function.
	//
	// MAX_SCAN bounds how far we scan. 0x800 (2 KB) is far larger than any of
	// the hooked functions need but bounds the worst case so we do not run off
	// into adjacent code.
	constexpr std::ptrdiff_t MAX_SCAN = 0x800;

	// Find the byte offset of the first `E8` call in the function whose target
	// matches a_callTarget, scanning up to MAX_SCAN bytes. Returns -1 on miss.
	std::ptrdiff_t FindCallOffset(const std::uintptr_t a_funcStart, const std::uintptr_t a_callTarget)
	{
		const auto* const bytes = reinterpret_cast<const std::uint8_t*>(a_funcStart);
		for (std::ptrdiff_t i = 0; i < MAX_SCAN; ++i) {
			if (bytes[i] != 0xE8) continue;
			std::int32_t rel32{};
			std::memcpy(&rel32, bytes + i + 1, sizeof(rel32));
			const auto target = static_cast<std::uintptr_t>(
				static_cast<std::int64_t>(a_funcStart + i + 5) + rel32);
			if (target == a_callTarget) {
				return i;
			}
		}
		return -1;
	}

	// Replace the first E8 call to a_replaceTarget inside a_funcId's body with
	// a call to a_newTarget via the trampoline. Logs and skips on miss.
	template <class F>
	void TryReplaceCall(
		const REL::ID&    a_funcId,
		std::uintptr_t    a_replaceTarget,
		F                 a_newTarget,
		std::string_view  a_label)
	{
		try {
			const auto funcStart = a_funcId.address();
			const auto offset = FindCallOffset(funcStart, a_replaceTarget);
			if (offset < 0) {
				REX::WARN(
					"hook '{}' skipped: no E8 call to target {:#x} found in first {} "
					"bytes of AL id {} (function may have been refactored).",
					a_label, a_replaceTarget, MAX_SCAN, a_funcId.id());
				++g_hooksSkipped;
				return;
			}
			const auto callAddr = funcStart + offset;
			REL::GetTrampoline().write_call<5>(callAddr, a_newTarget);
			REX::INFO(
				"hook '{}' installed: AL id {} +{:#x} (rel call to {:#x})",
				a_label, a_funcId.id(), offset, a_replaceTarget);
			++g_hooksInstalled;
		} catch (const std::exception& ex) {
			REX::ERROR("hook '{}' failed: {}", a_label, ex.what());
			++g_hooksSkipped;
		}
	}

	// Scan a function body for a fixed byte sequence and NOP it. Used for the
	// BSPCGamepadDevice::Poll device-claim store: we look for `C6 43 08 01`
	// (mov byte ptr [rbx+8], 1) anywhere in the function and overwrite with
	// 4 NOPs.
	template <std::size_t N>
	void TryNopBytePattern(
		const REL::ID&                a_funcId,
		const std::uint8_t            (&a_pattern)[N],
		std::string_view              a_label)
	{
		try {
			const auto funcStart = a_funcId.address();
			const auto* const bytes = reinterpret_cast<const std::uint8_t*>(funcStart);
			for (std::ptrdiff_t i = 0; i + static_cast<std::ptrdiff_t>(N) <= MAX_SCAN; ++i) {
				if (std::memcmp(bytes + i, a_pattern, N) == 0) {
					REL::WriteSafeFill(funcStart + i, REL::NOP, N);
					REX::INFO(
						"byte patch installed: '{}' AL id {} +{:#x} (NOPed {} bytes)",
						a_label, a_funcId.id(), i, N);
					++g_hooksInstalled;
					return;
				}
			}
			REX::WARN(
				"byte patch skipped: '{}' pattern not found in first {} bytes of AL id {}",
				a_label, MAX_SCAN, a_funcId.id());
			++g_hooksSkipped;
		} catch (const std::exception& ex) {
			REX::ERROR("byte patch '{}' failed: {}", a_label, ex.what());
			++g_hooksSkipped;
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
	// returns true when the event is actually a look event.
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

	// === Resolve the predicates' addresses once for call-site comparison. ===
	std::uintptr_t isUsingGamepadAddr = 0;
	try {
		isUsingGamepadAddr = REL::ID(
			RE::Offset::BSInputDeviceManager::IsUsingGamepad).address();
		REX::INFO("predicate IsUsingGamepad resolved to {:#x}", isUsingGamepadAddr);
	} catch (const std::exception& ex) {
		REX::ERROR(
			"failed to resolve IsUsingGamepad address: {}. all call-replacement "
			"hooks below will be skipped.", ex.what());
	}

	// === Direct byte patch: stop left-stick from claiming the device ===
	// Inside BSPCGamepadDevice::Poll the engine writes 1 to a byte indicating
	// "left stick moved -> active device is gamepad". NOP that mov so simply
	// moving the stick does not kick the cursor.
	{
		const std::uint8_t pattern[4] = { 0xC6, 0x43, 0x08, 0x01 }; // mov byte ptr [rbx+8], 1
		TryNopBytePattern(
			RE::Offset::BSPCGamepadDevice::Poll,
			pattern,
			"BSPCGamepadDevice::Poll device-claim mov");
	}

	// === Look-input call replacements ===
	// All these functions originally call IsUsingGamepad(...) once to decide
	// some look-related branch. We want them to instead call
	// IsUsingThumbstickLook so the branch keys off the source of the *look*
	// input rather than the active device.
	if (isUsingGamepadAddr) {
		TryReplaceCall(
			RE::Offset::PlayerControls::LookHandler::Func10,
			isUsingGamepadAddr, IsUsingThumbstickLook,
			"LookHandler::Func10 (2-quadrant slow-movement fix)");
		TryReplaceCall(
			RE::Offset::PlayerControls::Manager::ProcessLookInput,
			isUsingGamepadAddr, IsUsingThumbstickLook,
			"PlayerControls::Manager::ProcessLookInput (look sensitivity)");
		TryReplaceCall(
			RE::Offset::Main::Run_WindowsMessageLoop,
			isUsingGamepadAddr, IsUsingThumbstickLook,
			"Main::Run_WindowsMessageLoop (cursor window-capture)");
		// ShipHudDataModel::PerformInputProcessing has two calls to
		// IsUsingGamepad in the function body. The dynamic finder returns
		// the first; we still need the second. Patch site 1 first.
		TryReplaceCall(
			RE::Offset::ShipHudDataModel::PerformInputProcessing,
			isUsingGamepadAddr, IsUsingThumbstickLook,
			"ShipHudDataModel::PerformInputProcessing (ship reticle, first call)");
		// For the second call site, we need a "find Nth" variant. For now,
		// scan past the first match and try to find a second. Keep this
		// inline so we don't add another helper function.
		try {
			const auto funcStart = REL::ID(
				RE::Offset::ShipHudDataModel::PerformInputProcessing).address();
			const auto* const b = reinterpret_cast<const std::uint8_t*>(funcStart);
			std::ptrdiff_t found = -1;
			int matches = 0;
			for (std::ptrdiff_t i = 0; i < MAX_SCAN; ++i) {
				if (b[i] != 0xE8) continue;
				std::int32_t rel{};
				std::memcpy(&rel, b + i + 1, sizeof(rel));
				const auto target = static_cast<std::uintptr_t>(
					static_cast<std::int64_t>(funcStart + i + 5) + rel);
				if (target == isUsingGamepadAddr) {
					if (++matches == 2) { found = i; break; }
				}
			}
			if (found >= 0) {
				REL::GetTrampoline().write_call<5>(funcStart + found, IsUsingThumbstickLook);
				REX::INFO(
					"hook 'ShipHudDataModel::PerformInputProcessing (ship reticle, second call)' "
					"installed at +{:#x}", found);
				++g_hooksInstalled;
			} else {
				REX::WARN(
					"hook 'ShipHudDataModel::PerformInputProcessing (second call)' skipped: "
					"only {} call to IsUsingGamepad found in function (expected at least 2).",
					matches);
				++g_hooksSkipped;
			}
		} catch (const std::exception& ex) {
			REX::ERROR("ShipHudDataModel second-call hook failed: {}", ex.what());
			++g_hooksSkipped;
		}

		// === Cursor visibility/style call replacements ===
		// IMenu::ShowCursor and UI::SetCursorStyle each call IsUsingGamepad to
		// pick gamepad vs mouse cursor handling. We redirect to IsGamepadCursor
		// (a tighter predicate that also requires UsingThumbstickLook).
		TryReplaceCall(
			RE::Offset::IMenu::ShowCursor,
			isUsingGamepadAddr, IsGamepadCursor,
			"IMenu::ShowCursor (menu cursor visibility)");
		TryReplaceCall(
			RE::Offset::UI::SetCursorStyle,
			isUsingGamepadAddr, IsGamepadCursor,
			"UI::SetCursorStyle (pointer vs gamepad cursor)");
	}

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
