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
#include <cctype>
#include <charconv>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <source_location>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

// We need a small slice of Win32 + XInput to drive the config loader and
// hotkey/chord poll thread. Including <windows.h> / <xinput.h> here
// would re-trigger the long-running C2589 build break in the spdlog /
// std::format expansions that REX::INFO / REX::WARN / REX::ERROR rely
// on (min / max macros leak in even with NOMINMAX hoisted; the libxse
// PCH chain has its own ways of pulling windows.h in). Forward-declare
// the seven functions and one struct we touch instead. Linker resolves
// the imports against kernel32.dll / user32.dll / Xinput.lib.
extern "C" {
	using DWORD   = unsigned long;
	using WORD    = unsigned short;
	using BYTE    = unsigned char;
	using SHORT   = short;
	using HMODULE = void*;
	using LPCSTR  = const char*;

	struct XINPUT_GAMEPAD
	{
		WORD  wButtons;
		BYTE  bLeftTrigger;
		BYTE  bRightTrigger;
		SHORT sThumbLX;
		SHORT sThumbLY;
		SHORT sThumbRX;
		SHORT sThumbRY;
	};

	struct XINPUT_STATE
	{
		DWORD          dwPacketNumber;
		XINPUT_GAMEPAD Gamepad;
	};

	__declspec(dllimport) int   __stdcall GetModuleHandleExA(DWORD, LPCSTR, HMODULE*);
	__declspec(dllimport) DWORD __stdcall GetModuleFileNameA(HMODULE, char*, DWORD);
	__declspec(dllimport) short __stdcall GetAsyncKeyState(int);
	__declspec(dllimport) unsigned long long __stdcall GetTickCount64();
	__declspec(dllimport) void  __stdcall Sleep(DWORD);
	__declspec(dllimport) DWORD __stdcall XInputGetState(DWORD, XINPUT_STATE*);
}

#pragma comment(lib, "Xinput.lib")
#pragma comment(lib, "user32.lib")

namespace
{
	constexpr DWORD GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS      = 0x4;
	constexpr DWORD GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT = 0x2;
	constexpr DWORD MAX_PATH_LEN                                = 260;
	constexpr DWORD ERROR_SUCCESS_VALUE                         = 0;
	constexpr BYTE  XINPUT_TRIGGER_THRESHOLD                    = 30;
}

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

	// === Runtime configuration (SimultaneousInput.ini) ===
	//
	// LockControllerGlyphs: when true, IsGamepadCursor() always returns true
	// regardless of which device drove the most recent look event. The
	// camera-side simultaneous-input behavior is unchanged (mouse and gamepad
	// both still drive the camera). Default false to preserve legacy behavior
	// for desktop users.
	//
	// Two runtime-toggle paths, both polled on the same background thread:
	//
	// LockGlyphsHotkey: Win32 virtual-key code, default 0x77 (VK_F8). On a
	// rising edge, toggle g_lockControllerGlyphs and log.
	//
	// LockGlyphsChord: gamepad button mask + trigger flags (XInput).
	// Default LB + RB + DPadDown, must be held continuously for
	// LockGlyphsChordHoldMs (default 500 ms) to toggle. Held-then-toggled
	// latches until released so we don't fire repeatedly. Built for
	// Steam Remote Play / MoonDeck on Steam Deck where F-keys are
	// awkward and stick-clicks (L3 / R3) need releasing the stick.
	std::atomic<bool>    g_lockControllerGlyphs{ false };
	std::atomic<int>     g_lockGlyphsHotkey{ 0x77 };  // VK_F8

	// Default chord: LB (LEFT_SHOULDER 0x0100) + RB (RIGHT_SHOULDER 0x0200)
	// + DPadDown (0x0002). Both shoulders are physical buttons on the Deck,
	// DPadDown is reachable with the left thumb without losing the
	// shoulders. LB+RB+anything is rare in default Starfield bindings.
	std::atomic<unsigned> g_lockGlyphsChordButtons{ 0x0302 };
	std::atomic<bool>     g_lockGlyphsChordLT{ false };
	std::atomic<bool>     g_lockGlyphsChordRT{ false };
	std::atomic<unsigned> g_lockGlyphsChordHoldMs{ 500 };
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
//
// Override: if the LockControllerGlyphs config flag is set (or auto-detected
// on Steam Deck), this always returns true so the gamepad glyph branch is
// always taken. The camera-side hooks still call IsUsingThumbstickLook for
// their own decisions; only the cursor/glyph display is pinned.
bool IsGamepadCursor(RE::BSInputDeviceManager* a_inputDeviceManager)
{
	if (g_lockControllerGlyphs.load(std::memory_order_relaxed)) {
		return true;
	}
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

	// === Tiny single-file INI parser ===
	//
	// Supports:
	//   [Section]
	//   key = value     ; comment after value is also stripped
	//   ; or # full-line comment
	//
	// Section + key matching is case-insensitive. Bool values accept
	// true/false, 1/0, yes/no, on/off (any case). Whitespace around the =
	// and at line ends is trimmed.
	//
	// Hand-rolled to avoid pulling in a vcpkg dependency for ~20 LoC of
	// parsing. The plugin's only config surface is the [Display] section
	// today; if it grows past a handful of keys, swap this for inih or
	// simpleini.
	std::string TrimWs(std::string_view s)
	{
		std::size_t b = 0;
		while (b < s.size() && std::isspace(static_cast<unsigned char>(s[b]))) {
			++b;
		}
		std::size_t e = s.size();
		while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) {
			--e;
		}
		return std::string(s.substr(b, e - b));
	}

	std::string ToLower(std::string_view s)
	{
		std::string out;
		out.reserve(s.size());
		for (char c : s) {
			out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
		}
		return out;
	}

	bool ParseBool(std::string_view raw, bool defaultValue)
	{
		const auto v = ToLower(TrimWs(raw));
		if (v == "true" || v == "1" || v == "yes" || v == "on") {
			return true;
		}
		if (v == "false" || v == "0" || v == "no" || v == "off") {
			return false;
		}
		return defaultValue;
	}

	int ParseHotkey(std::string_view raw, int defaultVk)
	{
		auto v = TrimWs(raw);
		if (v.empty()) {
			return defaultVk;
		}
		// Accept either a hex literal (0x77), a decimal (119), or one of a
		// short list of common Win32 VK names. The full VK table has 200+
		// entries; we surface the keys someone is likely to bind without
		// pulling in a name-resolution library.
		const auto lower = ToLower(v);
		struct Named { std::string_view name; int vk; };
		static constexpr Named names[] = {
			{ "vk_f1",  0x70 }, { "vk_f2",  0x71 }, { "vk_f3",  0x72 },
			{ "vk_f4",  0x73 }, { "vk_f5",  0x74 }, { "vk_f6",  0x75 },
			{ "vk_f7",  0x76 }, { "vk_f8",  0x77 }, { "vk_f9",  0x78 },
			{ "vk_f10", 0x79 }, { "vk_f11", 0x7A }, { "vk_f12", 0x7B },
			{ "vk_pause",      0x13 },
			{ "vk_scroll",     0x91 },
			{ "vk_oem_plus",   0xBB },
			{ "vk_oem_minus",  0xBD },
			{ "vk_add",        0x6B },
			{ "vk_subtract",   0x6D },
			{ "vk_multiply",   0x6A },
			{ "vk_divide",     0x6F },
			{ "vk_numpad0",    0x60 }, { "vk_numpad1", 0x61 },
			{ "vk_numpad2",    0x62 }, { "vk_numpad3", 0x63 },
			{ "vk_numpad4",    0x64 }, { "vk_numpad5", 0x65 },
			{ "vk_numpad6",    0x66 }, { "vk_numpad7", 0x67 },
			{ "vk_numpad8",    0x68 }, { "vk_numpad9", 0x69 },
		};
		for (const auto& e : names) {
			if (lower == e.name) {
				return e.vk;
			}
		}
		// Numeric: hex or decimal.
		int parsed = 0;
		const char* begin = v.data();
		const char* end = v.data() + v.size();
		auto base = 10;
		if (v.size() >= 2 && v[0] == '0' && (v[1] == 'x' || v[1] == 'X')) {
			begin += 2;
			base = 16;
		}
		auto [ptr, ec] = std::from_chars(begin, end, parsed, base);
		if (ec == std::errc{} && parsed > 0 && parsed < 0x100) {
			return parsed;
		}
		return defaultVk;
	}

	struct ChordSpec
	{
		unsigned buttons = 0;       // OR of XINPUT_GAMEPAD_* bits
		bool     leftTrigger  = false;
		bool     rightTrigger = false;
		bool     valid = false;     // false if parse produced nothing usable
		std::string repr;           // canonical "LB+RB+DPadDown" for logging
	};

	ChordSpec ParseChord(std::string_view raw)
	{
		ChordSpec out;
		struct Token { std::string_view name; unsigned bits; bool isLT; bool isRT; };
		// All XInput buttons + the two analog triggers as boolean flags.
		// "Select" is an alias for "Back" (xbox vs ps naming).
		static constexpr Token tokens[] = {
			{ "lb",        0x0100, false, false },
			{ "rb",        0x0200, false, false },
			{ "lstick",    0x0040, false, false },
			{ "rstick",    0x0080, false, false },
			{ "a",         0x1000, false, false },
			{ "b",         0x2000, false, false },
			{ "x",         0x4000, false, false },
			{ "y",         0x8000, false, false },
			{ "dpadup",    0x0001, false, false },
			{ "dpaddown",  0x0002, false, false },
			{ "dpadleft",  0x0004, false, false },
			{ "dpadright", 0x0008, false, false },
			{ "start",     0x0010, false, false },
			{ "back",      0x0020, false, false },
			{ "select",    0x0020, false, false },
			{ "lt",        0x0000, true,  false },
			{ "rt",        0x0000, false, true  },
		};

		std::string_view rest = raw;
		while (!rest.empty()) {
			// Skip leading whitespace and chord separators (+, comma).
			std::size_t i = 0;
			while (i < rest.size() && (std::isspace(static_cast<unsigned char>(rest[i])) ||
			                            rest[i] == '+' || rest[i] == ',')) {
				++i;
			}
			rest.remove_prefix(i);
			if (rest.empty()) {
				break;
			}
			// Read until next separator.
			std::size_t j = 0;
			while (j < rest.size() && rest[j] != '+' && rest[j] != ',' &&
			       !std::isspace(static_cast<unsigned char>(rest[j]))) {
				++j;
			}
			const auto tok = ToLower(std::string(rest.substr(0, j)));
			rest.remove_prefix(j);

			bool matched = false;
			for (const auto& t : tokens) {
				if (tok == t.name) {
					out.buttons |= t.bits;
					out.leftTrigger  = out.leftTrigger  || t.isLT;
					out.rightTrigger = out.rightTrigger || t.isRT;
					if (!out.repr.empty()) {
						out.repr += '+';
					}
					out.repr += tok;
					matched = true;
					break;
				}
			}
			if (!matched) {
				REX::WARN(
					"config: unknown chord token '{}' in LockGlyphsChord; "
					"valid tokens: LB RB LStick RStick A B X Y "
					"DPadUp DPadDown DPadLeft DPadRight Start Back/Select LT RT",
					tok);
			}
		}
		out.valid = (out.buttons != 0) || out.leftTrigger || out.rightTrigger;
		return out;
	}

	struct IniConfig
	{
		bool      lockControllerGlyphs = false;
		int       lockGlyphsHotkey     = 0x77;  // VK_F8
		ChordSpec lockGlyphsChord;
		unsigned  lockGlyphsChordHoldMs = 500;
		bool      fileFound = false;

		IniConfig()
		{
			// Default chord = LB + RB + DPadDown.
			lockGlyphsChord.buttons = 0x0302;
			lockGlyphsChord.valid = true;
			lockGlyphsChord.repr = "lb+rb+dpaddown";
		}
	};

	IniConfig LoadIniConfig(const std::string& path)
	{
		IniConfig cfg;
		std::ifstream in(path);
		if (!in) {
			return cfg;
		}
		cfg.fileFound = true;
		std::string line;
		std::string section;
		while (std::getline(in, line)) {
			auto trimmed = TrimWs(line);
			if (trimmed.empty() || trimmed[0] == ';' || trimmed[0] == '#') {
				continue;
			}
			if (trimmed.front() == '[' && trimmed.back() == ']') {
				section = ToLower(trimmed.substr(1, trimmed.size() - 2));
				continue;
			}
			const auto eq = trimmed.find('=');
			if (eq == std::string::npos) {
				continue;
			}
			auto key = ToLower(TrimWs(std::string_view(trimmed).substr(0, eq)));
			auto val = std::string_view(trimmed).substr(eq + 1);
			// Strip inline ';' / '#' comments from the value.
			const auto cmt = val.find_first_of(";#");
			if (cmt != std::string_view::npos) {
				val = val.substr(0, cmt);
			}
			if (section == "display") {
				if (key == "lockcontrollerglyphs") {
					cfg.lockControllerGlyphs = ParseBool(val, cfg.lockControllerGlyphs);
				} else if (key == "lockglyphshotkey") {
					cfg.lockGlyphsHotkey = ParseHotkey(val, cfg.lockGlyphsHotkey);
				} else if (key == "lockglyphschord") {
					auto parsed = ParseChord(TrimWs(val));
					if (parsed.valid) {
						cfg.lockGlyphsChord = parsed;
					}  // else keep default; ParseChord already logged unknown tokens
				} else if (key == "lockglyphschordholdms") {
					unsigned ms = 0;
					const auto trimmed = TrimWs(val);
					auto [p, ec] = std::from_chars(
						trimmed.data(), trimmed.data() + trimmed.size(), ms);
					if (ec == std::errc{} && ms >= 50 && ms <= 5000) {
						cfg.lockGlyphsChordHoldMs = ms;
					}
				}
			}
		}
		return cfg;
	}

	void ToggleLockAndLog(const char* source, std::string_view detail)
	{
		const bool prev = g_lockControllerGlyphs.load(std::memory_order_relaxed);
		const bool next = !prev;
		g_lockControllerGlyphs.store(next, std::memory_order_relaxed);
		REX::INFO(
			"{}: LockControllerGlyphs toggled {} -> {} ({})",
			source,
			prev ? "true" : "false",
			next ? "true" : "false",
			detail);
	}

	// Background poll for both runtime toggles: KBM hotkey + gamepad chord.
	//
	// Polling vs. SetWindowsHookEx vs. RegisterHotKey: a low-level keyboard
	// hook injects into every thread's input chain and adds latency to
	// every keypress, which is unacceptable for a game; RegisterHotKey
	// requires a message pump we don't otherwise need; polling on a
	// detached thread is the smallest-diff option. 50 ms is below the
	// human keypress floor (~100 ms) so we never miss a tap, and below
	// 1% CPU on one core given GetAsyncKeyState and XInputGetState are
	// thin syscalls.
	//
	// KBM edge detection: high bit (0x8000) of GetAsyncKeyState gives us
	// "is key currently down" without latching on the low bit's "was
	// pressed since last call" semantics, which would race with us if
	// another caller inspects the same key.
	//
	// Gamepad chord: read XInput controller 0 (Steam Input always presents
	// as controller 0; we don't iterate 1..3 because Tony only uses one).
	// Chord is satisfied when ALL required buttons are down AND any
	// required triggers are above XINPUT_GAMEPAD_TRIGGER_THRESHOLD (30).
	// We track when the chord was first satisfied; once it has been held
	// continuously for >= holdMs, we toggle and latch (no repeats until
	// the chord is released). Releasing any required input resets the
	// state machine.
	void HotkeyPollLoop()
	{
		bool wasKeyDown = false;
		bool chordWasSatisfied = false;
		bool chordLatched = false;
		unsigned long long chordSatisfiedAtMs = 0;

		auto nowMs = []() -> unsigned long long {
			return static_cast<unsigned long long>(::GetTickCount64());
		};

		for (;;) {
			// === KBM hotkey ===
			const int vk = g_lockGlyphsHotkey.load(std::memory_order_relaxed);
			if (vk > 0) {
				const bool isKeyDown = (::GetAsyncKeyState(vk) & 0x8000) != 0;
				if (isKeyDown && !wasKeyDown) {
					ToggleLockAndLog(
						"hotkey",
						std::string("vk=0x") +
						[vk]() {
							char b[8] = {};
							auto [p, _] = std::to_chars(b, b + sizeof(b), vk, 16);
							return std::string(b, p);
						}());
				}
				wasKeyDown = isKeyDown;
			}

			// === Gamepad chord ===
			const auto reqButtons = g_lockGlyphsChordButtons.load(std::memory_order_relaxed);
			const bool reqLT = g_lockGlyphsChordLT.load(std::memory_order_relaxed);
			const bool reqRT = g_lockGlyphsChordRT.load(std::memory_order_relaxed);
			const auto holdMs = g_lockGlyphsChordHoldMs.load(std::memory_order_relaxed);

			if (reqButtons != 0 || reqLT || reqRT) {
				XINPUT_STATE state{};
				const auto rc = ::XInputGetState(0, &state);
				bool satisfied = false;
				if (rc == ERROR_SUCCESS_VALUE) {
					const auto& gp = state.Gamepad;
					const bool buttonsOk =
						(reqButtons == 0) || ((gp.wButtons & reqButtons) == reqButtons);
					const bool ltOk =
						!reqLT || (gp.bLeftTrigger >= XINPUT_TRIGGER_THRESHOLD);
					const bool rtOk =
						!reqRT || (gp.bRightTrigger >= XINPUT_TRIGGER_THRESHOLD);
					satisfied = buttonsOk && ltOk && rtOk;
				}

				if (satisfied) {
					if (!chordWasSatisfied) {
						chordSatisfiedAtMs = nowMs();
						chordLatched = false;
					}
					if (!chordLatched && (nowMs() - chordSatisfiedAtMs) >= holdMs) {
						std::string detail = "chord held " + std::to_string(holdMs) + "ms";
						ToggleLockAndLog("chord", detail);
						chordLatched = true;
					}
				} else {
					chordSatisfiedAtMs = 0;
					chordLatched = false;
				}
				chordWasSatisfied = satisfied;
			}

			::Sleep(50);
		}
	}

	void LoadConfig(const SFSE::LoadInterface*)
	{
		// Plugin runs from <Starfield>\Data\SFSE\Plugins\SimultaneousInput.dll;
		// the INI sits next to the DLL so the Plugins directory remains the
		// single source of truth for installed plugin state.
		char dllPath[MAX_PATH_LEN] = {};
		HMODULE thisModule = nullptr;
		::GetModuleHandleExA(
			GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
			reinterpret_cast<LPCSTR>(&LoadConfig),
			&thisModule);
		const auto pathLen = ::GetModuleFileNameA(thisModule, dllPath, MAX_PATH_LEN);
		std::string iniPath;
		if (pathLen > 4 && pathLen < MAX_PATH_LEN) {
			iniPath.assign(dllPath, pathLen - 4);  // strip .dll
			iniPath += ".ini";
		}

		const auto cfg = LoadIniConfig(iniPath);
		g_lockControllerGlyphs.store(cfg.lockControllerGlyphs, std::memory_order_relaxed);
		g_lockGlyphsHotkey.store(cfg.lockGlyphsHotkey, std::memory_order_relaxed);
		g_lockGlyphsChordButtons.store(cfg.lockGlyphsChord.buttons, std::memory_order_relaxed);
		g_lockGlyphsChordLT.store(cfg.lockGlyphsChord.leftTrigger, std::memory_order_relaxed);
		g_lockGlyphsChordRT.store(cfg.lockGlyphsChord.rightTrigger, std::memory_order_relaxed);
		g_lockGlyphsChordHoldMs.store(cfg.lockGlyphsChordHoldMs, std::memory_order_relaxed);

		if (!cfg.fileFound) {
			REX::INFO(
				"config: no INI at '{}'; using defaults "
				"(LockControllerGlyphs=false, LockGlyphsHotkey=VK_F8, "
				"LockGlyphsChord=LB+RB+DPadDown, LockGlyphsChordHoldMs=500)",
				iniPath);
		} else {
			REX::INFO(
				"config: loaded '{}' (LockControllerGlyphs={}, LockGlyphsHotkey=0x{:x}, "
				"LockGlyphsChord='{}' buttons=0x{:x} LT={} RT={}, LockGlyphsChordHoldMs={})",
				iniPath,
				cfg.lockControllerGlyphs ? "true" : "false",
				static_cast<unsigned>(cfg.lockGlyphsHotkey),
				cfg.lockGlyphsChord.repr,
				cfg.lockGlyphsChord.buttons,
				cfg.lockGlyphsChord.leftTrigger ? "true" : "false",
				cfg.lockGlyphsChord.rightTrigger ? "true" : "false",
				cfg.lockGlyphsChordHoldMs);
		}

		// Spawn detached poller. Lifetime is the game process; the thread
		// exits when the process does. No clean shutdown path because SFSE
		// plugins are not expected to unload.
		try {
			std::thread(HotkeyPollLoop).detach();
			REX::INFO(
				"hotkey/chord: registered runtime toggle (kbm vk=0x{:x}, "
				"chord '{}', hold {} ms, poll 50 ms)",
				static_cast<unsigned>(cfg.lockGlyphsHotkey),
				cfg.lockGlyphsChord.repr,
				cfg.lockGlyphsChordHoldMs);
		} catch (const std::exception& ex) {
			REX::WARN(
				"hotkey/chord: poller failed to start ({}); INI value still applies, "
				"runtime toggle disabled",
				ex.what());
		}
	}
}

extern "C" DLLEXPORT bool SFSEAPI SFSEPlugin_Load(const SFSE::LoadInterface* a_sfse)
{
	// libxse's SFSE::Init does spdlog setup itself when InitInfo.log is true,
	// and (when trampoline=true) reserves trampoline space from SFSE's
	// branch pool, falling back to a self-allocated trampoline.
	//
	// Trampoline budget: 32 bytes covers the six trampoline calls we install
	// on 1.16.236 (LookHandler::Func10, ProcessLookInput, ShipHud x2,
	// IMenu::ShowCursor, UI::SetCursorStyle). The 1.8.86-era
	// Run_WindowsMessageLoop hook is no longer attempted because the
	// underlying predicate call was refactored out of the message pump in
	// 1.16.236; see MAINTAINING.md section 7. Bump this if we add hooks. We
	// deliberately use the InitInfo path instead of the deprecated
	// SFSE::AllocTrampoline to stay /WX-clean (C4996 with the prior call).
	//
	// Logs land in %USERPROFILE%/Documents/My Games/Starfield/SFSE/Logs/
	// SimultaneousInput.log, the same dir SFSE writes sfse.log, so users
	// get one consolidated log folder.
	SFSE::Init(a_sfse, SFSE::InitInfo{
		.trampoline = true,
		.trampolineSize = 32,
	});
	LogRuntimeProbe(a_sfse);

	// Read SimultaneousInput.ini next to the DLL and apply the
	// LockControllerGlyphs override (auto-detect on Steam Deck if enabled).
	// Must run before any cursor hook fires so IsGamepadCursor sees the
	// final flag state on its first invocation.
	LoadConfig(a_sfse);

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
	// Inside BSPCGamepadDevice::Poll the engine writes 1 to a byte indicating
	// "left stick moved -> active device is gamepad". We NOP the 4-byte store
	// so simply moving the stick doesn't kick the cursor.
	// Pattern: C6 43 08 01  (mov byte ptr [rbx+8], 1)
	//
	// Original Parapets offset was +0x2A0 (Starfield 1.8.86). On 1.16.236 the
	// byte layout shifted: the same anchor is at +0x51D within the same
	// function. Rather than hard-code, we scan the function body for the
	// anchor pattern within a ~0x800-byte window and patch wherever we find
	// it. This makes the byte patch resilient to future minor refactors.
	try {
		REL::Relocation<std::uintptr_t> head(RE::Offset::BSPCGamepadDevice::Poll);
		constexpr std::size_t kScanLimit = 0x800;
		const std::uint8_t*   p = reinterpret_cast<const std::uint8_t*>(head.address());
		std::ptrdiff_t        match_off = -1;
		for (std::size_t i = 0; i + 4 <= kScanLimit; ++i) {
			if (p[i] == 0xC6 && p[i + 1] == 0x43 && p[i + 2] == 0x08 && p[i + 3] == 0x01) {
				match_off = static_cast<std::ptrdiff_t>(i);
				break;
			}
		}
		if (match_off >= 0) {
			REL::Relocation<std::uintptr_t> hook(RE::Offset::BSPCGamepadDevice::Poll, match_off);
			hook.write_fill(REL::NOP, 0x4);
			REX::INFO("byte patch installed: BSPCGamepadDevice::Poll +{:#x}", match_off);
			++g_hooksInstalled;
		} else {
			REX::WARN(
				"byte patch skipped: BSPCGamepadDevice::Poll AL id {} (rva {:#x}) "
				"anchor 'C6 43 08 01' not found in first {:#x} bytes; function may "
				"have been refactored further. left thumbstick will still device-switch.",
				RE::Offset::BSPCGamepadDevice::Poll.id(),
				RE::Offset::BSPCGamepadDevice::Poll.offset(),
				kScanLimit);
			++g_hooksSkipped;
		}
	} catch (const std::exception& ex) {
		REX::ERROR("BSPCGamepadDevice::Poll patch failed: {}", ex.what());
		++g_hooksSkipped;
	}

	// === Look-input call replacements (predicate IsUsingGamepad -> IsUsingThumbstickLook) ===
	// Offsets re-derived against Starfield 1.16.236 via
	// tools/derive_function_ids.py: each is the position of an E8 call to
	// the look-variant predicate (RVA 0x28cef30, AL 139340) inside the
	// host function body.
	TryWriteCall<5>(
		RE::Offset::PlayerControls::LookHandler::Func10, 0x196,
		IsUsingThumbstickLook,
		"LookHandler::Func10 (2-quadrant slow-movement fix)");

	TryWriteCall<5>(
		RE::Offset::PlayerControls::Manager::ProcessLookInput, 0x33F,
		IsUsingThumbstickLook,
		"PlayerControls::Manager::ProcessLookInput (look sensitivity)");

	// Main::Run_WindowsMessageLoop +0x39 (1.8.86) had no analog on
	// 1.16.236: the host body has 775 E8 calls in its first 24 KB and
	// none target either predicate variant. The cursor-capture branch was
	// inlined or moved. Hook permanently retired; see MAINTAINING.md
	// section 7.

	TryWriteCall<5>(
		RE::Offset::ShipHudDataModel::PerformInputProcessing, 0x2C7,
		IsUsingThumbstickLook,
		"ShipHudDataModel::PerformInputProcessing+0x2C7 (ship reticle pre)");

	TryWriteCall<5>(
		RE::Offset::ShipHudDataModel::PerformInputProcessing, 0x2E4,
		IsUsingThumbstickLook,
		"ShipHudDataModel::PerformInputProcessing+0x2E4 (ship reticle post)");

	// === Cursor visibility/style call replacements (-> IsGamepadCursor) ===
	// Offsets target the cursor-variant predicate (RVA 0x2c4b50, AL 35982);
	// see Offset.Ext.h for the predicate-split note.
	TryWriteCall<5>(
		RE::Offset::IMenu::ShowCursor, 0xA1,
		IsGamepadCursor,
		"IMenu::ShowCursor (menu cursor visibility)");

	TryWriteCall<5>(
		RE::Offset::UI::SetCursorStyle, 0x4CE,
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
