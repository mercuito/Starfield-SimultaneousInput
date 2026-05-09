#include "Plugin.h"
#include "RE/Offset.Ext.h"

// libxse/CommonLibSF surface. The umbrella SFSE/SFSE.h pulls in PCH (which
// includes REL::, REX::, and the SFSE/RE namespaces), API, Interfaces, Logger,
// Trampoline, and Version, which is everything we need for a hook plugin.
#include "SFSE/SFSE.h"

#include "REL/Pattern.h"
#include "REL/Relocation.h"

#include "REX/LOG.h"

#include "RE/A/Actor.h"
#include "RE/A/Array.h"
#include "RE/B/BGSBodyPartData.h"
#include "RE/B/BSFixedString.h"
#include "RE/B/BSInputEventUser.h"
#include "RE/B/BSScriptUtil.h"
#include "RE/B/BSTEvent.h"
#include "RE/B/BGSBodyPartDefs.h"
#include "RE/B/BGSMaterialType.h"
#include "RE/G/GameVM.h"
#include "RE/N/NiAVObject.h"
#include "RE/N/NiPoint.h"
#include "RE/P/Projectile.h"
#include "RE/T/TBO_InstanceData.h"
#include "RE/T/TESAmmo.h"
#include "RE/T/TESForm.h"
#include "RE/T/TESNPC.h"
#include "RE/T/TESRace.h"

#include <atomic>
#include <array>
#include <cctype>
#include <charconv>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <memory>
#include <mutex>
#include <source_location>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <variant>
#include <vector>

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
	__declspec(dllimport) HMODULE __stdcall GetModuleHandleA(LPCSTR);
	__declspec(dllimport) DWORD __stdcall GetModuleFileNameA(HMODULE, char*, DWORD);
	__declspec(dllimport) short __stdcall GetAsyncKeyState(int);
	__declspec(dllimport) unsigned long long __stdcall GetTickCount64();
	__declspec(dllimport) void  __stdcall Sleep(DWORD);
	__declspec(dllimport) DWORD __stdcall XInputGetState(DWORD, XINPUT_STATE*);
	__declspec(dllimport) int   __stdcall VirtualProtect(void*, unsigned long long, DWORD, DWORD*);
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
	std::atomic<std::uint32_t> g_projectileImpactLogCount{ 0 };
	std::atomic<std::uint32_t> g_hitEventLogCount{ 0 };

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

namespace
{
	using ProcessProjectileImpactEffect_t = void(RE::Projectile*, RE::Projectile::ImpactData*);
	using MissileProjectileUpdate_t = void(RE::Projectile*, float);
	using RuntimeImpactProcess_t = bool(RE::Projectile*, bool);
	using ProjectileVirtualTrace_t = std::uintptr_t(RE::Projectile*, void*);

	struct RuntimeImpactTraceState
	{
		std::uintptr_t projectile{ 0 };
		std::uintptr_t impactData{ 0 };
		std::uint32_t  projectileFormID{ 0 };
		std::uint32_t  processedTransitions{ 0 };
		bool           seenInitial{ false };
		bool           seenProcessed{ false };
		bool           seenEffectSpawned{ false };
	};

	struct ProjectileVirtualTraceHook
	{
		std::uintptr_t          vtableRVA;
		const char*             name;
		std::uintptr_t          vtable{ 0 };
		ProjectileVirtualTrace_t* original{ nullptr };
	};

	struct ProjectileUpdateTraceHook
	{
		std::uintptr_t           vtableRVA;
		const char*              name;
		std::uintptr_t           vtable{ 0 };
		MissileProjectileUpdate_t* original{ nullptr };
	};

	struct HitTraceDamageImpactData
	{
		RE::NiPoint3A location;  // 00
		RE::NiPoint3A normal;    // 10
		RE::NiPoint3A velocity;  // 20
		RE::NiPointer<RE::bhkNPCollisionObject> colObj;  // 30
	};
	static_assert(sizeof(HitTraceDamageImpactData) == 0x40);

	struct HitTraceHitData
	{
		HitTraceDamageImpactData impactData;      // 00
		RE::BSPointerHandle<RE::Actor> aggressor; // 40
		RE::BSPointerHandle<RE::Actor> target;    // 44
		RE::BSPointerHandle<RE::TESObjectREFR> sourceRef; // 48
		std::uint64_t attackData;                 // 50
		RE::TESForm* weapon;                      // 58 - TESObjectWEAP*
		void* weaponInstanceData;                 // 60
		void* criticalEffect;                     // 68 - SpellItem*
		void* hitEffect;                          // 70 - SpellItem*
		std::uint64_t unk78;                      // 78
		const RE::TESAmmo* ammo;                  // 80
		std::byte pad88[0x5C];                    // 88
		REX::TEnum<RE::BGSBodyPartDefs::LIMB_ENUM> damageLimb; // E4
		std::byte padE8[0x8];                     // E8
	};
	static_assert(sizeof(HitTraceHitData) == 0xF0);

	struct HitTraceTESHitEvent
	{
		HitTraceHitData hitData;              // 000
		RE::NiPointer<RE::TESObjectREFR> target; // 0F0
		RE::NiPointer<RE::TESObjectREFR> cause;  // 0F8
		RE::BSFixedString material;          // 100
		RE::TESFormID sourceFormID;          // 108
		RE::TESFormID projectileFormID;      // 10C
		bool usesHitData;                    // 110
	};
	static_assert(sizeof(HitTraceTESHitEvent) == 0x120);

	constexpr std::uintptr_t kProcessProjectileImpactEffectRVA = 0x1B3DB70;
	constexpr std::uintptr_t kMissileProjectileUpdateRVA = 0x1B34B90;
	constexpr std::uintptr_t kRuntimeImpactProcessRVA = 0x1B0BDF0;
	constexpr REL::ID kTESHitEventGetEventSourceID{ 34450 };
	constexpr std::uint32_t kProjectileImpactLogLimit = 512;
	constexpr std::size_t kProjectileVirtualTraceSlot = 0x156;
	constexpr std::size_t kRuntimeProjectileUpdateSlot = 0x13A;

	ProcessProjectileImpactEffect_t* g_processProjectileImpactEffect = nullptr;
	MissileProjectileUpdate_t* g_missileProjectileUpdate = nullptr;
	RuntimeImpactProcess_t* g_runtimeImpactProcess = nullptr;
	std::atomic<std::uint32_t> g_projectileVirtualTraceLogCount{ 0 };
	std::atomic<std::uint32_t> g_runtimeImpactProcessTraceCount{ 0 };
	std::array<RuntimeImpactTraceState, 64> g_runtimeImpactTraceStates{};
	std::uint32_t g_runtimeImpactTraceCursor{ 0 };

	std::array<ProjectileVirtualTraceHook, 10> g_projectileVirtualTraceHooks{ {
		{ 0x4CD4B90, "Projectile" },
		{ 0x4CD3608, "MissileProjectile" },
		{ 0x4CCC108, "ArrowProjectile" },
		{ 0x4CD1268, "GrenadeProjectile" },
		{ 0x4CCDB40, "BeamProjectile" },
		{ 0x4CD0588, "FlameProjectile" },
		{ 0x4CCE8C8, "ConeProjectile" },
		{ 0x4C30998, "PlasmaProjectile" },
		{ 0x4CCCDF0, "BarrierProjectile" },
		{ 0x4C31708, "EmitterProjectile" },
	} };

	std::array<ProjectileUpdateTraceHook, 5> g_projectileUpdateTraceHooks{ {
		{ 0x4CCDC58, "RuntimeShotProjectile" },
		{ 0x4CD3608, "MissileProjectile" },
		{ 0x4CCDB40, "BeamProjectile" },
		{ 0x4CD0588, "FlameProjectile" },
		{ 0x4CD1268, "GrenadeProjectile" },
	} };

	[[nodiscard]] std::uintptr_t StarfieldBase()
	{
		static const auto base = reinterpret_cast<std::uintptr_t>(GetModuleHandleA(nullptr));
		return base;
	}

	[[nodiscard]] std::uint32_t FormIDOf(const RE::TESForm* a_form)
	{
		return a_form ? a_form->GetFormID() : 0;
	}

	template <class T>
	[[nodiscard]] std::uint32_t HandleValue(RE::BSPointerHandle<T> a_handle)
	{
		return a_handle.get_handle();
	}

	[[nodiscard]] std::uintptr_t ReadQword(const void* a_base, std::ptrdiff_t a_offset)
	{
		return *reinterpret_cast<const std::uintptr_t*>(reinterpret_cast<std::uintptr_t>(a_base) + a_offset);
	}

	[[nodiscard]] bool TryReadQword(const void* a_base, std::ptrdiff_t a_offset, std::uintptr_t& a_out)
	{
		__try {
			a_out = ReadQword(a_base, a_offset);
			return true;
		} __except (1) {
			a_out = 0;
			return false;
		}
	}

	[[nodiscard]] std::uintptr_t RvaOf(std::uintptr_t a_address)
	{
		const auto base = StarfieldBase();
		return a_address >= base ? a_address - base : 0;
	}

	void LogCollisionBodyRecord(std::uint32_t a_logIndex, const char* a_phase, const char* a_eventName, const char* a_label, const void* a_body)
	{
		if (!a_body) {
			return;
		}

		std::array<std::uintptr_t, 17> fields{};
		for (std::size_t i = 0; i < fields.size(); ++i) {
			if (!TryReadQword(a_body, static_cast<std::ptrdiff_t>(i * sizeof(std::uintptr_t)), fields[i])) {
				REX::INFO(
					"impact-body[{}:{}:{}:{}]: body={:p} unreadable at +{:#x}",
					a_logIndex,
					a_phase,
					a_eventName,
					a_label,
					a_body,
					i * sizeof(std::uintptr_t));
				return;
			}
		}

		REX::INFO(
			"impact-body[{}:{}:{}:{}]: body={:p} "
			"q00={:#x} q08={:#x} q10={:#x} q18={:#x} q20={:#x} q28={:#x} q30={:#x} q38={:#x} "
			"q40={:#x} q48={:#x} q50={:#x} q58={:#x} q60={:#x} q68={:#x} q70={:#x} q78={:#x} q80={:#x}",
			a_logIndex,
			a_phase,
			a_eventName,
			a_label,
			a_body,
			fields[0],
			fields[1],
			fields[2],
			fields[3],
			fields[4],
			fields[5],
			fields[6],
			fields[7],
			fields[8],
			fields[9],
			fields[10],
			fields[11],
			fields[12],
			fields[13],
			fields[14],
			fields[15],
			fields[16]);
	}

	[[nodiscard]] const char* NameOf(const RE::NiAVObject* a_object)
	{
		if (!a_object) {
			return "<none>";
		}

		const auto* name = a_object->name.c_str();
		return name ? name : "<unnamed>";
	}

	[[nodiscard]] const char* LimbName(std::int32_t a_limb)
	{
		using LIMB = RE::BGSBodyPartDefs::LIMB_ENUM;

		switch (static_cast<LIMB>(a_limb)) {
		case LIMB::kNone:
			return "None";
		case LIMB::kTorso:
			return "Torso";
		case LIMB::kHead1:
			return "Head1";
		case LIMB::kEye1:
			return "Eye1";
		case LIMB::kLookAt1:
			return "LookAt1";
		case LIMB::kFlyGrab:
			return "FlyGrab";
		case LIMB::kHead2:
			return "Head2";
		case LIMB::kLeftArm1:
			return "LeftArm1";
		case LIMB::kLeftArm2:
			return "LeftArm2";
		case LIMB::kRightArm1:
			return "RightArm1";
		case LIMB::kRightArm2:
			return "RightArm2";
		case LIMB::kLeftLeg1:
			return "LeftLeg1";
		case LIMB::kLeftLeg2:
			return "LeftLeg2";
		case LIMB::kLeftLeg3:
			return "LeftLeg3";
		case LIMB::kRightLeg1:
			return "RightLeg1";
		case LIMB::kRightLeg2:
			return "RightLeg2";
		case LIMB::kRightLeg3:
			return "RightLeg3";
		case LIMB::kBrain:
			return "Brain";
		case LIMB::kWeapon:
			return "Weapon";
		case LIMB::kRoot:
			return "Root";
		case LIMB::kCom:
			return "Com";
		case LIMB::kPelvis:
			return "Pelvis";
		case LIMB::kCamera:
			return "Camera";
		case LIMB::kOffsetRoot:
			return "OffsetRoot";
		case LIMB::kLeftFoot:
			return "LeftFoot";
		case LIMB::kRightFoot:
			return "RightFoot";
		case LIMB::kFaceTargetSource:
			return "FaceTargetSource";
		default:
			return "Unknown";
		}
	}

	struct PapyrusNodeGuess
	{
		const char* primary{ "" };
		const char* alternate{ "" };
		const char* confidence{ "none" };
	};

	[[nodiscard]] PapyrusNodeGuess GuessPapyrusNode(std::int32_t a_limb, std::uint64_t a_collisionIdA, std::uint64_t a_collisionIdB)
	{
		using LIMB = RE::BGSBodyPartDefs::LIMB_ENUM;

		const auto hasCollisionID = [a_collisionIdA, a_collisionIdB](std::uint64_t a_value) {
			return a_collisionIdA == a_value || a_collisionIdB == a_value;
		};
		const auto hasCollisionIDs = [a_collisionIdA, a_collisionIdB](std::uint64_t a_first, std::uint64_t a_second) {
			return (a_collisionIdA == a_first && a_collisionIdB == a_second) ||
			       (a_collisionIdA == a_second && a_collisionIdB == a_first);
		};

		switch (static_cast<LIMB>(a_limb)) {
		case LIMB::kHead1:
		case LIMB::kHead2:
		case LIMB::kBrain:
			return { "C_Head", "C_Neck", "limb-direct" };
		case LIMB::kTorso:
			return { "C_Spine", "C_Chest", "limb-direct" };
		case LIMB::kLeftArm1:
		case LIMB::kLeftArm2:
			if (hasCollisionID(0x12)) {
				return { "L_Wrist", "L_Biceps", "collision-hand-candidate" };
			}
			if (hasCollisionID(0x9)) {
				return { "L_Biceps", "L_Wrist", "collision-upper-candidate" };
			}
			return { "L_Biceps", "L_Wrist", "limb-broad" };
		case LIMB::kRightArm1:
		case LIMB::kRightArm2:
			if (hasCollisionID(0x13)) {
				return { "R_Wrist", "R_Biceps", "collision-hand-candidate" };
			}
			if (hasCollisionID(0xb) && hasCollisionID(0xc)) {
				return { "R_Biceps", "R_Wrist", "collision-upper-candidate" };
			}
			return { "R_Biceps", "R_Wrist", "limb-broad" };
		case LIMB::kLeftFoot:
			return { "L_Foot", "L_Thigh", "limb-direct" };
		case LIMB::kRightFoot:
			return { "R_Foot", "R_Thigh", "limb-direct" };
		case LIMB::kLeftLeg1:
		case LIMB::kLeftLeg2:
		case LIMB::kLeftLeg3:
			if (hasCollisionIDs(0x4, 0xe)) {
				return { "L_Thigh", "L_Foot", "collision-upper-candidate" };
			}
			if (hasCollisionIDs(0x4, 0x7) || hasCollisionIDs(0x7, 0xd)) {
				return { "L_Foot", "L_Thigh", "collision-lower-candidate" };
			}
			return { "L_Thigh", "L_Foot", "limb-broad" };
		case LIMB::kRightLeg1:
		case LIMB::kRightLeg2:
		case LIMB::kRightLeg3:
			// Early empirical shotgun data shows right lower-leg hits involving ID 0x8.
			if (hasCollisionID(0x8)) {
				return { "R_Foot", "R_Thigh", "collision-lower-candidate" };
			}
			if (hasCollisionID(0x5)) {
				return { "R_Thigh", "R_Foot", "collision-upper-candidate" };
			}
			return { "R_Thigh", "R_Foot", "limb-broad" };
		case LIMB::kPelvis:
			return { "C_Spine", "C_Chest", "limb-broad" };
		case LIMB::kRoot:
			return { "Root", "C_Spine", "limb-direct" };
		case LIMB::kCom:
			return { "COM", "Root", "limb-direct" };
		case LIMB::kCamera:
			return { "Camera", "C_Head", "limb-direct" };
		default:
			return { "C_Spine", "C_Chest", "fallback" };
		}
	}

	struct ImpactRecord
	{
		std::int32_t id{ 0 };
		std::uint32_t targetFormID{ 0 };
		std::uint32_t projectileFormID{ 0 };
		std::uint32_t weaponFormID{ 0 };
		std::uint32_t ammoFormID{ 0 };
		std::uint32_t materialFormID{ 0 };
		std::int32_t damageLimb{ -1 };
		std::uint32_t collisionLayer{ 0 };
		std::uint32_t collisionIdA{ 0xFFFFFFFFu };
		std::uint32_t collisionIdB{ 0xFFFFFFFFu };
		RE::NiPoint3 position{};
		RE::NiPoint3 normal{};
		const char* node{ "" };
		const char* alternateNode{ "" };
		const char* confidence{ "" };
		bool actorSkin{ false };
	};

	constexpr std::uint32_t kActorSkinMaterialFormID = 0x00022954;
	constexpr std::size_t kImpactRecordBufferSize = 128;

	std::mutex g_impactRecordLock;
	std::array<ImpactRecord, kImpactRecordBufferSize> g_impactRecords{};
	std::uint32_t g_impactRecordWriteIndex{ 0 };
	std::atomic<std::int32_t> g_nextImpactRecordID{ 1 };

	[[nodiscard]] std::uint32_t SmallCollisionID(std::uintptr_t a_value)
	{
		return a_value <= 0xFFFFFFFFu ? static_cast<std::uint32_t>(a_value) : 0xFFFFFFFFu;
	}

	void StoreImpactRecord(
		const RE::Projectile* a_projectile,
		const RE::Projectile::ImpactData& a_impact,
		std::int32_t a_damageLimb,
		std::uintptr_t a_collisionIdA,
		std::uintptr_t a_collisionIdB,
		const PapyrusNodeGuess& a_nodeGuess)
	{
		if (!a_projectile) {
			return;
		}

		const auto* material = a_impact.materialType;
		ImpactRecord record{};
		record.id = g_nextImpactRecordID.fetch_add(1, std::memory_order_relaxed);
		record.targetFormID = a_impact.collidee;
		record.projectileFormID = FormIDOf(a_projectile);
		record.weaponFormID = FormIDOf(a_projectile->weaponSource.object);
		record.ammoFormID = FormIDOf(a_projectile->ammoSource);
		record.materialFormID = FormIDOf(material);
		record.damageLimb = a_damageLimb;
		record.collisionLayer = static_cast<std::uint32_t>(a_impact.collisionLayer.underlying());
		record.collisionIdA = SmallCollisionID(a_collisionIdA);
		record.collisionIdB = SmallCollisionID(a_collisionIdB);
		record.position = a_impact.location.position;
		record.normal = a_impact.normal;
		record.node = a_nodeGuess.primary;
		record.alternateNode = a_nodeGuess.alternate;
		record.confidence = a_nodeGuess.confidence;
		record.actorSkin = record.materialFormID == kActorSkinMaterialFormID;

		{
			std::scoped_lock lock(g_impactRecordLock);
			g_impactRecords[g_impactRecordWriteIndex++ % g_impactRecords.size()] = record;
		}
	}

	[[nodiscard]] std::optional<ImpactRecord> FindImpactRecord(std::int32_t a_impactID)
	{
		if (a_impactID <= 0) {
			return std::nullopt;
		}

		std::scoped_lock lock(g_impactRecordLock);
		for (const auto& record : g_impactRecords) {
			if (record.id == a_impactID) {
				return record;
			}
		}
		return std::nullopt;
	}

	[[nodiscard]] std::int32_t GetLatestImpactIdForTarget(std::monostate, RE::TESObjectREFR* a_target)
	{
		if (!a_target) {
			return 0;
		}

		const auto targetFormID = FormIDOf(a_target);
		std::int32_t latest = 0;
		std::scoped_lock lock(g_impactRecordLock);
		for (const auto& record : g_impactRecords) {
			if (record.actorSkin && record.targetFormID == targetFormID && record.id > latest) {
				latest = record.id;
			}
		}
		return latest;
	}

	[[nodiscard]] std::int32_t GetLatestAnyImpactIdForTarget(std::monostate, RE::TESObjectREFR* a_target)
	{
		if (!a_target) {
			return 0;
		}

		const auto targetFormID = FormIDOf(a_target);
		std::int32_t latest = 0;
		std::scoped_lock lock(g_impactRecordLock);
		for (const auto& record : g_impactRecords) {
			if (record.targetFormID == targetFormID && record.id > latest) {
				latest = record.id;
			}
		}
		return latest;
	}

	[[nodiscard]] bool IsImpactForTarget(std::monostate, std::int32_t a_impactID, RE::TESObjectREFR* a_target)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record && a_target && record->targetFormID == FormIDOf(a_target);
	}

	[[nodiscard]] bool IsImpactActorSkin(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->actorSkin : false;
	}

	[[nodiscard]] std::string GetImpactNode(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->node : "";
	}

	[[nodiscard]] std::string GetImpactAlternateNode(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->alternateNode : "";
	}

	[[nodiscard]] std::string GetImpactConfidence(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->confidence : "";
	}

	[[nodiscard]] std::int32_t GetImpactLimb(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->damageLimb : -1;
	}

	[[nodiscard]] std::int32_t GetImpactMaterialFormID(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? static_cast<std::int32_t>(record->materialFormID) : 0;
	}

	[[nodiscard]] float GetImpactPositionX(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->position.x : 0.0f;
	}

	[[nodiscard]] float GetImpactPositionY(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->position.y : 0.0f;
	}

	[[nodiscard]] float GetImpactPositionZ(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->position.z : 0.0f;
	}

	[[nodiscard]] float GetImpactNormalX(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->normal.x : 0.0f;
	}

	[[nodiscard]] float GetImpactNormalY(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->normal.y : 0.0f;
	}

	[[nodiscard]] float GetImpactNormalZ(std::monostate, std::int32_t a_impactID)
	{
		const auto record = FindImpactRecord(a_impactID);
		return record ? record->normal.z : 0.0f;
	}

	std::vector<std::unique_ptr<RE::BSScript::IFunction>> g_impactNativeFunctions;

	template <class Fn>
	bool BindImpactNative(RE::BSScript::IVirtualMachine& a_vm, std::string_view a_name, Fn a_fn)
	{
		std::unique_ptr<RE::BSScript::IFunction> function{
			new RE::BSScript::NativeFunction(
			"simultaneousinputimpact",
			a_name,
			a_fn,
			false)
		};
		auto* rawFunction = function.get();
		if (!a_vm.BindNativeMethod(rawFunction)) {
			REX::ERROR("Papyrus impact native bind failed: {}", a_name);
			return false;
		}

		g_impactNativeFunctions.push_back(std::move(function));
		return true;
	}

	void RegisterImpactPapyrusFunctions()
	{
		auto* gameVM = RE::GameVM::GetSingleton();
		auto* vm = gameVM ? gameVM->GetVM() : nullptr;
		if (!vm) {
			REX::ERROR("Papyrus impact native registration failed: GameVM/VM unavailable");
			++g_hooksSkipped;
			return;
		}

		bool ok = true;
		ok = BindImpactNative(*vm, "GetLatestImpactId", GetLatestImpactIdForTarget) && ok;
		ok = BindImpactNative(*vm, "GetLatestAnyImpactId", GetLatestAnyImpactIdForTarget) && ok;
		ok = BindImpactNative(*vm, "IsImpactForTarget", IsImpactForTarget) && ok;
		ok = BindImpactNative(*vm, "IsImpactActorSkin", IsImpactActorSkin) && ok;
		ok = BindImpactNative(*vm, "GetImpactNode", GetImpactNode) && ok;
		ok = BindImpactNative(*vm, "GetImpactAlternateNode", GetImpactAlternateNode) && ok;
		ok = BindImpactNative(*vm, "GetImpactConfidence", GetImpactConfidence) && ok;
		ok = BindImpactNative(*vm, "GetImpactLimb", GetImpactLimb) && ok;
		ok = BindImpactNative(*vm, "GetImpactMaterialFormID", GetImpactMaterialFormID) && ok;
		ok = BindImpactNative(*vm, "GetImpactPositionX", GetImpactPositionX) && ok;
		ok = BindImpactNative(*vm, "GetImpactPositionY", GetImpactPositionY) && ok;
		ok = BindImpactNative(*vm, "GetImpactPositionZ", GetImpactPositionZ) && ok;
		ok = BindImpactNative(*vm, "GetImpactNormalX", GetImpactNormalX) && ok;
		ok = BindImpactNative(*vm, "GetImpactNormalY", GetImpactNormalY) && ok;
		ok = BindImpactNative(*vm, "GetImpactNormalZ", GetImpactNormalZ) && ok;

		if (ok) {
			REX::INFO("Papyrus impact natives registered on simultaneousinputimpact");
			++g_hooksInstalled;
		} else {
			++g_hooksSkipped;
		}
	}

	[[nodiscard]] const char* FixedStringOrNone(const RE::BSFixedString& a_value)
	{
		const auto* value = a_value.c_str();
		return value && value[0] ? value : "<empty>";
	}

	[[nodiscard]] const char* FixedStringOrNone(const RE::BSFixedStringCS& a_value)
	{
		const auto* value = a_value.c_str();
		return value && value[0] ? value : "<empty>";
	}

	[[nodiscard]] RE::Actor* TryLookupActorByFormID(std::uint32_t a_formID)
	{
		if (a_formID == 0 || a_formID == 0xFFFFFFFF) {
			return nullptr;
		}

		if (auto* actor = RE::TESForm::LookupByID<RE::Actor>(a_formID)) {
			return actor;
		}

		// Projectile ImpactData stores a TESPointerHandle. For temporary refs,
		// the observed handle is the low 24 bits of the FFxxxxxx form ID.
		if ((a_formID & 0xFF000000) == 0) {
			return RE::TESForm::LookupByID<RE::Actor>(0xFF000000u | a_formID);
		}

		return nullptr;
	}

	void LogActorBodyPartRecord(
		std::uint32_t a_logIndex,
		const char* a_phase,
		const char* a_eventName,
		std::uint32_t a_targetID,
		std::int32_t a_damageLimb)
	{
		constexpr auto kTotalLimbs = static_cast<std::int32_t>(RE::BGSBodyPartDefs::LIMB_ENUM::kTotal);
		if (a_damageLimb < 0 || a_damageLimb >= kTotalLimbs) {
			return;
		}

		auto* actor = TryLookupActorByFormID(a_targetID);
		if (!actor) {
			REX::INFO(
				"impact-bodypart[{}:{}:{}]: targetID={:08X} tempFormID={:08X} damageLimb={}/'{}' actor=<lookup-failed>",
				a_logIndex,
				a_phase,
				a_eventName,
				a_targetID,
				0xFF000000u | a_targetID,
				a_damageLimb,
				LimbName(a_damageLimb));
			return;
		}

		const auto* npc = actor->GetNPC();
		const auto* race = npc ? npc->GetRace() : nullptr;
		const auto* bodyPartData = race ? race->bodyPartInfo.unk08 : nullptr;
		const auto* bodyPart = bodyPartData ? bodyPartData->parts[a_damageLimb] : nullptr;
		if (!bodyPart) {
			REX::INFO(
				"impact-bodypart[{}:{}:{}]: targetID={:08X} tempFormID={:08X} actor={:08X} npc={:08X} race={:08X} bodyPartData={:p} "
				"damageLimb={}/'{}' part=<missing>",
				a_logIndex,
				a_phase,
				a_eventName,
				a_targetID,
				0xFF000000u | a_targetID,
				FormIDOf(actor),
				FormIDOf(npc),
				FormIDOf(race),
				static_cast<const void*>(bodyPartData),
				a_damageLimb,
				LimbName(a_damageLimb));
			return;
		}

		REX::INFO(
			"impact-bodypart[{}:{}:{}]: targetID={:08X} tempFormID={:08X} actor={:08X} npc={:08X} race={:08X} bodyPartData={:p} part={:p} "
			"damageLimb={}/'{}' partLimb={} flags={:02X} "
			"hitReaction=(chainStart='{}' chainEnd='{}' variableX='{}' variableY='{}' variableZ='{}') "
			"strings=(unk70='{}' unk78='{}' unk80='{}' unk88='{}' unk90='{}')",
			a_logIndex,
			a_phase,
			a_eventName,
			a_targetID,
			0xFF000000u | a_targetID,
			FormIDOf(actor),
			FormIDOf(npc),
			FormIDOf(race),
			static_cast<const void*>(bodyPartData),
			static_cast<const void*>(bodyPart),
			a_damageLimb,
			LimbName(a_damageLimb),
			static_cast<std::int32_t>(bodyPart->limbEnum.underlying()),
			bodyPart->flags,
			FixedStringOrNone(bodyPart->hitReactionData.chainStart),
			FixedStringOrNone(bodyPart->hitReactionData.chainEnd),
			FixedStringOrNone(bodyPart->hitReactionData.variableX),
			FixedStringOrNone(bodyPart->hitReactionData.variableY),
			FixedStringOrNone(bodyPart->hitReactionData.variableZ),
			FixedStringOrNone(bodyPart->unk70),
			FixedStringOrNone(bodyPart->unk78),
			FixedStringOrNone(bodyPart->unk80),
			FixedStringOrNone(bodyPart->unk88),
			FixedStringOrNone(bodyPart->unk90));
	}

	RuntimeImpactTraceState& GetRuntimeImpactTraceState(RE::Projectile* a_projectile, const RE::Projectile::ImpactData* a_impact)
	{
		const auto projectile = reinterpret_cast<std::uintptr_t>(a_projectile);
		const auto impactData = reinterpret_cast<std::uintptr_t>(a_impact);
		const auto formID = FormIDOf(a_projectile);

		for (auto& state : g_runtimeImpactTraceStates) {
			if (state.projectile == projectile && state.impactData == impactData && state.projectileFormID == formID) {
				return state;
			}
		}

		auto& state = g_runtimeImpactTraceStates[g_runtimeImpactTraceCursor++ % g_runtimeImpactTraceStates.size()];
		state = RuntimeImpactTraceState{
			.projectile = projectile,
			.impactData = impactData,
			.projectileFormID = formID
		};
		return state;
	}

	ProjectileVirtualTraceHook* FindProjectileVirtualTraceHook(RE::Projectile* a_projectile)
	{
		if (!a_projectile) {
			return nullptr;
		}

		const auto vtable = *reinterpret_cast<std::uintptr_t*>(a_projectile);
		for (auto& hook : g_projectileVirtualTraceHooks) {
			if (hook.vtable == vtable) {
				return std::addressof(hook);
			}
		}
		return nullptr;
	}

	ProjectileUpdateTraceHook* FindProjectileUpdateTraceHook(RE::Projectile* a_projectile)
	{
		if (!a_projectile) {
			return nullptr;
		}

		const auto vtable = *reinterpret_cast<std::uintptr_t*>(a_projectile);
		for (auto& hook : g_projectileUpdateTraceHooks) {
			if (hook.vtable == vtable) {
				return std::addressof(hook);
			}
		}
		return nullptr;
	}

	void LogProjectileImpact(RE::Projectile* a_projectile, const RE::Projectile::ImpactData* a_impact)
	{
		if (!a_projectile || !a_impact) {
			return;
		}

		const auto logIndex = g_projectileImpactLogCount.fetch_add(1, std::memory_order_relaxed);
		if (logIndex >= kProjectileImpactLogLimit) {
			if (logIndex == kProjectileImpactLogLimit) {
				REX::INFO("impact-log: reached {} entries; suppressing further per-impact logs", kProjectileImpactLogLimit);
			}
			return;
		}

		const auto* material = a_impact->materialType;
		const auto* limbObj = a_projectile->targetLimbObj.get();
		const auto damageLimb = static_cast<std::int32_t>(a_impact->damageLimb.underlying());
		const auto* colObj = a_impact->colObj.get();
		std::uintptr_t collisionIdA = 0xFFFFFFFFFFFFFFFFull;
		std::uintptr_t collisionIdB = 0xFFFFFFFFFFFFFFFFull;
		if (colObj) {
			[[maybe_unused]] const auto readCollisionIdA = TryReadQword(colObj, 0x28, collisionIdA);
			[[maybe_unused]] const auto readCollisionIdB = TryReadQword(colObj, 0x58, collisionIdB);
		}
		const auto nodeGuess = GuessPapyrusNode(damageLimb, collisionIdA, collisionIdB);

		REX::INFO(
			"impact-log[{}]: projectile={:08X} shooterHandle={:08X} "
			"targetHandle={:08X} weapon={:08X} ammo={:08X} "
			"pos=({:.3f},{:.3f},{:.3f}) normal=({:.3f},{:.3f},{:.3f}) "
			"material={:08X}/'{}' damageLimb={}/'{}' collisionLayer={} resultOverride={} shapeKey={:08X} "
			"papyrusNode='{}' alternateNode='{}' nodeConfidence='{}' colIDs={:#x}/{:#x} "
			"decalSize={:.3f} targetWorldObject={}/{} processed={} spellCast={} effectSpawned={} backFace={} "
			"targetLimbObj={:p} impactPtr={:p} colObj={:p}",
			logIndex,
			FormIDOf(a_projectile),
			a_projectile->shooterHandle,
			a_impact->collidee,
			FormIDOf(a_projectile->weaponSource.object),
			FormIDOf(a_projectile->ammoSource),
			a_impact->location.position.x,
			a_impact->location.position.y,
			a_impact->location.position.z,
			a_impact->normal.x,
			a_impact->normal.y,
			a_impact->normal.z,
			FormIDOf(material),
			material ? material->materialName.c_str() : "<none>",
			damageLimb,
			LimbName(damageLimb),
			static_cast<std::int32_t>(a_impact->collisionLayer.underlying()),
			static_cast<std::int32_t>(a_impact->resultOverride.underlying()),
			a_impact->collisionShapeKey,
			nodeGuess.primary,
			nodeGuess.alternate,
			nodeGuess.confidence,
			collisionIdA,
			collisionIdB,
			a_impact->decalSize,
			a_impact->targetWorldObjectIndex,
			a_impact->targetWorldObjectCount,
			a_impact->processed,
			a_impact->spellCast,
			a_impact->effectSpawned,
			a_impact->backFace,
			static_cast<const void*>(limbObj),
			static_cast<const void*>(a_impact),
			static_cast<const void*>(colObj));

		LogActorBodyPartRecord(logIndex, "impact-hook", "direct", a_impact->collidee, damageLimb);
	}

	void LogRuntimeProjectileImpactArray(RE::Projectile* a_projectile, const char* a_phase)
	{
		if (!a_projectile) {
			return;
		}

		const auto base = reinterpret_cast<std::uintptr_t>(a_projectile);
		const auto count = *reinterpret_cast<const std::uint32_t*>(base + 0xD8);
		const auto* data = *reinterpret_cast<RE::Projectile::ImpactData* const*>(base + 0xE0);
		if (count == 0 || !data) {
			return;
		}

		const auto& impact = data[0];
		const auto* material = impact.materialType;
		const auto* limbObj = *reinterpret_cast<RE::NiAVObject* const*>(base + 0x1E0);
		auto& state = GetRuntimeImpactTraceState(a_projectile, std::addressof(impact));

		const auto firstSeen = !state.seenInitial;
		const auto processedTransition = impact.processed && !state.seenProcessed;
		const auto effectSpawnedTransition = impact.effectSpawned && !state.seenEffectSpawned;
		if (!firstSeen && !processedTransition && !effectSpawnedTransition) {
			return;
		}

		const auto* eventName = firstSeen ? "first-seen" : (processedTransition ? "processed" : "effect-spawned");
		state.seenInitial = true;
		if (processedTransition) {
			++state.processedTransitions;
		}
		state.seenProcessed = state.seenProcessed || impact.processed;
		state.seenEffectSpawned = state.seenEffectSpawned || impact.effectSpawned;

		const auto damageLimb = static_cast<std::int32_t>(impact.damageLimb.underlying());
		const auto* colObj = impact.colObj.get();
		std::uintptr_t collisionIdA = 0xFFFFFFFFFFFFFFFFull;
		std::uintptr_t collisionIdB = 0xFFFFFFFFFFFFFFFFull;
		if (colObj) {
			[[maybe_unused]] const auto readCollisionIdA = TryReadQword(colObj, 0x28, collisionIdA);
			[[maybe_unused]] const auto readCollisionIdB = TryReadQword(colObj, 0x58, collisionIdB);
		}
		const auto nodeGuess = GuessPapyrusNode(damageLimb, collisionIdA, collisionIdB);
		const auto logIndex = g_projectileImpactLogCount.fetch_add(1, std::memory_order_relaxed);
		if (logIndex >= kProjectileImpactLogLimit) {
			if (logIndex == kProjectileImpactLogLimit) {
				REX::INFO("impact-log: reached {} entries; suppressing further per-impact logs", kProjectileImpactLogLimit);
			}
			return;
		}

		REX::INFO(
			"impact-array[{}:{}:{}]: projectile={:08X} shooterHandle={:08X} count={} data={:p} "
			"targetHandle={:08X} weapon={:08X} ammo={:08X} "
			"pos=({:.3f},{:.3f},{:.3f}) normal=({:.3f},{:.3f},{:.3f}) "
			"material={:08X}/'{}' damageLimb={}/'{}' collisionLayer={} resultOverride={} shapeKey={:08X} "
			"papyrusNode='{}' alternateNode='{}' nodeConfidence='{}' colIDs={:#x}/{:#x} "
			"decalSize={:.3f} targetWorldObject={}/{} processed={} spellCast={} effectSpawned={} backFace={} "
			"targetLimbObj={:p} colObj={:p} processedTransitions={}",
			logIndex,
			a_phase,
			eventName,
			FormIDOf(a_projectile),
			*reinterpret_cast<const std::uint32_t*>(base + 0x180),
			count,
			static_cast<const void*>(data),
			impact.collidee,
			FormIDOf(a_projectile->weaponSource.object),
			FormIDOf(a_projectile->ammoSource),
			impact.location.position.x,
			impact.location.position.y,
			impact.location.position.z,
			impact.normal.x,
			impact.normal.y,
			impact.normal.z,
			FormIDOf(material),
			material ? material->materialName.c_str() : "<none>",
			damageLimb,
			LimbName(damageLimb),
			static_cast<std::int32_t>(impact.collisionLayer.underlying()),
			static_cast<std::int32_t>(impact.resultOverride.underlying()),
			impact.collisionShapeKey,
			nodeGuess.primary,
			nodeGuess.alternate,
			nodeGuess.confidence,
			collisionIdA,
			collisionIdB,
			impact.decalSize,
			impact.targetWorldObjectIndex,
			impact.targetWorldObjectCount,
			impact.processed,
			impact.spellCast,
			impact.effectSpawned,
			impact.backFace,
			static_cast<const void*>(limbObj),
			static_cast<const void*>(colObj),
			state.processedTransitions);

		if (firstSeen) {
			StoreImpactRecord(a_projectile, impact, damageLimb, collisionIdA, collisionIdB, nodeGuess);
		}

		LogActorBodyPartRecord(logIndex, a_phase, eventName, impact.collidee, damageLimb);

		if (colObj) {
			const auto colVtable = ReadQword(colObj, 0x00);
			const auto bodyA = ReadQword(colObj, 0x10);
			const auto bodyB = ReadQword(colObj, 0x40);
			REX::INFO(
				"impact-colobj[{}:{}:{}]: projectile={:08X} colObj={:p} vtable={:#x} vtableRVA={:#x} "
				"q08={:#x} q10={:#x} q18={:#x} q20={:#x} q28={:#x} q30={:#x} q38={:#x} q40={:#x} "
				"q48={:#x} q50={:#x} q58={:#x}",
				logIndex,
				a_phase,
				eventName,
				FormIDOf(a_projectile),
				static_cast<const void*>(colObj),
				colVtable,
				RvaOf(colVtable),
				ReadQword(colObj, 0x08),
				bodyA,
				ReadQword(colObj, 0x18),
				ReadQword(colObj, 0x20),
				ReadQword(colObj, 0x28),
				ReadQword(colObj, 0x30),
				ReadQword(colObj, 0x38),
				bodyB,
				ReadQword(colObj, 0x48),
				ReadQword(colObj, 0x50),
				ReadQword(colObj, 0x58));
			LogCollisionBodyRecord(logIndex, a_phase, eventName, "q10", reinterpret_cast<const void*>(bodyA));
			LogCollisionBodyRecord(logIndex, a_phase, eventName, "q40", reinterpret_cast<const void*>(bodyB));
		}
	}

	void ProcessProjectileImpactEffectHook(RE::Projectile* a_projectile, RE::Projectile::ImpactData* a_impact)
	{
		LogProjectileImpact(a_projectile, a_impact);

		if (g_processProjectileImpactEffect) {
			g_processProjectileImpactEffect(a_projectile, a_impact);
		}
	}

	void MissileProjectileUpdateHook(RE::Projectile* a_projectile, float a_delta)
	{
		LogRuntimeProjectileImpactArray(a_projectile, "pre-update");
		if (g_missileProjectileUpdate) {
			g_missileProjectileUpdate(a_projectile, a_delta);
		}
		LogRuntimeProjectileImpactArray(a_projectile, "post-update");
	}

	void RuntimeProjectileUpdateHook(RE::Projectile* a_projectile, float a_delta)
	{
		auto* hook = FindProjectileUpdateTraceHook(a_projectile);
		const auto* hookName = hook ? hook->name : "unknown-update-vtable";
		LogRuntimeProjectileImpactArray(a_projectile, hookName);
		if (hook && hook->original) {
			hook->original(a_projectile, a_delta);
		}
		LogRuntimeProjectileImpactArray(a_projectile, hookName);
	}

	void LogRuntimeImpactProcessProbe(RE::Projectile* a_projectile, const char* a_phase, bool a_flag, bool a_result)
	{
		if (!a_projectile) {
			return;
		}

		const auto logIndex = g_runtimeImpactProcessTraceCount.fetch_add(1, std::memory_order_relaxed);
		if (logIndex >= 128) {
			if (logIndex == 128) {
				REX::INFO("runtime-impact-process: reached 128 entries; suppressing further probe logs");
			}
			return;
		}

		const auto base = reinterpret_cast<std::uintptr_t>(a_projectile);
		const auto count = *reinterpret_cast<const std::uint32_t*>(base + 0xD8);
		const auto* data = *reinterpret_cast<const std::byte* const*>(base + 0xE0);
		const auto processed = data ? static_cast<unsigned>(data[0x6C]) : 0xFFu;

		REX::INFO(
			"runtime-impact-process[{}:{}]: projectile={:08X} this={:p} vtable={:#x} flag={} result={} "
			"weapon={:08X} ammo={:08X} count={} data={:p} firstProcessed={}",
			logIndex,
			a_phase,
			FormIDOf(a_projectile),
			static_cast<const void*>(a_projectile),
			*reinterpret_cast<const std::uintptr_t*>(a_projectile),
			a_flag,
			a_result,
			FormIDOf(a_projectile->weaponSource.object),
			FormIDOf(a_projectile->ammoSource),
			count,
			static_cast<const void*>(data),
			processed);
	}

	bool RuntimeImpactProcessHook(RE::Projectile* a_projectile, bool a_flag)
	{
		const auto result = g_runtimeImpactProcess ? g_runtimeImpactProcess(a_projectile, a_flag) : false;

		LogRuntimeImpactProcessProbe(a_projectile, "post", a_flag, result);
		LogRuntimeProjectileImpactArray(a_projectile, "runtime-post");
		return result;
	}

	std::uintptr_t ProjectileVirtualTraceHookFn(RE::Projectile* a_projectile, void* a_arg)
	{
		auto* hook = FindProjectileVirtualTraceHook(a_projectile);
		auto* original = hook ? hook->original : g_projectileVirtualTraceHooks.front().original;

		const auto logIndex = g_projectileVirtualTraceLogCount.fetch_add(1, std::memory_order_relaxed);
		if (logIndex < 64 && a_projectile) {
			const auto base = reinterpret_cast<std::uintptr_t>(a_projectile);
			const auto* limbObj = *reinterpret_cast<RE::NiAVObject* const*>(base + 0x1E0);
			REX::INFO(
				"projectile-vslot[{}]: class={} projectile={:08X} this={:p} arg={:p} "
				"vtable={:#x} "
				"shooterHandle={:08X} weapon={:08X} ammo={:08X} "
				"d8={:08X} e0={:p} e8={:p} f0={:p} targetLimbObj={:p}/'{}'",
				logIndex,
				hook ? hook->name : "<unknown>",
				FormIDOf(a_projectile),
				static_cast<const void*>(a_projectile),
				a_arg,
				*reinterpret_cast<const std::uintptr_t*>(a_projectile),
				*reinterpret_cast<const std::uint32_t*>(base + 0x180),
				FormIDOf(a_projectile->weaponSource.object),
				FormIDOf(a_projectile->ammoSource),
				*reinterpret_cast<const std::uint32_t*>(base + 0xD8),
				*reinterpret_cast<void* const*>(base + 0xE0),
				*reinterpret_cast<void* const*>(base + 0xE8),
				*reinterpret_cast<void* const*>(base + 0xF0),
				static_cast<const void*>(limbObj),
				NameOf(limbObj));
		}

		if (!original) {
			return 0;
		}
		return original(a_projectile, a_arg);
	}

	class HitEventTraceSink final : public RE::BSTEventSink<HitTraceTESHitEvent>
	{
	public:
		RE::BSEventNotifyControl ProcessEvent(const HitTraceTESHitEvent& a_event, RE::BSTEventSource<HitTraceTESHitEvent>*) override
		{
			const auto logIndex = g_hitEventLogCount.fetch_add(1, std::memory_order_relaxed);
			if (logIndex >= 256) {
				if (logIndex == 256) {
					REX::INFO("hit-event: reached 256 entries; suppressing further TESHitEvent logs");
				}
				return RE::BSEventNotifyControl::kContinue;
			}

			const auto& hit = a_event.hitData;
			const auto& impact = hit.impactData;
			const auto damageLimb = static_cast<std::int32_t>(hit.damageLimb.underlying());
			const auto* colObj = impact.colObj.get();

			REX::INFO(
				"hit-event[{}]: usesHitData={} targetRef={:08X} causeRef={:08X} material='{}' "
				"sourceForm={:08X} projectileForm={:08X} aggressorHandle={:08X} targetHandle={:08X} "
				"sourceRefHandle={:08X} weapon={:08X} ammo={:08X} damageLimb={}/'{}' "
				"pos=({:.3f},{:.3f},{:.3f}) normal=({:.3f},{:.3f},{:.3f}) velocity=({:.3f},{:.3f},{:.3f}) colObj={:p}",
				logIndex,
				a_event.usesHitData,
				FormIDOf(a_event.target.get()),
				FormIDOf(a_event.cause.get()),
				a_event.material.c_str(),
				a_event.sourceFormID,
				a_event.projectileFormID,
				HandleValue(hit.aggressor),
				HandleValue(hit.target),
				HandleValue(hit.sourceRef),
				FormIDOf(hit.weapon),
				FormIDOf(hit.ammo),
				damageLimb,
				LimbName(damageLimb),
				impact.location.x,
				impact.location.y,
				impact.location.z,
				impact.normal.x,
				impact.normal.y,
				impact.normal.z,
				impact.velocity.x,
				impact.velocity.y,
				impact.velocity.z,
				static_cast<const void*>(colObj));

			if (colObj) {
				const auto colVtable = ReadQword(colObj, 0x00);
				REX::INFO(
					"hit-event-colobj[{}]: colObj={:p} vtable={:#x} vtableRVA={:#x} "
					"q08={:#x} q10={:#x} q18={:#x} q20={:#x} q28={:#x} q30={:#x} q38={:#x} q40={:#x} "
					"q48={:#x} q50={:#x} q58={:#x}",
					logIndex,
					static_cast<const void*>(colObj),
					colVtable,
					RvaOf(colVtable),
					ReadQword(colObj, 0x08),
					ReadQword(colObj, 0x10),
					ReadQword(colObj, 0x18),
					ReadQword(colObj, 0x20),
					ReadQword(colObj, 0x28),
					ReadQword(colObj, 0x30),
					ReadQword(colObj, 0x38),
					ReadQword(colObj, 0x40),
					ReadQword(colObj, 0x48),
					ReadQword(colObj, 0x50),
					ReadQword(colObj, 0x58));
			}

			return RE::BSEventNotifyControl::kContinue;
		}
	};

	HitEventTraceSink g_hitEventTraceSink;

	void RegisterHitEventTraceSink()
	{
		using GetEventSource_t = RE::BSTEventSource<HitTraceTESHitEvent>*();
		REL::Relocation<GetEventSource_t*> getEventSource{ kTESHitEventGetEventSourceID };
		if (auto* source = getEventSource()) {
			source->RegisterSink(std::addressof(g_hitEventTraceSink));
			REX::INFO("TESHitEvent trace sink registered");
			++g_hooksInstalled;
		} else {
			REX::ERROR("TESHitEvent trace sink registration failed: event source is null");
			++g_hooksSkipped;
		}
	}

	void InstallProjectileImpactHooks()
	{
		for (auto& hook : g_projectileUpdateTraceHooks) {
			try {
				REL::Relocation<std::uintptr_t> vtbl{ REL::Offset(hook.vtableRVA) };
				hook.vtable = vtbl.address();
				const auto original = *reinterpret_cast<std::uintptr_t*>(hook.vtable + (kRuntimeProjectileUpdateSlot * sizeof(void*)));
				hook.original = reinterpret_cast<MissileProjectileUpdate_t*>(
					vtbl.write_vfunc(kRuntimeProjectileUpdateSlot, RuntimeProjectileUpdateHook));
				REX::INFO(
					"projectile update trace installed: {} slot {:#x} (vtable rva {:#x}, original rva {:#x})",
					hook.name,
					kRuntimeProjectileUpdateSlot,
					hook.vtableRVA,
					RvaOf(original));
				++g_hooksInstalled;
			} catch (const std::exception& ex) {
				REX::ERROR("{} update trace hook failed: {}", hook.name, ex.what());
				++g_hooksSkipped;
			}
		}
	}
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

// Retired engine predicate wrapper. The 1.16.236 AL ID that earlier tooling
// selected for this is not a predicate, so do not dispatch through it.
bool IsUsingGamepad(RE::BSInputDeviceManager* a_inputDeviceManager)
{
	(void)a_inputDeviceManager;
	return false;
}

// Latched state set by the LookHandler vtable shim below. True when the most
// recent QLook event came from a thumbstick; false when it came from MouseMove.
// This is the core of the mod: the engine treats look input as a single-source
// stream, but we split it on event type so mouse and gamepad coexist.
//
// Input dispatch can run on multiple threads, while the redirected sensitivity
// predicates may be called on a different one. Keep this atomic so button /
// trigger clears and mouse-look clears are visible immediately everywhere.
static std::atomic_bool UsingThumbstickLook{ false };

// The engine has a global byte at RVA 0x5F67820 in Starfield 1.16.236 that
// many code paths inline-check to decide "is gamepad the active input mode."
// (Verified via IDA xref scan — 145 read sites across the binary, including
// inside the original LookHandler::CanHandle implementation we replaced.)
//
// The maintainer's IsUsingGamepad-replacement strategy was supposed to flip
// this decision per-event by hooking call sites of a predicate function, but
// the deriver tool mis-identified the predicate function (the 4 hooked sites
// actually call BSStringPool::Entry::Release, a refcount cleanup, not a
// predicate). The predicate has been INLINED into all 145 callers as a direct
// `cmp cs:byte_145F67820, 0` — there's no single function to hook.
//
// Workaround: mirror the UsingThumbstickLook latch into this byte from the
// vtable shim. Every inlined check then reads our intended state for the
// event currently being processed. Gives true per-event sensitivity scaling
// without needing to find each inlined check.
static std::atomic<std::uint8_t*> g_gamepadActiveFlag{ nullptr };

static constexpr std::uintptr_t kGamepadActiveFlagRVA = 0x5F67820;
static constexpr DWORD kPageReadWrite = 0x04;

// Resolve byte_145F67820's runtime address and make its page writable.
// Idempotent — call once during SFSEPlugin_Load.
static void InitGamepadActiveFlag()
{
	HMODULE main_module = GetModuleHandleA(nullptr);
	if (!main_module) {
		REX::WARN("gamepad-flag mirror: GetModuleHandleA(NULL) returned null; skipped");
		return;
	}
	auto addr = reinterpret_cast<std::uint8_t*>(
		reinterpret_cast<std::uintptr_t>(main_module) + kGamepadActiveFlagRVA);
	DWORD old_prot = 0;
	if (VirtualProtect(addr, 1, kPageReadWrite, &old_prot)) {
		*addr = 0;
		UsingThumbstickLook.store(false, std::memory_order_relaxed);
		g_gamepadActiveFlag.store(addr, std::memory_order_relaxed);
		REX::INFO("gamepad-flag mirror: byte_145F67820 at {:p} now writable and initialized to 0 (was prot=0x{:X})",
			static_cast<void*>(addr), old_prot);
	} else {
		REX::WARN("gamepad-flag mirror: VirtualProtect failed for {:p}; skipping",
			static_cast<void*>(addr));
	}
}

static void ClearGamepadActiveFlag()
{
	if (auto* flag = g_gamepadActiveFlag.load(std::memory_order_relaxed)) {
		*flag = 0;
	}
}

static void SetGamepadActiveFlag()
{
	if (auto* flag = g_gamepadActiveFlag.load(std::memory_order_relaxed)) {
		*flag = 1;
	}
}

static constexpr std::uintptr_t kInputValueHelperRVA = 0x22FE890;
using InputValueHelper_t = void(void*, std::uint32_t, float, float, float);

static std::atomic<std::uint32_t> g_triggerActiveClearCount{ 0 };

void TriggerInputValueHelper(void* a_device, std::uint32_t a_id, float a_time, float a_previous, float a_value)
{
	REL::Relocation<InputValueHelper_t> original{ REL::Offset(kInputValueHelperRVA) };
	original(a_device, a_id, a_time, a_previous, a_value);

	if (a_device && (a_id == 9 || a_id == 10)) {
		auto* deviceBytes = static_cast<std::uint8_t*>(a_device);
		if (deviceBytes[9] == static_cast<std::uint8_t>(RE::InputEvent::DeviceType::kGamepad)) {
			deviceBytes[8] = 0;
			UsingThumbstickLook.store(false, std::memory_order_relaxed);
			ClearGamepadActiveFlag();

			const auto count = g_triggerActiveClearCount.fetch_add(1, std::memory_order_relaxed);
			if (count < 8) {
				REX::INFO(
					"trigger active-device clear: gamepad helper id={} value={:.3f} previous={:.3f}",
					a_id,
					a_value,
					a_previous);
			}
		}
	}
}

// Drop-in replacement for IsUsingGamepad in look-related call sites. The
// original engine code uses "is current device the gamepad" to switch
// sensitivity curves, quadrant-fix, and window-cursor capture. For our
// purposes those code paths should key off "is the user currently looking
// with the stick", not "did the user touch the stick at all".
bool IsUsingThumbstickLook(RE::BSInputDeviceManager*)
{
	return UsingThumbstickLook.load(std::memory_order_relaxed);
}

static constexpr std::uintptr_t kControlMapDataModelUpdateRVA = 0x255F2E0;
static constexpr std::uintptr_t kPlatformDataModelUpdateRVA = 0x2560490;

using ControlMapDataModelUpdate_t = void(void*);
using PlatformDataModelUpdate_t = void(void*);
using UIValueNotify_t = void(void*, bool);

static std::atomic<std::uint32_t> g_controlMapGlyphLockCount{ 0 };
static std::atomic<std::uint32_t> g_platformGlyphLockCount{ 0 };
static constexpr std::uint32_t    kGamepadPlatform = 1;

// ControlMapDataModel publishes PlatformData.uPlatform and ControlMapData to
// Scaleform menus. While it updates, force the UI-only active-device decision
// to gamepad, then restore the gameplay byte so camera sensitivity stays on
// the per-event mirror.
void ControlMapDataModelUpdateForGlyphLock(void* a_model)
{
	if (g_lockControllerGlyphs.load(std::memory_order_relaxed)) {
		const auto count = g_controlMapGlyphLockCount.fetch_add(1, std::memory_order_relaxed);
		if (count < 8) {
			REX::INFO("glyph lock: ControlMapDataModel update forced gamepad UI data");
		}

		auto* modelBytes = static_cast<std::uint8_t*>(a_model);
		const auto* flag = g_gamepadActiveFlag.load(std::memory_order_relaxed);
		const std::uint8_t oldFlag = flag ? *flag : 0;
		modelBytes[0x18] = 1;
		if (flag) {
			*const_cast<std::uint8_t*>(flag) = 1;
		}

		REL::Relocation<ControlMapDataModelUpdate_t> original{ REL::Offset(kControlMapDataModelUpdateRVA) };
		original(a_model);

		if (flag) {
			*const_cast<std::uint8_t*>(flag) = oldFlag;
		}
		return;
	}

	REL::Relocation<ControlMapDataModelUpdate_t> original{ REL::Offset(kControlMapDataModelUpdateRVA) };
	original(a_model);
}

// PlatformDataModel publishes the coarser "PC keyboard/mouse vs PC gamepad"
// platform value. Some menu reloads refresh this model after ControlMapData,
// so pin it as well or a load transition can overwrite controller glyph data
// with keyboard layout until the process restarts.
void PlatformDataModelUpdateForGlyphLock(void* a_model)
{
	REL::Relocation<PlatformDataModelUpdate_t> original{ REL::Offset(kPlatformDataModelUpdateRVA) };
	original(a_model);

	if (!g_lockControllerGlyphs.load(std::memory_order_relaxed)) {
		return;
	}

	const auto count = g_platformGlyphLockCount.fetch_add(1, std::memory_order_relaxed);
	if (count < 8) {
		REX::INFO("glyph lock: PlatformDataModel update forced gamepad platform");
	}

	auto* modelBytes = static_cast<std::uint8_t*>(a_model);
	auto* platformUiValueSource = modelBytes + 0x30;
	const auto sourceVtable = *reinterpret_cast<std::uintptr_t**>(platformUiValueSource);
	const auto getUiValue = reinterpret_cast<void* (*)(void*)>(sourceVtable[0x58 / sizeof(void*)]);
	auto* platformUiValue = getUiValue(platformUiValueSource);
	if (!platformUiValue) {
		return;
	}

	auto* platform = reinterpret_cast<std::uint32_t*>(static_cast<std::uint8_t*>(platformUiValue) + 0x18);
	if (*platform == kGamepadPlatform) {
		return;
	}

	*platform = kGamepadPlatform;
	const auto valueVtable = *reinterpret_cast<std::uintptr_t**>(platformUiValue);
	const auto notify = reinterpret_cast<UIValueNotify_t*>(valueVtable[0x48 / sizeof(void*)]);
	notify(platformUiValue, true);
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
	(void)a_inputDeviceManager;

	if (g_lockControllerGlyphs.load(std::memory_order_relaxed)) {
		return true;
	}
	return UsingThumbstickLook.load(std::memory_order_relaxed);
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

	template <std::size_t N, class F>
	bool TryWriteCallAt(
		std::uintptr_t              a_address,
		F                           a_dst,
		std::string_view            a_label,
		const std::source_location& a_loc = std::source_location::current())
	{
		try {
			if (!REL::Pattern<"E8">().match(a_address)) {
				REX::WARN(
					"hook '{}' skipped: rva {:#x} did not start with E8 (call). "
					"function was refactored on this runtime.",
					a_label,
					a_address - REX::FModule::GetExecutingModule().GetBaseAddress());
				++g_hooksSkipped;
				return false;
			}
			REL::GetTrampoline().write_call<N>(a_address, a_dst);
			REX::INFO(
				"hook '{}' installed: rva {:#x} -> {:#x}",
				a_label,
				a_address - REX::FModule::GetExecutingModule().GetBaseAddress(),
				a_address);
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
					const auto holdStr = TrimWs(val);
					auto [p, ec] = std::from_chars(
						holdStr.data(), holdStr.data() + holdStr.size(), ms);
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
	// Trampoline budget: each call replacement consumes branch-pool space.
	// 160 bytes covers the four trigger helper calls, two cursor calls, and
	// the temporary projectile trace hooks with margin. The 1.8.86-era
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
		.trampolineSize = 160,
	});
	LogRuntimeProbe(a_sfse);

	// Read SimultaneousInput.ini next to the DLL and apply the
	// LockControllerGlyphs override (auto-detect on Steam Deck if enabled).
	// Must run before any cursor hook fires so IsGamepadCursor sees the
	// final flag state on its first invocation.
	LoadConfig(a_sfse);

	// Resolve byte_145F67820's runtime address and make its page writable.
	// The LookHandler vtable shim mirrors UsingThumbstickLook into this
	// byte for per-event sensitivity scaling. See the comment on
	// g_gamepadActiveFlag for why this is the actual fix for the per-event
	// look-sensitivity decision (the maintainer's predicate-replacement
	// hooks target a refcount Release function, not a predicate).
	InitGamepadActiveFlag();

	// First milestone for the hit-location work: trace the native projectile
	// impact effect/decal path while the runtime ImpactData record is still
	// live. This keeps raw NiAVObject pointers frame-local and copies only
	// IDs/names into the log for validation.
	InstallProjectileImpactHooks();

	// Defer Papyrus native registration to kPostDataLoad — at SFSEPlugin_Load
	// time the GameVM singleton is still null, so RegisterImpactPapyrusFunctions
	// must run after the engine has finished bringing the VM up. Confirmed in
	// Starfield 1.16.236: registering at load time produces
	// "Papyrus impact native registration failed: GameVM/VM unavailable" and
	// no natives bind. kPostDataLoad fires after data files load and the VM
	// has bound vanilla scripts, which is the right window to add ours.
	if (auto* messaging = SFSE::GetMessagingInterface()) {
		messaging->RegisterListener([](SFSE::MessagingInterface::Message* a_msg) {
			if (a_msg && a_msg->type == SFSE::MessagingInterface::kPostDataLoad) {
				REX::INFO("SFSE message kPostDataLoad received; registering Papyrus impact natives");
				RegisterImpactPapyrusFunctions();
			}
		});
		REX::INFO("Papyrus impact native registration deferred to kPostDataLoad");
	} else {
		REX::ERROR("SFSE messaging interface unavailable; falling back to immediate native registration (will likely fail)");
		RegisterImpactPapyrusFunctions();
	}

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
				// Slot 1 is correct (verified in IDA: dispatcher at
				// Starfield.exe+0x22DD3F0 does `mov rax,[rcx]; call [rax+8]`).
				//
				// We CANNOT call `event->QUserEvent()` here: it returns
				// BSFixedString by value, BSFixedString has a non-trivial
				// dtor (refcount), so MSVC emits struct-return-via-hidden-arg
				// at the call site, but the engine's QUserEvent returns
				// in rax. The ABI mismatch crashed the engine on the first
				// mouse click (rsi=0xFFFFFFFF in [rsi+10h]).
				//
				// Instead we read IDEvent::strUserEvent directly from offset
				// 0x28 (no virtual call). MouseMove/Thumbstick events are
				// IDEvents in this engine, so the cast is safe. BSFixedString
				// equality is a leaf-pointer compare — no string content
				// access, no allocations.
				static const RE::BSFixedString kLookEvent{ "Look" };

				if (event->eventType != RE::InputEvent::EventType::kMouseMove &&
					event->eventType != RE::InputEvent::EventType::kThumbstick) {
					if (event->deviceType == RE::InputEvent::DeviceType::kGamepad &&
						event->eventType == RE::InputEvent::EventType::kButton) {
						const auto* button = static_cast<const RE::ButtonEvent*>(event);
						const char* cur = button->strUserEvent.c_str();
						UsingThumbstickLook.store(false, std::memory_order_relaxed);
						ClearGamepadActiveFlag();
						static thread_local const char* s_lastButtonUE = nullptr;
						static thread_local float s_lastButtonValue = -1.0f;
						if (cur != s_lastButtonUE || button->value != s_lastButtonValue) {
							REX::INFO(
								"shim: cleared look mirror for gamepad button userEvent='{}' value={:.3f} held={:.3f}",
								cur ? cur : "<null>",
								button->value,
								button->heldDownSecs);
							s_lastButtonUE = cur;
							s_lastButtonValue = button->value;
						}
					}
					return false;
				}

				const auto* idevent = static_cast<const RE::IDEvent*>(event);
				if (idevent->strUserEvent != kLookEvent) {
					// Analog trigger events are also surfaced as kThumbstick
					// IDEvents, but they are not camera-look events. If one
					// arrives while the last real look event was right-stick,
					// the gamepad sensitivity mirror can stay latched until a
					// keyboard movement event makes the engine pick KBM again.
					// Clear the mirror here, but still return false so the
					// LookHandler does not consume the trigger/button event.
					if (event->eventType == RE::InputEvent::EventType::kThumbstick) {
						static thread_local const char* s_lastUE = nullptr;
						const char* cur = idevent->strUserEvent.c_str();
						UsingThumbstickLook.store(false, std::memory_order_relaxed);
						ClearGamepadActiveFlag();
						if (cur != s_lastUE) {
							const auto* raw = reinterpret_cast<const std::byte*>(event);
							const float x = *reinterpret_cast<const float*>(raw + 0x38);
							const float y = *reinterpret_cast<const float*>(raw + 0x3C);
							REX::INFO("shim: cleared look mirror for non-Look kThumbstick userEvent='{}' x={:.3f} y={:.3f}",
								cur ? cur : "<null>", x, y);
							s_lastUE = cur;
						}
					}
					return false;
				}

				// DIAG (L2 sensitivity hunt): log writes to byte_145F67820
				// only on transition. Drop this once L2 fix lands.
				static thread_local int s_lastWrite = -1;

				if (event->eventType == RE::InputEvent::EventType::kMouseMove) {
					UsingThumbstickLook.store(false, std::memory_order_relaxed);
					ClearGamepadActiveFlag();
					if (s_lastWrite != 0) {
						REX::INFO("shim/diag: WRITE 0 (mouseMove userEvent=Look) [prev={}]", s_lastWrite);
						s_lastWrite = 0;
					}
				} else {
					// Only latch UsingThumbstickLook=true when the stick has
					// meaningful magnitude. The engine sends a final zero-
					// valued thumbstick event when the user releases the stick;
					// if we latched on that, UsingThumbstickLook would stay
					// true after release.
					//
					// ThumbstickEvent layout (verified in IDA via slot 4
					// OnThumbstickEvent at sub_1412BCC30 reading floats from
					// [rdx+38h] and [rdx+3Ch]): xValue at 0x38, yValue at 0x3C.
					const auto* raw = reinterpret_cast<const std::byte*>(event);
					const float xValue = *reinterpret_cast<const float*>(raw + 0x38);
					const float yValue = *reinterpret_cast<const float*>(raw + 0x3C);
					if (xValue != 0.0f || yValue != 0.0f) {
						UsingThumbstickLook.store(true, std::memory_order_relaxed);
						SetGamepadActiveFlag();
						if (s_lastWrite != 1) {
							REX::INFO("shim/diag: WRITE 1 (thumbstick Look x={:.3f} y={:.3f}) [prev={}]",
								xValue, yValue, s_lastWrite);
							s_lastWrite = 1;
						}
					} else {
						UsingThumbstickLook.store(false, std::memory_order_relaxed);
						ClearGamepadActiveFlag();
						if (s_lastWrite != 0) {
							REX::INFO("shim/diag: WRITE 0 (zero thumbstick Look x={:.3f} y={:.3f}) [prev={}]",
								xValue, yValue, s_lastWrite);
							s_lastWrite = 0;
						}
					}
				}
				return true;
			});
		REX::INFO("vtable shim installed: LookHandler slot 1");
		++g_hooksInstalled;
	} catch (const std::exception& ex) {
		REX::ERROR("vtable shim failed: {}", ex.what());
		++g_hooksSkipped;
	}

	// === Direct byte patch: stop sticks from claiming the device ===
	// Inside BSPCGamepadDevice poll/update paths the engine writes 1 to a byte
	// indicating "stick moved -> active device is gamepad". On 1.16.236 IDA
	// shows two paths with two direct writes apiece:
	//   Poll         +0x51D / +0x5DC
	//   ExtendedPoll +0x409 / +0x4A8
	// We NOP every occurrence so stick polling does not overwrite the
	// per-event byte mirror maintained by the LookHandler vtable shim.
	// Pattern: C6 43 08 01  (mov byte ptr [rbx+8], 1)
	try {
		constexpr std::size_t kScanLimit = 0x800;
		std::size_t           patched = 0;

		auto patchPollPath = [&](REL::Relocation<std::uintptr_t> head, const char* name) {
			const std::uint8_t* p = reinterpret_cast<const std::uint8_t*>(head.address());
			std::size_t pathPatched = 0;
			for (std::size_t i = 0; i + 4 <= kScanLimit; ++i) {
				if (p[i] == 0xC6 && p[i + 1] == 0x43 && p[i + 2] == 0x08 && p[i + 3] == 0x01) {
					REL::Relocation<std::uintptr_t> hook(head.address() + i);
					hook.write_fill(REL::NOP, 0x4);
					REX::INFO("byte patch installed: {} +{:#x}", name, i);
					++pathPatched;
					i += 3;  // skip past this match
				}
			}
			return pathPatched;
		};

		patched += patchPollPath(
			REL::Relocation<std::uintptr_t>(RE::Offset::BSPCGamepadDevice::Poll),
			"BSPCGamepadDevice::Poll");
		patched += patchPollPath(
			REL::Relocation<std::uintptr_t>(RE::Offset::BSPCGamepadDevice::ExtendedPoll),
			"BSPCGamepadDevice::ExtendedPoll");

		if (patched > 0) {
			++g_hooksInstalled;
			REX::INFO("byte patch summary: NOPed {} gamepad active-device write(s)", patched);
		} else {
			REX::WARN(
				"byte patch skipped: gamepad poll active-device anchor 'C6 43 08 01' "
				"not found in first {:#x} bytes of Poll AL id {} (rva {:#x}) or "
				"ExtendedPoll rva {:#x}; function may have been refactored further. "
				"thumbsticks will still device-switch.",
				kScanLimit,
				RE::Offset::BSPCGamepadDevice::Poll.id(),
				RE::Offset::BSPCGamepadDevice::Poll.offset(),
				RE::Offset::BSPCGamepadDevice::ExtendedPoll.offset());
			++g_hooksSkipped;
		}
	} catch (const std::exception& ex) {
		REX::ERROR("BSPCGamepadDevice::Poll patch failed: {}", ex.what());
		++g_hooksSkipped;
	}

	// === Trigger helper call replacements ===
	// LT/RT are generated through the shared input value helper with IDs 9/10.
	// Let the engine create the ButtonEvent normally, then clear only the
	// gamepad device active byte so SecondaryAttack does not leave mouse look
	// on the gamepad sensitivity path until a keyboard event arrives.
	try {
		REL::Relocation<std::uintptr_t> pollHead(RE::Offset::BSPCGamepadDevice::Poll);
		REL::Relocation<std::uintptr_t> extendedHead(RE::Offset::BSPCGamepadDevice::ExtendedPoll);

		TryWriteCallAt<5>(
			pollHead.address() + 0x3AC,
			TriggerInputValueHelper,
			"BSPCGamepadDevice::Poll LT helper");
		TryWriteCallAt<5>(
			pollHead.address() + 0x3DC,
			TriggerInputValueHelper,
			"BSPCGamepadDevice::Poll RT helper");
		TryWriteCallAt<5>(
			extendedHead.address() + 0x325,
			TriggerInputValueHelper,
			"BSPCGamepadDevice::ExtendedPoll LT helper");
		TryWriteCallAt<5>(
			extendedHead.address() + 0x34D,
			TriggerInputValueHelper,
			"BSPCGamepadDevice::ExtendedPoll RT helper");
	} catch (const std::exception& ex) {
		REX::ERROR("trigger helper hook setup failed: {}", ex.what());
		++g_hooksSkipped;
	}

	// === UI control-map data replacement ===
	// ControlMapDataModel::Update publishes PlatformData.uPlatform and the
	// mapped button events consumed by Starfield's Scaleform menu button bars.
	// Pin only this UI data model to gamepad when glyph lock is enabled.
	try {
		REL::Relocation<std::uintptr_t> vtbl{ REL::Offset(0x4D83688) };
		vtbl.write_vfunc(1, ControlMapDataModelUpdateForGlyphLock);
		REX::INFO("vtable shim installed: ControlMapDataModel update slot 1");
		++g_hooksInstalled;
	} catch (const std::exception& ex) {
		REX::ERROR("ControlMapDataModel update hook failed: {}", ex.what());
		++g_hooksSkipped;
	}
	try {
		REL::Relocation<std::uintptr_t> vtbl{ REL::Offset(0x4D837B0) };
		vtbl.write_vfunc(1, PlatformDataModelUpdateForGlyphLock);
		REX::INFO("vtable shim installed: PlatformDataModel update slot 1");
		++g_hooksInstalled;
	} catch (const std::exception& ex) {
		REX::ERROR("PlatformDataModel update hook failed: {}", ex.what());
		++g_hooksSkipped;
	}

	// === Retired look-input call replacements ===
	// IDA verification showed the alleged 1.16.236 look predicate at
	// RVA 0x28CEF30 is a BSStringPool-style refcount cleanup routine
	// (lock cmpxchg/xadd + WakeByAddressAll), not a boolean predicate.
	// Replacing those calls with IsUsingThumbstickLook skips cleanup and has
	// no useful return value at the call sites. For look scaling, rely on the
	// byte_145F67820 event mirror instead and leave those calls untouched.

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
