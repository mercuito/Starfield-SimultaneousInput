# Starfield Hit Impact Location Handoff

Last updated: 2026-05-09

This repo has an in-progress SFSE/Papyrus feature for exposing native projectile hit-impact data to scripts. The goal is to let Papyrus/PAPER attach an effect/emitter to a useful actor skeleton node, because vanilla `OnHit` does not provide impact position, hit bone, collision object, or attached decal data.

## Current Environment

- Repo: `D:\IDA\work\fork`
- Plugin source: `D:\IDA\work\fork\src\export\SFSEPlugin.cpp`
- Deployed plugin folder: `F:\Steam\steamapps\common\Starfield\Data\SFSE\Plugins`
- Main plugin log: `C:\Users\jackp\OneDrive\Documents\My Games\Starfield\SFSE\Logs\SimultaneousInput.log`
- CommonLibSF checkout is `libxse/CommonLibSF`, not the older Starfield-Reverse-Engineering fork.
- Current runtime tested: Starfield `1.16.236.0`, SFSE `0.2.19`.

Important caveat: this work was done in a dirty worktree that also contains unrelated SimultaneousInput changes. Do not blindly revert `src/export/SFSEPlugin.cpp`.

## High-Level Approach

The native hook captures projectile impact data before Papyrus sees anything. Script then polls a native buffer for the latest impact for a specific actor/reference.

We intentionally did **not** start from vanilla Papyrus `OnHit`. The useful data is in the projectile impact/decal path, specifically the runtime impact array on `RuntimeShotProjectile`.

The first script-facing implementation is polling, not pushed events:

- Native hook stores copied impact records in a small ring buffer.
- Papyrus script passes `Self`/actor reference into a native function.
- Native code returns the latest impact ID for that target.
- Script gets the node string and calls `ObjectReference.PlayImpactEffect(...)`.

This avoids calling Papyrus events directly from projectile/update hook context and avoids retaining raw NiAVObject or collision pointers after the native frame.

## Native Hook Status

Working hook:

- RuntimeShotProjectile vtable RVA: `0x4CCDC58`
- Hooked slot: `0x13A`
- Original function RVA observed: `0x1B09AA0`
- Hook function in source: `RuntimeProjectileUpdateHook`
- Impact array logger/source helper: `LogRuntimeProjectileImpactArray`

Observed runtime layout for this path:

- projectile `this + 0xD8`: impact count
- projectile `this + 0xE0`: `Projectile::ImpactData*` data pointer
- first impact record is enough for shotgun testing
- `ImpactData::processed` and `effectSpawned` transition from false to true later, so records should only be buffered on the first-seen state to avoid duplicate script IDs

Current code stores a record only when `eventName == first-seen`.

Other attempted paths:

- Direct hooks around candidate impact functions were noisy/risky.
- TESHitEvent sink registration was attempted earlier and caused fatal startup error. Do not re-enable without re-verifying the real event source.
- Address Library guesses in this repo have been stale before. Example: AL `139340` / RVA `0x28CEF30` was not `IsUsingGamepad`; it was BSStringPool-style refcount cleanup. Verify offsets with IDA/bytes before using them.

## Data Available In Impact Records

Useful fields captured from runtime `ImpactData` and projectile:

- target handle/form-like ID (`impact.collidee`)
- projectile form ID
- weapon form ID
- ammo form ID
- material form ID/name
- damage limb enum
- collision layer
- collision object pointer, used only during the native frame
- collision object qwords at offsets `0x28` and `0x58`, copied as small collision IDs when they are small integers
- world impact position
- world normal
- Papyrus node guess
- alternate node guess
- confidence string

Do not retain raw collision object / NiAVObject pointers in buffered script records.

Important material finding:

- NPC flesh hits consistently use material form `00022954`, name `ActorSkin`.
- Gear/backpack/armor-like hits can use other materials, e.g. `ActorMetal`, `MetalHollow`, `Dirt`.
- Script API currently has:
  - `GetLatestImpactId(ObjectReference akTarget)` returns only latest ActorSkin impact.
  - `GetLatestAnyImpactId(ObjectReference akTarget)` returns latest impact regardless of material, useful for debugging.

## Script-Side Attachment Target

The concrete Papyrus call target is:

```papyrus
ObjectReference.PlayImpactEffect(
    ImpactDataSet akImpactEffect,
    string asNodeName = "",
    float afPickDirX = 0.0,
    float afPickDirY = 0.0,
    float afPickDirZ = -1.0,
    float afPickLength = 512.0,
    bool abApplyNodeRotation = false,
    bool abUseNodeLocalRotation = false
) native
```

Useful human skeleton node names confirmed from local body part data / testing:

- `C_Head`
- `C_Neck`
- `C_Chest`
- `C_Spine`
- `L_Biceps`
- `L_Wrist`
- `R_Biceps`
- `R_Wrist`
- `L_Thigh`
- `L_Foot`
- `R_Thigh`
- `R_Foot`
- `Root`
- `Camera`

For lower legs/knees/calves, there does not appear to be a clean Papyrus node target in the known set, so the current fallback maps lower leg to foot nodes.

## Confirmed Collision-To-Node Mapping

Mapping is implemented in `GuessPapyrusNode(...)` in `SFSEPlugin.cpp`.

General rule:

- Use `damageLimb` first for broad body region.
- Refine broad arms/legs using copied collision IDs from collision object qwords `q28` and `q58`.
- Treat collision ID order as unordered for known pair checks where appropriate.
- Prefer ActorSkin hits for body effects.

Confirmed mapping table from shotgun testing on human NPCs:

| Region tested | Native limb | Collision IDs | Script node |
|---|---:|---:|---|
| Head | `Head1` | `0x10 / pointer` | `C_Head` |
| Torso/chest | `Torso` | examples `0x6/0x3`, `0x3/pointer` | `C_Spine`, alt `C_Chest` |
| Back | `Torso` | `0x3/0x1` | `C_Spine`, alt `C_Chest` |
| Pelvis/hip-ish | sometimes `None` or `Torso` | examples `0x2/pointer`, `0x1/0xd` | `C_Spine` fallback |
| Left hand/wrist | `LeftArm1` | contains `0x12` | `L_Wrist` |
| Left upper arm/bicep | `LeftArm1` | contains `0x9` | `L_Biceps` |
| Right hand/wrist | `RightArm1` | contains `0x13`, often `0x13/0x0` or `0x13/pointer` | `R_Wrist` |
| Right upper arm/bicep | `RightArm1` | `0xb/0xc`, later `0xb/0x11` also seen as upper arm | `R_Biceps` |
| Left thigh | `LeftLeg1` | `0x4/0xe` | `L_Thigh` |
| Left calf/knee/lower leg | `LeftLeg1` | `0x4/0x7`, `0x7/0x4`, `0x7/0xd` | `L_Foot` fallback |
| Left foot | `LeftFoot` | `0xd/0x1`, `0xd/0x7` | `L_Foot` |
| Right thigh / upper leg | `RightLeg1` | contains `0x5` and not `0x8`, examples `0x5/0x2`, `0x5/pointer` | `R_Thigh` |
| Right calf/knee/lower leg | `RightLeg1` | contains `0x8`, examples `0x8/0x5`, `0x8/0xe` | `R_Foot` fallback |
| Right foot | `RightFoot` | `0xe/0x8` | `R_Foot` |

Current deployed mapper, after the latest tested pass, produced expected nodes for:

- head -> `C_Head`
- left hand -> `L_Wrist`
- right hand -> `R_Wrist`
- right bicep -> `R_Biceps`
- torso -> `C_Spine`
- left foot -> `L_Foot`
- right foot -> `R_Foot`
- left thigh -> `L_Thigh`
- right thigh -> `R_Thigh`
- pelvis/back -> `C_Spine`

The only bad datapoints in the final mixed test were intentional/accidental misses hitting non-ActorSkin material, such as `MetalHollow`.

## Native Papyrus API Added

The source now contains a copied `ImpactRecord` ring buffer and these global native functions. The current binding name is lower-case because Starfield's compiler emitted lower-case script names during local testing:

```papyrus
ScriptName simultaneousinputimpact Native Hidden

int Function GetLatestImpactId(ObjectReference akTarget) global native
int Function GetLatestAnyImpactId(ObjectReference akTarget) global native
bool Function IsImpactForTarget(int aiImpactId, ObjectReference akTarget) global native
bool Function IsImpactActorSkin(int aiImpactId) global native
string Function GetImpactNode(int aiImpactId) global native
string Function GetImpactAlternateNode(int aiImpactId) global native
string Function GetImpactConfidence(int aiImpactId) global native
int Function GetImpactLimb(int aiImpactId) global native
int Function GetImpactMaterialFormID(int aiImpactId) global native
float Function GetImpactPositionX(int aiImpactId) global native
float Function GetImpactPositionY(int aiImpactId) global native
float Function GetImpactPositionZ(int aiImpactId) global native
float Function GetImpactNormalX(int aiImpactId) global native
float Function GetImpactNormalY(int aiImpactId) global native
float Function GetImpactNormalZ(int aiImpactId) global native
```

Expected log line on startup:

```text
Papyrus impact natives registered on simultaneousinputimpact
```

If this line is missing, verify the plugin loaded and `RegisterImpactPapyrusFunctions()` ran.

## Test Script Concept

The test route is a constant Ability spell with a Script magic effect. The script extends `ActiveMagicEffect` and polls the native API for the target actor.

Example script shape:

```papyrus
ScriptName nativeimpacteffecttest Extends ActiveMagicEffect

ImpactDataSet Property TestImpactEffect Auto
float Property PollSeconds = 0.10 Auto

Actor TargetActor
int LastImpactId = 0

Event OnEffectStart(Actor akTarget, Actor akCaster)
    TargetActor = akTarget
    RegisterForSingleUpdate(PollSeconds)
EndEvent

Event OnUpdate()
    if TargetActor
        int id = simultaneousinputimpact.GetLatestImpactId(TargetActor)

        if id > 0 && id != LastImpactId
            LastImpactId = id

            string nodeName = simultaneousinputimpact.GetImpactNode(id)
            Debug.Trace("nativeimpacteffecttest impact id=" + id + " node=" + nodeName)

            if TestImpactEffect && nodeName != ""
                TargetActor.PlayImpactEffect(TestImpactEffect, nodeName)
            endif
        endif

        RegisterForSingleUpdate(PollSeconds)
    endif
EndEvent
```

Creation Kit flow:

1. Create/compile native declaration script `simultaneousinputimpact.psc`.
2. Create/compile effect script `nativeimpacteffecttest.psc`.
3. Create a Magic Effect with archetype/script behavior appropriate for `ActiveMagicEffect`.
4. Attach `nativeimpacteffecttest` to the Magic Effect.
5. Fill `TestImpactEffect`.
6. Create an Ability spell with that Magic Effect.
7. Add the Ability to a test NPC.
8. Launch through SFSE and shoot the NPC.

## Papyrus Compiler Notes

This local CK/compiler setup had missing pieces:

- `Starfield_Papyrus_Flags.flg` was absent, so a minimal one was added at:
  `F:\Steam\steamapps\common\Starfield\Data\Scripts\Source\Starfield_Papyrus_Flags.flg`
- The install did not include base `.psc` sources like `ScriptObject.psc`, `Actor.psc`, `Quest.psc`, etc. `Starfield - Misc.ba2` contained `.pex`, not `.psc`.
- A local compile-stub folder was added for just enough types to compile the test scripts:
  `F:\Steam\steamapps\common\Starfield\Data\Scripts\Source\CompileStubs`
- The compiler behaved badly with mixed-case script names in `User\`; lower-case script filenames and lower-case `ScriptName` worked reliably:
  - `simultaneousinputimpact.psc`
  - `nativeimpacteffecttest.psc`

Direct compiler path:

```powershell
F:\Steam\steamapps\common\Starfield\Tools\Papyrus Compiler\PapyrusCompiler.exe
```

Working direct compile pattern:

```powershell
& 'F:\Steam\steamapps\common\Starfield\Tools\Papyrus Compiler\PapyrusCompiler.exe' 'nativeimpacteffecttest.psc' `
  -i='F:\Steam\steamapps\common\Starfield\Data\Scripts\Source\CompileStubs;F:\Steam\steamapps\common\Starfield\Data\Scripts\Source;F:\Steam\steamapps\common\Starfield\Data\Scripts\Source\User' `
  -o='F:\Steam\steamapps\common\Starfield\Data\Scripts' `
  -f='F:\Steam\steamapps\common\Starfield\Data\Scripts\Source\Starfield_Papyrus_Flags.flg'
```

Current compiled test outputs at the time of handoff:

- `F:\Steam\steamapps\common\Starfield\Data\Scripts\simultaneousinputimpact.pex`
- `F:\Steam\steamapps\common\Starfield\Data\Scripts\nativeimpacteffecttest.pex`

If CK's add-script dialog does not show the test script, check for lower-case `nativeimpacteffecttest`, clear the filter, restart CK, and confirm the script is being added to a Magic Effect, not directly to an Actor.

## Current Known Risks / TODO

- Verify the lower-case native binding in-game after a fresh launch:
  - `SimultaneousInput.log` should contain `Papyrus impact natives registered on simultaneousinputimpact`.
- Verify the Magic Effect script can actually call all native functions and that the VM resolves lower-case script name consistently.
- If `PlayImpactEffect` does not visually spawn anything, isolate whether the issue is:
  - native API not returning node,
  - `ImpactDataSet` selection,
  - Magic Effect script not running,
  - or `PlayImpactEffect` semantics.
- The ring buffer currently matches impacts by `targetFormID == FormIDOf(akTarget)`. If temporary reference handles differ from form IDs for some actors, this may need a more robust handle-to-ref mapping.
- The hook currently captures the working shotgun path best. Some weapons did not fire this path during earlier tests. Additional hooks may be needed for other projectile classes/weapon paths.
- Material filtering currently hardcodes `ActorSkin` form ID `00022954`.
- Collision ID mapping is empirical for human NPCs. Creatures/robots/aliens will need separate mapping or fallback behavior.
- Polling every `0.10` seconds is fine for test, but production should expose configurable update interval or use a quest/alias manager to reduce script cost.

## Build / Deploy

Build:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe' --build build --config Release
```

Deploy:

```powershell
Copy-Item -LiteralPath 'D:\IDA\work\fork\build\Release\SimultaneousInput.dll' -Destination 'F:\Steam\steamapps\common\Starfield\Data\SFSE\Plugins\SimultaneousInput.dll' -Force
Copy-Item -LiteralPath 'D:\IDA\work\fork\build\Release\SimultaneousInput.pdb' -Destination 'F:\Steam\steamapps\common\Starfield\Data\SFSE\Plugins\SimultaneousInput.pdb' -Force
```

If Starfield is running, copying the DLL will fail because it is locked. Close the game before deploy.
