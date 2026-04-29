# Maintaining SimultaneousInput across Starfield patches

Whenever Bethesda ships a Starfield patch, the typical failure mode is one of:

1. SFSE itself isn't compatible with the new runtime yet. Wait for SFSE.
2. SFSE updated, but the plugin's declared layout bit doesn't match what
   SFSE expects. Symptom: SFSE Plugin Loader logs
   `SimultaneousInput.dll: disabled, incompatible with current version`.
3. SFSE accepts the plugin, but one or more Address Library IDs now point
   at a refactored function. Symptom: `hook ... skipped` lines in
   `SimultaneousInput.log`, and the corresponding behavior is broken
   in-game (look sensitivity wrong, cursor stuck, reticle off, etc.).

This document is the recipe for diagnosing and fixing each.

## 1. Check SFSE first

Open `sfse.log` after launching the game once. The header lines say which
runtime SFSE supports and which runtime it observed. If SFSE itself rejects
the runtime, there is nothing to do here; wait for an SFSE update.

## 2. Layout-bit mismatch (recompile only)

If `sfse.log` says "disabled, incompatible with current version" specifically
for `SimultaneousInput.dll`, the layout bit in the plugin's
`SFSEPluginVersionData` doesn't match what SFSE wants. The fix is almost
always: rebuild against the current `CommonLibSF` HEAD, which gets the new
bit definition automatically.

Steps:

```bash
cd external/CommonLibSF
git fetch origin
git checkout origin/main
cd ../..
git add external/CommonLibSF
git commit -m "Bump CommonLibSF to <short-sha>"
git push
```

Watch the `build` workflow in GitHub Actions. Download the artifact and
deploy. If SFSE still rejects, check whether CommonLibSF's
`SFSE/Interfaces.h` updated its `IsLayoutDependent` bit comment ("1 << N is
for runtime ..."); if N changed, the plugin metadata setter call already
follows it. No code change needed.

## 3. AL ID refactoring (the real work)

When `SimultaneousInput.log` shows `hook 'XYZ' skipped: AL id 12345 +0xNN
did not start with E8 (call). function may have been refactored on this
runtime.`, that hook is stale.

To investigate:

1. Get a copy of `versionlib-1-15-216.bin` (or whatever runtime applies)
   from the Address Library mod's release page on Nexus.
2. Convert it to a CSV with one of the public tools, or use the PDB for
   that runtime if you have access.
3. Locate the function the AL ID used to point at. Cross-reference its
   name in CommonLibSF source or Ghidra.
4. Find the new ID for the same function in the current runtime's AL
   database (search by demangled name or by signature).
5. Update the corresponding `constexpr REL::ID` in `src/RE/Offset.Ext.h`,
   leaving a comment explaining why the ID changed and what runtime that
   applies to.
6. Verify the byte-pattern guard (e.g. `REL::Pattern<"E8">`) still matches
   at the new offset. If not, the function may have been rewritten in a
   way that changes the call shape (inlined, devirtualized, etc.) and a
   different patch site is needed. That's a Ghidra job; out of scope for
   a routine maintenance pass.

Reverse-engineering steps requiring Ghidra are explicitly out of scope
for the per-patch loop. If a hook reaches that point, surface the affected
function name in an issue or commit message and let a human take it.

## 4. Adding new hooks

If a future patch breaks a behavior we don't currently hook (e.g. some new
input pipeline), the pattern is:

1. Add a `constexpr REL::ID` in `src/RE/Offset.Ext.h` with a header comment
   explaining what the function does and why we hook it.
2. Add a `TryWriteCall<5>(...)` (or `safe_fill` / `write_vfunc`) call in
   `src/export/SFSEPlugin.cpp` inside `SFSEPlugin_Load`. Each hook should
   be guarded so a single failure logs and skips, never crashes the host.
3. If the new hook is a trampoline call, bump `SFSE::AllocTrampoline(N)`.
   The current 28 bytes covers 7 hooks at 5 bytes each (with reuse).
4. Bump the plugin version in `CMakeLists.txt` (`project(... VERSION x.y.z)`).
   Patch bump for additive hook fixes; minor for new hook coverage; major
   for any change in metadata or interface.
5. Update the compatibility matrix row in `README.md`.

## 5. Triggering a CI build manually

The workflow runs on every push, so the normal flow is just `git push`.
For a manual rerun without a code change, use `workflow_dispatch` from
the Actions tab on GitHub. The artifact is named
`SimultaneousInput-<sha>` and contains the DLL + PDB.

## 6. Derivation tooling

`tools/al_db_parser.py` is a self-contained Python module that parses the
Address Library v5 binary (the same `versionlib-*.bin` SFSE loads at runtime)
and the Starfield PE. It supports forward and reverse RVA lookup, function
end heuristics anchored on neighboring AL IDs, simple thunk following, and
E8 call enumeration. Run it with `--probe` against a local copy of the runtime
to dump per-hook diagnostics:

```
pip install --break-system-packages lief
python3 tools/al_db_parser.py \
    --db /path/to/versionlib-1-16-236-0.bin \
    --exe /path/to/Starfield.exe \
    --probe
```

`tools/derive_function_ids.ps1` is the older PowerShell variant. Both target
format-5 ALDBs; v0/v1/v2 (legacy AE-style) are out of scope.

## 7. Status against Starfield 1.16.236

A full re-derivation pass against 1.16.236 started in v1.3.0. IDA later showed
that several of the apparent look predicate call sites were false positives:
they target string-pool/refcount cleanup, not an `IsUsingGamepad` predicate.
Those call replacements are now retired. The current build relies on the
LookHandler vtable shim, cursor call replacements, and narrow gamepad poll
patches instead. The re-derivation was driven by
`tools/derive_function_ids.py`, a 0x6000-byte E8 scan of every host function
(`tools/derived_1.16.236.json`), and IDA inspection of the relevant input
device functions.

Two predicate variants now exist on 1.16.236, where 1.8.86 had only one:

- Formerly suspected look variant `IsUsingGamepad`: RVA 0x28cef30, AL
  **139340**. IDA verification showed this is a BSStringPool-style refcount
  cleanup routine (`lock cmpxchg` / `lock xadd` / `WakeByAddressAll`), not a
  boolean predicate. Do not redirect calls to it.
- Cursor variant: RVA 0x2c4b50, AL 35982. Called from the cursor hosts
  (IMenu::ShowCursor, UI::SetCursorStyle). We do not call this AL ID
  directly; the cursor hooks rewrite their existing `call rel32` to point at
  our `IsGamepadCursor`, which keys off the local `UsingThumbstickLook` latch
  and the LockControllerGlyphs override.

| Hook | AL ID | 1.16.236 status |
|---|---|---|
| LookHandler vtable shim (slot 1)         | 433589 | installed; vtable layout preserved, AL re-anchored via libxse `IDs_VTABLE.h`, verified in-game on v1.2.0 |
| BSPCGamepadDevice poll byte patch        | 124384 + RVA 0x2302390 | installed; AL 124384 is the public poll thunk/body path and RVA 0x2302390 is the adjacent extended poll/update path found in IDA. The plugin scans both first 0x800 bytes for `C6 43 08 01` and NOPs direct `[device+8] = 1` stick-active writes. |
| BSPCGamepadDevice LT/RT helper calls     | 124384 + RVA 0x2302390 | installed; four call sites for trigger IDs 9/10 are redirected to `TriggerInputValueHelper`, which lets the engine create LT/RT events normally and then clears the gamepad device active byte. This fixes the L2/SecondaryAttack mouse-sensitivity latch. |
| LookHandler::Func10 E8 site              | 129152 | retired. The previous +0x196 target calls RVA 0x28CEF30, which IDA shows is cleanup/refcount code, not a predicate. |
| Manager::ProcessLookInput E8 site        | 129407 thunk, real body RVA 0x24E9F20 | retired. AL 129407 resolves to a 12-byte thunk on 1.16.236; the earlier 129407+0x33F landed in neighboring sub_1424E6620, and the later absolute RVA experiment still targeted non-predicate code. |
| Main::Run_WindowsMessageLoop E8 site     | 149028 | retired. Host body is 24 KB with 775 E8 calls and zero target the predicate; cursor-capture branch was either inlined into the message handler or moved to a different function. AL ID retained for diagnostic purposes only; no TryWriteCall is attempted. |
| ShipHudDataModel::PerformInputProcessing pre  | 137087 | retired. Previous offsets target the same non-predicate cleanup routine. |
| ShipHudDataModel::PerformInputProcessing post | 137087 | retired. Previous offsets target the same non-predicate cleanup routine. |
| IMenu::ShowCursor E8 site                | 187256 | installed at +0xA1 (was +0x14). Host is unchanged across the refactor; 7 calls to the cursor predicate, first at +0xA1. (An earlier attempt migrated to AL 42816 from a libxse vtable read; that AL resolves to a tiny 8-byte getter, not ShowCursor. Reverted.) |
| UI::SetCursorStyle E8 site               | 187051 | installed at +0x4CE (was +0x98). 11 calls to the cursor predicate; we hook the first. |
| BSInputDeviceManager::IsUsingGamepad     | 139340 | not used. Old AL 178879 resolves to a logging stub, and AL 139340 is not a predicate. |

Expected runtime: 8 hooks installed: LookHandler vtable shim, one combined
gamepad poll byte patch, four LT/RT helper call replacements, and the two
cursor call replacements. Run_WindowsMessageLoop remains retired; in-game
impact is that the OS cursor may be confined to the window whenever a
controller is plugged in, which is the engine's default and what 1.16.236
vanilla already does.

### L2 / SecondaryAttack sensitivity latch

Symptom: after pressing L2 / `SecondaryAttack`, mouse look sensitivity becomes
extremely high or otherwise wrong until a keyboard movement key is pressed.
Pressing WASD resets the behavior.

The root cause is not `byte_145F67820` / `UsingThumbstickLook`. Runtime logs
showed mouse look events writing 0 to that mirror and L2 clearing it; no
thumbstick-look WRITE 1 occurred immediately before the bug. IDA instead
showed that LT/RT input generation flows through the shared value helper at
RVA 0x22FE890 (`sub_1422FE890`). That helper creates/updates the input event
and unconditionally marks the source device active with:

```asm
1422fe970  mov byte ptr [rbx+8], 1
```

For gamepad LT (`id == 9`) and RT (`id == 10`), that side effect leaves the
gamepad device active after the trigger event. The next mouse-look event can
then be processed while downstream code still sees the gamepad as the active
input device. Keyboard movement fixes the symptom because keyboard input
claims active-device state again.

The fix is deliberately narrow. Do not detour `sub_1422FE890` globally: it is
shared by keyboard, mouse, buttons, triggers, and analog paths, and an earlier
diagnostic detour crashed because the prologue contains AVX instructions that
must not be cut mid-instruction. Instead, patch only the LT/RT call sites in
the two gamepad poll paths:

- `BSPCGamepadDevice::Poll` LT/RT helper calls at `+0x3AC` and `+0x3DC`
- `BSPCGamepadDevice::ExtendedPoll` LT/RT helper calls at `+0x325` and `+0x34D`

`TriggerInputValueHelper` calls the original helper so `SecondaryAttack` still
works, then clears `[gamepadDevice + 0x8]`, `UsingThumbstickLook`, and the
global mirror for trigger IDs 9/10 only. This preserves normal event delivery
while preventing trigger events from leaving mouse look on the gamepad-active
sensitivity path.

If a future patch shifts these offsets again, re-run
`tools/derive_function_ids.py --exe <Starfield.exe> --db <versionlib.bin>`
and re-derive against the resulting `derived_<ver>.json`. The byte-pattern
scan for BSPCGamepadDevice::Poll is the most resilient pattern; the others
need offset updates but the AL IDs should stay stable across minor patches.

## 8. Config: LockControllerGlyphs (v1.4.0+)

`SimultaneousInput.ini` lives next to the DLL. Four keys, all optional;
in-source defaults preserve v1.3.0 behavior, the shipped
`dist/SimultaneousInput.ini` template flips `LockControllerGlyphs` to
`true` because that template is the one we ship for the streaming-host
use case.

```ini
[Display]
LockControllerGlyphs   = false           ; default; pin glyphs to gamepad branch when true
LockGlyphsHotkey       = VK_F8           ; runtime toggle via keyboard
LockGlyphsChord        = LB+RB+DPadDown  ; runtime toggle via gamepad
LockGlyphsChordHoldMs  = 500             ; clamped [50, 5000]
```

The flag short-circuits `IsGamepadCursor()` (in
`src/export/SFSEPlugin.cpp`) to always return `true`, which is what the
trampolined call sites at `IMenu::ShowCursor +0xA1` and
`UI::SetCursorStyle +0x4CE` invoke. The camera-side hooks
(`LookHandler::Func10`, `ProcessLookInput`,
`ShipHud::PerformInputProcessing`, plus the LookHandler vtable shim)
still call `IsUsingThumbstickLook()` for their own decisions, so
simultaneous mouse + gamepad camera control is unaffected.

**Why the manual flag is the primary mechanism (no Steam Deck
auto-detect):** Tony's primary use case is streaming Starfield from a
host PC to a Steam Deck via Steam Remote Play / MoonDeck. The game runs
on the host, not the Deck, so the host process has no Deck-specific
signal to detect. Steam Input emulates an Xbox controller end-to-end and
the host sees only generic gamepad events. An earlier draft tried
`SteamDeck=1` env auto-detection; it was dropped because it never fires
in the streaming setup. If you want auto-behavior in some future
Deck-native variant, add a separate detection path; do not assume the
env var alone is sufficient.

**Runtime toggles (hotkey + chord):** one detached background thread
polls both signals every 50 ms.

- KBM hotkey: `GetAsyncKeyState(vk) & 0x8000` for "currently down".
  Rising-edge detection flips `g_lockControllerGlyphs` and writes a
  `[I]` log line. Avoid `SetWindowsHookEx` (per-keypress latency on
  every thread) and `RegisterHotKey` (forces a message pump).
- Gamepad chord: `XInputGetState(0, &state)`. Steam Input always
  presents as controller 0; we don't iterate 1..3 because Tony only
  uses one controller. The chord is satisfied when ALL required
  buttons are down AND any required triggers are above
  `XINPUT_GAMEPAD_TRIGGER_THRESHOLD` (30 / 255 ~= 12%). We track when
  the chord was first satisfied; once held continuously for >=
  `LockGlyphsChordHoldMs`, we toggle and latch (no repeats until
  released). Releasing any required input resets the state machine.

50 ms is below the human keypress floor and keeps the polling thread
under 1% on one core (`GetAsyncKeyState` and `XInputGetState` are thin
syscalls). The thread is detached; SFSE plugins do not get a clean
unload, so we let the process tear it down on game exit.

**Default chord rationale (LB+RB+DPadDown):** both shoulder buttons are
physical on every standard pad including the Deck; DPadDown is reachable
with the left thumb without losing the shoulders; the combination is
not bound by default Starfield, so accidental triggers during play are
unlikely. Earlier candidate `LStick+RStick` (L3+R3) was dropped because
clicking both sticks requires releasing the sticks, which interrupts
look. F-keys alone were dropped because the Deck has no native F-key
input.

**Chord token table** (case-insensitive, `+` or `,` separated):

| Token        | XInput bit | Notes                              |
|--------------|------------|------------------------------------|
| `LB`         | 0x0100     | LEFT_SHOULDER                      |
| `RB`         | 0x0200     | RIGHT_SHOULDER                     |
| `LStick`     | 0x0040     | LEFT_THUMB (L3)                    |
| `RStick`     | 0x0080     | RIGHT_THUMB (R3)                   |
| `A`          | 0x1000     |                                    |
| `B`          | 0x2000     |                                    |
| `X`          | 0x4000     |                                    |
| `Y`          | 0x8000     |                                    |
| `DPadUp`     | 0x0001     |                                    |
| `DPadDown`   | 0x0002     |                                    |
| `DPadLeft`   | 0x0004     |                                    |
| `DPadRight`  | 0x0008     |                                    |
| `Start`      | 0x0010     |                                    |
| `Back`       | 0x0020     | alias `Select`                     |
| `LT`         | n/a        | analog, fires above threshold 30   |
| `RT`         | n/a        | analog, fires above threshold 30   |

Unknown tokens log a `[W]` warning and are skipped (parser keeps the
known tokens; if zero tokens are recognized the chord stays at default).

The plugin always logs the loaded INI path, the parsed values, and the
runtime-toggle registration. Look for two lines near the start of
`SimultaneousInput.log`:

```
config: loaded '<...>SimultaneousInput.ini' (LockControllerGlyphs=true, LockGlyphsHotkey=0x77, LockGlyphsChord='lb+rb+dpaddown' buttons=0x302 LT=false RT=false, LockGlyphsChordHoldMs=500)
hotkey/chord: registered runtime toggle (kbm vk=0x77, chord 'lb+rb+dpaddown', hold 500 ms, poll 50 ms)
```

When you fire either toggle in-game:

```
hotkey: LockControllerGlyphs toggled false -> true (vk=0x77)
chord:  LockControllerGlyphs toggled true -> false (chord held 500ms)
```

The INI parser is hand-rolled (~150 LoC including the chord parser, no
new vcpkg dep). Section + key matching case-insensitive; bool values
accept `true|false|1|0|yes|no|on|off`; `;` and `#` start comments
anywhere on a line. If the plugin ever needs more than a handful of
keys, swap the parser for inih or simpleini and keep the `IniConfig`
struct shape so callers do not move.

**Library link:** XInput is pulled in via `#pragma comment(lib,
"Xinput.lib")` inside `SFSEPlugin.cpp`. No CMakeLists change needed.
