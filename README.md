# SimultaneousInput (Starfield SFSE plugin)

Mixed mouse, keyboard, and gamepad input for Starfield. Lets you look with the
right thumbstick and aim with the mouse at the same time, keep the mouse cursor
in menus when a controller is held, etc. Useful on the Steam Deck for combining
gyro + mouse + gamepad.

## Fork rationale

This is a maintained fork of [Exit-9B/Starfield-SimultaneousInput][upstream],
originally written by Parapets. Upstream stopped at commit `27edad8` (Replace
fmt with `<format>`) in late 2023; the last "Update for Starfield X.Y.Z" commit
targets 1.8.86. Starfield has shipped many runtime patches since then, and
SFSE 0.2.x rejects DLLs whose declared layout-compatibility bit doesn't match
the new SFSE expectations. This fork bumps the dependency on
[CommonLibSF][clibsf], rebuilds the plugin, and adds per-hook resilience
+ build provenance so future runtime updates degrade gracefully instead of
hard-failing.

All credit for the original code goes to Parapets / Exit-9B. License: GPL-3.0
with the modding exceptions in [`EXCEPTIONS`](EXCEPTIONS).

## Compatibility matrix

| Plugin version | CommonLibSF commit | SFSE        | Starfield runtime         | Notes                                              |
| -------------- | ------------------ | ----------- | ------------------------- | -------------------------------------------------- |
| 1.0.3          | f2ea130 (2023-11)  | 0.2.x early | 1.8.86                    | Original upstream build, last release by Parapets. |
| 1.1.0          | 9caec20 (2025-09)  | 0.2.19+     | 1.14.70+ (target 1.15.x)  | This fork. Layout-bit moved to 1<<3 (1.14.70+).    |
| 1.3.0          | libxse 9caec20+    | 0.2.19+     | 1.16.236                  | All 8 reachable hooks re-anchored. WindowsMessageLoop hook retired. |
| 1.4.0          | libxse 9caec20+    | 0.2.19+     | 1.16.236                  | Adds `LockControllerGlyphs` INI flag + runtime KBM hotkey (default `VK_F8`) + gamepad chord (default `LB+RB+DPadDown`, hold 500 ms). Hook table unchanged from 1.3.0. |

The plugin uses Address Library v1 IDs to resolve engine functions at load
time. As long as the AL database for your installed runtime maps the same IDs
to the same functions, this build keeps working when Bethesda ships a patch.
If a function was refactored, the affected hook will log a `hook ... skipped`
warning to `Documents\My Games\Starfield\SFSE\Logs\SimultaneousInput.log` and
the plugin will continue with reduced functionality rather than crashing the
host. See [MAINTAINING.md](MAINTAINING.md) for the per-patch verification loop.

## Build

Two paths:

### CI (recommended)

Push to a branch on the fork. The `build` workflow in `.github/workflows/`
runs `windows-latest` + MSVC v143, configures via the `vs2022-windows` preset,
builds `RelWithDebInfo`, and uploads `SimultaneousInput.dll` + `.pdb` as the
`SimultaneousInput-<sha>` artifact. Download from the run page.

### Local (Windows)

Requires Visual Studio 2022 (17.10+), CMake 3.30+, and a `VCPKG_ROOT` env var
pointing at a vcpkg checkout.

```pwsh
git submodule update --init --recursive
cmake -B build -S . --preset=vs2022-windows
cmake --build build --config RelWithDebInfo
```

The DLL lands in `build/RelWithDebInfo/SimultaneousInput.dll`. The PDB next
to it is required to symbolicate any minidumps.

## Deploy

Drop `SimultaneousInput.dll`, `SimultaneousInput.pdb` (for crash diagnosis),
and `SimultaneousInput.ini` (for the v1.4.0 LockControllerGlyphs config) into:

```
<Starfield install>\Data\SFSE\Plugins\
```

Verify it loaded by checking
`Documents\My Games\Starfield\SFSE\Logs\sfse.log` for a line like
`SimultaneousInput.dll v1.4.0.0 loaded` and the plugin's own log file
`SimultaneousInput.log` for the runtime probe and per-hook install lines.

## Configuration (v1.4.0+)

`SimultaneousInput.ini` lives next to the DLL. Four keys, all optional,
all under `[Display]`:

```ini
[Display]
LockControllerGlyphs   = false
LockGlyphsHotkey       = VK_F8
LockGlyphsChord        = LB+RB+DPadDown
LockGlyphsChordHoldMs  = 500
```

- **`LockControllerGlyphs`** (default `false`): when `true`, on-screen
  glyphs and the cursor style stay pinned to the gamepad branch regardless
  of which device drove the most recent look event. The camera-side
  simultaneous-input feature is unaffected: mouse and gamepad both still
  drive the camera. Recommended for Steam Remote Play / MoonDeck setups
  streaming from a host PC to a Steam Deck or similar controller-form
  client: the host has no Deck-detection signal because Steam Input
  presents an emulated Xbox controller, so this manual switch is the
  intended primary mechanism. The default INI shipped with the release
  archive sets this to `true`; that copy is meant for the host PC. Set
  to `false` for desktop installs that want v1.3.0 device-following
  behavior.
- **`LockGlyphsHotkey`** (default `VK_F8` = `0x77`): Win32 virtual-key
  code that toggles the lock at runtime via keyboard. Press once to flip
  the state; takes effect on the next cursor draw, logged at `[I]`
  level. Accepts named VK constants (`VK_F1`..`VK_F12`, `VK_PAUSE`,
  `VK_SCROLL`, `VK_NUMPAD0`..`9`, `VK_ADD`, `VK_SUBTRACT`, `VK_OEM_PLUS`,
  `VK_OEM_MINUS`), hex (`0x77`), or decimal (`119`). See
  `dist/SimultaneousInput.ini` for the full annotated list.
- **`LockGlyphsChord`** (default `LB+RB+DPadDown`): gamepad button
  combination polled via XInput. Hold all listed inputs together for the
  hold-time below to fire. The chord latches once toggled, so it will
  not re-fire until at least one input is released. Token syntax is
  case-insensitive `+` (or `,`)-joined names. Recognized tokens:
  - **Buttons:** `LB`, `RB`, `LStick`, `RStick`, `A`, `B`, `X`, `Y`,
    `DPadUp`, `DPadDown`, `DPadLeft`, `DPadRight`, `Start`, `Back`
    (alias `Select`)
  - **Triggers:** `LT`, `RT` (analog; fire above ~12% press)

  The default `LB+RB+DPadDown` is comfortable on Steam Deck (both
  shoulders + left thumb on DPad) and uncommon in default Starfield
  bindings.
- **`LockGlyphsChordHoldMs`** (default `500`, clamped to `[50, 5000]`):
  how long the chord must be held continuously before it fires.

The plugin logs the loaded config and registers both runtime toggles at
startup, e.g.:

```
config: loaded '...\SimultaneousInput.ini' (LockControllerGlyphs=true, LockGlyphsHotkey=0x77, LockGlyphsChord='lb+rb+dpaddown' buttons=0x302 LT=false RT=false, LockGlyphsChordHoldMs=500)
hotkey/chord: registered runtime toggle (kbm vk=0x77, chord 'lb+rb+dpaddown', hold 500 ms, poll 50 ms)
```

When you fire either toggle in-game:

```
hotkey: LockControllerGlyphs toggled false -> true (vk=0x77)
chord: LockControllerGlyphs toggled true -> false (chord held 500ms)
```

If no INI is found the plugin uses the defaults above (with
`LockControllerGlyphs=false`) and logs that it fell through.

## Sanity-test checklist

After deploy, in-game:

- [ ] Move the right thumbstick to look around. Mouse should still emit cursor
      events for menus.
- [ ] Open the inventory or any menu while holding a controller. The mouse
      cursor should be visible and movable.
- [ ] Pilot a ship. The reticle should respond to whichever input you used
      most recently for look (stick or mouse), not be stuck on one.
- [ ] Tap a controller button mid-mouse-aim. Aiming should not snap or stutter.

If any check fails, open `SimultaneousInput.log` and look for `hook ... skipped`
warnings. That tells you which AL ID is now stale and needs investigation.

## Build provenance

Each build embeds the git SHA and UTC build timestamp into:

- the Windows file-version resource (`Comments` field, viewable via
  right-click -> Properties -> Details on the DLL)
- the `Plugin::BUILD_SHA` / `Plugin::BUILD_DATE` constants logged at startup

So a deployed copy can always be traced back to the source revision that
produced it.

[upstream]: https://github.com/Exit-9B/Starfield-SimultaneousInput
[clibsf]: https://github.com/Starfield-Reverse-Engineering/CommonLibSF
