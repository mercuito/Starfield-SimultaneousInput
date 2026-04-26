# tools/

Helpers for re-deriving Starfield Address Library IDs and in-function hook
offsets when the engine refactors across patches.

## Files

- `derive_function_ids.py` (Python 3, primary): parses `Starfield.exe` and
  the matching `versionlib-{ver}-0.bin` and (optionally) a
  `SimultaneousInput.log` skip file. Emits JSON describing each Parapets
  hook's host function in the new runtime, the candidate predicate
  destinations shared across host bodies, and proposed new offsets. Runs
  on Linux/macOS sandboxes too; no game install required.
- `derive_function_ids.ps1` (PowerShell, fallback): same logic for use on
  the Windows gaming machine when SSH is impractical.
- `derived_1.16.236.json`: the latest derivation output for Starfield
  1.16.236, captured locally and checked in for review.

## Run

```sh
# from anywhere, against pulled artifacts:
python3 tools/derive_function_ids.py \
  --exe /path/to/Starfield.exe \
  --db  /path/to/versionlib-1-16-236-0.bin \
  --log /path/to/SimultaneousInput.log \
  > tools/derived_1.16.236.json
```

```pwsh
# on anthony-gaming via SSH:
pwsh tools/derive_function_ids.ps1 `
  -Exe 'C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe' `
  -DB  'C:\Program Files (x86)\Steam\steamapps\common\Starfield\Data\SFSE\Plugins\versionlib-1-16-236-0.bin' `
  > tools\derived.json
```

## Verified findings (Starfield 1.16.236, captured 2026-04-26)

### Confirmed

- **PlayerControls::LookHandler vtable**: AL **433589** (libxse canonical,
  per `external/CommonLibSF/include/RE/IDs_VTABLE.h`). Was 407288 (Parapets,
  1.8.86 capture). Already corrected in `src/RE/Offset.Ext.h` on this
  branch.

- **BSPCGamepadDevice::Poll** real implementation: AL **124384** at RVA
  `0x2302bc0`. The Parapets ID 179249 in 1.16.236's AL DB resolves to a
  ~42-byte thunk at `0x356e720` whose body does not contain the
  `C6 43 08 01` patch anchor. Vtable[470133][1] is the real Poll, and the
  anchor pattern is now at offset **+0x51d** (was +0x2A0).

- **IMenu::ShowCursor** real implementation: AL **42816** at RVA
  `0x481e60`. The Parapets ID 187256 in 1.16.236's AL DB resolves to
  `0x37d31f0`, which has no E8 at +0x14. The libxse-canonical IMenu
  vtable[475515] slot 18 is `0x481e60`, which has E8 at +0x14 calling
  `0x481d30` and is the right host to hook.

- **New predicate equivalent of IsUsingGamepad**: RVA **0x28cef30**, AL
  **139340**. Called inside the bodies of `LookHandler::Func10`,
  `ProcessLookInput`, and `ShipHudDataModel::PerformInputProcessing` (the
  4 input-related host functions). Confidence: 4-of-6 host overlap; the
  remaining hosts (Run_WindowsMessageLoop and IMenu/UI cursor functions)
  call related but different predicates (`0x22cb8f0`, `0x002c4b50`, etc.),
  consistent with Bethesda having split or selectively inlined the
  predicate across subsystems.

  Original Parapets ID 178879 in 1.16.236's DB resolves to `0x3552490`,
  which is a debug log stub, not the predicate. The OLD ID was renumbered
  in the AL DB.

- **Run_WindowsMessageLoop** in 1.16.236 does not call the same predicate
  as the look hooks (it calls `0x022c9910` and `0x022cb8f0`, not
  `0x28cef30`). The original mod's design assumed a single shared
  IsUsingGamepad call; this assumption no longer holds.

- **ShipHudDataModel::PerformInputProcessing** in 1.16.236 calls
  `0x28cef30` at six distinct in-function offsets, not two. The original
  +0x7AF / +0x82A pair has been split into more checks. Replacing all six
  may over-correct.

### Still under investigation

- The exact in-function offsets where the E8 call to `0x28cef30` should be
  rewritten in `LookHandler::Func10`, `ProcessLookInput`, and `UI::SetCursorStyle`.
  These exist in the host bodies but the original Parapets offsets
  (0xE, 0x68, 0x98) no longer point to them.
- Whether `Run_WindowsMessageLoop`'s window-cursor capture in 1.16.236 is
  driven by an entirely new code path that doesn't call any
  IsUsingGamepad-style predicate (Bethesda may have inlined it).

## AL DB note

`derive_function_ids.py` reads the version-5 AL database with header
size 96 bytes (file_version u32 + game_version u32[4] + name char[64]
+ pointer_size i32 + data_format i32 + offset_count i32) and a flat
u32 array indexed by ID. This matches libxse's `m_v5[id]` lookup and is
verified against runtime resolution observed in `SimultaneousInput.log`.
