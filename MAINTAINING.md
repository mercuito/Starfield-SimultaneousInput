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

A full re-derivation pass against 1.16.236 was completed in v1.3.0. Eight of
the nine hooks have been re-anchored against the post-refactor binary; one
(Run_WindowsMessageLoop) is permanently retired because the predicate call
no longer exists in the host body. The re-derivation was driven by
`tools/derive_function_ids.py` plus a 0x6000-byte E8 scan of every host
function (`tools/derived_1.16.236.json`).

Two predicate variants now exist on 1.16.236, where 1.8.86 had only one:

- Look variant `IsUsingGamepad`: RVA 0x28cef30, AL **139340**. Called from
  the look-input hosts (LookHandler::Func10, ProcessLookInput, ShipHud).
- Cursor variant: RVA 0x2c4b50, AL 35982. Called from the cursor hosts
  (IMenu::ShowCursor, UI::SetCursorStyle). We do not call this AL ID
  directly; the cursor hooks rewrite their existing `call rel32` to point at
  our `IsGamepadCursor`, which internally invokes the look variant. The
  semantic is preserved because both variants return "is gamepad currently
  active".

| Hook | AL ID | 1.16.236 status |
|---|---|---|
| LookHandler vtable shim (slot 1)         | 433589 | installed; vtable layout preserved, AL re-anchored via libxse `IDs_VTABLE.h`, verified in-game on v1.2.0 |
| BSPCGamepadDevice::Poll byte patch       | 124384 | installed; AL re-anchored from vtable[470133][1] scan. Anchor `C6 43 08 01` lives at +0x51d (was +0x2A0). Plugin scans first 0x800 bytes for the pattern so future minor refactors do not require a code change. |
| LookHandler::Func10 E8 site              | 129152 | installed at +0x196 (was +0x0E). Three predicate calls cluster at +0x196 / +0x1a4 / +0x236; we hook the first. |
| Manager::ProcessLookInput E8 site        | 129407 | installed at +0x33F (was +0x68). Three predicate calls cluster at +0x33F / +0x34A / +0x355. |
| Main::Run_WindowsMessageLoop E8 site     | 149028 | retired. Host body is 24 KB with 775 E8 calls and zero target the predicate; cursor-capture branch was either inlined into the message handler or moved to a different function. AL ID retained for diagnostic purposes only; no TryWriteCall is attempted. |
| ShipHudDataModel::PerformInputProcessing pre  | 137087 | installed at +0x2C7 (was +0x7AF). Predicate cluster +0x2C7 / +0x2E4 / +0x2F7. |
| ShipHudDataModel::PerformInputProcessing post | 137087 | installed at +0x2E4 (was +0x82A). Same cluster, second call. |
| IMenu::ShowCursor E8 site                | 187256 | installed at +0xA1 (was +0x14). Host is unchanged across the refactor; 7 calls to the cursor predicate, first at +0xA1. (An earlier attempt migrated to AL 42816 from a libxse vtable read; that AL resolves to a tiny 8-byte getter, not ShowCursor. Reverted.) |
| UI::SetCursorStyle E8 site               | 187051 | installed at +0x4CE (was +0x98). 11 calls to the cursor predicate; we hook the first. |
| BSInputDeviceManager::IsUsingGamepad     | 139340 | re-anchored from old AL 178879 (which now resolves to a logging stub). Look variant; called by IsGamepadCursor for the cursor-host redirect. |

Expected runtime: 8/9 hooks installed, 1 skipped. The skipped hook
(Run_WindowsMessageLoop cursor capture) is logged at WARN level; in-game
impact is that the OS cursor may be confined to the window whenever a
controller is plugged in, which is the engine's default and what
1.16.236 vanilla already does.

If a future patch shifts these offsets again, re-run
`tools/derive_function_ids.py --exe <Starfield.exe> --db <versionlib.bin>`
and re-derive against the resulting `derived_<ver>.json`. The byte-pattern
scan for BSPCGamepadDevice::Poll is the most resilient pattern; the others
need offset updates but the AL IDs should stay stable across minor patches.
