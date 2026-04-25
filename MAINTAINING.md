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
