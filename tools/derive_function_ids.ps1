<#
.SYNOPSIS
  Re-derive Starfield 1.16.236 Address Library IDs for the 8 stale member-function
  hook targets in src/RE/Offset.Ext.h.

.DESCRIPTION
  The plugin records 9 hook targets as Address Library IDs. After the libxse
  migration, 1 (LookHandler vtable) was re-derived from libxse's IDs_VTABLE.h.
  The remaining 8 are member-function IDs which libxse does not catalogue.

  This script derives them by combining:

    1. PE parsing of Starfield.exe to enumerate .text and .rdata.
    2. AL DB v5 parsing (versionlib-1-16-236-0.bin) to map ID to RVA, and to
       reverse-map RVA back to ID for newly discovered function entry points.
    3. Vtable-anchored search: for classes whose vtable AL ID libxse exposes,
       walk vtable slots and check each candidate function body for the
       documented Parapets anchor pattern at the documented offset.
    4. For non-virtual targets, emit a structured "unresolved" record with the
       anchor pattern and the recommended Ghidra/IDA derivation step.

  Output is a single JSON object on stdout. Status notes go to stderr.

.PARAMETER Exe
  Full path to Starfield.exe (Steam: C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe).

.PARAMETER DB
  Full path to versionlib-1-16-236-0.bin (typically in Data\SFSE\Plugins\).

.PARAMETER VTableSlotsToScan
  How many slots to scan per vtable. Default 64. Increase if a target sits
  past slot 64.

.EXAMPLE
  pwsh tools/derive_function_ids.ps1 `
      -Exe 'C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe' `
      -DB  'C:\Users\Tony\Documents\My Games\Starfield\SFSE\Plugins\versionlib-1-16-236-0.bin' `
      > out.json
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Exe,
    [Parameter(Mandatory)] [string] $DB,
    [int] $VTableSlotsToScan = 64
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Note { param([string]$Msg) Write-Host "[derive] $Msg" -ForegroundColor Cyan }
function Write-Warn { param([string]$Msg) Write-Host "[derive] WARN: $Msg" -ForegroundColor Yellow }
function Write-Err  { param([string]$Msg) Write-Host "[derive] ERR:  $Msg" -ForegroundColor Red }

if (-not (Test-Path $Exe)) { throw "Starfield.exe not found at: $Exe" }
if (-not (Test-Path $DB))  { throw "AL DB not found at: $DB" }

# === AL DB v5 ============================================================
# Format (per CommonLibSF/lib/commonlib-shared/src/REL/IDDB.cpp):
#   u32  fileVersion           (must equal 5)
#   u32  gameVersion[4]        (e.g. 1,16,236,0)
#   char name[64]
#   i32  pointerSize
#   i32  dataFormat
#   i32  offsetCount
#   u32  offsets[offsetCount]  (flat array, offsets[id] = RVA)

Write-Note "Loading AL DB: $DB"
$dbBytes = [System.IO.File]::ReadAllBytes($DB)
$dbStream = [System.IO.MemoryStream]::new($dbBytes)
$dbReader = [System.IO.BinaryReader]::new($dbStream)

$fileVersion = $dbReader.ReadUInt32()
if ($fileVersion -ne 5) { throw "Expected AL DB format 5, got $fileVersion. This script only supports v5." }
$gameMajor = $dbReader.ReadUInt32()
$gameMinor = $dbReader.ReadUInt32()
$gamePatch = $dbReader.ReadUInt32()
$gameBuild = $dbReader.ReadUInt32()
$gameVerStr = "$gameMajor.$gameMinor.$gamePatch.$gameBuild"
Write-Note "AL DB game version: $gameVerStr"
$null = $dbReader.ReadBytes(64)              # name[64]
$pointerSize = $dbReader.ReadInt32()
$dataFormat  = $dbReader.ReadInt32()
$offsetCount = $dbReader.ReadInt32()
Write-Note "AL DB offsetCount=$offsetCount, pointerSize=$pointerSize, dataFormat=$dataFormat"

# offsets[id] = RVA (u32)
$alOffsets = New-Object 'System.UInt32[]' $offsetCount
[Buffer]::BlockCopy($dbBytes, $dbStream.Position, $alOffsets, 0, $offsetCount * 4)
$dbReader.Dispose()
$dbStream.Dispose()

# Forward + reverse maps. Reverse: only the FIRST id mapping to a given RVA is
# kept (multiple IDs can alias the same offset; the lowest ID wins, which
# matches AL DB conventions).
$rvaToId = @{}
for ($i = 0; $i -lt $offsetCount; $i++) {
    $rva = $alOffsets[$i]
    if ($rva -ne 0 -and -not $rvaToId.ContainsKey($rva)) {
        $rvaToId[$rva] = $i
    }
}
Write-Note "Built reverse RVA -> ID map ($($rvaToId.Count) unique RVAs)"

function Get-RvaForId([uint32]$id) {
    if ($id -ge $offsetCount) { return 0 }
    return $alOffsets[$id]
}
function Get-IdForRva([uint32]$rva) {
    if ($rvaToId.ContainsKey($rva)) { return $rvaToId[$rva] }
    return $null
}

# === PE parsing ==========================================================
Write-Note "Loading PE: $Exe"
$peBytes = [System.IO.File]::ReadAllBytes($Exe)
$peStream = [System.IO.MemoryStream]::new($peBytes)
$peReader = [System.IO.BinaryReader]::new($peStream)

# DOS header
$null = $peReader.ReadBytes(0x3C)
$peHeaderOffset = $peReader.ReadInt32()
$peStream.Position = $peHeaderOffset

# PE\0\0 + COFF
$sig = $peReader.ReadUInt32()
if ($sig -ne 0x00004550) { throw "Bad PE signature: 0x$($sig.ToString('X8'))" }
$null = $peReader.ReadUInt16()                   # machine
$numSections = $peReader.ReadUInt16()
$null = $peReader.ReadBytes(4 + 4 + 4)           # timestamp, symtab ptr, num syms
$sizeOfOptionalHeader = $peReader.ReadUInt16()
$null = $peReader.ReadUInt16()                   # characteristics

$optHeaderStart = $peStream.Position
$magic = $peReader.ReadUInt16()                  # 0x20B = PE32+
if ($magic -ne 0x20B) { throw "Expected PE32+ (0x20B), got 0x$($magic.ToString('X4'))" }
$null = $peReader.ReadBytes(22)                  # MajorLinkerVersion..SizeOfUninitializedData..AddressOfEntryPoint..BaseOfCode
$imageBase = $peReader.ReadUInt64()
Write-Note "ImageBase: 0x$($imageBase.ToString('X16'))"

$peStream.Position = $optHeaderStart + $sizeOfOptionalHeader

# Section table
$sections = @()
for ($s = 0; $s -lt $numSections; $s++) {
    $nameBytes = $peReader.ReadBytes(8)
    $name = [System.Text.Encoding]::ASCII.GetString($nameBytes).TrimEnd([char]0)
    $virtualSize = $peReader.ReadUInt32()
    $virtualAddress = $peReader.ReadUInt32()
    $sizeOfRawData = $peReader.ReadUInt32()
    $pointerToRawData = $peReader.ReadUInt32()
    $null = $peReader.ReadBytes(16)              # ptr to relocs/linenums + counts
    $null = $peReader.ReadUInt32()               # characteristics
    $sections += [pscustomobject]@{
        Name     = $name
        VAStart  = $virtualAddress
        VAEnd    = $virtualAddress + $virtualSize
        FileOff  = $pointerToRawData
        RawSize  = $sizeOfRawData
    }
}
foreach ($sec in $sections) {
    Write-Note ("section {0,-8} VA 0x{1:X8}..0x{2:X8} file 0x{3:X8} raw 0x{4:X8}" -f $sec.Name, $sec.VAStart, $sec.VAEnd, $sec.FileOff, $sec.RawSize)
}

function Convert-RvaToFileOffset([uint64]$rva) {
    foreach ($sec in $sections) {
        if ($rva -ge $sec.VAStart -and $rva -lt $sec.VAEnd) {
            return [int]($sec.FileOff + ($rva - $sec.VAStart))
        }
    }
    return -1
}
function Read-Bytes([uint64]$rva, [int]$count) {
    $off = Convert-RvaToFileOffset $rva
    if ($off -lt 0) { return $null }
    if ($off + $count -gt $peBytes.Length) { return $null }
    $out = New-Object byte[] $count
    [Array]::Copy($peBytes, $off, $out, 0, $count)
    return ,$out
}
function Read-UInt64Le([uint64]$rva) {
    $b = Read-Bytes $rva 8
    if (-not $b) { return $null }
    return [System.BitConverter]::ToUInt64($b, 0)
}

# === Pattern matching ====================================================
function Test-Pattern {
    param(
        [byte[]] $Body,
        [int]    $Offset,
        [string] $Pattern   # e.g. "C6 43 08 01" or "E8 ?? ?? ?? ??"
    )
    if (-not $Body) { return $false }
    $tokens = $Pattern -split '\s+' | Where-Object { $_ }
    if ($Offset + $tokens.Count -gt $Body.Length) { return $false }
    for ($i = 0; $i -lt $tokens.Count; $i++) {
        $t = $tokens[$i]
        if ($t -eq '??') { continue }
        $expected = [Convert]::ToByte($t, 16)
        if ($Body[$Offset + $i] -ne $expected) { return $false }
    }
    return $true
}

# === Hook target catalog ================================================
# Each target: containing function class (if any), libxse vtable AL ID(s),
# anchor offset and pattern, and old (1.8.86) AL ID for diagnostic comparison.
$targets = @(
    @{
        Name       = 'BSPCGamepadDevice::Poll'
        VTableIds  = @(470133)
        Anchors    = @(@{ Offset = 0x2A0; Pattern = 'C6 43 08 01' })
        OldId      = 179249
        OldHookId  = 'BSPCGamepadDevice.Poll'
        Mechanism  = 'byte_patch_nop4'
    },
    @{
        Name       = 'PlayerControls::LookHandler::Func10'
        VTableIds  = @(433589)
        Anchors    = @(@{ Offset = 0xE; Pattern = 'E8 ?? ?? ?? ??' })
        OldId      = 129152
        OldHookId  = 'PlayerControls.LookHandler.Func10'
        Mechanism  = 'rewrite_call5'
        # "Func10" naming hint: Parapets's name suggests this is a virtual at
        # vtable slot 0x10 (16). We still scan all slots; if slot 16 wins, we
        # log that confirmation.
        SlotHint   = 16
    },
    @{
        Name       = 'IMenu::ShowCursor'
        VTableIds  = @(475515, 475519, 475517)
        Anchors    = @(@{ Offset = 0x14; Pattern = 'E8 ?? ?? ?? ??' })
        OldId      = 187256
        OldHookId  = 'IMenu.ShowCursor'
        Mechanism  = 'rewrite_call5'
    },
    @{
        Name       = 'ShipHudDataModel::PerformInputProcessing'
        VTableIds  = @(440389,440383,440377,440387,440381,440375,440369,440379,
                       440405,440393,440403,440397,440391,440385,440395,440341,
                       440337,440357,440351,440345,440355,440349,440343,440339,
                       440347,440373,440367,440361,440371,440365,440359,440353,
                       440363)
        # Two anchors must both be present in the same function body.
        Anchors    = @(
            @{ Offset = 0x7AF; Pattern = 'E8 ?? ?? ?? ??' },
            @{ Offset = 0x82A; Pattern = 'E8 ?? ?? ?? ??' }
        )
        OldId      = 137087
        OldHookId  = 'ShipHudDataModel.PerformInputProcessing'
        Mechanism  = 'rewrite_call5_two_sites'
    },
    @{
        Name       = 'BSInputDeviceManager::IsUsingGamepad'
        VTableIds  = @(469745, 469743, 469747)
        # IsUsingGamepad has no offset-anchor; it's the predicate, not a host
        # function. We can only confirm it via vtable slot if it's virtual.
        # Most likely it's a non-virtual member (called by name from the engine)
        # so the script will fall through to "unresolved" with a hint.
        Anchors    = @()
        OldId      = 178879
        OldHookId  = 'BSInputDeviceManager.IsUsingGamepad'
        Mechanism  = 'predicate_target'
    },
    # === Non-vtable targets (no class anchor in libxse) ===
    @{
        Name       = 'PlayerControls::Manager::ProcessLookInput'
        VTableIds  = @()
        Anchors    = @(@{ Offset = 0x68; Pattern = 'E8 ?? ?? ?? ??' })
        OldId      = 129407
        OldHookId  = 'PlayerControls.Manager.ProcessLookInput'
        Mechanism  = 'rewrite_call5'
    },
    @{
        Name       = 'Main::Run_WindowsMessageLoop'
        VTableIds  = @()
        Anchors    = @(@{ Offset = 0x39; Pattern = 'E8 ?? ?? ?? ??' })
        OldId      = 149028
        OldHookId  = 'Main.Run_WindowsMessageLoop'
        Mechanism  = 'rewrite_call5'
    },
    @{
        Name       = 'UI::SetCursorStyle'
        VTableIds  = @()
        Anchors    = @(@{ Offset = 0x98; Pattern = 'E8 ?? ?? ?? ??' })
        OldId      = 187051
        OldHookId  = 'UI.SetCursorStyle'
        Mechanism  = 'rewrite_call5'
    }
)

# === Resolution loop ====================================================
$results = @{}

foreach ($tgt in $targets) {
    Write-Note "Resolving $($tgt.Name) (old ID $($tgt.OldId))"
    $resolved = $null
    $resolvedSlot = $null
    $resolvedVtableId = $null
    $resolvedFuncRva = $null

    foreach ($vtId in $tgt.VTableIds) {
        $vtRva = Get-RvaForId $vtId
        if ($vtRva -eq 0) {
            Write-Warn "  vtable AL ID $vtId not present in DB; skipping"
            continue
        }

        for ($slot = 0; $slot -lt $VTableSlotsToScan; $slot++) {
            $slotVa = Read-UInt64Le ([uint64]($vtRva + $slot * 8))
            if ($null -eq $slotVa -or $slotVa -eq 0) { break }
            $funcRva = [uint32]($slotVa - $imageBase)

            # Read up to ~0x900 bytes of function body for anchor checks.
            $body = Read-Bytes ([uint64]$funcRva) 0x900
            if (-not $body) { continue }

            $allMatch = $true
            foreach ($anc in $tgt.Anchors) {
                if (-not (Test-Pattern -Body $body -Offset $anc.Offset -Pattern $anc.Pattern)) {
                    $allMatch = $false
                    break
                }
            }
            if ($tgt.Anchors.Count -eq 0) { $allMatch = $false }   # can't confirm without anchor
            if ($allMatch) {
                $newId = Get-IdForRva ([uint32]$funcRva)
                if ($null -ne $newId) {
                    $resolved = $newId
                    $resolvedSlot = $slot
                    $resolvedVtableId = $vtId
                    $resolvedFuncRva = $funcRva
                    Write-Note ("  HIT: vtable {0} slot {1} -> RVA 0x{2:X} -> AL ID {3}" -f $vtId, $slot, $funcRva, $newId)
                    break
                } else {
                    Write-Warn ("  pattern matched at slot {0} (RVA 0x{1:X}) but no AL ID maps to that RVA" -f $slot, $funcRva)
                }
            }
        }
        if ($null -ne $resolved) { break }
    }

    if ($null -ne $resolved) {
        $results[$tgt.OldHookId] = @{
            new_id        = $resolved
            old_id        = $tgt.OldId
            via           = "vtable[$resolvedVtableId][$resolvedSlot]"
            func_rva_hex  = ('0x{0:X}' -f $resolvedFuncRva)
            mechanism     = $tgt.Mechanism
            anchors_ok    = $true
        }
    } else {
        $hint = if ($tgt.VTableIds.Count -gt 0) {
            "no vtable slot in any of [$($tgt.VTableIds -join ', ')] matches all anchors. Function may not be virtual on $gameVerStr, or anchor offset/pattern shifted. Open Starfield.exe in Ghidra (load with imagebase 0x$($imageBase.ToString('X'))), find symbol/string near the call site, and emit AL ID via reverse_lookup of its RVA."
        } else {
            "no vtable in libxse for this class. Resolve manually: in Ghidra, find the unique pattern around the patch site (the bytes preceding offset $('0x{0:X}' -f $tgt.Anchors[0].Offset)) in Starfield.exe, then map the function entry RVA back to an AL ID via the alOffsets table."
        }
        $results[$tgt.OldHookId] = @{
            new_id     = $null
            old_id     = $tgt.OldId
            unresolved = $true
            mechanism  = $tgt.Mechanism
            hint       = $hint
        }
        Write-Warn ("  unresolved: {0}" -f $tgt.Name)
    }
}

# === Emit JSON ==========================================================
$envelope = @{
    schema_version = 1
    starfield_version = $gameVerStr
    al_db_path = $DB
    exe_path = $Exe
    image_base_hex = ('0x{0:X}' -f $imageBase)
    derived_at = (Get-Date -Format 'o')
    targets = $results
}

$envelope | ConvertTo-Json -Depth 6
