<#
.SYNOPSIS
  Windows wrapper for tools/derive_function_ids.py.

.DESCRIPTION
  PowerShell wrapper that runs the Python derivation tool via either:
    - python.exe / py.exe (if Python is on PATH)
    - WSL python3 (fallback for systems where Python isn't installed)

  Pass full paths to Starfield.exe, the AL DB, and (optionally) the
  SimultaneousInput.log skip file. JSON is written to stdout.

.EXAMPLE
  pwsh tools/derive_function_ids.ps1 `
    -Exe 'C:\Program Files (x86)\Steam\steamapps\common\Starfield\Starfield.exe' `
    -DB  'C:\Program Files (x86)\Steam\steamapps\common\Starfield\Data\SFSE\Plugins\versionlib-1-16-236-0.bin' `
    -Log "$env:USERPROFILE\Documents\My Games\Starfield\SFSE\Logs\SimultaneousInput.log" `
    > tools\derived.json
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Exe,
    [Parameter(Mandatory)] [string] $DB,
    [string] $Log = ""
)

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pyScript  = Join-Path $scriptDir "derive_function_ids.py"
if (-not (Test-Path $pyScript)) { throw "missing $pyScript" }

$pyArgs = @("--exe", $Exe, "--db", $DB)
if ($Log -ne "") { $pyArgs += @("--log", $Log) }

# 1) try py.exe (Windows Python launcher)
$py = (Get-Command py.exe -ErrorAction SilentlyContinue) ??
      (Get-Command python.exe -ErrorAction SilentlyContinue) ??
      (Get-Command python3.exe -ErrorAction SilentlyContinue)
if ($py) {
    & $py.Path $pyScript @pyArgs
    return
}

# 2) fallback: WSL
$wsl = Get-Command wsl.exe -ErrorAction SilentlyContinue
if ($wsl) {
    function ConvertTo-WslPath([string]$p) {
        return (& wsl.exe wslpath -u $p).Trim()
    }
    $wPy   = ConvertTo-WslPath $pyScript
    $wExe  = ConvertTo-WslPath $Exe
    $wDB   = ConvertTo-WslPath $DB
    $wLog  = if ($Log) { ConvertTo-WslPath $Log } else { "" }
    $cmd   = "python3 '$wPy' --exe '$wExe' --db '$wDB'"
    if ($wLog) { $cmd += " --log '$wLog'" }
    & wsl.exe bash -lc $cmd
    return
}

throw "Neither Python (py.exe / python.exe) nor WSL is available. Install one."
