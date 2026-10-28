# Restore a checkpoint: server code into work\protocol-lab and account profiles into
# private\accounts. The current code and profiles are first copied to
# work\checkpoints\_before-restore-<timestamp> so a restore is itself reversible.
# Refuses while a local server or the game is running.
#   Restore-Checkpoint.ps1 -Name v1.25-local-startup-training [-CodeOnly | -ProfilesOnly]
[CmdletBinding()]
param([Parameter(Mandatory = $true)] [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')] [string]$Name,
      [switch]$CodeOnly, [switch]$ProfilesOnly)
$ErrorActionPreference = 'Stop'
$lab = $PSScriptRoot
$root = [IO.Path]::GetFullPath([IO.Path]::Combine($lab, '..\..'))
$checkpoint = [IO.Path]::Combine($root, 'work', 'checkpoints', $Name)
$accounts = [IO.Path]::Combine($root, 'private', 'accounts')
if (-not [IO.Directory]::Exists($checkpoint)) { throw "checkpoint '$Name' not found" }
if (@(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { [string]$_.CommandLine -like '*Test-RF-LocalHandshake*' }).Count -gt 0) { throw 'a local server (or its watchdog) is running: stop it first (Q in its window)' }
if (@(Get-Process | Where-Object { $_.ProcessName -in @('rumblefighter', 'RumbleLauncher') }).Count -gt 0) { throw 'close the game and launcher first' }
$safety = [IO.Path]::Combine($root, 'work', 'checkpoints', '_before-restore-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss'))
$null = [IO.Directory]::CreateDirectory([IO.Path]::Combine($safety, 'code'))
$null = [IO.Directory]::CreateDirectory([IO.Path]::Combine($safety, 'profiles'))
Copy-Item -Path ([IO.Path]::Combine($lab, '*.cs')), ([IO.Path]::Combine($lab, '*.ps1')), ([IO.Path]::Combine($lab, '*.cmd')), ([IO.Path]::Combine($lab, '*.py')) -Destination ([IO.Path]::Combine($safety, 'code'))
if ([IO.Directory]::Exists($accounts)) { Copy-Item -Path ([IO.Path]::Combine($accounts, '*.txt')) -Destination ([IO.Path]::Combine($safety, 'profiles')) -ErrorAction SilentlyContinue }
"current state saved to $safety"
if (-not $ProfilesOnly) {
    $code = [IO.Path]::Combine($checkpoint, 'code')
    $n = 0
    foreach ($f in Get-ChildItem -LiteralPath $code -File) { Copy-Item -LiteralPath $f.FullName -Destination ([IO.Path]::Combine($lab, $f.Name)) -Force; $n++ }
    "restored $n code file(s) from $Name (files added after the checkpoint are left in place)"
}
if (-not $CodeOnly) {
    $profiles = [IO.Path]::Combine($checkpoint, 'profiles')
    $null = [IO.Directory]::CreateDirectory($accounts)
    foreach ($f in Get-ChildItem -LiteralPath $profiles -Filter '*.txt' -File) {
        Copy-Item -LiteralPath $f.FullName -Destination ([IO.Path]::Combine($accounts, $f.Name)) -Force
        "restored profile $($f.BaseName)"
    }
}
