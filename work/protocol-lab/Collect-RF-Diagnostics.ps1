# Collects file and socket metadata only. Does not start or modify the game.
# Uses the current Windows execution policy; does not modify or bypass that policy.
[CmdletBinding()]
param(
    [string]$GameDirectory,
    [string]$OutputPath
)

$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    # Resolve only after parameter binding; the automatic script directory
    # was empty in the user's observed default-parameter evaluation.
    $diagnosticDirectory = $PSScriptRoot
    if ([string]::IsNullOrWhiteSpace($diagnosticDirectory)) {
        $diagnosticScriptPath = $MyInvocation.MyCommand.Path
        if ([string]::IsNullOrWhiteSpace($diagnosticScriptPath)) {
            [Console]::Error.WriteLine('Specify -OutputPath with a new report filename.')
            exit 1
        }
        $diagnosticDirectory = [System.IO.Path]::GetDirectoryName($diagnosticScriptPath)
    }
    $OutputPath = [System.IO.Path]::Combine($diagnosticDirectory, 'rf-windows-diagnostics.json')
}

if ([string]::IsNullOrWhiteSpace($GameDirectory)) {
    $dialog = $null
    try {
        Add-Type -AssemblyName System.Windows.Forms
        $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
        $dialog.Description = 'Select your Rumble Fighter installation folder. Its files will only be read.'
        $dialog.ShowNewFolderButton = $false
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
            Write-Host 'Cancelled. No report was created.'
            exit 0
        }
        $GameDirectory = $dialog.SelectedPath
    } catch {
        [Console]::Error.WriteLine('The folder selector is unavailable. Run again with -GameDirectory and your installation folder.')
        exit 1
    } finally { if ($null -ne $dialog) { $dialog.Dispose() } }
}

function Get-LaunchOptionNames {
    param([string]$CommandLine)
    # A fixed allowlist prevents an unusual argument value from leaking as a purported flag name.
    # No positional arguments, option values, unknown names, or raw command line are returned.
    $allowed = @('direct', 'ip', 'ipaddress', 'host', 'hostname', 'port', 'server', 'serverip', 'serverport', 'serveraddress', 'endpoint', 'address', 'addr', 'gateway', 'login', 'loginserver', 'loginport', 'authserver', 'authport', 'remote', 'connect', 'config', 'ini', 'launchparam', 'appparam', 'programid', 'versionurl', 'versionfileurl', 'forcecheck', 'checkminorversion', 'silentinstall', 'autoinstall', 'offline', 'local', 'localhost')
    return @([regex]::Matches($CommandLine, '(?i)(?:^|\s)"?[/-]{1,2}([A-Za-z][A-Za-z0-9_-]{0,31})(?=[:=\s"]|$)') |
        ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } |
        Where-Object { $allowed -contains $_ } | Sort-Object -Unique)
}

function Get-AddressClass {
    param([string]$Address)
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Address, [ref]$ip)) { return 'unknown' }
    if ([System.Net.IPAddress]::IsLoopback($ip)) { return 'loopback' }
    if ($ip.IsIPv4MappedToIPv6) { $ip = $ip.MapToIPv4() }
    if ([System.Net.IPAddress]::IsLoopback($ip)) { return 'loopback' }
    $b = $ip.GetAddressBytes()
    if ($ip.Equals([System.Net.IPAddress]::Any) -or $ip.Equals([System.Net.IPAddress]::IPv6Any)) { return 'unspecified' }
    if ($b.Length -eq 4) {
        if ($b[0] -eq 10 -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)) { return 'private' }
        if ($b[0] -eq 169 -and $b[1] -eq 254) { return 'link_local' }
        if ($b[0] -ge 224) { return 'multicast_or_reserved' }
    } else {
        if (($b[0] -band 254) -eq 252) { return 'private' }
        if ($ip.IsIPv6LinkLocal) { return 'link_local' }
        if ($ip.IsIPv6Multicast) { return 'multicast_or_reserved' }
    }
    return 'public_or_other'
}

function Get-PeMachine {
    param([string]$Path)
    $stream = $null
    $reader = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        $reader = New-Object System.IO.BinaryReader($stream)
        if ($stream.Length -lt 64 -or $reader.ReadUInt16() -ne 0x5A4D) { return 'not_pe' }
        $stream.Position = 0x3C
        $offset = $reader.ReadUInt32()
        if ($offset -gt ($stream.Length - 6)) { return 'invalid_pe' }
        $stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x00004550) { return 'invalid_pe' }
        switch ($reader.ReadUInt16()) {
            0x014C { return 'x86' }
            0x8664 { return 'x64' }
            0xAA64 { return 'arm64' }
            default { return 'other_pe' }
        }
    } catch { return 'unreadable' }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        elseif ($null -ne $stream) { $stream.Dispose() }
    }
}

function Get-ConfigKeyMetadata {
    param([string]$Path, [long]$Length)
    if ($Length -gt 1048576) { return @{ classification = 'too_large'; keys = @() } }
    try {
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $text = $null
        if ($bytes.Length -ge 2 -and $bytes[0] -eq 255 -and $bytes[1] -eq 254) {
            $text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2)
        } elseif ($bytes.Length -ge 2 -and $bytes[0] -eq 254 -and $bytes[1] -eq 255) {
            $text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2)
        } else {
            $controls = @($bytes | Where-Object { ($_ -lt 32 -and $_ -notin 9, 10, 13) -or $_ -eq 127 }).Count
            if ($bytes -contains 0 -or ($bytes.Length -gt 0 -and $controls / $bytes.Length -gt 0.02)) {
                return @{ classification = 'binary_or_opaque'; keys = @() }
            }
            $text = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
        }
        # Only recognized configuration key names; unknown names may themselves
        # contain account data. Neither their names nor any values are exported.
        $allowedKeys = @('host', 'hostname', 'ip', 'ipaddress', 'port', 'server', 'serverip', 'serverport', 'serveraddress', 'serveraddr', 'server_ip', 'server_port', 'server_address', 'endpoint', 'address', 'addr', 'gateway', 'loginserver', 'loginhost', 'loginip', 'loginport', 'login_server', 'login_ip', 'login_port', 'authserver', 'authhost', 'authip', 'authport', 'auth_server', 'auth_ip', 'auth_port', 'gameserver', 'gamehost', 'gameip', 'gameport', 'game_server', 'game_ip', 'game_port', 'channelserver', 'channelip', 'channelport', 'launchparam', 'appparam', 'programid', 'versionurl', 'versionfileurl', 'forcecheck', 'checkminorversion', 'silentinstall', 'autoinstall', 'direct', 'offline', 'local', 'config', 'ini')
        $allKeys = @([regex]::Matches($text, '(?m)^\s*([A-Za-z_][A-Za-z0-9_.-]{0,63})\s*=') |
            ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $keys = @($allKeys | Where-Object { $allowedKeys -contains $_ } | ForEach-Object { $_.ToLowerInvariant() })
        return @{ classification = 'text_candidate'; keys = $keys; unrecognized_key_count = $allKeys.Count - $keys.Count }
    } catch { return @{ classification = 'unreadable'; keys = @() } }
}

try {
    $rootItem = Get-Item -LiteralPath $GameDirectory -Force
    if (-not $rootItem.PSIsContainer) { throw 'invalid' }
    $root = $rootItem.FullName.TrimEnd([char[]]@('\', '/'))
    $destination = [System.IO.Path]::GetFullPath($OutputPath)
    if ($destination.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
        $destination.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'inside_game'
    }
} catch {
    [Console]::Error.WriteLine('Choose an existing game directory and a report location outside that directory.')
    exit 1
}
if (Test-Path -LiteralPath $destination) {
    [Console]::Error.WriteLine('The report already exists. Supply a new -OutputPath filename; existing files are never overwritten.')
    exit 1
}

$expected = @{
    'rumblefighter.exe' = '94194afa95d3d2cc81a55438a0f584bfaf039ca85adab5b07966ae3e4d593a59'
    'RumbleLauncher.exe' = '21dd6e1efb35d140876db353cbf57130f215e7173b80bb6df7d0f29c66e1b77b'
}
$names = @('rumblefighter.exe', 'RumbleLauncher.exe', 'RumbleLauncher.ini', 'WISEUPDATE.INI', 'GrLauncher.ini', 'rumfus.ini', 'wufilelist.ini', 'temp.ini', 'd3dx9_42.dll', 'audiere.dll', 'MSVCR100.dll')
$fileResults = @()
foreach ($name in $names) {
    $path = Join-Path $root $name
    $record = [ordered]@{ filename = $name; present = $false }
    try {
        if (Test-Path -LiteralPath $path -PathType Leaf) {
            $item = Get-Item -LiteralPath $path -Force
            $record.present = $true
            $record.size_bytes = $item.Length
            $record.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($expected.ContainsKey($name)) { $record.matches_uploaded_executable = ($record.sha256 -eq $expected[$name]) }
            if ($name -match '\.(exe|dll)$') {
                $record.machine = Get-PeMachine $path
                $version = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
                $record.file_version = if ($version.FileVersion -match '^[0-9., ]{1,64}$') { $version.FileVersion } else { $null }
                $record.product_version = if ($version.ProductVersion -match '^[0-9., ]{1,64}$') { $version.ProductVersion } else { $null }
            } elseif ($name -match '\.ini$') {
                $record.config = Get-ConfigKeyMetadata $path $item.Length
            }
        }
    } catch { $record.error = 'file_metadata_unavailable' }
    $fileResults += [pscustomobject]$record
}

$processResults = @()
$optionsById = @{}
$optionQueryAvailable = $true
try {
    # Local metadata query only. The original command line is never printed, serialized, or saved.
    $metadata = @(Get-CimInstance -ClassName Win32_Process -Filter "Name = 'rumblefighter.exe' OR Name = 'RumbleLauncher.exe'")
    foreach ($entry in $metadata) {
        $optionsById[[int]$entry.ProcessId] = @{
            readable = (-not [string]::IsNullOrWhiteSpace($entry.CommandLine))
            names = @(Get-LaunchOptionNames $entry.CommandLine)
        }
    }
    $metadata = $null
} catch { $optionQueryAvailable = $false }
foreach ($processName in @('rumblefighter', 'RumbleLauncher')) {
    try { $processes = @(Get-Process -Name $processName -ErrorAction SilentlyContinue) }
    catch { $processes = @() }
    foreach ($process in $processes) {
        $result = [ordered]@{ process_name = $processName + '.exe'; candidate_launch_option_names = @(); launch_option_metadata_available = $false; tcp = @(); udp = @(); errors = @() }
        if ($optionsById.ContainsKey([int]$process.Id)) {
            $result.candidate_launch_option_names = @($optionsById[[int]$process.Id].names)
            $result.launch_option_metadata_available = $optionsById[[int]$process.Id].readable
        } elseif (-not $optionQueryAvailable) { $result.errors += 'launch_option_metadata_unavailable' }
        # IDs are used solely to scope local socket queries and are never included in output.
        try {
            $connections = @(Get-NetTCPConnection -OwningProcess $process.Id -ErrorAction SilentlyContinue)
            $result.tcp = @($connections | ForEach-Object {
                [pscustomobject]@{
                    local_address_class = Get-AddressClass $_.LocalAddress
                    local_port = [int]$_.LocalPort
                    remote_address_class = Get-AddressClass $_.RemoteAddress
                    remote_port = [int]$_.RemotePort
                    state = $_.State.ToString()
                }
            })
        } catch { $result.errors += 'tcp_metadata_unavailable' }
        try {
            $endpoints = @(Get-NetUDPEndpoint -OwningProcess $process.Id -ErrorAction SilentlyContinue)
            $result.udp = @($endpoints | ForEach-Object {
                [pscustomobject]@{ local_address_class = Get-AddressClass $_.LocalAddress; local_port = [int]$_.LocalPort }
            })
        } catch { $result.errors += 'udp_metadata_unavailable' }
        $processResults += [pscustomobject]$result
    }
}

$report = [ordered]@{
    schema_version = 1
    collected_utc = [DateTime]::UtcNow.ToString('o')
    os_version = [Environment]::OSVersion.Version.ToString()
    powershell_version = $PSVersionTable.PSVersion.ToString()
    files = $fileResults
    existing_game_processes = $processResults
    limits = @(
        'No program was started; no configuration, registry, firewall, hosts file, or security setting was changed.',
        'No game-service request, packet capture, or game-executable execution was performed.',
        'No username, computer name, process ID, full path, command line, config value, raw file content, or literal network address is included.',
        'A missing DLL beside the game does not prove it is absent from Windows runtime directories.',
        'A running process is identified by its name; process metadata does not prove its executable path or identity.',
        'An empty socket list can mean no active sockets, insufficient access, or a process that exited during collection.',
        'Candidate launch-option names come only from a fixed allowlist; names can be syntactic coincidences and do not establish that the client supports them.',
        'An empty option-name list does not establish the absence of endpoint configuration.',
        'Config key names and socket metadata cannot establish support for a private-server endpoint or resolve GameGuard/session compatibility.'
    )
}

$outputStream = $null
try {
    $json = $report | ConvertTo-Json -Depth 9
    $encoded = (New-Object System.Text.UTF8Encoding($false)).GetBytes($json + [Environment]::NewLine)
    $outputStream = [System.IO.File]::Open($destination, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    $outputStream.Write($encoded, 0, $encoded.Length)
    $outputStream.Dispose()
    $outputStream = $null
    Write-Host ('Report saved: ' + [System.IO.Path]::GetFileName($destination))
} catch {
    [Console]::Error.WriteLine('The report could not be saved. Choose a new filename in an existing writable folder.')
    exit 1
} finally { if ($null -ne $outputStream) { $outputStream.Dispose() } }
