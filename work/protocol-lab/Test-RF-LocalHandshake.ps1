# Original local login/session server experiment for Windows PowerShell 5.1.
# Never modifies a real adapter, firewall, hosts file, DNS, game binary or portproxy.
# An ActiveStore-only address on the existing software loopback is removed afterward.
# 1.23: the server runs until deliberately stopped (Q, Ctrl+C or closing the window).
# A hidden watchdog (-WatchdogFor, started by the test itself) performs the same
# journal-verified cleanup if the window is closed or the test process dies.
[CmdletBinding()]
param([switch]$CleanupOnly, [switch]$EmptyCharacter, [switch]$Unclaimed95,
      [int]$WatchdogFor = 0, [string]$WatchdogTestId = '',
      [ValidatePattern('^[a-z0-9-]{1,32}$')] [string]$Profile = 'baseline')

$ErrorActionPreference = 'Stop'
$rfVip = '5.188.32.117'                       # lobby (TCP 7000)
$rfPlazaVip = '5.188.32.116'                  # 1.24: plaza (TCP 33343), TCP 3416, UDP 34162
$rfVips = @($rfVip, $rfPlazaVip)              # every address this test may own
$rfPlazaPort = 33343
$rfPort = 7000
$rfExpectedClientHash = '94194afa95d3d2cc81a55438a0f584bfaf039ca85adab5b07966ae3e4d593a59'
$rfSafeErrorCodes = @(
    'loopback_ownership_ambiguous', 'software_loopback_not_unique', 'loopback_dhcp_not_disabled',
    'unrecognized_portproxy_rule', 'conflicting_portproxy_rule', 'invalid_ownership_journal',
    'original_test_process_still_running', 'cleanup_interface_identity_changed',
    'cleanup_persistent_address_conflict', 'cleanup_address_identity_conflict',
    'cleanup_game_restarted', 'cleanup_verification_failed', 'cleanup_journal_identity_changed',
    'cleanup_journal_removal_failed', 'temporary_address_verification_failed',
    'unexpected_persistent_address', 'temporary_route_verification_failed', 'local_probe_not_ready',
    'temporary_address_not_unique', 'temporary_address_not_preferred',
    'temporary_address_wrong_interface', 'temporary_address_wrong_prefix',
    'temporary_address_source_flag_mismatch', 'journal_selftest_content_mismatch',
    'previous_cleanup_pending', 'user_stopped_during_setup', 'invalid_watchdog_arguments'
)
$rfWatchdog = $WatchdogFor -gt 0
# Seconds cleanup waits for the game to close; the watchdog waits without limit.
$rfCleanupWaitSeconds = $(if ($rfWatchdog) { 0 } else { 120 })
$rfDirectory = $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($rfDirectory)) {
    $rfDirectory = [IO.Path]::GetDirectoryName($MyInvocation.MyCommand.Path)
}
$rfJournalPath = [IO.Path]::Combine($rfDirectory, 'rf-local-handshake-state.json')
$rfTestId = $(if ($rfWatchdog -and $WatchdogTestId -match '^[a-f0-9]{32}$') { $WatchdogTestId } else { [Guid]::NewGuid().ToString('N') })
$rfReportName = 'rf-local-handshake-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '-' + $rfTestId.Substring(0, 8) + $(if ($rfWatchdog) { '-watchdog' } else { '' }) + '.json'
$rfSkipReport = $false
$rfPrivateRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($rfDirectory, '..\..\private'))
if (-not [IO.Directory]::Exists($rfPrivateRoot)) { $rfPrivateRoot = [IO.Path]::Combine($rfDirectory, 'private') }
# 1.23: one JSONL line per ended client session plus one server_shutdown line.
$rfSessionLogPath = [IO.Path]::Combine($rfPrivateRoot, 'run-logs', 'server-' + $rfTestId + '.jsonl')
$rfReportPath = [IO.Path]::Combine($rfDirectory, $rfReportName)
$rfStage = 'initialization_failed'
$rfMutex = $null
$rfHasMutex = $false
$rfProbe = $null
$rfPlaza = $null
$rfRecorder = $null
$rfGameProcess = $null
$rfGameProcessStartUtc = $null
$rfGameLogDirectory = $null
$rfGuardBefore = $null
$rfStartedAt = [DateTime]::Now
$rfState = $null
$rfOwnsJournal = $false
$rfReport = [ordered]@{
    schema = 'rf-local-handshake-v1'
    script_version = '1.28'
    test_id = $rfTestId
    mode = $(if ($rfWatchdog) { 'watchdog_cleanup' } elseif ($CleanupOnly) { 'cleanup_only' } elseif ($EmptyCharacter) { 'v1_12_empty_character_comparison' } else { 'local_lobby_entry_quest_ack' })
    started_utc = [DateTime]::UtcNow.ToString('o')
    status = 'not_started'
    error_code = $null
    error_detail = $null
    checks = [ordered]@{}
    observed_address = $null
    game_peer_correlated = $false
    correlated_process_name = $null
    client_build_verified = $false
    client_build_check = 'not_observed'
    probe = $null
    cleanup = [ordered]@{ status = 'not_needed'; error_code = $null; address_absent = $null; route_absent = $null; journal_removed = $false; listener_stopped = $false; waiting_for_processes = @() }
    limits = @(
        'The temporary addresses make 5.188.32.117 and (1.24) 5.188.32.116 local for all ports and protocols: TCP 7000 is the lobby, TCP 33343 the plaza (ProudNet core handshake only), TCP 3416 and UDP 34162 are accepted and counted but never answered. v1.23 and earlier did NOT redirect .116, so their clients reached the live official plaza server (client log: P2P Connected).',
        'Plaza (1.25): the 04 hint is byte-identical to rf-boss-baseline except the RSA modulus (v1.24 sent a two-byte-shifted settings block and the client closed). Stage timeline per plaza connection (accepted, hint, session key, 07 request, ConnectSuccess, first activity) is logged.',
        'ADD_ITEM (1.28): every 31/8A is answered with the observed 31/18B failure (code 10001 FAIL(unknown)). The channel-100 claim and level-1 reward have this captured; other bodies (e.g. the kind-0 catalog ADD_ITEM the client sends during startup) get the same frame rather than being left unanswered - leaving them silent hung the client 30 s then EndTask (GServerAccess.cpp(3194) return NULL). This is NOT a success reply; unrecognized ADD_ITEM is logged live and counted (add_item_unrecognized_failures).',
        'Packages (1.27): 31/86 UNPACK and 31/9A OPEN_BOX (Gemnet names) are REFUSED in the failure form captured for 31/8A (action+0x100, 520 bytes, code 10001 FAIL(unknown); unverified for these actions); nothing is consumed or granted. No capture or reference contains a success reply or package/box contents. Every unanswered or refused request is written to the session log immediately (opcode, length, body hex up to 64 bytes, owned item it names).',
        'Currency and purchases (1.26): Carats = login body +32 and the 31/81 balance; Astros = 31/89 second field (capture values + Gemnet names; which one the Store shows as G or R is checked in the real client). With the profile setting unlimited on, both are reported as its balance (default 99,999,999; int32 fields) and 31/80 purchases are free: each request is processed once, the item (observed record for the catalog, else Gemnet record shape) is saved atomically before the 31/81 reply (new instance, Carats), and logged to <profile>.purchases.log. Without unlimited currency purchases are refused unanswered (no price table). The 31/80/31/81 layout comes from the Gemnet reference, not from a capture.',
        'Independence audit (1.25): TCP endpoints of every process running from the game folder that are not loopback or the two local addresses, plus DNS-cache entries for game/GameGuard names, are recorded in independence_audit. The client still resolves the playredfox.net service names through normal DNS before using the redirected addresses.',
        'Plaza (1.24): answers only what rf-boss-baseline shows: policy XML + connection hint after 2E (38 captured settings bytes + OUR freshly generated RSA-1024 public key), 06 after the encrypted session key (decrypted with our private key; only the outcome is logged), 0A with a local host ID after 07, 1C for each 1A ping, RMI FBFC for each FA01 heartbeat. 1B and RMI FA13 get nothing (as captured). Every other plaza message (room/P2P group RMIs, relays, UDP hole punching) is recorded and NOT answered. Only the exact game build (process name + SHA-256) is served.',
        'Account (1.24): profile private/accounts/<profile>.txt (default baseline, created from the v1.18-v1.23 fixture at first login; wire bytes identical for it). Login, inventory pages (80 per page, cursor = last instance + 1, as captured), avatar list, equipment, cash and GET_USER_INFO read it. My Info: 40/A2 selects the avatar, 30/D6 is answered 30/D7 01 only for an owned catalog, 40/A4 equips only an owned instance into a slot whose catalog family was observed there, 40/A6 empties a slot (slot 0/class never). Each accepted change is saved atomically BEFORE its header-only ack; a refused one changes nothing and is NOT answered (no captured failure reply exists).',
        'GET_USER_INFO (1.24): 30/80 naming the logged-in account gets a 1567-byte 30/81 with account ID, name, level, experience, the 45 equipped CATALOG IDs and country/region; all other bytes are zero (their official meaning is unidentified). Other names are not answered. 1F/10 keepalives get no reply (as captured).',
        'Only the fixed invented local password (ProbeOnly123!) can receive an experimental local profile; the ID box is not required to match, and only yes/no facts about it are recorded. One initialization frame from the hash-verified user capture may then be replayed locally; this is not fresh GameGuard authentication.',
        'Persistent server (1.23): no runtime limit and no cumulative request limit. The server runs until Q, Ctrl+C or closing this window. A client disconnect ends only that client session (logged as client_session_end); the listener keeps accepting reconnects, each with fresh ciphers and protocol state, the same peer check (exact game build) and the same captured GameGuard initialization reply. Server shutdown is logged separately (server_shutdown). Per frame: version26, login91, then supported bodies of at most eleven bytes, GameGuard answers of at most 506 bytes and unanswered bodies of at most 1024 bytes (anything larger ends that client session), and an incomplete frame must complete within 5 seconds of its first byte. An idle connection never expires.',
        'Login and supported property bodies are decrypted only in bounded memory and then cleared. The property owner must match local account1; seven tail bytes remain uninterpreted. Credentials, packet bodies, GUIDs and tokens are never logged or saved.',
        'Server bytes written: only the replies described here, each at most 3928 bytes (largest: inventory page), one per answered request. Unanswered requests receive nothing.',
        'Avatar update requests 40/A2, 40/A4 and 40/A6 naming local avatar 1 receive the header-only ack observed for all 27 captured occurrences. Nothing is saved; the ack does not persist any avatar change.',
        'Avatar candidate: one invented local avatar ID 1, listed and equipped. Default 1.18 fixture: three inventory records, class (local instance 1001, catalog 1000176, +8 20046, item_end 0), Fishing Rod (1002, 5135224, +8 85582, item_end 1000; opaque zero is a candidate) and the class default Exo (1003, 2040035, +8 85582, item_end 1000, all opaque zero, the exact record profile captured for this class); equipment slot 0 = instance 1001, all other slots zero (rod and Exo owned, not equipped, as in every capture). With -EmptyCharacter: the v1.12 empty inventory and all-zero equipment.',
        'Grade list (1.16): 30/A0 gets 26 records: the 25 common IDs observed all-zero, plus channel 95 with (0,0,2), its exact first-observed values (the v1.15 client requested 95 via 31/8C). Every record is an observed value. A 31/8C grade-up request has its requested ID recorded and gets NO reply (no capture contains 31/8C or 31/8D); the connection stays open so the client timeout and later requests are observed.',
        'UpdateQuest (1.22): 30/CE (12-byte body) is answered with 30/CF echoing the body, as in both captured exchanges (small sample); quest progress is not persisted.',
        'Store (1.23): opening the Store makes the client send Get_Cash 31/88 again (observed in the v1.22 run). It is answered with the same local zero-balance 31/89 reply as at startup, every time. No capture contains a Store visit, so any further Store request is recorded and NOT answered.',
        'Level-1 reward (1.21): the fresh account (experience 0) makes the client call GetLevelUpItem, 31/8A body 01 00 61 a6 4c 00 e8 03 00 00 (catalog 5023329). No capture holds a successful grant of this kind, so none is invented: it gets the observed 31/18B failure frame (code 10001 FAIL(unknown)), which the client logged and continued past in v1.20. UNVERIFIED: whether 10001 is the code a real server would use here. Nothing is granted; experience and inventory are unchanged.',
        'Lobby (1.20): 10/B6 gets the observed 0x210/B7 reply (body 01, identical in all 11 captured occurrences). 40/84 room polls (body 0a00000000000046, as captured) get an EMPTY room list: 16 bytes, header fields 0 and count 0. The 10+223*N structure fits all 12 captured lists, but N=0 itself was never observed (UNVERIFIED). No captured room or player name is ever sent. Clocks, grade, BC, B6 and room polls may repeat without limit.',
        'Channel 95 (1.20, controlled experiment): grade 95 = (1,1,2), the value right after the official claim in rf-startup, plus the claim reward item (catalog 3043117, the exact record of rf-boss-baseline, local instance 1004), because both claimed-state sessions own it. -Unclaimed95 restores the v1.19 state. Used only when the private fixture provides the reward record.',
        'Main menu (1.19): 30/B2 (LoginCheck), 30/BA, 30/BC and 30/CC pages are answered with the exact frames one official session (rf-boss-baseline) received, loaded from a private hash-pinned fixture; they are game/global data (no names, no account or session values). A 30/CC body without a matching page is recorded and not answered.',
        'ADD_ITEM (1.17): 31/8A bodies (10 bytes of medal-channel claim data, no account data) are recorded. Only body 02 64 00.. (channel 100) is answered, with the 520-byte 31/18B failure code 10001 FAIL(unknown) that all three captures show for that exact body; no item is granted and the inventory is unchanged. Other bodies get no reply.',
        'Unanswered requests (1.17): after the avatar chain, an unsupported request (body up to 1024 bytes, at most 8) is read and discarded so the cipher stays aligned, recorded by header only, NOT answered, and the connection stays open instead of being closed.',
        'Post-avatar queries (1.14): 30/B4 index 1..5 in order gets the all-zero 19-byte status reply the official server also sent; 48/42 GameGuard answers are read and discarded with no reply, as the official server never replied. This local server does not validate GameGuard answers.',
        'Diagnostics: request/reply/disconnect times, game process exit time and code, filtered Windows Application Error/WER/Hang events naming the game or GameGuard (codes and file names only), sizes/write times of encrypted GameGuard .erl logs, game crash-dump presence, and a summary of the game log. The full game logs are copied only to private/run-logs and are not part of this report.',
        'Gift-list lengths and actions are observed; zero-filled bodies are experimental candidates, not verified empty-list serializers. No captured gift records are replayed.',
        'The empty buddy list (count 0, 100 zeroed 30-byte records) follows the official reply in the user capture rf-empty-buddy.pcapng, where the client continued. No captured buddy records are replayed.',
        'The opaque initialization blob may contain old session binding. It is extracted only in memory, never saved or included in reports. Other GameGuard destinations are not isolated by the one-IP route.',
        'ReplyWritten means the local probe handed a response to its socket; it does not prove application-level acceptance.',
        'Shutdown (1.23): Q or Ctrl+C stops the server, saves this report and runs the verified cleanup here. Closing the window stops the server from the console-close handler (sockets closed, server_shutdown logged); a hidden watchdog process started by this test then waits for the game and launcher to close and runs the same journal-verified cleanup, writing a separate -watchdog report. If both fail (for example a power loss), the next test run recovers the journal automatically, or use CleanupLocalHandshake.cmd; a reboot also removes the ActiveStore-only address.'
    )
}

function Write-RFMessage([string]$Message) {
    [Console]::WriteLine($Message)
}

function Get-RFSafeErrorDetail($Record) {
    $exception = $Record.Exception
    $leaf = $exception
    for ($i = 0; $i -lt 3 -and $null -ne $leaf.InnerException; $i++) {
        $leaf = $leaf.InnerException
    }
    # Class names and numeric codes only; no message, stack, target or path.
    $outerType = $exception.GetType().FullName
    $innerType = $leaf.GetType().FullName
    if ($outerType -notmatch '^[A-Za-z0-9_.+]{1,160}$') { $outerType = 'other_exception' }
    if ($innerType -notmatch '^[A-Za-z0-9_.+]{1,160}$') { $innerType = 'other_exception' }
    return [ordered]@{
        exception_type = $outerType; hresult = [int]$exception.HResult
        underlying_exception_type = $innerType; underlying_hresult = [int]$leaf.HResult
        category_number = [int]$Record.CategoryInfo.Category
    }
}

function Set-RFAddressObservation($Addresses, [int]$ExpectedIndex) {
    $samples = @()
    foreach ($address in @($Addresses | Select-Object -First 4)) {
        $stateName = [string]$address.AddressState
        if (@('Invalid', 'Tentative', 'Duplicate', 'Deprecated', 'Preferred') -notcontains $stateName) {
            $stateName = 'other_or_missing'
        }
        $samples += [ordered]@{
            state = $stateName
            prefix_length = [int]$address.PrefixLength
            interface_matches_expected = ($address.InterfaceIndex -eq $ExpectedIndex)
            skip_as_source = $address.SkipAsSource -eq $true
            skip_as_source_present = $null -ne $address.SkipAsSource
        }
    }
    $rfReport.observed_address = [ordered]@{ count = @($Addresses).Count; samples = $samples }
}

function Get-RFGameProcesses {
    return @(Get-Process -ErrorAction Stop | Where-Object {
        $_.ProcessName -ieq 'rumblefighter' -or $_.ProcessName -ieq 'RumbleLauncher'
    })
}

function Get-RFBlockingProcessNames {
    # Emit only canonical allowlisted names, never paths, PIDs or command lines.
    return @(Get-RFGameProcesses | ForEach-Object {
        if ($_.ProcessName -ieq 'rumblefighter') { 'rumblefighter' }
        elseif ($_.ProcessName -ieq 'RumbleLauncher') { 'RumbleLauncher' }
    } | Sort-Object -Unique)
}

function Get-RFAddresses([string]$Store, [string[]]$Ips = $rfVips) {
    try {
        return @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore $Store -ErrorAction Stop |
            Where-Object { $Ips -contains $_.IPAddress })
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            $_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*,Get-NetIPAddress') { return @() }
        throw
    }
}

function Get-RFRoutes([string]$Store, [string[]]$Ips = $rfVips) {
    $prefixes = @($Ips | ForEach-Object { $_ + '/32' })
    try {
        return @(Get-NetRoute -AddressFamily IPv4 -PolicyStore $Store -ErrorAction Stop |
            Where-Object { $prefixes -contains $_.DestinationPrefix })
    } catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -and
            $_.FullyQualifiedErrorId -like 'CmdletizationQuery_NotFound*,Get-NetRoute') { return @() }
        throw
    }
}

function Get-RFLoopback {
    $owners = @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop |
        Where-Object { $_.IPAddress -eq '127.0.0.1' })
    if ($owners.Count -ne 1) { throw 'loopback_ownership_ambiguous' }
    $candidates = @()
    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.NetworkInterfaceType -ne [Net.NetworkInformation.NetworkInterfaceType]::Loopback) { continue }
        $ipv4 = $nic.GetIPProperties().GetIPv4Properties()
        if ($null -ne $ipv4 -and $ipv4.Index -eq $owners[0].InterfaceIndex) {
            $candidates += [pscustomobject]@{ Index = [int]$ipv4.Index; Id = [string]$nic.Id }
        }
    }
    if ($candidates.Count -ne 1) { throw 'software_loopback_not_unique' }
    $configuration = @(Get-NetIPInterface -InterfaceIndex $candidates[0].Index -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction Stop)
    if ($configuration.Count -ne 1 -or [string]$configuration[0].Dhcp -ne 'Disabled') {
        throw 'loopback_dhcp_not_disabled'
    }
    return $candidates[0]
}

function Assert-RFNoPortProxy {
    # Read only. No portproxy service, registry or rule is changed.
    foreach ($table in @('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')) {
        $key = $null
        try {
            $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Services\PortProxy\' + $table + '\tcp', $false)
            if ($null -eq $key) { continue }
            foreach ($name in $key.GetValueNames()) {
                if ([string]::IsNullOrEmpty($name)) { continue }
                if ($name -notmatch '^(?<address>.+)/(?<port>[0-9]+)$') { throw 'unrecognized_portproxy_rule' }
                $conflicts = @('0.0.0.0', '::', '*') + $rfVips + @($rfVips | ForEach-Object { '::ffff:' + $_ })
                if (@($rfPort, $rfPlazaPort, 3416) -contains [int]$Matches.port -and $conflicts -contains $Matches.address) {
                    throw 'conflicting_portproxy_rule'
                }
            }
        } finally { if ($null -ne $key) { $key.Dispose() } }
    }
}

function Write-RFAtomicJson([string]$Path, $Object, [bool]$Replace) {
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    $stream = $null
    try {
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes((ConvertTo-Json -InputObject $Object -Depth 8) + [Environment]::NewLine)
        $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
        $stream.Dispose(); $stream = $null
        # PowerShell can convert $null to an empty string at a string parameter.
        # NullString passes an actual .NET null for the optional backup path.
        if ($Replace) { [IO.File]::Replace($temporary, $Path, [System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temporary, $Path) }
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    }
}

function Test-RFAtomicJson {
    $testPath = [IO.Path]::Combine($rfDirectory, 'rf-journal-selftest-' + [Guid]::NewGuid().ToString('N') + '.json')
    $created = $false
    try {
        Write-RFAtomicJson $testPath ([ordered]@{ phase = 'before' }) $false
        $created = $true
        Write-RFAtomicJson $testPath ([ordered]@{ phase = 'after' }) $true
        $readback = [IO.File]::ReadAllText($testPath) | ConvertFrom-Json -ErrorAction Stop
        if ($readback.phase -ne 'after') { throw 'journal_selftest_content_mismatch' }
    } finally {
        if ($created -and [IO.File]::Exists($testPath)) { [IO.File]::Delete($testPath) }
    }
}

function Read-RFJournal {
    $info = Get-Item -LiteralPath $rfJournalPath -ErrorAction Stop
    if ($info.Length -gt 16384) { throw 'invalid_ownership_journal' }
    $state = [IO.File]::ReadAllText($rfJournalPath) | ConvertFrom-Json -ErrorAction Stop
    # v1 (<= 1.23): one address (.117). v2 (1.24): `addresses`, a non-empty subset of $rfVips
    # in creation order. The owned list is normalized into owned_addresses.
    $owned = @()
    if ($state.schema -eq 'rf-loopback-ownership-v1' -and $state.address -eq $rfVip) { $owned = @($rfVip) }
    elseif ($state.schema -eq 'rf-loopback-ownership-v2') {
        $owned = @($state.addresses | ForEach-Object { [string]$_ })
        if ($owned.Count -lt 1 -or $owned.Count -gt $rfVips.Count -or @($owned | Where-Object { $rfVips -notcontains $_ }).Count -gt 0 -or
            @($owned | Sort-Object -Unique).Count -ne $owned.Count) { throw 'invalid_ownership_journal' }
    }
    if ($owned.Count -eq 0 -or
        $state.prefix_length -ne 32 -or $state.policy_store -ne 'ActiveStore' -or
        $state.skip_as_source -ne $true -or $state.test_id -notmatch '^[a-f0-9]{32}$' -or
        [int]$state.interface_index -lt 1 -or [string]::IsNullOrWhiteSpace([string]$state.interface_id) -or
        [int]$state.owner_pid -lt 1 -or [string]$state.owner_start_ticks -notmatch '^[0-9]+$') {
        throw 'invalid_ownership_journal'
    }
    $state | Add-Member -NotePropertyName owned_addresses -NotePropertyValue $owned -Force
    return $state
}

function Assert-RFOwnerStopped($State) {
    try { $owner = [Diagnostics.Process]::GetProcessById([int]$State.owner_pid) }
    catch [ArgumentException] { return }
    try {
        if ($owner.Id -ne $PID -and $owner.StartTime.ToUniversalTime().Ticks.ToString() -eq [string]$State.owner_start_ticks) {
            throw 'original_test_process_still_running'
        }
    } finally { $owner.Dispose() }
}

function Remove-RFOwnedAddress($State) {
    # Bound the close-game wait. If it expires, keep the local address rather
    # than silently sending game retries back toward the official destination.
    # 1.23: $rfCleanupWaitSeconds = 0 (watchdog) waits until the game is closed.
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $notice = -1
    while ($true) {
        $blockingNames = @(Get-RFBlockingProcessNames)
        $rfReport.cleanup.waiting_for_processes = @($blockingNames)
        if ($blockingNames.Count -eq 0) { break }
        $seconds = [int][Math]::Floor($watch.Elapsed.TotalSeconds)
        if ($rfCleanupWaitSeconds -gt 0 -and $seconds -ge $rfCleanupWaitSeconds) {
            $rfReport.cleanup.status = 'pending_game_still_running'
            Write-RFMessage 'CLEANUP PENDING: the temporary address remains local while the game runs. The background watchdog removes it automatically (same verified cleanup) once the game and launcher are closed. CleanupLocalHandshake.cmd or a reboot also removes it.'
            return
        }
        $noticeBucket = [int][Math]::Floor($seconds / 15.0)
        if ($noticeBucket -ne $notice) {
            $notice = $noticeBucket
            Write-RFMessage ('Cleanup is waiting for: ' + ($blockingNames -join ', ') + '. Close those programs now; use Task Manager if needed. The test waits at most ' + $rfCleanupWaitSeconds + ' seconds.')
        }
        [Threading.Thread]::Sleep($(if ($rfCleanupWaitSeconds -gt 0) { 250 } else { 1000 }))
    }
    # 1.24: only the addresses this journal owns are touched, each verified individually.
    $ownedIps = @($State.owned_addresses | Where-Object { $_ })
    if ($ownedIps.Count -eq 0) { $ownedIps = @($State.addresses | Where-Object { $rfVips -contains $_ }) }   # this run's own state
    if ($ownedIps.Count -eq 0) { throw 'invalid_ownership_journal' }
    if (@(Get-RFAddresses 'PersistentStore' $ownedIps).Count -gt 0) { throw 'cleanup_persistent_address_conflict' }
    foreach ($ip in $ownedIps) {
        $addresses = @(Get-RFAddresses 'ActiveStore' @($ip))
        if ($addresses.Count -eq 0) { continue }
        $loop = Get-RFLoopback
        if ($loop.Index -ne [int]$State.interface_index -or $loop.Id -ine [string]$State.interface_id) {
            throw 'cleanup_interface_identity_changed'
        }
        if ($addresses.Count -ne 1 -or $addresses[0].InterfaceIndex -ne $loop.Index -or
            $addresses[0].PrefixLength -ne 32 -or $addresses[0].SkipAsSource -ne $true) {
            throw 'cleanup_address_identity_conflict'
        }
        # Check immediately before mutation as well as before the polling wait.
        $blockingNames = @(Get-RFBlockingProcessNames)
        $rfReport.cleanup.waiting_for_processes = @($blockingNames)
        if ($blockingNames.Count -gt 0) { throw 'cleanup_game_restarted' }
        Remove-NetIPAddress -InterfaceIndex $loop.Index -AddressFamily IPv4 -IPAddress $ip -PolicyStore ActiveStore -Confirm:$false -ErrorAction Stop
    }
    $rfReport.cleanup.addresses = @($ownedIps)
    $rfReport.cleanup.address_absent = (@(Get-RFAddresses 'ActiveStore' $ownedIps).Count -eq 0)
    $rfReport.cleanup.route_absent = (@(Get-RFRoutes 'ActiveStore' $ownedIps).Count -eq 0)
    if (-not $rfReport.cleanup.address_absent -or -not $rfReport.cleanup.route_absent) {
        throw 'cleanup_verification_failed'
    }
    $current = Read-RFJournal
    if ($current.test_id -ne $State.test_id) { throw 'cleanup_journal_identity_changed' }
    [IO.File]::Delete($rfJournalPath)
    $rfReport.cleanup.journal_removed = -not [IO.File]::Exists($rfJournalPath)
    if (-not $rfReport.cleanup.journal_removed) { throw 'cleanup_journal_removal_failed' }
    $rfReport.cleanup.status = 'verified_removed'
    Write-RFMessage ('Cleanup verified: the test address(es) ' + ($ownedIps -join ', ') + ' and their local routes are gone.')
}

function Get-RFGuardLogState {
    # GameGuard's .erl logs are encrypted; only their size and write time are used.
    $state = [ordered]@{}
    if ($null -eq $rfGameLogDirectory) { return $state }
    try {
        foreach ($file in @(Get-ChildItem -LiteralPath ([IO.Path]::Combine($rfGameLogDirectory, 'GameGuard')) -Filter '*.erl' -File -ErrorAction Stop)) {
            $state[$file.Name] = [ordered]@{ bytes = [int64]$file.Length; write_utc = $file.LastWriteTimeUtc.ToString('o') }
        }
    } catch { }
    return $state
}

function Set-RFGameDiagnostics {
    # 1.13: crash vs. intentional exit evidence. File names and codes only; no paths
    # with user names, no event message bodies, no log text in the report.
    $diag = [ordered]@{
        host_utc_offset_minutes = [int][TimeZoneInfo]::Local.GetUtcOffset([DateTime]::Now).TotalMinutes
        game_process = [ordered]@{ observed = ($null -ne $rfGameProcess); start_utc = $rfGameProcessStartUtc; has_exited = $null; exit_utc = $null; exit_code = $null; exit_code_hex = $null }
        windows_error_events = @()
        game_log = [ordered]@{ copied = $false; private_copy_folder = $null; lines = 0; last_line_time_local = $null; last_line_source = $null; login_ok_line = $false; item_buildpart_lines = 0; tail_sources = @() }
    }
    if ($null -ne $rfGameProcess) {
        try {
            $rfGameProcess.Refresh()
            $diag.game_process.has_exited = [bool]$rfGameProcess.HasExited
            if ($rfGameProcess.HasExited) {
                # v1.14 returned 1601-01-01 here; treat any pre-2000 value as unavailable.
                $exitTime = $rfGameProcess.ExitTime.ToUniversalTime()
                $diag.game_process.exit_utc = $(if ($exitTime.Year -ge 2000) { $exitTime.ToString('o') } else { 'unavailable' })
                $diag.game_process.exit_observed_by_utc = [DateTime]::UtcNow.ToString('o')
                $diag.game_process.exit_code = [int64]$rfGameProcess.ExitCode
                $diag.game_process.exit_code_hex = ('0x{0:X8}' -f ([int64]$rfGameProcess.ExitCode -band 0xFFFFFFFF))
            }
        } catch { $diag.game_process.has_exited = 'unreadable' }
    }
    try {
        $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $rfStartedAt.AddSeconds(-5) } -ErrorAction Stop |
            Where-Object { $_.ProviderName -in @('Application Error', 'Windows Error Reporting', 'Application Hang') })
        foreach ($event in $events) {
            $text = [string]$event.Message
            if ($text -notmatch '(?i)rumblefighter|gamemon|npgg|gameguard') { continue }
            $entry = [ordered]@{ time_utc = $event.TimeCreated.ToUniversalTime().ToString('o'); provider = $event.ProviderName; id = $event.Id }
            if ($event.ProviderName -eq 'Application Error' -and $event.Properties.Count -ge 8) {
                $entry.application = [IO.Path]::GetFileName([string]$event.Properties[0].Value)
                $entry.module = [IO.Path]::GetFileName([string]$event.Properties[3].Value)
                $entry.exception_code = [string]$event.Properties[6].Value
                $entry.fault_offset = [string]$event.Properties[7].Value
            } elseif ($event.ProviderName -eq 'Windows Error Reporting' -and $text -match 'Event Name:\s*(\S+)') {
                $entry.event_name = $Matches[1]
            }
            $diag.windows_error_events += $entry
        }
    } catch {
        # Get-WinEvent throws when nothing matches; that is the expected no-crash result.
        if ([string]$_.FullyQualifiedErrorId -notmatch 'NoMatchingEventsFound') { $diag.windows_error_events = @('query_failed') }
    }
    if ($null -ne $rfGameLogDirectory) {
        try {
            $privateRoot = [IO.Path]::GetFullPath([IO.Path]::Combine($rfDirectory, '..\..\private'))
            if (-not [IO.Directory]::Exists($privateRoot)) { $privateRoot = [IO.Path]::Combine($rfDirectory, 'private') }
            $copyFolder = [IO.Path]::Combine($privateRoot, 'run-logs', $rfTestId)
            $null = [IO.Directory]::CreateDirectory($copyFolder)
            foreach ($name in @('RumbleFighter.log', 'log.txt')) {
                $source = [IO.Path]::Combine($rfGameLogDirectory, $name)
                if ([IO.File]::Exists($source)) { [IO.File]::Copy($source, [IO.Path]::Combine($copyFolder, $name), $true) }
            }
            $diag.game_log.private_copy_folder = 'private/run-logs/' + $rfTestId
            $logPath = [IO.Path]::Combine($copyFolder, 'RumbleFighter.log')
            if ([IO.File]::Exists($logPath)) {
                $diag.game_log.copied = $true
                $lines = @([IO.File]::ReadAllText($logPath, [Text.Encoding]::GetEncoding(949)) -split "`r?`n" | Where-Object { $_.Trim().Length -gt 0 })
                $diag.game_log.lines = $lines.Count
                $diag.game_log.login_ok_line = [bool]($lines | Where-Object { $_ -match 'login\(.*\) ok' })
                $diag.game_log.item_buildpart_lines = @($lines | Where-Object { $_ -match 'Item_BuildPartfrom' }).Count
                $sources = @()
                foreach ($line in $lines) {
                    if ($line -match '^(\d\d:\d\d:\d\d\.\d{3})\s+(\w+\.cpp\(\d+\))') { $sources += , @($Matches[1], $Matches[2]) }
                }
                if ($sources.Count -gt 0) {
                    $diag.game_log.last_line_time_local = $sources[-1][0]
                    $diag.game_log.last_line_source = $sources[-1][1]
                    $diag.game_log.tail_sources = @($sources | Select-Object -Last 8 | ForEach-Object { $_[0] + ' ' + $_[1] })
                }
            }
        } catch { $diag.game_log.copied = 'copy_failed' }
    }
    $after = Get-RFGuardLogState
    $guard = @()
    foreach ($name in $after.Keys) {
        $before = $null
        if ($null -ne $rfGuardBefore -and $rfGuardBefore.Contains($name)) { $before = $rfGuardBefore[$name] }
        $guard += [ordered]@{
            file = $name
            bytes_at_game_connected = $(if ($null -ne $before) { $before.bytes } else { $null })
            bytes_after = $after[$name].bytes
            write_utc_after = $after[$name].write_utc
            grew_after_game_connected = $(if ($null -ne $before) { $after[$name].bytes -gt $before.bytes } else { $null })
        }
    }
    $diag.gameguard_logs = $guard
    $dumps = @()
    if ($null -ne $rfGameLogDirectory) {
        foreach ($name in @('RumbleFighter.DMP', 'RumbleFighter_Copy.DMP', 'RumbleDump.zip')) {
            $path = [IO.Path]::Combine($rfGameLogDirectory, $name)
            if ([IO.File]::Exists($path)) {
                $info = [IO.FileInfo]::new($path)
                $dumps += [ordered]@{ file = $name; bytes = [int64]$info.Length; write_utc = $info.LastWriteTimeUtc.ToString('o'); written_during_test = ($info.LastWriteTime -ge $rfStartedAt) }
            }
        }
    }
    # GemDumpLoader.exe is the game's own crash handler; these are the dump names it embeds.
    $diag.game_crash_dumps = $dumps
    $rfReport.game_diagnostics = $diag
}

function Set-RFProbeReport {
    if ($null -eq $rfProbe) { return }
    $result = $rfProbe.Result
    $safeStatus = [string]$result.Status
    $safeError = [string]$result.ErrorCode
    if ($safeStatus -notmatch '^[a-z0-9_]{0,80}$') { $safeStatus = 'unrecognized_probe_status' }
    if ($safeError -notmatch '^[a-z0-9_]{0,80}$') { $safeError = 'unrecognized_probe_error' }
    $safeReplyKind = [string]$result.LoginReplyKind
    if ($safeReplyKind -notin @('none', 'fixed_rejection', 'synthetic_success')) { $safeReplyKind = 'unrecognized' }
    $safeStopReason = [string]$result.PostLoginStopReason
    if ($safeStopReason -notmatch '^[a-z0-9_]{0,80}$') { $safeStopReason = 'unrecognized_stop_reason' }
    $postHeaders = @()
    foreach ($header in @($result.PostLoginHeaders | Select-Object -First 64)) {
        $postHeaders += [ordered]@{
            type = [int]$header.FrameType
            action = [int]$header.Action
            total_bytes = [int]$header.TotalBytes
            at_ms = [int]$header.AtMs
            reply_at_ms = [int]$header.ReplyAtMs
            reply_bytes = [int]$header.ReplyBytes
        }
    }
    $rfReport.probe = [ordered]@{
        status = $safeStatus
        request_type = [int]$result.RequestType
        request_action = [int]$result.RequestAction
        request_bytes = [int]$result.RequestBytes
        header_parsed = [bool]$result.HeaderParsed
        peer_authorized = [bool]$result.PeerAuthorized
        accepted_after_start_ms = [int]$result.AcceptedAfterStartMs
        first_byte_after_accept_ms = [int]$result.FirstByteAfterAcceptMs
        reply_bytes = [int]$result.ReplyBytes
        reply_written = [bool]$result.ReplyWritten
        synthetic_socket_check = [bool]$result.SyntheticSocketCheck
        error_code = $safeError
        socket_error_code = [int]$result.SocketErrorCode
        login_request_type = [int]$result.LoginRequestType
        login_request_action = [int]$result.LoginRequestAction
        login_request_bytes = [int]$result.LoginRequestBytes
        login_header_parsed = [bool]$result.LoginHeaderParsed
        login_frame_received = [bool]$result.LoginFrameReceived
        login_reply_bytes = [int]$result.LoginReplyBytes
        login_reply_written = [bool]$result.LoginReplyWritten
        local_fixture_matched = [bool]$result.LocalFixtureMatched
        login_reply_kind = $safeReplyKind
        post_login_request_bytes = [int]$result.PostLoginRequestBytes
        post_login_headers = @($postHeaders)
        probe_started_utc = $(if ([string]$result.StartedUtc -match '^[0-9T:.\-+Z]{0,40}$') { [string]$result.StartedUtc } else { 'unrecognized' })
        login_reply_at_ms = [int]$result.LoginReplyAtMs
        connection_ended_at_ms = [int]$result.ConnectionEndedAtMs
        fixture_kind = $(if ([string]$result.FixtureKind -in @('local_class_rod_exo', 'v1_12_empty_character')) { [string]$result.FixtureKind } else { 'unrecognized' })
        clock_reply_count = [int]$result.ClockReplyCount
        post_login_reply_bytes = [int]$result.PostLoginReplyBytes
        post_login_stop_reason = $safeStopReason
        capture_fixture_loaded = [bool]$result.CaptureFixtureLoaded
        gameguard_replay_written = [bool]$result.GameGuardReplayWritten
        gameguard_replay_bytes = [int]$result.GameGuardReplayBytes
        startup_ack_written = [bool]$result.StartupAckWritten
        startup_ack_bytes = [int]$result.StartupAckBytes
        local_cash_reply_written = [bool]$result.LocalCashReplyWritten
        local_cash_reply_bytes = [int]$result.LocalCashReplyBytes
        property_request_count = [int]$result.PropertyRequestCount
        property_owner_match_count = [int]$result.PropertyOwnerMatchCount
        property_reply_count = [int]$result.PropertyReplyCount
        property_reply_bytes = [int]$result.PropertyReplyBytes
        gift_from_reply_written = [bool]$result.GiftFromReplyWritten
        gift_from_reply_bytes = [int]$result.GiftFromReplyBytes
        gift_to_reply_written = [bool]$result.GiftToReplyWritten
        gift_to_reply_bytes = [int]$result.GiftToReplyBytes
        buddy_request_body_zero = [bool]$result.BuddyRequestBodyZero
        buddy_reply_written = [bool]$result.BuddyReplyWritten
        buddy_reply_bytes = [int]$result.BuddyReplyBytes
        avatar_list_reply_written = [bool]$result.AvatarListReplyWritten
        equipped_avatar_reply_written = [bool]$result.EquippedAvatarReplyWritten
        avatar_equipment_reply_written = [bool]$result.AvatarEquipmentReplyWritten
        login_email_field_matched = [bool]$result.LoginEmailFieldMatched
        login_password_field_matched = [bool]$result.LoginPasswordFieldMatched
        local_login_accepted = [bool]$result.LocalLoginAccepted
        avatar_a2_ack_count = [int]$result.AvatarA2AckCount
        avatar_a4_ack_count = [int]$result.AvatarA4AckCount
        avatar_a6_ack_count = [int]$result.AvatarA6AckCount
        avatar_a6_trailing_byte = [int]$result.AvatarA6TrailingByte
        grade_reply_count = [int]$result.GradeReplyCount
        b4_reply_count = [int]$result.B4ReplyCount
        gameguard_answer_count = [int]$result.GuardAnswerCount
        gameguard_answer_bytes = [int]$result.GuardAnswerBytes
        grade_up_requested_id = [int]$result.GradeUpRequestedId
        grade_up_requested_ids = @($result.GradeUpRequestedIds | ForEach-Object { [int]$_ })
        add_item_bodies = @($result.AddItemBodies | Where-Object { [string]$_ -match '^[0-9a-f]{20}$' })
        add_item_failure_replies = [int]$result.AddItemFailureReplies
        add_item_unanswered_count = [int]$result.AddItemUnansweredCount
        add_item_unrecognized_failures = [int]$result.AddItemUnrecognizedFailures
        first_unanswered_request = $(if ([string]$result.FirstUnansweredRequest -match '^[0-9a-f]{2,4}/[0-9a-f]{2,4}$') { [string]$result.FirstUnansweredRequest } else { '' })
        unanswered_request_count = [int]$result.UnansweredRequestCount
        lobby_fixture_loaded = [bool]$result.LobbyFixtureLoaded
        login_check_reply_written = [bool]$result.LoginCheckReplyWritten
        menu_ba_replies = [int]$result.MenuBaReplies
        menu_bc_replies = [int]$result.MenuBcReplies
        menu_cc_replies = [int]$result.MenuCcReplies
        menu_cc_unmatched_bodies = @($result.MenuCcUnmatchedBodies | Where-Object { [string]$_ -match '^[0-9a-f]{16}$' })
        channel95_claimed = [bool]$result.Channel95Claimed
        reward_record_served = [bool]$result.RewardRecordServed
        b6_replies = [int]$result.B6Replies
        level_up_grant_failure_replies = [int]$result.LevelUpGrantFailureReplies
        quest_update_replies = [int]$result.QuestUpdateReplies
        quest_update_bodies = @($result.QuestUpdateBodies | Where-Object { [string]$_ -match '^[0-9a-f]{24}$' })
        main_menu_entered_at_ms = [int]$result.MainMenuEnteredAtMs
        lobby_entered_at_ms = [int]$result.LobbyEnteredAtMs
        room_list_replies = [int]$result.RoomListReplies
        last_room_list_at_ms = [int]$result.LastRoomListAtMs
        lobby_connected_seconds = $(if ($result.LobbyEnteredAtMs -ge 0) { [int](([int]$result.LastRoomListAtMs - [int]$result.LobbyEnteredAtMs) / 1000) } else { 0 })
        last_request_at_ms = [int]$result.LastRequestAtMs
        request_counts = @($result.RequestCounts | Where-Object { [string]$_ -match '^[0-9a-f]{2,4}/[0-9a-f]{2,4}=[0-9]+$' })
        recent_post_login_headers = @($result.RecentHeaders | ForEach-Object { [ordered]@{ type = [int]$_.FrameType; action = [int]$_.Action; total_bytes = [int]$_.TotalBytes; at_ms = [int]$_.AtMs; reply_at_ms = [int]$_.ReplyAtMs; reply_bytes = [int]$_.ReplyBytes } })
        login_id_empty = [bool]$result.LoginIdEmpty
        login_id_has_at = [bool]$result.LoginIdHasAt
        login_id_case_insensitive_match = [bool]$result.LoginIdCaseInsensitiveMatch
        login_id_contains_invented = [bool]$result.LoginIdContainsInvented
        session_number = [int]$result.SessionNumber
        cash_replies = [int]$result.CashReplies
        account_source = $(if ([string]$result.AccountSource -match '^[a-z_]{1,40}$') { [string]$result.AccountSource } else { 'unrecognized' })
        user_info_replies = [int]$result.UserInfoReplies
        item_check_replies = [int]$result.ItemCheckReplies
        item_check_end_mismatches = [int]$result.ItemCheckEndMismatches
        avatar_selects = [int]$result.AvatarSelects
        equip_changes = [int]$result.EquipChanges
        unequip_changes = [int]$result.UnequipChanges
        lobby_action_rejects = [int]$result.LobbyActionRejects
        lobby_action_reject_reasons = @($result.LobbyActionRejectReasons | Where-Object { [string]$_ -match '^[0-9a-f]{2,4}/[0-9a-f]{2,4}:[a-z0-9_]{1,40}$' })
        account_save_failures = [int]$result.AccountSaveFailures
        keepalive_1f10_count = [int]$result.KeepaliveCount
        purchase_replies = [int]$result.PurchaseReplies
        purchase_observed_records = [int]$result.PurchaseObservedRecords
    }
    # 1.24: saved account summary (catalog IDs of equipped items; game data, no credentials).
    if ($null -ne $rfProbe.Accounts -and $rfProbe.Accounts.Exists) {
        try {
            $acct = $rfProbe.Accounts.Load()
            $equipped = @()
            foreach ($a in $acct.Avatars) {
                for ($n = 0; $n -lt 45; $n++) {
                    $item = $(if ($a.Slots[$n] -ne 0) { $acct.FindItem($a.Slots[$n]) } else { $null })
                    if ($null -ne $item) { $equipped += ('avatar' + $a.Id + ' slot' + $n + '=' + $item.Catalog) }
                }
            }
            $rfReport.account = [ordered]@{ profile = $Profile; level = [int]$acct.Level; experience = [int64]$acct.Experience; items = [int]$acct.Items.Count
                unlimited_currency = [bool]$acct.UnlimitedCurrency; shown_carats = [int]$acct.EffectiveCarats; shown_astros = [int]$acct.EffectiveAstros
                current_avatar = [int]$acct.CurrentAvatar; equipped = $equipped; dangling_references = @($acct.DanglingReferences()).Count }
        } catch { $rfReport.account = 'unreadable' }
    }
    # 1.23: every ended client session of this server run (the probe field above is the latest).
    $rfReport.client_sessions_ended = [int]$rfProbe.EndedSessionCount
    $rfReport.client_sessions = @(ConvertFrom-RFSessionLines $rfProbe.SessionLines)
}

# 1.25 independence audit: TCP endpoints of processes running from the game folder (game,
# launcher, GameGuard). Loopback and the two locally owned addresses are expected; anything
# else is an official/external dependency and is recorded with its first-seen time.
$rfGameFolder = 'C:\PlayRedFox\RumbleFighter'
$rfExternal = [ordered]@{}
function Update-RFExternalAudit([double]$Seconds) {
    try {
        $procs = @{}
        foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop | Where-Object { [string]$_.ExecutablePath -like ($rfGameFolder + '\*') })) {
            $procs[[int]$p.ProcessId] = [IO.Path]::GetFileName([string]$p.ExecutablePath)
        }
        if ($procs.Count -eq 0) { return }
        foreach ($c in @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $procs.ContainsKey([int]$_.OwningProcess) })) {
            $remote = [string]$c.RemoteAddress
            if ($remote -in @('0.0.0.0', '::', '127.0.0.1', '::1') -or $rfVips -contains $remote -or [string]$c.State -eq 'Listen') { continue }
            $key = $procs[[int]$c.OwningProcess] + ' -> ' + $remote + ':' + $c.RemotePort
            if (-not $rfExternal.Contains($key)) {
                $rfExternal[$key] = [ordered]@{ endpoint = $key; first_seen_s = [Math]::Round($Seconds, 1); state = [string]$c.State }
                Write-RFMessage ('EXTERNAL CONNECTION (not local): ' + $key + ' [' + $c.State + ']')
            }
        }
    } catch { }
}
function Get-RFDnsAudit {
    try {
        return @(Get-DnsClientCache -ErrorAction Stop | Where-Object { $_.Entry -match '(?i)playredfox|gameguard|nprotect|rumble|gemnet' } |
            ForEach-Object { [ordered]@{ name = [string]$_.Entry; data = [string]$_.Data; type = [int]$_.Type } })
    } catch { return @('dns_cache_unreadable') }
}

function Stop-RFPlaza([string]$Reason) {
    if ($null -ne $rfPlaza) { $rfPlaza.Stop($Reason) }
    if ($null -ne $rfRecorder) { $rfRecorder.Stop() }
    $rfReport.independence_audit = [ordered]@{
        external_tcp_endpoints = @($rfExternal.Values)
        dns_cache_game_names = @(Get-RFDnsAudit)
        note = 'TCP endpoints of processes running from the game folder other than loopback and the locally owned 5.188.32.117/.116, sampled every 2 s while the server ran; DNS cache filtered to game/GameGuard names.'
    }
    if ($null -ne $rfPlaza) {
        $rfReport.plaza = [ordered]@{
            connect_success_count = [int]$rfPlaza.ConnectSuccessCount
            connections_ended = [int]$rfPlaza.EndedConnections
            connections = @(ConvertFrom-RFSessionLines $rfPlaza.Lines)
            tcp3416_connections = [int]$rfRecorder.TcpConnections; tcp3416_bytes_in = [int]$rfRecorder.TcpBytesIn
            udp34162_datagrams = [int]$rfRecorder.UdpDatagrams; udp34162_bytes_in = [int]$rfRecorder.UdpBytesIn
        }
    }
}

# Session-log lines are produced by the probe from status codes, counters and hex
# headers only; anything that does not parse is skipped rather than copied.
function ConvertFrom-RFSessionLines($Lines) {
    $records = @()
    foreach ($line in @($Lines | Select-Object -Last 500)) {
        if ([string]::IsNullOrWhiteSpace([string]$line)) { continue }
        try { $records += ([string]$line | ConvertFrom-Json -ErrorAction Stop) } catch { }
    }
    return $records
}

function Write-RFSessionEnd($Record, [switch]$Final) {
    $lobby = $(if ([int]$Record.lobby_entered_at_ms -ge 0) { 'lobby reached, ' + $Record.room_list_replies + ' room polls answered' } elseif ([int]$Record.main_menu_entered_at_ms -ge 0) { 'main menu reached' } else { 'before the main menu' })
    $unanswered = $(if ([int]$Record.unanswered_request_count -gt 0) { '; unanswered requests: ' + $Record.unanswered_request_count + ' (first ' + $Record.first_unanswered_request + ')' } else { '' })
    Write-RFMessage ('CLIENT SESSION ' + $Record.session + ' ENDED: ' + $Record.end_reason + '; ' + $lobby + '; Get_Cash replies: ' + $Record.cash_replies + $unanswered + $(if ($Final) { '.' } else { '. The server keeps listening; reconnect or press Q / Ctrl+C to stop.' }))
}

try {
    $rfStage = 'administrator_required'
    $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-RFMessage 'Right-click the CMD file and choose Run as administrator. No network changes were made.'
        throw 'administrator_required'
    }
    $rfStage = 'powershell_5_1_required'
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') { throw 'powershell_5_1_required' }
    $rfStage = 'another_test_is_running'
    if ($rfWatchdog) {
        # 1.23 watchdog: wait for the test process to end (normally, by window close or
        # killed), then take the test mutex (released or abandoned by that process).
        $rfStage = 'invalid_watchdog_arguments'
        if ($WatchdogTestId -notmatch '^[a-f0-9]{32}$') { throw 'invalid_watchdog_arguments' }
        try { $rfParent = [Diagnostics.Process]::GetProcessById($WatchdogFor) } catch [ArgumentException] { $rfParent = $null }
        if ($null -ne $rfParent) { try { $rfParent.WaitForExit() } finally { $rfParent.Dispose() } }
        $rfStage = 'another_test_is_running'
    }
    $rfMutex = [Threading.Mutex]::new($false, 'Global\RFLocalHandshake_5_188_32_117_7000')
    try { $rfHasMutex = $rfMutex.WaitOne($(if ($rfWatchdog) { -1 } else { 0 })) }
    catch [Threading.AbandonedMutexException] { $rfHasMutex = $true }
    if (-not $rfHasMutex) {
        Write-RFMessage 'Another test, or the cleanup watchdog of a closed test window (it waits for the game and launcher to close), is running. Close the game and launcher, wait a few seconds, and try again.'
        throw 'another_test_is_running'
    }
    $rfStage = 'network_cmdlets_unavailable'
    foreach ($name in @('Get-NetIPAddress', 'Get-NetIPInterface', 'Get-NetRoute', 'Get-NetTCPConnection', 'New-NetIPAddress', 'Remove-NetIPAddress')) {
        $null = Get-Command -Name $name -ErrorAction Stop
    }

    if ($rfWatchdog) {
        # Only this test's own journal is ever cleaned here; anything else is left alone.
        $rfStage = 'invalid_ownership_journal'
        if (-not [IO.File]::Exists($rfJournalPath)) {
            $rfSkipReport = $true   # the test cleaned up itself
        } else {
            $rfState = Read-RFJournal
            if ($rfState.test_id -ne $rfTestId) {
                $rfSkipReport = $true   # a later test owns the journal now
            } else {
                $rfStage = 'original_test_process_still_running'
                Assert-RFOwnerStopped $rfState
                $rfOwnsJournal = $true
                $rfReport.status = 'watchdog_cleanup_after_test_process_ended'
            }
        }
    } elseif ($CleanupOnly) {
        $rfStage = 'ownership_journal_unavailable'
        if (-not [IO.File]::Exists($rfJournalPath)) {
            $rfReport.status = 'no_ownership_journal'
            Write-RFMessage 'No ownership journal exists in this folder. No address will be removed. Use the original test folder, or reboot if an interrupted test left its temporary address.'
        } else {
            $rfState = Read-RFJournal
            $rfStage = 'original_test_process_still_running'
            Assert-RFOwnerStopped $rfState
            $rfOwnsJournal = $true
            $rfReport.status = 'cleanup_requested'
        }
    } else {
        $rfStage = 'previous_cleanup_required'
        if ([IO.File]::Exists($rfJournalPath)) {
            # 1.23: recover an earlier test's journal with the same verified cleanup, but only
            # when its owner process has ended (we hold the mutex, so no watchdog is cleaning).
            $rfPrevious = Read-RFJournal
            $rfStage = 'original_test_process_still_running'
            Assert-RFOwnerStopped $rfPrevious
            Write-RFMessage 'An earlier test left its ownership journal and its process has ended. Running its verified cleanup first.'
            $rfStage = 'previous_cleanup_required'
            Remove-RFOwnedAddress $rfPrevious
            $rfReport.previous_journal_recovery = $rfReport.cleanup
            $rfReport.cleanup = [ordered]@{ status = 'not_needed'; error_code = $null; address_absent = $null; route_absent = $null; journal_removed = $false; listener_stopped = $false; waiting_for_processes = @() }
            if ($rfReport.previous_journal_recovery.status -ne 'verified_removed') { throw 'previous_cleanup_pending' }
        }
        $rfStage = 'probe_compile_or_selftest_failed'
        Add-Type -Path @([IO.Path]::Combine($rfDirectory, 'RFHandshakeProbe.cs'), [IO.Path]::Combine($rfDirectory, 'RFAccount.cs'),
            [IO.Path]::Combine($rfDirectory, 'RFPlaza.cs')) -ErrorAction Stop
        # 1.23: Ctrl+C / Ctrl+Break now only request a graceful stop (checked below), so the
        # cleanup in finally is never interrupted; window close stops the server directly.
        $rfReport.checks.console_handler_installed = [RFLocalHandshake.ConsoleGuard]::Install($null)
        [RFLocalHandshake.Probe]::SelfTest()
        $rfReport.checks.probe_selftest = $true
        $rfStage = 'journal_selftest_failed'
        Test-RFAtomicJson
        $rfReport.checks.journal_create_replace_readback = $true
        $rfStage = 'game_or_launcher_must_be_closed'
        if (@(Get-RFGameProcesses).Count -gt 0) {
            Write-RFMessage 'Close Rumble Fighter and its launcher, then run this test again. No network changes were made.'
            throw 'game_or_launcher_must_be_closed'
        }
        $rfStage = 'capture_selection_failed'
        Write-RFMessage 'This version reuses only the GameGuard initialization frame from your original rf-startup.pcapng capture. It does not implement fresh GameGuard authentication.'
        $rfCapturePath = [IO.Path]::Combine($rfDirectory, 'rf-startup.pcapng')
        if (-not [IO.File]::Exists($rfCapturePath)) {
            # Preservation workspace layout: work\protocol-lab -> private\captures.
            $rfPrivateCapture = [IO.Path]::GetFullPath([IO.Path]::Combine($rfDirectory, '..\..\private\captures\rf-startup.pcapng'))
            if ([IO.File]::Exists($rfPrivateCapture)) { $rfCapturePath = $rfPrivateCapture }
        }
        if (-not [IO.File]::Exists($rfCapturePath)) {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
            $rfDialog = [Windows.Forms.OpenFileDialog]::new()
            try {
                $rfDialog.Title = 'Select the original rf-startup.pcapng capture you previously uploaded'
                $rfDialog.Filter = 'Packet capture (*.pcapng)|*.pcapng'
                $rfDialog.Multiselect = $false
                $rfDialog.CheckFileExists = $true
                $rfDialog.InitialDirectory = $rfDirectory
                if ($rfDialog.ShowDialog() -ne [Windows.Forms.DialogResult]::OK) { throw 'capture_selection_cancelled' }
                $rfCapturePath = $rfDialog.FileName
            } finally { $rfDialog.Dispose() }
        }
        $rfStage = 'capture_fixture_validation_failed'
        [byte[]]$rfCaptureFrame = $null
        try {
            $rfCaptureFrame = [RFLocalHandshake.Probe]::LoadCapturedInitialization($rfCapturePath)
            $rfProbe = [RFLocalHandshake.Probe]::new()
            $rfProbe.ClassFixture = -not $EmptyCharacter
            # 1.20 controlled experiment: claimed channel 95 (+ its reward record); -Unclaimed95 reverts.
            $rfProbe.Channel95Claimed = -not $Unclaimed95
            # 1.19: main-menu frames from ONE official session (private, hash-pinned in the probe).
            $rfLobbyPath = [IO.Path]::GetFullPath([IO.Path]::Combine($rfDirectory, '..\..\private\fixtures\lobby-boss-v2.bin'))
            try { $rfProbe.SetLobbyFixture([RFLocalHandshake.Probe]::LoadLobbyFixture($rfLobbyPath)) }
            catch { Write-RFMessage 'Main-menu fixture missing or altered (private\fixtures\lobby-boss-v2.bin): main-menu requests will be observed but not answered.' }
            $rfProbe.SetCapturedInitialization($rfCaptureFrame)
            $rfReport.checks.capture_fixture_verified = $true
            if (-not $EmptyCharacter) {
                # 1.24: persistent account profile (created from the baseline at first login).
                $rfProbe.Accounts = [RFLocalHandshake.AccountStore]::new([IO.Path]::Combine($rfPrivateRoot, 'accounts', $Profile + '.txt'))
                $rfReport.account_profile = $Profile
                # 1.26: observed item records used for purchases (optional; reference shape otherwise).
                try { $rfProbe.ItemRecords = [RFLocalHandshake.ItemCatalog]::Load([IO.Path]::Combine($rfPrivateRoot, 'fixtures', 'item-records.v1.tsv')) }
                catch { Write-RFMessage 'Item-record table missing: purchases use the reference record shape only.' }
            }
            $null = [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($rfSessionLogPath))
            $rfProbe.SessionLogPath = $rfSessionLogPath
            $rfReport.session_log = 'private/run-logs/server-' + $rfTestId + '.jsonl'
            $null = [RFLocalHandshake.ConsoleGuard]::Install($rfProbe)
        } finally {
            if ($null -ne $rfCaptureFrame) { [Array]::Clear($rfCaptureFrame, 0, $rfCaptureFrame.Length) }
            $rfCaptureFrame = $null
            $rfCapturePath = $null
        }
        $rfStage = 'software_loopback_preflight_failed'
        $rfLoop = Get-RFLoopback
        $rfReport.checks.unique_software_loopback = $true
        $rfStage = 'target_address_already_present'
        if (@(Get-RFAddresses 'ActiveStore').Count -gt 0 -or @(Get-RFAddresses 'PersistentStore').Count -gt 0) { throw 'target_address_already_present' }
        $rfStage = 'target_route_already_present'
        if (@(Get-RFRoutes 'ActiveStore').Count -gt 0 -or @(Get-RFRoutes 'PersistentStore').Count -gt 0) { throw 'target_route_already_present' }
        $rfStage = 'tcp_preflight_failed'
        $rfConnections = @(Get-NetTCPConnection -ErrorAction Stop)
        $active = @($rfConnections | Where-Object {
            ($rfVips -contains $_.RemoteAddress -or $rfVips -contains $_.LocalAddress) -and
            [string]$_.State -notin @('Listen', 'TimeWait', 'Closed', 'DeleteTcb')
        })
        if ($active.Count -gt 0) { $rfStage = 'target_connections_still_active'; throw 'target_connections_still_active' }
        $rfConflictAddresses = @('0.0.0.0', '::') + $rfVips + @($rfVips | ForEach-Object { '::ffff:' + $_ })
        $listeners = @($rfConnections | Where-Object {
            [string]$_.State -eq 'Listen' -and @($rfPort, $rfPlazaPort, 3416) -contains [int]$_.LocalPort -and
            $rfConflictAddresses -contains $_.LocalAddress
        })
        if ($listeners.Count -gt 0) {
            Write-RFMessage ('Another program is listening on TCP port(s) ' + ((@($listeners | ForEach-Object { $_.LocalPort }) | Sort-Object -Unique) -join ', ') + ' for all addresses or a game address. Close it and run this test again. No network changes were made.')
            $rfStage = 'conflicting_tcp_listener'; throw 'conflicting_tcp_listener'
        }
        $rfUdpConflicts = @(Get-NetUDPEndpoint -ErrorAction SilentlyContinue | Where-Object { [int]$_.LocalPort -eq 34162 -and $rfConflictAddresses -contains $_.LocalAddress })
        if ($rfUdpConflicts.Count -gt 0) {
            Write-RFMessage 'Another program uses UDP port 34162 for all addresses. Close it and run this test again. No network changes were made.'
            $rfStage = 'conflicting_udp_endpoint'; throw 'conflicting_udp_endpoint'
        }
        $rfStage = 'portproxy_preflight_failed'
        Assert-RFNoPortProxy
        $rfReport.checks.existing_configuration_clear = $true
        $rfStage = 'ownership_journal_write_failed'
        $rfOwner = [Diagnostics.Process]::GetCurrentProcess()
        $rfState = [ordered]@{
            schema = 'rf-loopback-ownership-v2'; test_id = $rfTestId; phase = 'creation_intent'
            addresses = @($rfVips); prefix_length = 32; skip_as_source = $true; policy_store = 'ActiveStore'
            interface_index = $rfLoop.Index; interface_id = $rfLoop.Id
            owner_pid = $PID; owner_start_ticks = $rfOwner.StartTime.ToUniversalTime().Ticks.ToString()
            created_utc = [DateTime]::UtcNow.ToString('o')
        }
        $rfOwner.Dispose()
        Write-RFAtomicJson $rfJournalPath $rfState $false
        $rfOwnsJournal = $true
        # 1.23: the watchdog (own hidden console, so a closed window or Ctrl+C here does not
        # reach it) waits for this process to end and cleans up only this journal.
        $rfStage = 'watchdog_start_failed'
        $rfWatchdogProcess = Start-Process -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) -WindowStyle Hidden -PassThru -ArgumentList @(
            '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $PSCommandPath + '"'),
            '-WatchdogFor', [string]$PID, '-WatchdogTestId', $rfTestId)
        $rfReport.checks.watchdog_started = ($null -ne $rfWatchdogProcess)
        if ($null -ne $rfWatchdogProcess) { $rfWatchdogProcess.Dispose() }
        if ([RFLocalHandshake.ConsoleGuard]::StopRequested) { throw 'user_stopped_during_setup' }
        $rfStage = 'temporary_loopback_address_rejected'
        Write-RFMessage 'Starting a temporary local test: all traffic to 5.188.32.117 (lobby) and 5.188.32.116 (plaza) will stay on this computer. Close the game and launcher when prompted so cleanup can restore the routes.'
        foreach ($rfIp in $rfVips) {
            $rfStage = 'temporary_loopback_address_rejected'
            $null = New-NetIPAddress -InterfaceIndex $rfLoop.Index -AddressFamily IPv4 -IPAddress $rfIp -PrefixLength 32 -SkipAsSource $true -PolicyStore ActiveStore -ErrorAction Stop
            $rfStage = 'temporary_address_query_failed'
            $rfAddressWatch = [Diagnostics.Stopwatch]::StartNew()
            do {
                $rfAdded = @(Get-RFAddresses 'ActiveStore' @($rfIp))
                Set-RFAddressObservation $rfAdded $rfLoop.Index
                $preferred = $rfAdded.Count -eq 1 -and [string]$rfAdded[0].AddressState -eq 'Preferred'
                if ($preferred) { break }
                [Threading.Thread]::Sleep(100)
            } while ($rfAddressWatch.Elapsed.TotalSeconds -lt 5)
            if ($rfAdded.Count -ne 1) { throw 'temporary_address_not_unique' }
            if (-not $preferred) { throw 'temporary_address_not_preferred' }
            if ($rfAdded[0].InterfaceIndex -ne $rfLoop.Index) { throw 'temporary_address_wrong_interface' }
            if ($rfAdded[0].PrefixLength -ne 32) { throw 'temporary_address_wrong_prefix' }
            if ($rfAdded[0].SkipAsSource -ne $true) { throw 'temporary_address_source_flag_mismatch' }
            $rfStage = 'temporary_route_query_failed'
            $rfLocalRoutes = @(Get-RFRoutes 'ActiveStore' @($rfIp))
            if ($rfLocalRoutes.Count -ne 1 -or $rfLocalRoutes[0].InterfaceIndex -ne $rfLoop.Index -or $rfLocalRoutes[0].NextHop -ne '0.0.0.0') { throw 'temporary_route_verification_failed' }
        }
        $rfReport.checks.temporary_address_verified = $true
        $rfStage = 'persistent_address_query_failed'
        if (@(Get-RFAddresses 'PersistentStore').Count -gt 0) { throw 'unexpected_persistent_address' }
        $rfReport.checks.persistent_address_absent = $true
        $rfReport.checks.temporary_address_and_route_verified = $true
        $rfStage = 'ownership_journal_update_failed'
        $rfState.phase = 'address_verified'
        Write-RFAtomicJson $rfJournalPath $rfState $true
        $rfReport.checks.ownership_journal_updated = $true
        $rfStage = 'local_socket_preflight_failed'
        $rfProbe.Start()
        if (-not $rfProbe.Ready) { throw 'local_probe_not_ready' }
        $rfReport.checks.probe_ready = $true
        # 1.24: plaza (ProudNet core handshake) on .116:33343, record-only TCP 3416 / UDP 34162.
        $rfStage = 'plaza_start_failed'
        $rfPlaza = [RFLocalHandshake.PlazaServer]::new([Net.IPAddress]::Parse($rfPlazaVip), $rfPlazaPort, $rfExpectedClientHash)
        $rfPlaza.LogPath = $rfSessionLogPath
        $rfPlaza.Start()
        $rfRecorder = [RFLocalHandshake.OpaqueRecorder]::new()
        $rfRecorder.LogPath = $rfSessionLogPath
        $rfRecorder.Start([Net.IPAddress]::Parse($rfPlazaVip), 3416, 34162)
        $rfReport.checks.plaza_ready = $rfPlaza.Ready
        [RFLocalHandshake.ConsoleGuard]::Attach($rfPlaza, $rfRecorder)
        Write-RFMessage 'READY. Open your normal Rumble Fighter launcher now. Wait for GAME CONNECTED in this window before clicking Sign In.'
        Write-RFMessage 'The server now runs until YOU stop it: press Q or Ctrl+C in THIS window. Closing the game or disconnecting ends only that client session; the server keeps listening and you can reconnect.'
        Write-RFMessage 'Closing this window also stops the server; a hidden watchdog then removes the temporary addresses once the game and launcher are closed.'
        Write-RFMessage ('During this test only, all traffic to 5.188.32.117 and 5.188.32.116 stays on this computer. Account profile: ' + $Profile + $(if ($EmptyCharacter) { ' (not used: empty-character mode)' } else { '' }) + '.')
        $rfStage = 'probe_monitoring_failed'
        $rfWatch = [Diagnostics.Stopwatch]::StartNew()
        $rfGameNoticeShown = $false
        $rfLastStatus = 0
        $rfTargetSession = 0
        $rfSeenSessions = 0
        $rfConnectedSession = 0
        $rfGameExitNoticed = $false
        $rfLastAudit = -10; $rfPlazaSeen = 0; $rfPlazaEndedSeen = 0
        $rfReport.server_end_reason = 'monitor_failed'
        # 1.23: no wall-clock limit; only an explicit stop or a failed listener ends the loop.
        while ($true) {
            if ($rfProbe.Completed) {
                $rfReport.server_end_reason = 'listener_stopped_unexpectedly'
                Write-RFMessage 'The local server stopped unexpectedly (listener failure). Cleaning up.'
                break
            }
            if ([RFLocalHandshake.ConsoleGuard]::StopRequested) {
                $rfReport.server_end_reason = [RFLocalHandshake.ConsoleGuard]::StopEvent
                Write-RFMessage ('Stop requested (' + $rfReport.server_end_reason + '). Stopping the server, saving the report, then cleaning up.')
                break
            }
            $rfStopRequested = $false
            try {
                while ([Console]::KeyAvailable) {
                    if ([Console]::ReadKey($true).Key -eq [ConsoleKey]::Q) { $rfStopRequested = $true }
                }
            } catch { }
            if ($rfStopRequested) {
                $rfReport.server_end_reason = 'user_stop_key'
                Write-RFMessage 'Stop requested (Q). Stopping the server, saving the report, then cleaning up.'
                break
            }
            if ($null -ne $rfGameProcess -and -not $rfGameExitNoticed) {
                try {
                    $rfGameProcess.Refresh()
                    if ($rfGameProcess.HasExited) {
                        $rfGameExitNoticed = $true
                        Write-RFMessage ('The game process exited (code 0x{0:X8}). The server keeps listening: start the game again to reconnect, or press Q / Ctrl+C to stop and clean up.' -f ([int64]$rfGameProcess.ExitCode -band 0xFFFFFFFF))
                    }
                } catch { }
            }
            if ($rfWatch.Elapsed.TotalSeconds - $rfLastAudit -ge 2) {
                $rfLastAudit = $rfWatch.Elapsed.TotalSeconds
                Update-RFExternalAudit $rfWatch.Elapsed.TotalSeconds
                $rfPlazaOk = $rfPlaza.ConnectSuccessCount
                if ($rfPlazaOk -gt $rfPlazaSeen) {
                    $rfPlazaSeen = $rfPlazaOk
                    Write-RFMessage ('PLAZA: local plaza session established (ConnectSuccess sent, connection ' + $rfPlazaOk + '). The client log should now show "P2P Connected : 3" or higher.')
                }
                $rfPlazaEndedNow = $rfPlaza.EndedConnections
                if ($rfPlazaEndedNow -gt $rfPlazaEndedSeen) {
                    foreach ($rfPl in @(ConvertFrom-RFSessionLines $rfPlaza.Lines | Select-Object -Last ($rfPlazaEndedNow - $rfPlazaEndedSeen))) {
                        Write-RFMessage ('PLAZA connection ' + $rfPl.connection + ' ended: ' + $rfPl.end_reason + '; stage ' + $rfPl.stage + '; peer ' + $rfPl.peer + '; last server frame ' + $rfPl.last_server_frame + '.')
                    }
                    $rfPlazaEndedSeen = $rfPlazaEndedNow
                }
            }
            $rfEnded = $rfProbe.EndedSessionCount
            if ($rfEnded -gt $rfSeenSessions) {
                foreach ($rfRecord in @(ConvertFrom-RFSessionLines $rfProbe.SessionLines)) {
                    if ([int]$rfRecord.session -gt $rfSeenSessions) { Write-RFSessionEnd $rfRecord }
                }
                $rfSeenSessions = $rfEnded
            }
            if ($rfWatch.Elapsed.TotalSeconds - $rfLastStatus -ge 30) {
                $rfLastStatus = $rfWatch.Elapsed.TotalSeconds
                $rfLive = $rfProbe.Result
                if ($rfLive.LobbyEnteredAtMs -ge 0 -and $rfLive.ConnectionEndedAtMs -lt 0) {
                    $rfLobbySeconds = [int](($rfLive.LastRoomListAtMs - $rfLive.LobbyEnteredAtMs) / 1000)
                    Write-RFMessage ('LOBBY (session ' + $rfLive.SessionNumber + '): room-list polls answered ' + $rfLive.RoomListReplies + '; connected in the lobby for ' + $rfLobbySeconds + ' s (first to latest poll); Get_Cash replies ' + $rfLive.CashReplies + '; unanswered requests ' + $rfLive.UnansweredRequestCount + '.')
                    if ($rfTargetSession -ne $rfLive.SessionNumber -and $rfLobbySeconds -ge 300) {
                        $rfTargetSession = $rfLive.SessionNumber
                        Write-RFMessage '5-MINUTE MILESTONE REACHED (acceptance check only; the server keeps running). Continue with the test steps.'
                    }
                }
            }
            $rfPendingPort = $rfProbe.PendingPort
            $rfPendingAddress = $rfProbe.PendingAddress
            if ($rfPendingPort -gt 0 -and -not [string]::IsNullOrEmpty($rfPendingAddress)) {
                $peers = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
                    $_.RemoteAddress -eq $rfVip -and $_.RemotePort -eq $rfPort -and
                    $_.LocalPort -eq $rfPendingPort -and $_.LocalAddress -eq $rfPendingAddress -and
                    [string]$_.State -eq 'Established'
                })
                if ($peers.Count -eq 1) {
                    $peer = $null
                    try {
                        $peer = [Diagnostics.Process]::GetProcessById([int]$peers[0].OwningProcess)
                        if ($peer.ProcessName -ieq 'rumblefighter') {
                            $rfVerifiedBuild = $false
                            try {
                                $rfClientPath = $peer.MainModule.FileName
                                $rfActualHash = (Get-FileHash -LiteralPath $rfClientPath -Algorithm SHA256 -ErrorAction Stop).Hash
                                $rfVerifiedBuild = $rfActualHash -ieq $rfExpectedClientHash
                                $rfReport.client_build_check = $(if ($rfVerifiedBuild) { 'verified' } else { 'hash_mismatch' })
                            } catch { $rfReport.client_build_check = 'unreadable' }
                            $rfReport.client_build_verified = $rfVerifiedBuild
                            if ($rfProbe.PendingPort -eq $rfPendingPort -and $rfProbe.PendingAddress -eq $rfPendingAddress) {
                                $rfDecisionAccepted = $rfProbe.AuthorizePeer($rfPendingPort, $rfVerifiedBuild)
                                if ($rfVerifiedBuild -and $rfDecisionAccepted) {
                                    $rfReport.game_peer_correlated = $true
                                    $rfReport.correlated_process_name = 'rumblefighter'
                                    $rfConnection = [int]$rfProbe.Result.SessionNumber
                                    if ($rfGameNoticeShown -and $rfConnection -ne $rfConnectedSession) {
                                        Write-RFMessage ('GAME CONNECTED again (connection ' + $rfConnection + '). Sign in with the same invented password ProbeOnly123! if the game asks.')
                                        # A restarted game is a new process: follow it for exit notices.
                                        if ($null -eq $rfGameProcess -or $rfGameProcess.Id -ne [int]$peers[0].OwningProcess) {
                                            try {
                                                $rfNewGame = [Diagnostics.Process]::GetProcessById([int]$peers[0].OwningProcess)
                                                $null = $rfNewGame.Handle
                                                if ($null -ne $rfGameProcess) { $rfGameProcess.Dispose() }
                                                $rfGameProcess = $rfNewGame
                                                $rfGameExitNoticed = $false
                                            } catch { }
                                        }
                                    }
                                    $rfConnectedSession = $rfConnection
                                    if (-not $rfGameNoticeShown) {
                                        Write-RFMessage 'GAME CONNECTED: the exact game build is connected to this local probe.'
                                        Write-RFMessage 'In the game, replace BOTH saved login fields. Use email probe@test.invalid and password ProbeOnly123! Then click Sign In ONCE. These are invented values, not an account.'
                                        Write-RFMessage 'Only the password matters for this local test: type ProbeOnly123! in the password box. Typing probe@test.invalid in the ID box is still preferred.'
                                        Write-RFMessage 'This version continues local startup through an empty buddy list and one invented, unequipped local avatar. Note any new screen or error. Never use your real account or password here.'
                                        $rfGameNoticeShown = $true
                                        # Hold a handle so exit time/code stay readable after exit.
                                        try {
                                            $rfGameProcess = [Diagnostics.Process]::GetProcessById([int]$peers[0].OwningProcess)
                                            $null = $rfGameProcess.Handle
                                            $rfGameProcessStartUtc = $rfGameProcess.StartTime.ToUniversalTime().ToString('o')
                                            $rfGameLogDirectory = [IO.Path]::GetDirectoryName($rfClientPath)
                                        } catch { $rfGameProcess = $null }
                                        $rfGuardBefore = Get-RFGuardLogState
                                    }
                                }
                            }
                        }
                    } catch [ArgumentException] { }
                    finally { if ($null -ne $peer) { $peer.Dispose() } }
                }
            }
            [Threading.Thread]::Sleep(100)
        }
        # Deliberate shutdown: stop accepting and close the active socket (logged once as
        # server_shutdown), then report every client session.
        $rfStage = 'server_shutdown_failed'
        $rfProbe.Stop($rfReport.server_end_reason)
        Stop-RFPlaza ([string]$rfReport.server_end_reason)
        $rfReport.cleanup.listener_stopped = $true
        Set-RFProbeReport
        foreach ($rfRecord in @($rfReport.client_sessions)) {
            if ([int]$rfRecord.session -gt $rfSeenSessions) { Write-RFSessionEnd $rfRecord -Final }
        }
        Write-RFMessage ('SERVER STOPPED (' + $rfReport.server_end_reason + '). Client sessions served: ' + $rfReport.client_sessions_ended + '.')
        $rfReport.status = 'probe_finished'
        if ($rfReport.probe.avatar_list_reply_written -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_local_avatar_candidates_written'
            Write-RFMessage ('Avatar list written: ' + $rfReport.probe.avatar_list_reply_written + '; equipped avatar: ' + $rfReport.probe.equipped_avatar_reply_written + '; equipment: ' + $rfReport.probe.avatar_equipment_reply_written + '; avatar update acks A2/A4/A6: ' + $rfReport.probe.avatar_a2_ack_count + '/' + $rfReport.probe.avatar_a4_ack_count + '/' + $rfReport.probe.avatar_a6_ack_count + '; grade replies: ' + $rfReport.probe.grade_reply_count + '; B4 replies: ' + $rfReport.probe.b4_reply_count + '; GameGuard answers received: ' + $rfReport.probe.gameguard_answer_count + '; grade-up requested ID: ' + $rfReport.probe.grade_up_requested_id + '. Stop reason: ' + $rfReport.probe.post_login_stop_reason + '.')
            Write-RFMessage 'Screenshot the game screen now (lobby, character screen, or error). Then close BOTH the game and launcher when prompted, and wait for Cleanup verified.'
            Write-RFMessage 'Upload the newly dated version 1.28 report from this folder after cleanup finishes.'
        } elseif ($rfReport.probe.buddy_reply_written -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_empty_buddy_list_written'
            Write-RFMessage ('Empty buddy list written (' + $rfReport.probe.buddy_reply_bytes + ' bytes). Stop reason: ' + $rfReport.probe.post_login_stop_reason + '. The report lists the next request header the game sent.')
            Write-RFMessage 'Screenshot any new screen or error now. Then close BOTH the game and launcher when prompted, and wait for Cleanup verified.'
            Write-RFMessage 'Upload the newly dated version 1.28 report from this folder after cleanup finishes.'
        } elseif ($rfReport.probe.gift_from_reply_written -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_zero_filled_gift_candidates_written'
            Write-RFMessage ('Received-gift candidate written: ' + $rfReport.probe.gift_from_reply_written + '; sent-gift candidate written: ' + $rfReport.probe.gift_to_reply_written + '. These writes alone do not prove empty-list acceptance.')
            Write-RFMessage 'Screenshot any new screen or error now. Then close BOTH the game and launcher when prompted, and wait for Cleanup verified.'
            Write-RFMessage 'Upload the newly dated version 1.28 report from this folder after cleanup finishes.'
        } elseif ($rfReport.probe.property_reply_count -gt 0 -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_empty_property_replies_written'
            Write-RFMessage ('Empty inventory replies written: ' + $rfReport.probe.property_reply_count + '. The report records the next header or stopping reason; this does not establish a usable character or lobby.')
            Write-RFMessage 'Screenshot any new screen or error now. Then close BOTH the game and launcher when prompted, and wait for Cleanup verified.'
            Write-RFMessage 'Upload the newly dated version 1.28 report from this folder after cleanup finishes.'
        } elseif ($rfReport.probe.post_login_stop_reason -eq 'property_owner_mismatch' -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_property_owner_mismatch'
            Write-RFMessage 'The inventory request did not match the local test account. No inventory reply was sent. The report contains counters only, not the received identifier.'
            Write-RFMessage 'Close BOTH the game and launcher when prompted, let cleanup finish, and upload the new version 1.28 report.'
        } elseif ($rfReport.probe.local_cash_reply_written -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_local_startup_and_balance_replies_written'
            Write-RFMessage 'The startup acknowledgement and zero local balances were written. The report records the next header or stopping reason; this does not establish a usable lobby or ongoing GameGuard authentication.'
            Write-RFMessage 'Screenshot any new screen or error now. Then close BOTH the game and launcher when prompted, and wait for Cleanup verified.'
            Write-RFMessage 'Upload the newly dated version 1.28 report from this folder after cleanup finishes.'
        } elseif ($rfReport.probe.startup_ack_written -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_local_startup_ack_written'
            Write-RFMessage 'The startup acknowledgement was written; the local balance reply was not completed. The report records the stopping point.'
            Write-RFMessage 'Note any new screen or error, close BOTH the game and launcher when prompted, and upload the newly dated version 1.28 report after cleanup.'
        } elseif ($rfReport.probe.gameguard_replay_written -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_captured_initialization_reply_written'
            Write-RFMessage 'The captured initialization reply was written once. This is a compatibility experiment, not a complete or fresh GameGuard authentication exchange.'
            Write-RFMessage 'Record whether Start Null Error appeared, changed, or disappeared, and screenshot any new error. Close the game and launcher when prompted.'
            Write-RFMessage 'Upload the newly dated version 1.28 report from this folder after cleanup finishes.'
        } elseif ($rfReport.probe.login_reply_written -and $rfReport.probe.login_reply_kind -eq 'synthetic_success' -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_local_profile_reply_written'
            Write-RFMessage 'The fixed test credentials matched and the experimental local profile was written. This alone does not prove the game accepted it.'
            Write-RFMessage ('Post-login headers observed: ' + @($rfReport.probe.post_login_headers).Count + '; clock replies: ' + $rfReport.probe.clock_reply_count + '. The report records where this bounded test stopped.')
            Write-RFMessage 'Note or screenshot any new game screen or error, then close the game and launcher when prompted. Upload the newly dated version 1.28 report from this folder.'
        } elseif ($rfReport.probe.login_frame_received -and $rfReport.probe.login_reply_written -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_login_frame_received_local_test_reply_written'
            Write-RFMessage ('The invented test password did not match, so the local rejection banner was shown. Password field matched: ' + $rfReport.probe.login_password_field_matched + '.')
            Write-RFMessage 'Type ProbeOnly123! exactly (capital P and O) in the password box. Never enter your real password here.'
        } elseif ($rfReport.probe.reply_written -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_version_request_received_reply_written'
            Write-RFMessage 'The version request and acknowledgement write completed, but the login-message test did not finish. Send the report for its exact result.'
        } else {
            Write-RFMessage 'No complete version exchange was recorded. The report distinguishes received bytes, timeouts and connection closure.'
        }
        if ($rfReport.probe.lobby_entered_at_ms -ge 0 -and $rfReport.game_peer_correlated) {
            $rfReport.status = 'game_lobby_session'
            Write-RFMessage ('Lobby session: entered at ' + $rfReport.probe.lobby_entered_at_ms + ' ms; room-list polls answered ' + $rfReport.probe.room_list_replies + '; lobby connected ' + $rfReport.probe.lobby_connected_seconds + ' s; end reason: ' + $rfReport.session_end_reason + '.')
        }
    }
} catch {
    $rfReport.status = 'stopped_before_completion'
    $rfReport.error_code = $rfStage
    $rfReport.error_detail = Get-RFSafeErrorDetail $_
    if ($rfSafeErrorCodes -contains [string]$_.Exception.Message) { $rfReport.error_code = [string]$_.Exception.Message }
    Write-RFMessage ('Test stopped: ' + $rfReport.error_code + '. No raw exception or payload values are included in the report.')
} finally {
    if ($null -ne $rfProbe) {
        if ([string]::IsNullOrEmpty([string]$rfReport.server_end_reason) -or $rfReport.server_end_reason -eq 'monitor_failed') {
            $rfReport.server_end_reason = $(if ($null -ne $rfReport.error_code) { 'error_' + $rfReport.error_code } else { 'monitor_failed' })
        }
        try { $rfProbe.Stop([string]$rfReport.server_end_reason); Stop-RFPlaza ([string]$rfReport.server_end_reason); $rfReport.cleanup.listener_stopped = $true; Set-RFProbeReport }
        catch { $rfReport.cleanup.listener_stopped = $false }
        # 1.16: persist the probe result before the (up to 120 s) cleanup wait; the same
        # file is replaced with the final cleanup and diagnostics afterwards.
        try {
            $rfReport.report_phase = 'probe_result_saved_before_cleanup'
            $rfReport.probe_saved_utc = [DateTime]::UtcNow.ToString('o')
            Write-RFAtomicJson $rfReportPath $rfReport $false
            Write-RFMessage ('Probe result saved before cleanup: ' + $rfReportName)
        } catch { Write-RFMessage 'The early probe result could not be saved; the final report will still be written.' }
    }
    if ($rfHasMutex -and $rfOwnsJournal -and $null -ne $rfState) {
        try { Remove-RFOwnedAddress $rfState }
        catch {
            $rfReport.cleanup.status = 'pending_verification_or_cleanup_failed'
            $rfReport.cleanup.error_code = 'cleanup_operation_failed'
            if ($rfSafeErrorCodes -contains [string]$_.Exception.Message) { $rfReport.cleanup.error_code = [string]$_.Exception.Message }
            Write-RFMessage 'CLEANUP PENDING: No unrelated configuration was removed. Close the game and launcher; the background watchdog then retries the verified cleanup. CleanupLocalHandshake.cmd (as administrator, this folder) or a reboot also clears this test''s ActiveStore-only address.'
        }
    }
    if ($rfReport.cleanup.status -like 'pending*') { $rfReport.status = 'cleanup_pending' }
    if ($rfWatchdog -and -not $rfSkipReport) {
        # The closed test window could not save its report: record its client sessions from
        # the session log and append the watchdog's own cleanup outcome to that log.
        try {
            if ([IO.File]::Exists($rfSessionLogPath)) {
                $rfLogLines = @([IO.File]::ReadAllLines($rfSessionLogPath))
                $rfReport.client_sessions = @(ConvertFrom-RFSessionLines @($rfLogLines | Where-Object { $_ -like '{"event":"client_session_end"*' }))
                $rfReport.server_shutdown = @(ConvertFrom-RFSessionLines @($rfLogLines | Where-Object { $_ -like '{"event":"server_shutdown"*' }))
            }
            $rfReport.session_log = 'private/run-logs/server-' + $rfTestId + '.jsonl'
            [IO.File]::AppendAllText($rfSessionLogPath, '{"event":"watchdog_cleanup","utc":"' + [DateTime]::UtcNow.ToString('o') + '","cleanup_status":"' + ([string]$rfReport.cleanup.status -replace '[^a-z_]', '') + '"}' + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
        } catch { $rfReport.session_log_read = 'failed' }
    }
    if (-not $CleanupOnly -and -not $rfWatchdog) {
        try {
            Set-RFGameDiagnostics
            $gd = $rfReport.game_diagnostics
            Write-RFMessage ('Game exited: ' + $gd.game_process.has_exited + '; exit code: ' + $gd.game_process.exit_code_hex + '; Windows error events: ' + @($gd.windows_error_events).Count + '; game crash dumps: ' + @($gd.game_crash_dumps).Count + '; last game-log source: ' + $gd.game_log.last_line_source + '.')
        } catch { $rfReport.game_diagnostics = 'collection_failed' }
        if ($null -ne $rfGameProcess) { $rfGameProcess.Dispose() }
    }
    $rfReport.finished_utc = [DateTime]::UtcNow.ToString('o')
    if (-not $rfWatchdog) { try { [RFLocalHandshake.ConsoleGuard]::Uninstall() } catch { } }
    if (-not $rfSkipReport) { try {
        $rfReport.report_phase = 'final_with_cleanup_and_diagnostics'
        Write-RFAtomicJson $rfReportPath $rfReport ([IO.File]::Exists($rfReportPath))
        Write-RFMessage ('Report saved beside this script: ' + $rfReportName)
        Write-RFMessage 'Upload that report JSON. Do not upload the ownership journal.'
    } catch { Write-RFMessage 'The report could not be saved. Keep this window message; no private exception details were printed.' } }
    if ($rfHasMutex -and $null -ne $rfMutex) { try { $rfMutex.ReleaseMutex() } catch { } }
    if ($null -ne $rfMutex) { $rfMutex.Dispose() }
}

if ($rfReport.status -eq 'cleanup_pending' -or $null -ne $rfReport.error_code) { exit 1 }
exit 0
