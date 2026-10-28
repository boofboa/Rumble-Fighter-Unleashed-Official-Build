# 1.23/1.24 automated persistence/shutdown/isolation checks. Run as administrator with the game CLOSED.
# Offline part: self-test, two-session reconnect through the real ServeStream path
# (3000 room polls, repeated Get_Cash), console handler checks.
# Live part (loopback only): runs the real harness several times in its own console and
#   A. two plain TCP reconnects, then Ctrl+C       -> graceful stop + verified cleanup
#   B. one reconnect, then the harness is killed   -> watchdog performs verified cleanup
#   C. harness AND watchdog killed (address left)  -> next run recovers the journal
# The test clients are not the game, so each connection is refused at the peer check
# (logged as a client session "peer_not_authorized"); no game protocol bytes are sent.
# Harness reports and session logs of these runs are moved to work\reports\persistence-checks.
[CmdletBinding()]
param([switch]$OfflineOnly)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$private = [IO.Path]::GetFullPath([IO.Path]::Combine($here, '..\..\private'))
$harness = [IO.Path]::Combine($here, 'Test-RF-LocalHandshake.ps1')
$journal = [IO.Path]::Combine($here, 'rf-local-handshake-state.json')
$vip = '5.188.32.117'
$vips = @('5.188.32.117', '5.188.32.116')   # 1.24: lobby + plaza addresses
$checkProfile = 'zz-persistence-check'      # never the user's baseline profile
$results = [Collections.Generic.List[string]]::new()
$failures = 0
function Check([string]$Name, [bool]$Ok, [string]$Detail = '') {
    $line = $(if ($Ok) { 'PASS ' } else { 'FAIL ' }) + $Name + $(if ($Detail) { ' (' + $Detail + ')' } else { '' })
    $script:results.Add($line); [Console]::WriteLine($line)
    if (-not $Ok) { $script:failures++ }
}

# ---------- offline ----------
Add-Type -Path @([IO.Path]::Combine($here, 'RFHandshakeProbe.cs'), [IO.Path]::Combine($here, 'RFAccount.cs'), [IO.Path]::Combine($here, 'RFPlaza.cs'))
[RFLocalHandshake.Probe]::SelfTest()
Check 'offline self-test' $true
$capture = [IO.Path]::Combine($private, 'captures\rf-startup.pcapng')
$fixture = [IO.Path]::Combine($private, 'fixtures\lobby-boss-v2.bin')
$scratchLog = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'rf-reconnect-' + [Guid]::NewGuid().ToString('N') + '.jsonl')
try { Check 'offline reconnect: 2 sessions, 3000 polls, repeated Get_Cash, shutdown/close handlers' $true ([RFLocalHandshake.Probe]::RunScriptedReconnect($capture, $fixture, $scratchLog, 3000)) }
catch { Check 'offline reconnect' $false $_.Exception.Message }
finally { if ([IO.File]::Exists($scratchLog)) { [IO.File]::Delete($scratchLog) } }
try { Check 'offline scripted lobby (claimed95, 400 polls)' $true ([RFLocalHandshake.Probe]::RunScriptedSession($capture, $fixture, 400, $true)) }
catch { Check 'offline scripted lobby' $false $_.Exception.Message }
try { Check 'offline account state (wire identity, pagination, equip rules, store, 2-connection persistence)' $true ([RFLocalHandshake.Probe]::SelfTestAccount($capture, $fixture, [IO.Path]::Combine([IO.Path]::GetTempPath(), 'rf-account-selftest'))) }
catch { Check 'offline account state' $false $_.Exception.Message }
$plazaLog = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'rf-plaza-' + [Guid]::NewGuid().ToString('N') + '.jsonl')
try { Check 'offline plaza (ProudNet handshake, RSA round trip, pings, framing limits)' $true ([RFLocalHandshake.PlazaSelfTest]::Run($plazaLog)) }
catch { Check 'offline plaza' $false $_.Exception.Message }
finally { if ([IO.File]::Exists($plazaLog)) { [IO.File]::Delete($plazaLog) } }
# 1.25: our 04 hint must equal the captured hint in every byte except the RSA modulus
# (v1.24 shipped a two-byte-shifted settings block and the real client closed after it).
try {
    $officialHex = (& ([IO.Path]::Combine($here, '_RunPython.cmd')) ([IO.Path]::Combine($here, 'rf_official_hint.py')) ([IO.Path]::Combine($private, 'captures\rf-boss-baseline.pcapng')) | Select-Object -Last 1).Trim()
    $official = [byte[]]::new($officialHex.Length / 2); for ($i = 0; $i -lt $official.Length; $i++) { $official[$i] = [Convert]::ToByte($officialHex.Substring(2 * $i, 2), 16) }
    $ourHint = [RFLocalHandshake.PlazaServer]::new([Net.IPAddress]::Loopback, 0, [System.Management.Automation.Language.NullString]::Value).HintPayload()
    $mismatch = @(for ($i = 0; $i -lt [Math]::Max($official.Length, $ourHint.Length); $i++) { if (($i -lt 49 -or $i -gt 176) -and ($i -ge $ourHint.Length -or $i -ge $official.Length -or $official[$i] -ne $ourHint[$i])) { $i } })
    Check 'offline plaza hint identical to captured hint outside the RSA modulus (182 bytes)' ($official.Length -eq 182 -and $ourHint.Length -eq 182 -and $mismatch.Count -eq 0) ('mismatching offsets: ' + ($mismatch -join ','))
} catch { Check 'offline plaza hint identity' $false $_.Exception.Message }
if ($OfflineOnly) { $results; if ($failures) { exit 1 } else { exit 0 } }

# ---------- live (loopback) ----------
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'run as administrator' }
if (@(Get-Process | Where-Object { $_.ProcessName -in @('rumblefighter', 'RumbleLauncher') }).Count) { throw 'close the game and launcher first' }
$outDir = [IO.Path]::GetFullPath([IO.Path]::Combine($here, '..\reports\persistence-checks\' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')))
$null = [IO.Directory]::CreateDirectory($outDir)
$startedUtc = [DateTime]::UtcNow

function Get-Address { @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { $vips -contains $_.IPAddress }) }
function Get-Watchdog([string]$TestId) {
    @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { [string]$_.CommandLine -like ('*-WatchdogTestId ' + $TestId + '*') })
}
function Start-Harness {
    $before = @(Get-ChildItem -LiteralPath $here -Filter 'rf-local-handshake-2*.json' | ForEach-Object Name)
    $p = Start-Process -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) -PassThru -WindowStyle Minimized -ArgumentList @(
        '-STA', '-NoLogo', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $harness + '"'), '-Profile', $checkProfile)
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt 180) {
        if ($p.HasExited) { return [pscustomobject]@{ Process = $p; Ready = $false; TestId = $null; Before = $before } }
        if ([IO.File]::Exists($journal)) {
            try { $j = [IO.File]::ReadAllText($journal) | ConvertFrom-Json } catch { $j = $null }
            if ($null -ne $j -and $j.phase -eq 'address_verified' -and $j.owner_pid -eq $p.Id -and
                @(Get-NetTCPConnection -State Listen -LocalPort 7000 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq $vip }).Count -eq 1 -and
                @(Get-NetTCPConnection -State Listen -LocalPort 33343 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq '5.188.32.116' }).Count -eq 1) {
                return [pscustomobject]@{ Process = $p; Ready = $true; TestId = [string]$j.test_id; Before = $before }
            }
        }
        Start-Sleep -Milliseconds 250
    }
    return [pscustomobject]@{ Process = $p; Ready = $false; TestId = $null; Before = $before }
}
function Connect-Once {
    # A plain TCP client (not the game): accepted, refused at the peer check after 5 s.
    $c = [Net.Sockets.TcpClient]::new()
    try {
        $c.Connect($vip, 7000)
        $s = $c.GetStream(); $s.ReadTimeout = 9000
        $buffer = New-Object byte[] 16
        try { $n = $s.Read($buffer, 0, 16) } catch { $n = -1 }
        return $n -eq 0   # server closed the unauthorized connection
    } finally { $c.Close() }
}
function Connect-Plaza {
    # Not the game: the plaza must close the connection after its peer check, sending nothing.
    $c = [Net.Sockets.TcpClient]::new()
    try {
        $c.Connect('5.188.32.116', 33343)
        $s = $c.GetStream(); $s.ReadTimeout = 9000
        $policyRequest = [byte[]](0x13, 0x57, 0x01, 0x01, 0x2e)
        $s.Write($policyRequest, 0, 5)
        $buffer = New-Object byte[] 16
        $w = [Diagnostics.Stopwatch]::StartNew()
        try { $n = $s.Read($buffer, 0, 16) } catch { $n = -1 }   # -1: reset (unread input) also means closed
        return ($n -eq 0 -or $n -eq -1) -and $w.ElapsedMilliseconds -lt 8000
    } finally { $c.Close() }
}function Send-CtrlC([int]$TargetPid) {
    # Separate helper process: it detaches from our console, attaches to the harness console
    # and raises Ctrl+C there (as the user pressing Ctrl+C in that window).
    $h = Start-Process -FilePath ([IO.Path]::Combine($PSHOME, 'powershell.exe')) -PassThru -Wait -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + [IO.Path]::Combine($here, 'Send-ConsoleCtrl.ps1') + '"'), '-TargetPid', [string]$TargetPid, '-Event', '0')
    return $h.ExitCode
}
function Get-NewReports($Run) {
    @(Get-ChildItem -LiteralPath $here -Filter 'rf-local-handshake-2*.json' | Where-Object { $Run.Before -notcontains $_.Name })
}
function Read-Report($File) { [IO.File]::ReadAllText($File.FullName) | ConvertFrom-Json }
function Wait-Until([scriptblock]$Condition, [int]$Seconds) {
    $w = [Diagnostics.Stopwatch]::StartNew()
    while ($w.Elapsed.TotalSeconds -lt $Seconds) { if (& $Condition) { return $true }; Start-Sleep -Milliseconds 250 }
    return [bool](& $Condition)
}
function Save-RunFiles($Run, [string]$Label) {
    foreach ($f in Get-NewReports $Run) { Move-Item -LiteralPath $f.FullName -Destination ([IO.Path]::Combine($outDir, $Label + '-' + $f.Name)) }
    if ($Run.TestId) {
        $log = [IO.Path]::Combine($private, 'run-logs', 'server-' + $Run.TestId + '.jsonl')
        if ([IO.File]::Exists($log)) { Move-Item -LiteralPath $log -Destination ([IO.Path]::Combine($outDir, $Label + '-server.jsonl')) }
    }
}

try {
    # A. reconnects + Ctrl+C
    $a = Start-Harness
    Check 'A: harness ready (address verified, listener up)' $a.Ready
    if ($a.Ready) {
        Check 'A: hidden watchdog running' (Wait-Until { @(Get-Watchdog $a.TestId).Count -eq 1 } 15)
        Check 'A: connection 1 accepted then refused at peer check' (Connect-Once)
        Check 'A: connection 2 (reconnect) accepted then refused at peer check' (Connect-Once)
        Check 'A: plaza listening on 5.188.32.116:33343' (@(Get-NetTCPConnection -State Listen -LocalPort 33343 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq '5.188.32.116' }).Count -eq 1)
        Check 'A: plaza refuses a non-game peer' (Connect-Plaza)
        $u = [Net.Sockets.UdpClient]::new(); try { $null = $u.Send([byte[]](1, 2, 3), 3, '5.188.32.116', 34162) } finally { $u.Close() }
        $t3416 = [Net.Sockets.TcpClient]::new(); try { $t3416.Connect('5.188.32.116', 3416); Start-Sleep -Milliseconds 300 } finally { $t3416.Close() }
        Check 'A: listener still up after two client sessions' (@(Get-NetTCPConnection -State Listen -LocalPort 7000 -ErrorAction SilentlyContinue | Where-Object { $_.LocalAddress -eq $vip }).Count -eq 1)
        $code = Send-CtrlC $a.Process.Id
        Check 'A: Ctrl+C delivered to harness console' ($code -eq 0) ('helper exit ' + $code)
        Check 'A: harness exited after Ctrl+C' (Wait-Until { $a.Process.HasExited } 60)
        Check 'A: address removed' (@(Get-Address).Count -eq 0)
        Check 'A: journal removed' (-not [IO.File]::Exists($journal))
        Check 'A: watchdog exited (nothing left to clean)' (Wait-Until { @(Get-Watchdog $a.TestId).Count -eq 0 } 30)
        $reports = Get-NewReports $a
        Check 'A: exactly one report (no watchdog report)' ($reports.Count -eq 1) ([string]$reports.Count)
        if ($reports.Count -ge 1) {
            $r = Read-Report $reports[0]
            Check 'A: server_end_reason ctrl_c' ($r.server_end_reason -eq 'ctrl_c') ([string]$r.server_end_reason)
            Check 'A: cleanup verified_removed' ($r.cleanup.status -eq 'verified_removed') ([string]$r.cleanup.status)
            Check 'A: two client sessions, both peer_not_authorized' ($r.client_sessions_ended -eq 2 -and @($r.client_sessions | Where-Object { $_.end_reason -eq 'peer_not_authorized' }).Count -eq 2)
            Check 'A: plaza connection logged as peer_refused (not_game_process)' (@($r.plaza.connections | Where-Object { $_.end_reason -eq 'peer_refused' -and $_.peer -eq 'not_game_process' }).Count -eq 1)
            Check 'A: 3416 and 34162 recorded only' ($r.plaza.tcp3416_connections -ge 1 -and $r.plaza.udp34162_datagrams -ge 1)
            Check 'A: cleanup covered both addresses' (@($r.cleanup.addresses).Count -eq 2 -and $r.cleanup.address_absent -and $r.cleanup.route_absent)
            Check 'A: no runtime/request limit text left' (-not (@($r.limits) -match 'at most 64 post-login|20000|15 minutes|20 minutes'))
        }
        $log = [IO.Path]::Combine($private, 'run-logs', 'server-' + $a.TestId + '.jsonl')
        $lines = @(if ([IO.File]::Exists($log)) { [IO.File]::ReadAllLines($log) })
        Check 'A: session log has 2 client_session_end + server_shutdown(ctrl_c) + plaza lines' (@($lines | Where-Object { $_ -like '*client_session_end*' }).Count -eq 2 -and @($lines | Where-Object { $_ -like '*"event":"server_shutdown"*"reason":"ctrl_c"*' }).Count -eq 1 -and @($lines | Where-Object { $_ -like '*plaza_shutdown*' }).Count -eq 1) ([string]$lines.Count)
    }
    Save-RunFiles $a 'A'

    # B. harness killed -> watchdog cleanup
    $b = Start-Harness
    Check 'B: harness ready' $b.Ready
    if ($b.Ready) {
        Check 'B: connection accepted then refused at peer check' (Connect-Once)
        Stop-Process -Id $b.Process.Id -Force
        Check 'B: watchdog removed the address' (Wait-Until { @(Get-Address).Count -eq 0 } 60)
        Check 'B: watchdog removed the journal' (Wait-Until { -not [IO.File]::Exists($journal) } 30)
        Check 'B: watchdog exited' (Wait-Until { @(Get-Watchdog $b.TestId).Count -eq 0 } 30)
        $reports = @(Get-NewReports $b)
        $wdReport = @($reports | Where-Object { $_.Name -like '*-watchdog.json' })
        Check 'B: watchdog report written' ($wdReport.Count -eq 1)
        if ($wdReport.Count -eq 1) {
            $r = Read-Report $wdReport[0]
            Check 'B: watchdog cleanup verified_removed' ($r.cleanup.status -eq 'verified_removed' -and $r.cleanup.address_absent -and $r.cleanup.route_absent -and $r.cleanup.journal_removed) ([string]$r.cleanup.status)
            Check 'B: watchdog report lists the client session' (@($r.client_sessions).Count -eq 1)
        }
        $log = [IO.Path]::Combine($private, 'run-logs', 'server-' + $b.TestId + '.jsonl')
        $lines = @(if ([IO.File]::Exists($log)) { [IO.File]::ReadAllLines($log) })
        Check 'B: session log ends with watchdog_cleanup verified_removed' ($lines.Count -ge 2 -and $lines[-1] -like '*"event":"watchdog_cleanup"*verified_removed*')
    }
    Save-RunFiles $b 'B'

    # C. harness and watchdog killed -> next run recovers the journal
    $c = Start-Harness
    Check 'C: harness ready' $c.Ready
    if ($c.Ready) {
        foreach ($w in Get-Watchdog $c.TestId) { Stop-Process -Id $w.ProcessId -Force }
        Stop-Process -Id $c.Process.Id -Force
        Start-Sleep -Seconds 1
        Check 'C: both addresses and journal left behind (simulated power-loss case)' (@(Get-Address).Count -eq 2 -and [IO.File]::Exists($journal))
        Save-RunFiles $c 'C'
        $d = Start-Harness
        Check 'C: next run recovered the journal and became ready' $d.Ready
        if ($d.Ready) {
            $code = Send-CtrlC $d.Process.Id
            Check 'C: next run stopped by Ctrl+C' ((Wait-Until { $d.Process.HasExited } 60) -and $code -eq 0)
            $reports = @(Get-NewReports $d | Where-Object { $_.Name -notlike '*-watchdog.json' })
            if ($reports.Count -ge 1) {
                $r = Read-Report $reports[0]
                Check 'C: previous_journal_recovery verified_removed' ($r.previous_journal_recovery.status -eq 'verified_removed') ([string]$r.previous_journal_recovery.status)
                Check 'C: own cleanup verified_removed' ($r.cleanup.status -eq 'verified_removed')
            } else { Check 'C: next-run report' $false 'missing' }
        }
        Save-RunFiles $d 'D'
    } else { Save-RunFiles $c 'C' }
} finally {
    # Never leave the address behind: verified cleanup through the harness itself.
    # First stop any harness still running (its watchdog then cleans up); only if that
    # does not finish, stop the watchdogs and use the harness's own CleanupOnly mode.
    foreach ($h in @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { [string]$_.CommandLine -like '*Test-RF-LocalHandshake.ps1"' -or [string]$_.CommandLine -like '*Test-RF-LocalHandshake.ps1" ' })) {
        Stop-Process -Id $h.ProcessId -Force
        Check 'final: a harness was still running and had to be stopped' $false
    }
    if (-not (Wait-Until { @(Get-Address).Count -eq 0 -and -not [IO.File]::Exists($journal) } 30)) {
        foreach ($w in @(Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { [string]$_.CommandLine -like '*-WatchdogTestId *' })) { Stop-Process -Id $w.ProcessId -Force }
        & ([IO.Path]::Combine($PSHOME, 'powershell.exe')) -NoProfile -ExecutionPolicy Bypass -File $harness -CleanupOnly | Out-Null
        Check 'final: leftover cleaned by CleanupOnly' (@(Get-Address).Count -eq 0 -and -not [IO.File]::Exists($journal))
    }
    foreach ($f in @(Get-ChildItem -LiteralPath $here -Filter 'rf-local-handshake-2*.json' | Where-Object { $_.LastWriteTimeUtc -ge $startedUtc })) {
        Move-Item -LiteralPath $f.FullName -Destination ([IO.Path]::Combine($outDir, 'late-' + $f.Name))
    }
    Check 'final: no test address, route or journal remains' (@(Get-Address).Count -eq 0 -and -not [IO.File]::Exists($journal) -and
        @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Where-Object { @('5.188.32.117/32', '5.188.32.116/32') -contains $_.DestinationPrefix }).Count -eq 0)
    foreach ($f in @([IO.Path]::Combine($private, 'accounts', $checkProfile + '.txt'))) { if ([IO.File]::Exists($f)) { [IO.File]::Delete($f) } }
    [IO.File]::WriteAllLines([IO.Path]::Combine($outDir, 'checks.txt'), $results)
    [Console]::WriteLine('Results saved: ' + $outDir)
}
if ($failures) { exit 1 } else { exit 0 }
