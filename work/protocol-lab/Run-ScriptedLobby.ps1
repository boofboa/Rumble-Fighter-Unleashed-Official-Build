# Offline startup-to-lobby check (no admin, no network, no game).
# Compiles RFHandshakeProbe.cs, runs its self-test, then replays the known post-login
# request sequence plus 160 lobby polls (~5.3 min of real client polling) through the
# real server code for both account states. Needs the private capture and fixture.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$private = [IO.Path]::GetFullPath([IO.Path]::Combine($here, '..\..\private'))
Add-Type -Path @([IO.Path]::Combine($here, 'RFHandshakeProbe.cs'), [IO.Path]::Combine($here, 'RFAccount.cs'), [IO.Path]::Combine($here, 'RFPlaza.cs'))
[RFLocalHandshake.Probe]::SelfTest()
'SelfTest: PASS'
$capture = [IO.Path]::Combine($private, 'captures\rf-startup.pcapng')
$fixture = [IO.Path]::Combine($private, 'fixtures\lobby-boss-v2.bin')
'claimed95:   ' + [RFLocalHandshake.Probe]::RunScriptedSession($capture, $fixture, 160, $true)
'unclaimed95: ' + [RFLocalHandshake.Probe]::RunScriptedSession($capture, $fixture, 20, $false)
# 1.23: two client sessions on one persistent server (reconnect), 3000 polls, repeated Get_Cash.
$log = [IO.Path]::Combine([IO.Path]::GetTempPath(), 'rf-reconnect-' + [Guid]::NewGuid().ToString('N') + '.jsonl')
try { 'reconnect:   ' + [RFLocalHandshake.Probe]::RunScriptedReconnect($capture, $fixture, $log, 3000) }
finally { if ([IO.File]::Exists($log)) { [IO.File]::Delete($log) } }
