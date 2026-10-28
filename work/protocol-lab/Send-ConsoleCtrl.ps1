# Test helper for Run-PersistenceChecks.ps1: raises Ctrl+C (Event 0) or Ctrl+Break (1) in the
# console of process TargetPid, as if the user pressed it in that window. Run it as its own
# process: it detaches from its console and ignores the event itself.
param([int]$TargetPid, [int]$Event = 0)
Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public static class RFConsoleCtrl { [DllImport("kernel32.dll", SetLastError=true)] public static extern bool FreeConsole(); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool AttachConsole(uint p); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool SetConsoleCtrlHandler(IntPtr h, bool a); [DllImport("kernel32.dll", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint e, uint g); }'
$null = [RFConsoleCtrl]::FreeConsole()
if (-not [RFConsoleCtrl]::AttachConsole($TargetPid)) { exit 2 }
$null = [RFConsoleCtrl]::SetConsoleCtrlHandler([IntPtr]::Zero, $true)
if (-not [RFConsoleCtrl]::GenerateConsoleCtrlEvent($Event, 0)) { exit 3 }
Start-Sleep -Milliseconds 500
exit 0
