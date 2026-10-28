# 1.24 local account administration (no admin rights or network needed).
# Profiles are files private\accounts\<profile>.txt (rf-account-v1). The server reads the
# selected profile at every login and writes My Info equipment changes back to it, so changes
# made here apply at the next login (reconnect) even while the server runs.
#
#   RFAdmin.ps1 show                       [-Profile baseline]
#   RFAdmin.ps1 create  -From baseline     -Profile admin      (copy a profile; refuses to overwrite)
#   RFAdmin.ps1 grant   2030247 2040298    -Profile admin      (observed records only)
#   RFAdmin.ps1 grant-all-observed         -Profile admin      (every catalog in item-records.v1.tsv)
#   RFAdmin.ps1 set-level 90 -Experience N -Profile admin      (EXPERIMENTAL: exp table unknown)
#   RFAdmin.ps1 set-balance -Carats N -Cash N -Medals N -Profile admin   (Cash = Astros)
#   RFAdmin.ps1 unlimited on [-Balance 99999999] -Profile admin   |   unlimited off -Profile admin
#   RFAdmin.ps1 backup [-Label x] | restore -File path | reset | repair   [-Profile p]
#
# Every change is validated and written atomically; reset/restore/grant-all back up first.
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateSet('show', 'create', 'grant', 'grant-all-observed', 'set-level', 'set-balance', 'unlimited', 'backup', 'restore', 'reset', 'repair')]
    [string]$Command,
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)] [string[]]$Values,
    [ValidatePattern('^[a-z0-9-]{1,32}$')] [string]$Profile = 'baseline',
    [ValidatePattern('^[a-z0-9-]{1,32}$')] [string]$From = 'baseline',
    [long]$Experience = -1, [int]$Cash = -1, [int]$Medals = -1, [int]$Carats = -1, [int]$Balance = -1,
    [string]$Label = '', [string]$File = ''
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$private = [IO.Path]::GetFullPath([IO.Path]::Combine($here, '..\..\private'))
$accounts = [IO.Path]::Combine($private, 'accounts')
$backups = [IO.Path]::Combine($accounts, 'backups')
$recordsPath = [IO.Path]::Combine($private, 'fixtures', 'item-records.v1.tsv')
$lobbyFixturePath = [IO.Path]::Combine($private, 'fixtures', 'lobby-boss-v2.bin')
if (-not ('RFLocalHandshake.AccountStore' -as [type])) {
    Add-Type -Path @([IO.Path]::Combine($here, 'RFHandshakeProbe.cs'), [IO.Path]::Combine($here, 'RFAccount.cs'), [IO.Path]::Combine($here, 'RFPlaza.cs'))
}
$path = [IO.Path]::Combine($accounts, $Profile + '.txt')
$store = [RFLocalHandshake.AccountStore]::new($path)

function Get-Baseline {
    # Same baseline the server creates on first login (claimed-95 reward record included).
    $reward = $null
    try { $reward = [RFLocalHandshake.Probe]::LoadLobbyFixture($lobbyFixturePath).RewardRecord } catch { }
    return [RFLocalHandshake.AccountState]::CreateBaseline($reward)
}
function Get-Catalog { return [RFLocalHandshake.ItemCatalog]::Load($recordsPath) }
function Assert-Profile { if (-not $store.Exists) { throw "profile '$Profile' does not exist (it is created at first login, or with: create -From baseline)" } }
function Invoke-Change([scriptblock]$Change) {
    $reason = $store.Update([Func[RFLocalHandshake.AccountState, string]]$Change)
    if ($null -ne $reason) { throw "refused: $reason" }
}

switch ($Command) {
    'show' {
        Assert-Profile
        $s = $store.Load()
        $catalog = $null; try { $catalog = Get-Catalog } catch { }
        "profile $Profile ($path)"
        "account $($s.AccountId) '$($s.Name)' level $($s.Level) experience $($s.Experience) carats $($s.Carats) astros $($s.Cash) medals $($s.Medals) current avatar $($s.CurrentAvatar)"
        "unlimited currency: $(if ($s.UnlimitedCurrency) { 'ON, shown balance ' + $s.UnlimitedBalance + ', purchases free' } else { 'off' })"
        $ledger = $path + '.purchases.log'; "purchases logged: $(if ([IO.File]::Exists($ledger)) { @(Get-Content $ledger).Count } else { 0 })"
        "items $($s.Items.Count) (next instance $($s.NextInstance))"
        foreach ($a in $s.Avatars) {
            $slots = @()
            for ($n = 0; $n -lt 45; $n++) {
                if ($a.Slots[$n] -ne 0) {
                    $item = $s.FindItem($a.Slots[$n])
                    $slots += "$n=$($a.Slots[$n])" + $(if ($null -ne $item) { "(cat $($item.Catalog))" } else { '(DANGLING)' })
                }
            }
            "avatar $($a.Id): " + ($slots -join ' ')
        }
        $byFamily = $s.Items | Group-Object { [int][Math]::Floor($_.Catalog / 10000) } | Sort-Object Name | ForEach-Object { "$($_.Name)x$($_.Count)" }
        "catalog families (catalog/10000 x count): " + ($byFamily -join ' ')
        $dangling = $s.DanglingReferences()
        "dangling equipment references: $($dangling.Count)"
    }
    'create' {
        if ($store.Exists) { throw "profile '$Profile' already exists" }
        $source = [RFLocalHandshake.AccountStore]::new([IO.Path]::Combine($accounts, $From + '.txt'))
        $state = $(if ($source.Exists) { $source.Load() } elseif ($From -eq 'baseline') { Get-Baseline } else { throw "source profile '$From' does not exist" })
        $store.Replace($state)
        "created profile $Profile from $From"
    }
    'grant' {
        Assert-Profile
        $catalog = Get-Catalog
        $ids = @($Values | ForEach-Object { [int]$_ })
        if ($ids.Count -eq 0) { throw 'grant needs one or more catalog IDs' }
        foreach ($id in $ids) { if (-not $catalog.Records.ContainsKey($id)) { throw "catalog $id has no observed record (not granted; nothing changed)" } }
        Invoke-Change { param($s) foreach ($id in $ids) { $null = $s.Grant($catalog.Records[$id]) }; $null }
        "granted $($ids.Count) item(s) to $Profile"
    }
    'grant-all-observed' {
        Assert-Profile
        $catalog = Get-Catalog
        $backup = $store.Backup($backups, $Profile + '-before-grant-all')
        $owned = @{}; foreach ($i in $store.Load().Items) { $owned[$i.Catalog] = $true }
        $ids = @($catalog.Records.Keys | Where-Object { -not $owned.ContainsKey($_) } | Sort-Object)
        Invoke-Change { param($s) foreach ($id in $ids) { $null = $s.Grant($catalog.Records[$id]) }; $null }
        "granted $($ids.Count) observed catalog item(s) not yet owned; backup: $backup"
    }
    'set-level' {
        Assert-Profile
        $level = [int]$Values[0]
        if ($level -lt 0 -or $level -gt 255) { throw 'level must be 0..255' }
        Invoke-Change { param($s) $s.Level = $level; if ($Experience -ge 0) { $s.Experience = $Experience }; $null }
        "level set to $level" + $(if ($Experience -ge 0) { ", experience $Experience" } else { '' }) + ' (EXPERIMENTAL: the client experience table is not recovered yet)'
    }
    'set-balance' {
        Assert-Profile
        Invoke-Change { param($s) if ($Cash -ge 0) { $s.Cash = $Cash }; if ($Medals -ge 0) { $s.Medals = $Medals }; if ($Carats -ge 0) { $s.Carats = $Carats }; $null }
        "balances updated"
    }
    'unlimited' {
        Assert-Profile
        $mode = [string]$Values[0]
        if ($mode -notin @('on', 'off')) { throw 'use: unlimited on|off [-Balance N]' }
        if ($Balance -ne -1 -and ($Balance -lt 1 -or $Balance -gt [RFLocalHandshake.AccountState]::MaxUnlimitedBalance)) { throw ('-Balance must be 1..' + [RFLocalHandshake.AccountState]::MaxUnlimitedBalance) }
        Invoke-Change { param($s) $s.UnlimitedCurrency = ($mode -eq 'on'); if ($Balance -ge 1) { $s.UnlimitedBalance = $Balance }; $null }
        $s = $store.Load()
        "unlimited currency $mode for $Profile; shown Carats $($s.EffectiveCarats), shown Astros $($s.EffectiveAstros) (stored Carats $($s.Carats), Astros $($s.Cash) unchanged); Store purchases are " + $(if ($s.UnlimitedCurrency) { 'free' } else { 'refused (no price table)' })
    }
    'backup' { Assert-Profile; "backup: " + $store.Backup($backups, $(if ($Label) { $Profile + '-' + $Label } else { $Profile })) }
    'restore' {
        if (-not [IO.File]::Exists($File)) { throw 'restore needs -File <backup path>' }
        if ($store.Exists) { "safety backup: " + $store.Backup($backups, $Profile + '-before-restore') }
        $store.Restore($File)
        "restored $Profile from $File"
    }
    'reset' {
        if ($store.Exists) { "safety backup: " + $store.Backup($backups, $Profile + '-before-reset') }
        $store.Replace((Get-Baseline))
        "reset $Profile to the baseline account"
    }
    'repair' {
        Assert-Profile
        $before = @($store.Load().DanglingReferences())
        if ($before.Count -eq 0) { 'no dangling equipment references'; break }
        "safety backup: " + $store.Backup($backups, $Profile + '-before-repair')
        Invoke-Change { param($s) $null = $s.RepairDangling(); $null }
        "cleared $($before.Count) dangling reference(s): $($before -join ', ')"
    }
}
