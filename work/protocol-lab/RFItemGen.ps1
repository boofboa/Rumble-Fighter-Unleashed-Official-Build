# Item generator for the LOCAL server's account profiles (private\accounts\<profile>.txt).
# It only edits local profile files; it has no network code and cannot affect official servers.
# Changes go through the same locked, validated, atomic store the server uses and appear in the
# game at the next login (reconnect), even while the local server runs.
#
# Catalog sources, most trustworthy first:
#   observed  exact 49-byte records from the official captures (private\fixtures\item-records.v1.tsv)
#   store     catalog IDs (+ item_end) the game client itself sent in local Store purchases
#             (<profile>.purchases.log of every profile); record = the reference shape
#   reference public Gemnet data (class items, default Exos, rod; with names; ItemEnd 1000)
#   worn      IDs other players wore in captured rooms (ItemEnd unknown -> 1000)
#   manual    any other ID: only with -ItemEnd and -Force (unverified; the client may ignore it)
#
#   RFItemGen.cmd list   [-Family 203] [-Source observed|store|all]
#   RFItemGen.cmd grant  2030834 1051700 [-Count 3] [-ItemEnd 500] [-Force]   -Profile admin
#   RFItemGen.cmd grant-family 203                                         -Profile admin
#   RFItemGen.cmd grant-store                                              -Profile admin
#   RFItemGen.cmd remove 1015 1016                                         -Profile admin
[CmdletBinding()]
param(
    # Empty = interactive menu (double-clicking RFItemGen.cmd).
    [Parameter(Position = 0)] [ValidateSet('', 'list', 'grant', 'grant-family', 'grant-store', 'grant-all', 'remove', 'menu')] [string]$Command = '',
    [Parameter(Position = 1, ValueFromRemainingArguments = $true)] [string[]]$Values,
    [ValidatePattern('^[a-z0-9-]{1,32}$')] [string]$Profile = 'admin',
    [ValidateSet('observed', 'reference', 'worn', 'store', 'all')] [string]$Source = 'all',
    [int]$Family = -1,
    [ValidateRange(1, 100)] [int]$Count = 1,
    [int]$ItemEnd = -1,
    [switch]$Force
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$private = [IO.Path]::GetFullPath([IO.Path]::Combine($here, '..\..\private'))
$accounts = [IO.Path]::Combine($private, 'accounts')
if (-not ('RFLocalHandshake.AccountStore' -as [type])) {
    Add-Type -Path @([IO.Path]::Combine($here, 'RFHandshakeProbe.cs'), [IO.Path]::Combine($here, 'RFAccount.cs'), [IO.Path]::Combine($here, 'RFPlaza.cs'))
}
$path = [IO.Path]::Combine($accounts, $Profile + '.txt')
$store = [RFLocalHandshake.AccountStore]::new($path)

# Family (catalog / 10000) -> slot name: capture-derived slot pairs, named with Gemnet's
# AvatarDef.SlotName enum (both sources agree). Families never seen in a slot stay "other".
$familyNames = @{ 100 = 'class'; 105 = 'hair'; 106 = 'top'; 107 = 'bottom'; 108 = 'gloves'; 109 = 'shoes'; 102 = 'eyes'; 103 = 'nose'; 104 = 'mouth'
    203 = 'scroll'; 204 = 'exo'; 301 = 'back'; 303 = 'neck'; 302 = 'ears'; 305 = 'glasses'; 306 = 'mask'; 304 = 'waist'
    503 = 'slot22'; 508 = 'inventory'; 206 = 'slot27'; 308 = 'title'; 309 = 'merit' }
function Get-FamilyName([int]$Family) { if ($familyNames.ContainsKey($Family)) { "$Family/" + $familyNames[$Family] } else { "$Family/other" } }

# catalog -> entry { catalog, source, item_end, slots, record (49 bytes, instance 0) }
function Get-Catalog {
    $entries = @{}
    $observed = [RFLocalHandshake.ItemCatalog]::Load([IO.Path]::Combine($private, 'fixtures', 'item-records.v1.tsv'))
    foreach ($id in $observed.Records.Keys) {
        $raw = $observed.Records[$id]
        $entries[[int]$id] = [pscustomobject]@{ catalog = [int]$id; source = 'observed'; item_end = [BitConverter]::ToInt32($raw, 29); slots = $observed.Slots[$id]; record = $raw }
    }
    # Public reference (Gemnet CreateAccount): class items, default Exos, rod, with names.
    # Names are attached to any known catalog; unknown IDs become source 'reference'.
    $reference = [IO.Path]::Combine($private, 'fixtures', 'reference-gemnet.v1.tsv')
    $script:Names = @{}
    if ([IO.File]::Exists($reference)) {
        foreach ($line in [IO.File]::ReadAllLines($reference)) {
            if ($line.StartsWith('#')) { continue }
            $f = $line.Split("`t"); $id = [int]$f[0]; $script:Names[$id] = $f[2]
            if (-not $entries.ContainsKey($id)) {
                $entries[$id] = [pscustomobject]@{ catalog = $id; source = 'reference'; item_end = [int]$f[1]; slots = '-'; record = (New-Record $id ([int]$f[1])) }
            }
        }
    }
    # Catalogs other players wore in captured rooms (IDs only; rf_equipped_catalogs.py). Their
    # item_end is not visible there, so 1000 is used (the reference default; unverified).
    $worn = [IO.Path]::Combine($private, 'fixtures', 'equipped-catalogs.v1.tsv')
    if ([IO.File]::Exists($worn)) {
        foreach ($line in [IO.File]::ReadAllLines($worn)) {
            if ($line.StartsWith('#')) { continue }
            $f = $line.Split("`t"); $id = [int]$f[0]
            if ($entries.ContainsKey($id)) { continue }
            $entries[$id] = [pscustomobject]@{ catalog = $id; source = 'worn'; item_end = 1000; slots = $f[1]; record = (New-Record $id 1000) }
        }
    }
    foreach ($log in @(Get-ChildItem -LiteralPath $accounts -Filter '*.purchases.log' -File -ErrorAction SilentlyContinue)) {
        foreach ($line in [IO.File]::ReadAllLines($log.FullName)) {
            if ($line -notmatch 'catalog=(\d+) item_end=(\d+)') { continue }
            $id = [int]$Matches[1]; $end = [int]$Matches[2]
            if ($entries.ContainsKey($id)) { continue }
            $entries[$id] = [pscustomobject]@{ catalog = $id; source = 'store'; item_end = $end; slots = '-'; record = (New-Record $id $end) }
        }
    }
    return $entries
}

# The Gemnet reference record shape the server already uses for Store purchases.
function New-Record([int]$Catalog, [int]$End) {
    $raw = [byte[]]::new(49)
    [Array]::Copy([BitConverter]::GetBytes($Catalog), 0, $raw, 4, 4)
    [Array]::Copy([BitConverter]::GetBytes([RFLocalHandshake.AccountState]::ReferenceWord8), 0, $raw, 8, 4)
    [Array]::Copy([BitConverter]::GetBytes($End), 0, $raw, 29, 4)
    return $raw
}

function Resolve-Grant([int]$Id, $Catalog) {
    if ($Catalog.ContainsKey($Id)) {
        $e = $Catalog[$Id]
        if ($ItemEnd -ge 0 -and $ItemEnd -ne $e.item_end) { return [pscustomobject]@{ catalog = $Id; source = $e.source + '+item_end'; record = (New-Record $Id $ItemEnd) } }
        return $e
    }
    if (-not $Force -or $ItemEnd -lt 0) { throw "catalog $Id is neither observed nor bought in the local Store: add -ItemEnd N -Force to grant it unverified (nothing changed)" }
    return [pscustomobject]@{ catalog = $Id; source = 'manual_unverified'; record = (New-Record $Id $ItemEnd) }
}

function Invoke-Grants($Grants) {
    if (-not $store.Exists) { throw "profile '$Profile' does not exist (RFAdmin.cmd create -From baseline -Profile $Profile)" }
    $before = $store.Load()
    if ($before.Items.Count + $Grants.Count * $Count -gt 20000) { throw 'refused: the profile would exceed 20000 items' }
    if ($Grants.Count * $Count -gt 20) { "safety backup: " + $store.Backup([IO.Path]::Combine($accounts, 'backups'), $Profile + '-before-itemgen') }
    $granted = [Collections.Generic.List[string]]::new()
    $reason = $store.Update([Func[RFLocalHandshake.AccountState, string]] {
        param($s)
        foreach ($g in $Grants) { for ($n = 0; $n -lt $Count; $n++) { $r = $s.Grant($g.record); $granted.Add("$($r.Instance)=$($g.catalog) ($($g.source))") } }
        $null })
    if (-not [string]::IsNullOrEmpty($reason)) { throw "refused: $reason" }
    "granted $($granted.Count) item(s) to ${Profile}: " + (($granted | Select-Object -First 12) -join ', ') + $(if ($granted.Count -gt 12) { ', ...' } else { '' })
    'They appear in the game at your next login: close the game and sign in again (the local server can keep running).'
}

function Show-Owned {
    if (-not $store.Exists) { "profile '$Profile' does not exist yet"; return }
    $s = $store.Load()
    "profile $Profile : $($s.Items.Count) item(s)"
    $s.Items | Sort-Object Instance | ForEach-Object { '  item {0}  catalog {1}  family {2}' -f $_.Instance, $_.Catalog, [Math]::Floor($_.Catalog / 10000) }
}

# Interactive menu: every action calls the same commands as the command line.
function Start-Menu {
    $profiles = @(Get-ChildItem -LiteralPath $accounts -Filter '*.txt' -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -notlike '*.purchases.log' } | ForEach-Object { $_.BaseName })
    while ($true) {
        ''
        "=== Local item generator (account: $Profile) ==="
        '  1  list known items (optionally one family)'
        '  2  grant items by catalog ID'
        '  3  grant every known item of a family (203 scroll, 204 Exo, 105 tops, ...)'
        '  4  grant every item ever bought in the local Store'
    '  8  grant EVERYTHING known (observed + worn + Store)'
        '  5  show items this account owns'
        '  6  remove items (by item number)'
        "  7  switch account (available: $($profiles -join ', '))"
        '  0  exit'
        $choice = Read-Host 'choice'
        try {
            switch ($choice) {
                '1' { $f = Read-Host 'family (empty = all)'; $script:Family = $(if ($f -match '^\d+$') { [int]$f } else { -1 }); & $listBlock; $script:Family = -1 }
                '2' {
                    $ids = @((Read-Host 'catalog IDs separated by spaces') -split '\s+' | Where-Object { $_ -match '^\d+$' })
                    if ($ids.Count -eq 0) { 'no IDs entered'; break }
                    $c = Read-Host 'copies of each (empty = 1)'
                    $script:Count = $(if ($c -match '^\d+$' -and [int]$c -ge 1 -and [int]$c -le 100) { [int]$c } else { 1 })
                    $catalog = Get-Catalog
                    Invoke-Grants @($ids | ForEach-Object { Resolve-Grant ([int]$_) $catalog })
                    $script:Count = 1
                }
                '3' { $f = Read-Host 'family number'; if ($f -match '^\d+$') { $script:Values = @($f); & $familyBlock } else { 'not a number' } }
                '4' { & $storeBlock }
                '8' { & $allBlock }
                '5' { Show-Owned }
                '6' { $script:Values = @((Read-Host 'item numbers separated by spaces') -split '\s+' | Where-Object { $_ -match '^\d+$' }); if ($Values.Count) { & $removeBlock } }
                '7' { $p = Read-Host 'account name'; if ($p -match '^[a-z0-9-]{1,32}$') { $script:Profile = $p; $script:path = [IO.Path]::Combine($accounts, $p + '.txt'); $script:store = [RFLocalHandshake.AccountStore]::new($script:path) } else { 'invalid name' } }
                '0' { return }
                default { 'unknown choice' }
            }
        } catch { 'ERROR: ' + $_.Exception.Message }
    }
}

$listBlock = {
    $catalog = Get-Catalog
    $rows = @($catalog.Values | Where-Object { ($Source -eq 'all' -or $_.source -eq $Source) -and ($Family -lt 0 -or [Math]::Floor($_.catalog / 10000) -eq $Family) } | Sort-Object catalog)
    $rows | ForEach-Object { $fam = [int][Math]::Floor($_.catalog / 10000); '{0}  {1,-14} {2,-9} item_end {3,-5} slots {4,-8} {5}' -f $_.catalog, (Get-FamilyName $fam), $_.source, $_.item_end, $_.slots, $(if ($script:Names.ContainsKey($_.catalog)) { $script:Names[$_.catalog] } else { '' }) }
    "$($rows.Count) catalog(s). Families: 100 class, 102-109 clothing, 203 scroll, 204 Exo, 206/30x accessories, 50x/51x items and packages."
}
$familyBlock = {
    if ($Values.Count -ne 1) { throw 'grant-family needs one family number, e.g. 203' }
    $fam = [int]$Values[0]
    $catalog = Get-Catalog
    $owned = @{}; if ($store.Exists) { foreach ($i in $store.Load().Items) { $owned[$i.Catalog] = $true } }
    $picks = @($catalog.Values | Where-Object { [Math]::Floor($_.catalog / 10000) -eq $fam -and -not $owned.ContainsKey($_.catalog) } | Sort-Object catalog)
    if ($picks.Count -eq 0) { "nothing to grant: no known, not-yet-owned catalog in family $fam" } else { Invoke-Grants $picks }
}
$storeBlock = {
    $catalog = Get-Catalog
    $owned = @{}; if ($store.Exists) { foreach ($i in $store.Load().Items) { $owned[$i.Catalog] = $true } }
    $picks = @($catalog.Values | Where-Object { $_.source -eq 'store' -and -not $owned.ContainsKey($_.catalog) } | Sort-Object catalog)
    if ($picks.Count -eq 0) { 'nothing to grant: every Store-seen catalog is already owned' } else { Invoke-Grants $picks }
}
$allBlock = {
    $catalog = Get-Catalog
    $owned = @{}; if ($store.Exists) { foreach ($i in $store.Load().Items) { $owned[$i.Catalog] = $true } }
    $picks = @($catalog.Values | Where-Object { -not $owned.ContainsKey($_.catalog) } | Sort-Object catalog)
    if ($picks.Count -eq 0) { 'nothing to grant: every known catalog is already owned' } else { Invoke-Grants $picks }
}
$removeBlock = {
    if (-not $store.Exists) { throw "profile '$Profile' does not exist" }
    $ids = @($Values | ForEach-Object { [int]$_ })
    if ($ids.Count -eq 0) { throw 'remove needs item numbers (menu option 5 lists them)' }
    "safety backup: " + $store.Backup([IO.Path]::Combine($accounts, 'backups'), $Profile + '-before-remove')
    $reason = $store.Update([Func[RFLocalHandshake.AccountState, string]] {
        param($s)
        foreach ($id in $ids) {
            $item = $s.FindItem($id)
            if ($null -eq $item) { return "item $id not owned" }
            foreach ($a in $s.Avatars) { if ($a.Slots[0] -eq $id) { return "item $id is the class item (slot 0)" } }
            $null = $s.Items.Remove($item)
        }
        $null = $s.RepairDangling()   # unequips removed items
        $null })
    if (-not [string]::IsNullOrEmpty($reason)) { throw "refused: $reason (nothing changed)" }
    "removed $($ids.Count) item(s) from $Profile (unequipped where needed). Sign in again to see it in the game."
}

switch ($Command) {
    { $_ -in @('', 'menu') } { Start-Menu }
    'list' { & $listBlock }
    'grant' {
        $catalog = Get-Catalog
        $ids = @($Values | ForEach-Object { [int]$_ })
        if ($ids.Count -eq 0) { throw 'grant needs catalog IDs' }
        Invoke-Grants @($ids | ForEach-Object { Resolve-Grant $_ $catalog })
    }
    'grant-family' { & $familyBlock }
    'grant-store' { & $storeBlock }
    'grant-all' { & $allBlock }
    'remove' { & $removeBlock }
}