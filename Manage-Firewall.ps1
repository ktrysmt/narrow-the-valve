#Requires -Version 5.1
<#
.SYNOPSIS
    Data-driven Windows Firewall rule manager.

.DESCRIPTION
    Applies a JSON "ruleset" to Windows Firewall as a named group of rules, and lets
    you inspect, disable, re-enable, export or remove that group as a unit.

    Address and port values can be literal, or produced at apply time by a resolver
    (see lib\Resolvers.ps1), so a rule can follow a moving upstream list instead of
    going stale.

    Safety model
      * Every dynamic value is resolved and validated BEFORE any rule is touched. A
        failed lookup aborts the run and leaves existing rules exactly as they were.
      * A resolver returning fewer entries than its declared minCount aborts the run,
        so a truncated response can never widen a rule to "everything".
      * Rules are upserted in place under a stable identifier, never dropped and
        recreated, so there is no window in which the group is half-applied.
      * Only rules named "fwmgr:<group>:*" are ever modified or deleted. Rules made
        by hand or by other software are out of reach.
      * A Block rule with no address, port or program constraint is refused unless
        -Force is given.
      * The current state of the group is exported to backups\ before Apply/Remove.

.PARAMETER Action
    Status  (default) Show managed groups, or one group in detail.
    Apply   Create or update the group described by -RuleSet.
    Enable  Re-enable every rule in the group.
    Disable Turn the group off without deleting it. The first thing to try when
            something stops connecting.
    Remove  Delete every rule in the group.
    Export  Write the group's live rules out as a ruleset JSON file.

.PARAMETER RuleSet
    Ruleset to act on: either a bare name resolved against .\rulesets\<name>.json,
    or a path to a .json file.

.PARAMETER Group
    Operate on a firewall group directly, without a ruleset file. Accepted by
    Status, Enable, Disable, Remove and Export.

.PARAMETER Program
    Restrict every rule in the ruleset to this executable. Strongly recommended for
    rules that would otherwise apply machine-wide.

.PARAMETER KeepState
    On Apply, leave each rule's enabled/disabled state as it is instead of resetting
    it to what the ruleset declares. Use this to refresh a group you have disabled.

.PARAMETER NoBackup
    Skip the pre-change export to backups\.

.PARAMETER Force
    Allow rules this script would otherwise refuse as too broad.

.EXAMPLE
    .\Manage-Firewall.ps1

    List every group this tool manages and every ruleset available.

.EXAMPLE
    .\Manage-Firewall.ps1 Apply steam-relay-tokyo -Program "D:\Steam\...\nightreign.exe" -WhatIf

    Resolve the relay list and show exactly what would change, without touching the
    firewall.

.EXAMPLE
    .\Manage-Firewall.ps1 Disable -Group SDR-Pin-TYO
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Status', 'Apply', 'Enable', 'Disable', 'Remove', 'Export')]
    [string] $Action = 'Status',

    [Parameter(Position = 1)]
    [string] $RuleSet,

    [string] $Group,
    [string] $Program,
    [string] $OutFile,

    [switch] $KeepState,
    [switch] $NoBackup,
    [switch] $Force
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'lib\Resolvers.ps1')

# Every rule this script owns is named "<prefix>:<group>:<key>". The prefix is what
# makes ownership decidable: anything without it is somebody else's rule.
$script:RulePrefix   = 'fwmgr'
$script:RuleSetDir   = Join-Path $PSScriptRoot 'rulesets'
$script:BackupDir    = Join-Path $PSScriptRoot 'backups'
$script:ExportDir    = Join-Path $PSScriptRoot 'exports'

# ruleset JSON key -> New-NetFirewallRule parameter
$script:FieldMap = [ordered]@{
    displayName   = 'DisplayName'
    description   = 'Description'
    direction     = 'Direction'
    action        = 'Action'
    enabled       = 'Enabled'
    profile       = 'Profile'
    protocol      = 'Protocol'
    localPort     = 'LocalPort'
    remotePort    = 'RemotePort'
    localAddress  = 'LocalAddress'
    remoteAddress = 'RemoteAddress'
    program       = 'Program'
    service       = 'Service'
    interfaceType = 'InterfaceType'
}

# Filters left unset are pinned to 'Any' rather than omitted, so that re-applying a
# ruleset converges: a filter dropped from the JSON is actively cleared on the rule.
$script:FieldDefaults = @{
    Enabled       = 'True'
    Profile       = 'Any'
    Protocol      = 'Any'
    LocalPort     = 'Any'
    RemotePort    = 'Any'
    LocalAddress  = 'Any'
    RemoteAddress = 'Any'
    Program       = 'Any'
    Service       = 'Any'
    InterfaceType = 'Any'
}


#region helpers ---------------------------------------------------------------

function Write-Section {
    param([string]$Text)
    Write-Host ''
    Write-Host $Text -ForegroundColor Cyan
    Write-Host ('-' * $Text.Length) -ForegroundColor DarkGray
}

function ConvertTo-HashtableDeep {
    <#  ConvertFrom-Json hands back PSCustomObjects on 5.1; hashtables are easier
        to probe with ContainsKey than properties are under Set-StrictMode. #>
    param($InputObject)

    if ($null -eq $InputObject) { return $null }

    if ($InputObject -is [string] -or $InputObject.GetType().IsPrimitive) { return $InputObject }

    if ($InputObject -is [System.Collections.IDictionary]) {
        $table = @{}
        foreach ($key in @($InputObject.Keys)) {
            $table[[string]$key] = ConvertTo-HashtableDeep $InputObject[$key]
        }
        return $table
    }

    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        $table = @{}
        foreach ($prop in $InputObject.PSObject.Properties) {
            $table[$prop.Name] = ConvertTo-HashtableDeep $prop.Value
        }
        return $table
    }

    if ($InputObject -is [System.Collections.IEnumerable]) {
        $list = @()
        foreach ($item in $InputObject) { $list += , (ConvertTo-HashtableDeep $item) }
        return , $list
    }

    return $InputObject
}

function Assert-Administrator {
    param([string]$ForAction)

    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "'$ForAction' changes firewall rules and needs an elevated PowerShell session."
    }
}

function Get-RuleName {
    param([string]$GroupName, [string]$Key)
    return ('{0}:{1}:{2}' -f $script:RulePrefix, $GroupName, $Key)
}

function Get-GroupRuleFilter {
    param([string]$GroupName)
    if ($GroupName) { return ('{0}:{1}:*' -f $script:RulePrefix, $GroupName) }
    return ('{0}:*' -f $script:RulePrefix)
}

function Get-ManagedRule {
    param([string]$GroupName)
    # The unary comma keeps an empty result an empty array instead of letting the
    # pipeline collapse it to $null, so callers can always ask for .Count.
    return , @(Get-NetFirewallRule -Name (Get-GroupRuleFilter $GroupName) -ErrorAction SilentlyContinue)
}

function Format-FilterValue {
    param($Value, [int]$Preview = 3)

    $items = @($Value)
    if ($items.Count -eq 0) { return 'Any' }
    if ($items.Count -le $Preview) { return ($items -join ', ') }
    return ('{0} entries ({1}, ...)' -f $items.Count, (($items | Select-Object -First $Preview) -join ', '))
}

#endregion

#region ruleset loading -------------------------------------------------------

function Resolve-RuleSetPath {
    param([string]$Name)

    if (-not $Name) { throw "this action needs -RuleSet (a name under rulesets\, or a path to a .json file)." }

    $candidates = @()
    if ($Name -match '\.json$' -or $Name -match '[\\/]') { $candidates += $Name }
    $candidates += (Join-Path $script:RuleSetDir ("{0}.json" -f $Name))
    $candidates += (Join-Path $script:RuleSetDir $Name)

    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).ProviderPath
        }
    }
    throw "ruleset '$Name' not found. Looked for: $($candidates -join '; ')"
}

function Import-RuleSet {
    param([string]$Path)

    $raw = Get-Content -LiteralPath $Path -Raw
    try {
        $parsed = $raw | ConvertFrom-Json
    } catch {
        throw "ruleset '$Path' is not valid JSON: $($_.Exception.Message)"
    }

    $ruleSet = ConvertTo-HashtableDeep $parsed
    if ($ruleSet -isnot [hashtable]) { throw "ruleset '$Path' must contain a JSON object at the top level." }

    $groupName = [string](Get-SpecValue -Spec $ruleSet -Name 'group')
    if (-not $groupName) { throw "ruleset '$Path' is missing the required 'group' key." }

    # The group name is interpolated into a wildcard query, so exclude the wildcard
    # metacharacters along with the ':' that delimits the rule name.
    if ($groupName -notmatch '^[A-Za-z0-9._\- ]+$') {
        throw "ruleset '$Path': group '$groupName' may only contain letters, digits, space, dot, underscore and hyphen."
    }

    $rules = @(Get-SpecValue -Spec $ruleSet -Name 'rules' -Default @())
    if ($rules.Count -eq 0) { throw "ruleset '$Path' declares no rules." }

    $ruleSet['group']    = $groupName
    $ruleSet['rules']    = $rules
    $ruleSet['_path']    = $Path
    $ruleSet['_basePath'] = Split-Path -Parent $Path
    return $ruleSet
}

function New-RuleSpec {
    <#  Turn one ruleset rule into a parameter set for New-NetFirewallRule, with all
        dynamic values already resolved. Throws rather than emitting anything the
        firewall would misread. #>
    param(
        [hashtable]$Rule,
        [hashtable]$Defaults,
        [string]$GroupName,
        [string]$BasePath,
        [string]$ProgramOverride
    )

    $key = [string](Get-SpecValue -Spec $Rule -Name 'key')
    if (-not $key) { throw "every rule needs a 'key' that is unique within the ruleset." }
    if ($key -notmatch '^[A-Za-z0-9._-]+$') {
        throw "rule key '$key': only letters, digits, dot, underscore and hyphen are allowed."
    }

    # Resolvers that need to know which executable the rule is scoped to get it here,
    # settled before the field loop runs: 'program' is resolved late in FieldMap order,
    # so a resolver reading it from the half-built spec would see nothing.
    $effectiveProgram = $ProgramOverride
    if (-not $effectiveProgram) {
        if ($Rule.ContainsKey('program'))          { $effectiveProgram = [string]$Rule['program'] }
        elseif ($Defaults.ContainsKey('program'))  { $effectiveProgram = [string]$Defaults['program'] }
    }
    $context = @{ ProgramPath = $effectiveProgram; Group = $GroupName; Key = $key }

    $spec = @{}
    foreach ($jsonKey in $script:FieldMap.Keys) {
        $param = $script:FieldMap[$jsonKey]

        # Presence is decided with ContainsKey and the value is read by indexing, not
        # through a function return: returning a list from a function unrolls it, and
        # an empty list unrolls to $null. That would quietly reclassify a deliberately
        # empty "remoteAddress": [] as "field absent" and widen the rule to Any.
        $present = $false
        $raw     = $null
        if ($Rule.ContainsKey($jsonKey) -and $null -ne $Rule[$jsonKey]) {
            $raw = $Rule[$jsonKey]; $present = $true
        } elseif ($Defaults.ContainsKey($jsonKey) -and $null -ne $Defaults[$jsonKey]) {
            $raw = $Defaults[$jsonKey]; $present = $true
        }

        if (-not $present) {
            if ($script:FieldDefaults.ContainsKey($param)) { $spec[$param] = $script:FieldDefaults[$param] }
            continue
        }

        $value = Resolve-FirewallValue -Value $raw -FieldName "$key.$jsonKey" -BasePath $BasePath -Context $context

        if ($param -eq 'Enabled') {
            if ($value -is [bool]) { $value = $(if ($value) { 'True' } else { 'False' }) }
            $value = [string]$value
        }

        if ($value -is [System.Array] -and $value.Count -eq 0) {
            throw "rule '$key': field '$jsonKey' resolved to an empty list. Remove the field or give it a value."
        }

        $spec[$param] = $value
    }

    if (-not $spec['DisplayName']) { throw "rule '$key' is missing 'displayName'." }
    if (@('Inbound', 'Outbound') -notcontains $spec['Direction']) {
        throw "rule '$key': direction must be Inbound or Outbound (got '$($spec['Direction'])')."
    }
    if (@('Allow', 'Block') -notcontains $spec['Action']) {
        throw "rule '$key': action must be Allow or Block (got '$($spec['Action'])')."
    }
    if (@('True', 'False') -notcontains $spec['Enabled']) {
        throw "rule '$key': enabled must be true or false (got '$($spec['Enabled'])')."
    }

    # Windows only attaches a port filter to TCP and UDP rules; asking for ports on
    # any other protocol is silently meaningless, so say so instead.
    $portScoped = @('TCP', 'UDP') -contains ([string]$spec['Protocol']).ToUpperInvariant()
    foreach ($portParam in @('LocalPort', 'RemotePort')) {
        $hasPort = (@($spec[$portParam]) -join ',') -ne 'Any'
        if ($hasPort -and -not $portScoped) {
            throw "rule '$key': $portParam is set but protocol is '$($spec['Protocol'])'. Ports require TCP or UDP."
        }
        if (-not $portScoped) { $spec.Remove($portParam) }
    }

    if ($ProgramOverride) { $spec['Program'] = $ProgramOverride }
    if ($spec['Program'] -ne 'Any') {
        if (-not (Test-Path -LiteralPath ([string]$spec['Program']) -PathType Leaf)) {
            throw "rule '$key': program not found: $($spec['Program'])"
        }
    }

    $stamp = Get-Date -Format 'yyyy-MM-dd HH:mm'
    if ($spec['Description']) {
        $spec['Description'] = "$($spec['Description']) [fwmgr $GroupName/$key, applied $stamp]"
    } else {
        $spec['Description'] = "[fwmgr $GroupName/$key, applied $stamp]"
    }

    $spec['Name']  = Get-RuleName -GroupName $GroupName -Key $key
    $spec['Group'] = $GroupName
    return $spec
}

function Test-RuleSpecSafety {
    param([hashtable]$Spec, [switch]$AllowBroad)

    if ($Spec['Action'] -ne 'Block') { return }

    $anyAddress = (@($Spec['RemoteAddress']) -join ',') -eq 'Any'
    $anyPort    = (-not $Spec.ContainsKey('RemotePort')) -or ((@($Spec['RemotePort']) -join ',') -eq 'Any')
    $anyProgram = $Spec['Program'] -eq 'Any'
    $anyProto   = ([string]$Spec['Protocol']) -eq 'Any'

    if ($anyAddress -and $anyPort -and $anyProgram -and $anyProto) {
        $message = "rule '$($Spec['DisplayName'])' would block ALL $($Spec['Direction']) traffic: no address, port, protocol or program constraint."
        if (-not $AllowBroad) { throw "$message Re-run with -Force if that is genuinely what you want." }
        Write-Warning $message
    }
}

#endregion

#region actions ---------------------------------------------------------------

function Export-RuleGroup {
    <#  Serialise a live group back into ruleset shape. Used both for -Action Export
        and for the automatic pre-change backup. Dynamic values come out resolved,
        which is what you want from a backup and what you would edit by hand. #>
    param([string]$GroupName, [string]$Path, [switch]$Quiet)

    $rules = Get-ManagedRule -GroupName $GroupName
    if ($rules.Count -eq 0) { return $false }

    $prefixLength = (Get-RuleName -GroupName $GroupName -Key '').Length
    $exported = @()

    foreach ($rule in ($rules | Sort-Object Name)) {
        $ports    = $rule | Get-NetFirewallPortFilter
        $addrs    = $rule | Get-NetFirewallAddressFilter
        $app      = $rule | Get-NetFirewallApplicationFilter
        $service  = $rule | Get-NetFirewallServiceFilter

        $entry = [ordered]@{
            key           = $rule.Name.Substring($prefixLength)
            displayName   = $rule.DisplayName
            description   = $rule.Description
            direction     = [string]$rule.Direction
            action        = [string]$rule.Action
            enabled       = ($rule.Enabled -eq 'True')
            profile       = [string]$rule.Profile
            protocol      = [string]$ports.Protocol
            localPort     = @($ports.LocalPort)
            remotePort    = @($ports.RemotePort)
            localAddress  = @($addrs.LocalAddress)
            remoteAddress = @($addrs.RemoteAddress)
            program       = [string]$app.Program
            service       = [string]$service.Service
        }
        $exported += $entry
    }

    $document = [ordered]@{
        group       = $GroupName
        description = "Exported from live firewall rules on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')."
        rules       = $exported
    }

    $directory = Split-Path -Parent $Path
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $json = $document | ConvertTo-Json -Depth 8
    [System.IO.File]::WriteAllText($Path, $json, (New-Object System.Text.UTF8Encoding($false)))

    if (-not $Quiet) { Write-Host "Exported $($exported.Count) rule(s) to $Path" }
    return $true
}

function Backup-RuleGroup {
    param([string]$GroupName)

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path  = Join-Path $script:BackupDir ("{0}_{1}.json" -f ($GroupName -replace '\s', '_'), $stamp)
    if (Export-RuleGroup -GroupName $GroupName -Path $path -Quiet) {
        Write-Host "Backup: $path" -ForegroundColor DarkGray
    }
}

function Show-Status {
    param([string]$GroupName)

    if (-not $GroupName) {
        $all = Get-ManagedRule
        Write-Section 'Managed groups'
        if ($all.Count -eq 0) {
            Write-Host '  (none installed)'
        } else {
            foreach ($set in ($all | Group-Object Group | Sort-Object Name)) {
                $enabled = @($set.Group | Where-Object { $_.Enabled -eq 'True' }).Count
                Write-Host ('  {0,-28} {1} rule(s), {2} enabled' -f $set.Name, $set.Count, $enabled)
            }
        }

        Write-Section 'Available rulesets'
        $files = @(Get-ChildItem -Path $script:RuleSetDir -Filter '*.json' -ErrorAction SilentlyContinue | Sort-Object Name)
        if ($files.Count -eq 0) {
            Write-Host '  (none)'
        } else {
            foreach ($file in $files) {
                $label = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
                $installed = ''
                try {
                    $candidate = Import-RuleSet -Path $file.FullName
                    if ((Get-ManagedRule -GroupName $candidate['group']).Count -gt 0) { $installed = '  [installed]' }
                    Write-Host ('  {0,-28} group={1}{2}' -f $label, $candidate['group'], $installed)
                } catch {
                    Write-Host ('  {0,-28} <unreadable: {1}>' -f $label, $_.Exception.Message) -ForegroundColor Yellow
                }
            }
        }
        Write-Host ''
        Write-Host 'Detail:  .\Manage-Firewall.ps1 Status -Group <name>' -ForegroundColor DarkGray
        return
    }

    $rules = Get-ManagedRule -GroupName $GroupName
    Write-Section "Group '$GroupName'"
    if ($rules.Count -eq 0) {
        Write-Host '  no rules installed for this group.'
        return
    }

    foreach ($rule in ($rules | Sort-Object Name)) {
        $ports = $rule | Get-NetFirewallPortFilter
        $addrs = $rule | Get-NetFirewallAddressFilter
        $app   = $rule | Get-NetFirewallApplicationFilter

        $state = if ($rule.Enabled -eq 'True') { 'enabled ' } else { 'DISABLED' }
        $colour = if ($rule.Enabled -eq 'True') { 'Green' } else { 'Yellow' }

        Write-Host ''
        Write-Host ('  [{0}] {1}' -f $state, $rule.DisplayName) -ForegroundColor $colour
        Write-Host ('      name          {0}' -f $rule.Name)
        Write-Host ('      match         {0} {1} / {2}' -f $rule.Direction, $rule.Action, $ports.Protocol)
        Write-Host ('      remote port   {0}' -f (Format-FilterValue $ports.RemotePort))
        Write-Host ('      remote addr   {0}' -f (Format-FilterValue $addrs.RemoteAddress))
        if ($app.Program -ne 'Any') {
            Write-Host ('      program       {0}' -f $app.Program)
        } else {
            Write-Host ('      program       Any (applies machine-wide)') -ForegroundColor DarkYellow
        }
        Write-Host ('      description   {0}' -f $rule.Description) -ForegroundColor DarkGray
    }
    Write-Host ''
}

function Invoke-RuleSetApply {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [hashtable]$RuleSet,
        [string]$ProgramOverride,
        [switch]$PreserveState,
        [switch]$SkipBackup,
        [switch]$AllowBroad
    )

    $groupName = [string]$RuleSet['group']
    $defaults  = @{}
    $declared  = Get-SpecValue -Spec $RuleSet -Name 'defaults'
    if ($declared -is [hashtable]) { $defaults = $declared }

    # Phase 1 - resolve and validate everything. The firewall is untouched until this
    # completes, so a failed lookup or a bad field is a no-op rather than a partial
    # apply.
    Write-Section "Resolving '$groupName' from $($RuleSet['_path'])"
    $specs = @()
    foreach ($rule in @($RuleSet['rules'])) {
        $specs += , (New-RuleSpec -Rule $rule -Defaults $defaults -GroupName $groupName `
                                  -BasePath $RuleSet['_basePath'] -ProgramOverride $ProgramOverride)
    }

    $duplicates = @($specs | Group-Object { $_['Name'] } | Where-Object { $_.Count -gt 1 })
    if ($duplicates.Count -gt 0) {
        throw "duplicate rule keys in ruleset: $(($duplicates | ForEach-Object { $_.Name }) -join ', ')"
    }

    foreach ($spec in $specs) { Test-RuleSpecSafety -Spec $spec -AllowBroad:$AllowBroad }

    foreach ($spec in $specs) {
        $portText = 'n/a'
        if ($spec.ContainsKey('RemotePort')) { $portText = Format-FilterValue $spec['RemotePort'] }
        Write-Host ''
        Write-Host ('  {0}' -f $spec['DisplayName']) -ForegroundColor Green
        Write-Host ('      {0} {1} / {2}   remote port {3}' -f $spec['Direction'], $spec['Action'], $spec['Protocol'], $portText)
        Write-Host ('      remote addr   {0}' -f (Format-FilterValue $spec['RemoteAddress']))
        Write-Host ('      program       {0}' -f $spec['Program'])
    }
    Write-Host ''

    if (-not $PSCmdlet.ShouldProcess("firewall group '$groupName'", "apply $($specs.Count) rule(s)")) {
        Write-Host 'No changes made.' -ForegroundColor DarkGray
        return
    }

    Assert-Administrator -ForAction 'Apply'

    # Phase 2 - snapshot whatever is there now.
    if (-not $SkipBackup) { Backup-RuleGroup -GroupName $groupName }

    # Phase 3 - upsert. Set-NetFirewallRule edits a live rule atomically, so a rule
    # is never absent mid-run the way a delete-then-create cycle would leave it.
    $created = 0
    $updated = 0
    foreach ($spec in $specs) {
        $existing = Get-NetFirewallRule -Name $spec['Name'] -ErrorAction SilentlyContinue

        if ($null -eq $existing) {
            New-NetFirewallRule @spec | Out-Null
            $created++
            continue
        }

        if ($existing.Group -ne $groupName) {
            throw "rule '$($spec['Name'])' already exists in group '$($existing.Group)'. Refusing to hijack it."
        }

        $params = $spec.Clone()
        $params.Remove('Group')
        $params['NewDisplayName'] = $params['DisplayName']
        $params.Remove('DisplayName')
        if ($PreserveState) { $params['Enabled'] = [string]$existing.Enabled }

        Set-NetFirewallRule @params
        $updated++
    }

    # Phase 4 - drop rules this group used to own but the ruleset no longer declares.
    $wanted  = @($specs | ForEach-Object { $_['Name'] })
    $current = Get-ManagedRule -GroupName $groupName
    $stale   = @($current | Where-Object { $wanted -notcontains $_.Name })
    foreach ($rule in $stale) {
        Write-Host "  pruning rule no longer in the ruleset: $($rule.DisplayName)" -ForegroundColor DarkYellow
        Remove-NetFirewallRule -Name $rule.Name
    }

    Write-Host ''
    Write-Host ("[$groupName] {0} created, {1} updated, {2} pruned." -f $created, $updated, $stale.Count) -ForegroundColor Green
    if ($PreserveState) { Write-Host '  (-KeepState: enabled/disabled state left as it was)' -ForegroundColor DarkGray }
    Write-Host "  Roll back:  .\Manage-Firewall.ps1 Disable -Group `"$groupName`"" -ForegroundColor DarkGray
}

function Set-RuleGroupState {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$GroupName, [ValidateSet('Enable', 'Disable')][string]$State)

    $rules = Get-ManagedRule -GroupName $GroupName
    if ($rules.Count -eq 0) {
        Write-Host "[$GroupName] no managed rules found; nothing to do."
        return
    }

    if (-not $PSCmdlet.ShouldProcess("firewall group '$GroupName'", "$State $($rules.Count) rule(s)")) { return }
    Assert-Administrator -ForAction $State

    if ($State -eq 'Enable') { $rules | Enable-NetFirewallRule } else { $rules | Disable-NetFirewallRule }
    Write-Host "[$GroupName] $($rules.Count) rule(s) $($State.ToLower())d." -ForegroundColor Green
}

function Remove-RuleGroup {
    [CmdletBinding(SupportsShouldProcess = $true)]
    param([string]$GroupName, [switch]$SkipBackup)

    $rules = Get-ManagedRule -GroupName $GroupName
    if ($rules.Count -eq 0) {
        Write-Host "[$GroupName] no managed rules found; nothing to do."
        return
    }

    if (-not $PSCmdlet.ShouldProcess("firewall group '$GroupName'", "remove $($rules.Count) rule(s)")) { return }
    Assert-Administrator -ForAction 'Remove'

    if (-not $SkipBackup) { Backup-RuleGroup -GroupName $GroupName }
    $rules | Remove-NetFirewallRule
    Write-Host "[$GroupName] $($rules.Count) rule(s) removed." -ForegroundColor Green
}

#endregion

#region dispatch --------------------------------------------------------------

try {
    # Fail on elevation before doing any network or disk work, so a non-elevated
    # session gets one clear message instead of a stack of resolved output followed
    # by a refusal. -WhatIf deliberately stays available without elevation.
    if (@('Apply', 'Enable', 'Disable', 'Remove') -contains $Action -and -not $WhatIfPreference) {
        Assert-Administrator -ForAction $Action
    }

    # -Group wins; otherwise the group comes from the ruleset file.
    $loadedRuleSet = $null
    $targetGroup   = $Group

    if ($Action -eq 'Apply') {
        $loadedRuleSet = Import-RuleSet -Path (Resolve-RuleSetPath -Name $RuleSet)
        $targetGroup   = $loadedRuleSet['group']
    } elseif (-not $targetGroup -and $RuleSet) {
        $loadedRuleSet = Import-RuleSet -Path (Resolve-RuleSetPath -Name $RuleSet)
        $targetGroup   = $loadedRuleSet['group']
    }

    switch ($Action) {

        'Status' { Show-Status -GroupName $targetGroup }

        'Apply' {
            Invoke-RuleSetApply -RuleSet $loadedRuleSet -ProgramOverride $Program `
                                -PreserveState:$KeepState -SkipBackup:$NoBackup -AllowBroad:$Force
        }

        'Enable'  {
            if (-not $targetGroup) { throw 'Enable needs -Group or -RuleSet.' }
            Set-RuleGroupState -GroupName $targetGroup -State 'Enable'
        }

        'Disable' {
            if (-not $targetGroup) { throw 'Disable needs -Group or -RuleSet.' }
            Set-RuleGroupState -GroupName $targetGroup -State 'Disable'
        }

        'Remove'  {
            if (-not $targetGroup) { throw 'Remove needs -Group or -RuleSet.' }
            Remove-RuleGroup -GroupName $targetGroup -SkipBackup:$NoBackup
        }

        'Export'  {
            if (-not $targetGroup) { throw 'Export needs -Group or -RuleSet.' }
            $path = $OutFile
            if (-not $path) {
                $path = Join-Path $script:ExportDir ("{0}.json" -f ($targetGroup -replace '\s', '_'))
            }
            if (-not (Export-RuleGroup -GroupName $targetGroup -Path $path)) {
                Write-Host "[$targetGroup] no managed rules found; nothing exported."
            }
        }
    }
} catch {
    Write-Host ''
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host '  The firewall was not changed.' -ForegroundColor DarkGray
    exit 1
}

#endregion
