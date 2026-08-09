#Requires -Version 5.1
<#
    Dynamic value providers for Manage-Firewall.ps1.

    A ruleset field may hold:

        "10.0.0.0/8"                        - used as-is
        ["10.0.0.0/8", "192.168.0.0/16"]    - used as-is
        { "resolver": "<name>", ... }       - produced by one of the functions below

    Contract for every resolver:

      * It returns a string, or an array of strings, and nothing else.
      * It THROWS on anything it cannot vouch for. Resolvers run before the firewall
        is touched, so throwing is the safe outcome: the machine keeps the rules it
        already has. Never return a partial or empty list to "keep going".

    Adding a resolver: write a Resolve-XxxValue function and add one line to the
    switch in Resolve-FirewallValue.
#>

Set-StrictMode -Version 2.0

# Per-process response cache so a ruleset that references the same upstream source
# from several fields sees one consistent snapshot and makes one request.
$script:ResolverCache = @{}

function Get-JsonProperty {
    <#  Property access that tolerates absence, which Set-StrictMode does not. #>
    param($Object, [string]$Name)

    if ($null -eq $Object) { return $null }
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $null }
    return $prop.Value
}

function Get-SpecValue {
    <#  Convenience reader for scalar spec keys. Returning a collection through it is
        lossy - PowerShell unrolls arrays on return, and an empty one unrolls to
        $null - so callers that care about list values index the hashtable directly
        instead. See New-RuleSpec. #>
    param([hashtable]$Spec, [string]$Name, $Default = $null)

    if ($Spec.ContainsKey($Name) -and $null -ne $Spec[$Name]) { return $Spec[$Name] }
    return $Default
}


function Resolve-FirewallValue {
    <#
    .SYNOPSIS
        Turn one ruleset field into the literal value handed to New-NetFirewallRule.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [AllowNull()] $Value,
        [Parameter(Mandatory = $true)] [string] $FieldName,
        [string] $BasePath = '.',
        [hashtable] $Context = @{}
    )

    if ($null -eq $Value) { return $null }
    if ($Value -isnot [hashtable]) { return , $Value }

    $name = Get-SpecValue -Spec $Value -Name 'resolver'
    if (-not $name) {
        throw "field '$FieldName': object values must carry a 'resolver' key."
    }

    switch ($name) {
        'steam-sdr' { $result = Resolve-SteamSdrValue -Spec $Value -Context $Context }
        'file'      { $result = Resolve-FileValue     -Spec $Value -BasePath $BasePath }
        'dns'       { $result = Resolve-DnsValue      -Spec $Value }
        default     { throw "field '$FieldName': unknown resolver '$name'. Known: steam-sdr, file, dns." }
    }

    $items = @($result)
    $min = [int](Get-SpecValue -Spec $Value -Name 'minCount' -Default 1)
    if ($min -lt 1) { $min = 1 }

    if ($items.Count -lt $min) {
        throw ("field '$FieldName': resolver '$name' returned $($items.Count) entr" +
               "$(if ($items.Count -eq 1) { 'y' } else { 'ies' }), fewer than the required minCount of $min. " +
               'Refusing to build a rule from an incomplete list.')
    }

    Write-Verbose "resolver '$name' -> $($items.Count) value(s) for field '$FieldName'"
    return , $items
}


function Get-SteamAppIdFromProgram {
    <#
    .SYNOPSIS
        Work out which Steam app an executable belongs to, from its path alone.

    .DESCRIPTION
        Steam lays every library out as <library>\steamapps\common\<installdir>\...,
        and records the pairing in <library>\steamapps\appmanifest_<appid>.acf as
        "appid" / "installdir". So walking up from the exe to the <installdir> level
        gives a key that one manifest in that same library will match.

        Deriving it from the exe rather than from a configured library root means
        this works for games on any drive without extra configuration, and it cannot
        disagree with the -Program the rule is actually scoped to.
    #>
    param([string]$ProgramPath)

    if (-not $ProgramPath -or $ProgramPath -eq 'Any') {
        throw ("resolver 'steam-sdr': appId 'auto' needs the game executable to work from. " +
               'Pass -Program <path to the game .exe>, or put an explicit numeric appId in the ruleset.')
    }

    $cacheKey = "steam-appid:$($ProgramPath.ToLowerInvariant())"
    if ($script:ResolverCache.ContainsKey($cacheKey)) { return $script:ResolverCache[$cacheKey] }

    $full = [System.IO.Path]::GetFullPath($ProgramPath)

    # Climb until the current directory's parent is 'common' and its grandparent is
    # 'steamapps'; that directory is the installdir the manifests key off.
    $installDir = $null
    $steamApps  = $null
    $dir = Split-Path -Parent $full
    while ($dir) {
        $parent = Split-Path -Parent $dir
        if ($parent -and (Split-Path -Leaf $parent) -eq 'common') {
            $grandParent = Split-Path -Parent $parent
            if ($grandParent -and (Split-Path -Leaf $grandParent) -eq 'steamapps') {
                $installDir = Split-Path -Leaf $dir
                $steamApps  = $grandParent
                break
            }
        }
        $dir = $parent
    }

    if (-not $installDir) {
        throw ("resolver 'steam-sdr': '$ProgramPath' does not sit inside a Steam library " +
               '(expected ...\steamapps\common\<game>\...). Put an explicit numeric appId in the ruleset.')
    }

    foreach ($manifest in @(Get-ChildItem -LiteralPath $steamApps -Filter 'appmanifest_*.acf' -ErrorAction SilentlyContinue)) {
        # .acf is UTF-8; on 5.1 Get-Content would otherwise decode it as ANSI and
        # mangle installdir names that are not pure ASCII.
        $text = Get-Content -LiteralPath $manifest.FullName -Raw -Encoding UTF8
        $idMatch  = [regex]::Match($text, '"appid"\s*"(\d+)"', 'IgnoreCase')
        $dirMatch = [regex]::Match($text, '"installdir"\s*"([^"]+)"', 'IgnoreCase')
        if ($idMatch.Success -and $dirMatch.Success -and $dirMatch.Groups[1].Value -eq $installDir) {
            $appId = [int]$idMatch.Groups[1].Value
            $script:ResolverCache[$cacheKey] = $appId
            Write-Host "  steam-sdr: appId $appId ($installDir) resolved from $(Split-Path -Leaf $full)" -ForegroundColor DarkGray
            return $appId
        }
    }

    throw ("resolver 'steam-sdr': no appmanifest in '$steamApps' claims installdir '$installDir'. " +
           'The game may have been moved between libraries; verify the Steam install, or set a numeric appId.')
}


function Get-SteamSdrConfig {
    <#
    .SYNOPSIS
        Fetch (and cache) Valve's published Steam Datagram Relay list for one app.
    #>
    param([int]$AppId)

    $cacheKey = "steam-sdr:$AppId"
    if ($script:ResolverCache.ContainsKey($cacheKey)) { return $script:ResolverCache[$cacheKey] }

    $url = "https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=$AppId"
    Write-Verbose "steam-sdr: GET $url"

    try {
        $cfg = Invoke-RestMethod -Uri $url -TimeoutSec 30 -UseBasicParsing
    } catch {
        throw "steam-sdr: request to $url failed: $($_.Exception.Message)"
    }

    if (-not (Get-JsonProperty $cfg 'success')) {
        throw "steam-sdr: GetSDRConfig returned success=false for appid $AppId."
    }
    if ($null -eq (Get-JsonProperty $cfg 'pops')) {
        throw "steam-sdr: GetSDRConfig returned no 'pops' for appid $AppId."
    }

    $script:ResolverCache[$cacheKey] = $cfg
    return $cfg
}


function Resolve-SteamSdrValue {
    <#
    .SYNOPSIS
        Select Steam relay POPs and emit either their IPv4 addresses or their port range.

    .DESCRIPTION
        Spec keys:
          appId        (required) Steam app id, e.g. 2622380, or "auto" to derive it
                       from the executable the rule is scoped to
          includePops  keep only these POPs          ] mutually
          excludePops  keep everything but these POPs] exclusive
          emit         'ipv4' (default) or 'portRange'
          minCount     enforced by the caller

        Note that excludePops is the interesting direction: "block every relay except
        tyo" means excluding tyo from the *blocklist*. That makes the named POP
        load-bearing, so its continued existence is verified before anything is built.

        Valve does not publish IPv6 relay addresses in this feed, so an IPv6-capable
        client could in principle reach a relay this rule does not cover. There is
        nothing in the upstream data to key such a rule off.
    #>
    param([hashtable]$Spec, [hashtable]$Context = @{})

    $rawAppId = Get-SpecValue -Spec $Spec -Name 'appId' -Default 0
    if ($rawAppId -is [string] -and $rawAppId.Trim() -eq 'auto') {
        $appId = Get-SteamAppIdFromProgram -ProgramPath ([string](Get-SpecValue -Spec $Context -Name 'ProgramPath'))
    } else {
        $appId = [int]$rawAppId
    }
    if ($appId -le 0) { throw "resolver 'steam-sdr': 'appId' must be a positive number or the string ""auto""." }

    $include = @(Get-SpecValue -Spec $Spec -Name 'includePops' -Default @())
    $exclude = @(Get-SpecValue -Spec $Spec -Name 'excludePops' -Default @())
    $emit    = [string](Get-SpecValue -Spec $Spec -Name 'emit' -Default 'ipv4')

    if ($include.Count -gt 0 -and $exclude.Count -gt 0) {
        throw "resolver 'steam-sdr': set 'includePops' or 'excludePops', not both."
    }

    $cfg  = Get-SteamSdrConfig -AppId $appId
    $pops = $cfg.pops.PSObject.Properties

    # Every POP named in the spec must still exist and still have relays. If Valve
    # renames or empties the POP we are steering traffic towards, "block all the
    # others" silently becomes "block everything" - so refuse to build the rule.
    foreach ($popName in @($include + $exclude)) {
        $entry = $pops[$popName]
        if ($null -eq $entry -or -not (Get-JsonProperty $entry.Value 'relays')) {
            throw ("resolver 'steam-sdr': POP '$popName' is absent from the current config or has no " +
                   'relays. Refusing to build a rule whose preferred POP no longer exists.')
        }
    }

    $selected = New-Object System.Collections.Generic.List[object]
    foreach ($pop in $pops) {
        if ($include.Count -gt 0 -and $include -notcontains $pop.Name) { continue }
        if ($exclude.Count -gt 0 -and $exclude -contains $pop.Name)    { continue }

        $relays = Get-JsonProperty $pop.Value 'relays'
        if ($null -eq $relays) { continue }
        foreach ($relay in @($relays)) { [void]$selected.Add($relay) }
    }

    if ($selected.Count -eq 0) {
        throw "resolver 'steam-sdr': the POP selection matched no relays."
    }

    switch ($emit) {
        'ipv4' {
            $ips = @()
            foreach ($relay in $selected) {
                $ip = Get-JsonProperty $relay 'ipv4'
                if ($ip) { $ips += [string]$ip }
            }
            return @($ips | Sort-Object -Unique)
        }
        'portRange' {
            $ports = @()
            foreach ($relay in $selected) {
                $range = Get-JsonProperty $relay 'port_range'
                if ($null -ne $range) { $ports += @($range) }
            }
            if ($ports.Count -eq 0) {
                throw "resolver 'steam-sdr': no port_range data to derive a range from."
            }
            $min = ($ports | Measure-Object -Minimum).Minimum
            $max = ($ports | Measure-Object -Maximum).Maximum
            return "$min-$max"
        }
        default {
            throw "resolver 'steam-sdr': unknown emit '$emit' (expected 'ipv4' or 'portRange')."
        }
    }
}


function Resolve-FileValue {
    <#
    .SYNOPSIS
        Read one address or port per line from a text file.

    .DESCRIPTION
        Spec keys:
          path      (required) absolute, or relative to the ruleset file
          minCount  enforced by the caller

        Blank lines and lines starting with # or ; are skipped, as is anything after
        an inline # so entries can be annotated.
    #>
    param([hashtable]$Spec, [string]$BasePath)

    $path = [string](Get-SpecValue -Spec $Spec -Name 'path')
    if (-not $path) { throw "resolver 'file': 'path' is required." }

    if (-not [System.IO.Path]::IsPathRooted($path)) { $path = Join-Path $BasePath $path }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "resolver 'file': no such file: $path"
    }

    $values = @()
    foreach ($line in (Get-Content -LiteralPath $path)) {
        $text = $line
        $hash = $text.IndexOf('#')
        if ($hash -ge 0) { $text = $text.Substring(0, $hash) }
        $semi = $text.IndexOf(';')
        if ($semi -ge 0) { $text = $text.Substring(0, $semi) }
        $text = $text.Trim()
        if ($text -ne '') { $values += $text }
    }

    return @($values | Sort-Object -Unique)
}


function Resolve-DnsValue {
    <#
    .SYNOPSIS
        Resolve hostnames to literal addresses at apply time.

    .DESCRIPTION
        Spec keys:
          hostnames      (required) array of names
          addressFamily  'IPv4' (default) or 'IPv6'
          minCount       enforced by the caller

        A firewall rule holds the addresses as they were at apply time; it does not
        re-resolve. Anything behind a CDN or short TTL will drift, so re-apply on a
        schedule or prefer a static range.
    #>
    param([hashtable]$Spec)

    $hostnames = @(Get-SpecValue -Spec $Spec -Name 'hostnames' -Default @())
    if ($hostnames.Count -eq 0) { throw "resolver 'dns': 'hostnames' is required and must be non-empty." }

    $family = [string](Get-SpecValue -Spec $Spec -Name 'addressFamily' -Default 'IPv4')
    switch ($family) {
        'IPv4'  { $want = [System.Net.Sockets.AddressFamily]::InterNetwork }
        'IPv6'  { $want = [System.Net.Sockets.AddressFamily]::InterNetworkV6 }
        default { throw "resolver 'dns': unknown addressFamily '$family' (expected 'IPv4' or 'IPv6')." }
    }

    $addresses = @()
    foreach ($name in $hostnames) {
        try {
            $resolved = [System.Net.Dns]::GetHostAddresses([string]$name)
        } catch {
            throw "resolver 'dns': could not resolve '$name': $($_.Exception.Message)"
        }
        foreach ($addr in $resolved) {
            if ($addr.AddressFamily -eq $want) { $addresses += $addr.IPAddressToString }
        }
    }

    if ($addresses.Count -eq 0) {
        throw "resolver 'dns': no $family addresses found for $($hostnames -join ', ')."
    }
    return @($addresses | Sort-Object -Unique)
}
