# Narrow-the-Valve

Apply, inspect, disable, and remove Windows Firewall rules, treating one JSON file as one group.

Remote addresses can be fixed values, or fetched from an external source at apply time (resolvers). When the upstream list changes, re-running keeps the rules in sync.

---

## Quick start

`steam-relay-tokyo` is used as the running example below; every other ruleset follows the same flow.

```powershell
cd $env:USERPROFILE\narrow-the-valve

# 1. See what's there (no admin rights needed)
.\Manage-Firewall.ps1

# 2. See what would happen. Nothing is changed yet
.\Manage-Firewall.ps1 Apply steam-relay-tokyo -Program "D:\...\yourgame.exe" -WhatIf

# 3. Apply it from an elevated PowerShell
.\Manage-Firewall.ps1 Apply steam-relay-tokyo -Program "D:\...\yourgame.exe"

# 4. Verify. Both rules should be enabled, with program pointing at the game exe
.\Manage-Firewall.ps1 Status -Group SDR-Pin-TYO

# 5. Stop it if something goes wrong
.\Manage-Firewall.ps1 Disable -Group SDR-Pin-TYO
```

Step 2 is the habit worth keeping: `-WhatIf` really does fetch the lists, and shows you the resulting rules without writing anything.

Running the script at all requires either a one-time `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, or the full-path invocation, which also saves the `cd`:

```
powershell -NoProfile -ExecutionPolicy Bypass -File "$env:USERPROFILE\narrow-the-valve\Manage-Firewall.ps1" Apply steam-relay-tokyo -Program "C:\Program Files (x86)\Steam\steamapps\common\ARMORED CORE VI FIRES OF RUBICON\Game\armoredcore6.exe"
```

---

## Commands

```
.\Manage-Firewall.ps1 [Action] [RuleSet] [options]
```

| Command | What it does |
| --- | --- |
| `.\Manage-Firewall.ps1` | Lists the managed groups and the available rulesets |
| `... Status -Group <name>` | Details for that group (enabled/disabled, destination count, target exe) |
| `... Apply <ruleset>` | Create or update. Updates in place if it already exists |
| `... Disable -Group <name>` | Temporarily disable. Reach for this first if you lose connectivity |
| `... Enable -Group <name>` | Re-enable |
| `... Remove -Group <name>` | Delete |
| `... Export -Group <name> -OutFile x.json` | Write the current rules out in ruleset format |

`<ruleset>` is either a name under `rulesets\` (without the extension) or a path to a `.json` file.

| Option | Meaning |
| --- | --- |
| `-Program <path>` | Restrict the entire ruleset to traffic from that exe |
| `-WhatIf` | Resolve and validate only; change nothing |
| `-KeepState` | Preserve the enabled/disabled state on Apply, so a group you disabled yourself is not silently re-enabled |
| `-Force` | Allow rules that would otherwise be rejected as too broad |
| `-NoBackup` | Skip the automatic pre-change backup |

`Status` and `-WhatIf` run without admin rights. Only operations that change something need elevation.

---

## Writing a ruleset

Drop in `rulesets\my-rules.json` and it becomes usable as `Apply my-rules`. Minimal form:

```json
{
  "group": "My-Group",
  "rules": [
    {
      "key": "block-them",
      "displayName": "Block those hosts",
      "direction": "Outbound",
      "action": "Block",
      "protocol": "TCP",
      "remotePort": "443",
      "remoteAddress": ["203.0.113.0/24", "198.51.100.7"]
    }
  ]
}
```

`group`, `key`, `displayName`, `direction`, and `action` are required. `key` must be unique within the group, since it is the rule's identifier.

Other fields you can set: `description` `enabled` `profile` `protocol` `localPort` `remotePort` `localAddress` `remoteAddress` `program` `service` `interfaceType`

- A top-level `"defaults": { ... }` supplies defaults for every rule; a value on the rule itself wins
- Omitted fields are written out explicitly as `Any`. Delete a field from the JSON and re-apply, and the filter really does disappear from the rule
- Values come in three forms — single, array, and resolver:

```json
"remoteAddress": "10.0.0.0/8"
"remoteAddress": ["10.0.0.0/8", "192.168.0.0/16"]
"remoteAddress": { "resolver": "file", "path": "lists/blocklist.txt", "minCount": 1 }
```

---

## Resolvers

A resolver fetches the value at apply time instead of reading it from the JSON.

### `steam-sdr`

Picks from the list of Steam relay servers published by Valve.

```json
{ "resolver": "steam-sdr", "appId": "auto", "excludePops": ["tyo"], "minCount": 100 }
```

- `appId` — set it to `"auto"` and it is determined from the exe passed to `-Program`: the Steam library layout (`steamapps\common\<installdir>\...`) is walked and matched against `installdir` in `appmanifest_<appid>.acf`, so it works no matter which drive the game is on. A literal number works too, which is what you want if you intend to run without `-Program`
- `excludePops` — targets everything other than those POPs, i.e. leaves only those. `includePops` is the inverse. POP names come from the `pops` field of [GetSDRConfig](https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=2622380)
- `"emit": "portRange"` — derives a range such as `27015-27140` from the `port_range` of the selected relays

### `file`

Reads a text file with one entry per line. Blank lines and anything after `#` / `;` are ignored, and relative paths are relative to the JSON.

```json
{ "resolver": "file", "path": "lists/blocklist.txt", "minCount": 1 }
```

### `dns`

Resolves hostnames. What gets baked in is the address at apply time; it is never re-resolved afterwards.

```json
{ "resolver": "dns", "hostnames": ["example.com"], "addressFamily": "IPv4", "minCount": 1 }
```

To add a resolver, write a `Resolve-Xxx` in `lib\Resolvers.ps1` and add a single line to the `switch` in `Resolve-FirewallValue`.

---

## Built to fail safe

- Resolve before touching anything — nothing is written to the firewall until every fetch and validation has completed. If a fetch fails, the existing rules are left as they are
- Abort below `minCount` — prevents a truncated response from degenerating into "no destination = everything". Empty arrays are rejected the same way
- In-place update — not delete-then-recreate, so there is never a moment mid-apply where the rule is missing
- Only `fwmgr:<group>:*` is touched — hand-made rules and rules from other software are left alone
- Overly broad Block rules are rejected — if none of destination, port, protocol, or program is constrained, it will not be created without `-Force`
- Automatic backup — the current state is written to `backups\` before Apply / Remove, in the same format as Export so it can be read back
- Descriptions converge — each rule's description carries a `[fwmgr <group>/<key>, applied <time>]` marker, and any existing marker is stripped on the way in, so applying an export or a backup does not stack a second one
- Orphan cleanup — a rule removed from the JSON is automatically deleted from that group

---

## Bundled rulesets

### `steam-relay-tokyo` — pin Steam's relay servers to Tokyo

The procedure from [this article](https://zenn.dev/kikurage7/articles/8b4d12fe0b7198). It blocks traffic to relay servers outside Tokyo, so Tokyo is what's left by elimination. Both the current and the legacy relay scheme are covered, by these two rules, and Apply always creates both:

| Rule | Target | Port | How destinations are chosen |
| --- | --- | --- | --- |
| `SDR block non-TYO relays` | Current-scheme SDR relays | `27015-27140` (derived from the API) | Every entry other than `tyo` from Valve's [GetSDRConfig](https://api.steampowered.com/ISteamApps/GetSDRConfig/v1?appid=2622380), 135 at present |
| `SDR block non-TYO legacy relays` | Legacy P2P relays | `4379-4380` | Seven Valve netblocks, enumerated as fixed values |

The legacy scheme is the one that actually caused the trouble in the article: the connection ended up on the Seoul relay `146.66.152.43:4379`. That address does not appear in GetSDRConfig, so the API cannot supply it and the netblocks have to be written out directly. `45.121.184.0/24`, which holds Tokyo's legacy relay, is deliberately left out of that list, and that omission is what leaves Tokyo standing.

Because `appId` is `"auto"`, you never name the game — the one ruleset covers any of them. Things to keep in mind:

- `-Program` is required, since it is also what `appId: "auto"` keys off. Point it at the game's own exe that carries the traffic (`nightreign.exe`, `armoredcore6.exe`, and so on), not the `start_protected_game.exe` launcher
- Only if you want it to apply to every game: rewrite `appId` as a number and drop `-Program`. Other games that connect abroad via relay servers may then stop connecting
- Relay server IPs change. Re-run `Apply` roughly once a month, or whenever things misbehave
- Two titles cannot be protected at once. `group` is fixed to `SDR-Pin-TYO`, so re-applying with a different `-Program` overwrites the same group. To run two, copy the JSON and change `group`
- Outside Japan, set `excludePops` to a nearby POP — and fix the legacy rule at the same time. Its seven `remoteAddress` blocks are written on the assumption that only Tokyo is excluded, so leaving them as-is would also block the legacy relay at the site you want to keep. If you don't need it, delete the `legacy-relays` rule entirely
- This only affects the leg between you and the relay server. The other player's connection quality, and which relay they land on, are outside your control, so it will not remove the latency of being matched with a distant player
- Valve does not publish IPv6 addresses through this API, so traffic passes straight through if an IPv6 route exists
- When another Steam game mysteriously won't connect, suspect the `SDR-Pin-TYO` group first

### `example-app-blocklist` — template

A sample of the `file` / `dns` resolvers and of scoping to a program. The exe path does not exist, so applying it as-is fails on purpose. Copy it and edit it.

---

## Scheduled refresh

Relay addresses move, so a group is only as current as its last Apply. Register a scheduled task and stop thinking about it. Run this once from an elevated PowerShell; `$exe` is the only line to edit.

```powershell
cd $env:USERPROFILE\narrow-the-valve
$script = (Resolve-Path .\Manage-Firewall.ps1).ProviderPath
$exe    = 'C:\...\yourgame.exe'
$logDir = "$env:ProgramData\narrow-the-valve"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null

# The trailing fragment is single-quoted so $LASTEXITCODE reaches the task, instead of
# being expanded here at registration time.
$inner = "& '$script' Apply steam-relay-tokyo -Program '$exe' -KeepState *>> '$logDir\refresh.log'" + '; exit [int]$LASTEXITCODE'

$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument "-NoProfile -ExecutionPolicy Bypass -Command `"$inner`""

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 4am `
    -RandomDelay (New-TimeSpan -Minutes 30)

$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 15)

Register-ScheduledTask -TaskName 'Refresh SDR-Pin-TYO' -TaskPath '\narrow-the-valve\' `
    -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
    -Description 'Re-apply steam-relay-tokyo so the relay list stays current.'
```

Why the ceremony, rather than a bare `Register-ScheduledTask`:

| Piece | Why |
| --- | --- |
| Runs as `SYSTEM` | Apply needs elevation. SYSTEM has it unattended: no stored password, no UAC prompt, and it runs whether or not anyone is logged in |
| `-KeepState` | A group you disabled by hand stays disabled. Without it, the 4am run quietly switches your rules back on |
| `-RunOnlyIfNetworkAvailable`, `-RestartCount 3` | The run really does call the Steam API, so an interface that is not up yet would otherwise burn the week's only attempt |
| `-StartWhenAvailable` | A machine that is off at 4am catches up at next boot instead of silently skipping |
| `powershell.exe`, not `pwsh` | The script targets Windows PowerShell 5.1, where the NetSecurity cmdlets are native |
| `*>> refresh.log` | `-File` cannot redirect, and the output is worth keeping. Nothing rotates this file |

Check on it:

```powershell
Start-ScheduledTask -TaskName 'Refresh SDR-Pin-TYO' -TaskPath '\narrow-the-valve\'

Get-ScheduledTaskInfo -TaskName 'Refresh SDR-Pin-TYO' -TaskPath '\narrow-the-valve\' |
    Select-Object LastRunTime, LastTaskResult, NextRunTime

Get-Content "$env:ProgramData\narrow-the-valve\refresh.log" -Tail 40
```

`LastTaskResult` 0 is success; 1 means the script aborted and left the firewall untouched. `Status -Group SDR-Pin-TYO` is the other half of the answer — every rule's description carries the timestamp of the Apply that last wrote it, so you can see whether a run really landed.

Each scheduled run also writes a snapshot to `backups\`, and nothing prunes them. Add `-NoBackup` to `$inner` if a weekly snapshot is not worth the file.

Undo the whole thing with:

```powershell
Unregister-ScheduledTask -TaskName 'Refresh SDR-Pin-TYO' -TaskPath '\narrow-the-valve\' -Confirm:$false
```

### Refreshing by hand

An occasional manual refresh, from an elevated PowerShell:

```powershell
& "$env:USERPROFILE\narrow-the-valve\Manage-Firewall.ps1" Apply steam-relay-tokyo -Program "C:\...\yourgame.exe" -NoBackup
```

The same thing from an ordinary prompt, elevating on the way:

```powershell
Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -NoExit -Command `"& '$env:USERPROFILE\narrow-the-valve\Manage-Firewall.ps1' Apply steam-relay-tokyo -Program 'C:\...\yourgame.exe' -NoBackup`""
```

`-NoExit` is what keeps the elevated window open; without it the window closes the instant the run ends and you never see the result. `-NoBackup` skips the snapshot, which is what you want for something you run often and deliberately. `-KeepState` is deliberately absent here, since running it by hand usually means you want the group on.

Re-run it as often as you like. Rules are upserted under a stable name rather than recreated, fields you left out are pinned back to `Any`, rules dropped from the ruleset are pruned, and the description marker is stripped before a fresh one is stamped, so the group converges on the ruleset instead of drifting. The addresses themselves converge on upstream, which is the point. And a failed fetch aborts before anything is written, so a failed run is a no-op rather than a half-applied group.

---

## Layout

```
narrow-the-valve/
  Manage-Firewall.ps1                  # main script
  lib/Resolvers.ps1                    # steam-sdr / file / dns
  rulesets/
    steam-relay-tokyo.json
    example-app-blocklist.json
    lists/example-blocklist.txt
  backups/                             # automatic pre-change snapshots (generated)
  exports/                             # Export output (generated)
```
