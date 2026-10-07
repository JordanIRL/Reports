<#
.TITLE
    Intune Lens — resultant settings for Intune-managed Windows devices.

.SYNOPSIS
    Intune Lens — resultant settings (RSOP) for Intune-managed Windows devices.
    Answers: "What are ALL the settings that apply to this device / these devices?"
    Run with no parameters for a guided interactive menu.

.DESCRIPTION
    Aggregates every Windows configuration source in an Intune tenant:
      - Settings Catalog policies            (deviceManagement/configurationPolicies)
      - Endpoint Security policies (ASR, AV, Firewall, BitLocker, EDR, ...) - modern (configurationPolicies) and legacy (intents)
      - Security Baselines                   (modern: configurationPolicies, legacy: intents)
      - Device Configuration templates       (deviceManagement/deviceConfigurations, incl. custom OMA-URI)
      - Administrative Templates / ADMX      (deviceManagement/groupPolicyConfigurations)
      - Compliance policies                  (classic deviceCompliancePolicies incl. actions for
                                              noncompliance + custom compliance scripts, and
                                              Settings Catalog compliancePolicies) [optional]
      - Windows Update profiles              (feature / expedited quality / quality update
                                              (hotpatch) policies / driver) [optional]
      - Platform scripts                     (Windows PowerShell, macOS shell, macOS custom
                                              attributes - decoded script content, searchable) [optional]
      - Remediations                         (deviceHealthScripts: detection + remediation script
                                              content, run schedule per assignment) [optional]
      - App Configuration policies           (managed devices: mobileAppConfigurations;
                                              managed apps: targetedManagedAppConfigurations) [optional]
      - App Protection policies              (iOS / Android / Windows MAM, legacy WIP) [optional]
      - Enrollment configurations            (Enrollment Status Page, Windows Hello for Business,
                                              platform restrictions, device limits, co-management -
                                              resolved by priority) [optional]
      - Windows Autopilot deployment profiles (resolved by Intune's oldest-profile rule and
                                              All devices fallback, cross-checked with the
                                              device's Autopilot record) [optional]
      - Applications                         (deviceAppManagement/mobileApps - ONE entry per app with
                                              its Required / Available / Uninstall assignments, the
                                              resolved intent for the device using Intune's documented
                                              intent-conflict rules, install details, supersedence /
                                              dependencies, and the device-reported install state) [optional]

    For each target device it resolves:
      - Entra ID transitive group membership of the DEVICE object
      - Entra ID transitive group membership of the PRIMARY USER (user-targeted policies)
      - "All devices" / "All users" virtual assignments
      - Assignment filters (local rule evaluation against live inventory first; server-side
        /deviceManagement/evaluateAssignmentFilter for rules that are not locally decidable),
        combined with Intune's filter-mode precedence when several assignments reach the
        device: Exclude-mode filter > no filter > Include-mode filter (same mode = OR)
      - Group exclusions (kind-aware: user-group exclusions do not undo device-targeted
        includes and vice versa, per the Intune support matrix)
      - Priority / precedence where Intune picks one winner (ESP, enrollment restrictions,
        device limits, Autopilot profiles) - losers are reported as Superseded
      - Enrollment configuration predictions describe the current assignment snapshot,
        not historical enforcement at enrollment. Known userless/default and Windows
        device-limit exceptions are accounted for when exposed in device inventory.

    ...then flattens every individual setting (name + value) from every applicable policy,
    detects conflicts (same setting defined with different values by multiple applicable
    policies), and optionally cross-checks against what the device actually reported
    (reports/getConfigurationPoliciesReportForDevice - the data behind the portal's
    per-device Configuration blade).

    Targets can be specified by serial number, device name, Entra ID group, or assignment filter.

    Output: console summary + self-contained interactive HTML report (searchable, with
    CSV download). Optional raw CSV / JSON exports.

    Requires module: Microsoft.Graph.Authentication (only; raw REST is used for everything else).
    Delegated scopes: DeviceManagementConfiguration.Read.All,
                      DeviceManagementManagedDevices.Read.All,
                      Directory.Read.All,
                      DeviceManagementApps.Read.All (unless -SkipApps and -SkipAppPolicies),
                      DeviceManagementScripts.Read.All (unless -SkipScripts),
                      DeviceManagementServiceConfig.Read.All (unless -SkipEnrollment)

.PARAMETER SerialNumber
    One or more device serial numbers.

.PARAMETER DeviceName
    One or more Intune device names.

.PARAMETER Group
    Entra ID group display name or object id. All *device* members (transitive) are resolved.

.PARAMETER GroupAssignedOnly
    With -Group: instead of resolving member devices, list the policies/settings whose
    assignments directly reference this group (fast; no per-device evaluation).

.PARAMETER AssignmentFilter
    Assignment filter display name or id. The filter is evaluated server-side and all
    matching devices become targets.

.PARAMETER All
    Tenant-wide inventory: every policy (assigned or not) with all settings and a
    resolved assignment summary (group names, filters, exclusions). Great for cleanup.

.PARAMETER ScopeGroup
    With -All: narrow the inventory to policies whose assignments reach this Entra ID
    group (display name or object id) - directly, via a parent group (transitive), or
    via an All devices / All users assignment. Policies that only EXCLUDE the scope
    stay visible as Excluded (their settings land in the shadow set); everything else
    is dropped. Answers "what policies apply to this group?" without per-device math.

.PARAMETER ScopeFilter
    With -All: narrow the inventory to policies with at least one assignment carrying
    this assignment filter (display name or id). The include/exclude mode of the
    filter usage is spelled out per policy. Combinable with -ScopeGroup (both must match).

.PARAMETER SkipUpdates
    Skip Windows Update profiles (feature / expedite / driver).

.PARAMETER SkipScripts
    Skip platform scripts, remediations and macOS shell scripts / custom attributes (their
    decoded content is otherwise pulled and made searchable - that is how you catch a script
    that silently uninstalls an app). Script endpoints sit behind the dedicated
    DeviceManagementScripts.Read.All scope (only requested when scripts are included).

.PARAMETER SkipApps
    Skip applications. When apps are included (default) the report gets an Apps tab with
    one entry per app showing its Required / Available / Uninstall assignments side by side
    and - per device - the intent Intune resolves using its documented conflict rules
    (Required beats Uninstall, Uninstall beats Available, ...), so "what is uninstalling
    app X on this device" is a direct lookup. Requires DeviceManagementApps.Read.All.

.PARAMETER SkipAppPolicies
    Skip App Configuration policies (managed devices + managed apps) and App Protection
    policies. Requires DeviceManagementApps.Read.All when included.

.PARAMETER SkipEnrollment
    Skip enrollment configurations (ESP, Windows Hello for Business, restrictions, limits,
    co-management) and Windows Autopilot deployment profiles / the device's Autopilot
    record. Requires DeviceManagementServiceConfig.Read.All when included.

.PARAMETER ExportHtml
    Path for the interactive HTML report. Default: .\IntuneLens-<timestamp>.html
    (pass -NoHtml to suppress).

.PARAMETER ExportCsv
    Optional path for a flat CSV (one row per device x setting).

.PARAMETER ExportJson
    Optional path for the full structured JSON result.

.PARAMETER NoHtml
    Suppress the default HTML report.

.PARAMETER SkipCompliance
    Do not include compliance policies.

.PARAMETER SkipReportedStatus
    Skip the per-device "what did the device actually report" cross-check (faster).

.PARAMETER MaxDevices
    Safety cap for group/filter modes (default 25). 0 = unlimited.

.PARAMETER CacheMinutes
    The policy corpus (all policies + settings + assignments) is cached on disk to make
    repeat queries fast. Default TTL 60 minutes. Use -Refresh to force a re-pull.

.PARAMETER Refresh
    Ignore the on-disk policy cache and re-pull everything from Graph.

.PARAMETER PassThru
    Emit the per-device result objects to the pipeline.

.PARAMETER TenantId
    Optional tenant id/domain for Connect-MgGraph.

.PARAMETER ClientId
    Optional app registration client id for Connect-MgGraph (defaults to the Graph SDK app).

.PARAMETER Environment
    Graph environment: Global (default), USGov, USGovDoD, China.

.PARAMETER UseDeviceCode
    Use device-code sign-in (handy over SSH / in containers).

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -SerialNumber 5CD1234XYZ

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -SerialNumber 5CD1234XYZ,PF2ABCDE -ExportCsv rsop.csv

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -Group "Sales Laptops"

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -Group "Pilot Ring 1" -GroupAssignedOnly

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -AssignmentFilter "Corp Windows 11" -MaxDevices 10

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -All -ScopeGroup "Sales Laptops" -ExportCsv sales-scope.csv

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -All -ScopeFilter "Corp Windows 11"

.TAGS
    Microsoft Intune, Microsoft Graph, RSOP, Windows, reporting, troubleshooting

.PLATFORM
    PowerShell 7 or later on Windows, macOS, or Linux.

.PERMISSIONS
    Delegated: DeviceManagementConfiguration.Read.All,
    DeviceManagementManagedDevices.Read.All, Directory.Read.All,
    DeviceManagementApps.Read.All, DeviceManagementScripts.Read.All,
    DeviceManagementServiceConfig.Read.All.

.AUTHOR
    Jordan

.VERSION
    3.0.0

.CHANGELOG
    3.0.0 (2026-10-07) — adds App Configuration (managed devices + managed apps), App
    Protection, Remediations, macOS scripts, enrollment configurations (ESP / WHfB /
    restrictions / limits, priority-resolved), Autopilot profiles + device record,
    Settings Catalog compliance, actions for noncompliance, custom compliance scripts and
    hotpatch quality update policies. Apps become one entry per app with Required /
    Available / Uninstall side by side and Intune's documented intent-conflict resolution
    per device, plus supersedence / dependencies and device-reported install state.
    Applicability now honours Intune's filter-mode precedence (Exclude > no filter >
    Include) and records a per-assignment hit for every device. Device-reported status
    is added for compliance policies and remediations. The report (template schema 3)
    gains an Apps tab, faceted multi-select filters with live counts, field-qualified
    search, removable filter pills, Settings group-by and shareable view state.
    2.6.0 (2026-07-12) — redesigns the rich report around a clearer diagnostic shell,
    compact grouped filters, responsive setting cards, reduced keyboard tab stops,
    and an accessible modal detail drawer.
    2.5.3 (2026-07-12) — correctly renders ADMX multi-text string collections while
    preserving structured name/value presentation lists.
    2.5.2 (2026-07-12) — isolates cache options, prevents decrypted OMA-URI values
    from being cached, honours explicit Graph context selectors, and fixes paging limits.

.LASTUPDATE
    2026-10-07

.NOTES
    Version 3.0.0 (2026-10-07)
    Run with NO parameters for a guided interactive menu.
    Read-only: performs GET/report POST calls only; never modifies tenant data.
    Encrypted custom OMA-URI values are decrypted into the report - treat the export as sensitive.
    Keep report-template.html next to this script for the full-featured HTML report.
#>
#Requires -Version 7.0
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'BySerial', Mandatory = $true, Position = 0)]
    [string[]]$SerialNumber,

    [Parameter(ParameterSetName = 'ByDeviceName', Mandatory = $true)]
    [string[]]$DeviceName,

    [Parameter(ParameterSetName = 'ByGroup', Mandatory = $true)]
    [string]$Group,

    [Parameter(ParameterSetName = 'ByGroup')]
    [switch]$GroupAssignedOnly,

    [Parameter(ParameterSetName = 'ByFilter', Mandatory = $true)]
    [string]$AssignmentFilter,

    # Tenant-wide inventory: every policy + every setting + assignment summary (no device math)
    [Parameter(ParameterSetName = 'All', Mandatory = $true)]
    [switch]$All,

    # -All scoping (additive): narrow the inventory to a group and/or an assignment filter
    [Parameter(ParameterSetName = 'All')]
    [string]$ScopeGroup,

    [Parameter(ParameterSetName = 'All')]
    [string]$ScopeFilter,

    [switch]$SkipUpdates,   # skip feature/quality/driver update profiles
    [switch]$SkipScripts,   # skip platform scripts
    [switch]$SkipApps,      # skip applications (Required / Available / Uninstall per app)
    [switch]$SkipAppPolicies, # skip App Configuration + App Protection policies
    [switch]$SkipEnrollment,  # skip enrollment configurations + Autopilot profiles

    [string]$ExportHtml,
    [string]$ExportCsv,
    [string]$ExportJson,
    [switch]$NoHtml,

    [switch]$SkipCompliance,
    [switch]$SkipReportedStatus,

    [int]$MaxDevices = 25,
    [int]$CacheMinutes = 60,
    [switch]$Refresh,
    [switch]$PassThru,

    [string]$TenantId,
    [string]$ClientId,
    [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
    [string]$Environment = 'Global',
    [switch]$UseDeviceCode
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$script:Version = '3.0.0'
$script:TemplateSchema = 3
$script:StartTime = Get-Date
$script:ContainsDecryptedSecrets = $false

#region ---------- console helpers ----------------------------------------------------------

function Write-Step  { param([string]$Text) Write-Host ("==> " + $Text) -ForegroundColor Cyan }
function Write-Info  { param([string]$Text) Write-Host ("    " + $Text) -ForegroundColor DarkGray }
function Write-Good  { param([string]$Text) Write-Host ("    " + $Text) -ForegroundColor Green }
function Write-Warn2 { param([string]$Text) Write-Host ("    ! " + $Text) -ForegroundColor Yellow }

# Run log: every notable event (esp. Graph call failures) is collected here and embedded
# in the HTML report's Warnings panel, so problems are visible without scrollback.
$script:RunLog = New-Object System.Collections.Generic.List[object]

function Add-RunLog {
    param([ValidateSet('info', 'warn', 'error')][string]$Level, [string]$Message)
    [void]$script:RunLog.Add([pscustomobject]@{
        Time    = (Get-Date).ToString('HH:mm:ss')
        Level   = $Level
        Message = $Message
    })
    if ($Level -ne 'info') { Write-Warn2 $Message }
}

#endregion

#region ---------- graph plumbing -----------------------------------------------------------

$script:RequiredScopes = @(
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'Directory.Read.All'
)
if (-not $SkipApps -or -not $SkipAppPolicies) { $script:RequiredScopes += 'DeviceManagementApps.Read.All' }
# Platform scripts / remediations live behind their own permission; a token holding only
# DeviceManagementConfiguration.Read.All gets 403 from the script endpoints.
if (-not $SkipScripts) { $script:RequiredScopes += 'DeviceManagementScripts.Read.All' }
# Enrollment configurations, Autopilot profiles and Autopilot device records.
if (-not $SkipEnrollment) { $script:RequiredScopes += 'DeviceManagementServiceConfig.Read.All' }

function Connect-RsopGraph {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Module 'Microsoft.Graph.Authentication' is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null

    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }

    $needConnect = $true
    if ($ctx -and $ctx.Scopes) {
        $missing = @($script:RequiredScopes | Where-Object { $ctx.Scopes -notcontains $_ })
        $contextMatches =
            (-not $TenantId -or [string]$ctx.TenantId -ieq $TenantId) -and
            (-not $ClientId -or [string]$ctx.ClientId -ieq $ClientId) -and
            ([string]$ctx.Environment -ieq $Environment)
        if ($missing.Count -eq 0 -and $contextMatches) {
            $needConnect = $false
            Write-Info ("Reusing existing Graph session: {0} ({1})" -f $ctx.Account, $ctx.TenantId)
        }
        elseif (-not $contextMatches) {
            Write-Info 'Existing Graph session does not match the requested tenant, client, or environment; reconnecting.'
        }
    }

    if ($needConnect) {
        Write-Step "Signing in to Microsoft Graph (read-only scopes)"
        $cp = @{ Scopes = $script:RequiredScopes; Environment = $Environment; NoWelcome = $true; ContextScope = 'Process' }
        if ($TenantId)      { $cp['TenantId'] = $TenantId }
        if ($ClientId)      { $cp['ClientId'] = $ClientId }
        if ($UseDeviceCode) { $cp['UseDeviceCode'] = $true }
        Connect-MgGraph @cp
        $ctx = Get-MgContext
    }
    return $ctx
}

function Invoke-Rsop {
    # Thin wrapper: one retry on transient failures (SDK already honors 429 Retry-After).
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory = $true)][string]$Uri,
        [object]$Body
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            if ($null -ne $Body) {
                $json = $Body | ConvertTo-Json -Depth 12
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $json -ContentType 'application/json' -OutputType HashTable
            }
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType HashTable
        }
        catch {
            if ($attempt -ge 2) { throw }
            Start-Sleep -Seconds 3
        }
    }
}

function Invoke-RsopStream {
    # POST for report-style endpoints that answer with a Stream (octet-stream +
    # Content-Disposition): the SDK refuses to hand those back inline regardless of
    # -OutputType and demands -OutputFilePath, so land the body in a temp file and
    # parse from there. Works just as well when the tenant answers with plain JSON.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][object]$Body
    )
    $json = $Body | ConvertTo-Json -Depth 12
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('IntuneLens-' + [guid]::NewGuid().ToString('n') + '.json')
    try {
        Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $json -ContentType 'application/json' -OutputFilePath $tmp | Out-Null
        if (-not (Test-Path -LiteralPath $tmp)) { return $null }
        $raw = [System.IO.File]::ReadAllText($tmp)
        if (-not $raw) { return $null }
        # ConvertFrom-ReportGrid also copes with raw strings (JSON-in-string / base64)
        try { return $raw | ConvertFrom-Json -AsHashtable } catch { return $raw }
    }
    finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}

function Get-RsopPaged {
    # Follows @odata.nextLink; returns a flat array of items.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$Activity
    )
    $items = New-Object System.Collections.Generic.List[object]
    $next = $Uri
    $page = 0
    while ($next) {
        $page++
        if ($Activity) {
            Write-Progress -Id 7 -Activity $Activity -Status ("page {0} ({1} items so far)" -f $page, $items.Count)
        }
        $resp = Invoke-Rsop -Uri $next
        if ($resp -and $resp.ContainsKey('value')) {
            foreach ($i in @($resp['value'])) { [void]$items.Add($i) }
        }
        $next = $null
        if ($resp -and $resp.ContainsKey('@odata.nextLink')) { $next = $resp['@odata.nextLink'] }
    }
    if ($Activity) { Write-Progress -Id 7 -Activity $Activity -Completed }
    return $items.ToArray()
}

function Get-Prop {
    # Case-insensitive property/key lookup that works on hashtables and PSObjects.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        foreach ($k in $Object.Keys) {
            # unary comma: stop the pipeline from unrolling single-element arrays
            # (a one-row report grid would otherwise lose its shape)
            if ([string]$k -ieq $Name) { return , $Object[$k] }
        }
        return $null
    }
    $p = $Object.PSObject.Properties | Where-Object { $_.Name -ieq $Name } | Select-Object -First 1
    if ($p) { return , $p.Value }
    return $null
}

function Get-PropList {
    # Enumerate collection items on the pipeline. Callers needing a stable array use
    # @(Get-PropList ...); Get-Prop itself preserves arrays and report-grid row shape.
    param($Object, [string]$Name)
    $v = Get-Prop $Object $Name
    if ($null -eq $v) { return }
    return @($v)
}

function Format-GraphDate {
    # The SDK converts ISO JSON dates to DateTime. Preserve an unambiguous ISO value
    # before formatting or sorting; [string]DateTime otherwise depends on culture.
    param($Value)
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { return $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture) }
    return [string]$Value
}

function Add-RsopQuery {
    # Appends an OData query option to a URI that may or may not already carry one.
    param([string]$Uri, [string]$Query)
    if ($Uri.Contains('?')) { return "$Uri&$Query" }
    return "$Uri`?$Query"
}

function Invoke-RsopBatch {
    # GETs many relative URLs ('/deviceAppManagement/mobileApps/{id}/assignments') through
    # /$batch, 20 per request. Returns @{ url = response body (hashtable) or $null }.
    # Collection bodies that page (@odata.nextLink) are completed with Get-RsopPaged; a
    # throttled or failed sub-request is retried once on its own; if the batch endpoint
    # itself fails, every URL in that chunk is fetched individually.
    param([string[]]$Urls, [string]$Activity)
    $out = @{}
    $list = @($Urls | Where-Object { $_ } | Select-Object -Unique)
    for ($i = 0; $i -lt $list.Count; $i += 20) {
        $chunk = @($list[$i..([math]::Min($i + 19, $list.Count - 1))])
        if ($Activity) {
            Write-Progress -Id 8 -Activity $Activity -Status ("{0}/{1}" -f [math]::Min($i + 20, $list.Count), $list.Count) -PercentComplete ([int](100 * $i / [math]::Max(1, $list.Count)))
        }
        $retry = New-Object System.Collections.Generic.List[string]
        try {
            $reqs = @(for ($j = 0; $j -lt $chunk.Count; $j++) { @{ id = [string]$j; method = 'GET'; url = $chunk[$j] } })
            $resp = Invoke-Rsop -Method POST -Uri 'beta/$batch' -Body @{ requests = $reqs }
            foreach ($r in @($resp['responses'])) {
                $idx = [int]$r['id']
                $url = $chunk[$idx]
                $status = [int]$r['status']
                if ($status -ge 200 -and $status -lt 300) {
                    $body = $r['body']
                    if ($body -is [System.Collections.IDictionary] -and $body.ContainsKey('@odata.nextLink') -and $body['@odata.nextLink']) {
                        try {
                            $rest = Get-RsopPaged -Uri ([string]$body['@odata.nextLink'])
                            $body['value'] = @(@($body['value']) + @($rest))
                        } catch { }
                    }
                    $out[$url] = $body
                }
                elseif ($status -eq 429 -or $status -ge 500) { [void]$retry.Add($url) }
                else { $out[$url] = $null }
            }
        }
        catch {
            foreach ($u in $chunk) { [void]$retry.Add($u) }
        }
        foreach ($u in $retry) {
            try { $out[$u] = Invoke-Rsop -Uri ('beta' + $u) } catch { $out[$u] = $null }
        }
    }
    if ($Activity) { Write-Progress -Id 8 -Activity $Activity -Completed }
    return $out
}

function Get-RsopItemsWithAssignments {
    # LIST a collection together with each item's assignments. $expand on LIST calls is not
    # documented for most Intune collections, so: try the expand once; if the call is
    # rejected, list plainly; then fetch /{id}/<nav> in batches for every item that came back
    # without the navigation property. Extra navigations (e.g. 'apps') are completed the same way.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [string[]]$Navigations = @('assignments'),
        [string]$Activity
    )
    $items = $null
    try { $items = @(Get-RsopPaged -Uri (Add-RsopQuery $Uri ('$expand=' + ($Navigations -join ','))) -Activity $Activity) }
    catch { $items = $null }
    if ($null -eq $items) { $items = @(Get-RsopPaged -Uri $Uri -Activity $Activity) }   # throws to the caller

    $base = ($Uri -replace '^(beta|v1\.0)', '') -replace '\?.*$', ''
    foreach ($nav in $Navigations) {
        $missing = @($items | Where-Object { $_ -is [System.Collections.IDictionary] -and -not $_.ContainsKey($nav) -and $_['id'] })
        if ($missing.Count -eq 0) { continue }
        $urls = @($missing | ForEach-Object { '{0}/{1}/{2}' -f $base, $_['id'], $nav })
        $got = Invoke-RsopBatch -Urls $urls -Activity $(if ($Activity) { "$Activity ($nav)" } else { $null })
        foreach ($it in $missing) {
            $u = '{0}/{1}/{2}' -f $base, $it['id'], $nav
            $b = $got[$u]
            $it[$nav] = $(if ($b -is [System.Collections.IDictionary] -and $b.ContainsKey('value')) { @($b['value']) } else { @() })
        }
    }
    return , $items
}

function ConvertFrom-ReportGrid {
    # Normalizes Intune report responses ({Schema:[{Column}],Values:[[...]]}) and the
    # evaluateAssignmentFilter stream (raw JSON, JSON-in-string, or base64-in-'value')
    # into an array of PSCustomObjects.
    param($Response)

    if ($null -eq $Response) { return @() }

    if ($Response -is [string]) {
        $s = $Response.Trim()
        if ($s.StartsWith('{') -or $s.StartsWith('[')) {
            try { return ConvertFrom-ReportGrid -Response ($s | ConvertFrom-Json -AsHashtable) } catch { }
            try { return ConvertFrom-ReportGrid -Response ($s | ConvertFrom-Json) } catch { return @() }
        }
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))
            if ($decoded.TrimStart().StartsWith('{') -or $decoded.TrimStart().StartsWith('[')) {
                return ConvertFrom-ReportGrid -Response $decoded
            }
        } catch { }
        return @()
    }

    $schema = Get-Prop $Response 'Schema'
    $values = Get-Prop $Response 'Values'
    if ($schema -and $null -ne $values) {
        $cols = @()
        foreach ($c in @($schema)) {
            $cn = Get-Prop $c 'Column'
            if (-not $cn) { $cn = [string]$c }
            $cols += $cn
        }
        $rows = New-Object System.Collections.Generic.List[object]
        foreach ($v in @($values)) {
            $row = [ordered]@{}
            $arr = @($v)
            for ($i = 0; $i -lt $cols.Count -and $i -lt $arr.Count; $i++) { $row[$cols[$i]] = $arr[$i] }
            [void]$rows.Add([pscustomobject]$row)
        }
        return $rows.ToArray()
    }

    $val = Get-Prop $Response 'value'
    if ($null -ne $val) {
        if ($val -is [string]) { return ConvertFrom-ReportGrid -Response $val }
        $out = @()
        foreach ($item in @($val)) {
            if ($item -is [System.Collections.IDictionary]) { $out += [pscustomobject]$item } else { $out += $item }
        }
        return $out
    }

    return @()
}

#endregion

#region ---------- value rendering helpers --------------------------------------------------

function Format-SettingValue {
    param($Value)
    if ($null -eq $Value) { return '' }
    if ($Value -is [bool]) { if ($Value) { return 'True' } else { return 'False' } }
    if ($Value -is [System.Collections.IDictionary] -or ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string])) {
        try {
            $clean = Remove-JsonNoise -Value $Value
            $j = $clean | ConvertTo-Json -Depth 8 -Compress
            if ($j.Length -gt 2000) { $j = $j.Substring(0, 2000) + ' ...(truncated)' }
            return $j
        } catch { return [string]$Value }
    }
    $s = [string]$Value
    if ($s.Length -gt 2000) { $s = $s.Substring(0, 2000) + ' ...(truncated)' }
    return $s
}

function Remove-JsonNoise {
    # Strips null-valued keys and @odata.type annotations from nested objects so JSON
    # values in the report show only what is actually configured.
    param($Value, [int]$Depth = 0)
    if ($Depth -gt 6) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) {
            $ks = [string]$k
            if ($ks.StartsWith('@') -or $ks.Contains('@odata')) { continue }
            $v = $Value[$k]
            if ($null -eq $v) { continue }
            $o[$ks] = Remove-JsonNoise -Value $v -Depth ($Depth + 1)
        }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $arr = @()
        foreach ($e in $Value) { $arr += , (Remove-JsonNoise -Value $e -Depth ($Depth + 1)) }
        return , $arr
    }
    return $Value
}

function Format-IsoDuration {
    # 'P5D' -> 'P5D (5 days)', 'PT30M' -> 'PT30M (30 minutes)'. Non-durations pass through.
    param([string]$Text)
    if ($Text -notmatch '^P(?=\d|T\d)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$') { return $Text }
    $units = @('year', 'month', 'week', 'day', 'hour', 'minute', 'second')
    $parts = @()
    for ($i = 1; $i -le 7; $i++) {
        if ($Matches[$i]) {
            $n = [double]$Matches[$i]
            $parts += ("{0} {1}{2}" -f $Matches[$i], $units[$i - 1], $(if ($n -eq 1) { '' } else { 's' }))
        }
    }
    if ($parts.Count -eq 0) { return "$Text (immediately)" }
    return ("{0} ({1})" -f $Text, ($parts -join ' '))
}

function ConvertFrom-Base64Text {
    # Base64 -> UTF-8 text (BOM stripped). Returns $null when the input isn't base64.
    param([string]$Value)
    if (-not $Value) { return $null }
    try {
        $t = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
        return $t.TrimStart([char]0xFEFF).Trim()
    } catch { return $null }
}

function ConvertTo-FriendlyName {
    # 'defenderSecurityCenterDisableAppBrowserUI' -> 'Defender Security Center Disable App Browser UI'
    param([string]$Text)
    if (-not $Text) { return $Text }
    $t = $Text -creplace '([a-z0-9])([A-Z])', '$1 $2'
    $t = $t -replace '[_\.]+', ' '
    $t = $t.Trim()
    if ($t.Length -gt 0) { $t = $t.Substring(0, 1).ToUpper() + $t.Substring(1) }
    return $t
}

function Get-DefinitionTail {
    # Last meaningful chunk of a settings-catalog / intent definition id.
    param([string]$DefinitionId)
    if (-not $DefinitionId) { return $DefinitionId }
    $tail = ($DefinitionId -split '_')[-1]
    return ConvertTo-FriendlyName $tail
}

#endregion

#region ---------- settings catalog flattening ----------------------------------------------

$script:ReusableSettingNames = @{}

function Resolve-ReusableSettingName {
    param([string]$Id)
    if (-not $Id) { return $Id }
    if ($script:ReusableSettingNames.ContainsKey($Id)) { return $script:ReusableSettingNames[$Id] }
    $name = $Id
    try {
        $r = Invoke-Rsop -Uri ("beta/deviceManagement/reusablePolicySettings/{0}?`$select=id,displayName" -f $Id)
        if ($r -and $r['displayName']) { $name = ("{0} (reusable setting)" -f $r['displayName']) }
    } catch { }
    $script:ReusableSettingNames[$Id] = $name
    return $name
}

function Expand-CatalogInstance {
    # Recursively flattens a deviceManagementConfigurationSettingInstance tree into rows.
    param(
        $Instance,
        [hashtable]$Defs,
        [string]$Prefix,
        [System.Collections.Generic.List[object]]$Rows
    )
    if ($null -eq $Instance) { return }

    $odata = [string](Get-Prop $Instance '@odata.type')
    $defId = [string](Get-Prop $Instance 'settingDefinitionId')
    $def = $null
    if ($defId -and $Defs.ContainsKey($defId)) { $def = $Defs[$defId] }

    $name = $null
    if ($def) { $name = [string](Get-Prop $def 'displayName') }
    if (-not $name) { $name = Get-DefinitionTail $defId }
    $display = if ($Prefix) { "$Prefix > $name" } else { $name }

    # Microsoft reference for this setting, straight from the setting definition Graph already
    # expanded: a concise description (prefer 'description', fall back to 'helpText') and the
    # first infoUrls entry (usually a learn.microsoft.com deep link). Surfaced in the report's
    # detail inspector as "Microsoft Learn".
    $rowInfo = ''
    $rowInfoUrl = ''
    if ($def) {
        $desc = [string](Get-Prop $def 'description')
        if (-not $desc) { $desc = [string](Get-Prop $def 'helpText') }
        if ($desc) {
            $desc = ($desc -replace '\s+', ' ').Trim()
            if ($desc.Length -gt 400) { $desc = $desc.Substring(0, 397) + '...' }
            $rowInfo = $desc
        }
        foreach ($u in (Get-PropList $def 'infoUrls')) { if ($u) { $rowInfoUrl = [string]$u; break } }
    }

    switch -Wildcard ($odata) {

        '*choiceSettingInstance' {
            $cv = Get-Prop $Instance 'choiceSettingValue'
            $optId = [string](Get-Prop $cv 'value')
            $optName = $null
            if ($def) {
                $opts = Get-Prop $def 'options'
                foreach ($o in @($opts)) {
                    if ([string](Get-Prop $o 'itemId') -eq $optId) { $optName = [string](Get-Prop $o 'displayName'); break }
                }
            }
            if (-not $optName) { $optName = Get-DefinitionTail $optId }
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = $optName; Info = $rowInfo; InfoUrl = $rowInfoUrl })
            foreach ($child in (Get-PropList $cv 'children')) {
                Expand-CatalogInstance -Instance $child -Defs $Defs -Prefix $display -Rows $Rows
            }
        }

        '*choiceSettingCollectionInstance' {
            $vals = @(Get-PropList $Instance 'choiceSettingCollectionValue')
            $labels = @()
            foreach ($cv in $vals) {
                $optId = [string](Get-Prop $cv 'value')
                $optName = $null
                if ($def) {
                    $opts = Get-Prop $def 'options'
                    foreach ($o in @($opts)) {
                        if ([string](Get-Prop $o 'itemId') -eq $optId) { $optName = [string](Get-Prop $o 'displayName'); break }
                    }
                }
                if (-not $optName) { $optName = Get-DefinitionTail $optId }
                $labels += $optName
            }
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = ($labels -join '; '); Info = $rowInfo; InfoUrl = $rowInfoUrl })
            $idx = 0
            foreach ($cv in $vals) {
                foreach ($child in (Get-PropList $cv 'children')) {
                    Expand-CatalogInstance -Instance $child -Defs $Defs -Prefix ("{0} [{1}]" -f $display, $idx) -Rows $Rows
                }
                $idx++
            }
        }

        '*simpleSettingInstance' {
            $sv = Get-Prop $Instance 'simpleSettingValue'
            $svType = [string](Get-Prop $sv '@odata.type')
            $val = Get-Prop $sv 'value'
            if ($svType -like '*Secret*') { $val = '(secret - not shown)' }
            elseif ($svType -like '*Reference*') { $val = Resolve-ReusableSettingName ([string]$val) }
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = (Format-SettingValue $val); Info = $rowInfo; InfoUrl = $rowInfoUrl })
        }

        '*simpleSettingCollectionInstance' {
            $vals = @()
            foreach ($sv in (Get-PropList $Instance 'simpleSettingCollectionValue')) {
                $svType = [string](Get-Prop $sv '@odata.type')
                if ($svType -like '*Secret*') { $vals += '(secret)' } else { $vals += (Format-SettingValue (Get-Prop $sv 'value')) }
            }
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = ($vals -join '; '); Info = $rowInfo; InfoUrl = $rowInfoUrl })
        }

        '*groupSettingCollectionInstance' {
            $groups = @(Get-PropList $Instance 'groupSettingCollectionValue')
            $idx = 0
            foreach ($g in $groups) {
                $p = if ($groups.Count -gt 1) { "{0} [{1}]" -f $display, $idx } else { $display }
                foreach ($child in (Get-PropList $g 'children')) {
                    Expand-CatalogInstance -Instance $child -Defs $Defs -Prefix $p -Rows $Rows
                }
                $idx++
            }
            if ($groups.Count -eq 0) {
                [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = '(configured, empty)'; Info = $rowInfo; InfoUrl = $rowInfoUrl })
            }
        }

        '*groupSettingInstance' {
            $g = Get-Prop $Instance 'groupSettingValue'
            foreach ($child in (Get-PropList $g 'children')) {
                Expand-CatalogInstance -Instance $child -Defs $Defs -Prefix $display -Rows $Rows
            }
        }

        default {
            # Unknown instance type: record what we can.
            $val = Get-Prop $Instance 'value'
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = (Format-SettingValue $val); Info = $rowInfo; InfoUrl = $rowInfoUrl })
        }
    }
}

function Convert-CatalogSettings {
    # $SettingItems = items from configurationPolicies/{id}/settings?$expand=settingDefinitions
    param($SettingItems, [hashtable]$CategoryMap = @{})
    $defs = @{}
    foreach ($item in @($SettingItems)) {
        foreach ($d in (Get-PropList $item 'settingDefinitions')) {
            $did = [string](Get-Prop $d 'id')
            if ($did -and -not $defs.ContainsKey($did)) { $defs[$did] = $d }
        }
    }
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($item in @($SettingItems)) {
        $inst = Get-Prop $item 'settingInstance'
        $before = $rows.Count
        Expand-CatalogInstance -Instance $inst -Defs $defs -Prefix '' -Rows $rows
        # stamp the root setting's category (matches how the portal groups settings)
        $cat = ''
        $rootDefId = [string](Get-Prop $inst 'settingDefinitionId')
        if ($rootDefId -and $defs.ContainsKey($rootDefId)) {
            $catId = [string](Get-Prop $defs[$rootDefId] 'categoryId')
            if ($catId -and $CategoryMap.ContainsKey($catId)) { $cat = $CategoryMap[$catId] }
        }
        for ($ri = $before; $ri -lt $rows.Count; $ri++) {
            $rows[$ri] | Add-Member -NotePropertyName Category -NotePropertyValue $cat -Force
        }
    }
    return $rows.ToArray()
}

#endregion

#region ---------- legacy / admx / intent flattening ----------------------------------------

function Get-OmaPlainText {
    # Resolves an encrypted custom OMA-URI value to plaintext via the deviceConfiguration
    # getOmaSettingPlainTextValue function. Returns $null on any failure (permissions, missing
    # id, transient error) so the caller can fall back to a placeholder. NOTE: this writes the
    # decrypted secret into the report/CSV - the export must then be treated as sensitive.
    param([string]$ConfigId, [string]$SecretRefId)
    if (-not $ConfigId -or -not $SecretRefId) { return $null }
    if (-not $script:OmaPlainCache) { $script:OmaPlainCache = @{} }
    $ck = "$ConfigId|$SecretRefId"
    if ($script:OmaPlainCache.ContainsKey($ck)) { return $script:OmaPlainCache[$ck] }
    $result = $null
    try {
        $uri = "beta/deviceManagement/deviceConfigurations/{0}/getOmaSettingPlainTextValue(secretReferenceValueId='{1}')" -f $ConfigId, $SecretRefId
        $resp = Invoke-Rsop -Uri $uri
        if ($resp -and $resp.ContainsKey('value')) { $result = [string]$resp['value'] }
    }
    catch { $result = $null }
    $script:OmaPlainCache[$ck] = $result
    return $result
}

function Convert-LegacyProperties {
    # Flattens a deviceConfiguration / deviceCompliancePolicy object's non-null typed properties.
    # Rows get a Category derived from the item's @odata.type so legacy settings group and
    # match like everything else; $FallbackCategory covers collections whose items carry no
    # @odata.type (e.g. windows update profiles).
    param($Policy, [string]$FallbackCategory = '', [string[]]$Skip = @(), [string]$Category = '')
    $metaProps = @(
        'id', 'displayname', 'description', 'createddatetime', 'lastmodifieddatetime', 'version',
        'supportsscopetags', 'rolescopetagids', 'assignments',
        'devicemanagementapplicabilityruleosedition', 'devicemanagementapplicabilityruleosversion',
        'devicemanagementapplicabilityruledevicemode', 'scheduledactionsforrule',
        'devicestatuses', 'userstatuses', 'devicestatusoverview', 'userstatusoverview',
        'devicesettingstatesummaries', 'devicestatussummary', 'userstatussummary',
        'scriptcontent', 'filename', 'isassigned', 'deployedappcount', 'deploymentsummary', 'apps',
        'runsummary', 'devicerunstates', 'userrunstates', 'groupassignments'
    ) + @($Skip | ForEach-Object { ([string]$_).ToLower() })
    $rows = New-Object System.Collections.Generic.List[object]
    $cfgId = [string](Get-Prop $Policy 'id')   # needed to decrypt encrypted OMA-URI values
    $odataShort = ([string](Get-Prop $Policy '@odata.type')) -replace '#microsoft.graph.', ''
    $rowCategory = $FallbackCategory
    if ($odataShort) {
        $trimmed = $odataShort -replace '(Configuration|Policy|Profile)$', ''
        if ($trimmed) { $rowCategory = ConvertTo-FriendlyName $trimmed }
    }
    if ($Category) { $rowCategory = $Category }

    foreach ($key in @($Policy.Keys)) {
        $k = [string]$key
        if ($k.StartsWith('@') -or $k.Contains('@odata')) { continue }
        if ($metaProps -contains $k.ToLower()) { continue }
        $v = $Policy[$key]
        if ($null -eq $v) { continue }
        if ($v -is [string] -and $v -eq '') { continue }
        if (($v -is [System.Collections.IEnumerable]) -and ($v -isnot [string]) -and (@($v).Count -eq 0)) { continue }

        if ($k -ieq 'omaSettings') {
            foreach ($oma in @($v)) {
                $omaName = [string](Get-Prop $oma 'displayName')
                $omaUri = [string](Get-Prop $oma 'omaUri')
                $omaVal = Get-Prop $oma 'value'
                $omaType = [string](Get-Prop $oma '@odata.type')
                if ($omaType -like '*StringXml*' -or ($omaVal -is [string] -and $omaVal.Length -gt 400)) {
                    $omaVal = (Format-SettingValue $omaVal)
                }
                $enc = Get-Prop $oma 'isEncrypted'
                if ($enc) {
                    # encrypted OMA values come back null; fetch the plaintext via the
                    # getOmaSettingPlainTextValue function (writes the secret into the report)
                    $secretRef = [string](Get-Prop $oma 'secretReferenceValueId')
                    $plain = Get-OmaPlainText -ConfigId $cfgId -SecretRefId $secretRef
                    if ($null -ne $plain -and $plain -ne '') {
                        $omaVal = $plain
                        $script:ContainsDecryptedSecrets = $true
                    }
                    else { $omaVal = '(encrypted value - could not decrypt; view in portal)' }
                }
                [void]$rows.Add([pscustomobject]@{
                    Key      = "oma:$omaUri"
                    Setting  = "Custom OMA-URI: $omaName ($omaUri)"
                    Value    = (Format-SettingValue $omaVal)
                    Category = 'Custom OMA-URI'
                })
            }
            continue
        }

        $fv = Format-SettingValue $v
        if ($v -is [string]) { $fv = Format-IsoDuration $fv }
        [void]$rows.Add([pscustomobject]@{
            Key      = "legacy:$odataShort/$k"
            Setting  = (ConvertTo-FriendlyName $k)
            Value    = $fv
            Category = $rowCategory
        })
    }
    return $rows.ToArray()
}

function Get-AppIdentifierText {
    # managedMobileApp.mobileAppIdentifier -> bundle id / package id / Windows app id.
    param($ManagedApp)
    $ident = Get-Prop $ManagedApp 'mobileAppIdentifier'
    if ($null -eq $ident) { return '' }
    foreach ($k in @('bundleId', 'packageId', 'windowsAppId')) {
        $v = [string](Get-Prop $ident $k)
        if ($v) { return $v }
    }
    if ($ident -is [System.Collections.IDictionary]) {
        foreach ($k in $ident.Keys) { if (-not ([string]$k).StartsWith('@') -and $ident[$k] -is [string]) { return [string]$ident[$k] } }
    }
    return ''
}

function Get-AppIdentifierPlatform {
    param($ManagedApp)
    $t = [string](Get-Prop (Get-Prop $ManagedApp 'mobileAppIdentifier') '@odata.type')
    if ($t -match 'ios') { return 'ios' }
    if ($t -match 'android') { return 'android' }
    if ($t -match 'windows') { return 'windows' }
    return 'other'
}

function Convert-AppConfigDeviceSettings {
    # managedDeviceMobileAppConfiguration (iOS keys / plist XML, Android managed properties
    # + runtime permissions) -> setting rows. The key carries the targeted app ids so that two
    # app-config policies setting the same key for the same app surface as a conflict.
    param($Policy)
    $rows = New-Object System.Collections.Generic.List[object]
    $appKey = ((@(Get-PropList $Policy 'targetedMobileApps') | Sort-Object) -join ',')

    foreach ($it in (Get-PropList $Policy 'settings')) {
        $k = [string](Get-Prop $it 'appConfigKey')
        if (-not $k) { continue }
        $kt = ([string](Get-Prop $it 'appConfigKeyType')) -replace 'Type$', ''
        [void]$rows.Add([pscustomobject]@{
            Key = "appcfg:${appKey}:$k"; Setting = $k; Value = (Format-SettingValue (Get-Prop $it 'appConfigKeyValue'))
            Category = $(if ($kt) { "Configuration key ($kt)" } else { 'Configuration key' })
        })
    }
    $xml = [string](Get-Prop $Policy 'encodedSettingXml')
    if ($xml) {
        $dec = ConvertFrom-Base64Text $xml
        if (-not $dec) { $dec = $xml }
        if ($dec.Length -gt 6000) { $dec = $dec.Substring(0, 6000) + "`n...(truncated)" }
        [void]$rows.Add([pscustomobject]@{ Key = "appcfg:${appKey}:xml"; Setting = 'Configuration XML (plist)'; Value = $dec; Category = 'Configuration XML' })
    }
    $payload = [string](Get-Prop $Policy 'payloadJson')
    if ($payload) {
        $json = $null
        foreach ($cand in @((ConvertFrom-Base64Text $payload), $payload)) {
            if (-not $cand) { continue }
            try { $json = $cand | ConvertFrom-Json -AsHashtable -ErrorAction Stop; break } catch { }
        }
        $props = @()
        if ($json) { $props = @(Get-PropList $json 'managedProperty') }
        if ($props.Count -gt 0) {
            foreach ($mp in $props) {
                $k = [string](Get-Prop $mp 'key')
                $val = $null
                foreach ($vk in @('valueString', 'valueInteger', 'valueBool', 'valueStringArray', 'valueBundle', 'valueBundleArray')) {
                    $cv = Get-Prop $mp $vk
                    if ($null -ne $cv) { $val = $cv; break }
                }
                [void]$rows.Add([pscustomobject]@{ Key = "appcfg:${appKey}:$k"; Setting = $k; Value = (Format-SettingValue $val); Category = 'Managed configuration' })
            }
        }
        else {
            $raw = $(if ($json) { Format-SettingValue $json } else { $payload })
            [void]$rows.Add([pscustomobject]@{ Key = "appcfg:${appKey}:payload"; Setting = 'Configuration payload (JSON)'; Value = $raw; Category = 'Managed configuration' })
        }
    }
    foreach ($pa in (Get-PropList $Policy 'permissionActions')) {
        $perm = [string](Get-Prop $pa 'permission')
        if (-not $perm) { continue }
        [void]$rows.Add([pscustomobject]@{ Key = "appcfg:${appKey}:perm:$perm"; Setting = "Permission: $perm"; Value = [string](Get-Prop $pa 'action'); Category = 'Runtime permissions' })
    }
    foreach ($r in (Convert-LegacyProperties -Policy $Policy -Category 'Policy options' -Skip @('targetedMobileApps', 'settings', 'encodedSettingXml', 'payloadJson', 'permissionActions'))) {
        [void]$rows.Add($r)
    }
    return $rows.ToArray()
}

function Set-AppSettingConflictKeys {
    # Keep one displayed row per setting, but compare each explicitly targeted app.
    # Whole app-set keys miss overlaps such as {A,B} and {B,C}.
    param($Rows, [string[]]$Scopes, [string]$Prefix, [string]$PolicyId, [string]$CombinedScope)
    $scopes0 = @($Scopes | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $scopes0.Count) { $scopes0 = @("policy:$PolicyId") }
    $oldPrefix = "${Prefix}:${CombinedScope}:"
    foreach ($r in $Rows) {
        $key = [string]$r.Key
        if ($key.StartsWith($oldPrefix, [StringComparison]::OrdinalIgnoreCase)) { $key = $key.Substring($oldPrefix.Length) }
        elseif ($key.StartsWith("${Prefix}:", [StringComparison]::OrdinalIgnoreCase)) { $key = $key.Substring($Prefix.Length + 1) }
        # Target selection and management-level metadata are policy options, not
        # conflicting app settings. Their rows remain inspectable by policy.
        $keys = if ($r.Category -eq 'Policy options') { @("${Prefix}:policy:${PolicyId}:$key") } else { @($scopes0 | ForEach-Object { "${Prefix}:${_}:$key" }) }
        $r | Add-Member -NotePropertyName ConflictKeys -NotePropertyValue $keys -Force
    }
}

$script:ComplianceActionNames = @{
    block = 'Mark device noncompliant'; notification = 'Send email to end user'; pushNotification = 'Send push notification to end user'
    remoteLock = 'Remotely lock the noncompliant device'; retire = 'Add device to retire list'; wipe = 'Wipe device'
    removeResourceAccessProfiles = 'Remove resource access profiles'; noAction = 'No action'
}

function Convert-ComplianceActions {
    # scheduledActionsForRule[].scheduledActionConfigurations[] -> "Actions for noncompliance" rows.
    param($Rules, [string]$PolicyId)
    $rows = New-Object System.Collections.Generic.List[object]
    $n = 0
    foreach ($rule in @($Rules)) {
        foreach ($act in (Get-PropList $rule 'scheduledActionConfigurations')) {
            $n++
            $type = [string](Get-Prop $act 'actionType')
            $label = $script:ComplianceActionNames[$type]
            if (-not $label) { $label = ConvertTo-FriendlyName $type }
            $h = 0; [void][int]::TryParse([string](Get-Prop $act 'gracePeriodHours'), [ref]$h)
            $when = 'immediately'
            if ($h -gt 0) {
                if ($h % 24 -eq 0) { $when = ("after {0} day{1}" -f ($h / 24), $(if ($h / 24 -eq 1) { '' } else { 's' })) }
                else { $when = ("after {0} hours" -f $h) }
            }
            [void]$rows.Add([pscustomobject]@{
                Key = ("compliance:{0}:action:{1}" -f $PolicyId, $n); Setting = "Action for noncompliance: $label"; Value = $when; Category = 'Actions for noncompliance'
            })
        }
    }
    return $rows.ToArray()
}

function Format-Win32Rule {
    # One win32LobApp detection / requirement rule -> a readable line.
    param($Rule)
    $t = ([string](Get-Prop $Rule '@odata.type')) -replace '#microsoft.graph.win32LobApp', ''
    $op = [string](Get-Prop $Rule 'operationType'); $cmpOp = [string](Get-Prop $Rule 'operator'); $cv = [string](Get-Prop $Rule 'comparisonValue')
    $cmp = ''
    if ($cmpOp -and $cmpOp -ne 'notConfigured') { $cmp = (" {0} {1}" -f $cmpOp, $cv) }
    switch -Wildcard ($t) {
        'FileSystemRule' {
            $p = ('{0}\{1}' -f (Get-Prop $Rule 'path'), (Get-Prop $Rule 'fileOrFolderName')) -replace '\\\\', '\'
            return ("File: {0} - {1}{2}" -f $p, $op, $cmp)
        }
        'RegistryRule' {
            $vn = [string](Get-Prop $Rule 'valueName')
            return ("Registry: {0}{1} - {2}{3}" -f (Get-Prop $Rule 'keyPath'), $(if ($vn) { " [$vn]" } else { '' }), $op, $cmp)
        }
        'ProductCodeRule' {
            $pv = [string](Get-Prop $Rule 'productVersion'); $pvo = [string](Get-Prop $Rule 'productVersionOperator')
            return ("MSI product code {0}{1}" -f (Get-Prop $Rule 'productCode'), $(if ($pvo -and $pvo -ne 'notConfigured') { " - version $pvo $pv" } else { '' }))
        }
        'PowerShellScriptRule' {
            $body = ConvertFrom-Base64Text ([string](Get-Prop $Rule 'scriptContent'))
            if ($body -and $body.Length -gt 1500) { $body = $body.Substring(0, 1500) + "`n...(truncated)" }
            $nm = [string](Get-Prop $Rule 'displayName')
            return ("PowerShell script{0} (runs as {1}){2}`n{3}" -f $(if ($nm) { " '$nm'" } else { '' }), (Get-Prop $Rule 'runAsAccount'), $cmp, $body)
        }
        default { return (Format-SettingValue (Remove-JsonNoise -Value $Rule)) }
    }
}

function Get-AppInfoRows {
    # Install / detection / packaging facts worth seeing next to an app's assignments.
    # Returns @(@{ Label; Value }) - only populated fields.
    param($App)
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($l, $v) if ($null -ne $v -and "$v" -ne '') { [void]$rows.Add([pscustomobject]@{ Label = $l; Value = [string]$v }) } }

    & $add 'Publisher' (Get-Prop $App 'publisher')
    & $add 'Version' (Get-Prop $App 'displayVersion')
    foreach ($p in @(
            @('packageIdentifier', 'Package identifier'), @('mobileAppCatalogPackageId', 'Catalog package id'), @('bundleId', 'Bundle id'),
            @('packageId', 'Package id'), @('identityName', 'Package identity'), @('appStoreUrl', 'Store URL'), @('appUrl', 'App URL'),
            @('setupFilePath', 'Setup file'), @('installCommandLine', 'Install command'), @('uninstallCommandLine', 'Uninstall command'),
            @('commandLine', 'MSI command line'), @('productCode', 'MSI product code'), @('minimumSupportedWindowsRelease', 'Minimum Windows release'))) {
        & $add $p[1] (Get-Prop $App $p[0])
    }
    $ie = Get-Prop $App 'installExperience'
    if ($ie) {
        & $add 'Install context' (Get-Prop $ie 'runAsAccount')
        & $add 'Restart behaviour' (Get-Prop $ie 'deviceRestartBehavior')
        $mr = Get-Prop $ie 'maxRunTimeInMinutes'; if ($mr) { & $add 'Max install time' ("{0} minutes" -f $mr) }
    }
    $arch = [string](Get-Prop $App 'allowedArchitectures')
    if (-not $arch -or $arch -eq 'none') { $arch = [string](Get-Prop $App 'applicableArchitectures') }
    if ($arch -and $arch -ne 'none') { & $add 'Architectures' $arch }
    $aau = Get-Prop $App 'allowAvailableUninstall'; if ($aau -eq $true) { & $add 'Allow uninstall from Company Portal' 'Yes' }
    $msi = Get-Prop $App 'msiInformation'
    if ($msi -and (Get-Prop $msi 'productCode')) { & $add 'MSI product code' ("{0} (v{1})" -f (Get-Prop $msi 'productCode'), (Get-Prop $msi 'productVersion')) }

    $rules = @(Get-PropList $App 'rules')
    if ($rules.Count -gt 0) {
        $det = @($rules | Where-Object { [string](Get-Prop $_ 'ruleType') -ne 'requirement' } | ForEach-Object { Format-Win32Rule $_ })
        $req = @($rules | Where-Object { [string](Get-Prop $_ 'ruleType') -eq 'requirement' } | ForEach-Object { Format-Win32Rule $_ })
    }
    else {
        # legacy collections on older Win32 apps
        $det = @(Get-PropList $App 'detectionRules' | ForEach-Object { Format-Win32Rule $_ })
        $req = @(Get-PropList $App 'requirementRules' | ForEach-Object { Format-Win32Rule $_ })
    }
    if ($det.Count) { & $add 'Detection rules' ($det -join "`n") }
    if ($req.Count) { & $add 'Requirement rules' ($req -join "`n") }
    $rc = @(Get-PropList $App 'returnCodes' | ForEach-Object { "{0} = {1}" -f (Get-Prop $_ 'returnCode'), (Get-Prop $_ 'type') })
    if ($rc.Count) { & $add 'Return codes' ($rc -join ', ') }

    # Microsoft 365 Apps: apps deselected from the suite are actively REMOVED from devices
    $excluded = Get-Prop $App 'excludedApps'
    if ($excluded) {
        $exNames = @()
        if ($excluded -is [System.Collections.IDictionary]) { foreach ($k in $excluded.Keys) { if ($excluded[$k] -eq $true) { $exNames += [string]$k } } }
        else { foreach ($pp in $excluded.PSObject.Properties) { if ($pp.Value -eq $true) { $exNames += $pp.Name } } }
        if ($exNames.Count -gt 0) { & $add 'Excluded Microsoft 365 apps (uninstalled if present)' (($exNames | Sort-Object) -join ', ') }
    }
    $pids = @(Get-PropList $App 'productIds'); if ($pids.Count) { & $add 'Products' ($pids -join ', ') }
    & $add 'Update channel' (Get-Prop $App 'updateChannel')
    $opa = [string](Get-Prop $App 'officePlatformArchitecture'); if ($opa -and $opa -ne 'none') { & $add 'Office architecture' $opa }
    if ((Get-Prop $App 'useSharedComputerActivation') -eq $true) { & $add 'Shared computer activation' 'Yes' }
    if ((Get-Prop $App 'shouldUninstallOlderVersionsOfOffice') -eq $true) { & $add 'Remove older Office versions (MSI)' 'Yes' }
    & $add 'Target Office version' (Get-Prop $App 'targetVersion')
    return $rows.ToArray()
}

function Format-AssignmentOptions {
    # Per-assignment delivery options (app notifications / deadline / restart grace,
    # remediation run schedule, policy-set origin) -> one readable line.
    param($Assignment)
    $parts = @()
    $s = Get-Prop $Assignment 'settings'
    if ($s) {
        $n = [string](Get-Prop $s 'notifications')
        if ($n) {
            $nl = @{ showAll = 'show all'; showReboot = 'restart only'; hideAll = 'hide all' }[$n]
            if (-not $nl) { $nl = $n }
            $parts += "notifications: $nl"
        }
        $its = Get-Prop $s 'installTimeSettings'
        if ($its) {
            $tz = $(if ((Get-Prop $its 'useLocalTime') -eq $true) { 'device time' } else { 'UTC' })
            $st = [string](Get-Prop $its 'startDateTime'); $dl = [string](Get-Prop $its 'deadlineDateTime')
            if ($st) { $parts += ("available from {0} ({1})" -f ($st -replace 'T', ' ' -replace ':\d\d(\.\d+)?Z?$', ''), $tz) }
            if ($dl) { $parts += ("deadline {0} ({1})" -f ($dl -replace 'T', ' ' -replace ':\d\d(\.\d+)?Z?$', ''), $tz) }
        }
        $rs = Get-Prop $s 'restartSettings'
        if ($rs -and (Get-Prop $rs 'gracePeriodInMinutes')) { $parts += ("restart grace {0} min" -f (Get-Prop $rs 'gracePeriodInMinutes')) }
        if ([string](Get-Prop $s 'deliveryOptimizationPriority') -eq 'foreground') { $parts += 'delivery optimization: foreground' }
        $au = Get-Prop $s 'autoUpdateSettings'
        if ($au) {
            $aus = [string](Get-Prop $au 'autoUpdateSupersededAppsState'); if (-not $aus) { $aus = [string](Get-Prop $au 'autoUpdateSupersededApps') }
            if ($aus -eq 'enabled') { $parts += 'auto-update superseded versions' }
        }
        if ((Get-Prop $s 'useDeviceContext') -eq $true) { $parts += 'device context' }
        if ((Get-Prop $s 'useDeviceLicensing') -eq $true) { $parts += 'device licensing' }
        if ((Get-Prop $s 'uninstallOnDeviceRemoval') -eq $false) { $parts += 'kept on device removal' }
        if ((Get-Prop $s 'isRemovable') -eq $false) { $parts += 'user cannot remove' }
        if ((Get-Prop $s 'preventAutoAppUpdate') -eq $true) { $parts += 'auto-update blocked' }
        if (Get-Prop $s 'vpnConfigurationId') { $parts += 'per-app VPN' }
        $aum = [string](Get-Prop $s 'autoUpdateMode'); if ($aum -and $aum -ne 'default') { $parts += "update mode: $aum" }
    }
    $sch = Get-Prop $Assignment 'runSchedule'
    if ($sch) {
        $st = ([string](Get-Prop $sch '@odata.type')) -replace '#microsoft.graph.deviceHealthScript', '' -replace 'Schedule$', ''
        $iv = [int](Get-Prop $sch 'interval'); $tm = [string](Get-Prop $sch 'time'); $dt = [string](Get-Prop $sch 'date')
        $utc = $(if ((Get-Prop $sch 'useUtc') -eq $true) { ' UTC' } else { '' })
        if ($tm) { $tm = $tm -replace '(\d\d:\d\d):\d\d(\.\d+)?', '$1' }
        switch ($st) {
            'Hourly'  { $parts += ("runs every {0} hour{1}" -f $iv, $(if ($iv -eq 1) { '' } else { 's' })) }
            'Daily'   { $parts += ("runs every {0} day{1}{2}" -f $iv, $(if ($iv -eq 1) { '' } else { 's' }), $(if ($tm) { " at $tm$utc" } else { '' })) }
            'RunOnce' { $parts += ("runs once {0} {1}{2}" -f $dt, $tm, $utc).Trim() }
            default   { if ($iv) { $parts += ("runs every {0}" -f $iv) } }
        }
    }
    if ((Get-Prop $Assignment 'runRemediationScript') -eq $false) { $parts += 'detection only' }
    if ([string](Get-Prop $Assignment 'source') -eq 'policySets') { $parts += 'via policy set' }
    return ($parts -join '; ')
}

function Convert-AdmxValues {
    # $DefinitionValues = items from groupPolicyConfigurations/{id}/definitionValues?$expand=...
    param($DefinitionValues)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($dv in @($DefinitionValues)) {
        $def = Get-Prop $dv 'definition'
        $defId = [string](Get-Prop $def 'id')
        $defName = [string](Get-Prop $def 'displayName')
        if (-not $defName) { $defName = '(unknown ADMX setting)' }
        $classType = [string](Get-Prop $def 'classType')
        $scope = if ($classType -ieq 'user') { ' (User)' } else { ' (Computer)' }
        $enabled = Get-Prop $dv 'enabled'
        $state = if ($enabled) { 'Enabled' } else { 'Disabled' }
        $cat = ''
        $catPath = [string](Get-Prop $def 'categoryPath')
        if ($catPath) { $cat = @($catPath -split '\\' | Where-Object { $_ })[-1] }

        [void]$rows.Add([pscustomobject]@{
            Key      = "admx:$defId"
            Setting  = "$defName$scope"
            Value    = $state
            Category = $cat
        })

        if ($enabled) {
            foreach ($pv in (Get-PropList $dv 'presentationValues')) {
                $pres = Get-Prop $pv 'presentation'
                $label = [string](Get-Prop $pres 'label')
                if (-not $label) { $label = 'Value' }
                $pvId = [string](Get-Prop $pv 'id')
                $val = $null
                $vv = Get-Prop $pv 'value'
                $vvs = @(Get-PropList $pv 'values')
                if ($null -ne $vv) { $val = Format-SettingValue $vv }
                elseif ($vvs.Count -gt 0) {
                    $parts = @()
                    foreach ($e in $vvs) {
                        if ($null -eq $e) { continue }
                        # Multi-text presentations return a String collection; list-style
                        # presentations return objects with name/value fields.
                        if ($e -is [string] -or $e -is [System.ValueType]) {
                            $parts += (Format-SettingValue $e)
                            continue
                        }
                        $en = Get-Prop $e 'name'
                        $ev = Get-Prop $e 'value'
                        if ($null -ne $en -and "$en" -ne '') {
                            $parts += ("{0}={1}" -f $en, (Format-SettingValue $ev))
                        }
                        elseif ($null -ne $ev) {
                            $parts += (Format-SettingValue $ev)
                        }
                    }
                    $val = $parts -join '; '
                }
                if ($null -ne $val -and "$val" -ne '') {
                    [void]$rows.Add([pscustomobject]@{
                        Key      = "admx:$defId#$pvId"
                        Setting  = "$defName$scope :: $label"
                        Value    = $val
                        Category = $cat
                    })
                }
            }
        }
    }
    return $rows.ToArray()
}

function Convert-IntentSettings {
    # $Settings = items from intents/{id}/settings; $DefMap: definitionId -> @{Name;Category}
    # (built from templates/{id}/categories?$expand=settingDefinitions)
    param($Settings, [hashtable]$DefMap = @{})
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($s in @($Settings)) {
        $defId = [string](Get-Prop $s 'definitionId')
        $val = Get-Prop $s 'value'
        if ($null -eq $val) { $val = Get-Prop $s 'valueJson' }
        if ($null -eq $val) { continue }
        if ($val -is [string]) {
            $trim = $val.Trim('"')
            if ($trim -eq 'null' -or $trim -eq '') { continue }
            $val = $trim
        }
        $name = Get-DefinitionTail $defId
        $cat = ''
        if ($defId -and $DefMap.ContainsKey($defId)) {
            $m = $DefMap[$defId]
            if ($m.Name) { $name = $m.Name }
            if ($m.Category) { $cat = $m.Category }
        }
        [void]$rows.Add([pscustomobject]@{
            Key      = "intent:$defId"
            Setting  = $name
            Value    = (Format-SettingValue $val)
            Category = $cat
        })
    }
    return $rows.ToArray()
}

#endregion

#region ---------- policy corpus (all families) + cache -------------------------------------

function Get-PolicyPlatformTag {
    # Coarse platform tag so we don't show iOS profiles against Windows devices.
    param([string]$Family, $Raw)
    switch ($Family) {
        'admx'   { return 'windows' }
        'intent' { return 'windows' }
        'catalog' {
            $p = [string](Get-Prop $Raw 'platforms')
            if ($p -match 'windows') { return 'windows' }
            if ($p -match 'macOS') { return 'macos' }
            if ($p -match 'iOS|visionOS|tvOS') { return 'ios' }
            if ($p -match 'android|aosp') { return 'android' }
            if ($p -match 'linux') { return 'linux' }
            return 'other'
        }
        default {
            $t = ([string](Get-Prop $Raw '@odata.type')).ToLower()
            if ($t -match 'ios|iphone|ipad') { return 'ios' }
            if ($t -match 'macos') { return 'macos' }
            if ($t -match 'android|aosp') { return 'android' }
            if ($t -match 'windows|editionupgrade|sharedpc|domainjoin') { return 'windows' }
            return 'other'
        }
    }
}

function ConvertTo-CompactAssignments {
    param($Assignments)
    $out = @()
    foreach ($a in @($Assignments)) {
        $t = Get-Prop $a 'target'
        if ($null -eq $t) {
            # legacy script groupAssignments: { targetGroupId } only
            $tg = [string](Get-Prop $a 'targetGroupId')
            if ($tg) { $out += [pscustomobject]@{ Type = 'groupAssignmentTarget'; GroupId = $tg; FilterId = ''; FilterType = ''; Intent = ''; Options = '' } }
            continue
        }
        $gid = [string](Get-Prop $t 'groupId')
        if (-not $gid) { $gid = [string](Get-Prop $t 'entraObjectId') }   # scopeTagGroupAssignmentTarget
        $out += [pscustomobject]@{
            Type       = ([string](Get-Prop $t '@odata.type')) -replace '#microsoft.graph.', ''
            GroupId    = $gid
            FilterId   = [string](Get-Prop $t 'deviceAndAppManagementAssignmentFilterId')
            FilterType = [string](Get-Prop $t 'deviceAndAppManagementAssignmentFilterType')
            Intent     = [string](Get-Prop $a 'intent')
            Options    = (Format-AssignmentOptions -Assignment $a)
        }
    }
    return $out
}

function Get-FamilyLabel {
    param([string]$Family, $Raw, [hashtable]$TemplateMap)
    switch ($Family) {
        'catalog' {
            $tr = Get-Prop $Raw 'templateReference'
            $tf = [string](Get-Prop $tr 'templateFamily')
            $tn = [string](Get-Prop $tr 'templateDisplayName')
            if ($tf -and $tf -ne 'none') {
                $nice = switch -Wildcard ($tf) {
                    'baseline'                          { 'Security Baseline' }
                    'endpointSecurityAntivirus'         { 'Endpoint Security - Antivirus' }
                    'endpointSecurityAttackSurfaceReduction*' { 'Endpoint Security - ASR' }
                    'endpointSecurityDiskEncryption'    { 'Endpoint Security - Disk Encryption' }
                    'endpointSecurityFirewall'          { 'Endpoint Security - Firewall' }
                    'endpointSecurityEndpointDetectionAndResponse' { 'Endpoint Security - EDR' }
                    'endpointSecurityAccountProtection' { 'Endpoint Security - Account Protection' }
                    'endpointSecurityApplicationControl' { 'Endpoint Security - App Control' }
                    'endpointSecurityEndpointPrivilegeManagement' { 'Endpoint Security - Privilege Management (EPM)' }
                    'enrollmentConfiguration'           { 'Autopilot device preparation' }
                    'appQuietTime'                      { 'App quiet time' }
                    'deviceConfigurationScripts'        { 'Settings Catalog (script template)' }
                    'deviceConfigurationPolicies'       { 'Settings Catalog (template)' }
                    'windowsOsRecoveryPolicies'         { 'Windows OS recovery' }
                    'companyPortal'                     { 'Company Portal settings' }
                    default { "Settings Catalog ($tf)" }
                }
                if ($tn) { return "$nice" } else { return $nice }
            }
            return 'Settings Catalog'
        }
        'legacy' {
            $t = ([string](Get-Prop $Raw '@odata.type')) -replace '#microsoft.graph.', ''
            if ($t -ieq 'windows10CustomConfiguration') { return 'Template - Custom OMA-URI' }
            return "Template - $(ConvertTo-FriendlyName $t)"
        }
        'admx' { return 'Administrative Templates (ADMX)' }
        'intent' {
            $tid = [string](Get-Prop $Raw 'templateId')
            if ($tid -and $TemplateMap.ContainsKey($tid)) { return "$($TemplateMap[$tid]) (legacy intent)" }
            return 'Endpoint Security / Baseline (legacy intent)'
        }
        'compliance' { return 'Compliance Policy' }
    }
    return $Family
}

function Get-PolicyCorpus {
    param([string]$TenantKey)

    $cacheFile = Join-Path $HOME (".intune-rsop-cache-{0}.json" -f ($TenantKey -replace '[^a-zA-Z0-9\-]', ''))
    $cacheOptions = [pscustomobject]@{
        IncludeCompliance  = [bool](-not $SkipCompliance)
        IncludeUpdates     = [bool](-not $SkipUpdates)
        IncludeScripts     = [bool](-not $SkipScripts)
        IncludeApps        = [bool](-not $SkipApps)
        IncludeAppPolicies = [bool](-not $SkipAppPolicies)
        IncludeEnrollment  = [bool](-not $SkipEnrollment)
    }
    # Version 5 and earlier may contain decrypted custom OMA-URI values. Remove those
    # files on every run, even when cache reads are disabled with -Refresh/-CacheMinutes 0.
    if (Test-Path $cacheFile) {
        try {
            $cacheHeader = Get-Content -Raw -Path $cacheFile | ConvertFrom-Json
            $cacheHeaderVersion = 0; try { $cacheHeaderVersion = [int]$cacheHeader.cacheVersion } catch { }
            if ($cacheHeaderVersion -lt 6) {
                Remove-Item -LiteralPath $cacheFile -Force -ErrorAction Stop
                Write-Warn2 'Removed a legacy policy cache that may contain decrypted OMA-URI values.'
            }
        }
        catch {
            Remove-Item -LiteralPath $cacheFile -Force -ErrorAction SilentlyContinue
            Write-Warn2 'Removed an unreadable legacy policy cache.'
        }
    }
    if (-not $Refresh -and $CacheMinutes -gt 0 -and (Test-Path $cacheFile)) {
        try {
            $cached = Get-Content -Raw -Path $cacheFile | ConvertFrom-Json
            $age = (Get-Date) - [datetime]$cached.generated
            $ver = 0; try { $ver = [int]$cached.cacheVersion } catch { }
            $optionsMatch = $ver -eq 9 -and $null -ne $cached.cacheOptions -and
                [bool]$cached.cacheOptions.IncludeCompliance -eq $cacheOptions.IncludeCompliance -and
                [bool]$cached.cacheOptions.IncludeUpdates -eq $cacheOptions.IncludeUpdates -and
                [bool]$cached.cacheOptions.IncludeScripts -eq $cacheOptions.IncludeScripts -and
                [bool]$cached.cacheOptions.IncludeApps -eq $cacheOptions.IncludeApps -and
                [bool]$cached.cacheOptions.IncludeAppPolicies -eq $cacheOptions.IncludeAppPolicies -and
                [bool]$cached.cacheOptions.IncludeEnrollment -eq $cacheOptions.IncludeEnrollment
            if ($optionsMatch -and $age.TotalMinutes -lt $CacheMinutes) {
                Write-Step ("Using cached policy data from {0:HH:mm:ss} ({1:n0} min old; -Refresh to re-pull)" -f [datetime]$cached.generated, $age.TotalMinutes)
                return $cached
            }
            if ($ver -lt 6) {
                Remove-Item -LiteralPath $cacheFile -Force -ErrorAction SilentlyContinue
                Write-Warn2 'Removed a legacy policy cache that may contain decrypted OMA-URI values.'
            }
        } catch { Write-Warn2 "Cache unreadable; re-pulling." }
    }

    $policies = New-Object System.Collections.Generic.List[object]
    $appObjs = New-Object System.Collections.Generic.List[object]
    $warnings = New-Object System.Collections.Generic.List[string]
    # app id -> display name, and bundle / package id -> app id (lets app-config and
    # app-protection policies name the apps they target)
    $appNameById = @{}
    $appIdByIdentifier = @{}

    # -- templates map for legacy intents ------------------------------------------------
    $templateMap = @{}
    try {
        foreach ($t in (Get-RsopPaged -Uri 'beta/deviceManagement/templates?$select=id,displayName')) {
            $templateMap[[string]$t['id']] = [string]$t['displayName']
        }
    } catch { }

    # -- settings catalog category names (groups the report like the portal does) --------
    Write-Step "Pulling setting category names"
    $catMap = @{}
    try {
        foreach ($c in (Get-RsopPaged -Uri 'beta/deviceManagement/configurationCategories?$select=id,displayName' -Activity 'configurationCategories')) {
            $catMap[[string]$c['id']] = [string]$c['displayName']
        }
        Write-Info ("{0} categories" -f $catMap.Count)
    } catch { [void]$warnings.Add("Could not list setting categories: $($_.Exception.Message)") }

    function Get-PolicyMeta {
        param($Raw)
        $mod = Format-GraphDate (Get-Prop $Raw 'lastModifiedDateTime')
        if ($mod.Length -ge 10) { $mod = $mod.Substring(0, 10) }
        return @{
            Desc     = [string](Get-Prop $Raw 'description')
            Modified = $mod
            Created  = Format-GraphDate (Get-Prop $Raw 'createdDateTime')
        }
    }

    function Add-CorpusPolicy {
        # Single constructor for corpus policy entries so every family carries the same shape.
        param([string]$Id, [string]$Name, [string]$Family, [string]$FamilyLabel, [string]$Platform, $Raw,
              $Assignments, $Settings, [string]$Detail = '', [hashtable]$Extra = @{})
        $meta = Get-PolicyMeta -Raw $Raw
        $o = [ordered]@{
            Id          = $Id
            Name        = $Name
            Family      = $Family
            FamilyLabel = $FamilyLabel
            Platform    = $Platform
            Desc        = $meta.Desc
            Modified    = $meta.Modified
            Created     = $meta.Created
            Detail      = $Detail
            Assignments = @($Assignments | Where-Object { $null -ne $_ })
            Settings    = @($Settings | Where-Object { $null -ne $_ })
        }
        foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
        [void]$policies.Add([pscustomobject]$o)
    }

    function Resolve-TargetApps {
        # mobileApp ids and/or bundle / package identifiers -> @(@{ AppId; Name })
        param([string[]]$AppIds, $ManagedApps)
        $out = @()
        foreach ($aid in @($AppIds | Where-Object { $_ })) {
            $nm = $appNameById[$aid]
            if (-not $nm) {
                try { $r = Invoke-Rsop -Uri ("beta/deviceAppManagement/mobileApps/{0}?`$select=id,displayName" -f $aid); $nm = [string]$r['displayName']; $appNameById[$aid] = $nm } catch { $nm = $aid }
            }
            $out += [pscustomobject]@{ AppId = $aid; Name = $nm }
        }
        foreach ($managedApp in $ManagedApps) {
            $ident = Get-AppIdentifierText $managedApp
            if (-not $ident) { continue }
            $identPlatform = Get-AppIdentifierPlatform $managedApp
            $aid = $appIdByIdentifier["${identPlatform}|$($ident.ToLower())"]
            $out += [pscustomobject]@{ AppId = $(if ($aid) { $aid } else { '' }); Name = $(if ($aid -and $appNameById[$aid]) { "{0} ({1})" -f $appNameById[$aid], $ident } else { $ident }) }
        }
        return $out
    }

    function Get-ScriptBodyRows {
        # Fetches one platform script individually (list responses omit the body),
        # decodes the base64 content and returns it as a searchable setting row. This is
        # how the report can answer "which script is removing app X".
        param([string]$BaseUri, $Item)
        $id = [string](Get-Prop $Item 'id')
        if (-not $id) { return , @() }
        $detail = $null
        try { $detail = Invoke-Rsop -Uri ("{0}/{1}" -f $BaseUri, $id) } catch {
            [void]$warnings.Add(("Could not fetch script body for '{0}': {1}" -f (Get-Prop $Item 'displayName'), $_.Exception.Message))
            return , @()
        }
        $b64 = [string](Get-Prop $detail 'scriptContent')
        if (-not $b64) { return , @() }
        $text = ''
        try { $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)).Trim() } catch { return , @() }
        if (-not $text) { return , @() }
        if ($text.Length -gt 6000) { $text = $text.Substring(0, 6000) + "`n...(truncated)" }
        $label = 'Script content'
        $fname = [string](Get-Prop $detail 'fileName')
        if ($fname) { $label = ("Script content ({0})" -f $fname) }
        return , @([pscustomobject]@{
            Key      = ("script:{0}:scriptContent" -f $id)
            Setting  = $label
            Value    = $text
            Category = 'Script body'
        })
    }

    # -- 1) Settings Catalog + modern Endpoint Security + modern Baselines ---------------
    Write-Step "Pulling Settings Catalog / Endpoint Security / Baseline policies (configurationPolicies)"
    $cfgPolicies = Get-RsopPaged -Uri 'beta/deviceManagement/configurationPolicies?$expand=assignments&$top=100' -Activity 'configurationPolicies'
    $n = 0
    foreach ($p in $cfgPolicies) {
        $n++
        $pname = [string]$p['name']
        Write-Progress -Id 3 -Activity 'Fetching settings (Settings Catalog & Endpoint Security)' -Status ("{0}/{1}  {2}" -f $n, @($cfgPolicies).Count, $pname) -PercentComplete ([int](100 * $n / [math]::Max(1, @($cfgPolicies).Count)))
        $rows = @()
        try {
            $settings = Get-RsopPaged -Uri ("beta/deviceManagement/configurationPolicies/{0}/settings?`$expand=settingDefinitions" -f $p['id'])
            $rows = Convert-CatalogSettings -SettingItems $settings -CategoryMap $catMap
        } catch {
            [void]$warnings.Add("Could not fetch settings for '$pname': $($_.Exception.Message)")
        }
        $meta = Get-PolicyMeta -Raw $p
        $tref = $p['templateReference']
        $detail = ''
        if ($tref) { $detail = [string](Get-Prop $tref 'templateDisplayName') }
        [void]$policies.Add([pscustomobject]@{
            Id          = [string]$p['id']
            Name        = $pname
            Family      = 'catalog'
            FamilyLabel = Get-FamilyLabel -Family 'catalog' -Raw $p -TemplateMap $templateMap
            Platform    = Get-PolicyPlatformTag -Family 'catalog' -Raw $p
            Desc        = $meta.Desc
            Modified    = $meta.Modified
            Detail      = $detail
            Assignments = @(ConvertTo-CompactAssignments -Assignments $p['assignments'])
            Settings    = @($rows)
        })
    }
    Write-Progress -Id 3 -Activity 'Fetching settings (Settings Catalog & Endpoint Security)' -Completed

    # -- 2) Legacy device configuration templates ----------------------------------------
    Write-Step "Pulling classic Device Configuration templates (deviceConfigurations)"
    $legacy = Get-RsopPaged -Uri 'beta/deviceManagement/deviceConfigurations?$expand=assignments&$top=100' -Activity 'deviceConfigurations'
    foreach ($p in $legacy) {
        $meta = Get-PolicyMeta -Raw $p
        [void]$policies.Add([pscustomobject]@{
            Id          = [string]$p['id']
            Name        = [string]$p['displayName']
            Family      = 'legacy'
            FamilyLabel = Get-FamilyLabel -Family 'legacy' -Raw $p -TemplateMap $templateMap
            Platform    = Get-PolicyPlatformTag -Family 'legacy' -Raw $p
            Desc        = $meta.Desc
            Modified    = $meta.Modified
            Detail      = ''
            Assignments = @(ConvertTo-CompactAssignments -Assignments $p['assignments'])
            Settings    = @(Convert-LegacyProperties -Policy $p)
        })
    }

    # -- 3) Administrative templates (ADMX) ----------------------------------------------
    Write-Step "Pulling Administrative Templates (groupPolicyConfigurations)"
    $admx = Get-RsopPaged -Uri 'beta/deviceManagement/groupPolicyConfigurations?$expand=assignments&$top=100' -Activity 'groupPolicyConfigurations'
    $n = 0
    foreach ($p in $admx) {
        $n++
        $pname = [string]$p['displayName']
        Write-Progress -Id 3 -Activity 'Fetching ADMX definition values' -Status ("{0}/{1}  {2}" -f $n, @($admx).Count, $pname) -PercentComplete ([int](100 * $n / [math]::Max(1, @($admx).Count)))
        $rows = @()
        try {
            $dv = Get-RsopPaged -Uri ("beta/deviceManagement/groupPolicyConfigurations/{0}/definitionValues?`$expand=definition(`$select=id,classType,displayName,categoryPath),presentationValues(`$expand=presentation)" -f $p['id'])
            $rows = Convert-AdmxValues -DefinitionValues $dv
        } catch {
            [void]$warnings.Add("Could not fetch ADMX values for '$pname': $($_.Exception.Message)")
        }
        $meta = Get-PolicyMeta -Raw $p
        [void]$policies.Add([pscustomobject]@{
            Id          = [string]$p['id']
            Name        = $pname
            Family      = 'admx'
            FamilyLabel = 'Administrative Templates (ADMX)'
            Platform    = 'windows'
            Desc        = $meta.Desc
            Modified    = $meta.Modified
            Detail      = ''
            Assignments = @(ConvertTo-CompactAssignments -Assignments $p['assignments'])
            Settings    = @($rows)
        })
    }
    Write-Progress -Id 3 -Activity 'Fetching ADMX definition values' -Completed

    # -- 4) Legacy endpoint security / baselines (intents) -------------------------------
    Write-Step "Pulling legacy Endpoint Security / Security Baselines (intents)"
    $intents = @()
    try { $intents = Get-RsopPaged -Uri 'beta/deviceManagement/intents' -Activity 'intents' } catch {
        [void]$warnings.Add("Could not list intents: $($_.Exception.Message)")
    }
    $intentDefMaps = @{}   # templateId -> (definitionId -> @{Name;Category})
    $n = 0
    foreach ($p in $intents) {
        $n++
        $pname = [string]$p['displayName']
        Write-Progress -Id 3 -Activity 'Fetching intent settings' -Status ("{0}/{1}  {2}" -f $n, @($intents).Count, $pname) -PercentComplete ([int](100 * $n / [math]::Max(1, @($intents).Count)))

        # real setting display names live on the intent's template categories
        $tid = [string]$p['templateId']
        if ($tid -and -not $intentDefMaps.ContainsKey($tid)) {
            $dm = @{}
            try {
                $cats = Get-RsopPaged -Uri ("beta/deviceManagement/templates/{0}/categories?`$expand=settingDefinitions" -f $tid)
                foreach ($c in @($cats)) {
                    $cname = [string](Get-Prop $c 'displayName')
                    foreach ($sd in (Get-PropList $c 'settingDefinitions')) {
                        $sdid = [string](Get-Prop $sd 'id')
                        if ($sdid -and -not $dm.ContainsKey($sdid)) {
                            $dm[$sdid] = @{ Name = [string](Get-Prop $sd 'displayName'); Category = $cname }
                        }
                    }
                }
            } catch { }
            $intentDefMaps[$tid] = $dm
        }
        $defMap = @{}
        if ($tid -and $intentDefMaps.ContainsKey($tid)) { $defMap = $intentDefMaps[$tid] }

        $rows = @(); $asg = @()
        try {
            $isettings = Get-RsopPaged -Uri ("beta/deviceManagement/intents/{0}/settings" -f $p['id'])
            $rows = Convert-IntentSettings -Settings $isettings -DefMap $defMap
        } catch { [void]$warnings.Add("Could not fetch settings for intent '$pname': $($_.Exception.Message)") }
        try {
            $ia = Get-RsopPaged -Uri ("beta/deviceManagement/intents/{0}/assignments" -f $p['id'])
            $asg = @(ConvertTo-CompactAssignments -Assignments $ia)
        } catch { [void]$warnings.Add("Could not fetch assignments for intent '$pname': $($_.Exception.Message)") }
        $meta = Get-PolicyMeta -Raw $p
        [void]$policies.Add([pscustomobject]@{
            Id          = [string]$p['id']
            Name        = $pname
            Family      = 'intent'
            FamilyLabel = Get-FamilyLabel -Family 'intent' -Raw $p -TemplateMap $templateMap
            Platform    = 'windows'
            Desc        = $meta.Desc
            Modified    = $meta.Modified
            Detail      = $(if ($tid -and $templateMap.ContainsKey($tid)) { $templateMap[$tid] } else { '' })
            Assignments = $asg
            Settings    = @($rows)
        })
    }
    Write-Progress -Id 3 -Activity 'Fetching intent settings' -Completed

    # -- 5) Compliance policies (optional) ------------------------------------------------
    if (-not $SkipCompliance) {
        Write-Step "Pulling Compliance policies"
        # custom compliance discovery scripts are referenced by id from Windows policies
        $complianceScripts = @{}
        if (-not $SkipScripts) {
            try {
                foreach ($cs in (Get-RsopPaged -Uri 'beta/deviceManagement/deviceComplianceScripts')) {
                    $complianceScripts[[string]$cs['id']] = $cs
                }
            } catch { Add-RunLog -Level info -Message ("Could not list custom compliance scripts: {0}" -f $_.Exception.Message) }
        }
        try {
            $comp = $null
            $actionsExpanded = $true
            try { $comp = Get-RsopPaged -Uri 'beta/deviceManagement/deviceCompliancePolicies?$expand=assignments,scheduledActionsForRule($expand=scheduledActionConfigurations)&$top=100' -Activity 'compliancePolicies' }
            catch {
                $actionsExpanded = $false
                $comp = Get-RsopPaged -Uri 'beta/deviceManagement/deviceCompliancePolicies?$expand=assignments&$top=100' -Activity 'compliancePolicies'
            }
            $actionMap = @{}
            if (-not $actionsExpanded) {
                $urls = @($comp | ForEach-Object { '/deviceManagement/deviceCompliancePolicies/{0}/scheduledActionsForRule?$expand=scheduledActionConfigurations' -f $_['id'] })
                $got = Invoke-RsopBatch -Urls $urls -Activity 'compliance actions'
                foreach ($p in $comp) {
                    $b = $got['/deviceManagement/deviceCompliancePolicies/{0}/scheduledActionsForRule?$expand=scheduledActionConfigurations' -f $p['id']]
                    if ($b) { $actionMap[[string]$p['id']] = @($b['value']) }
                }
            }
            foreach ($p in $comp) {
                $pid0 = [string]$p['id']
                $rows = @(Convert-LegacyProperties -Policy $p -Skip @('deviceCompliancePolicyScript'))
                $rules = $(if ($actionsExpanded) { @(Get-PropList $p 'scheduledActionsForRule') } else { @($actionMap[$pid0]) })
                $rows += @(Convert-ComplianceActions -Rules $rules -PolicyId $pid0)
                $scr = Get-Prop $p 'deviceCompliancePolicyScript'
                if ($scr) {
                    $sid = [string](Get-Prop $scr 'deviceComplianceScriptId')
                    $sobj = $complianceScripts[$sid]
                    $sname = $(if ($sobj) { [string]$sobj['displayName'] } else { $sid })
                    $rows += [pscustomobject]@{ Key = "compliance:${pid0}:script"; Setting = 'Custom compliance: discovery script'; Value = $sname; Category = 'Custom compliance' }
                    $body = $(if ($sobj) { ConvertFrom-Base64Text ([string]$sobj['detectionScriptContent']) } else { $null })
                    if ($body) {
                        if ($body.Length -gt 6000) { $body = $body.Substring(0, 6000) + "`n...(truncated)" }
                        $rows += [pscustomobject]@{ Key = "compliance:${pid0}:scriptBody"; Setting = "Custom compliance: discovery script content ($sname)"; Value = $body; Category = 'Script body' }
                    }
                    $rj = ConvertFrom-Base64Text ([string](Get-Prop $scr 'rulesContent'))
                    if ($rj) { $rows += [pscustomobject]@{ Key = "compliance:${pid0}:rules"; Setting = 'Custom compliance: rules (JSON)'; Value = $rj; Category = 'Custom compliance' } }
                }
                Add-CorpusPolicy -Id $pid0 -Name ([string]$p['displayName']) -Family 'compliance' -FamilyLabel 'Compliance Policy' `
                    -Platform (Get-PolicyPlatformTag -Family 'compliance' -Raw $p) -Raw $p `
                    -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows
            }
        } catch { [void]$warnings.Add("Could not list compliance policies: $($_.Exception.Message)") }

        # Settings Catalog based compliance (Linux, and any other platform authored this way)
        try {
            $cp2 = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/compliancePolicies' -Activity 'compliancePolicies (settings catalog)'
            foreach ($p in $cp2) {
                $pid0 = [string]$p['id']
                $rows = @()
                try {
                    $st = Get-RsopPaged -Uri ("beta/deviceManagement/compliancePolicies/{0}/settings?`$expand=settingDefinitions" -f $pid0)
                    $rows = @(Convert-CatalogSettings -SettingItems $st -CategoryMap $catMap)
                } catch { [void]$warnings.Add("Could not fetch settings for compliance policy '$($p['name'])': $($_.Exception.Message)") }
                try {
                    $acts = Get-RsopPaged -Uri ("beta/deviceManagement/compliancePolicies/{0}/scheduledActionsForRule?`$expand=scheduledActionConfigurations" -f $pid0)
                    $rows += @(Convert-ComplianceActions -Rules $acts -PolicyId $pid0)
                } catch { }
                Add-CorpusPolicy -Id $pid0 -Name ([string]$p['name']) -Family 'compliance' -FamilyLabel 'Compliance Policy (Settings Catalog)' `
                    -Platform (Get-PolicyPlatformTag -Family 'catalog' -Raw $p) -Raw $p `
                    -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows
            }
        } catch { Add-RunLog -Level info -Message ("Settings Catalog compliance policies not available: {0}" -f $_.Exception.Message) }
    }

    # -- 6) Windows Update profiles + platform scripts (assignment-relevant extras) --------
    $extraSources = @(
        @{ Uri = 'beta/deviceManagement/windowsFeatureUpdateProfiles'; Label = 'Windows Update - Feature'; Gate = [bool]$SkipUpdates; Platform = 'windows' },
        @{ Uri = 'beta/deviceManagement/windowsQualityUpdateProfiles'; Label = 'Windows Update - Quality (expedite)'; Gate = [bool]$SkipUpdates; Platform = 'windows' },
        @{ Uri = 'beta/deviceManagement/windowsQualityUpdatePolicies'; Label = 'Windows Update - Quality update policy (hotpatch)'; Gate = [bool]$SkipUpdates; Platform = 'windows'; Soft = $true },
        @{ Uri = 'beta/deviceManagement/windowsDriverUpdateProfiles'; Label = 'Windows Update - Drivers'; Gate = [bool]$SkipUpdates; Platform = 'windows' },
        @{ Uri = 'beta/deviceManagement/deviceManagementScripts'; Label = 'Platform Script (PowerShell)'; Gate = [bool]$SkipScripts; HasBody = $true; Platform = 'windows' },
        @{ Uri = 'beta/deviceManagement/deviceShellScripts'; Label = 'Platform Script (macOS shell)'; Gate = [bool]$SkipScripts; HasBody = $true; Platform = 'macos'; Soft = $true },
        @{ Uri = 'beta/deviceManagement/deviceCustomAttributeShellScripts'; Label = 'Custom Attribute (macOS)'; Gate = [bool]$SkipScripts; HasBody = $true; Platform = 'macos'; Soft = $true }
    )
    foreach ($src in $extraSources) {
        if ($src.Gate) { continue }
        Write-Step ("Pulling {0}" -f $src.Label)
        $items = @()
        try {
            $items = Get-RsopItemsWithAssignments -Uri $src.Uri -Activity $src.Label
        } catch {
            $hint = ''
            if ($src.HasBody -and $_.Exception.Message -match 'Forbidden') {
                $hint = ' (script endpoints need the DeviceManagementScripts.Read.All scope - re-run and consent, or -SkipScripts to silence)'
            }
            $msg = ("Could not list {0}: {1}{2}" -f $src.Label, $_.Exception.Message, $hint)
            if ($src.Soft) { Add-RunLog -Level info -Message $msg } else { [void]$warnings.Add($msg) }
            continue
        }
        foreach ($p in $items) {
            $asg = $p['assignments']
            # legacy scripts may only carry groupAssignments { targetGroupId }
            if (@($asg).Count -eq 0 -and $src.HasBody) {
                try { $asg = Get-RsopPaged -Uri ("{0}/{1}/groupAssignments" -f $src.Uri, $p['id']) } catch { $asg = @() }
            }
            $rows = @(Convert-LegacyProperties -Policy $p -FallbackCategory $src.Label)
            if ($src.HasBody) { $rows += @(Get-ScriptBodyRows -BaseUri $src.Uri -Item $p) }
            Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'extra' -FamilyLabel $src.Label `
                -Platform $src.Platform -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $asg) -Settings $rows
        }
    }

    # -- 6b) Remediations (device health scripts) -----------------------------------------
    if (-not $SkipScripts) {
        Write-Step "Pulling Remediations (deviceHealthScripts)"
        $hs = @()
        try { $hs = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/deviceHealthScripts' -Activity 'Remediations' }
        catch {
            # 403 / 400 typically means Remediations licensing was never confirmed in the tenant
            Add-RunLog -Level info -Message ("Remediations not available (licensing not confirmed or missing DeviceManagementScripts.Read.All): {0}" -f $_.Exception.Message)
            $hs = @()
        }
        # list responses may omit script bodies: fetch those individually (batched)
        $needBody = @($hs | Where-Object { -not $_['detectionScriptContent'] -and -not $_['isGlobalScript'] })
        $bodies = @{}
        if ($needBody.Count -gt 0) {
            $bodies = Invoke-RsopBatch -Urls @($needBody | ForEach-Object { '/deviceManagement/deviceHealthScripts/{0}' -f $_['id'] }) -Activity 'Remediation script bodies'
        }
        foreach ($p in $hs) {
            $pid0 = [string]$p['id']
            $full = $p
            $b = $bodies['/deviceManagement/deviceHealthScripts/{0}' -f $pid0]
            if ($b) { $full = $b }
            $rows = @(Convert-LegacyProperties -Policy $full -Category 'Remediation options' -Skip @('detectionScriptContent', 'remediationScriptContent', 'highestAvailableVersion'))
            foreach ($pair in @(@('detectionScriptContent', 'Detection script'), @('remediationScriptContent', 'Remediation script'))) {
                $txt = ConvertFrom-Base64Text ([string](Get-Prop $full $pair[0]))
                if (-not $txt) { continue }
                if ($txt.Length -gt 6000) { $txt = $txt.Substring(0, 6000) + "`n...(truncated)" }
                $rows += [pscustomobject]@{ Key = ("remediation:{0}:{1}" -f $pid0, $pair[0]); Setting = $pair[1]; Value = $txt; Category = 'Script body' }
            }
            $detail = $(if ($p['isGlobalScript']) { 'Microsoft-published' } else { '' })
            Add-CorpusPolicy -Id $pid0 -Name ([string]$p['displayName']) -Family 'remediation' -FamilyLabel 'Remediation' -Platform 'windows' `
                -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows -Detail $detail
        }
        if (@($hs).Count) { Write-Info ("{0} remediation script packages" -f @($hs).Count) }
    }

    # -- 7) Applications: one entry per app ------------------------------------------------
    # Assignments keep their intent (required / available / uninstall /
    # availableWithoutEnrollment); the per-device engine resolves which intent wins using
    # Intune's documented conflict rules, so an app shows up once with all three sections.
    if (-not $SkipApps) {
        Write-Step "Pulling applications (mobileApps)"
        $apps = @()
        try {
            $apps = @(Get-RsopPaged -Uri 'beta/deviceAppManagement/mobileApps?$filter=isAssigned eq true' -Activity 'mobileApps')
        } catch {
            try {
                $apps = @(Get-RsopPaged -Uri 'beta/deviceAppManagement/mobileApps' -Activity 'mobileApps' | Where-Object { $_['isAssigned'] -eq $true })
            } catch {
                [void]$warnings.Add("Could not list applications (missing DeviceManagementApps.Read.All? -SkipApps to silence): $($_.Exception.Message)")
                $apps = @()
            }
        }
        # Listing apps with $expand=assignments is deprecated: fetch each app's assignments
        # (batched, 20 per request).
        $asgUrls = @($apps | ForEach-Object { '/deviceAppManagement/mobileApps/{0}/assignments' -f $_['id'] })
        $asgMap = @{}
        if ($asgUrls.Count) { $asgMap = Invoke-RsopBatch -Urls $asgUrls -Activity 'Application assignments' }

        # Supersedence / dependency graph: one tenant-wide call, per-app fallback.
        $relRows = @()
        try { $relRows = @(Get-RsopPaged -Uri 'beta/deviceAppManagement/mobileAppRelationships' -Activity 'mobileAppRelationships') }
        catch {
            $withRel = @($apps | Where-Object { [int]$_['dependentAppCount'] -gt 0 -or [int]$_['supersedingAppCount'] -gt 0 -or [int]$_['supersededAppCount'] -gt 0 })
            if ($withRel.Count) {
                $rb = Invoke-RsopBatch -Urls @($withRel | ForEach-Object { '/deviceAppManagement/mobileApps/{0}/relationships' -f $_['id'] }) -Activity 'App relationships'
                foreach ($a in $withRel) {
                    $b = $rb['/deviceAppManagement/mobileApps/{0}/relationships' -f $a['id']]
                    foreach ($r in @($b['value'])) { if ($r -and -not $r['sourceId']) { $r['sourceId'] = [string]$a['id'] }; if ($r) { $relRows += $r } }
                }
            }
        }
        $relsByApp = @{}
        $relSeen = New-Object 'System.Collections.Generic.HashSet[string]'
        $addRel = {
            param([string]$Owner, [string]$Relation, [string]$Type, [string]$TargetId, [string]$TargetName, [string]$TargetVersion)
            if (-not $Owner -or -not $TargetId) { return }
            if (-not $relSeen.Add(("{0}|{1}|{2}" -f $Owner, $Relation, $TargetId))) { return }
            if (-not $relsByApp.ContainsKey($Owner)) { $relsByApp[$Owner] = New-Object System.Collections.Generic.List[object] }
            $note = ''
            if ($Relation -eq 'Supersedes' -and $Type -eq 'replace') { $note = 'uninstalls the superseded app before installing this one (even if it is not assigned)' }
            elseif ($Relation -eq 'Superseded by' -and $Type -eq 'replace') { $note = 'installing the superseding app uninstalls this one' }
            elseif ($Relation -eq 'Depends on' -and $Type -eq 'autoInstall') { $note = 'installed automatically first, even if not assigned' }
            [void]$relsByApp[$Owner].Add([pscustomobject]@{ Relation = $Relation; Type = $Type; TargetId = $TargetId; TargetName = $TargetName; TargetVersion = $TargetVersion; Note = $note })
        }
        foreach ($r in $relRows) {
            $src = [string]$r['sourceId']
            $tgt = [string]$r['targetId']
            if (-not $src) {
                $parts = ([string]$r['id']) -split '_'
                if ($parts.Count -eq 2) { $src = $(if ($parts[1] -eq $tgt) { $parts[0] } else { $parts[1] }) }
            }
            $isSup = ([string]$r['@odata.type']) -match 'Supersedence'
            $kind = $(if ($isSup) { [string]$r['supersedenceType'] } else { [string]$r['dependencyType'] })
            $tt = [string]$r['targetType']
            $fwd = $null; $inv = $null
            if ($isSup) { if ($tt -eq 'child') { $fwd = 'Supersedes'; $inv = 'Superseded by' } else { $fwd = 'Superseded by'; $inv = 'Supersedes' } }
            else { if ($tt -eq 'child') { $fwd = 'Depends on'; $inv = 'Required by' } else { $fwd = 'Required by'; $inv = 'Depends on' } }
            & $addRel $src $fwd $kind $tgt ([string]$r['targetDisplayName']) ([string]$r['targetDisplayVersion'])
            if ($r['sourceDisplayName']) {
                & $addRel $tgt $inv $kind $src ([string]$r['sourceDisplayName']) ([string]$r['sourceDisplayVersion'])
            }
        }

        $typeLabels = @{
            win32LobApp                  = 'Win32 app'
            win32CatalogApp              = 'Enterprise App Catalog (Win32)'
            winGetApp                    = 'Microsoft Store app (winget)'
            officeSuiteApp               = 'Microsoft 365 Apps suite'
            windowsMobileMSI             = 'MSI line-of-business'
            windowsUniversalAppX         = 'AppX / MSIX line-of-business'
            windowsAppX                  = 'AppX / MSIX line-of-business'
            microsoftStoreForBusinessApp = 'Store for Business (legacy)'
            windowsMicrosoftEdgeApp      = 'Microsoft Edge'
            windowsWebApp                = 'Web link (Windows)'
            webApp                       = 'Web link'
            iosStoreApp                  = 'iOS store app'
            iosVppApp                    = 'iOS volume-purchased app'
            iosLobApp                    = 'iOS line-of-business'
            managedIOSStoreApp           = 'iOS store app (managed)'
            macOSLobApp                  = 'macOS line-of-business'
            macOSDmgApp                  = 'macOS DMG app'
            macOSPkgApp                  = 'macOS PKG app'
            macOsVppApp                  = 'macOS volume-purchased app'
            macOSMicrosoftEdgeApp        = 'Microsoft Edge (macOS)'
            macOSOfficeSuiteApp          = 'Microsoft 365 Apps (macOS)'
            macOSMicrosoftDefenderApp    = 'Microsoft Defender (macOS)'
            androidManagedStoreApp       = 'Managed Google Play app'
            androidStoreApp              = 'Android store app'
            androidLobApp                = 'Android line-of-business'
            managedAndroidStoreApp       = 'Android store app (managed)'
        }
        $nApps = 0
        foreach ($app in $apps) {
            $nApps++
            $appId = [string](Get-Prop $app 'id')
            if (-not $appId) { continue }
            $appName = [string](Get-Prop $app 'displayName')
            Write-Progress -Id 3 -Activity 'Indexing applications' -Status ("{0}/{1}  {2}" -f $nApps, $apps.Count, $appName) -PercentComplete ([int](100 * $nApps / [math]::Max(1, $apps.Count)))
            $aType = ([string](Get-Prop $app '@odata.type')) -replace '#microsoft.graph.', ''
            $friendly = $typeLabels[$aType]
            if (-not $friendly) { $friendly = ConvertTo-FriendlyName $aType }
            $platform = 'other'
            if ($aType -match '^macO[Ss]') { $platform = 'macos' }
            elseif ($aType -match '^(ios|managedIOS)') { $platform = 'ios' }
            elseif ($aType -match '^(android|managedAndroid)') { $platform = 'android' }
            elseif ($aType -match '^(win32|windows|winGet|officeSuite|microsoftStore)') { $platform = 'windows' }

            $appNameById[$appId] = $appName
            foreach ($ik in @('bundleId', 'packageId', 'packageIdentifier', 'identityName', 'appIdentifier')) {
                $iv = [string](Get-Prop $app $ik)
                if ($iv) { $appIdByIdentifier["${platform}|$($iv.ToLower())"] = $appId }
            }

            $asgBody = $asgMap['/deviceAppManagement/mobileApps/{0}/assignments' -f $appId]
            $asgRaw = $(if ($asgBody) { @($asgBody['value']) } else { @(Get-PropList $app 'assignments') })
            $meta = Get-PolicyMeta -Raw $app
            [void]$appObjs.Add([pscustomobject]@{
                Id            = $appId
                Name          = $appName
                Type          = $friendly
                OdataType     = $aType
                Platform      = $platform
                Publisher     = [string](Get-Prop $app 'publisher')
                Version       = [string](Get-Prop $app 'displayVersion')
                Desc          = $meta.Desc
                Modified      = $meta.Modified
                Info          = @(Get-AppInfoRows -App $app)
                Relationships = @($(if ($relsByApp.ContainsKey($appId)) { $relsByApp[$appId].ToArray() } else { @() }))
                Assignments   = @(ConvertTo-CompactAssignments -Assignments $asgRaw)
            })
        }
        Write-Progress -Id 3 -Activity 'Indexing applications' -Completed
        Write-Info ("{0} assigned apps indexed ({1} supersedence / dependency links)" -f $apps.Count, $relSeen.Count)
    }

    # -- 8) App Configuration policies --------------------------------------------------------
    if (-not $SkipAppPolicies) {
        Write-Step "Pulling App Configuration policies (managed devices)"
        try {
            $acfg = Get-RsopItemsWithAssignments -Uri 'beta/deviceAppManagement/mobileAppConfigurations' -Activity 'mobileAppConfigurations'
            foreach ($p in $acfg) {
                $t = ([string]$p['@odata.type']).ToLower()
                $plat = $(if ($t -match 'ios') { 'ios' } elseif ($t -match 'android') { 'android' } elseif ($t -match 'macos') { 'macos' } else { 'other' })
                $targets = @(Resolve-TargetApps -AppIds @(Get-PropList $p 'targetedMobileApps'))
                $rows = @(Convert-AppConfigDeviceSettings -Policy $p)
                $scopeIds = @(Get-PropList $p 'targetedMobileApps')
                Set-AppSettingConflictKeys -Rows $rows -Scopes $scopeIds -Prefix 'appcfg' -PolicyId ([string]$p['id']) -CombinedScope (($scopeIds | Sort-Object) -join ',')
                Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'appconfig' -FamilyLabel 'App Configuration (managed devices)' `
                    -Platform $plat -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows `
                    -Detail (($targets | ForEach-Object { $_.Name }) -join ', ') -Extra @{ TargetApps = @($targets) }
            }
        } catch { [void]$warnings.Add("Could not list App Configuration policies (managed devices): $($_.Exception.Message)") }

        Write-Step "Pulling App Configuration policies (managed apps)"
        try {
            $mcfg = Get-RsopItemsWithAssignments -Uri 'beta/deviceAppManagement/targetedManagedAppConfigurations' -Navigations @('apps', 'assignments') -Activity 'targetedManagedAppConfigurations'
            foreach ($p in $mcfg) {
                $pid0 = [string]$p['id']
                $mapps = @(Get-PropList $p 'apps')
                $idents = @($mapps | ForEach-Object { Get-AppIdentifierText $_ } | Where-Object { $_ })
                $plats = @($mapps | ForEach-Object { Get-AppIdentifierPlatform $_ } | Select-Object -Unique)
                $plat = $(if ($plats.Count -eq 1) { [string]$plats[0] } else { 'other' })
                $agt = [string]$p['appGroupType']
                $appKey = (($idents | Sort-Object) -join ',')
                if (-not $appKey) { $appKey = $agt }
                $rows = New-Object System.Collections.Generic.List[object]
                foreach ($cs in (Get-PropList $p 'customSettings')) {
                    $nm = [string](Get-Prop $cs 'name')
                    if (-not $nm) { continue }
                    [void]$rows.Add([pscustomobject]@{ Key = "mamcfg:${appKey}:$nm"; Setting = $nm; Value = (Format-SettingValue (Get-Prop $cs 'value')); Category = 'Configuration key' })
                }
                # newer MAM app config (e.g. Edge / Outlook settings) lives in a settings-catalog collection
                try {
                    $st = Get-RsopPaged -Uri ("beta/deviceAppManagement/targetedManagedAppConfigurations/{0}/settings?`$expand=settingDefinitions" -f $pid0)
                    foreach ($r in (Convert-CatalogSettings -SettingItems $st -CategoryMap $catMap)) { [void]$rows.Add($r) }
                } catch { }
                if ($agt) { [void]$rows.Add([pscustomobject]@{ Key = "mamcfg:${pid0}:appGroupType"; Setting = 'Targeted apps'; Value = (ConvertTo-FriendlyName $agt); Category = 'Policy options' }) }
                $lvl = [string]$p['targetedAppManagementLevels']
                if ($lvl) { [void]$rows.Add([pscustomobject]@{ Key = "mamcfg:${pid0}:levels"; Setting = 'Device management types'; Value = $lvl; Category = 'Policy options' }) }
                $targets = @(Resolve-TargetApps -ManagedApps $mapps)
                Set-AppSettingConflictKeys -Rows $rows.ToArray() -Scopes $idents -Prefix 'mamcfg' -PolicyId $pid0 -CombinedScope $appKey
                Add-CorpusPolicy -Id $pid0 -Name ([string]$p['displayName']) -Family 'appconfig-mam' -FamilyLabel 'App Configuration (managed apps)' `
                    -Platform $plat -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows.ToArray() `
                    -Detail $(if ($idents.Count) { ($targets | ForEach-Object { $_.Name }) -join ', ' } else { ConvertTo-FriendlyName $agt }) `
                    -Extra @{ TargetApps = @($targets); ManagementLevels = $lvl }
            }
        } catch { [void]$warnings.Add("Could not list App Configuration policies (managed apps): $($_.Exception.Message)") }

        # -- 9) App Protection policies (MAM) -------------------------------------------------
        Write-Step "Pulling App Protection policies"
        $mamSources = @(
            @{ Uri = 'beta/deviceAppManagement/iosManagedAppProtections'; Label = 'App Protection - iOS/iPadOS'; Platform = 'ios'; Apps = $true },
            @{ Uri = 'beta/deviceAppManagement/androidManagedAppProtections'; Label = 'App Protection - Android'; Platform = 'android'; Apps = $true },
            @{ Uri = 'beta/deviceAppManagement/windowsManagedAppProtections'; Label = 'App Protection - Windows (Edge)'; Platform = 'windows'; Apps = $true; UnmanagedOnly = $true },
            @{ Uri = 'beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies'; Label = 'Windows Information Protection (legacy)'; Platform = 'windows'; Apps = $false },
            @{ Uri = 'beta/deviceAppManagement/windowsInformationProtectionPolicies'; Label = 'Windows Information Protection without enrollment (legacy)'; Platform = 'windows'; Apps = $false; UnmanagedOnly = $true }
        )
        foreach ($src in $mamSources) {
            $navs = $(if ($src.Apps) { @('apps', 'assignments') } else { @('assignments') })
            $items = @()
            try { $items = Get-RsopItemsWithAssignments -Uri $src.Uri -Navigations $navs -Activity $src.Label }
            catch { Add-RunLog -Level info -Message ("Could not list {0}: {1}" -f $src.Label, $_.Exception.Message); continue }
            foreach ($p in $items) {
                $mapps = @(Get-PropList $p 'apps')
                $idents = @($mapps | ForEach-Object { Get-AppIdentifierText $_ } | Where-Object { $_ })
                $rows = @(Convert-LegacyProperties -Policy $p -Category 'Protection settings' -Skip @('targetedAppManagementLevels', 'appGroupType'))
                $agt = [string]$p['appGroupType']
                if ($agt) { $rows += [pscustomobject]@{ Key = "mam:appGroupType"; Setting = 'Targeted apps'; Value = (ConvertTo-FriendlyName $agt); Category = 'Policy options' } }
                $lvl = [string]$p['targetedAppManagementLevels']
                if ($lvl) { $rows += [pscustomobject]@{ Key = "mam:levels"; Setting = 'Device management types'; Value = $lvl; Category = 'Policy options' } }
                $appKey = (($idents | Sort-Object) -join ',')
                if (-not $appKey) { $appKey = $agt }
                # MAM settings only conflict when the same app is protected twice: scope keys by app set
                foreach ($r in $rows) { $r.Key = ("mam:{0}:{1}" -f $appKey, $r.Key) }
                $targets = @(Resolve-TargetApps -ManagedApps $mapps)
                if ($targets.Count) { $rows += [pscustomobject]@{ Key = "mam:apps"; Setting = 'Protected apps'; Value = (($targets | ForEach-Object { $_.Name }) -join ', '); Category = 'Policy options' } }
                Set-AppSettingConflictKeys -Rows $rows -Scopes $idents -Prefix 'mam' -PolicyId ([string]$p['id']) -CombinedScope $appKey
                Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'mam' -FamilyLabel $src.Label -Platform $src.Platform `
                    -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows `
                    -Detail $(if ($agt) { ConvertTo-FriendlyName $agt } else { '' }) `
                    -Extra @{ TargetApps = @($targets); ManagementLevels = $lvl; UnmanagedOnly = [bool]$src.UnmanagedOnly }
            }
        }
    }

    # -- 10) Enrollment configurations + Autopilot profiles -----------------------------------
    if (-not $SkipEnrollment) {
        Write-Step "Pulling enrollment configurations (ESP, Windows Hello, restrictions, limits)"
        try {
            $ecs = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/deviceEnrollmentConfigurations' -Activity 'deviceEnrollmentConfigurations'
            foreach ($p in $ecs) {
                $pid0 = [string]$p['id']
                $ot = ([string]$p['@odata.type']) -replace '#microsoft.graph.', ''
                $et = [string]$p['deviceEnrollmentConfigurationType']
                $isDefault = ($et -like 'default*') -or ($pid0 -match '_Default') -or ($ot -eq 'windowsRestoreDeviceEnrollmentConfiguration')
                $label = 'Enrollment - other'; $class = 'other'; $plat = 'other'; $kinds = 'both'
                switch -Wildcard ($ot) {
                    'windows10EnrollmentCompletionPageConfiguration' { $label = 'Enrollment Status Page'; $class = 'esp'; $plat = 'windows' }
                    'deviceEnrollmentWindowsHelloForBusinessConfiguration' { $label = 'Windows Hello for Business (enrollment)'; $class = 'whfb'; $plat = 'windows' }
                    'deviceEnrollmentPlatformRestrictionConfiguration' {
                        $pt = [string]$p['platformType']
                        $label = 'Enrollment restriction (platform)'; $kinds = 'user'
                        $plat = $(switch -Wildcard ($pt) { 'windows*' { 'windows' } 'ios' { 'ios' } 'mac' { 'macos' } 'android*' { 'android' } 'linux' { 'linux' } default { 'other' } })
                        # Android device administrator and Android Enterprise use
                        # independent restriction profiles and priority lists.
                        $class = $(if ($pt -ieq 'androidForWork') { 'restriction:androidForWork' } else { "restriction:$plat" })
                    }
                    'deviceEnrollmentPlatformRestrictionsConfiguration' { $label = 'Enrollment restriction (platform)'; $class = 'restriction:*'; $kinds = 'user' }
                    'deviceEnrollmentLimitConfiguration' { $label = 'Enrollment restriction (device limit)'; $class = 'limit'; $kinds = 'user' }
                    'deviceComanagementAuthorityConfiguration' { $label = 'Co-management authority'; $class = 'comanagement'; $plat = 'windows' }
                    'deviceEnrollmentNotificationConfiguration' { $label = 'Enrollment notifications'; $class = "notification:$pid0" }
                    'windowsRestoreDeviceEnrollmentConfiguration' { $label = 'Windows restore (enrollment)'; $class = 'restore'; $plat = 'windows' }
                }
                $rows = @(Convert-LegacyProperties -Policy $p -Category $label -Skip @('priority', 'deviceEnrollmentConfigurationType', 'selectedMobileAppIds'))
                if ($ot -eq 'windows10EnrollmentCompletionPageConfiguration') {
                    $sel = @(Get-PropList $p 'selectedMobileAppIds')
                    $names = @(Resolve-TargetApps -AppIds $sel | ForEach-Object { $_.Name })
                    $rows += [pscustomobject]@{ Key = "esp:blockingApps"; Setting = 'Blocking apps (selected)'; Value = $(if ($names.Count) { $names -join '; ' } else { '(none selected)' }); Category = $label }
                }
                $asg = @(ConvertTo-CompactAssignments -Assignments $p['assignments'])
                if ($isDefault) {
                    # default configurations apply to everyone unless a higher-priority one wins
                    $asg = @(
                        [pscustomobject]@{ Type = 'allDevicesAssignmentTarget'; GroupId = ''; FilterId = ''; FilterType = ''; Intent = ''; Options = 'default configuration' },
                        [pscustomobject]@{ Type = 'allLicensedUsersAssignmentTarget'; GroupId = ''; FilterId = ''; FilterType = ''; Intent = ''; Options = 'default configuration' }
                    )
                }
                $prio = $(if ($isDefault) { 'Default' } else { [string]$p['priority'] })
                Add-CorpusPolicy -Id $pid0 -Name ([string]$p['displayName']) -Family 'enrollment' -FamilyLabel $label -Platform $plat -Raw $p `
                    -Assignments $asg -Settings $rows -Detail $(if ($isDefault) { 'Default (applies when nothing else does)' } else { "Priority $prio" }) `
                    -Extra @{ Priority = $prio; PriorityClass = $class; IsDefault = [bool]$isDefault; TargetKinds = $kinds }
            }
        } catch { [void]$warnings.Add("Could not list enrollment configurations (needs DeviceManagementServiceConfig.Read.All; -SkipEnrollment to silence): $($_.Exception.Message)") }

        Write-Step "Pulling Windows Autopilot deployment profiles"
        try {
            $aps = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/windowsAutopilotDeploymentProfiles' -Activity 'Autopilot profiles'
            foreach ($p in $aps) {
                # prefer the current property names over their deprecated twins
                $skip = @('language', 'extractHardwareHash', 'enableWhiteGlove', 'managementServiceAppId', 'assignedDevices')
                if ($p['outOfBoxExperienceSetting']) { $skip += 'outOfBoxExperienceSettings' }
                $rows = @(Convert-LegacyProperties -Policy $p -Category 'Autopilot profile' -Skip $skip)
                $mode = $(if (([string]$p['@odata.type']) -match 'activeDirectory') { 'Hybrid Entra join' } else { 'Entra join' })
                Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'autopilot' -FamilyLabel 'Autopilot deployment profile' -Platform 'windows' `
                    -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows -Detail $mode `
                    -Extra @{ PriorityClass = 'autopilot'; TargetKinds = 'device' }
            }
        } catch { [void]$warnings.Add("Could not list Autopilot deployment profiles: $($_.Exception.Message)") }
    }

    # -- assignment filters ----------------------------------------------------------------
    Write-Step "Pulling assignment filters"
    $filters = @()
    try {
        foreach ($f in (Get-RsopPaged -Uri 'beta/deviceManagement/assignmentFilters?$select=id,displayName,platform,rule')) {
            $filters += [pscustomobject]@{
                Id       = [string]$f['id']
                Name     = [string]$f['displayName']
                Platform = [string]$f['platform']
                Rule     = [string]$f['rule']
            }
        }
    } catch { [void]$warnings.Add("Could not list assignment filters: $($_.Exception.Message)") }

    $corpus = [pscustomobject]@{
        cacheVersion = 9
        cacheOptions = $cacheOptions
        generated    = (Get-Date).ToString('o')
        tenant       = $TenantKey
        policies     = $policies.ToArray()
        apps         = $appObjs.ToArray()
        filters      = $filters
        warnings     = $warnings.ToArray()
    }

    if ($CacheMinutes -gt 0 -and -not $script:ContainsDecryptedSecrets) {
        try { $corpus | ConvertTo-Json -Depth 12 -Compress | Set-Content -Path $cacheFile -Encoding UTF8 } catch { }
    }
    elseif ($script:ContainsDecryptedSecrets) {
        Remove-Item -LiteralPath $cacheFile -Force -ErrorAction SilentlyContinue
        Write-Warn2 'Policy cache disabled for this run because decrypted OMA-URI values are present.'
    }

    $assignedCount = @($corpus.policies | Where-Object { @($_.Assignments).Count -gt 0 }).Count
    Write-Good ("Loaded {0} policies ({1} with assignments), {2} apps, {3} assignment filters" -f @($corpus.policies).Count, $assignedCount, @($corpus.apps).Count, @($corpus.filters).Count)
    foreach ($w in $corpus.warnings) { Write-Warn2 $w }
    return $corpus
}

#endregion

#region ---------- device + directory resolution --------------------------------------------

$script:DeviceIndex = $null

function Get-DeviceIndex {
    # Bulk index of Windows managed devices (used as a fallback and for group/filter modes).
    if ($null -ne $script:DeviceIndex) { return $script:DeviceIndex }
    Write-Info "Building managed-device index (one-time per run)..."
    $sel = 'id,deviceName,serialNumber,azureADDeviceId,userId,userPrincipalName,operatingSystem,osVersion,model,manufacturer,lastSyncDateTime,ownerType,enrollmentProfileName,deviceCategoryDisplayName,joinType,skuFamily,skuNumber,jailBroken,complianceState,managementAgent,enrolledDateTime,deviceEnrollmentType,autopilotEnrolled,isEncrypted,managedDeviceOwnerType'
    $all = Get-RsopPaged -Uri ("beta/deviceManagement/managedDevices?`$select={0}&`$top=1000" -f $sel) -Activity 'managedDevices index'
    $script:DeviceIndex = @($all)
    Write-Info ("Indexed {0} managed devices" -f @($all).Count)
    return $script:DeviceIndex
}

function Find-ManagedDevices {
    param(
        [ValidateSet('serialNumber', 'deviceName', 'azureADDeviceId')]
        [string]$By,
        [string]$Value
    )
    $sel = 'id,deviceName,serialNumber,azureADDeviceId,userId,userPrincipalName,operatingSystem,osVersion,model,manufacturer,lastSyncDateTime,ownerType,enrollmentProfileName,deviceCategoryDisplayName,joinType,skuFamily,skuNumber,jailBroken,complianceState,managementAgent,enrolledDateTime,deviceEnrollmentType,autopilotEnrolled,isEncrypted,managedDeviceOwnerType'
    $esc = $Value -replace "'", "''"
    try {
        $uri = "beta/deviceManagement/managedDevices?`$filter={0} eq '{1}'&`$select={2}" -f $By, $esc, $sel
        $hits = Get-RsopPaged -Uri $uri
        if (@($hits).Count -gt 0) { return @($hits) }
    } catch {
        Write-Info ("Server-side filter on {0} not accepted; falling back to full index scan." -f $By)
    }
    $idx = Get-DeviceIndex
    return @($idx | Where-Object { [string](Get-Prop $_ $By) -ieq $Value })
}

function Select-BestEnrollment {
    # Serial/name can match several enrollment records; prefer the most recently synced.
    param($Candidates, [string]$Label)
    $list = @($Candidates | Sort-Object { [string](Get-Prop $_ 'lastSyncDateTime') } -Descending)
    if ($list.Count -gt 1) {
        Write-Warn2 ("'{0}' matched {1} enrollment records; using most recently synced ({2}). Others are likely stale." -f $Label, $list.Count, (Get-Prop $list[0] 'deviceName'))
    }
    return $list[0]
}

function Get-EntraGroupIds {
    # Transitive group membership for a directory object (device or user).
    param([string]$DirectoryObjectId, [string]$Kind)
    if (-not $DirectoryObjectId) { return @() }
    try {
        $resp = Invoke-Rsop -Method POST -Uri ("v1.0/{0}/{1}/getMemberGroups" -f $Kind, $DirectoryObjectId) -Body @{ securityEnabledOnly = $false }
        return @($resp['value'] | ForEach-Object { [string]$_ })
    } catch {
        $message = "Could not read group membership for {0} {1}: {2}" -f $Kind, $DirectoryObjectId, $_.Exception.Message
        Add-RunLog -Level error -Message $message
        throw $message
    }
}

$script:GroupNameCache = @{}

function Resolve-GroupNames {
    param([string[]]$Ids)
    $todo = @($Ids | Where-Object { $_ -and -not $script:GroupNameCache.ContainsKey($_) } | Select-Object -Unique)
    for ($i = 0; $i -lt $todo.Count; $i += 900) {
        $chunk = @($todo[$i..([math]::Min($i + 899, $todo.Count - 1))])
        try {
            $resp = Invoke-Rsop -Method POST -Uri 'v1.0/directoryObjects/getByIds' -Body @{ ids = $chunk; types = @('group') }
            foreach ($o in @($resp['value'])) {
                $script:GroupNameCache[[string]$o['id']] = [string]$o['displayName']
            }
        } catch { }
    }
    foreach ($id in @($Ids)) {
        if ($id -and -not $script:GroupNameCache.ContainsKey($id)) { $script:GroupNameCache[$id] = $id }
    }
}

function Get-GroupName { param([string]$Id) if ($Id -and $script:GroupNameCache.ContainsKey($Id)) { return $script:GroupNameCache[$Id] } return $Id }

function Get-DeviceContext {
    # Everything needed to evaluate assignments for one managed device.
    param($ManagedDevice)

    $md = $ManagedDevice
    $azId = [string](Get-Prop $md 'azureADDeviceId')
    $dirId = $null
    $deviceGroupsResolved = $true
    if ($azId -and $azId -ne '00000000-0000-0000-0000-000000000000') {
        try {
            $resp = Invoke-Rsop -Uri ("v1.0/devices?`$filter=deviceId eq '{0}'&`$select=id" -f $azId)
            $vals = @($resp['value'])
            if ($vals.Count -gt 0) { $dirId = [string]$vals[0]['id'] }
        } catch {
            $deviceGroupsResolved = $false
            Add-RunLog -Level error -Message ("Could not resolve the Entra device object for '{0}': {1}" -f (Get-Prop $md 'deviceName'), $_.Exception.Message)
        }
    }
    $deviceGroups = @()
    if ($dirId) {
        try { $deviceGroups = Get-EntraGroupIds -DirectoryObjectId $dirId -Kind 'devices' }
        catch { $deviceGroupsResolved = $false }
    }
    else {
        $deviceGroupsResolved = $false
        Add-RunLog -Level error -Message ("No Entra device object found for '{0}' - device-group targeting cannot be evaluated." -f (Get-Prop $md 'deviceName'))
    }

    $userId = [string](Get-Prop $md 'userId')
    $userGroups = @()
    $userGroupsResolved = $true
    if ($userId -and $userId -ne '00000000-0000-0000-0000-000000000000') {
        try { $userGroups = Get-EntraGroupIds -DirectoryObjectId $userId -Kind 'users' }
        catch { $userGroupsResolved = $false }
    }

    $dg = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $deviceGroups) { [void]$dg.Add($g) }
    $ug = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $userGroups) { [void]$ug.Add($g) }

    return [pscustomobject]@{
        ManagedDevice   = $md
        DirectoryId     = $dirId
        DeviceGroupIds  = $dg
        UserGroupIds    = $ug
        DeviceGroupsResolved = $deviceGroupsResolved
        UserGroupsResolved   = $userGroupsResolved
        HasPrimaryUser  = [bool]($userId -and $userId -ne '00000000-0000-0000-0000-000000000000')
    }
}

#endregion

#region ---------- assignment filter evaluation ----------------------------------------------

$script:FilterEvalCache = @{}
$script:FilterById = @{}
$script:FilterEvalVariant = 0   # remembers which request shape this tenant accepts

function Invoke-FilterEvaluate {
    # Calls /deviceManagement/evaluateAssignmentFilter trying several request shapes,
    # because the endpoint is picky and its response is a Stream with varying envelopes.
    # Returns normalized rows; throws only if every variant fails.
    param($FilterObj, [int]$Top = 100, [int]$Skip = 0, [string]$Search = '')

    $mk = {
        param([bool]$HashPrefix, [bool]$IncludeEmpty)
        $data = [ordered]@{}
        if ($HashPrefix) { $data['@odata.type'] = '#microsoft.graph.assignmentFilterEvaluateRequest' }
        else             { $data['@odata.type'] = 'microsoft.graph.assignmentFilterEvaluateRequest' }
        $data['platform'] = $FilterObj.Platform
        $data['rule']     = $FilterObj.Rule
        $data['top']      = $Top
        $data['skip']     = $Skip
        if ($IncludeEmpty -or $Search) { $data['search'] = $Search }
        if ($IncludeEmpty) { $data['orderBy'] = @() }
        return @{ data = $data }
    }
    # The endpoint answers with a Stream (octet-stream + Content-Disposition) on real
    # tenants, which the SDK refuses to return inline - so temp-file variants go first.
    # variant 1: '#'-prefixed type, omit empty fields, response via temp file
    # variant 2: portal-style body (no '#', always send search/orderBy), temp file
    # variant 3: '#'-prefixed type, parsed inline (works where the answer is plain JSON)
    $variants = @(
        @{ N = 1; Body = (& $mk $true $false);  Stream = $true  },
        @{ N = 2; Body = (& $mk $false $true);  Stream = $true  },
        @{ N = 3; Body = (& $mk $true $false);  Stream = $false }
    )
    if ($script:FilterEvalVariant -gt 0) {
        $variants = @($variants | Sort-Object { $_.N -ne $script:FilterEvalVariant })
    }

    $lastErr = $null
    foreach ($v in $variants) {
        try {
            if ($v.Stream) {
                $resp = Invoke-RsopStream -Uri 'beta/deviceManagement/evaluateAssignmentFilter' -Body $v.Body
            } else {
                $json = $v.Body | ConvertTo-Json -Depth 8
                $resp = Invoke-MgGraphRequest -Method POST -Uri 'beta/deviceManagement/evaluateAssignmentFilter' -Body $json -ContentType 'application/json' -OutputType HashTable
            }
            $rows = ConvertFrom-ReportGrid -Response $resp
            $script:FilterEvalVariant = $v.N
            return @($rows)
        } catch {
            $lastErr = $_.Exception.Message
            Add-RunLog -Level info -Message ("evaluateAssignmentFilter variant {0} failed for '{1}': {2}" -f $v.N, $FilterObj.Name, $lastErr)
        }
    }
    throw ("all evaluateAssignmentFilter request variants failed; last error: {0}" -f $lastErr)
}

# ---- client-side rule evaluation (fallback when the service call fails) --------------------

function ConvertTo-FilterTokens {
    param([string]$Rule)
    $tokens = New-Object System.Collections.Generic.List[object]
    $i = 0; $n = $Rule.Length
    while ($i -lt $n) {
        $c = $Rule[$i]
        if ([char]::IsWhiteSpace($c)) { $i++; continue }
        if ($c -eq '"') {
            $sb = New-Object System.Text.StringBuilder
            $i++
            while ($i -lt $n -and $Rule[$i] -ne '"') {
                if ($Rule[$i] -eq '\' -and $i + 1 -lt $n) { [void]$sb.Append($Rule[$i + 1]); $i += 2 }
                else { [void]$sb.Append($Rule[$i]); $i++ }
            }
            if ($i -ge $n) { throw 'unterminated string' }
            $i++
            [void]$tokens.Add(@{ T = 'str'; V = $sb.ToString() })
            continue
        }
        if ('()[],'.Contains($c)) { [void]$tokens.Add(@{ T = [string]$c; V = [string]$c }); $i++; continue }
        $j = $i
        while ($j -lt $n -and -not [char]::IsWhiteSpace($Rule[$j]) -and -not '()[],"'.Contains($Rule[$j])) { $j++ }
        $w = $Rule.Substring($i, $j - $i); $i = $j
        $wl = $w.ToLowerInvariant()
        # Rule syntax allows every operator with or without the dash ('-eq' | 'eq'),
        # including the boolean ones ('-and' | 'and').
        $opNames = @('eq', 'ne', 'in', 'notin', 'startswith', 'notstartswith',
                     'endswith', 'notendswith', 'contains', 'notcontains', 'gt', 'ge', 'lt', 'le')
        $bare = $wl.TrimStart('-')
        if ($bare -in @('and', 'or', 'not')) { [void]$tokens.Add(@{ T = 'kw'; V = $bare }) }
        elseif ($bare -in $opNames) { [void]$tokens.Add(@{ T = 'op'; V = ('-' + $bare) }) }
        elseif ($wl.StartsWith('-')) { [void]$tokens.Add(@{ T = 'op'; V = $wl }) }
        else { [void]$tokens.Add(@{ T = 'id'; V = $w }) }
    }
    return , $tokens.ToArray()
}

# Windows SKU number -> Intune filter operatingSystemSKU value, per
# learn.microsoft.com/intune/fundamentals/filters/ref-device-properties
$script:WinSkuNames = @{
    4 = 'Enterprise'; 27 = 'EnterpriseN'; 48 = 'Professional'; 49 = 'BusinessN'
    72 = 'EnterpriseEval'; 84 = 'EnterpriseNEval'; 98 = 'CoreN'; 99 = 'CoreCountrySpecific'
    100 = 'CoreSingleLanguage'; 101 = 'Core'; 111 = 'Core'; 119 = 'PPIPro'
    121 = 'Education'; 122 = 'EducationN'; 123 = 'IoTUAP'; 125 = 'EnterpriseS'
    126 = 'EnterpriseSN'; 129 = 'EnterpriseSEval'; 131 = 'IoTUAPCommercial'; 136 = 'Holographic'
    138 = 'ProfessionalSingleLanguage'; 161 = 'ProfessionalWorkstation'; 162 = 'ProfessionalN'
    164 = 'ProfessionalEducation'; 165 = 'ProfessionalEducationN'; 171 = 'EnterpriseG'
    172 = 'EnterpriseGN'; 175 = 'ServerRdsh'; 188 = 'IoTEnterprise'
    202 = 'CloudEditionN'; 203 = 'CloudEdition'
}

function Get-FilterDeviceValue {
    # Maps a filter rule property (device.xxx) onto managedDevice fields.
    # Returns $null (not '') when the device data cannot answer the question.
    param([string]$PropRef, $Md)
    $p = ($PropRef -replace '^(?i)device\.', '').ToLowerInvariant()
    switch ($p) {
        'devicename'             { return [string](Get-Prop $Md 'deviceName') }
        'manufacturer'           { return [string](Get-Prop $Md 'manufacturer') }
        'model'                  { return [string](Get-Prop $Md 'model') }
        'osversion'              { return [string](Get-Prop $Md 'osVersion') }
        'operatingsystemversion' { return [string](Get-Prop $Md 'osVersion') }
        'operatingsystemsku'     {
            # The rule compares against SKU *names* (Enterprise, Professional, ...) which
            # correspond to the numeric skuNumber; skuFamily is only a fallback.
            $n = Get-Prop $Md 'skuNumber'
            $ni = 0
            if ($null -ne $n -and [int]::TryParse([string]$n, [ref]$ni) -and $script:WinSkuNames.ContainsKey($ni)) {
                return [string]$script:WinSkuNames[$ni]
            }
            $fam = [string](Get-Prop $Md 'skuFamily')
            if ($fam) { return $fam }
            return $null
        }
        'enrollmentprofilename'  { return [string](Get-Prop $Md 'enrollmentProfileName') }
        'devicecategory'         { return [string](Get-Prop $Md 'deviceCategoryDisplayName') }
        'deviceownership'        {
            $o = [string](Get-Prop $Md 'ownerType')
            if ($o -ieq 'company') { return 'Corporate' }
            if ($o -ieq 'personal') { return 'Personal' }
            return $o
        }
        'devicetrusttype'        {
            # joinType 'azureADJoined' vs rule literal 'Azure AD joined' - Compare-FilterValue
            # normalizes whitespace on both sides for this property.
            return [string](Get-Prop $Md 'joinType')
        }
        'isrooted'               {
            $j = [string](Get-Prop $Md 'jailBroken')
            if ($j) { return $j }
            return $null
        }
        default                  { return $null }
    }
}

function Compare-FilterValue {
    # Single comparison; returns $true/$false, or $null when it cannot be decided.
    # $Prop = normalized rule property name; $RightIsBare = value was an unquoted token
    # (needed to give -eq $null / -eq Null the documented "is empty" semantics).
    param($Left, [string]$Op, $Right, [string]$Prop = '', [bool]$RightIsBare = $false)
    # $null = property unknown to the local evaluator -> undecidable; '' = known-empty -> comparable
    if ($null -eq $Left) { return $null }
    $l = ([string]$Left).Trim().ToLowerInvariant()

    if ($RightIsBare -and ([string]$Right) -match '^\$?null$') {
        switch ($Op) {
            '-eq' { return ($l -eq '') }
            '-ne' { return ($l -ne '') }
            default { return $null }
        }
    }

    # deviceTrustType inventory values have no spaces ('azureADJoined') while rule
    # literals do ('Azure AD joined') - compare that property whitespace-insensitively.
    $norm = { param($x) (([string]$x) -replace '\s', '').ToLowerInvariant() }
    $wsInsensitive = ($Prop -eq 'devicetrusttype')

    switch ($Op) {
        '-eq'            {
            if ($wsInsensitive) { return ((& $norm $Left) -eq (& $norm $Right)) }
            return $l -eq ([string]$Right).Trim().ToLowerInvariant()
        }
        '-ne'            { return -not (Compare-FilterValue -Left $Left -Op '-eq' -Right $Right -Prop $Prop) }
        '-startswith'    { return $l.StartsWith(([string]$Right).ToLowerInvariant()) }
        '-notstartswith' { return -not $l.StartsWith(([string]$Right).ToLowerInvariant()) }
        '-endswith'      { return $l.EndsWith(([string]$Right).ToLowerInvariant()) }
        '-notendswith'   { return -not $l.EndsWith(([string]$Right).ToLowerInvariant()) }
        '-contains'      { return $l.Contains(([string]$Right).ToLowerInvariant()) }
        '-notcontains'   { return -not $l.Contains(([string]$Right).ToLowerInvariant()) }
        '-in'            {
            foreach ($r in @($Right)) {
                if ($wsInsensitive) { if ((& $norm $Left) -eq (& $norm $r)) { return $true } }
                elseif ($l -eq ([string]$r).Trim().ToLowerInvariant()) { return $true }
            }
            return $false
        }
        '-notin'         { return -not (Compare-FilterValue -Left $Left -Op '-in' -Right $Right -Prop $Prop) }
        { $_ -in @('-gt', '-ge', '-lt', '-le') } {
            $lv = $null; $rv = $null
            if ([version]::TryParse([string]$Left, [ref]$lv) -and [version]::TryParse([string]$Right, [ref]$rv)) {
                switch ($Op) { '-gt' { return $lv -gt $rv } '-ge' { return $lv -ge $rv } '-lt' { return $lv -lt $rv } '-le' { return $lv -le $rv } }
            }
            return $null
        }
        default          { return $null }
    }
}

function Test-FilterRuleLocal {
    # Parses and evaluates an Intune filter rule against a managedDevice, entirely locally.
    # Returns $true / $false / $null (couldn't parse or property unavailable).
    param([string]$Rule, $Md)
    try {
        $toks = ConvertTo-FilterTokens -Rule $Rule
        $state = @{ i = 0; t = $toks }

        $peek = { if ($state.i -lt $state.t.Count) { $state.t[$state.i] } else { $null } }
        $take = { $tk = & $peek; $state.i++; $tk }

        # three-valued logic combinators ('fOr' would collide with the 'for' keyword)
        function Merge-TriAnd($a, $b) { if ($a -eq $false -or $b -eq $false) { return $false }; if ($null -eq $a -or $null -eq $b) { return $null }; return $true }
        function Merge-TriOr($a, $b)  { if ($a -eq $true -or $b -eq $true) { return $true };  if ($null -eq $a -or $null -eq $b) { return $null }; return $false }

        $parsePrimary = $null; $parseUnary = $null; $parseAnd = $null; $parseOr = $null

        $parsePrimary = {
            $tk = & $peek
            if ($null -eq $tk) { throw 'unexpected end' }
            if ($tk.T -eq '(') {
                [void](& $take)
                $v = & $parseOr
                $tk2 = & $take
                if ($null -eq $tk2 -or $tk2.T -ne ')') { throw 'expected )' }
                return $v
            }
            if ($tk.T -ne 'id') { throw "expected property, got '$($tk.V)'" }
            [void](& $take)
            $propRef = $tk.V
            $opTok = & $take
            if ($null -eq $opTok -or $opTok.T -ne 'op') { throw 'expected operator' }
            $valTok = & $peek
            $right = $null
            $rightIsBare = $false
            if ($null -ne $valTok -and $valTok.T -eq '[') {
                [void](& $take)
                $list = @()
                while ($true) {
                    $t2 = & $take
                    if ($null -eq $t2) { throw 'unterminated list' }
                    if ($t2.T -eq ']') { break }
                    if ($t2.T -eq ',') { continue }
                    $list += [string]$t2.V
                }
                $right = $list
            } else {
                $t2 = & $take
                if ($null -eq $t2) { throw 'expected value' }
                $right = [string]$t2.V
                $rightIsBare = ($t2.T -eq 'id')
            }
            $prop = ($propRef -replace '^(?i)(device|app)\.', '').ToLowerInvariant()
            $left = Get-FilterDeviceValue -PropRef $propRef -Md $Md
            return (Compare-FilterValue -Left $left -Op $opTok.V -Right $right -Prop $prop -RightIsBare $rightIsBare)
        }
        $parseUnary = {
            $tk = & $peek
            if ($null -ne $tk -and $tk.T -eq 'kw' -and $tk.V -eq 'not') {
                [void](& $take)
                $v = & $parseUnary
                if ($null -eq $v) { return $null }
                return (-not $v)
            }
            return (& $parsePrimary)
        }
        $parseAnd = {
            $v = & $parseUnary
            while ($true) {
                $tk = & $peek
                if ($null -ne $tk -and $tk.T -eq 'kw' -and $tk.V -eq 'and') { [void](& $take); $r = & $parseUnary; $v = Merge-TriAnd $v $r }
                else { break }
            }
            return $v
        }
        $parseOr = {
            $v = & $parseAnd
            while ($true) {
                $tk = & $peek
                if ($null -ne $tk -and $tk.T -eq 'kw' -and $tk.V -eq 'or') { [void](& $take); $r = & $parseAnd; $v = Merge-TriOr $v $r }
                else { break }
            }
            return $v
        }

        $result = & $parseOr
        if ($state.i -lt $state.t.Count) { throw 'trailing tokens' }
        return $result
    } catch {
        return $null
    }
}

$script:FilterMatchSetCache = @{}

function Get-FilterMatchSet {
    # Fully evaluates a filter server-side (paged) into id/name lookup sets, once per
    # filter per run. Complete=$false means the result was capped, so a device being
    # absent from the set proves nothing.
    param($FilterObj, [int]$Cap = 2000)
    $fid = [string]$FilterObj.Id
    if ($script:FilterMatchSetCache.ContainsKey($fid)) { return $script:FilterMatchSetCache[$fid] }

    $set = $null
    try {
        $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $skip = 0; $count = 0; $complete = $false
        while ($true) {
            $batch = @(Invoke-FilterEvaluate -FilterObj $FilterObj -Top 100 -Skip $skip)
            foreach ($r in $batch) {
                $count++
                foreach ($p in @($r.PSObject.Properties)) {
                    $pn = $p.Name.ToLower()
                    if ($pn -match '^(deviceid|intunedeviceid)$' -and $p.Value) { [void]$ids.Add([string]$p.Value) }
                    elseif ($pn -match 'devicename' -and $p.Value) { [void]$names.Add([string]$p.Value) }
                }
            }
            if ($batch.Count -lt 100) { $complete = $true; break }
            if ($count -ge $Cap) { break }
            $skip += 100
        }
        $set = @{ Ids = $ids; Names = $names; Complete = $complete }
        if (-not $complete) {
            Add-RunLog -Level warn -Message ("Filter '{0}' matches more than {1} devices; absence from the evaluation set is treated as unknown, not as non-match." -f $FilterObj.Name, $Cap)
        }
    } catch {
        Add-RunLog -Level info -Message ("Full server-side evaluation of filter '{0}' failed: {1}" -f $FilterObj.Name, $_.Exception.Message)
        $set = $null
    }
    $script:FilterMatchSetCache[$fid] = $set
    return $set
}

function Test-DeviceMatchesFilter {
    # Layered: (1) local rule evaluation against live inventory (the server-side report
    # lags enrollment and pages at 100 rows, so a device missing from it proves nothing),
    # (2) server-side evaluateAssignmentFilter scoped by device-name search for positive
    # evidence, (3) full paged server evaluation - absence only counts as non-match when
    # that set is complete. Cached per (filter, device).
    param([string]$FilterId, $ManagedDevice)

    $mdId = [string](Get-Prop $ManagedDevice 'id')
    $mdName = [string](Get-Prop $ManagedDevice 'deviceName')
    $cacheKey = "$FilterId|$mdId"
    if ($script:FilterEvalCache.ContainsKey($cacheKey)) { return $script:FilterEvalCache[$cacheKey] }

    $flt = $null
    if ($script:FilterById.ContainsKey($FilterId)) { $flt = $script:FilterById[$FilterId] }
    if ($null -eq $flt) {
        Add-RunLog -Level warn -Message ("Assignment referenced unknown filter id {0}" -f $FilterId)
        $script:FilterEvalCache[$cacheKey] = 'error'; return 'error'
    }

    $result = 'error'

    # Managed-app filters (app.* properties) are evaluated inside the app at launch - no
    # device inventory can answer them, and evaluateAssignmentFilter doesn't serve them.
    if ([string]$flt.Platform -match 'MobileApplicationManagement') {
        Add-RunLog -Level info -Message ("Filter '{0}' is a managed-app filter (evaluated in the app at runtime); applicability left as unknown." -f $flt.Name)
        $script:FilterEvalCache[$cacheKey] = 'error'
        return 'error'
    }

    $local = Test-FilterRuleLocal -Rule $flt.Rule -Md $ManagedDevice
    if ($local -is [bool]) {
        Add-RunLog -Level info -Message ("Filter '{0}' evaluated locally for '{1}': {2}" -f $flt.Name, $mdName, $local)
        $script:FilterEvalCache[$cacheKey] = $local
        return $local
    }
    Add-RunLog -Level info -Message ("Filter '{0}' rule not locally decidable for '{1}'; asking the service. Rule: {2}" -f $flt.Name, $mdName, $flt.Rule)

    if ($mdName) {
        try {
            $rows = Invoke-FilterEvaluate -FilterObj $flt -Search $mdName
            foreach ($r in @($rows)) {
                foreach ($p in @($r.PSObject.Properties)) {
                    $pn = $p.Name.ToLower()
                    if ($pn -match 'devicename' -and [string]$p.Value -ieq $mdName) { $result = $true; break }
                    if ($pn -match '^(deviceid|intunedeviceid)$' -and [string]$p.Value -ieq $mdId) { $result = $true; break }
                }
                if ($result -eq $true) { break }
            }
        } catch {
            Add-RunLog -Level info -Message ("Search-scoped evaluation of filter '{0}' failed ({1})." -f $flt.Name, $_.Exception.Message)
        }
    }

    if ($result -isnot [bool]) {
        $set = Get-FilterMatchSet -FilterObj $flt
        if ($null -ne $set) {
            if (($mdId -and $set.Ids.Contains($mdId)) -or ($mdName -and $set.Names.Contains($mdName))) { $result = $true }
            elseif ($set.Complete) { $result = $false }
            else { $result = 'error' }
        }
    }

    if ($result -isnot [bool]) {
        Add-RunLog -Level error -Message ("Filter '{0}' could not be conclusively evaluated for '{1}'. Rule: {2}" -f $flt.Name, $mdName, $flt.Rule)
    }
    $script:FilterEvalCache[$cacheKey] = $result
    return $result
}

function Get-FilterMatchedDevices {
    # Full evaluation of a filter -> managed devices (used for -AssignmentFilter mode).
    # Falls back to local rule evaluation across the device index when the service call fails.
    param($FilterObj, [int]$Cap = 0)
    $rows = New-Object System.Collections.Generic.List[object]
    $skip = 0
    $truncated = $false
    try {
        while ($true) {
            $batch = @(Invoke-FilterEvaluate -FilterObj $FilterObj -Top 100 -Skip $skip)
            foreach ($b in $batch) { [void]$rows.Add($b) }
            if ($batch.Count -lt 100) { break }
            if ($Cap -gt 0 -and $rows.Count -ge $Cap) { $truncated = $true; break }
            $skip += 100
        }
    } catch {
        Write-Warn2 ("Server-side evaluation of filter '{0}' failed ({1}); evaluating the rule locally across the device index." -f $FilterObj.Name, $_.Exception.Message)
        $idx = Get-DeviceIndex
        $matched = New-Object System.Collections.Generic.List[object]
        $undecided = 0
        foreach ($d in $idx) {
            $v = Test-FilterRuleLocal -Rule $FilterObj.Rule -Md $d
            if ($v -is [bool]) { if ($v) { [void]$matched.Add($d) } }
            else { $undecided++ }
        }
        if ($undecided -gt 0) {
            Write-Warn2 ("Filter rule could not be evaluated locally for {0} devices; they are not included." -f $undecided)
        }
        if ($Cap -gt 0 -and $matched.Count -gt $Cap) {
            Write-Warn2 ("Filter results capped at {0} devices." -f $Cap)
            return @($matched.ToArray() | Select-Object -First $Cap)
        }
        return $matched.ToArray()
    }
    if ($truncated) {
        while ($rows.Count -gt $Cap) { $rows.RemoveAt($rows.Count - 1) }
        Write-Warn2 ("Filter results capped at {0} devices." -f $Cap)
    }

    # Map preview rows back to managed devices (by id column when present, else by name).
    $idx = Get-DeviceIndex
    $byId = @{}; $byName = @{}
    foreach ($d in $idx) {
        $byId[[string](Get-Prop $d 'id')] = $d
        $byName[([string](Get-Prop $d 'deviceName')).ToLower()] = $d
    }
    $out = New-Object System.Collections.Generic.List[object]
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $rows) {
        $md = $null
        foreach ($p in @($r.PSObject.Properties)) {
            $pn = $p.Name.ToLower()
            if ($pn -match '^(deviceid|intunedeviceid)$' -and $byId.ContainsKey([string]$p.Value)) { $md = $byId[[string]$p.Value]; break }
        }
        if ($null -eq $md) {
            foreach ($p in @($r.PSObject.Properties)) {
                if ($p.Name.ToLower() -match 'devicename') {
                    $k = ([string]$p.Value).ToLower()
                    if ($byName.ContainsKey($k)) { $md = $byName[$k] }
                    break
                }
            }
        }
        if ($null -ne $md) {
            $mid = [string](Get-Prop $md 'id')
            if ($seen.Add($mid)) { [void]$out.Add($md) }
        }
    }
    return $out.ToArray()
}

#endregion

#region ---------- applicability engine ------------------------------------------------------

# Applicability is evaluated in two phases, mirroring Intune:
#   1. Get-ReachingPaths: which INCLUDE assignments reach the device by group membership
#      (device groups, the primary user's groups, All devices / All users), after same-kind
#      group exclusions. User-group exclusions do not undo device-targeted includes and vice
#      versa (Intune doesn't evaluate user-to-device relationships).
#   2. Resolve-FilterPrecedence: assignment filters across every reaching path, using Intune's
#      filter-mode precedence: an Exclude-mode filter wins over 'no filter', which wins over
#      an Include-mode filter; filters in the same mode are ORed
#      (learn.microsoft.com/intune/fundamentals/filters/troubleshoot).
# Apps add a step in between: the winning intent is resolved from phase 1 first and only
# the winning intent's filters are evaluated (Resolve-AppIntent).
# Every assignment gets a hit marker (Hit/Note) that the report shows next to it:
#   applies | excluded (include cancelled by a group exclusion) | excluding (exclusion that
#   matches this device) | filteredout | notevaluated | overridden | ignored | unknown | ''

function New-HitArray {
    param([int]$Count)
    $h = New-Object object[] $Count
    for ($i = 0; $i -lt $Count; $i++) { $h[$i] = [pscustomobject]@{ Hit = ''; Note = '' } }
    return , $h
}

function Get-FilterDisplayName {
    param([string]$FilterId)
    if ($FilterId -and $script:FilterById.ContainsKey($FilterId)) { return $script:FilterById[$FilterId].Name }
    return $FilterId
}

function Get-ReachingPaths {
    param($Assignments, $Ctx, [ValidateSet('both', 'user', 'device')][string]$TargetKinds = 'both', [string]$PathTag = '')
    $asg = @($Assignments)
    $hits = New-HitArray -Count $asg.Count
    $paths = New-Object System.Collections.Generic.List[object]
    $excludeReasons = New-Object System.Collections.Generic.List[string]
    $unknownNotes = New-Object System.Collections.Generic.List[string]
    $deviceExcl = New-Object System.Collections.Generic.List[string]
    $userExcl = New-Object System.Collections.Generic.List[string]
    $membershipUnknown = (-not $Ctx.DeviceGroupsResolved) -or ($Ctx.HasPrimaryUser -and -not $Ctx.UserGroupsResolved)
    $hasGroupExclusions = $false

    for ($i = 0; $i -lt $asg.Count; $i++) {
        $a = $asg[$i]
        if ([string]$a.Type -notlike '*exclusionGroupAssignmentTarget*') { continue }
        $hasGroupExclusions = $true
        if (-not $a.GroupId) { continue }
        $gn = Get-GroupName $a.GroupId
        $notes = @()
        if ($Ctx.DeviceGroupIds.Contains($a.GroupId)) { [void]$deviceExcl.Add($gn); $notes += 'the device is a member' }
        if ($Ctx.UserGroupIds.Contains($a.GroupId)) { [void]$userExcl.Add($gn); $notes += 'the primary user is a member' }
        if ($notes.Count) { $hits[$i] = [pscustomobject]@{ Hit = 'excluding'; Note = ("Excludes this device - {0}" -f ($notes -join ' and ')) } }
        elseif ($membershipUnknown) { $hits[$i] = [pscustomobject]@{ Hit = 'unknown'; Note = 'Group membership could not be resolved' } }
    }

    $hadDeviceInclude = $false; $hadUserInclude = $false; $pathExcluded = $false
    for ($i = 0; $i -lt $asg.Count; $i++) {
        $a = $asg[$i]
        $type = [string]$a.Type
        if ($type -like '*exclusionGroupAssignmentTarget*') { continue }
        $base = $null; $kind = ''
        switch -Wildcard ($type) {
            '*allDevicesAssignmentTarget*' { $base = 'All devices'; $kind = 'device'; break }
            '*allLicensedUsersAssignmentTarget*' {
                if ($Ctx.HasPrimaryUser) { $base = 'All users (via primary user)'; $kind = 'user' }
                else { $hits[$i] = [pscustomobject]@{ Hit = ''; Note = 'Device has no primary user' } }
                break
            }
            '*GroupAssignmentTarget*' {
                if ($a.GroupId) {
                    if ($Ctx.DeviceGroupIds.Contains($a.GroupId)) { $base = ("Device group '{0}'" -f (Get-GroupName $a.GroupId)); $kind = 'device' }
                    elseif ($Ctx.UserGroupIds.Contains($a.GroupId)) { $base = ("User group '{0}' (via primary user)" -f (Get-GroupName $a.GroupId)); $kind = 'user' }
                    elseif ($membershipUnknown) {
                        [void]$unknownNotes.Add(("Could not determine membership of group '{0}' because directory membership resolution failed." -f (Get-GroupName $a.GroupId)))
                        $hits[$i] = [pscustomobject]@{ Hit = 'unknown'; Note = 'Group membership could not be resolved' }
                    }
                }
                break
            }
        }
        if ($null -eq $base) { continue }
        if ($TargetKinds -eq 'user' -and $kind -eq 'device') {
            $hits[$i] = [pscustomobject]@{ Hit = 'ignored'; Note = 'This policy type is evaluated for users only - device targeting is ignored' }
            continue
        }
        if ($TargetKinds -eq 'device' -and $kind -eq 'user') {
            $hits[$i] = [pscustomobject]@{ Hit = 'ignored'; Note = 'This policy type is evaluated for devices only - user targeting is ignored' }
            continue
        }
        if ($kind -eq 'device') { $hadDeviceInclude = $true } else { $hadUserInclude = $true }

        # same-kind exclusion beats the include (and its filter) for this path
        if ($kind -eq 'device' -and $deviceExcl.Count -gt 0) {
            $pathExcluded = $true
            $why = ("{0} - excluded via device group '{1}'" -f $base, (@($deviceExcl) -join "', '"))
            [void]$excludeReasons.Add($why)
            $hits[$i] = [pscustomobject]@{ Hit = 'excluded'; Note = ("Cancelled by the exclusion of '{0}'" -f (@($deviceExcl) -join "', '")) }
            continue
        }
        if ($kind -eq 'user' -and $userExcl.Count -gt 0) {
            $pathExcluded = $true
            $why = ("{0} - excluded via user group '{1}' (via primary user)" -f $base, (@($userExcl) -join "', '"))
            [void]$excludeReasons.Add($why)
            $hits[$i] = [pscustomobject]@{ Hit = 'excluded'; Note = ("Cancelled by the exclusion of '{0}'" -f (@($userExcl) -join "', '")) }
            continue
        }
        [void]$paths.Add([pscustomobject]@{
            Index = $i; Base = $base; Kind = $kind; Tag = $PathTag
            FilterId = [string]$a.FilterId; FilterType = [string]$a.FilterType; Hits = $hits
        })
    }

    $mixNotes = @()
    if ($userExcl.Count -gt 0 -and $hadDeviceInclude) {
        $mixNotes += ("note: user-group exclusion '{0}' does not affect device-targeted assignments (Intune doesn't evaluate user-to-device relationships)" -f (@($userExcl) -join "', '"))
    }
    if ($deviceExcl.Count -gt 0 -and $hadUserInclude) {
        $mixNotes += ("note: device-group exclusion '{0}' does not affect user-targeted assignments (Intune doesn't evaluate user-to-device relationships)" -f (@($deviceExcl) -join "', '"))
    }
    return [pscustomobject]@{
        Paths = $paths.ToArray(); Hits = $hits; ExcludeReasons = $excludeReasons.ToArray(); UnknownNotes = $unknownNotes.ToArray()
        MixNotes = $mixNotes; DeviceExcl = $deviceExcl.ToArray(); UserExcl = $userExcl.ToArray()
        PathExcluded = $pathExcluded; MembershipUnknown = $membershipUnknown; HasGroupExclusions = $hasGroupExclusions
    }
}

function Resolve-FilterPrecedence {
    # Returns Status = Applies | FilteredOut | Unknown | None (no reaching path) with Reasons
    # and the target kinds (device/user) of the paths that made it apply.
    param($Paths, $Ctx)
    $all = @($Paths)
    if ($all.Count -eq 0) { return [pscustomobject]@{ Status = 'None'; Reasons = @(); Kinds = @() } }
    $md = $Ctx.ManagedDevice
    $hasF = { param($p) $p.FilterId -and $p.FilterType -and $p.FilterType -ne 'none' }
    $exc = @($all | Where-Object { (& $hasF $_) -and $_.FilterType -ieq 'exclude' })
    $none = @($all | Where-Object { -not (& $hasF $_) })
    $inc = @($all | Where-Object { (& $hasF $_) -and $_.FilterType -ieq 'include' })
    $tag = { param($p) if ($p.Tag) { "[$($p.Tag)] " } else { '' } }
    $setHit = { param($p, $h, $n) $p.Hits[$p.Index] = [pscustomobject]@{ Hit = $h; Note = $n } }

    if ($exc.Count -gt 0) {
        $matched = @(); $unknown = @(); $clear = @()
        foreach ($p in $exc) {
            $fn = Get-FilterDisplayName $p.FilterId
            $m = Test-DeviceMatchesFilter -FilterId $p.FilterId -ManagedDevice $md
            if ($m -isnot [bool]) { $unknown += $p; & $setHit $p 'unknown' ("Exclude filter '{0}' could not be evaluated" -f $fn) }
            elseif ($m) { $matched += $p; & $setHit $p 'filteredout' ("Exclude filter '{0}' matched - device excluded" -f $fn) }
            else { $clear += $p; & $setHit $p 'applies' ("Exclude filter '{0}' not matched" -f $fn) }
        }
        foreach ($p in @($none + $inc)) { & $setHit $p 'notevaluated' 'Not evaluated - an Exclude-mode filter on another assignment takes precedence' }
        if ($matched.Count -gt 0) {
            return [pscustomobject]@{ Status = 'FilteredOut'; Kinds = @(); Reasons = @($matched | ForEach-Object {
                        "{0}{1} + exclude filter '{2}' (matched - excluded; Exclude-mode filters take precedence over every other assignment)" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
        }
        if ($unknown.Count -gt 0) {
            return [pscustomobject]@{ Status = 'Unknown'; Kinds = @(); Reasons = @($unknown | ForEach-Object {
                        "{0}{1} + exclude filter '{2}' - filter evaluation failed, applicability unknown" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
        }
        return [pscustomobject]@{ Status = 'Applies'; Kinds = @($clear | ForEach-Object { $_.Kind } | Select-Object -Unique); Reasons = @($clear | ForEach-Object {
                    "{0}{1} + exclude filter '{2}' (not matched)" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
    }
    if ($none.Count -gt 0) {
        foreach ($p in $none) { & $setHit $p 'applies' 'Targets this device (no filter)' }
        foreach ($p in $inc) { & $setHit $p 'notevaluated' 'Not evaluated - an assignment without a filter already applies' }
        return [pscustomobject]@{ Status = 'Applies'; Kinds = @($none | ForEach-Object { $_.Kind } | Select-Object -Unique); Reasons = @($none | ForEach-Object { "{0}{1}" -f (& $tag $_), $_.Base }) }
    }
    $ok = @(); $unknown = @(); $miss = @()
    foreach ($p in $inc) {
        $fn = Get-FilterDisplayName $p.FilterId
        $m = Test-DeviceMatchesFilter -FilterId $p.FilterId -ManagedDevice $md
        if ($m -isnot [bool]) { $unknown += $p; & $setHit $p 'unknown' ("Include filter '{0}' could not be evaluated" -f $fn) }
        elseif ($m) { $ok += $p; & $setHit $p 'applies' ("Include filter '{0}' matched" -f $fn) }
        else { $miss += $p; & $setHit $p 'filteredout' ("Include filter '{0}' NOT matched" -f $fn) }
    }
    if ($ok.Count -gt 0) {
        $r = @($ok | ForEach-Object { "{0}{1} + include filter '{2}' (matched)" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) })
        $r += @($miss | ForEach-Object { "(other path filtered out: {0}{1} + include filter '{2}' (NOT matched))" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) })
        return [pscustomobject]@{ Status = 'Applies'; Kinds = @($ok | ForEach-Object { $_.Kind } | Select-Object -Unique); Reasons = $r }
    }
    if ($unknown.Count -gt 0) {
        return [pscustomobject]@{ Status = 'Unknown'; Kinds = @(); Reasons = @($unknown | ForEach-Object {
                    "{0}{1} + include filter '{2}' - filter evaluation failed, applicability unknown" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
    }
    return [pscustomobject]@{ Status = 'FilteredOut'; Kinds = @(); Reasons = @($miss | ForEach-Object {
                "{0}{1} + include filter '{2}' (NOT matched)" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
}

function Get-PolicyApplicability {
    # Evaluates one policy's assignments against one device context.
    # Returns Status: Applies | Excluded | FilteredOut | Unknown | NotTargeted, Reasons,
    # Hits (aligned with $Policy.Assignments) and Kinds (target kinds that made it apply).
    param($Policy, $Ctx, [string]$TargetKinds = 'both')
    if (-not $TargetKinds) { $TargetKinds = 'both' }
    $r = Get-ReachingPaths -Assignments $Policy.Assignments -Ctx $Ctx -TargetKinds $TargetKinds

    if ($r.HasGroupExclusions -and $r.MembershipUnknown) {
        $unresolved = @()
        if (-not $Ctx.DeviceGroupsResolved) { $unresolved += 'device' }
        if ($Ctx.HasPrimaryUser -and -not $Ctx.UserGroupsResolved) { $unresolved += 'primary user' }
        foreach ($h in $r.Hits) { $h.Hit = 'unknown'; $h.Note = 'Group membership could not be resolved' }
        return [pscustomobject]@{
            Status  = 'Unknown'; Hits = $r.Hits; Kinds = @()
            Reasons = @(("Could not resolve {0} group membership; group-targeted applicability is unknown." -f ($unresolved -join ' and ')))
        }
    }

    $f = Resolve-FilterPrecedence -Paths $r.Paths -Ctx $Ctx
    switch ($f.Status) {
        'Applies' {
            $all = @($f.Reasons)
            if ($r.ExcludeReasons.Count -gt 0) { $all += @($r.ExcludeReasons | ForEach-Object { "(other path excluded: $_)" }) }
            $all += $r.MixNotes
            return [pscustomobject]@{ Status = 'Applies'; Reasons = $all; Hits = $r.Hits; Kinds = $f.Kinds }
        }
        'Unknown' {
            return [pscustomobject]@{ Status = 'Unknown'; Reasons = (@($f.Reasons) + @($r.UnknownNotes) + @($r.ExcludeReasons) + $r.MixNotes); Hits = $r.Hits; Kinds = @() }
        }
    }
    # nothing applies: an undecided membership could still make it apply, so Unknown
    # outranks Excluded / FilteredOut
    if ($r.UnknownNotes.Count -gt 0) {
        return [pscustomobject]@{ Status = 'Unknown'; Reasons = (@($r.UnknownNotes) + @($r.ExcludeReasons) + @($f.Reasons) + $r.MixNotes); Hits = $r.Hits; Kinds = @() }
    }
    if ($r.PathExcluded) {
        return [pscustomobject]@{ Status = 'Excluded'; Reasons = (@($r.ExcludeReasons) + @($f.Reasons | ForEach-Object { "(other path filtered out: $_)" }) + $r.MixNotes); Hits = $r.Hits; Kinds = @() }
    }
    if ($f.Status -eq 'FilteredOut') {
        return [pscustomobject]@{ Status = 'FilteredOut'; Reasons = (@($f.Reasons) + $r.MixNotes); Hits = $r.Hits; Kinds = @() }
    }
    if ($r.DeviceExcl.Count -gt 0 -or $r.UserExcl.Count -gt 0) {
        $names = @(@($r.DeviceExcl) + @($r.UserExcl) | Select-Object -Unique)
        return [pscustomobject]@{ Status = 'Excluded'; Reasons = @(("Member of excluded group '{0}' (no include path targets this device)" -f ($names -join "', '"))); Hits = $r.Hits; Kinds = @() }
    }
    return [pscustomobject]@{ Status = 'NotTargeted'; Reasons = @(); Hits = $r.Hits; Kinds = @() }
}

$script:IntentLabels = @{
    required = 'Required'; available = 'Available'; uninstall = 'Uninstall'
    availableWithoutEnrollment = 'Available (no enrollment)'; requiredAndAvailable = 'Required + Available'
}

function Resolve-AppIntent {
    # Intune's documented resolution when one device/user is reached by several intents
    # (learn.microsoft.com/intune/app-management/deployment/assign-groups#how-conflicts-
    # between-app-intents-are-resolved). $Reach: intent -> kinds ('user'/'device') reaching it.
    # Returns @{ Key; Win (intents whose filters are evaluated); Note } or $null.
    param([hashtable]$Reach)
    $has = { param([string]$i, [string]$k) $Reach.ContainsKey($i) -and (-not $k -or @($Reach[$i]) -contains $k) }
    $R = & $has 'required' ''; $A = & $has 'available' ''; $U = & $has 'uninstall' ''; $W = & $has 'availableWithoutEnrollment' ''
    if ($R) {
        if ($A) {
            $n = 'Required and Available both reach this device: Intune merges them into "Required and Available" (the filters of both are evaluated).'
            if ($U) { $n += ' Uninstall also reaches it but Required always wins over Uninstall.' }
            return @{ Key = 'requiredAndAvailable'; Win = @('required', 'available'); Note = $n }
        }
        if ($W -and (& $has 'required' 'device')) {
            return @{ Key = 'requiredAndAvailable'; Win = @('required', 'availableWithoutEnrollment'); Note = 'Device Required + user Available without enrollment resolve to "Required and Available without enrollment".' }
        }
        $n = ''
        if ($U) { $n = 'Required and Uninstall both reach this device - Required wins (Intune: Required always beats Uninstall, for user and device targeting alike).' }
        elseif ($W) { $n = 'Required beats Available without enrollment.' }
        return @{ Key = 'required'; Win = @('required'); Note = $n }
    }
    if ($U) {
        if ($A -and (& $has 'available' 'user') -and -not (& $has 'available' 'device') -and (& $has 'uninstall' 'device') -and -not (& $has 'uninstall' 'user')) {
            return @{ Key = 'available'; Win = @('available'); Note = 'User Available + device Uninstall resolve to Available: the app shows in Company Portal; a copy previously installed as Required is uninstalled, but an install from Company Portal is honoured.' }
        }
        if ($A) { return @{ Key = 'uninstall'; Win = @('uninstall'); Note = 'Available and Uninstall both reach this device - Uninstall wins (same target type).' } }
        if ($W) { return @{ Key = 'uninstall'; Win = @('uninstall'); Note = 'Uninstall and Available without enrollment: the uninstall is honoured unless the user installs the app from Company Portal.' } }
        return @{ Key = 'uninstall'; Win = @('uninstall'); Note = '' }
    }
    if ($A) { return @{ Key = 'available'; Win = @('available'); Note = $(if ($W) { 'Available beats Available without enrollment.' } else { '' }) } }
    if ($W) { return @{ Key = 'availableWithoutEnrollment'; Win = @('availableWithoutEnrollment'); Note = '' } }
    return $null
}

function Get-AppApplicability {
    # One app against one device: per-intent reach -> intent resolution -> filters of the
    # winning intent(s). Returns the per-intent breakdown the Apps tab renders.
    param($App, $Ctx)
    $asg = @($App.Assignments)
    $intents = @($asg | ForEach-Object { if ($_.Intent) { [string]$_.Intent } else { 'unknown' } } | Select-Object -Unique)
    $order = @('required', 'available', 'uninstall', 'availableWithoutEnrollment')
    $intents = @($order | Where-Object { $intents -contains $_ }) + @($intents | Where-Object { $order -notcontains $_ })

    $per = [ordered]@{}
    $reach = @{}
    $anyUnknownMembership = $false
    foreach ($it in $intents) {
        $sub = @($asg | Where-Object { ([string]$_.Intent -eq $it) -or (-not $_.Intent -and $it -eq 'unknown') })
        $rp = Get-ReachingPaths -Assignments $sub -Ctx $Ctx -PathTag $script:IntentLabels[$it]
        if ($rp.HasGroupExclusions -and $rp.MembershipUnknown) { $anyUnknownMembership = $true }
        if ($rp.UnknownNotes.Count) { $anyUnknownMembership = $true }
        $per[$it] = [pscustomobject]@{ Intent = $it; Sub = $sub; R = $rp; Status = 'NotTargeted'; Via = @() }
        if ($rp.Paths.Count -gt 0 -and $it -ne 'unknown') { $reach[$it] = @($rp.Paths | ForEach-Object { $_.Kind } | Select-Object -Unique) }
    }

    $res = Resolve-AppIntent -Reach $reach
    $status = 'NotTargeted'; $effKey = ''; $resolution = @(); $conflict = $false; $kinds = @()
    if ($res) {
        $winPaths = @()
        foreach ($w in $res.Win) { if ($per.Contains($w)) { $winPaths += @($per[$w].R.Paths) } }
        $f = Resolve-FilterPrecedence -Paths $winPaths -Ctx $Ctx
        $effKey = $res.Key
        $winLabel = $script:IntentLabels[$res.Key]
        foreach ($w in $res.Win) {
            if (-not $per.Contains($w)) { continue }
            # the merged / winning intent(s) share one filter outcome
            $per[$w].Status = $(switch ($f.Status) { 'Applies' { 'Applies' } 'FilteredOut' { 'FilteredOut' } default { 'Unknown' } })
            $pfx = '[' + $script:IntentLabels[$w] + ']'
            $per[$w].Via = @($f.Reasons | Where-Object { ([string]$_).Contains($pfx) } | ForEach-Object { ([string]$_).Replace($pfx + ' ', '') })
        }
        foreach ($k in $reach.Keys) {
            if ($res.Win -contains $k) { continue }
            $conflict = $true
            $per[$k].Status = 'Overridden'
            $per[$k].Via = @($per[$k].R.Paths | ForEach-Object { $_.Base })
            foreach ($p in $per[$k].R.Paths) { $p.Hits[$p.Index] = [pscustomobject]@{ Hit = 'overridden'; Note = ("Reaches the device but loses to {0} (intent conflict rules)" -f $winLabel) } }
        }
        if ($res.Key -eq 'requiredAndAvailable' -and $reach.Count -eq 2) { $conflict = $false }
        switch ($f.Status) {
            'Applies' {
                $status = 'Applies'; $kinds = $f.Kinds
                $resolution += ("{0} - {1}" -f $winLabel, (($f.Reasons | Where-Object { $_ -notlike '(other path*' } | ForEach-Object { $_ -replace '^\[[^\]]+\]\s*', '' }) -join '; '))
            }
            'FilteredOut' {
                $status = 'FilteredOut'
                $resolution += ("{0} wins the intent resolution, but its assignment filter excludes the device - the app is not delivered. ({1})" -f $winLabel, (($f.Reasons | ForEach-Object { $_ -replace '^\[[^\]]+\]\s*', '' }) -join '; '))
                if ($conflict) { $resolution += 'Intune resolves the intent BEFORE evaluating filters, so the losing intent is not applied either.' }
            }
            default {
                $status = 'Unknown'
                $resolution += ("{0} wins the intent resolution, but its filter could not be evaluated. ({1})" -f $winLabel, (($f.Reasons | ForEach-Object { $_ -replace '^\[[^\]]+\]\s*', '' }) -join '; '))
            }
        }
        if ($res.Note) { $resolution += $res.Note }
        foreach ($k in $reach.Keys) { if ($res.Win -notcontains $k) { $resolution += ("{0} via {1} is overridden." -f $script:IntentLabels[$k], (@($per[$k].R.Paths | ForEach-Object { $_.Base }) -join ', ')) } }
    }
    # intents that never reached the device: excluded / unknown / not targeted
    $anyExcluded = $false
    foreach ($k in @($per.Keys)) {
        $e = $per[$k]
        if ($reach.ContainsKey($k)) { continue }
        if ($e.R.PathExcluded) { $e.Status = 'Excluded'; $e.Via = @($e.R.ExcludeReasons); $anyExcluded = $true }
        elseif ($e.R.UnknownNotes.Count -or ($e.R.HasGroupExclusions -and $e.R.MembershipUnknown)) { $e.Status = 'Unknown'; $e.Via = @($e.R.UnknownNotes) }
        elseif ($e.R.DeviceExcl.Count -or $e.R.UserExcl.Count) {
            $e.Status = 'Excluded'; $anyExcluded = $true
            $e.Via = @(("Member of excluded group '{0}'" -f (@(@($e.R.DeviceExcl) + @($e.R.UserExcl) | Select-Object -Unique) -join "', '")))
        }
        $e.Via = @($e.Via) + @($e.R.MixNotes)
    }
    if (-not $res) {
        if ($anyUnknownMembership) { $status = 'Unknown'; $resolution += 'Group membership could not be fully resolved; whether the app targets this device is unknown.' }
        elseif ($anyExcluded) { $status = 'Excluded'; $resolution += (@($per.Values | Where-Object { $_.Status -eq 'Excluded' } | ForEach-Object { "{0}: {1}" -f $script:IntentLabels[$_.Intent], ($_.Via -join '; ') }) -join ' | ') }
    }
    return [pscustomobject]@{
        Status = $status; EffectiveIntent = $effKey; Resolution = ($resolution -join ' '); IntentConflict = $conflict; Kinds = $kinds
        Intents = @($per.Values)
    }
}

#endregion

#region ---------- reported status (device truth) --------------------------------------------

function Get-ReportedPolicyStatus {
    # What the device actually reported, via the same endpoint the portal's per-device
    # Configuration blade uses. Returns @{ policyIdLower = @{Status=..; Name=..} }
    param([string]$IntuneDeviceId)
    $map = @{}
    # Best-effort mapping of the report's numeric PolicyStatus (raw value is kept alongside).
    $statusMap = @{
        0 = 'Unknown'; 1 = 'Not applicable'; 2 = 'Succeeded'; 3 = 'Remediated';
        4 = 'Not compliant'; 5 = 'Error'; 6 = 'Conflict'; 7 = 'Not assigned'
    }
    # The service rejects a bare IntuneDeviceId filter with 400 on some tenants; the
    # portal always scopes the report to the supported policy base types, so mirror
    # its request shape first and fall back to simpler bodies from there.
    $baseTypeClause = "((PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') " +
        "or (PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy') " +
        "or (PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy') " +
        "or (PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceManagementIntent'))"
    try {
        $rows = @()
        $skip = 0
        while ($true) {
            $portalBody = @{
                select  = @('IntuneDeviceId', 'PolicyBaseTypeName', 'PolicyId', 'PolicyStatus', 'UPN', 'UserId', 'PolicyName', 'UnifiedPolicyType')
                filter  = ("{0} and (IntuneDeviceId eq '{1}')" -f $baseTypeClause, $IntuneDeviceId)
                skip    = $skip
                top     = 50
                orderBy = @('PolicyName')
            }
            $simpleBody = @{
                select = @('PolicyId', 'PolicyName', 'PolicyStatus', 'UPN', 'PolicyBaseTypeName')
                filter = "(IntuneDeviceId eq '$IntuneDeviceId')"
                skip   = $skip
                top    = 50
            }
            $reportUri = 'beta/deviceManagement/reports/getConfigurationPoliciesReportForDevice'
            try {
                # report responses are a Stream; read via temp file (see Invoke-RsopStream)
                $resp = Invoke-RsopStream -Uri $reportUri -Body $portalBody
            } catch {
                Add-RunLog -Level info -Message ("device report (portal-shaped) failed: {0}; retrying with simple filter" -f $_.Exception.Message)
                try {
                    $resp = Invoke-RsopStream -Uri $reportUri -Body $simpleBody
                } catch {
                    Add-RunLog -Level info -Message ("device report (simple filter) failed: {0}; retrying parsed inline" -f $_.Exception.Message)
                    $resp = Invoke-Rsop -Method POST -Uri $reportUri -Body $portalBody
                }
            }
            $batch = @(ConvertFrom-ReportGrid -Response $resp)
            $rows += $batch
            if ($batch.Count -lt 50) { break }
            if ($skip -ge 9950) {
                Add-RunLog -Level warn -Message 'Device-reported policy results exceeded 10,000 rows and were truncated.'
                break
            }
            $skip += 50
        }
        foreach ($r in @($rows)) {
            $polId = [string](Get-Prop $r 'PolicyId')
            if (-not $polId) { continue }
            $statusRaw = Get-Prop $r 'PolicyStatus'
            $statusTxt = "$statusRaw"
            $si = 0
            if ([int]::TryParse("$statusRaw", [ref]$si) -and $statusMap.ContainsKey($si)) {
                $statusTxt = ("{0} ({1})" -f $statusMap[$si], $si)
            }
            $key = $polId.ToLower()
            if (-not $map.ContainsKey($key)) {
                $map[$key] = [pscustomobject]@{
                    Status = $statusTxt
                    Name   = [string](Get-Prop $r 'PolicyName')
                    Upn    = [string](Get-Prop $r 'UPN')
                }
            }
        }
    } catch {
        Add-RunLog -Level warn -Message ("Reported-status lookup failed for device {0}: {1}" -f $IntuneDeviceId, $_.Exception.Message)
    }
    return $map
}

$script:ComplianceStatusNames = @{
    0 = 'Unknown'; 1 = 'Not applicable'; 2 = 'Compliant'; 3 = 'Remediated'; 4 = 'Not compliant'; 5 = 'Error'; 6 = 'Conflict'; 7 = 'Not assigned'
}

function Get-ReportedComplianceStatus {
    # Per-policy compliance state the device reported. Primary: the reporting pipeline the
    # portal uses (getDevicePoliciesComplianceReport); fallback: deviceCompliancePolicyStates.
    # Returns @{ policyIdLower = 'Compliant' ... }
    param([string]$IntuneDeviceId)
    $map = @{}
    $fmt = {
        param($raw, $loc)
        if ($loc) { return [string]$loc }
        $n = 0
        if ([int]::TryParse("$raw", [ref]$n) -and $script:ComplianceStatusNames.ContainsKey($n)) { return $script:ComplianceStatusNames[$n] }
        return (ConvertTo-FriendlyName "$raw")
    }
    try {
        $skip = 0
        while ($true) {
            $body = @{ select = @('PolicyId', 'PolicyName', 'PolicyStatus', 'LastContact'); filter = "(DeviceId eq '$IntuneDeviceId')"; skip = $skip; top = 50 }
            $rows = @(ConvertFrom-ReportGrid -Response (Invoke-RsopStream -Uri 'beta/deviceManagement/reports/getDevicePoliciesComplianceReport' -Body $body))
            foreach ($r in $rows) {
                $pid0 = [string](Get-Prop $r 'PolicyId')
                if ($pid0) { $map[$pid0.ToLower()] = (& $fmt (Get-Prop $r 'PolicyStatus') (Get-Prop $r 'PolicyStatus_loc')) }
            }
            if ($rows.Count -lt 50 -or $skip -ge 950) { break }
            $skip += 50
        }
    } catch {
        Add-RunLog -Level info -Message ("Compliance report for device failed ({0}); trying deviceCompliancePolicyStates." -f $_.Exception.Message)
    }
    if ($map.Count -eq 0) {
        try {
            foreach ($s in (Get-RsopPaged -Uri ("beta/deviceManagement/managedDevices/{0}/deviceCompliancePolicyStates" -f $IntuneDeviceId))) {
                $sid = [string]$s['id']
                $m = [regex]::Match($sid, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
                if ($m.Success) { $map[$m.Value.ToLower()] = (& $fmt $s['state'] $null) }
                if ($s['displayName']) { $map['name:' + ([string]$s['displayName']).ToLower()] = (& $fmt $s['state'] $null) }
            }
        } catch { Add-RunLog -Level info -Message ("deviceCompliancePolicyStates unavailable: {0}" -f $_.Exception.Message) }
    }
    return $map
}

function Get-ReportedRemediationStatus {
    # Remediation (device health script) results for one device. @{ policyIdLower = 'text' }
    param([string]$IntuneDeviceId)
    $map = @{}
    try {
        foreach ($s in (Get-RsopPaged -Uri ("beta/deviceManagement/managedDevices/{0}/deviceHealthScriptStates" -f $IntuneDeviceId))) {
            $pid0 = [string]$s['policyId']
            if (-not $pid0) { continue }
            $when = Format-GraphDate $s['lastStateUpdateDateTime']
            if ($when.Length -ge 16) { $when = $when.Substring(0, 16) -replace 'T', ' ' }
            $txt = ("detection: {0} · remediation: {1}{2}" -f $s['detectionState'], $s['remediationState'], $(if ($when) { " ($when)" } else { '' }))
            $out = [string]$s['preRemediationDetectionScriptOutput']
            if ($out) { if ($out.Length -gt 160) { $out = $out.Substring(0, 160) + '...' }; $txt += " · output: $out" }
            $map[$pid0.ToLower()] = $txt
        }
    } catch { Add-RunLog -Level info -Message ("Remediation states unavailable for device {0}: {1}" -f $IntuneDeviceId, $_.Exception.Message) }
    return $map
}

$script:ReportedIntentMap = @{
    requiredInstall = 'required'; requiredUninstall = 'uninstall'; available = 'available'; requiredAndAvailableInstall = 'requiredAndAvailable'
    availableInstallWithoutEnrollment = 'availableWithoutEnrollment'; exclude = 'excluded'; notAvailable = 'notAvailable'
}

function Get-ReportedAppStates {
    # Intune's own resolved intent + install state for every app on this device
    # (users/{primaryUser}/mobileAppIntentAndStates - the data behind the device's Managed
    # Apps blade). Returns @{ appIdLower = @{ Intent; InstallState; Name; Version } }
    param([string]$UserId, [string]$IntuneDeviceId)
    $map = @{}
    if (-not $UserId -or $UserId -eq '00000000-0000-0000-0000-000000000000') { return $map }
    $entry = $null
    try {
        foreach ($e in (Get-RsopPaged -Uri ("beta/users/{0}/mobileAppIntentAndStates" -f $UserId))) {
            if ([string]$e['managedDeviceIdentifier'] -ieq $IntuneDeviceId -or [string]$e['id'] -ieq $IntuneDeviceId) { $entry = $e; break }
        }
    } catch {
        try { $entry = Invoke-Rsop -Uri ("beta/users/{0}/mobileAppIntentAndStates/{1}" -f $UserId, $IntuneDeviceId) } catch {
            Add-RunLog -Level info -Message ("Device app states unavailable: {0}" -f $_.Exception.Message)
        }
    }
    if ($null -eq $entry) { return $map }
    foreach ($a in @($entry['mobileAppList'])) {
        $aid = [string]$a['applicationId']
        if (-not $aid) { continue }
        $map[$aid.ToLower()] = [pscustomobject]@{
            Intent       = [string]$a['mobileAppIntent']
            InstallState = [string]$a['installState']
            Name         = [string]$a['displayName']
            Version      = [string]$a['displayVersion']
        }
    }
    return $map
}

function Get-AutopilotRecord {
    # The device's Windows Autopilot registration and the profile the service actually
    # assigned (authoritative over the predicted one).
    param([string]$SerialNumber)
    if (-not $SerialNumber) { return $null }
    $esc = $SerialNumber -replace "'", "''"
    $rec = $null
    try {
        $hits = @(Get-RsopPaged -Uri ("beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter=contains(serialNumber,'{0}')" -f $esc))
        $rec = @($hits | Where-Object { [string]$_['serialNumber'] -ieq $SerialNumber })[0]
    } catch {
        Add-RunLog -Level info -Message ("Autopilot record lookup failed: {0}" -f $_.Exception.Message)
        return $null
    }
    if ($null -eq $rec) { return $null }
    $prof = $null; $intended = $null
    try { $prof = Invoke-Rsop -Uri ("beta/deviceManagement/windowsAutopilotDeviceIdentities/{0}/deploymentProfile?`$select=id,displayName" -f $rec['id']) } catch { }
    try { $intended = Invoke-Rsop -Uri ("beta/deviceManagement/windowsAutopilotDeviceIdentities/{0}/intendedDeploymentProfile?`$select=id,displayName" -f $rec['id']) } catch { }
    $when = Format-GraphDate $rec['deploymentProfileAssignedDateTime']
    if ($when.Length -ge 10) { $when = $when.Substring(0, 10) }
    return [pscustomobject]@{
        GroupTag       = [string]$rec['groupTag']
        Status         = [string]$rec['deploymentProfileAssignmentStatus']
        AssignedDate   = $when
        ProfileId      = [string](Get-Prop $prof 'id')
        ProfileName    = [string](Get-Prop $prof 'displayName')
        IntendedId     = [string](Get-Prop $intended 'id')
        IntendedName   = [string](Get-Prop $intended 'displayName')
        EnrollmentState = [string]$rec['enrollmentState']
    }
}

#endregion

#region ---------- per-device orchestration --------------------------------------------------

function Get-DevicePlatform {
    param($Md)
    $os = [string](Get-Prop $Md 'operatingSystem')
    if ($os -match 'Windows') { return 'windows' }
    if ($os -match 'macOS|Mac OS') { return 'macos' }
    if ($os -match 'iOS|iPadOS') { return 'ios' }
    if ($os -match 'Android') { return 'android' }
    if ($os -match 'Linux') { return 'linux' }
    return 'other'
}

function Get-AssignmentFilterName {
    param($Assignment)
    if (-not ($Assignment.FilterId -and $Assignment.FilterType -and $Assignment.FilterType -ne 'none')) { return $null }
    $fn = $Assignment.FilterId
    if ($script:FilterById.ContainsKey($Assignment.FilterId)) { $fn = $script:FilterById[$Assignment.FilterId].Name }
    return $fn
}

function ConvertTo-AssignmentSummary {
    # Human-readable summary of a policy's assignments (group names + filters).
    param($Assignments)
    $inc = @(); $exc = @()
    foreach ($a in @($Assignments)) {
        $fnote = ''
        $fn = Get-AssignmentFilterName -Assignment $a
        if ($fn) { $fnote = (" [{0} filter: {1}]" -f $a.FilterType, $fn) }
        # break per case: '*groupAssignmentTarget*' also matches the (case-insensitive)
        # exclusion type, and a switch without break runs every matching case
        switch -Wildcard ([string]$a.Type) {
            '*exclusionGroupAssignmentTarget*'   { $exc += ((Get-GroupName $a.GroupId)); break }
            '*allDevicesAssignmentTarget*'       { $inc += ("All devices" + $fnote); break }
            '*allLicensedUsersAssignmentTarget*' { $inc += ("All users" + $fnote); break }
            '*groupAssignmentTarget*'            { $inc += ((Get-GroupName $a.GroupId) + $fnote); break }
        }
    }
    $parts = @()
    if ($inc.Count -gt 0) { $parts += ("Include: " + ($inc -join '; ')) }
    if ($exc.Count -gt 0) { $parts += ("Exclude: " + ($exc -join '; ')) }
    if ($parts.Count -eq 0) { return 'Not assigned' }
    return ($parts -join '  |  ')
}

function ConvertTo-AssignmentDetail {
    # Structured include/exclude breakdown of assignments - what the report's detail panes
    # render (target, filter + mode, delivery options, and the per-device hit marker).
    param($Assignments, $Hits)
    $asg = @($Assignments)
    $hl = @($Hits)
    $out = New-Object System.Collections.Generic.List[object]
    for ($i = 0; $i -lt $asg.Count; $i++) {
        $a = $asg[$i]
        $mode = 'Include'; $target = $null
        switch -Wildcard ([string]$a.Type) {
            '*exclusionGroupAssignmentTarget*'   { $mode = 'Exclude'; $target = ("Group: " + (Get-GroupName $a.GroupId)); break }
            '*allDevicesAssignmentTarget*'       { $target = 'All devices'; break }
            '*allLicensedUsersAssignmentTarget*' { $target = 'All users'; break }
            '*groupAssignmentTarget*'            { $target = ("Group: " + (Get-GroupName $a.GroupId)); break }
            default                              { $target = [string]$a.Type }
        }
        if (-not $target) { continue }
        $fn = Get-AssignmentFilterName -Assignment $a
        $h = $(if ($i -lt $hl.Count) { $hl[$i] } else { $null })
        [void]$out.Add([pscustomobject]@{
            Mode       = $mode
            Target     = $target
            GroupId    = [string]$a.GroupId
            Filter     = [string]$fn
            FilterMode = $(if ($fn) { [string]$a.FilterType } else { '' })
            Intent     = [string]$a.Intent
            Options    = [string]$a.Options
            Hit        = $(if ($h) { [string]$h.Hit } else { '' })
            HitNote    = $(if ($h) { [string]$h.Note } else { '' })
        })
    }
    # plain array (no unary comma): every call site wraps this in @(), which would
    # otherwise double-wrap the returned array into a single element
    return $out.ToArray()
}

function New-PolicyEntry {
    # The per-scope policy row the report renders (Policies tab, inspector, matrix).
    param($Policy, [string]$Status, [string]$Via, $Hits)
    return [pscustomobject]@{
        PolicyId         = $Policy.Id
        Name             = $Policy.Name
        Family           = $Policy.Family
        FamilyLabel      = $Policy.FamilyLabel
        Platform         = [string]$Policy.Platform
        Intent           = ''
        Status           = $Status
        Via              = $Via
        Reported         = ''
        SettingCount     = @($Policy.Settings | Where-Object { $null -ne $_ }).Count
        Modified         = [string]$Policy.Modified
        Detail           = [string]$Policy.Detail
        Desc             = [string]$Policy.Desc
        Priority         = [string]$Policy.Priority
        TargetApps       = @(@($Policy.TargetApps) | Where-Object { $_ })
        Assignment       = (ConvertTo-AssignmentSummary -Assignments $Policy.Assignments)
        AssignmentDetail = @(ConvertTo-AssignmentDetail -Assignments $Policy.Assignments -Hits $Hits)
    }
}

function New-SettingRow {
    param($Setting, $Policy, [string]$PolicyName, [string]$Via, [string]$Status)
    $o = [ordered]@{
        Key         = $Setting.Key
        Setting     = $Setting.Setting
        Value       = $Setting.Value
        Category    = [string]$Setting.Category
        Info        = $Setting.Info
        InfoUrl     = $Setting.InfoUrl
        PolicyId    = $Policy.Id
        PolicyName  = $PolicyName
        FamilyLabel = $Policy.FamilyLabel
        Via         = $Via
        ConflictKeys = @($(if ($Setting.ConflictKeys) { $Setting.ConflictKeys } else { $Setting.Key }) | Where-Object { $null -ne $_ })
    }
    if ($Status) { $o['Status'] = $Status } else { $o['Conflict'] = '' }
    return [pscustomobject]$o
}

function Test-UnmanagedOnly {
    # MAM policies scoped to unmanaged devices never apply on an MDM-enrolled device.
    param($Policy)
    if ($Policy.UnmanagedOnly) { return $true }
    $lv = @(([string]$Policy.ManagementLevels) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    return ($lv.Count -gt 0 -and @($lv | Where-Object { $_ -ne 'unmanaged' }).Count -eq 0)
}

function Get-EnrollmentEvaluationContext {
    # Enrollment restrictions act at enrollment time. These inventory fields identify
    # known exceptions; current assignments do not reconstruct the historical decision.
    param($ManagedDevice)
    $type = [string](Get-Prop $ManagedDevice 'deviceEnrollmentType')
    $agent = [string](Get-Prop $ManagedDevice 'managementAgent')
    $join = [string](Get-Prop $ManagedDevice 'joinType')
    $enrollmentWindows = ([string](Get-Prop $ManagedDevice 'operatingSystem')) -match 'Windows'
    $nonUserDriven = $type -in @('windowsBulkUserless', 'windowsBulkAzureDomainJoin', 'windowsAzureADJoinUsingDeviceAuth',
        'windowsCoManagement', 'windowsAutoEnrollment', 'appleBulkWithoutUser', 'androidEnterpriseDedicatedDevice')
    $limitException = ''
    if ($enrollmentWindows) {
        if ((Get-Prop $ManagedDevice 'autopilotEnrolled') -eq $true) { $limitException = 'Windows Autopilot enrollment' }
        elseif ($type -in @('deviceEnrollmentManager', 'windowsBulkUserless', 'windowsBulkAzureDomainJoin')) { $limitException = 'device enrollment manager or bulk enrollment' }
        elseif ($type -eq 'windowsCoManagement' -or $agent -match 'configurationManager') { $limitException = 'co-management enrollment' }
        elseif ($type -eq 'windowsAutoEnrollment') { $limitException = 'Windows automatic enrollment (including Group Policy)' }
        elseif ($type -in @('windowsAzureADJoin', 'windowsAzureADJoinUsingDeviceAuth') -or $join -eq 'azureADJoined') { $limitException = 'Microsoft Entra joined Windows enrollment' }
    }
    return [pscustomobject]@{ NonUserDriven = $nonUserDriven; LimitException = $limitException }
}

function Resolve-PriorityWinners {
    # Intune applies exactly one Enrollment Status Page / enrollment restriction / device
    # limit / co-management configuration, and one Autopilot profile, per device. Pick the
    # winner per class and mark the rest Superseded:
    #  - enrollment configurations: lowest priority number wins, default last; for ESP a
    #    device-targeted profile beats any user-targeted one
    #    (learn.microsoft.com/intune/device-enrollment/windows/setup-status-page#prioritize-profiles)
    #  - Autopilot: the oldest created profile wins
    #    (learn.microsoft.com/autopilot/profiles#windows-autopilot-profile-priority)
    param($Evaluated, [string]$DevPlatform)
    $groups = @{}
    foreach ($ev in $Evaluated) {
        $cls = [string]$ev.P.PriorityClass
        if (-not $cls -or $cls -like 'notification:*') { continue }
        if ($ev.Entry.Status -ne 'Applies') { continue }
        if ($cls -eq 'restriction:*') { $cls = "restriction:$DevPlatform" }   # the tenant default covers every platform
        if (-not $groups.ContainsKey($cls)) { $groups[$cls] = New-Object System.Collections.Generic.List[object] }
        [void]$groups[$cls].Add($ev)
    }
    foreach ($cls in @($groups.Keys)) {
        $list = $groups[$cls].ToArray()
        if ($cls -eq 'autopilot') {
            $sorted = @($list | Sort-Object @{ e = { if ($_.DefaultForDevice) { 1 } else { 0 } } },
                @{ e = { $d = [datetime]::MaxValue; if (-not [datetime]::TryParse([string]$_.P.Created, [ref]$d)) { $d = [datetime]::MaxValue }; $d } })
            $why = 'a specific group assignment beats All devices fallback, then the oldest created profile wins'
        }
        else {
            $sorted = @($list | Sort-Object @{ e = { if ($_.P.IsDefault) { 1 } else { 0 } } },
                @{ e = { if ($cls -eq 'esp' -and -not (@($_.Kinds) -contains 'device')) { 1 } else { 0 } } },
                @{ e = { $n = 0; [void][int]::TryParse([string]$_.P.Priority, [ref]$n); $n } })
            $why = $(if ($cls -eq 'esp') { 'device-targeted profiles beat user-targeted ones, then the lowest priority number wins' } else { 'the lowest priority number wins' })
        }
        $win = $sorted[0]
        $winDesc = $(if ($cls -eq 'autopilot') { "created $(([string]$win.P.Created).Substring(0, [math]::Min(10, ([string]$win.P.Created).Length)))" } elseif ($win.P.IsDefault) { 'default' } else { "priority $($win.P.Priority)" })
        if ($sorted.Count -gt 1) {
            $win.Entry.Via = ("Effective - wins over {0} other configuration(s) ({1}) | {2}" -f ($sorted.Count - 1), $why, $win.Entry.Via)
        }
        foreach ($ev in @($sorted | Select-Object -Skip 1)) {
            $ev.Entry.Status = 'Superseded'
            $ev.Entry.Via = ("Superseded by '{0}' ({1}; {2}) | {3}" -f $win.P.Name, $winDesc, $why, $ev.Entry.Via)
        }
    }
}

function New-AppEntry {
    # One app row for the Apps tab: per-intent targets with hit markers + resolution.
    param($App, $Result, $Reported, $ConfigPolicies)
    $intents = @()
    foreach ($i in @($Result.Intents | Where-Object { $null -ne $_ })) {
        $intents += [pscustomobject]@{
            Intent  = $i.Intent
            Label   = $(if ($script:IntentLabels[$i.Intent]) { $script:IntentLabels[$i.Intent] } else { ConvertTo-FriendlyName $i.Intent })
            Status  = $i.Status
            Via     = (@($i.Via) -join ' | ')
            Targets = @(ConvertTo-AssignmentDetail -Assignments $i.Sub -Hits $(if ($i.R) { $i.R.Hits } else { $null }))
        }
    }
    $eff = [string]$Result.EffectiveIntent
    $label = switch ($Result.Status) {
        'Applies'     { $script:IntentLabels[$eff] }
        'FilteredOut' { 'Filtered out' }
        'Excluded'    { 'Excluded' }
        'Unknown'     { 'Unknown' }
        'Assigned'    { 'Assigned' }
        default       { [string]$Result.Status }
    }
    $rep = $null
    if ($Reported) {
        $rk = $script:ReportedIntentMap[[string]$Reported.Intent]
        $pred = $(if ($Result.Status -eq 'Applies') { $eff } else { 'none' })
        $mismatch = $false
        if ($rk) {
            if ($pred -eq 'none') { $mismatch = ($rk -notin @('excluded', 'notAvailable')) }
            else { $mismatch = ($rk -ne $pred) -and -not ($pred -eq 'requiredAndAvailable' -and $rk -eq 'required') }
        }
        $rep = [pscustomobject]@{
            Intent       = $(if ($rk -and $script:IntentLabels[$rk]) { $script:IntentLabels[$rk] } elseif ($rk) { ConvertTo-FriendlyName $rk } else { [string]$Reported.Intent })
            InstallState = (ConvertTo-FriendlyName ([string]$Reported.InstallState))
            Version      = [string]$Reported.Version
            Mismatch     = $mismatch
        }
    }
    return [pscustomobject]@{
        AppId          = $App.Id
        Name           = $App.Name
        Type           = $App.Type
        Platform       = $App.Platform
        Publisher      = $App.Publisher
        Version        = $App.Version
        Desc           = $App.Desc
        Modified       = $App.Modified
        Status         = $Result.Status
        EffectiveIntent = $eff
        EffectiveLabel = $label
        Resolution     = [string]$Result.Resolution
        IntentConflict = [bool]$Result.IntentConflict
        Intents        = $intents
        Reported       = $rep
        Info           = @($App.Info | Where-Object { $null -ne $_ })
        Relationships  = @($App.Relationships | Where-Object { $null -ne $_ })
        ConfigPolicies = @($ConfigPolicies | Where-Object { $null -ne $_ })
    }
}

function Get-AppConfigIndex {
    # appId -> app configuration / protection policies that target it
    param($Corpus, [hashtable]$StatusById)
    $idx = @{}
    foreach ($p in @($Corpus.policies)) {
        foreach ($t in @($p.TargetApps)) {
            if (-not $t -or -not $t.AppId) { continue }
            if (-not $idx.ContainsKey($t.AppId)) { $idx[$t.AppId] = New-Object System.Collections.Generic.List[object] }
            $st = $(if ($StatusById -and $StatusById.ContainsKey($p.Id)) { $StatusById[$p.Id] } elseif ($StatusById) { 'NotTargeted' } else { $(if (@($p.Assignments).Count) { 'Assigned' } else { 'NotAssigned' }) })
            [void]$idx[$t.AppId].Add([pscustomobject]@{ PolicyId = $p.Id; Name = $p.Name; FamilyLabel = $p.FamilyLabel; Status = $st })
        }
    }
    return $idx
}

function Get-AppIntentSkeleton {
    # Intents for scopes without device math (inventory / group): targets grouped by intent.
    param($App, [scriptblock]$HitFor)
    $asg = @($App.Assignments)
    $order = @('required', 'available', 'uninstall', 'availableWithoutEnrollment')
    $present = @($asg | ForEach-Object { [string]$_.Intent } | Where-Object { $_ } | Select-Object -Unique)
    $present = @($order | Where-Object { $present -contains $_ }) + @($present | Where-Object { $order -notcontains $_ })
    $out = @()
    foreach ($it in $present) {
        $sub = @($asg | Where-Object { [string]$_.Intent -eq $it })
        $hits = $null
        if ($HitFor) { $hits = @($sub | ForEach-Object { & $HitFor $_ }) }
        $out += [pscustomobject]@{ Intent = $it; Sub = $sub; R = $(if ($hits) { [pscustomobject]@{ Hits = $hits } } else { $null }); Status = 'Assigned'; Via = @() }
    }
    return , $out
}

function Resolve-DeviceRsop {
    param($ManagedDevice, $Corpus)

    $md = $ManagedDevice
    $mdName = [string](Get-Prop $md 'deviceName')
    $mdId = [string](Get-Prop $md 'id')
    Write-Step ("Resolving device: {0}  (serial: {1})" -f $mdName, (Get-Prop $md 'serialNumber'))

    $ctx = Get-DeviceContext -ManagedDevice $md
    Write-Info ("Entra groups - device: {0}, primary user: {1}" -f $ctx.DeviceGroupIds.Count, $ctx.UserGroupIds.Count)

    # Resolve display names for every group referenced by any assignment - membership
    # reasons, exclusions AND the per-policy assignment breakdown all need names, not GUIDs.
    $mentioned = New-Object System.Collections.Generic.List[string]
    foreach ($p in @(@($Corpus.policies) + @($Corpus.apps))) {
        foreach ($a in @($p.Assignments)) {
            if ($a.GroupId) { [void]$mentioned.Add([string]$a.GroupId) }
        }
    }
    Resolve-GroupNames -Ids $mentioned.ToArray()

    $devPlatform = Get-DevicePlatform -Md $md
    $enrollmentContext = Get-EnrollmentEvaluationContext -ManagedDevice $md

    $evaluated = New-Object System.Collections.Generic.List[object]
    $evalPolicies = @($Corpus.policies | Where-Object { @($_.Assignments).Count -gt 0 })
    $n = 0
    foreach ($p in $evalPolicies) {
        $n++
        Write-Progress -Id 5 -Activity ("Evaluating policies for {0}" -f $mdName) -Status ("{0}/{1}  {2}" -f $n, $evalPolicies.Count, $p.Name) -PercentComplete ([int](100 * $n / [math]::Max(1, $evalPolicies.Count)))

        if ($devPlatform -ne 'other' -and $p.Platform -ne 'other' -and $p.Platform -ne $devPlatform) { continue }

        # MAM is user-targeted; Autopilot profiles / restrictions carry their own kind
        $tk = [string]$p.TargetKinds
        if (-not $tk) { $tk = $(if ($p.Family -in @('mam', 'appconfig-mam')) { 'user' } else { 'both' }) }
        if ($p.PriorityClass -like 'restriction:*' -and $p.IsDefault -and $enrollmentContext.NonUserDriven) { $tk = 'both' }
        $app = Get-PolicyApplicability -Policy $p -Ctx $ctx -TargetKinds $tk
        if ($app.Status -eq 'NotTargeted') { continue }

        $status = $app.Status
        $via = (@($app.Reasons) -join ' | ')
        if ($p.Family -in @('mam', 'appconfig-mam') -and $status -in @('Applies', 'Unknown') -and (Test-UnmanagedOnly -Policy $p)) {
            $status = 'NotApplicable'
            $via = ("Targets unmanaged devices only ({0}) - not applied to an MDM-enrolled device | {1}" -f $(if ($p.ManagementLevels) { $p.ManagementLevels } else { 'MAM for unmanaged devices' }), $via)
        }
        if ($p.Family -eq 'enrollment') {
            if ($status -in @('Applies', 'Unknown') -and $p.PriorityClass -eq 'limit' -and $enrollmentContext.LimitException) {
                $status = 'NotApplicable'
                $via = ("Intune device-limit restrictions do not apply to {0} | {1}" -f $enrollmentContext.LimitException, $via)
            }
            elseif ($status -in @('Applies', 'Unknown') -and $p.PriorityClass -like 'restriction:*' -and -not $p.IsDefault -and $enrollmentContext.NonUserDriven) {
                $status = 'NotApplicable'
                $via = "A non-user-driven enrollment uses the default platform restriction | $via"
            }
            $via = "Enrollment snapshot: current configuration and assignments; original enrollment enforcement is not verified | $via"
        }
        $entry = New-PolicyEntry -Policy $p -Status $status -Via $via -Hits $app.Hits
        $defaultForDevice = [bool]$p.IsDefault
        if ($p.Family -eq 'autopilot') {
            $specific = $false
            for ($aIndex = 0; $aIndex -lt @($p.Assignments).Count; $aIndex++) {
                if ($p.Assignments[$aIndex].Type -eq 'groupAssignmentTarget' -and $app.Hits[$aIndex].Hit -eq 'applies') { $specific = $true; break }
            }
            $defaultForDevice = -not $specific
        }
        [void]$evaluated.Add([pscustomobject]@{ P = $p; Entry = $entry; Kinds = @($app.Kinds); DefaultForDevice = $defaultForDevice })
    }
    Write-Progress -Id 5 -Activity ("Evaluating policies for {0}" -f $mdName) -Completed

    Resolve-PriorityWinners -Evaluated $evaluated -DevPlatform $devPlatform

    $policyResults = New-Object System.Collections.Generic.List[object]
    $settingRows = New-Object System.Collections.Generic.List[object]
    $shadowRows = New-Object System.Collections.Generic.List[object]   # settings of targeted-but-not-applying policies (report "near misses")
    foreach ($ev in $evaluated) {
        $p = $ev.P; $entry = $ev.Entry
        [void]$policyResults.Add($entry)
        if ($entry.Status -eq 'Applies' -or $entry.Status -eq 'Unknown') {
            $tag = $(if ($entry.Status -eq 'Unknown') { ' [applicability unknown]' } else { '' })
            foreach ($s in @($p.Settings)) { [void]$settingRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName ($p.Name + $tag) -Via $entry.Via)) }
        }
        elseif ($shadowRows.Count -lt 4000) {
            foreach ($s in @($p.Settings)) { [void]$shadowRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName $p.Name -Via $entry.Via -Status $entry.Status)) }
        }
    }
    if ($shadowRows.Count -ge 4000) {
        Add-RunLog -Level info -Message ("{0}: settings of excluded/filtered policies capped at 4000 rows for report size" -f $mdName)
    }

    # Cross-check with what the device actually reported.
    if (-not $SkipReportedStatus) {
        $reported = Get-ReportedPolicyStatus -IntuneDeviceId $mdId
        $known = New-Object 'System.Collections.Generic.HashSet[string]'
        $reportFamilies = @('catalog', 'legacy', 'admx', 'intent')
        foreach ($pr in $policyResults) {
            $k = ([string]$pr.PolicyId).ToLower()
            [void]$known.Add($k)
            if ($reported.ContainsKey($k)) { $pr.Reported = $reported[$k].Status }
            elseif ($pr.Status -eq 'Applies' -and $pr.Family -in $reportFamilies) { $pr.Reported = 'not in device report' }
        }
        foreach ($k in $reported.Keys) {
            if (-not $known.Contains($k)) {
                $r = $reported[$k]
                [void]$policyResults.Add([pscustomobject]@{
                    PolicyId    = $k
                    Name        = $r.Name
                    Family      = 'reported'
                    FamilyLabel = 'Reported by device (not predicted - verify targeting)'
                    Platform    = ''
                    Intent      = ''
                    Status      = 'ReportedOnly'
                    Via         = 'Device check-in report'
                    Reported    = $r.Status
                    SettingCount = 0
                    Modified    = ''
                    Detail      = ''
                    Desc        = ''
                    Priority    = ''
                    TargetApps  = @()
                    Assignment  = ''
                    AssignmentDetail = @()
                })
            }
        }
        if (-not $SkipCompliance) {
            $comp = Get-ReportedComplianceStatus -IntuneDeviceId $mdId
            foreach ($pr in @($policyResults | Where-Object { $_.Family -eq 'compliance' })) {
                $k = ([string]$pr.PolicyId).ToLower()
                if ($comp.ContainsKey($k)) { $pr.Reported = $comp[$k] }
                elseif ($comp.ContainsKey('name:' + ([string]$pr.Name).ToLower())) { $pr.Reported = $comp['name:' + ([string]$pr.Name).ToLower()] }
            }
        }
        if (-not $SkipScripts -and @($policyResults | Where-Object { $_.Family -eq 'remediation' }).Count) {
            $rem = Get-ReportedRemediationStatus -IntuneDeviceId $mdId
            foreach ($pr in @($policyResults | Where-Object { $_.Family -eq 'remediation' })) {
                $k = ([string]$pr.PolicyId).ToLower()
                if ($rem.ContainsKey($k)) { $pr.Reported = $rem[$k] }
            }
        }
    }

    # Autopilot: the service's assigned profile is authoritative over the prediction.
    $apText = ''
    if (-not $SkipEnrollment -and $devPlatform -eq 'windows') {
        $apr = Get-AutopilotRecord -SerialNumber ([string](Get-Prop $md 'serialNumber'))
        if ($apr) {
            $bits = @()
            if ($apr.ProfileName) { $bits += ("profile '{0}'" -f $apr.ProfileName) } else { $bits += 'no profile assigned' }
            if ($apr.Status) { $bits += $apr.Status }
            if ($apr.AssignedDate) { $bits += ("assigned {0}" -f $apr.AssignedDate) }
            if ($apr.GroupTag) { $bits += ("group tag '{0}'" -f $apr.GroupTag) }
            if ($apr.IntendedName -and $apr.IntendedId -ne $apr.ProfileId) { $bits += ("intended '{0}' (pending)" -f $apr.IntendedName) }
            $apText = $bits -join ' · '
            foreach ($pr in @($policyResults | Where-Object { $_.Family -eq 'autopilot' })) {
                if ($apr.ProfileId -and [string]$pr.PolicyId -ieq $apr.ProfileId) { $pr.Reported = ("assigned per Autopilot record ({0})" -f $apr.Status) }
                elseif ($apr.IntendedId -and [string]$pr.PolicyId -ieq $apr.IntendedId) { $pr.Reported = 'intended per Autopilot record (pending)' }
                else { $pr.Reported = 'not the profile on the Autopilot record' }
            }
        }
        else { $apText = 'not registered in Windows Autopilot (or record not readable)' }
    }

    # Conflict detection: same setting key from >1 applicable policy.
    $byKey = @{}
    foreach ($row in $settingRows) {
        foreach ($k in @($row.ConflictKeys)) {
            if (-not $k) { continue }
            if (-not $byKey.ContainsKey($k)) { $byKey[$k] = New-Object System.Collections.Generic.List[object] }
            [void]$byKey[$k].Add($row)
        }
    }
    $conflicts = New-Object System.Collections.Generic.List[object]
    foreach ($k in $byKey.Keys) {
        $rows = $byKey[$k]
        $policies = @($rows | Select-Object -ExpandProperty PolicyId -Unique)
        if ($policies.Count -lt 2) { continue }
        $values = @($rows | Select-Object -ExpandProperty Value -Unique)
        $flag = if ($values.Count -gt 1) { 'CONFLICT' } else { 'Duplicate' }
        foreach ($r in $rows) {
            # An app-scoped row can participate in several comparisons. A duplicate
            # on one app must not erase a conflict already found on another app.
            if ($flag -eq 'CONFLICT' -or $r.Conflict -ne 'CONFLICT') { $r.Conflict = $flag }
        }
        if ($flag -eq 'CONFLICT') {
            $targetApp = ''
            if ($k -match '^(appcfg|mamcfg|mam):([^:]+):' -and $Matches[2] -ne 'policy') { $targetApp = $Matches[2] }
            [void]$conflicts.Add([pscustomobject]@{
                Key     = $k
                Kind    = 'setting'
                Setting = $rows[0].Setting + $(if ($targetApp) { " (app: $targetApp)" } else { '' })
                TargetApp = $targetApp
                Sources = @($rows | ForEach-Object { [pscustomobject]@{ Policy = $_.PolicyName; PolicyId = $_.PolicyId; Value = $_.Value } })
            })
        }
    }

    # Applications: one entry per app, intent resolved for this device.
    $appResults = New-Object System.Collections.Generic.List[object]
    if (@($Corpus.apps).Count -gt 0) {
        $appStates = @{}
        if (-not $SkipReportedStatus) { $appStates = Get-ReportedAppStates -UserId ([string](Get-Prop $md 'userId')) -IntuneDeviceId $mdId }
        $statusById = @{}
        foreach ($pr in $policyResults) { $statusById[[string]$pr.PolicyId] = $pr.Status }
        $cfgIdx = Get-AppConfigIndex -Corpus $Corpus -StatusById $statusById
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $nA = 0
        $appList = @($Corpus.apps)
        foreach ($a in $appList) {
            $nA++
            if (@($a.Assignments).Count -eq 0) { continue }
            if ($devPlatform -ne 'other' -and $a.Platform -ne 'other' -and $a.Platform -ne $devPlatform) { continue }
            Write-Progress -Id 5 -Activity ("Resolving apps for {0}" -f $mdName) -Status ("{0}/{1}  {2}" -f $nA, $appList.Count, $a.Name) -PercentComplete ([int](100 * $nA / [math]::Max(1, $appList.Count)))
            $r = Get-AppApplicability -App $a -Ctx $ctx
            $touched = ($r.Status -ne 'NotTargeted') -or @($r.Intents | Where-Object { $_.Status -ne 'NotTargeted' }).Count -gt 0
            $rep = $appStates[([string]$a.Id).ToLower()]
            if (-not $touched -and -not $rep) { continue }
            [void]$seen.Add([string]$a.Id)
            [void]$appResults.Add((New-AppEntry -App $a -Result $r -Reported $rep -ConfigPolicies $(if ($cfgIdx.ContainsKey($a.Id)) { $cfgIdx[$a.Id].ToArray() } else { @() })))
        }
        Write-Progress -Id 5 -Activity ("Resolving apps for {0}" -f $mdName) -Completed
        # apps Intune reports an active intent for, that no assignment in the snapshot predicts
        foreach ($k in $appStates.Keys) {
            if ($seen.Contains($k)) { continue }
            $s = $appStates[$k]
            $rk = $script:ReportedIntentMap[[string]$s.Intent]
            if (-not $rk -or $rk -in @('excluded', 'notAvailable')) { continue }
            $knownApp = @($appList | Where-Object { ([string]$_.Id) -ieq $k })[0]
            $stub = [pscustomobject]@{
                Id = $k; Name = $(if ($knownApp) { $knownApp.Name } else { $s.Name }); Type = $(if ($knownApp) { $knownApp.Type } else { '' })
                Platform = $(if ($knownApp) { $knownApp.Platform } else { '' }); Publisher = $(if ($knownApp) { $knownApp.Publisher } else { '' })
                Version = $(if ($knownApp) { $knownApp.Version } else { $s.Version }); Desc = ''; Modified = $(if ($knownApp) { $knownApp.Modified } else { '' })
                Info = $(if ($knownApp) { @($knownApp.Info) } else { @() }); Relationships = $(if ($knownApp) { @($knownApp.Relationships) } else { @() })
            }
            $res = [pscustomobject]@{
                Status = 'ReportedOnly'; EffectiveIntent = $rk; IntentConflict = $false; Intents = @()
                Resolution = 'Intune reports this intent for the device, but no assignment in this snapshot predicts it - check nested / recently changed groups or a dependency / supersedence relationship.'
            }
            $entry = New-AppEntry -App $stub -Result $res -Reported $s -ConfigPolicies @()
            $entry.EffectiveLabel = $script:IntentLabels[$rk]
            [void]$appResults.Add($entry)
        }
        foreach ($ae in $appResults) {
            if (-not $ae.IntentConflict) { continue }
            [void]$conflicts.Add([pscustomobject]@{
                Key     = ("app:{0}" -f $ae.AppId)
                Kind    = 'app'
                Setting = ("App assignment intent: {0}" -f $ae.Name)
                Sources = @($ae.Intents | Where-Object { $_.Status -in @('Applies', 'Overridden', 'FilteredOut', 'Unknown') } | ForEach-Object {
                        [pscustomobject]@{
                            Policy   = ("{0} via {1}" -f $_.Label, $(if ($_.Via) { $_.Via } else { 'assignment' }))
                            PolicyId = ("app:{0}" -f $ae.AppId)
                            Value    = $(if ($_.Status -eq 'Overridden') { "$($_.Label) (overridden)" } else { "$($_.Label) (wins: $($ae.EffectiveLabel))" })
                        } })
            })
        }
    }

    $applied = @($policyResults | Where-Object { $_.Status -eq 'Applies' })
    $appsOn = @($appResults | Where-Object { $_.Status -eq 'Applies' })
    Write-Good ("{0}: {1} policies apply, {2} settings, {3} conflicts, {4} excluded/filtered, {5} apps targeted" -f `
        $mdName, $applied.Count, $settingRows.Count, $conflicts.Count, `
        @($policyResults | Where-Object { $_.Status -in @('Excluded', 'FilteredOut') }).Count, $appsOn.Count)

    $own = [string](Get-Prop $md 'managedDeviceOwnerType'); if (-not $own) { $own = [string](Get-Prop $md 'ownerType') }
    $enr = Format-GraphDate (Get-Prop $md 'enrolledDateTime'); if ($enr.Length -ge 10) { $enr = $enr.Substring(0, 10) }
    $enc = Get-Prop $md 'isEncrypted'
    return [pscustomobject]@{
        Device = [pscustomobject]@{
            Scope           = 'device'
            DeviceName      = $mdName
            SerialNumber    = [string](Get-Prop $md 'serialNumber')
            IntuneDeviceId  = $mdId
            EntraDeviceId   = [string](Get-Prop $md 'azureADDeviceId')
            PrimaryUser     = [string](Get-Prop $md 'userPrincipalName')
            OS              = ("{0} {1}" -f (Get-Prop $md 'operatingSystem'), (Get-Prop $md 'osVersion')).Trim()
            Model           = ("{0} {1}" -f (Get-Prop $md 'manufacturer'), (Get-Prop $md 'model')).Trim()
            LastSync        = Format-GraphDate (Get-Prop $md 'lastSyncDateTime')
            Compliance      = (ConvertTo-FriendlyName ([string](Get-Prop $md 'complianceState')))
            JoinType        = (ConvertTo-FriendlyName ([string](Get-Prop $md 'joinType')))
            Ownership       = (ConvertTo-FriendlyName $own)
            Enrolled        = $enr
            EnrollmentType  = (ConvertTo-FriendlyName ([string](Get-Prop $md 'deviceEnrollmentType')))
            EnrollmentProfile = [string](Get-Prop $md 'enrollmentProfileName')
            ManagementAgent = (ConvertTo-FriendlyName ([string](Get-Prop $md 'managementAgent')))
            Encrypted       = $(if ($null -eq $enc) { '' } elseif ($enc) { 'Yes' } else { 'No' })
            Autopilot       = $apText
            DeviceGroups    = @($ctx.DeviceGroupIds | ForEach-Object { Get-GroupName $_ } | Sort-Object)
            UserGroups      = @($ctx.UserGroupIds | ForEach-Object { Get-GroupName $_ } | Sort-Object)
        }
        Policies  = @($policyResults | Sort-Object @{e = { $_.Status -ne 'Applies' } }, FamilyLabel, Name)
        Settings  = @($settingRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Conflicts = @($conflicts | Sort-Object Setting)
        Shadow    = @($shadowRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Apps      = @($appResults | Sort-Object Name)
    }
}

function Get-GroupAssignedRsop {
    # -GroupAssignedOnly: which policies and apps directly reference this group (no device math).
    param($GroupObj, $Corpus)

    $gid = [string]$GroupObj.id
    $gname = [string]$GroupObj.displayName
    $policyResults = New-Object System.Collections.Generic.List[object]
    $settingRows = New-Object System.Collections.Generic.List[object]
    $hitFor = {
        param($a)
        if ([string]$a.GroupId -ne $gid) { return [pscustomobject]@{ Hit = ''; Note = '' } }
        if ($a.Type -like '*exclusion*') { return [pscustomobject]@{ Hit = 'excluding'; Note = 'This group is excluded' } }
        return [pscustomobject]@{ Hit = 'applies'; Note = 'Assigned to this group' }
    }.GetNewClosure()

    foreach ($p in @($Corpus.policies)) {
        foreach ($a in @($p.Assignments)) {
            if ([string]$a.GroupId -ne $gid) { continue }
            $isExcl = ($a.Type -like '*exclusion*')
            $fnote = ''
            $fn = Get-AssignmentFilterName -Assignment $a
            if ($fn) { $fnote = (" + {0} filter '{1}'" -f $a.FilterType, $fn) }
            $status = if ($isExcl) { 'Excluded' } else { 'Applies' }
            $via = $(if ($isExcl) { "Group '$gname' is EXCLUDED$fnote" } else { "Assigned to group '$gname'$fnote" })
            [void]$policyResults.Add((New-PolicyEntry -Policy $p -Status $status -Via $via -Hits @(@($p.Assignments) | ForEach-Object { & $hitFor $_ })))
            if (-not $isExcl) {
                foreach ($s in @($p.Settings)) { [void]$settingRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName $p.Name -Via $via)) }
            }
            break
        }
    }

    $appResults = New-Object System.Collections.Generic.List[object]
    $cfgIdx = Get-AppConfigIndex -Corpus $Corpus
    foreach ($a in @($Corpus.apps)) {
        $mine = @(@($a.Assignments) | Where-Object { [string]$_.GroupId -eq $gid })
        if ($mine.Count -eq 0) { continue }
        $inc = @($mine | Where-Object { $_.Type -notlike '*exclusion*' })
        $ints = @($inc | ForEach-Object { $script:IntentLabels[[string]$_.Intent] } | Select-Object -Unique)
        $res = [pscustomobject]@{
            Status = $(if ($inc.Count) { 'Assigned' } else { 'Excluded' }); EffectiveIntent = $(if ($inc.Count -eq 1) { [string]$inc[0].Intent } else { '' })
            IntentConflict = $false; Intents = (Get-AppIntentSkeleton -App $a -HitFor $hitFor)
            Resolution = $(if ($inc.Count) { "Group '$gname' is assigned as: " + ($ints -join ', ') } else { "Group '$gname' is excluded" })
        }
        $e = New-AppEntry -App $a -Result $res -Reported $null -ConfigPolicies $(if ($cfgIdx.ContainsKey($a.Id)) { $cfgIdx[$a.Id].ToArray() } else { @() })
        if ($inc.Count) { $e.EffectiveLabel = ($ints -join ' + ') }
        [void]$appResults.Add($e)
    }

    return [pscustomobject]@{
        Device = [pscustomobject]@{
            Scope = 'group'
            DeviceName = "GROUP: $gname"; SerialNumber = ''; IntuneDeviceId = ''; EntraDeviceId = $gid
            PrimaryUser = ''; OS = '(policies and apps directly assigned to this group)'; Model = ''; LastSync = ''
            DeviceGroups = @(); UserGroups = @()
        }
        Policies  = @($policyResults | Sort-Object Status, FamilyLabel, Name)
        Settings  = @($settingRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Conflicts = @()
        Shadow    = @()
        Apps      = @($appResults | Sort-Object Name)
    }
}

function Test-InventoryScope {
    # -All scoping for one set of assignments: does it reach the scope group (directly, via a
    # parent group, or All devices / All users) and/or carry the scope filter?
    # Returns $null when out of scope, else @{ InScope; Reason; Hits }.
    param($Assignments, $ScopeGroup, $ScopeFilter)
    $asg = @($Assignments)
    $inc = New-Object System.Collections.Generic.List[string]
    $exc = New-Object System.Collections.Generic.List[string]
    $fhits = New-Object System.Collections.Generic.List[string]
    $filterOnInclude = $false
    $hits = New-HitArray -Count $asg.Count
    for ($i = 0; $i -lt $asg.Count; $i++) {
        $a = $asg[$i]
        $isExcl = ([string]$a.Type -like '*exclusionGroupAssignmentTarget*')
        $target = ''
        switch -Wildcard ([string]$a.Type) {
            '*allDevicesAssignmentTarget*'       { $target = 'All devices'; break }
            '*allLicensedUsersAssignmentTarget*' { $target = 'All users'; break }
            '*GroupAssignmentTarget*'            { if ($a.GroupId) { $target = ("group '{0}'" -f (Get-GroupName $a.GroupId)) }; break }
        }
        $fnote = ''
        $fn = Get-AssignmentFilterName -Assignment $a
        if ($fn) { $fnote = (" [{0} filter: {1}]" -f $a.FilterType, $fn) }
        $ipfx = $(if ($a.Intent) { "$($script:IntentLabels[[string]$a.Intent]): " } else { '' })

        if ($null -ne $ScopeFilter -and [string]$a.FilterId -ieq [string]$ScopeFilter.Id) {
            [void]$fhits.Add(("{0}uses {1} filter '{2}' on {3}" -f $ipfx, $a.FilterType, $ScopeFilter.Name, $(if ($target) { $target } else { '(unknown target)' })))
            if (-not $isExcl) { $filterOnInclude = $true; $hits[$i] = [pscustomobject]@{ Hit = 'applies'; Note = 'Carries the scope filter' } }
        }
        if ($null -ne $ScopeGroup) {
            if ($a.GroupId) {
                $how = ''
                if ([string]$a.GroupId -ieq [string]$ScopeGroup.Id) { $how = ("group '{0}'" -f $ScopeGroup.Name) }
                elseif ($ScopeGroup.Parents.ContainsKey([string]$a.GroupId)) { $how = ("parent group '{0}'" -f $ScopeGroup.Parents[[string]$a.GroupId]) }
                if ($how) {
                    if ($isExcl) { [void]$exc.Add(("{0}EXCLUDED via {1}" -f $ipfx, $how)); $hits[$i] = [pscustomobject]@{ Hit = 'excluding'; Note = "Excludes the scope ($how)" } }
                    else { [void]$inc.Add(("{0}assigned to {1}{2}" -f $ipfx, $how, $fnote)); $hits[$i] = [pscustomobject]@{ Hit = 'applies'; Note = "Reaches the scope ($how)" } }
                }
            }
            elseif (-not $isExcl -and ($target -eq 'All devices' -or $target -eq 'All users')) {
                [void]$inc.Add(("{0}{1} (tenant-wide){2}" -f $ipfx, $target, $fnote))
                $hits[$i] = [pscustomobject]@{ Hit = 'applies'; Note = 'Tenant-wide assignment reaches the scope' }
            }
        }
    }
    $groupOk = ($null -eq $ScopeGroup) -or ($inc.Count -gt 0 -or $exc.Count -gt 0)
    $filterOk = ($null -eq $ScopeFilter) -or ($fhits.Count -gt 0)
    if (-not ($groupOk -and $filterOk)) { return $null }
    $inScope = $true
    if ($null -ne $ScopeGroup) { $inScope = ($inc.Count -gt 0) }
    elseif ($null -ne $ScopeFilter) { $inScope = $filterOnInclude }
    return [pscustomobject]@{ InScope = $inScope; Reason = ((@($inc) + @($exc) + @($fhits)) -join '; '); Hits = $hits }
}

function Get-TenantInventoryRsop {
    # -All: every policy (and assigned app) in the tenant with its settings and an assignment
    # summary. No device math and no conflict detection (policies target different devices).
    # -ScopeGroup / -ScopeFilter narrow the inventory to what reaches the group (directly, via
    # a parent group, or All devices / All users) and/or carries the filter, each with the
    # reason spelled out. Policies that only EXCLUDE the scope stay visible as Excluded.
    param($Corpus, $ScopeGroup, $ScopeFilter)

    # resolve every group name referenced anywhere, once
    $allGids = New-Object System.Collections.Generic.List[string]
    foreach ($p in @(@($Corpus.policies) + @($Corpus.apps))) {
        foreach ($a in @($p.Assignments)) { if ($a.GroupId) { [void]$allGids.Add([string]$a.GroupId) } }
    }
    Resolve-GroupNames -Ids $allGids.ToArray()

    $scoped = ($null -ne $ScopeGroup -or $null -ne $ScopeFilter)
    $policyResults = New-Object System.Collections.Generic.List[object]
    $settingRows = New-Object System.Collections.Generic.List[object]
    $shadowRows = New-Object System.Collections.Generic.List[object]

    foreach ($p in @($Corpus.policies)) {
        $summary = ConvertTo-AssignmentSummary -Assignments $p.Assignments
        $assigned = ($summary -ne 'Not assigned')
        $status = $(if ($assigned) { 'Assigned' } else { 'NotAssigned' })
        $via = $summary
        $hits = $null
        if ($scoped) {
            $sc = Test-InventoryScope -Assignments $p.Assignments -ScopeGroup $ScopeGroup -ScopeFilter $ScopeFilter
            if ($null -eq $sc) { continue }   # out of scope -> dropped
            $status = $(if ($sc.InScope) { 'Assigned' } else { 'Excluded' })
            $via = ("Scope: {0}  |  {1}" -f $sc.Reason, $summary)
            $hits = $sc.Hits
        }
        [void]$policyResults.Add((New-PolicyEntry -Policy $p -Status $status -Via $via -Hits $hits))

        if ($status -eq 'Excluded') {
            # scope-excluded: keep the settings inspectable via Investigate's rule-out list
            foreach ($s in @($p.Settings)) { [void]$shadowRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName $p.Name -Via $via -Status 'Excluded')) }
            continue
        }
        $tag = $(if ($status -eq 'NotAssigned') { ' [not assigned]' } else { '' })
        foreach ($s in @($p.Settings)) { [void]$settingRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName ($p.Name + $tag) -Via $via)) }
    }

    $appResults = New-Object System.Collections.Generic.List[object]
    $cfgIdx = Get-AppConfigIndex -Corpus $Corpus
    foreach ($a in @($Corpus.apps)) {
        if (@($a.Assignments).Count -eq 0) { continue }
        $status = 'Assigned'; $reason = ''; $hits = $null
        if ($scoped) {
            $sc = Test-InventoryScope -Assignments $a.Assignments -ScopeGroup $ScopeGroup -ScopeFilter $ScopeFilter
            if ($null -eq $sc) { continue }
            $status = $(if ($sc.InScope) { 'Assigned' } else { 'Excluded' })
            $reason = "Scope: " + $sc.Reason
            $hits = $sc.Hits
        }
        $hitList = @($hits)
        $asgList = @($a.Assignments)
        $hitFor = $(if ($hits) { { param($x) $ix = [array]::IndexOf($asgList, $x); if ($ix -ge 0) { $hitList[$ix] } else { [pscustomobject]@{ Hit = ''; Note = '' } } }.GetNewClosure() } else { $null })
        $res = [pscustomobject]@{
            Status = $status; EffectiveIntent = ''; IntentConflict = $false
            Intents = (Get-AppIntentSkeleton -App $a -HitFor $hitFor); Resolution = $reason
        }
        $e = New-AppEntry -App $a -Result $res -Reported $null -ConfigPolicies $(if ($cfgIdx.ContainsKey($a.Id)) { $cfgIdx[$a.Id].ToArray() } else { @() })
        $e.EffectiveLabel = ((@($res.Intents | ForEach-Object { $script:IntentLabels[$_.Intent] })) -join ' / ')
        [void]$appResults.Add($e)
    }

    # Counts come straight off the List/array .Count (pwsh 7.6 throws on @($genericList).Count).
    $totalPolicies = @($Corpus.policies).Count
    $assignedCount = @($policyResults | Where-Object { $_.Status -eq 'Assigned' }).Count
    $name = 'TENANT-WIDE INVENTORY'
    $osLine = ("{0} policies ({1} assigned, {2} unassigned) · {3} assigned apps" -f $totalPolicies, $assignedCount, ($totalPolicies - $assignedCount), $appResults.Count)
    if ($scoped) {
        $bits = @()
        if ($null -ne $ScopeGroup) { $bits += ("group '{0}'" -f $ScopeGroup.Name) }
        if ($null -ne $ScopeFilter) { $bits += ("filter '{0}'" -f $ScopeFilter.Name) }
        $inScopeCount = $policyResults.Count
        $excCount = @($policyResults | Where-Object { $_.Status -eq 'Excluded' }).Count
        $name = 'TENANT INVENTORY (scoped)'
        $osLine = ("scope {0}: {1} of {2} policies in scope ({3} apply, {4} exclude it) · {5} apps in scope" -f `
            ($bits -join ' + '), $inScopeCount, $totalPolicies, $assignedCount, $excCount, $appResults.Count)
    }
    return [pscustomobject]@{
        Device = [pscustomobject]@{
            Scope = 'tenant'
            DeviceName = $name; SerialNumber = ''; IntuneDeviceId = ''; EntraDeviceId = ''
            PrimaryUser = ''
            OS = $osLine
            Model = ''; LastSync = ''; DeviceGroups = @(); UserGroups = @()
        }
        Policies  = @($policyResults | Sort-Object Status, FamilyLabel, Name)
        Settings  = @($settingRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Conflicts = @()
        Shadow    = @($shadowRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Apps      = @($appResults | Sort-Object Name)
    }
}

#endregion

#region ---------- output: console / csv / json / html ---------------------------------------

function Show-ConsoleSummary {
    param($Result)
    $d = $Result.Device
    Write-Host ""
    Write-Host ("DEVICE  {0}" -f $d.DeviceName) -ForegroundColor White
    Write-Host ("        serial {0} | {1} | {2} | user {3}" -f $d.SerialNumber, $d.OS, $d.Model, $d.PrimaryUser) -ForegroundColor DarkGray
    $applied  = @($Result.Policies | Where-Object { $_.Status -in @('Applies', 'Assigned') })
    $excluded = @($Result.Policies | Where-Object { $_.Status -in @('Excluded', 'FilteredOut', 'NotAssigned') })
    $unknown  = @($Result.Policies | Where-Object { $_.Status -in @('Unknown', 'ReportedOnly') })
    Write-Host ("        {0} policies apply | {1} settings | {2} conflicts | {3} excluded/filtered | {4} unknown/reported-only" -f `
        $applied.Count, @($Result.Settings).Count, @($Result.Conflicts).Count, $excluded.Count, $unknown.Count) -ForegroundColor White

    if ($applied.Count -gt 0) {
        $tbl = $applied | Select-Object @{n = 'Policy'; e = { $_.Name } },
            @{n = 'Type'; e = { $_.FamilyLabel } },
            @{n = 'Settings'; e = { $_.SettingCount } },
            @{n = 'Reported'; e = { $_.Reported } },
            @{n = 'Applies via'; e = { $_.Via } } |
            Format-Table -AutoSize -Wrap | Out-String -Width 300
        Write-Host $tbl
    }
    foreach ($x in $excluded) {
        Write-Host ("   EXCLUDED: {0}  <- {1}" -f $x.Name, $x.Via) -ForegroundColor Yellow
    }
    foreach ($x in $unknown) {
        Write-Host ("   {0}: {1}  <- {2}" -f $x.Status.ToUpper(), $x.Name, $x.Via) -ForegroundColor Magenta
    }
    if (@($Result.Conflicts).Count -gt 0) {
        Write-Host ("   CONFLICTS ({0}):" -f @($Result.Conflicts).Count) -ForegroundColor Red
        foreach ($c in $Result.Conflicts) {
            Write-Host ("     - {0}" -f $c.Setting) -ForegroundColor Red
            foreach ($s in $c.Sources) { Write-Host ("         {0}  =>  {1}" -f $s.Policy, $s.Value) -ForegroundColor DarkYellow }
        }
    }
    $apps = @($Result.Apps)
    if ($apps.Count -gt 0) {
        $on = @($apps | Where-Object { $_.Status -eq 'Applies' })
        $cnt = { param($k) @($on | Where-Object { $_.EffectiveIntent -eq $k -or ($k -in @('required', 'available') -and $_.EffectiveIntent -eq 'requiredAndAvailable') }).Count }
        if ($d.Scope -eq 'device') {
            Write-Host ("   APPS: {0} targeted - {1} required, {2} available, {3} uninstall; {4} intent conflict(s); {5} excluded/filtered" -f `
                $on.Count, (& $cnt 'required'), (& $cnt 'available'), (& $cnt 'uninstall'), @($apps | Where-Object { $_.IntentConflict }).Count,
                @($apps | Where-Object { $_.Status -in @('Excluded', 'FilteredOut') }).Count) -ForegroundColor White
            foreach ($a in @($on | Where-Object { $_.EffectiveIntent -eq 'uninstall' })) {
                Write-Host ("   UNINSTALL: {0}  <- {1}" -f $a.Name, $a.Resolution) -ForegroundColor Yellow
            }
            foreach ($a in @($apps | Where-Object { $_.IntentConflict })) {
                Write-Host ("   APP INTENT CONFLICT: {0} -> {1}  ({2})" -f $a.Name, $a.EffectiveLabel, $a.Resolution) -ForegroundColor Magenta
            }
            foreach ($a in @($apps | Where-Object { $_.Reported -and $_.Reported.Mismatch })) {
                if ($a.Status -eq 'ReportedOnly') {
                    Write-Host ("   ASSIGNMENT NOT FOUND IN SNAPSHOT: {0} - Intune reports {1} ({2})" -f $a.Name, $a.Reported.Intent, $a.Reported.InstallState) -ForegroundColor Magenta
                }
                else {
                    Write-Host ("   DEVICE REPORTS DIFFERENT INTENT: {0} - predicted {1}, Intune reports {2} ({3})" -f $a.Name, $a.EffectiveLabel, $a.Reported.Intent, $a.Reported.InstallState) -ForegroundColor Magenta
                }
            }
        }
        else {
            Write-Host ("   APPS: {0} in this view" -f $apps.Count) -ForegroundColor White
        }
    }
}

function Get-CsvRows {
    param($Results)
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in @($Results)) {
        $reportedByPolicy = @{}
        $intentByPolicy = @{}
        foreach ($p in @($r.Policies)) {
            $reportedByPolicy[[string]$p.PolicyId] = [string]$p.Reported
            $intentByPolicy[[string]$p.PolicyId] = [string]$p.Intent
        }
        foreach ($s in @($r.Settings)) {
            $rep = ''
            if ($reportedByPolicy.ContainsKey([string]$s.PolicyId)) { $rep = $reportedByPolicy[[string]$s.PolicyId] }
            $int = ''
            if ($intentByPolicy.ContainsKey([string]$s.PolicyId)) { $int = $intentByPolicy[[string]$s.PolicyId] }
            [void]$rows.Add([pscustomobject]@{
                DeviceName     = $r.Device.DeviceName
                SerialNumber   = $r.Device.SerialNumber
                PolicyType     = $s.FamilyLabel
                AssignmentIntent = $int
                PolicyName     = $s.PolicyName
                Category       = [string]$s.Category
                Setting        = $s.Setting
                Value          = $s.Value
                Conflict       = $s.Conflict
                AppliesVia     = [string]$s.Via
                PolicyReported = $rep
                PolicyId       = $s.PolicyId
                SettingKey     = $s.Key
            })
        }
        # one row per app: the resolved intent, plus each intent's targets
        foreach ($a in @($r.Apps)) {
            $targets = @($a.Intents | ForEach-Object {
                    $t = @($_.Targets | ForEach-Object { "{0} {1}{2}" -f $_.Mode, $_.Target, $(if ($_.Filter) { " [$($_.FilterMode) filter: $($_.Filter)]" } else { '' }) })
                    "{0}: {1}" -f $_.Label, ($t -join '; ')
                })
            [void]$rows.Add([pscustomobject]@{
                DeviceName       = $r.Device.DeviceName
                SerialNumber     = $r.Device.SerialNumber
                PolicyType       = ("App - {0}" -f $a.Type)
                AssignmentIntent = $a.EffectiveLabel
                PolicyName       = $a.Name
                Category         = 'App assignment'
                Setting          = 'Resolved assignment intent'
                Value            = $a.EffectiveLabel
                Conflict         = $(if ($a.IntentConflict) { 'INTENT CONFLICT' } else { '' })
                AppliesVia       = ((@($a.Resolution) + $targets) -join ' | ')
                PolicyReported   = $(if ($a.Reported) { "{0} / {1}" -f $a.Reported.Intent, $a.Reported.InstallState } else { '' })
                PolicyId         = $a.AppId
                SettingKey       = ("app:{0}" -f $a.AppId)
            })
        }
    }
    return $rows.ToArray()
}

$script:HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f6f7f9;--card:#ffffff;--ink:#1a1f2b;--muted:#68707f;--line:#e3e6ea;--accent:#2458d6;
--chip:#eef1f5;--red:#c62f2f;--redbg:#fdecec;--amber:#9a6700;--amberbg:#fff3d6;--green:#1a7f37;--greenbg:#e9f7ee;}
@media (prefers-color-scheme: dark){:root{--bg:#12141a;--card:#1b1e27;--ink:#e8eaf0;--muted:#9aa2b1;--line:#2a2f3b;
--accent:#7aa2ff;--chip:#252a36;--red:#ff7b7b;--redbg:#3a2020;--amber:#e3b341;--amberbg:#3a3120;--green:#57d38c;--greenbg:#1d3327;}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink);padding:24px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--muted);margin-bottom:18px;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
select,input[type=text]{background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:14px;min-width:200px}
input[type=text]{flex:1;min-width:240px}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 0}
.stat{background:var(--chip);border-radius:8px;padding:8px 14px;font-size:13px}
.stat b{font-size:16px;display:block}
.tabs{display:flex;gap:4px;margin:16px 0 0;border-bottom:1px solid var(--line)}
.tab{padding:8px 16px;cursor:pointer;border:none;background:none;color:var(--muted);font-size:14px;border-bottom:2px solid transparent}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);font-weight:600}
.tblwrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th{position:sticky;top:0;background:var(--card);text-align:left;padding:8px 10px;border-bottom:2px solid var(--line);color:var(--muted);font-weight:600;white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
tr:hover td{background:var(--chip)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;white-space:nowrap}
.b-conflict{background:var(--redbg);color:var(--red)}
.b-dup{background:var(--chip);color:var(--muted)}
.b-applies{background:var(--greenbg);color:var(--green)}
.b-excluded{background:var(--redbg);color:var(--red)}
.b-other{background:var(--amberbg);color:var(--amber)}
.small{color:var(--muted);font-size:12px}
.btn{background:var(--accent);color:#fff;border:none;border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
label.chk{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:13px;white-space:nowrap}
.conf-card{border:1px solid var(--line);border-left:4px solid var(--red);border-radius:8px;padding:10px 14px;margin-bottom:10px}
.conf-card h3{margin:0 0 6px;font-size:14px}
.conf-src{display:flex;justify-content:space-between;gap:16px;padding:3px 0;font-size:13px;border-top:1px dashed var(--line)}
.groups{font-size:12px;color:var(--muted);margin-top:6px}
mark{background:var(--amberbg);color:inherit;border-radius:3px}
</style>
</head>
<body>
<h1>🔍 Intune Lens</h1>
<div class="sub">Query: __QUERY__ &middot; Generated by __ACCOUNT__ on __GENERATED__ &middot; v__VERSION__</div>

<div class="card">
  <div class="row">
    <select id="devSel"></select>
    <input type="text" id="q" placeholder="Search settings, values, policies...">
    <select id="famSel"><option value="">All policy types</option></select>
    <label class="chk"><input type="checkbox" id="confOnly"> conflicts only</label>
    <button class="btn" id="csvBtn">Download CSV</button>
  </div>
  <div class="stats" id="stats"></div>
  <div class="groups" id="groups"></div>
  <div class="tabs">
    <button class="tab active" data-tab="settings">Settings</button>
    <button class="tab" data-tab="policies">Policies</button>
    <button class="tab" data-tab="apps">Apps</button>
    <button class="tab" data-tab="conflicts">Conflicts</button>
  </div>
</div>

<div class="card" id="pane-settings">
  <div class="tblwrap"><table id="tblSettings">
    <thead><tr><th>Setting</th><th>Value</th><th>Policy</th><th>Type</th><th></th></tr></thead>
    <tbody></tbody>
  </table></div>
  <div class="small" id="rowCount"></div>
</div>

<div class="card" id="pane-policies" style="display:none">
  <div class="tblwrap"><table id="tblPolicies">
    <thead><tr><th>Status</th><th>Policy</th><th>Type</th><th>#Settings</th><th>Device reported</th><th>Applies via</th></tr></thead>
    <tbody></tbody>
  </table></div>
</div>

<div class="card" id="pane-apps" style="display:none">
  <div class="tblwrap"><table id="tblApps">
    <thead><tr><th>App</th><th>Type</th><th>Resolved intent</th><th>Assignments by intent</th><th>Why</th></tr></thead>
    <tbody></tbody>
  </table></div>
</div>

<div class="card" id="pane-conflicts" style="display:none"><div id="confList"></div></div>

<script>
const DATA = __DATA__;
let cur = 0;

const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function init(){
  const sel = document.getElementById("devSel");
  DATA.devices.forEach((d,i)=>{
    const o=document.createElement("option");
    o.value=i; o.textContent=d.Device.DeviceName + (d.Device.SerialNumber? " ("+d.Device.SerialNumber+")":"");
    sel.appendChild(o);
  });
  sel.onchange = ()=>{cur=parseInt(sel.value); buildFamilies(); render();};
  document.getElementById("q").oninput = render;
  document.getElementById("famSel").onchange = render;
  document.getElementById("confOnly").onchange = render;
  document.getElementById("csvBtn").onclick = downloadCsv;
  document.querySelectorAll(".tab").forEach(t=>{
    t.onclick=()=>{
      document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));
      t.classList.add("active");
      ["settings","policies","apps","conflicts"].forEach(p=>{
        document.getElementById("pane-"+p).style.display = (t.dataset.tab===p) ? "" : "none";
      });
    };
  });
  buildFamilies(); render();
}

function buildFamilies(){
  const d = DATA.devices[cur];
  const fams = [...new Set(d.Settings.map(s=>s.FamilyLabel))].sort();
  const sel = document.getElementById("famSel");
  sel.innerHTML = '<option value="">All policy types</option>';
  fams.forEach(f=>{const o=document.createElement("option");o.value=f;o.textContent=f;sel.appendChild(o);});
}

function render(){
  const d = DATA.devices[cur];
  const q = document.getElementById("q").value.toLowerCase();
  const fam = document.getElementById("famSel").value;
  const confOnly = document.getElementById("confOnly").checked;

  const applied = d.Policies.filter(p=>p.Status==="Applies").length;
  const excl = d.Policies.filter(p=>p.Status==="Excluded"||p.Status==="FilteredOut").length;
  document.getElementById("stats").innerHTML =
    '<div class="stat"><b>'+applied+'</b>policies apply</div>'+
    '<div class="stat"><b>'+d.Settings.length+'</b>settings</div>'+
    '<div class="stat"><b>'+d.Conflicts.length+'</b>conflicts</div>'+
    '<div class="stat"><b>'+excl+'</b>excluded / filtered out</div>';

  const g = d.Device;
  document.getElementById("groups").innerHTML =
    (g.OS? esc(g.OS)+" &middot; " : "") + (g.PrimaryUser? "user "+esc(g.PrimaryUser)+" &middot; ":"") +
    (g.DeviceGroups && g.DeviceGroups.length ? "device groups: "+esc(g.DeviceGroups.join(", ")) : "") +
    (g.UserGroups && g.UserGroups.length ? " &middot; user groups: "+esc(g.UserGroups.join(", ")) : "");

  // settings table
  const tb = document.querySelector("#tblSettings tbody");
  const frag = document.createDocumentFragment();
  let shown = 0;
  d.Settings.forEach(s=>{
    if (fam && s.FamilyLabel!==fam) return;
    if (confOnly && s.Conflict!=="CONFLICT") return;
    if (q){
      const hay = (s.Setting+" "+s.Value+" "+s.PolicyName+" "+s.FamilyLabel).toLowerCase();
      if (!hay.includes(q)) return;
    }
    shown++;
    const tr = document.createElement("tr");
    let badge = "";
    if (s.Conflict==="CONFLICT") badge = '<span class="badge b-conflict">CONFLICT</span>';
    else if (s.Conflict==="Duplicate") badge = '<span class="badge b-dup">dup</span>';
    tr.innerHTML = "<td>"+esc(s.Setting)+"</td><td>"+esc(s.Value)+"</td><td>"+esc(s.PolicyName)+
      "</td><td class='small'>"+esc(s.FamilyLabel)+"</td><td>"+badge+"</td>";
    frag.appendChild(tr);
  });
  tb.innerHTML=""; tb.appendChild(frag);
  document.getElementById("rowCount").textContent = shown+" of "+d.Settings.length+" settings shown";

  // policies table (same search + type filter as the settings table)
  const pb = document.querySelector("#tblPolicies tbody");
  const pf = document.createDocumentFragment();
  d.Policies.forEach(p=>{
    if (fam && p.FamilyLabel!==fam) return;
    if (q){
      const hay = (p.Name+" "+p.FamilyLabel+" "+(p.Intent||"")+" "+p.Via).toLowerCase();
      if (!hay.includes(q)) return;
    }
    const tr=document.createElement("tr");
    let cls="b-other";
    if(p.Status==="Applies"||p.Status==="Assigned")cls="b-applies"; else if(p.Status==="Excluded"||p.Status==="FilteredOut")cls="b-excluded";
    tr.innerHTML="<td><span class='badge "+cls+"'>"+esc(p.Status)+"</span></td><td>"+esc(p.Name)+(p.Intent?" <span class='small'>("+esc(p.Intent)+")</span>":"")+"</td><td class='small'>"+
      esc(p.FamilyLabel)+"</td><td>"+esc(p.SettingCount)+"</td><td class='small'>"+esc(p.Reported||"")+"</td><td class='small'>"+esc(p.Via)+"</td>";
    pf.appendChild(tr);
  });
  pb.innerHTML=""; pb.appendChild(pf);

  // apps (one row per app, resolved intent)
  const ab = document.querySelector("#tblApps tbody");
  ab.innerHTML = (d.Apps||[]).filter(a=>!q||(a.Name+" "+a.Type+" "+a.EffectiveLabel+" "+(a.Resolution||"")).toLowerCase().includes(q)).map(a=>
    "<tr><td>"+esc(a.Name)+"</td><td class='small'>"+esc(a.Type)+"</td><td><b>"+esc(a.EffectiveLabel)+"</b>"+(a.IntentConflict?" <span class='badge b-conflict'>intent conflict</span>":"")+
    "</td><td class='small'>"+(a.Intents||[]).map(i=>esc(i.Label)+": "+esc((i.Targets||[]).map(t=>t.Mode+" "+t.Target).join(", "))).join("<br>")+"</td><td class='small'>"+esc(a.Resolution||"")+"</td></tr>").join("");

  // conflicts
  const cl = document.getElementById("confList");
  if(!d.Conflicts.length){ cl.innerHTML = '<div class="small">No conflicting values among applicable policies. Note: conflicts are matched per setting key; the same OS setting delivered via different policy families (e.g. ADMX vs Settings Catalog) cannot always be correlated.</div>'; }
  else {
    cl.innerHTML = d.Conflicts.map(c=>
      '<div class="conf-card"><h3>'+esc(c.Setting)+'</h3>'+
      c.Sources.map(s=>'<div class="conf-src"><span>'+esc(s.Policy)+'</span><b>'+esc(s.Value)+'</b></div>').join("")+
      '</div>').join("");
  }
}

function downloadCsv(){
  const d = DATA.devices[cur];
  const q = v => '"'+String(v==null?"":v).replace(/"/g,'""')+'"';
  let csv = "DeviceName,SerialNumber,PolicyName,PolicyType,Setting,Value,Conflict\r\n";
  d.Settings.forEach(s=>{
    csv += [q(d.Device.DeviceName),q(d.Device.SerialNumber),q(s.PolicyName),q(s.FamilyLabel),q(s.Setting),q(s.Value),q(s.Conflict)].join(",")+"\r\n";
  });
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv"}));
  a.download="IntuneLens-"+(d.Device.SerialNumber||d.Device.DeviceName).replace(/[^a-z0-9-]/gi,"_")+".csv";
  a.click();
}

init();
</script>
</body>
</html>
'@

function Export-HtmlReport {
    param($Results, [string]$Path, [string]$QueryLabel, [string]$Tenant, [string]$Account)

    # Accept only a template with the expected schema marker and required placeholders.
    # An incompatible adjacent file must not silently generate a broken rich report.
    $templatePath = $script:HtmlTemplatePath
    if (-not $templatePath) { $templatePath = Join-Path $PSScriptRoot 'report-template.html' }
    $html = $script:HtmlTemplate
    if (Test-Path $templatePath) {
        $candidate = Get-Content -Raw -Path $templatePath
        $schemaMarker = '<meta name="intune-lens-template-schema" content="{0}">' -f $script:TemplateSchema
        if ($candidate.Contains($schemaMarker) -and $candidate.Contains('__DATA__') -and $candidate.Contains('__TITLE__')) {
            $html = $candidate
        }
        else {
            Add-RunLog -Level warn -Message ("report-template.html is incompatible with template schema {0}; using the basic built-in layout." -f $script:TemplateSchema)
        }
    }
    else {
        Add-RunLog -Level warn -Message 'report-template.html not found next to the script; using the basic built-in layout.'
    }

    $payload = [pscustomobject]@{
        query     = $QueryLabel
        generated = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        tenant    = $Tenant
        account   = $Account
        version   = $script:Version
        warnings  = $script:RunLog.ToArray()
        devices   = @($Results)
    }
    $json = $payload | ConvertTo-Json -Depth 12 -Compress
    $json = $json.Replace('</', '<\/')

    $html = $html.Replace('__DATA__', $json)
    $safeTitle = [System.Net.WebUtility]::HtmlEncode(("Intune Lens - " + $QueryLabel))
    $html = $html.Replace('__TITLE__', $safeTitle)
    $html = $html.Replace('__QUERY__', [System.Net.WebUtility]::HtmlEncode($QueryLabel))
    $html = $html.Replace('__GENERATED__', (Get-Date).ToString('dd-MM-yyyy'))
    $html = $html.Replace('__ACCOUNT__', [System.Net.WebUtility]::HtmlEncode($(if ($Account) { $Account } else { 'unknown account' })))
    $html = $html.Replace('__VERSION__', $script:Version)
    Set-Content -Path $Path -Value $html -Encoding UTF8
    Write-Good ("HTML report: {0}" -f (Resolve-Path $Path))
}

#endregion

#region ---------- main -----------------------------------------------------------------------

function Resolve-GroupIdentity {
    # Group picker object / object id / display name -> @{ id; displayName } (or $null).
    param($Value)
    if ($Value -is [System.Collections.IDictionary] -or ($Value.PSObject -and (Get-Prop $Value 'id'))) {
        return [pscustomobject]@{ id = [string](Get-Prop $Value 'id'); displayName = [string](Get-Prop $Value 'displayName') }
    }
    $guid = [guid]::Empty
    if ([guid]::TryParse([string]$Value, [ref]$guid)) {
        $g = Invoke-Rsop -Uri ("v1.0/groups/{0}?`$select=id,displayName" -f $Value)
        return [pscustomobject]@{ id = [string](Get-Prop $g 'id'); displayName = [string](Get-Prop $g 'displayName') }
    }
    $esc = [string]$Value -replace "'", "''"
    $resp = Invoke-Rsop -Uri ("v1.0/groups?`$filter=displayName eq '{0}'&`$select=id,displayName" -f $esc)
    $vals = @($resp['value'])
    if ($vals.Count -gt 1) {
        $matches = @($vals | ForEach-Object { "{0} ({1})" -f $_['displayName'], $_['id'] }) -join '; '
        throw "Multiple groups are named '$Value'. Re-run with the required object id. Matches: $matches"
    }
    if ($vals.Count -eq 0) { return $null }
    return [pscustomobject]@{ id = [string]$vals[0]['id']; displayName = [string]$vals[0]['displayName'] }
}

function Resolve-QueryResults {
    # Shared by CLI flags and the interactive menu. Returns @{ Label; Results }.
    param([string]$Mode, $Corpus, $Value, [bool]$AssignedOnly = $false)

    $results = New-Object System.Collections.Generic.List[object]
    $label = ''

    switch ($Mode) {
        'serial' {
            $label = "Serial: " + (@($Value) -join ', ')
            foreach ($sn in @($Value)) {
                $hits = Find-ManagedDevices -By serialNumber -Value $sn.Trim()
                if (@($hits).Count -eq 0) { Write-Warn2 ("No managed device found with serial '{0}'" -f $sn); continue }
                $md = Select-BestEnrollment -Candidates $hits -Label $sn
                [void]$results.Add((Resolve-DeviceRsop -ManagedDevice $md -Corpus $Corpus))
            }
        }
        'name' {
            $label = "Device: " + (@($Value) -join ', ')
            foreach ($dn in @($Value)) {
                $hits = Find-ManagedDevices -By deviceName -Value $dn.Trim()
                if (@($hits).Count -eq 0) { Write-Warn2 ("No managed device found named '{0}'" -f $dn); continue }
                $md = Select-BestEnrollment -Candidates $hits -Label $dn
                [void]$results.Add((Resolve-DeviceRsop -ManagedDevice $md -Corpus $Corpus))
            }
        }
        'group' {
            $gobj = Resolve-GroupIdentity -Value $Value
            if ($null -eq $gobj) { throw "Group '$Value' not found." }
            $label = "Group: " + $gobj.displayName

            if ($AssignedOnly) {
                Write-Step ("Listing policies directly assigned to group '{0}'" -f $gobj.displayName)
                Resolve-GroupNames -Ids @($gobj.id)
                [void]$results.Add((Get-GroupAssignedRsop -GroupObj $gobj -Corpus $Corpus))
            }
            else {
                Write-Step ("Resolving device members of '{0}' (transitive)" -f $gobj.displayName)
                $members = Get-RsopPaged -Uri ("v1.0/groups/{0}/transitiveMembers/microsoft.graph.device?`$select=id,deviceId,displayName&`$top=999" -f $gobj.id)
                Write-Info ("{0} device objects in group (user members are not expanded to their devices)" -f @($members).Count)
                $targets = New-Object System.Collections.Generic.List[object]
                $idx = Get-DeviceIndex
                $byAzId = @{}
                foreach ($d in $idx) { $byAzId[[string](Get-Prop $d 'azureADDeviceId')] = $d }
                foreach ($m in @($members)) {
                    $devId = [string](Get-Prop $m 'deviceId')
                    if ($devId -and $byAzId.ContainsKey($devId)) { [void]$targets.Add($byAzId[$devId]) }
                }
                Write-Info ("{0} of them are Intune-managed" -f $targets.Count)
                if ($MaxDevices -gt 0 -and $targets.Count -gt $MaxDevices) {
                    Write-Warn2 ("Group has {0} managed devices; evaluating the first {1} (use -MaxDevices 0 for all)." -f $targets.Count, $MaxDevices)
                }
                $take = if ($MaxDevices -gt 0) { [math]::Min($MaxDevices, $targets.Count) } else { $targets.Count }
                for ($i = 0; $i -lt $take; $i++) {
                    [void]$results.Add((Resolve-DeviceRsop -ManagedDevice $targets[$i] -Corpus $Corpus))
                }
            }
        }
        'filter' {
            $flt = $null
            foreach ($f in @($Corpus.filters)) {
                if ($f.Id -ieq [string]$Value -or $f.Name -ieq [string]$Value) { $flt = $f; break }
            }
            if ($null -eq $flt) {
                $names = @($Corpus.filters | ForEach-Object { $_.Name }) -join "', '"
                throw "Assignment filter '$Value' not found. Available: '$names'"
            }
            $label = "Filter: " + $flt.Name
            Write-Step ("Evaluating assignment filter '{0}' server-side" -f $flt.Name)
            $targets = @(Get-FilterMatchedDevices -FilterObj $flt -Cap $MaxDevices)
            Write-Info ("{0} devices match the filter" -f $targets.Count)
            if ($MaxDevices -gt 0 -and $targets.Count -gt $MaxDevices) {
                Write-Warn2 ("Evaluating the first {0} (use -MaxDevices 0 for all)." -f $MaxDevices)
            }
            $take = if ($MaxDevices -gt 0) { [math]::Min($MaxDevices, $targets.Count) } else { $targets.Count }
            for ($i = 0; $i -lt $take; $i++) {
                [void]$results.Add((Resolve-DeviceRsop -ManagedDevice $targets[$i] -Corpus $Corpus))
            }
        }
        'all' {
            $label = 'Tenant-wide inventory'
            $sgObj = $null; $sfObj = $null
            $gRef = $null; $fRef = $null
            if ($null -ne $Value) { $gRef = Get-Prop $Value 'Group'; $fRef = Get-Prop $Value 'Filter' }
            if ($gRef) {
                $g = Resolve-GroupIdentity -Value $gRef
                if ($null -eq $g) { throw "Scope group '$gRef' not found." }
                # policies assigned to a group the scope group is nested in reach its members too
                $parents = @{}
                try {
                    foreach ($pg in (Get-RsopPaged -Uri ("v1.0/groups/{0}/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName&`$top=999" -f $g.id))) {
                        $parents[[string](Get-Prop $pg 'id')] = [string](Get-Prop $pg 'displayName')
                    }
                    if ($parents.Count -gt 0) { Write-Info ("Scope group is nested in {0} parent group(s); assignments to those count as in scope." -f $parents.Count) }
                } catch {
                    Add-RunLog -Level warn -Message ("Could not resolve parent groups of '{0}' ({1}); scope matches direct assignments only." -f $g.displayName, $_.Exception.Message)
                }
                $sgObj = [pscustomobject]@{ Id = $g.id; Name = $g.displayName; Parents = $parents }
                $label += (" - group '{0}'" -f $g.displayName)
            }
            if ($fRef) {
                foreach ($f in @($Corpus.filters)) {
                    if ($f.Id -ieq [string]$fRef -or $f.Name -ieq [string]$fRef) { $sfObj = $f; break }
                }
                if ($null -eq $sfObj) {
                    $names = @($Corpus.filters | ForEach-Object { $_.Name }) -join "', '"
                    throw "Scope filter '$fRef' not found. Available: '$names'"
                }
                $label += (" - filter '{0}'" -f $sfObj.Name)
            }
            Write-Step $(if ($sgObj -or $sfObj) { "Building scoped tenant inventory" } else { "Building tenant-wide settings inventory" })
            [void]$results.Add((Get-TenantInventoryRsop -Corpus $Corpus -ScopeGroup $sgObj -ScopeFilter $sfObj))
        }
    }

    return [pscustomobject]@{ Label = $label; Results = $results.ToArray() }
}

function Export-RsopResults {
    param($Results, [string]$Label, [string]$Tenant, [string]$Account, [string]$HtmlPath, [string]$CsvPath, [string]$JsonPath)
    foreach ($r in @($Results)) { Show-ConsoleSummary -Result $r }
    if ($HtmlPath) { Export-HtmlReport -Results @($Results) -Path $HtmlPath -QueryLabel $Label -Tenant $Tenant -Account $Account }
    if ($CsvPath) {
        Get-CsvRows -Results @($Results) | Export-Csv -Path $CsvPath -NoTypeInformation -Encoding UTF8
        Write-Good ("CSV export: {0}" -f (Resolve-Path $CsvPath))
    }
    if ($JsonPath) {
        [pscustomobject]@{ query = $Label; generated = (Get-Date).ToString('o'); devices = @($Results) } |
            ConvertTo-Json -Depth 12 | Set-Content -Path $JsonPath -Encoding UTF8
        Write-Good ("JSON export: {0}" -f (Resolve-Path $JsonPath))
    }
}

function Reset-RunLog {
    param($Corpus)
    $script:RunLog.Clear()
    foreach ($w in @($Corpus.warnings)) {
        [void]$script:RunLog.Add([pscustomobject]@{ Time = ''; Level = 'warn'; Message = [string]$w })
    }
}

function Open-File {
    param([string]$Path)
    try {
        if ($env:OS -eq 'Windows_NT') { Start-Process -FilePath $Path }
        elseif ($IsMacOS) { & open $Path }
        else { & xdg-open $Path 2>$null }
    } catch { Write-Warn2 "Could not auto-open $Path" }
}

#endregion

#region ---------- interactive menu -----------------------------------------------------------

function Select-EntraGroup {
    # Search-as-you-type group picker.
    while ($true) {
        $q = Read-Host "  Group name starts with (blank = cancel)"
        if (-not $q) { return $null }
        $guid = [guid]::Empty
        if ([guid]::TryParse($q, [ref]$guid)) {
            try { $g = Invoke-Rsop -Uri ("v1.0/groups/{0}?`$select=id,displayName" -f $q); return $g } catch { Write-Warn2 "Not found."; continue }
        }
        $esc = $q -replace "'", "''"
        $resp = Invoke-Rsop -Uri ("v1.0/groups?`$filter=startswith(displayName,'{0}')&`$select=id,displayName&`$top=20" -f $esc)
        $vals = @($resp['value'])
        if ($vals.Count -eq 0) { Write-Warn2 "No groups match."; continue }
        for ($i = 0; $i -lt $vals.Count; $i++) { Write-Host ("   [{0}] {1}" -f ($i + 1), $vals[$i]['displayName']) }
        $pick = Read-Host "  Pick number (blank = search again)"
        $pi = 0
        if ([int]::TryParse($pick, [ref]$pi) -and $pi -ge 1 -and $pi -le $vals.Count) { return $vals[$pi - 1] }
    }
}

function Select-CorpusFilter {
    param($Corpus)
    $flts = @($Corpus.filters)
    if ($flts.Count -eq 0) { Write-Warn2 "Tenant has no assignment filters."; return $null }
    for ($i = 0; $i -lt $flts.Count; $i++) {
        Write-Host ("   [{0}] {1}  ({2})" -f ($i + 1), $flts[$i].Name, $flts[$i].Platform)
    }
    $pick = Read-Host "  Pick number (blank = cancel)"
    $pi = 0
    if ([int]::TryParse($pick, [ref]$pi) -and $pi -ge 1 -and $pi -le $flts.Count) { return $flts[$pi - 1].Name }
    return $null
}

function Invoke-InteractiveMenu {
    param($Corpus, [string]$TenantKey, $GraphCtx)

    while ($true) {
        $assigned = @($Corpus.policies | Where-Object { @($_.Assignments).Count -gt 0 }).Count
        Write-Host ""
        Write-Host ("  🔍 Intune Lens v{0}" -f $script:Version) -ForegroundColor White
        Write-Host ("  Tenant {0}  |  signed in as {1}" -f $TenantKey, $GraphCtx.Account) -ForegroundColor DarkGray
        Write-Host ("  Policy corpus: {0} policies ({1} assigned), {2} apps, {3} filters, pulled {4}" -f `
            @($Corpus.policies).Count, $assigned, @($Corpus.apps).Count, @($Corpus.filters).Count, ([datetime]$Corpus.generated).ToString('HH:mm')) -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  What do you want to look up?" -ForegroundColor Cyan
        Write-Host "   [1] Device(s) by serial number"
        Write-Host "   [2] Device(s) by name"
        Write-Host "   [3] All devices in an Entra group"
        Write-Host "   [4] Policies and apps assigned directly to a group  (fast, no device math)"
        Write-Host "   [5] Devices matching an assignment filter"
        Write-Host "   [6] Tenant-wide settings inventory  (every policy + every setting; optional group/filter scope)"
        Write-Host "   [R] Refresh policy cache      [Q] Quit"
        $choice = (Read-Host "  Choice").Trim().ToUpper()

        if ($choice -eq 'Q') { break }
        if ($choice -eq 'R') {
            $script:Refresh = $true
            $Corpus = Get-PolicyCorpus -TenantKey $TenantKey
            $script:Refresh = $false
            $script:FilterById = @{}
            foreach ($f in @($Corpus.filters)) { $script:FilterById[[string]$f.Id] = $f }
            continue
        }

        $mode = $null; $value = $null; $assignedOnly = $false
        switch ($choice) {
            '1' {
                $s = Read-Host "  Serial number(s), comma-separated"
                if ($s) { $mode = 'serial'; $value = @($s -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            }
            '2' {
                $s = Read-Host "  Device name(s), comma-separated"
                if ($s) { $mode = 'name'; $value = @($s -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            }
            '3' { $g = Select-EntraGroup; if ($g) { $mode = 'group'; $value = $g } }
            '4' { $g = Select-EntraGroup; if ($g) { $mode = 'group'; $value = $g; $assignedOnly = $true } }
            '5' { $f = Select-CorpusFilter -Corpus $Corpus; if ($f) { $mode = 'filter'; $value = $f } }
            '6' {
                $mode = 'all'
                Write-Host "  Optional scope - answers 'what policies apply to this group / filter?'" -ForegroundColor DarkGray
                $sg = (Read-Host "  Scope by group name or id (blank = whole tenant)").Trim()
                $sf = (Read-Host "  Scope by assignment filter name or id (blank = none)").Trim()
                if ($sg -or $sf) { $value = [pscustomobject]@{ Group = $sg; Filter = $sf } }
            }
            default { continue }
        }
        if (-not $mode) { continue }

        Reset-RunLog -Corpus $Corpus
        $q = $null
        try { $q = Resolve-QueryResults -Mode $mode -Corpus $Corpus -Value $value -AssignedOnly $assignedOnly }
        catch { Write-Warn2 $_.Exception.Message; continue }
        if (-not $q -or @($q.Results).Count -eq 0) { Write-Warn2 "Nothing resolved."; continue }

        $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
        $htmlPath = Join-Path (Get-Location) ("IntuneLens-{0}.html" -f $stamp)
        Export-RsopResults -Results $q.Results -Label $q.Label -Tenant $TenantKey -Account $GraphCtx.Account -HtmlPath $htmlPath

        $open = (Read-Host "  Open the HTML report now? [Y/n]").Trim().ToUpper()
        if ($open -ne 'N') { Open-File -Path $htmlPath }
        $csvAns = (Read-Host "  Also write a CSV? Enter a path or leave blank to skip").Trim()
        if ($csvAns) {
            Get-CsvRows -Results $q.Results | Export-Csv -Path $csvAns -NoTypeInformation -Encoding UTF8
            Write-Good ("CSV export: {0}" -f (Resolve-Path $csvAns))
        }
    }
}

#endregion

#region ---------- main -----------------------------------------------------------------------

$ctx = Connect-RsopGraph
$tenantKey = [string]$ctx.TenantId

$corpus = Get-PolicyCorpus -TenantKey $tenantKey

# Index filters for quick lookup during evaluation.
$script:FilterById = @{}
foreach ($f in @($corpus.filters)) { $script:FilterById[[string]$f.Id] = $f }

if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
    Invoke-InteractiveMenu -Corpus $corpus -TenantKey $tenantKey -GraphCtx $ctx
    Write-Host ""
    Write-Host "Bye." -ForegroundColor Cyan
    return
}

Reset-RunLog -Corpus $corpus

$mode = $null; $value = $null; $assignedOnly = $false
switch ($PSCmdlet.ParameterSetName) {
    'BySerial'     { $mode = 'serial'; $value = $SerialNumber }
    'ByDeviceName' { $mode = 'name'; $value = $DeviceName }
    'ByGroup'      { $mode = 'group'; $value = $Group; $assignedOnly = [bool]$GroupAssignedOnly }
    'ByFilter'     { $mode = 'filter'; $value = $AssignmentFilter }
    'All'          {
        $mode = 'all'
        if ($ScopeGroup -or $ScopeFilter) { $value = [pscustomobject]@{ Group = $ScopeGroup; Filter = $ScopeFilter } }
    }
}

$q = Resolve-QueryResults -Mode $mode -Corpus $corpus -Value $value -AssignedOnly $assignedOnly
if (-not $q -or @($q.Results).Count -eq 0) {
    Write-Warn2 "Nothing resolved - no report generated."
    return
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if (-not $ExportHtml -and -not $NoHtml) { $ExportHtml = Join-Path (Get-Location) ("IntuneLens-{0}.html" -f $stamp) }

Export-RsopResults -Results $q.Results -Label $q.Label -Tenant $tenantKey -Account $ctx.Account -HtmlPath $ExportHtml -CsvPath $ExportCsv -JsonPath $ExportJson

$elapsed = (Get-Date) - $script:StartTime
Write-Host ""
Write-Host ("Done in {0:n0}s." -f $elapsed.TotalSeconds) -ForegroundColor Cyan

if ($PassThru) { @($q.Results) }

#endregion
