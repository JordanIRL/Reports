#Requires -Version 7.4
<#
.SYNOPSIS
    Read-only audit of a Microsoft 365 tenant's Microsoft Teams Rooms configuration.

.DESCRIPTION
    Finds Teams Rooms accounts without relying on naming conventions (licenses, devices, mailbox type,
    group membership and optional seeds), then checks them against Microsoft's current guidance:
    Conditional Access, Intune compliance and enrollment (Windows and Android/AOSP), licensing, resource
    account setup, password expiry (cloud and AD-synced), password-less readiness, groups, Exchange
    calendar processing, time zones, EWS retirement, Room Finder / Places, and Teams policies.

    Sign-in is delegated and brokered by the Windows Web Account Manager (WAM). The tool only reads:
    Graph calls are GET (plus GET-only $batch), the Exchange session loads only Get-* cmdlets, and only
    Get-Cs* Teams cmdlets are used. Nothing in the tenant is changed.

    Output (in -OutputPath): Report.html, Findings.csv, Rooms.csv, Snapshot.json, Remediation-Plan.ps1
    (every command commented out) and templates\ (report-only CA policies, dynamic group rules).

.PARAMETER Sections
    Areas to check. Default: all. Discovery always runs.

.PARAMETER TenantId
    Tenant to sign in to (optional; WAM picks the account).

.PARAMETER ClientId
    Client ID of a dedicated read-only app registration for Microsoft Graph (recommended - see README).

.PARAMETER ResourceAccountUpn
    Teams Rooms account UPNs to treat as Teams Rooms regardless of other signals.

.PARAMETER ResourceAccountCsv
    CSV with a UserPrincipalName (or UPN) column of Teams Rooms accounts.

.PARAMETER MtrGroupId
    Object ID(s) of existing group(s) that contain Teams Rooms accounts.

.PARAMETER UpnPattern
    One or more regular expressions matched against UPNs, e.g. one per building prefix: '^LON-', '^NYC\.rm'.

.PARAMETER WindowsDeviceNamePattern
    Regular expression for Windows Teams Rooms device names, for rooms not registered in Autopilot with an MTR- tag.

.PARAMETER SignInLookbackDays
    Days of sign-in logs to analyse per room account (default 7).

.PARAMETER SkipSignInLogs
    Do not read sign-in logs (faster; fewer findings).

.PARAMETER StaleDays
    A room account with no sign-in for longer than this is reported (default 30).

.PARAMETER OnPremMaxPasswordAgeDays
    Your AD maximum password age. Used to estimate expiry for synced accounts, since AD is not queried.

.PARAMETER FromSnapshot
    Re-run all checks offline against a Snapshot.json from an earlier run. No sign-in needed.

.PARAMETER InProcessExchangeAndTeams
    Connect Exchange Online and Teams in this PowerShell session instead of a separate process. By default they
    run in a separate process because their sign-in libraries clash with Microsoft Graph's in one session; if the
    in-process connection fails the tool falls back to a separate process anyway.

.PARAMETER OutputPath
    Folder for the results. Default: .\MtrAudit-<tenant>-<timestamp>

.PARAMETER NoHtml
    Skip the HTML report.

.EXAMPLE
    .\Invoke-MtrTenantAudit.ps1
    Full audit with default discovery.

.EXAMPLE
    .\Invoke-MtrTenantAudit.ps1 -UpnPattern '^LON-','^NYC-','^conf\.' -OnPremMaxPasswordAgeDays 90
    Seeds discovery with per-building prefixes and estimates on-prem password expiry.

.EXAMPLE
    .\Invoke-MtrTenantAudit.ps1 -Sections ConditionalAccess,Groups -ClientId 00000000-0000-0000-0000-000000000000
    Checks only Conditional Access and groups using a dedicated read-only app registration.

.EXAMPLE
    .\Invoke-MtrTenantAudit.ps1 -FromSnapshot .\MtrAudit-Contoso-20260928-1030\Snapshot.json
    Re-runs the checks offline against saved data.

.NOTES
    Requires PowerShell 7.4+ on Windows, Microsoft.Graph.Authentication, ExchangeOnlineManagement 3.7.2+
    and MicrosoftTeams with WAM support. Recommended role: Global Reader.
#>
[CmdletBinding(DefaultParameterSetName = 'Live')]
param(
    [ValidateSet('Identity', 'Licensing', 'ConditionalAccess', 'Groups', 'Exchange', 'Places', 'Teams', 'Intune')]
    [string[]]$Sections = @('Identity', 'Licensing', 'ConditionalAccess', 'Groups', 'Exchange', 'Places', 'Teams', 'Intune'),

    [Parameter(ParameterSetName = 'Live')]
    [ValidateNotNullOrEmpty()]
    [string]$TenantId,

    [Parameter(ParameterSetName = 'Live')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(ParameterSetName = 'Live')]
    [string[]]$ResourceAccountUpn,

    [Parameter(ParameterSetName = 'Live')]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$ResourceAccountCsv,

    [Parameter(ParameterSetName = 'Live')]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string[]]$MtrGroupId,

    [Parameter(ParameterSetName = 'Live')]
    [string[]]$UpnPattern,

    [Parameter(ParameterSetName = 'Live')]
    [string]$WindowsDeviceNamePattern,

    [ValidateRange(1, 30)]
    [int]$SignInLookbackDays = 7,

    [Parameter(ParameterSetName = 'Live')]
    [switch]$SkipSignInLogs,

    [ValidateRange(1, 365)]
    [int]$StaleDays = 30,

    [ValidateRange(1, 3650)]
    [int]$OnPremMaxPasswordAgeDays,

    [Parameter(ParameterSetName = 'Offline', Mandatory)]
    [ValidateScript({ Test-Path -LiteralPath $_ -PathType Leaf })]
    [string]$FromSnapshot,

    [Parameter(ParameterSetName = 'Live')]
    [switch]$InProcessExchangeAndTeams,

    [string]$OutputPath,

    [switch]$NoHtml
)

$ErrorActionPreference = 'Stop'
$script:MtrToolVersion = '1.0.0'

$sourceRoot = Join-Path $PSScriptRoot 'src'
foreach ($file in Get-ChildItem -Path $sourceRoot -Recurse -Filter '*.ps1' | Where-Object Name -ne 'Invoke-MtrIsolatedCall.ps1' | Sort-Object FullName) {
    . $file.FullName
}
$baseline = Import-PowerShellDataFile -Path (Join-Path $PSScriptRoot 'config/MtrBaseline.psd1')

foreach ($pattern in @($UpnPattern) + @($WindowsDeviceNamePattern)) {
    if (-not $pattern) { continue }
    try { $null = [regex]::new($pattern) } catch { throw "Invalid regular expression '$pattern': $($_.Exception.Message)" }
}

$session = $null
try {
    if ($PSCmdlet.ParameterSetName -eq 'Offline') {
        Write-Information "Loading snapshot $FromSnapshot" -InformationAction Continue
        $ctx = Import-MtrSnapshot -Path $FromSnapshot
        if (-not $PSBoundParameters.ContainsKey('Sections') -and @($ctx.Meta.Sections).Count) { $Sections = @($ctx.Meta.Sections) }
        if (-not $OutputPath) {
            $OutputPath = Join-Path (Split-Path -Path (Resolve-Path -LiteralPath $FromSnapshot) -Parent) ("Recheck-{0}" -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
        }
    }
    else {
        $services = @('Graph')
        if ('Exchange' -in $Sections -or 'Places' -in $Sections) { $services += 'Exchange' }
        if ('Teams' -in $Sections) { $services += 'Teams' }
        Test-MtrPrerequisite -Services $services -Baseline $baseline

        $session = Connect-MtrService -Services $services -TenantId $TenantId -ClientId $ClientId -InProcessExchangeAndTeams:$InProcessExchangeAndTeams -SourceRoot $sourceRoot
        $ctx = New-MtrContext -Parameters @{
            Sections                 = $Sections
            SignInLookbackDays       = $SignInLookbackDays
            StaleDays                = $StaleDays
            OnPremMaxPasswordAgeDays = $OnPremMaxPasswordAgeDays
            UpnPattern               = $UpnPattern
            WindowsDeviceNamePattern = $WindowsDeviceNamePattern
            SeedCount                = (Get-MtrCount $ResourceAccountUpn)
        }
        $ctx.Meta.Sections = $Sections
        $ctx.Meta.RunBy = $session.Upn
        foreach ($service in 'Exchange', 'Teams') {
            if ($service -in $services) {
                $mode = switch ($session.$service) { 'Isolated' { 'separate PowerShell process (connects per call)' } 'InProcess' { 'this PowerShell session' } default { 'not connected' } }
                Add-MtrCoverage -Context $ctx -Section $service -Item 'Connection mode' -Status $(if ($session.$service -eq 'Unavailable') { 'Failed' } else { 'OK' }) -Detail ("$mode. $($session.Errors[$service])").Trim()
            }
        }

        Invoke-MtrCollection -Context $ctx -Session $session -Baseline $baseline -Sections $Sections `
            -ResourceAccountUpn $ResourceAccountUpn -ResourceAccountCsv $ResourceAccountCsv -MtrGroupId $MtrGroupId -UpnPattern $UpnPattern `
            -WindowsDeviceNamePattern $WindowsDeviceNamePattern -SignInLookbackDays $SignInLookbackDays -SkipSignInLogs:$SkipSignInLogs

        if (-not $OutputPath) {
            $tenantLabel = if ($ctx.Meta.TenantName) { $ctx.Meta.TenantName -replace '[^\w\-]', '_' } else { 'tenant' }
            $OutputPath = Join-Path (Get-Location) ("MtrAudit-{0}-{1}" -f $tenantLabel, (Get-Date -Format 'yyyyMMdd-HHmm'))
        }
    }

    $null = New-Item -ItemType Directory -Path $OutputPath -Force
    if ($PSCmdlet.ParameterSetName -eq 'Live') {
        Export-MtrSnapshot -Context $ctx -Path (Join-Path $OutputPath 'Snapshot.json')
    }

    Write-Information 'Analysing...' -InformationAction Continue
    $settings = [pscustomobject]@{
        Now                      = ConvertTo-MtrDateTime $ctx.Meta.CollectedAt
        StaleDays                = $StaleDays
        OnPremMaxPasswordAgeDays = $OnPremMaxPasswordAgeDays
        SignInLookbackDays       = $SignInLookbackDays
        Sections                 = $Sections
    }
    $model = Resolve-MtrAccount -Context $ctx -Baseline $baseline

    $checks = [ordered]@{
        Discovery         = 'Test-MtrDiscovery'
        Licensing         = 'Test-MtrLicensing'
        Identity          = 'Test-MtrIdentity'
        ConditionalAccess = 'Test-MtrConditionalAccess'
        Groups            = 'Test-MtrGroups'
        Exchange          = 'Test-MtrExchange'
        Places            = 'Test-MtrPlaces'
        Teams             = 'Test-MtrTeams'
        Intune            = 'Test-MtrIntune'
    }
    $findings = [System.Collections.Generic.List[object]]::new()
    foreach ($section in $checks.Keys) {
        if ($section -ne 'Discovery' -and $section -notin $Sections) { continue }
        try {
            foreach ($f in @(& $checks[$section] -Model $model -Context $ctx -Baseline $baseline -Settings $settings)) { if ($f) { $findings.Add($f) } }
        }
        catch {
            Write-Warning "Checks for $section failed: $($_.Exception.Message)"
            $findings.Add((New-MtrFinding -CheckId 'TOOL-01' -Severity Low -Category 'Tool' -Title "Checks for $section did not complete" `
                        -Detail "$($_.Exception.Message) ($($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber))" `
                        -Recommendation 'Findings for this section are incomplete. Re-run with -Verbose, or re-check offline with -FromSnapshot after fixing the cause.'))
        }
    }
    $findingArray = $findings.ToArray()

    $rooms = @(Get-MtrRoomRow -Model $model -Context $ctx -Baseline $baseline)
    Export-MtrCsv -Findings $findingArray -Rooms $rooms -OutputPath $OutputPath
    New-MtrRemediationPlan -Findings $findingArray -Context $ctx -Path (Join-Path $OutputPath 'Remediation-Plan.ps1')
    New-MtrTemplate -Model $model -Context $ctx -Baseline $baseline -Path (Join-Path $OutputPath 'templates')
    $reportPath = $null
    if (-not $NoHtml) {
        $reportPath = Join-Path $OutputPath 'Report.html'
        New-MtrHtmlReport -Findings $findingArray -Rooms $rooms -Model $model -Context $ctx -Baseline $baseline -Path $reportPath
    }

    $bySeverity = @{}
    foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info', 'Pass') { $bySeverity[$s] = @($findingArray | Where-Object Severity -eq $s).Count }
    Write-Information '' -InformationAction Continue
    $mtrCount = Get-MtrCount $model.MtrAccounts
    $deviceCount = Get-MtrCount $model.Devices
    Write-Information ("Teams Rooms accounts: {0} | devices: {1} | findings - Critical {2}, High {3}, Medium {4}, Low {5}, Info {6}" -f `
            $mtrCount, $deviceCount, $bySeverity.Critical, $bySeverity.High, $bySeverity.Medium, $bySeverity.Low, $bySeverity.Info) -InformationAction Continue
    $otherAccounts = @((Get-MtrArray $model.Accounts) | Where-Object { $_.Classification -notin 'Confirmed', 'Probable' } | Group-Object Classification | ForEach-Object { '{0} {1}' -f $_.Name, $_.Count })
    if ($otherAccounts.Count) { Write-Information "Other accounts examined: $($otherAccounts -join ', ')" -InformationAction Continue }
    foreach ($f in @($findingArray | Where-Object { $_.Severity -in 'Critical', 'High' } | Sort-Object SeverityRank, CheckId | Select-Object -First 15)) {
        Write-Information ("  [{0}] {1} {2}" -f $f.Severity, $f.CheckId, $f.Title) -InformationAction Continue
    }
    $gaps = @($ctx.Coverage | Where-Object { $_.Status -in 'Failed', 'Partial' })
    if ($gaps.Count) { Write-Warning "$($gaps.Count) collection step(s) failed or were partial - see the Coverage section of the report." }
    Write-Information "Results: $OutputPath" -InformationAction Continue

    $summary = [pscustomobject]@{
        OutputPath   = (Resolve-Path -LiteralPath $OutputPath).Path
        Report       = $reportPath
        TeamsRooms   = $mtrCount
        Devices      = $deviceCount
        Critical     = $bySeverity.Critical
        High         = $bySeverity.High
        Medium       = $bySeverity.Medium
        Low          = $bySeverity.Low
        Findings     = $findingArray
    }
    # Findings stay on the object ($result.Findings) but are not dumped to the console by default.
    $defaultView = [System.Management.Automation.PSPropertySet]::new('DefaultDisplayPropertySet', [string[]]@('OutputPath', 'Report', 'TeamsRooms', 'Devices', 'Critical', 'High', 'Medium', 'Low'))
    $summary | Add-Member -MemberType MemberSet -Name PSStandardMembers -Value ([System.Management.Automation.PSMemberInfo[]]@($defaultView))
    $summary
}
finally {
    Disconnect-MtrService -Session $session
}
