# CSV exports, the commented remediation plan, and Conditional Access / dynamic group templates.

$script:MtrRoomColumns = @(
    'Classification', 'UserPrincipalName', 'DisplayName', 'Evidence', 'NamePrefix', 'LicenseTier', 'Licenses', 'SyncedFromAD', 'AccountEnabled',
    'MailboxType', 'RoomLists', 'Building', 'City', 'Floor', 'Capacity', 'MTREnabled', 'TimeZone', 'Platforms', 'Devices', 'LastSignIn',
    'ConditionalAccess', 'PasswordlessStatus', 'PasswordlessDetail'
)

function Get-MtrRoomRow {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline)
    $caByAccount = @{}
    if ($Context.ConditionalAccess) {
        foreach ($e in @(Get-MtrCaEvaluation -Model $Model -Context $Context -Baseline $Baseline)) {
            foreach ($a in (Get-MtrArray $e.Applies)) {
                if (-not $caByAccount[$a.Id]) { $caByAccount[$a.Id] = [System.Collections.Generic.List[string]]::new() }
                $caByAccount[$a.Id].Add($(if ($e.ReportOnly) { "$($e.Name) (report-only)" } else { $e.Name }))
            }
        }
    }
    foreach ($a in @($Model.Accounts | Sort-Object Classification, UserPrincipalName)) {
        $readiness = if ($a.Classification -in 'Confirmed', 'Probable') { Get-MtrPasswordlessReadiness -Account $a -Baseline $Baseline } else { $null }
        $place = $a.Place
        $exoPlace = $a.ExoPlace
        [pscustomobject][ordered]@{
            Classification      = $a.Classification
            UserPrincipalName   = $a.UserPrincipalName
            DisplayName         = $a.DisplayName
            Evidence            = @($a.Evidence) -join ' | '
            NamePrefix          = $a.NamePrefix
            LicenseTier         = $a.LicenseTier
            Licenses            = @($a.SkuPartNumbers) -join ', '
            SyncedFromAD        = $a.IsSynced
            AccountEnabled      = $a.AccountEnabled
            MailboxType         = $a.MailboxType
            RoomLists           = @($a.RoomLists) -join ', '
            Building            = if ($place -and $place.building) { $place.building } elseif ($exoPlace) { $exoPlace.Building } else { $null }
            City                = if ($place -and $place.address.city) { $place.address.city } elseif ($exoPlace) { $exoPlace.City } else { $null }
            Floor               = if ($place -and $null -ne $place.floorNumber) { $place.floorNumber } elseif ($exoPlace) { $exoPlace.Floor } else { $null }
            Capacity            = if ($place -and $place.capacity) { $place.capacity } elseif ($exoPlace) { $exoPlace.Capacity } else { $null }
            MTREnabled          = if ($exoPlace) { $exoPlace.MTREnabled } elseif ($place) { $place.teamsEnabledState } else { $null }
            TimeZone            = if ($a.Exchange -and $a.Exchange.Regional) { $a.Exchange.Regional.TimeZone } else { $null }
            Platforms           = @($a.Platforms) -join ', '
            Devices             = @($a.Devices | ForEach-Object { '{0} ({1} {2}, {3})' -f $_.Name, $_.Manufacturer, $_.Model, $_.ComplianceState }) -join '; '
            LastSignIn          = if ($a.LastSignIn) { $a.LastSignIn.ToString('yyyy-MM-dd HH:mm') } else { $null }
            ConditionalAccess   = if ($caByAccount[$a.Id]) { @($caByAccount[$a.Id]) -join '; ' } else { $null }
            PasswordlessStatus  = if ($readiness) { $readiness.Status } else { $null }
            PasswordlessDetail  = if ($readiness) { $readiness.Summary } else { $null }
        }
    }
}

function Export-MtrCsv {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rooms, [Parameter(Mandatory)][string]$OutputPath)
    $Findings | Sort-Object SeverityRank, Category, CheckId | Select-Object Severity, CheckId, Category, Title, Target, FixLocation, Detail, Impact, Recommendation,
    @{ n = 'AffectedObjects'; e = { @($_.AffectedObjects) -join '; ' } }, Reference |
        Export-Csv -Path (Join-Path $OutputPath 'Findings.csv') -NoTypeInformation -Encoding utf8
    $roomsPath = Join-Path $OutputPath 'Rooms.csv'
    if ($Rooms.Count) { $Rooms | Export-Csv -Path $roomsPath -NoTypeInformation -Encoding utf8 }
    else { Set-Content -Path $roomsPath -Value (($script:MtrRoomColumns | ForEach-Object { '"{0}"' -f $_ }) -join ',') -Encoding utf8 }
}

function New-MtrRemediationPlan {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Path)
    $sb = [System.Text.StringBuilder]::new()
    # Tenant-controlled text (names, policy titles) must never break out of a # comment line, so line breaks are removed.
    $one = { param($Text) ([string]$Text) -replace '[\r\n\u0085\u2028\u2029]+', ' ' }
    $null = $sb.AppendLine('<#')
    $null = $sb.AppendLine('    Teams Rooms remediation plan')
    $null = $sb.AppendLine("    Tenant : $(& $one $Context.Meta.TenantName) ($(& $one $Context.Meta.TenantId))")
    $null = $sb.AppendLine("    Created: $([datetime]::UtcNow.ToString('yyyy-MM-dd HH:mm')) UTC by Invoke-MtrTenantAudit (read-only). Nothing in this file has been run.")
    $null = $sb.AppendLine('')
    $null = $sb.AppendLine('    Every command is commented out. Review each one, confirm the target, and run it yourself in the')
    $null = $sb.AppendLine('    location given by "RUN IN".')
    if ($Context.Tenant -and $Context.Tenant.OnPremisesSyncEnabled) {
        $null = $sb.AppendLine('    This tenant synchronizes from on-prem AD: anything marked On-prem AD / On-prem Exchange must be')
        $null = $sb.AppendLine('    changed on-prem, or sync will overwrite it.')
    }
    $null = $sb.AppendLine('#>')
    $null = $sb.AppendLine("throw 'Remediation-Plan.ps1 is a review document. Copy individual commands after reviewing them; do not run this file.'")
    $null = $sb.AppendLine('')

    $actionable = @($Findings | Where-Object { $_.Severity -notin 'Info', 'Pass' -and ($_.RemediationCommand.Count -or $_.VerifyCommand.Count -or $_.FixLocation -ne 'None') } | Sort-Object SeverityRank, FixLocation, CheckId)
    foreach ($group in ($actionable | Group-Object FixLocation)) {
        $null = $sb.AppendLine('# ' + ('=' * 100))
        $null = $sb.AppendLine("# RUN IN: $(& $one $group.Name)")
        $null = $sb.AppendLine('# ' + ('=' * 100))
        foreach ($f in $group.Group) {
            $null = $sb.AppendLine('')
            $null = $sb.AppendLine("# [$($f.Severity)] $($f.CheckId) - $(& $one $f.Title)")
            if ($f.Target -and $f.Target -ne 'Tenant') { $null = $sb.AppendLine("#   Target: $(& $one $f.Target)") }
            if ($f.Recommendation) { $null = $sb.AppendLine("#   Action: $(& $one $f.Recommendation)") }
            if ($f.Reference) { $null = $sb.AppendLine("#   Docs  : $(& $one $f.Reference)") }
            $objects = Get-MtrArray $f.AffectedObjects
            if ($objects.Count) {
                $null = $sb.AppendLine('#   Affects:')
                foreach ($o in ($objects | Select-Object -First 50)) { $null = $sb.AppendLine("#     - $(& $one $o)") }
                if ($objects.Count -gt 50) { $null = $sb.AppendLine("#     ... and $($objects.Count - 50) more (see Findings.csv)") }
            }
            if ($f.VerifyCommand.Count) {
                $null = $sb.AppendLine('#   Verify first (read-only):')
                foreach ($c in $f.VerifyCommand) { $null = $sb.AppendLine("#     $(& $one $c)") }
            }
            if ($f.RemediationCommand.Count) {
                $null = $sb.AppendLine('#   Fix:')
                foreach ($c in $f.RemediationCommand) { $null = $sb.AppendLine("#     $(& $one $c)") }
            }
            elseif ($f.FixLocation -in 'Entra ID', 'Intune', 'Teams Admin Center', 'Pro Management Portal', 'Microsoft Places') {
                $null = $sb.AppendLine("#   Fix: make the change in $($f.FixLocation) as described above.")
            }
        }
        $null = $sb.AppendLine('')
    }
    Set-Content -Path $Path -Value $sb.ToString() -Encoding utf8
}

function New-MtrTemplate {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)][string]$Path)
    $null = New-Item -ItemType Directory -Path $Path -Force
    $group = Get-MtrMtrGroupForExclusion -Model $Model
    $groupId = if ($group) { $group.Id } else { '<TeamsRoomsGroupId>' }
    $trusted = @($Context.ConditionalAccess.NamedLocations | Where-Object IsTrusted | ForEach-Object Id)
    $excludeLocations = if ($trusted.Count) { $trusted } else { @('AllTrusted') }

    $policies = [ordered]@{
        'CA-TeamsRooms-RequireCompliantDevice.json' = [ordered]@{
            displayName   = 'Teams Rooms - Require compliant device'
            state         = 'enabledForReportingButNotEnforced'
            conditions    = [ordered]@{
                users          = @{ includeGroups = Get-MtrArray $groupId }
                applications   = @{ includeApplications = @('Office365') }
                platforms      = @{ includePlatforms = @('windows', 'android') }
                clientAppTypes = @('all')
            }
            grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('compliantDevice') }
        }
        'CA-TeamsRooms-BlockOutsideTrustedLocations.json' = [ordered]@{
            displayName   = 'Teams Rooms - Block sign-in outside trusted locations'
            state         = 'enabledForReportingButNotEnforced'
            conditions    = [ordered]@{
                users          = @{ includeGroups = Get-MtrArray $groupId }
                applications   = @{ includeApplications = @('All') }
                locations      = [ordered]@{ includeLocations = @('All'); excludeLocations = Get-MtrArray $excludeLocations }
                clientAppTypes = @('all')
            }
            grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('block') }
        }
        'CA-TeamsRooms-BlockUnsupportedPlatforms.json' = [ordered]@{
            displayName   = 'Teams Rooms - Block platforms other than Windows and Android'
            state         = 'enabledForReportingButNotEnforced'
            conditions    = [ordered]@{
                users          = @{ includeGroups = Get-MtrArray $groupId }
                applications   = @{ includeApplications = @('All') }
                platforms      = [ordered]@{ includePlatforms = @('all'); excludePlatforms = @('windows', 'android') }
                clientAppTypes = @('all')
            }
            grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('block') }
        }
        'CA-TeamsRooms-BlockLegacyAuthentication.json' = [ordered]@{
            displayName   = 'Teams Rooms - Block legacy authentication'
            state         = 'enabledForReportingButNotEnforced'
            conditions    = [ordered]@{
                users          = @{ includeGroups = Get-MtrArray $groupId }
                applications   = @{ includeApplications = @('All') }
                clientAppTypes = @('exchangeActiveSync', 'other')
            }
            grantControls = [ordered]@{ operator = 'OR'; builtInControls = @('block') }
        }
    }
    foreach ($name in $policies.Keys) {
        Set-Content -Path (Join-Path $Path $name) -Value ($policies[$name] | ConvertTo-Json -Depth 10) -Encoding utf8
    }

    $rules = Get-MtrSuggestedGroupRule -Model $Model -Context $Context -Baseline $Baseline
    $text = @"
Dynamic group rules for Teams Rooms (generated $([datetime]::UtcNow.ToString('yyyy-MM-dd')))
======================================================================================
None of these rules depend on account naming conventions.

1. User group - license based
   $(if ($rules.LicenseRule) { $rules.LicenseRule } else { '(No service plan unique to Teams Rooms SKUs was found in this tenant.)' })
   Service plans used: $(if ($rules.LicensePlans.Count) { $rules.LicensePlans -join ', ' } else { 'n/a' })
   Note: do not use this group to assign the Teams Rooms license itself (circular).

2. User group - on-prem attribute (synced from AD)
   $($rules.AttributeRule)
   $(if ($rules.AttributeCandidate) { "Found in the tenant: $($rules.AttributeCandidate.Attribute) = '$($rules.AttributeCandidate.Value)' on $([int]($rules.AttributeCandidate.Coverage * 100))% of room accounts; $($rules.AttributeCandidate.Collisions) non-room candidate(s) share it." } else { 'Populate the attribute on every room account in AD first, e.g. Set-ADUser <room> -Replace @{extensionAttribute10="TeamsRoom"}' })
   Useful as the Conditional Access include/exclude group and for group-based licensing.

3. Device group - Windows Teams Rooms (requires Autopilot group tag starting MTR-)
   $($rules.WindowsDeviceRule)

4. Device group - Teams Android devices enrolled with the Teams AOSP profile
   $($rules.AndroidDeviceRule)

Suggested Conditional Access templates (all in report-only state) are in this folder. Import them in the
Entra admin center (Conditional Access > Policies > Upload policy file), review, then turn them on after
the report-only results look clean. Group used: $groupId
"@
    Set-Content -Path (Join-Path $Path 'DynamicGroup-Rules.txt') -Value $text -Encoding utf8
}
