# Conditional Access (CA) checks. Each policy is evaluated per room account using its users/groups/roles
# assignments, then its conditions, grant and session controls are compared with what Teams Rooms support.

function Get-MtrCaUserScope {
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)]$Account)
    $u = $Policy.conditions.users
    if (-not $u) { return 'NotIncluded' }
    $groups = Get-MtrArray $Account.GroupIds
    $roles = Get-MtrArray $Account.RoleTemplateIds
    $included = (@($u.includeUsers) -contains 'All') -or (@($u.includeUsers) -contains $Account.Id) -or
        (@($u.includeGroups | Where-Object { $_ -in $groups }).Count -gt 0) -or (@($u.includeRoles | Where-Object { $_ -in $roles }).Count -gt 0)
    if (-not $included) { return 'NotIncluded' }
    $excluded = (@($u.excludeUsers) -contains $Account.Id) -or
        (@($u.excludeGroups | Where-Object { $_ -in $groups }).Count -gt 0) -or (@($u.excludeRoles | Where-Object { $_ -in $roles }).Count -gt 0)
    if ($excluded) { 'Excluded' } else { 'Applies' }
}

function Get-MtrCaResourceScope {
    param([Parameter(Mandatory)]$Policy, [Parameter(Mandatory)]$Baseline)
    $apps = $Policy.conditions.applications
    $inc = Get-MtrArray $apps.includeApplications
    $exc = Get-MtrArray $apps.excludeApplications
    $office365Members = @('Office365', 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe', '00000003-0000-0ff1-ce00-000000000000')
    $covered = foreach ($r in $Baseline.ConditionalAccess.RequiredResources) {
        $isIncluded = ($inc -contains 'All') -or ($inc -contains $r.Id) -or ($inc -contains 'Office365' -and $r.Id -in $office365Members)
        $isExcluded = ($exc -contains $r.Id) -or ($exc -contains 'Office365' -and $r.Id -in $office365Members)
        if ($isIncluded -and -not $isExcluded) { $r.Name }
    }
    $relevant = @($inc | Where-Object { $_ -in $Baseline.ConditionalAccess.RelevantApplicationIds }).Count -gt 0
    [pscustomobject]@{
        IsRelevant      = $relevant -or (Get-MtrCount $apps.includeUserActions) -gt 0
        AllResources    = $inc -contains 'All'
        RequiredCovered = Get-MtrArray $covered
        UserActions     = Get-MtrArray $apps.includeUserActions
    }
}

function Get-MtrCaPlatformScope {
    param([Parameter(Mandatory)]$Policy)
    $p = $Policy.conditions.platforms
    if (-not $p -or -not (Get-MtrCount $p.includePlatforms)) { return @('windows', 'android') }
    $inc = Get-MtrArray $p.includePlatforms
    $exc = Get-MtrArray $p.excludePlatforms
    @(foreach ($plat in 'windows', 'android') { if (($inc -contains 'all' -or $inc -contains $plat) -and $exc -notcontains $plat) { $plat } })
}

function Get-MtrMtrGroupForExclusion {
    # The best existing group to use for "exclude Teams Rooms" edits and templates.
    param([Parameter(Mandatory)]$Model)
    $Model.Groups | Where-Object IsMtrLike | Sort-Object @{ e = 'SecurityEnabled'; Descending = $true }, @{ e = 'MtrMemberCount'; Descending = $true } | Select-Object -First 1
}

function Get-MtrCaEvaluation {
    <#
    .SYNOPSIS
        Evaluates every CA policy against the Teams Rooms accounts and lists the issues found.
    #>
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline)
    $mtr = Get-MtrArray $Model.MtrAccounts
    $mtrIds = @($mtr | ForEach-Object Id)
    $mtrLikeGroups = @($Model.Groups | Where-Object IsMtrLike | ForEach-Object Id)
    $unsupported = $Baseline.ConditionalAccess.UnsupportedBuiltInControls

    foreach ($policy in (Get-MtrArray $Context.ConditionalAccess.Policies)) {
        if (-not $policy -or $policy.state -eq 'disabled') { continue }
        $scopes = @($mtr | ForEach-Object { [pscustomobject]@{ Account = $_; Scope = Get-MtrCaUserScope -Policy $policy -Account $_ } })
        $applies = @($scopes | Where-Object Scope -eq 'Applies' | ForEach-Object Account)
        $excluded = @($scopes | Where-Object Scope -eq 'Excluded' | ForEach-Object Account)
        if (-not $applies.Count -and -not $excluded.Count) { continue }

        $users = $policy.conditions.users
        $includeUsers = @($users.includeUsers | Where-Object { $_ -notin 'All', 'None', 'GuestsOrExternalUsers' })
        $dedicatedByUsers = $includeUsers.Count -and (@($includeUsers | Where-Object { $_ -in $mtrIds }).Count / $includeUsers.Count) -ge 0.8
        $dedicatedByGroups = (Get-MtrCount $users.includeGroups) -and @($users.includeGroups | Where-Object { $_ -notin $mtrLikeGroups }).Count -eq 0
        $isDedicated = (@($users.includeUsers) -notcontains 'All') -and -not (Get-MtrCount $users.includeRoles) -and ($dedicatedByUsers -or $dedicatedByGroups) -and $applies.Count

        $platforms = @(Get-MtrCaPlatformScope -Policy $policy)
        $clientApps = Get-MtrArray $policy.conditions.clientAppTypes
        $legacyOnly = $clientApps.Count -and -not @($clientApps | Where-Object { $_ -in 'all', 'browser', 'mobileAppsAndDesktopClients' }).Count
        $resource = Get-MtrCaResourceScope -Policy $policy -Baseline $Baseline
        $locations = $policy.conditions.locations
        $hasLocation = $locations -and (Get-MtrCount $locations.includeLocations) -and -not (@($locations.includeLocations) -contains 'All' -and -not (Get-MtrCount $locations.excludeLocations))
        $grant = $policy.grantControls
        $builtIn = Get-MtrArray $grant.builtInControls
        $operator = if ($grant.operator) { [string]$grant.operator } else { 'OR' }
        $requiresCompliant = $builtIn -contains 'compliantDevice'
        $compliantAlternative = $operator -eq 'OR' -and $requiresCompliant
        $session = $policy.sessionControls
        $flows = [string]$policy.conditions.authenticationFlows.transferMethods
        $reportOnly = $policy.state -eq 'enabledForReportingButNotEnforced'

        $affectsRooms = $applies.Count -and $platforms.Count -and -not $legacyOnly -and $resource.IsRelevant
        $issues = [System.Collections.Generic.List[object]]::new()
        $addIssue = {
            param([string]$Id, [string]$Severity, [string]$Title, [string]$Impact, [object[]]$Accounts)
            if (-not @($Accounts | Where-Object { $_ }).Count) { return }
            $issues.Add([pscustomobject]@{ Id = $Id; Severity = $Severity; Title = $Title; Impact = $Impact; Accounts = Get-MtrArray $Accounts })
        }

        if ($affectsRooms) {
            $windowsAccounts = @($applies | Where-Object { 'Windows' -in $_.Platforms -or -not (Get-MtrCount $_.Platforms) })
            $androidAccounts = @($applies | Where-Object { 'Android' -in $_.Platforms })
            if ('windows' -notin $platforms) { $windowsAccounts = @() }
            if ('android' -notin $platforms) { $androidAccounts = @() }

            if ($builtIn -contains 'block') {
                if ($flows -match 'deviceCodeFlow') {
                    & $addIssue 'CA-04' 'High' 'Blocks device code flow for room accounts' 'Remote sign-in of Android Teams devices (microsoft.com/devicelogin from Teams Admin Center) stops working.' $androidAccounts
                }
                elseif ($resource.RequiredCovered.Count -and -not $hasLocation) {
                    & $addIssue 'CA-05' 'Critical' "Blocks resources Teams Rooms need ($($resource.RequiredCovered -join ', '))" 'Room accounts in scope cannot sign in on the listed platforms.' $applies
                }
            }
            if (($builtIn -contains 'mfa' -or $grant.authenticationStrength) -and -not $compliantAlternative) {
                $what = if ($grant.authenticationStrength) { "authentication strength '$($grant.authenticationStrength.displayName)'" } else { 'MFA' }
                $unknownPlatform = @($windowsAccounts | Where-Object { -not (Get-MtrCount $_.Platforms) }).Count
                $suffix = if ($unknownPlatform) { " - includes $unknownPlatform room(s) whose device platform could not be determined" } else { '' }
                if ($windowsAccounts.Count) { & $addIssue 'CA-03' 'Critical' "Requires $what (not supported on Teams Rooms on Windows)$suffix" 'Windows rooms cannot complete MFA; sign-in fails.' $windowsAccounts }
                if ($androidAccounts.Count) {
                    $sev = if ($grant.authenticationStrength) { 'Critical' } else { 'High' }
                    & $addIssue 'CA-03' $sev "Requires $what on Android rooms" 'Interactive MFA on a shared room device is not viable; Microsoft recommends compliant device plus trusted location instead.' $androidAccounts
                }
            }
            elseif (($builtIn -contains 'mfa' -or $grant.authenticationStrength) -and $compliantAlternative) {
                & $addIssue 'CA-03' 'Low' 'Requires MFA OR a compliant device' 'Rooms rely on the compliant-device alternative; a non-compliant room will be prompted for MFA and fail.' $applies
            }
            foreach ($control in $builtIn) {
                $name = Get-MtrPropertyValue $unsupported $control
                if (-not $name) { continue }
                $sev = if ($compliantAlternative) { 'Low' } else { 'High' }
                & $addIssue 'CA-06' $sev "Uses unsupported grant control: $name" 'This control is not supported for Teams Rooms accounts.' $applies
            }
            if ((Get-MtrCount $grant.termsOfUse)) { & $addIssue 'CA-06' 'High' 'Requires Terms of Use acceptance' 'Teams devices cannot accept terms of use.' $applies }
            if ($session) {
                if ($session.signInFrequency.isEnabled) { & $addIssue 'CA-07' 'High' 'Sign-in frequency session control' 'Rooms are periodically signed out; not supported.' $applies }
                if ($session.persistentBrowser.isEnabled) { & $addIssue 'CA-07' 'Medium' 'Persistent browser session control' 'Not supported for Teams Rooms.' $applies }
                if ($session.applicationEnforcedRestrictions.isEnabled) { & $addIssue 'CA-07' 'Medium' 'App enforced restrictions' 'Not supported for Teams Rooms.' $applies }
                if ($session.cloudAppSecurity.isEnabled) { & $addIssue 'CA-07' 'Medium' 'Conditional Access App Control' 'Not supported for Teams Rooms.' $applies }
                if ($session.continuousAccessEvaluation.mode -and $session.continuousAccessEvaluation.mode -ne 'disabled') { & $addIssue 'CA-07' 'High' "Customized continuous access evaluation ($($session.continuousAccessEvaluation.mode))" 'Microsoft states this must be set to Disable for Teams devices or they become unstable.' $applies }
                if ($session.disableResilienceDefaults) { & $addIssue 'CA-07' 'Medium' 'Resilience defaults disabled' 'Not supported for Teams Rooms; rooms lose sign-in during Entra outages.' $applies }
                if ($session.secureSignInSession.isEnabled) { & $addIssue 'CA-07' 'High' 'Token protection for sign-in sessions' 'Not supported for Teams Rooms.' $applies }
            }
            if ($policy.conditions.insiderRiskLevels) { & $addIssue 'CA-08' 'High' 'Insider risk condition' 'Not supported for Teams Rooms.' $applies }
            if ($resource.UserActions -contains 'urn:user:registerdevice' -and ($builtIn -contains 'mfa' -or $grant.authenticationStrength)) {
                & $addIssue 'CA-09' 'High' 'Requires MFA to register or join devices' 'Android rooms cannot register and Windows rooms cannot Entra-join with the resource account.' $applies
            }
            if ($grant.authenticationStrength -and $compliantAlternative) {
                & $addIssue 'CA-06' 'Medium' 'Authentication strength present (even as an alternative)' 'Authentication strength is not supported for policies that affect Teams devices.' $applies
            }
        }

        [pscustomobject]@{
            Policy            = $policy
            Id                = $policy.id
            Name              = $policy.displayName
            State             = $policy.state
            ReportOnly        = $reportOnly
            IsDedicated       = [bool]$isDedicated
            AffectsRooms      = [bool]$affectsRooms
            Applies           = $applies
            Excluded          = $excluded
            Platforms         = $platforms
            LegacyOnly        = [bool]$legacyOnly
            RequiresCompliant = $requiresCompliant -and $operator -eq 'AND' -or ($requiresCompliant -and $builtIn.Count -eq 1)
            HasLocation       = [bool]$hasLocation
            IsBlock           = $builtIn -contains 'block'
            Resource          = $resource
            Issues            = $issues.ToArray()
        }
    }
}

function Test-MtrConditionalAccess {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $mtr = Get-MtrArray $Model.MtrAccounts
    if (-not $Context.ConditionalAccess) { return }
    $policies = @($Context.ConditionalAccess.Policies | Where-Object { $_ })
    if (-not $policies.Count) {
        $sd = $Context.Identity.Extra.SecurityDefaults
        if (-not ($sd -and $sd.isEnabled)) {
            New-MtrFinding -CheckId 'CA-00' -Severity Medium -Category 'Conditional Access' -Title 'No Conditional Access policies exist' `
                -Impact 'Room accounts are protected only by their password, from any network and any device.' `
                -Recommendation 'Create a Teams Rooms policy requiring a compliant device and trusted location (see templates\CA-TeamsRooms-*.json).' -FixLocation 'Entra ID' -Reference $links.ConditionalAccess
        }
        return
    }
    if (-not $mtr.Count) { return }

    $evaluations = @(Get-MtrCaEvaluation -Model $Model -Context $Context -Baseline $Baseline)
    $mtrGroup = Get-MtrMtrGroupForExclusion -Model $Model
    $mtrGroupId = if ($mtrGroup) { $mtrGroup.Id } else { '<TeamsRoomsGroupId>' }

    # Issues per policy
    foreach ($e in $evaluations) {
        foreach ($issue in $e.Issues) {
            $sev = if ($e.ReportOnly) { Step-MtrSeverity $issue.Severity } else { $issue.Severity }
            $prefix = if ($e.ReportOnly) { '(Report-only) ' } else { '' }
            New-MtrFinding -CheckId $issue.Id -Severity $sev -Category 'Conditional Access' -Title "$prefix'$($e.Name)': $($issue.Title)" `
                -Target "$((Get-MtrCount $issue.Accounts)) room accounts" -AffectedObjects @($issue.Accounts | ForEach-Object UserPrincipalName) `
                -Detail $(if ($e.ReportOnly) { 'The policy is in report-only mode; this becomes a sign-in failure when it is enabled.' } else { "Policy state: $($e.State)." }) `
                -Impact $issue.Impact `
                -Recommendation $(if ($e.IsDedicated) { 'Remove the unsupported control from this Teams Rooms policy; use compliant device and trusted location instead.' } else { "Exclude the Teams Rooms group from '$($e.Name)' and cover rooms with a dedicated policy." }) `
                -FixLocation 'Entra ID' -Reference $links.SupportedCA
        }
    }

    # CA-01 Dedicated policy
    $dedicated = @($evaluations | Where-Object { $_.IsDedicated -and -not $_.ReportOnly })
    $strongDedicated = @($dedicated | Where-Object { $_.RequiresCompliant -or ($_.IsBlock -and $_.HasLocation) -or (@($_.Policy.grantControls.builtInControls) -contains 'compliantDevice') })
    if (-not $dedicated.Count) {
        New-MtrFinding -CheckId 'CA-01' -Severity High -Category 'Conditional Access' -Title 'No dedicated Conditional Access policy for Teams Rooms' `
            -Detail 'No enabled policy targets a group (or user list) made up of Teams Rooms accounts.' `
            -Impact 'Rooms are either caught by user policies they cannot satisfy, or excluded and left unprotected.' `
            -Recommendation 'Create Teams Rooms policies: require a compliant device and block sign-in outside trusted named locations, scoped to Windows and Android, and exclude the rooms group from every other policy. Report-only templates are in templates\.' `
            -FixLocation 'Entra ID' -Reference $links.ConditionalAccess
    }
    elseif (-not $strongDedicated.Count) {
        New-MtrFinding -CheckId 'CA-01' -Severity Medium -Category 'Conditional Access' -Title 'Teams Rooms policies do not require a compliant device or trusted location' `
            -AffectedObjects @($dedicated | ForEach-Object Name) `
            -Impact 'Without MFA, rooms need a substitute second factor; Microsoft recommends compliant device plus known network location.' `
            -Recommendation 'Add "Require device to be marked as compliant" and a location-based block to the Teams Rooms policies.' -FixLocation 'Entra ID' -Reference $links.AndroidAuth
    }
    if ($dedicated.Count) {
        $covered = @($dedicated | ForEach-Object { $_.Applies } | ForEach-Object Id | Sort-Object -Unique)
        $uncovered = @($mtr | Where-Object { $_.Id -notin $covered })
        if ($uncovered.Count) {
            New-MtrFinding -CheckId 'CA-02' -Severity Medium -Category 'Conditional Access' -Title 'Teams Rooms accounts not covered by the Teams Rooms Conditional Access policies' `
                -Target "$($uncovered.Count) accounts" -AffectedObjects @($uncovered | ForEach-Object UserPrincipalName) `
                -Detail ('Dedicated policies: {0}.' -f (($dedicated | ForEach-Object Name) -join ', ')) `
                -Impact 'Usually a symptom of name-based group rules missing rooms from other buildings.' `
                -Recommendation 'Add these accounts to the Teams Rooms group, preferably by switching it to a license- or attribute-based dynamic rule.' -FixLocation 'Entra ID' -Reference $links.DynamicGroups
        }
    }

    # CA-10 General policies that still apply to rooms
    $general = @($evaluations | Where-Object { -not $_.IsDedicated -and $_.AffectsRooms })
    if ($general.Count) {
        $cmds = [System.Collections.Generic.List[string]]::new()
        $cmds.Add('# Prefer making these edits in the Entra admin center (Protection > Conditional Access). If using Graph, note that')
        $cmds.Add('# the excludeGroups array is replaced entirely, so the full merged list is supplied for each policy.')
        foreach ($e in $general) {
            $merged = @(@($e.Policy.conditions.users.excludeGroups) + @($mtrGroupId) | Where-Object { $_ } | Sort-Object -Unique)
            $list = ($merged | ForEach-Object { ConvertTo-MtrPsLiteral $_ }) -join ','
            $cmds.Add("# $($e.Name)")
            $cmds.Add("Invoke-MgGraphRequest -Method PATCH -Uri 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies/$($e.Id)' -Body (@{ conditions = @{ users = @{ excludeGroups = @($list) } } } | ConvertTo-Json -Depth 5)")
        }
        New-MtrFinding -CheckId 'CA-10' -Severity Medium -Category 'Conditional Access' -Title "$($general.Count) general Conditional Access policies apply to Teams Rooms accounts" `
            -AffectedObjects @($general | ForEach-Object { '{0} ({1}; {2} rooms{3})' -f $_.Name, $_.State, (Get-MtrCount $_.Applies), $(if ($_.Name -match '^Microsoft-managed') { '; Microsoft-managed' }) }) `
            -Detail $(if ($mtrGroup) { "Suggested exclusion group: $($mtrGroup.DisplayName) ($($mtrGroup.Id))." } else { 'No existing Teams Rooms group was found - create one first (see GRP findings).' }) `
            -Impact 'Microsoft recommends excluding Teams Rooms accounts from all other policies so user-focused controls (MFA, sign-in frequency, registration) never reach them.' `
            -Recommendation 'Exclude the Teams Rooms group from each listed policy, including Microsoft-managed policies.' -FixLocation 'Entra ID' `
            -RemediationCommand $cmds.ToArray() -Reference $links.ConditionalAccess
    }

    # CA-11 Compliance required but room cannot comply
    $enforcedCompliance = @($evaluations | Where-Object { $_.AffectsRooms -and -not $_.ReportOnly -and @($_.Policy.grantControls.builtInControls) -contains 'compliantDevice' -and ($_.Policy.grantControls.operator -eq 'AND' -or (Get-MtrCount $_.Policy.grantControls.builtInControls) -eq 1) })
    if ($enforcedCompliance.Count) {
        $subject = @($enforcedCompliance | ForEach-Object Applies | Sort-Object Id -Unique)
        $noIntune = @($subject | Where-Object { -not $_.HasIntunePlan })
        if ($noIntune.Count) {
            New-MtrFinding -CheckId 'CA-11' -Severity High -Category 'Conditional Access' -Title 'Rooms without Intune are required to be compliant' `
                -Target "$($noIntune.Count) accounts" -AffectedObjects @($noIntune | ForEach-Object { '{0} ({1}{2})' -f $_.UserPrincipalName, $_.LicenseTier, $(if ($_.LicenseTier -ne 'Basic' -and $_.HasMtrLicense) { ', Intune service plan disabled' }) }) `
                -Detail ('Compliance is required by: {0}.' -f (($enforcedCompliance | ForEach-Object Name) -join ', ')) `
                -Impact 'Teams Rooms Basic (or a license with Intune disabled) cannot enroll, so the device can never be compliant and sign-in is blocked.' `
                -Recommendation 'Move these rooms to Teams Rooms Pro, or exclude them from the compliance requirement.' -FixLocation 'Entra ID' -Reference $links.Licensing
        }
        if ($Context.Intune) {
            $bad = @($subject | Where-Object { $_.HasIntunePlan } | Where-Object {
                    $devs = Get-MtrArray $_.Devices
                    -not $devs.Count -or @($devs | Where-Object { $_.ComplianceState -and $_.ComplianceState -notin 'compliant', 'inGracePeriod' }).Count
                })
            if ($bad.Count) {
                New-MtrFinding -CheckId 'CA-12' -Severity High -Category 'Conditional Access' -Title 'Rooms required to be compliant have no compliant managed device' `
                    -Target "$($bad.Count) accounts" -AffectedObjects @($bad | ForEach-Object { '{0} ({1})' -f $_.UserPrincipalName, $(if ((Get-MtrCount $_.Devices)) { (@($_.Devices | ForEach-Object { "$($_.Name): $($_.ComplianceState)" }) -join ', ') } else { 'no managed device found' }) }) `
                    -Impact 'Sign-in is blocked (error 53000) until the device reports compliant.' `
                    -Recommendation 'See the Intune findings for failing compliance settings; Windows rooms that are not enrolled in Intune cannot satisfy this control.' -FixLocation 'Intune'
            }
        }
    }

    # Named locations used by Teams Rooms policies
    $locIds = @($dedicated | ForEach-Object { @($_.Policy.conditions.locations.includeLocations) + @($_.Policy.conditions.locations.excludeLocations) } | Where-Object { $_ -and $_ -notin 'All', 'AllTrusted' } | Sort-Object -Unique)
    if ($locIds.Count) {
        $named = @($Context.ConditionalAccess.NamedLocations | Where-Object { $_.Id -in $locIds })
        New-MtrFinding -CheckId 'CA-13' -Severity Info -Category 'Conditional Access' -Title 'Named locations used by Teams Rooms policies' `
            -AffectedObjects @($named | ForEach-Object { '{0} (trusted: {1}; {2})' -f $_.DisplayName, $_.IsTrusted, $(if ((Get-MtrCount $_.IpRanges)) { Format-MtrList -Items $_.IpRanges -Max 6 } else { Format-MtrList -Items $_.Countries -Max 6 }) }) `
            -Recommendation 'Make sure every site with Teams Rooms egresses from one of these ranges.'
    }
}
