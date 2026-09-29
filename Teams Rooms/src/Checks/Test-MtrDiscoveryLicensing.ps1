# Discovery (DISC) and Licensing (LIC) checks. Pure functions over the discovery model.

function Test-MtrDiscovery {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $mtr = Get-MtrArray $Model.MtrAccounts

    $byClass = $Model.Accounts | Group-Object Classification | ForEach-Object { '{0}: {1}' -f $_.Name, $_.Count }
    if (-not $mtr.Count) {
        $others = if ($byClass) { " Other accounts examined - $($byClass -join ', ')." } else { '' }
        New-MtrFinding -CheckId 'DISC-00' -Severity High -Category 'Discovery' -Title 'No Teams Rooms accounts identified' `
            -Detail "No account had a Teams Rooms license, a Teams device, or enough room signals to be classified as a Teams Room. Most checks had nothing to evaluate.$others" `
            -Recommendation 'Re-run with -ResourceAccountUpn, -ResourceAccountCsv, -MtrGroupId or -UpnPattern (one regex per building prefix) to seed discovery, and check the Coverage section for collection failures.'
    }
    else {
        Test-MtrDiscoveryInventory -Model $Model -Mtr $mtr -ByClass $byClass -Links $links
    }
    Test-MtrDiscoveryUnusedRoomAccount -Model $Model -Links $links
}

function Test-MtrDiscoveryInventory {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)][object[]]$Mtr, $ByClass, $Links)
    $android = @($Model.Devices | Where-Object Platform -eq 'Android')
    $windows = @($Model.Devices | Where-Object Platform -eq 'Windows')
    $models = $Model.Devices | Group-Object { '{0} {1}' -f $_.Manufacturer, $_.Model } | Sort-Object Count -Descending | ForEach-Object { '{0} x{1}' -f $_.Name, $_.Count }
    New-MtrFinding -CheckId 'DISC-01' -Severity Info -Category 'Discovery' -Title 'Teams Rooms inventory' `
        -Detail ("Accounts - {0}. Devices - Android: {1}, Windows: {2}. Models: {3}. Each account's evidence is listed in Rooms.csv and the room inventory." -f ($byClass -join ', '), $android.Count, $windows.Count, (Format-MtrList -Items @($models) -Max 12))

    # Naming: explain why targeting must not rely on name prefixes
    $prefixGroups = @($mtr | Group-Object NamePrefix | Sort-Object Count -Descending)
    if ($prefixGroups.Count -gt 1) {
        $byList = foreach ($g in $prefixGroups) {
            $lists = @($g.Group | ForEach-Object RoomLists | Where-Object { $_ } | Sort-Object -Unique)
            '{0} ({1} rooms{2})' -f $g.Name, $g.Count, $(if ($lists.Count) { '; room lists: ' + (Format-MtrList -Items $lists -Max 3) } else { '' })
        }
        New-MtrFinding -CheckId 'DISC-02' -Severity Info -Category 'Discovery' -Title "Teams Rooms accounts use $($prefixGroups.Count) different name prefixes" `
            -Detail ("Prefixes found: {0}. Discovery here used licenses, devices, mailbox type and group membership, not names." -f ($byList -join '; ')) `
            -Impact 'Dynamic groups, Conditional Access exclusions and Intune assignments based on a name prefix will silently miss rooms from other buildings.' `
            -Recommendation 'Target Teams Rooms by something that does not depend on naming: a license-based dynamic group, or an on-prem AD extensionAttribute synced to Entra. Suggested rules are in templates\DynamicGroup-Rules.txt. Renaming accounts is not required.' `
            -FixLocation 'Entra ID' -Reference $links.DynamicGroups
    }
}

function Test-MtrDiscoveryUnusedRoomAccount {
    param([Parameter(Mandatory)]$Model, $Links)
    $inconsistent = @($Model.Accounts | Where-Object { $_.Classification -eq 'Inconsistent' })
    $enabledNoUse = @($inconsistent | Where-Object { $_.IsRoomMailbox -and $_.AccountEnabled -and -not $_.HasMtrLicense -and -not $_.HasSharedDeviceLicense -and -not (Get-MtrCount $_.Devices) })
    if ($enabledNoUse.Count) {
        $synced = @($enabledNoUse | Where-Object IsSynced)
        $cmds = @('# Confirm each room is not a Teams Room before disabling its sign-in.')
        foreach ($a in $synced) { $cmds += "Disable-ADAccount -Identity $(ConvertTo-MtrPsLiteral ($a.User.onPremisesSamAccountName))   # $($a.UserPrincipalName)" }
        foreach ($a in @($enabledNoUse | Where-Object { -not $_.IsSynced })) { $cmds += "Update-MgUser -UserId $(ConvertTo-MtrPsLiteral $a.Id) -AccountEnabled:`$false   # $($a.UserPrincipalName)" }
        New-MtrFinding -CheckId 'DISC-03' -Severity Medium -Category 'Discovery' -Title "$($enabledNoUse.Count) room mailbox account(s) can sign in but show no Teams Rooms use" `
            -Target "$($enabledNoUse.Count) accounts" -AffectedObjects @($enabledNoUse | ForEach-Object UserPrincipalName) `
            -Detail 'These room mailboxes have an enabled account but no Teams Rooms or Shared Devices license and no managed Teams device.' `
            -Impact 'An enabled room account with a password is sign-in surface nobody watches. If it is actually a Teams Room, it is unlicensed.' `
            -Recommendation 'If the room has a Teams device, assign a Teams Rooms license. Otherwise disable the account (room mailboxes do not need an enabled account for booking). Synced accounts must be disabled on-prem.' `
            -FixLocation $(if ($synced.Count) { 'On-prem AD' } else { 'Entra ID' }) -RemediationCommand $cmds -Reference $links.ResourceAccount
    }
}

function Test-MtrLicensing {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $mtr = Get-MtrArray $Model.MtrAccounts
    $skus = @($Context.Licensing.Skus | Where-Object { $_ })

    $unlicensed = @($mtr | Where-Object { -not $_.HasMtrLicense })
    $sharedOnRoom = @($unlicensed | Where-Object { $_.HasSharedDeviceLicense -and -not $_.IsPanelOnly })
    $suiteOnly = @($unlicensed | Where-Object { $_.HasUserSuiteLicense -and -not $_.HasSharedDeviceLicense })
    $none = @($unlicensed | Where-Object { -not $_.HasSharedDeviceLicense -and -not $_.HasUserSuiteLicense })

    if ($sharedOnRoom.Count) {
        New-MtrFinding -CheckId 'LIC-01' -Severity High -Category 'Licensing' -Title 'Teams Shared Devices license used on Teams Rooms' `
            -Target "$($sharedOnRoom.Count) accounts" -AffectedObjects @($sharedOnRoom | ForEach-Object UserPrincipalName) `
            -Detail 'These accounts have a Teams Shared Devices license and at least one device that is not a panel.' `
            -Impact 'Shared Devices licenses are not supported on and do not work with Teams Rooms devices.' `
            -Recommendation 'Assign Teams Rooms Pro (or Basic for small estates). Shared Devices is only appropriate for a panel-only room.' `
            -FixLocation 'Entra ID' -Reference $links.RoomsPlan
    }
    if ($none.Count) {
        New-MtrFinding -CheckId 'LIC-02' -Severity High -Category 'Licensing' -Title 'Teams Rooms accounts with no Teams Rooms license' `
            -Target "$($none.Count) accounts" -AffectedObjects @($none | ForEach-Object UserPrincipalName) `
            -Detail 'Classified as Teams Rooms (device, group or room signals) but no Teams Rooms, Shared Devices or user license was found.' `
            -Impact 'The device cannot use Teams without a license.' `
            -Recommendation 'Assign a Teams Rooms Pro license, ideally through a license-based group (see DynamicGroup-Rules.txt).' `
            -FixLocation 'Entra ID' -Reference $links.Licensing
    }
    if ($suiteOnly.Count) {
        New-MtrFinding -CheckId 'LIC-03' -Severity Medium -Category 'Licensing' -Title 'Teams Rooms signed in with an enterprise user license' `
            -Target "$($suiteOnly.Count) accounts" -AffectedObjects @($suiteOnly | ForEach-Object UserPrincipalName) `
            -Detail 'These accounts run on an enterprise user suite (for example E3/E5) instead of a Teams Rooms license.' `
            -Impact 'Enterprise per-user suites are not authorized for shared meeting devices, and Android rooms show the personal user interface unless an IP phone policy forces MeetingSignIn.' `
            -Recommendation 'Move these rooms to Teams Rooms Pro and remove the user suite.' -FixLocation 'Entra ID' -Reference $links.RoomsPlan
    }

    $both = @($mtr | Where-Object { $_.HasMtrLicense -and $_.HasUserSuiteLicense })
    if ($both.Count) {
        New-MtrFinding -CheckId 'LIC-04' -Severity Low -Category 'Licensing' -Title 'Teams Rooms accounts also hold an enterprise user license' `
            -Target "$($both.Count) accounts" -AffectedObjects @($both | ForEach-Object UserPrincipalName) `
            -Detail 'Both a Teams Rooms license and an enterprise user suite are assigned.' -Impact 'Unneeded cost and a larger set of services the room account can reach.' `
            -Recommendation 'Remove the user suite; Teams Rooms Pro includes everything the device needs.' -FixLocation 'Entra ID'
    }

    $basicConsumed = ($skus | Where-Object IsBasic | Measure-Object -Property Consumed -Sum).Sum
    if ($basicConsumed -gt $Baseline.Licensing.BasicMaxLicenses) {
        New-MtrFinding -CheckId 'LIC-05' -Severity High -Category 'Licensing' -Title "More than $($Baseline.Licensing.BasicMaxLicenses) Teams Rooms Basic licenses assigned ($basicConsumed)" `
            -Impact 'Teams Rooms Basic is limited to 25 rooms per tenant; additional rooms must use Pro.' -Recommendation 'Move rooms beyond 25 to Teams Rooms Pro.' `
            -FixLocation 'Entra ID' -Reference $links.Licensing
    }
    $basicRooms = @($mtr | Where-Object LicenseTier -eq 'Basic')
    if ($basicRooms.Count) {
        New-MtrFinding -CheckId 'LIC-06' -Severity Info -Category 'Licensing' -Title "$($basicRooms.Count) room(s) on Teams Rooms Basic" `
            -AffectedObjects @($basicRooms | ForEach-Object UserPrincipalName) `
            -Detail 'Basic does not include Intune, Entra ID P1 (Conditional Access), Pro Management or password-less migration.' `
            -Impact 'These rooms cannot satisfy a compliant-device Conditional Access requirement and cannot enroll Android devices in Intune.' `
            -Recommendation 'Plan Pro licenses for rooms that must meet Conditional Access / Intune requirements. See CA findings for Basic rooms caught by compliance policies.' `
            -Reference $links.Licensing
    }

    # Disabled service plans inside Teams Rooms SKUs
    $planSeverity = [ordered]@{ '^TEAMS' = 'Critical'; '^INTUNE_A' = 'High'; '^AAD_PREMIUM' = 'Medium' }
    $disabled = @{}
    foreach ($a in $mtr) { foreach ($p in (Get-MtrArray $a.DisabledMtrPlans)) { if (-not $disabled[$p]) { $disabled[$p] = [System.Collections.Generic.List[string]]::new() }; $disabled[$p].Add($a.UserPrincipalName) } }
    foreach ($plan in $disabled.Keys) {
        $sev = 'Low'
        foreach ($pattern in $planSeverity.Keys) { if ($plan -match $pattern) { $sev = $planSeverity[$pattern]; break } }
        $impact = switch -Regex ($plan) {
            '^TEAMS' { 'Teams is disabled for the room; it cannot sign in to Teams.' }
            '^INTUNE_A' { 'Intune is disabled: Android rooms cannot enroll and compliance-based Conditional Access will block sign-in.' }
            '^AAD_PREMIUM' { 'Entra ID P1 is disabled for the account; Conditional Access coverage for the room depends on it.' }
            default { 'A service included in the Teams Rooms license is turned off.' }
        }
        New-MtrFinding -CheckId 'LIC-07' -Severity $sev -Category 'Licensing' -Title "Service plan $plan disabled in the Teams Rooms license" `
            -Target "$($disabled[$plan].Count) accounts" -AffectedObjects @($disabled[$plan]) -Impact $impact `
            -Recommendation 'Re-enable the service plan in the license assignment (or the licensing group).' -FixLocation 'Entra ID' -Reference $links.Licensing
    }

    $errors = @(foreach ($a in $mtr) { foreach ($s in (Get-MtrArray $a.LicenseAssignmentStates)) { if ($s.error -and $s.error -ne 'None') { '{0}: {1} ({2})' -f $a.UserPrincipalName, $s.error, $(if ($s.assignedByGroup) { 'via group' } else { 'direct' }) } } })
    if ($errors.Count) {
        New-MtrFinding -CheckId 'LIC-08' -Severity High -Category 'Licensing' -Title 'License assignment errors on Teams Rooms accounts' -AffectedObjects $errors `
            -Impact 'The license is not actually applied, so services are missing.' -Recommendation 'Resolve the error (usually out of licenses or a conflicting plan) in the Entra admin center.' -FixLocation 'Entra ID'
    }

    foreach ($sku in @($skus | Where-Object IsTeamsRooms)) {
        if ($sku.CapabilityStatus -in 'Warning', 'Suspended', 'LockedOut' -or $sku.Consumed -gt $sku.Enabled) {
            New-MtrFinding -CheckId 'LIC-09' -Severity High -Category 'Licensing' -Title "Teams Rooms subscription $($sku.SkuPartNumber) needs attention" `
                -Detail ("Status {0}; enabled {1}, consumed {2}, warning {3}, suspended {4}." -f $sku.CapabilityStatus, $sku.Enabled, $sku.Consumed, $sku.Warning, $sku.Suspended) `
                -Impact 'Rooms lose service when the subscription lapses or is over-assigned.' -Recommendation 'Renew or true-up the subscription.' -FixLocation 'None'
        }
        elseif ($sku.Enabled - $sku.Consumed -gt 0) {
            New-MtrFinding -CheckId 'LIC-10' -Severity Info -Category 'Licensing' -Title "$($sku.Enabled - $sku.Consumed) unused $($sku.SkuPartNumber) license(s)" `
                -Detail ("Enabled {0}, consumed {1}." -f $sku.Enabled, $sku.Consumed)
        }
    }

    $direct = @($mtr | Where-Object { $_.HasMtrLicense -and -not @($_.LicenseAssignmentStates | Where-Object { $_.assignedByGroup -and $Model.SkuById[[string]$_.skuId].IsTeamsRooms }).Count })
    if ($direct.Count -and $mtr.Count -gt 3) {
        New-MtrFinding -CheckId 'LIC-11' -Severity Low -Category 'Licensing' -Title "$($direct.Count) Teams Rooms license(s) are assigned directly" `
            -AffectedObjects @($direct | ForEach-Object UserPrincipalName) `
            -Recommendation 'Consider group-based licensing from a Teams Rooms group so new rooms are licensed consistently.' -FixLocation 'Entra ID'
    }
}
