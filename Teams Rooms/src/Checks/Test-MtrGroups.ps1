# Groups (GRP) checks and naming-independent dynamic group rule suggestions.

function Get-MtrSuggestedGroupRule {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline)
    $skus = @($Context.Licensing.Skus | Where-Object { $_ })
    $nonMtrPlanIds = @($skus | Where-Object { -not $_.IsTeamsRooms } | ForEach-Object { $_.ServicePlans } | ForEach-Object servicePlanId | Sort-Object -Unique)
    $plans = @($skus | Where-Object IsTeamsRooms | ForEach-Object { $_.ServicePlans } |
            Where-Object { $_.servicePlanName -match $Baseline.Licensing.MtrServicePlanPattern -and $_.servicePlanId -notin $nonMtrPlanIds } |
            Sort-Object servicePlanId -Unique)
    $licenseRule = if ($plans.Count) {
        (@($plans | ForEach-Object { '(user.assignedPlans -any (assignedPlan.servicePlanId -eq "{0}" -and assignedPlan.capabilityStatus -eq "Enabled"))' -f $_.servicePlanId }) -join ' -or ')
    }
    else { $null }

    # An extensionAttribute already shared by (almost) every Teams Rooms account
    $mtr = Get-MtrArray $Model.MtrAccounts
    $others = @($Model.Accounts | Where-Object { $_.Classification -notin 'Confirmed', 'Probable' })
    $attributeCandidate = $null
    if ($mtr.Count -ge 2) {
        foreach ($i in 1..15) {
            $name = "extensionAttribute$i"
            $values = @($mtr | ForEach-Object { Get-MtrPropertyValue $_.User.onPremisesExtensionAttributes $name } | Where-Object { $_ })
            if (-not $values.Count) { continue }
            $top = $values | Group-Object | Sort-Object Count -Descending | Select-Object -First 1
            if ($top.Count / [double]$mtr.Count -ge 0.9) {
                $collisions = @($others | Where-Object { (Get-MtrPropertyValue $_.User.onPremisesExtensionAttributes $name) -eq $top.Name })
                $attributeCandidate = [pscustomobject]@{ Attribute = $name; Value = $top.Name; Coverage = [math]::Round($top.Count / [double]$mtr.Count, 2); Collisions = $collisions.Count }
                break
            }
        }
    }
    $attributeRule = if ($attributeCandidate) { 'user.{0} -eq "{1}"' -f $attributeCandidate.Attribute, $attributeCandidate.Value } else { 'user.extensionAttribute10 -eq "TeamsRoom"' }

    $teamsProfile = @($Context.Intune.EnrollmentProfiles | Where-Object { $_.isTeamsDeviceProfile }) | Select-Object -First 1
    [pscustomobject]@{
        LicenseRule        = $licenseRule
        LicensePlans       = @($plans | ForEach-Object { '{0} ({1})' -f $_.servicePlanName, $_.servicePlanId })
        AttributeRule      = $attributeRule
        AttributeCandidate = $attributeCandidate
        WindowsDeviceRule  = '(device.devicePhysicalIds -any _ -startswith "[OrderID]:{0}")' -f $Baseline.Devices.AutopilotMtrGroupTagPrefix
        AndroidDeviceRule  = '(device.enrollmentProfileName -eq "{0}")' -f $(if ($teamsProfile) { $teamsProfile.displayName } else { '<Teams AOSP enrollment profile name>' })
    }
}

function Test-MtrGroups {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $mtr = Get-MtrArray $Model.MtrAccounts
    if (-not $mtr.Count -or -not $Context.Groups) { return }
    $mtrIds = @($mtr | ForEach-Object Id)
    $mtrGroups = @($Model.Groups | Where-Object IsMtrLike | Sort-Object MtrMemberCount -Descending)
    $rules = Get-MtrSuggestedGroupRule -Model $Model -Context $Context -Baseline $Baseline
    $ruleText = "License-based: $(if ($rules.LicenseRule) { $rules.LicenseRule } else { '(no Teams Rooms-only service plan found)' }). Attribute-based (set on-prem, synced): $($rules.AttributeRule)."

    if (-not $mtrGroups.Count) {
        if ($mtr.Count -ge 2) {
            New-MtrFinding -CheckId 'GRP-01' -Severity High -Category 'Groups' -Title 'No group contains the Teams Rooms accounts' `
                -Detail "No group has at least $([int]($Baseline.Thresholds.MtrGroupRatio * 100))% Teams Rooms members. $ruleText" `
                -Impact 'Conditional Access exclusions, the Teams Rooms CA policy, compliance assignment and group-based licensing all need a reliable group of room accounts.' `
                -Recommendation 'Create a security group with a dynamic rule that does not depend on names (license- or attribute-based). Rules are in templates\DynamicGroup-Rules.txt.' `
                -FixLocation 'Entra ID' -Reference $links.DynamicGroups
        }
    }
    else {
        $best = $mtrGroups[0]
        $missing = @($mtr | Where-Object { $best.Id -notin $_.GroupIds })
        New-MtrFinding -CheckId 'GRP-02' -Severity $(if ($missing.Count) { 'Medium' } else { 'Pass' }) -Category 'Groups' `
            -Title $(if ($missing.Count) { "Teams Rooms group '$($best.DisplayName)' is missing $($missing.Count) room account(s)" } else { "Teams Rooms group '$($best.DisplayName)' contains every room account" }) `
            -AffectedObjects @($missing | ForEach-Object { '{0} (prefix {1})' -f $_.UserPrincipalName, $_.NamePrefix }) `
            -Detail ('Groups that look like Teams Rooms groups: {0}.' -f (($mtrGroups | ForEach-Object { '{0} ({1}/{2} members are rooms{3}{4})' -f $_.DisplayName, $_.MtrMemberCount, $_.MemberCount, $(if ($_.IsDynamic) { ', dynamic' }), $(if ($_.IsSynced) { ', synced from AD' }) }) -join '; ')) `
            -Impact 'Rooms outside the group miss the Teams Rooms CA policy and exclusions.' `
            -Recommendation "Switch the group to a naming-independent rule. $ruleText" -FixLocation $(if ($best.IsSynced) { 'On-prem AD' } else { 'Entra ID' }) -Reference $links.DynamicGroups

        foreach ($g in $mtrGroups) {
            $rule = [string]$g.MembershipRule
            if ($g.IsDynamic -and $rule -match 'user\.(userPrincipalName|displayName|mail|mailNickname|onPremisesSamAccountName)\s+-(startsWith|match|contains|like|notStartsWith)') {
                New-MtrFinding -CheckId 'GRP-03' -Severity Medium -Category 'Groups' -Title "Group '$($g.DisplayName)' selects rooms by name" `
                    -Detail "Rule: $rule" -Impact 'With naming that varies by building, rooms from buildings that do not match the pattern are silently left out.' `
                    -Recommendation "Replace the rule. $ruleText" -FixLocation 'Entra ID' -Reference $links.DynamicGroups
            }
            elseif (-not $g.IsDynamic -and -not $g.IsSynced) {
                New-MtrFinding -CheckId 'GRP-03' -Severity Low -Category 'Groups' -Title "Group '$($g.DisplayName)' is maintained by hand" `
                    -Impact 'New rooms depend on someone remembering to add them.' -Recommendation "Consider a dynamic rule. $ruleText" -FixLocation 'Entra ID'
            }

            # Non-room members inherit every exclusion the group has
            $members = @($g.Members | Where-Object { $_.Type -eq '#microsoft.graph.user' -and $_.Id -notin $mtrIds })
            if ($members.Count) {
                $roomOids = @($Context.Exchange.RoomMailboxes | ForEach-Object ExternalDirectoryObjectId)
                $people = @($members | Where-Object { $_.Id -notin $roomOids })
                $rooms = @($members | Where-Object { $_.Id -in $roomOids })
                $excludedFrom = @($Context.ConditionalAccess.Policies | Where-Object { $g.Id -in @($_.conditions.users.excludeGroups) } | ForEach-Object displayName)
                if ($people.Count) {
                    New-MtrFinding -CheckId 'GRP-04' -Severity High -Category 'Groups' -Title "Group '$($g.DisplayName)' contains $($people.Count) account(s) that are not Teams Rooms" `
                        -AffectedObjects @($people | ForEach-Object { if ($_.UserPrincipalName) { $_.UserPrincipalName } else { $_.DisplayName } }) `
                        -Detail $(if ($excludedFrom.Count) { "The group is excluded from: $(Format-MtrList -Items $excludedFrom -Max 8)." } else { 'The group is not currently used as a CA exclusion.' }) `
                        -Impact 'Anyone in a Teams Rooms group inherits its Conditional Access exclusions - for a person that usually means no MFA.' `
                        -Recommendation 'Remove these members, or confirm they are room accounts and license them.' -FixLocation $(if ($g.IsSynced) { 'On-prem AD' } else { 'Entra ID' })
                }
                if ($rooms.Count) {
                    New-MtrFinding -CheckId 'GRP-05' -Severity Low -Category 'Groups' -Title "Group '$($g.DisplayName)' includes $($rooms.Count) bookable room(s) with no Teams Rooms signals" `
                        -AffectedObjects @($rooms | ForEach-Object { if ($_.UserPrincipalName) { $_.UserPrincipalName } else { $_.DisplayName } }) `
                        -Recommendation 'Harmless if intended; otherwise remove them so the group maps 1:1 to Teams Rooms.'
                }
            }
        }
    }

    # Device groups for Intune targeting
    $windows = @($Model.Devices | Where-Object Platform -eq 'Windows')
    if ($windows.Count) {
        $deviceRuleGroups = @($Context.Groups.DynamicGroups | Where-Object { $_.membershipRule -match '(?i)devicePhysicalIds' -and $_.membershipRule -match [regex]::Escape($Baseline.Devices.AutopilotMtrGroupTagPrefix) })
        if (-not $deviceRuleGroups.Count) {
            New-MtrFinding -CheckId 'GRP-06' -Severity Low -Category 'Groups' -Title 'No dynamic device group for Windows Teams Rooms' `
                -Detail "Suggested rule: $($rules.WindowsDeviceRule)" `
                -Impact 'Without a device group, Windows rooms cannot be excluded from general Intune policies or targeted with Teams Rooms policies.' `
                -Recommendation 'Create the device group (requires the MTR- Autopilot group tag) and use it to exclude rooms from general Windows policies.' -FixLocation 'Entra ID' -Reference $links.AutopilotAutologin
        }
    }
}
