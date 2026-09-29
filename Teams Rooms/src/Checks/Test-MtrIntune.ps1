# Intune checks for Teams Rooms on Android (AND) and Windows (WIN), plus Teams device health (TDEV).

function Get-MtrAssignmentEffect {
    # How an Intune assignment list reaches a device: via device targeting, user targeting, or not at all.
    param([object[]]$Targets, [string[]]$DeviceGroupIds = @(), [string[]]$UserGroupIds = @())
    $device = $null; $user = $null; $excluded = $false; $filter = $false
    foreach ($t in (Get-MtrArray $Targets)) {
        if (-not $t) { continue }
        if ($t.deviceAndAppManagementAssignmentFilterId -and $t.deviceAndAppManagementAssignmentFilterType -notin $null, 'none') { $filter = $true }
        switch -Regex ([string]$t.'@odata.type') {
            'exclusionGroupAssignmentTarget' { if ($t.groupId -in $DeviceGroupIds -or $t.groupId -in $UserGroupIds) { $excluded = $true }; break }
            'allDevicesAssignmentTarget' { $device = 'All devices'; break }
            'allLicensedUsersAssignmentTarget' { $user = 'All users'; break }
            'groupAssignmentTarget' {
                if ($t.groupId -in $DeviceGroupIds) { $device = "device group $($t.groupId)" }
                elseif ($t.groupId -in $UserGroupIds) { $user = "user group $($t.groupId)" }
                break
            }
        }
    }
    [pscustomobject]@{ Device = $device; User = $user; Excluded = $excluded; HasFilter = $filter }
}

function Get-MtrDeviceAccountGroup {
    param([Parameter(Mandatory)]$Model)
    $map = @{}
    foreach ($a in (Get-MtrArray $Model.Accounts)) { foreach ($d in (Get-MtrArray $a.Devices)) { $map[$d.Id] = @($map[$d.Id]) + @($a.GroupIds) } }
    $map
}

function Test-MtrIntune {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $intune = $Context.Intune
    if (-not $intune) { return }
    $now = $Settings.Now
    $devices = Get-MtrArray $Model.Devices
    $android = @($devices | Where-Object Platform -eq 'Android')
    $windows = @($devices | Where-Object Platform -eq 'Windows')
    $accountGroups = Get-MtrDeviceAccountGroup -Model $Model
    $profilesCollected = @($Context.Coverage | Where-Object { $_.Item -eq 'Android (AOSP) enrollment profiles' -and $_.Status -eq 'OK' }).Count -gt 0
    $complianceCollected = @($Context.Coverage | Where-Object { $_.Item -eq 'Compliance policies' -and $_.Status -eq 'OK' }).Count -gt 0

    # ---------- Android ----------
    $androidRooms = @($Model.MtrAccounts | Where-Object { 'Android' -in $_.Platforms })
    if (($android.Count -or $androidRooms.Count) -and $profilesCollected) {
        $teamsProfiles = @($intune.EnrollmentProfiles | Where-Object { $_.isTeamsDeviceProfile })
        if (-not $teamsProfiles.Count) {
            New-MtrFinding -CheckId 'AND-01' -Severity High -Category 'Intune Android' -Title 'No AOSP enrollment profile for Teams devices' `
                -Detail 'No Android (AOSP) corporate-owned, user-associated profile has "For Microsoft Teams devices" enabled.' `
                -Impact 'Device Administrator is deprecated for Teams Android devices; devices on current firmware enroll through this profile and cannot enroll (or sign in, if compliance is required) without it.' `
                -Recommendation 'Create one AOSP profile with "For Microsoft Teams devices" = Enabled and a 65-year token.' -FixLocation 'Intune' -Reference $links.AospEnrollment
        }
        foreach ($p in $teamsProfiles) {
            $expires = ConvertTo-MtrDateTime $p.tokenExpirationDateTime
            if (-not $expires) { continue }
            $days = [math]::Floor(($expires - $now).TotalDays)
            if ($days -lt 0) {
                New-MtrFinding -CheckId 'AND-02' -Severity Critical -Category 'Intune Android' -Title "Teams AOSP enrollment token for '$($p.displayName)' expired $(-$days) days ago" `
                    -Impact 'An expired token stops devices completing sign-in and blocks new devices from enrolling.' `
                    -Recommendation 'Renew the token on the profile (Devices > Enrollment > Android > AOSP).' -FixLocation 'Intune' -Reference $links.AospEnrollment
            }
            elseif ($days -le $Baseline.Thresholds.AospTokenWarningDays) {
                New-MtrFinding -CheckId 'AND-02' -Severity High -Category 'Intune Android' -Title "Teams AOSP enrollment token for '$($p.displayName)' expires in $days days" `
                    -Impact 'When it expires, Teams Android devices cannot complete sign-in or enroll.' -Recommendation 'Renew the token now (up to 65 years).' -FixLocation 'Intune' -Reference $links.AospEnrollment
            }
        }
    }
    $da = @($android | Where-Object IsDeviceAdmin)
    if ($da.Count) {
        New-MtrFinding -CheckId 'AND-03' -Severity High -Category 'Intune Android' -Title "$($da.Count) Teams Android device(s) still enrolled with Device Administrator" `
            -AffectedObjects @($da | ForEach-Object { '{0} ({1} {2}, enrollment {3})' -f $_.Name, $_.Manufacturer, $_.Model, $_.EnrollmentType }) `
            -Impact 'Device Administrator is deprecated for Teams Android devices.' `
            -Recommendation 'Update firmware (Logitech Sync / Teams Admin Center), make sure the Teams AOSP profile and AOSP compliance policy exist, then let devices migrate to AOSP.' `
            -FixLocation 'Intune' -Reference $links.AospEnrollment
    }

    $aospPolicies = @($intune.CompliancePolicies | Where-Object { $_.'@odata.type' -match 'aosp' })
    $aospDevices = @($android | Where-Object IsAosp)
    $appliedAosp = @{}
    foreach ($policy in $aospPolicies) {
        $hit = @($aospDevices | Where-Object {
                $e = Get-MtrAssignmentEffect -Targets @($policy.assignments | ForEach-Object target) -DeviceGroupIds $_.GroupIds -UserGroupIds @($accountGroups[$_.Id])
                ($e.Device -or $e.User) -and -not $e.Excluded
            })
        if (-not $hit.Count) { continue }
        foreach ($d in $hit) { $appliedAosp[$d.Id] = $true }
        if ($policy.passwordRequired) {
            New-MtrFinding -CheckId 'AND-04' -Severity High -Category 'Intune Android' -Title "AOSP compliance policy '$($policy.displayName)' requires a device password" `
                -Target "$($hit.Count) devices" -AffectedObjects @($hit | ForEach-Object Name) `
                -Impact 'Teams devices do not support a password unlock, so they will be non-compliant.' -Recommendation 'Remove password requirements from policies assigned to Teams devices.' -FixLocation 'Intune' -Reference $links.SupportedCA
        }
        $minOs = ConvertTo-MtrVersion $policy.osMinimumVersion
        if ($minOs) {
            $below = @($hit | Where-Object { $v = ConvertTo-MtrVersion $_.OsVersion; $v -and $v -lt $minOs })
            if ($below.Count) {
                New-MtrFinding -CheckId 'AND-05' -Severity High -Category 'Intune Android' -Title "'$($policy.displayName)' requires Android $($policy.osMinimumVersion); $($below.Count) Teams device(s) run older" `
                    -AffectedObjects @($below | ForEach-Object { '{0} ({1}, Android {2})' -f $_.Name, $_.Model, $_.OsVersion }) `
                    -Impact 'These rooms are (or will become) non-compliant and blocked by compliance-based Conditional Access.' `
                    -Recommendation 'Set the minimum OS to match the Logitech fleet (check supported versions per model), or update device firmware first.' -FixLocation 'Intune' -Reference $links.AospEnrollment
            }
        }
        if ($policy.minAndroidSecurityPatchLevel) {
            $required = ConvertTo-MtrDateTime $policy.minAndroidSecurityPatchLevel
            $behind = @($hit | Where-Object { $lvl = ConvertTo-MtrDateTime $_.SecurityPatchLevel; $required -and $lvl -and $lvl -lt $required })
            if ($behind.Count) {
                New-MtrFinding -CheckId 'AND-05' -Severity High -Category 'Intune Android' -Title "'$($policy.displayName)' requires security patch $($policy.minAndroidSecurityPatchLevel); $($behind.Count) Teams device(s) are older" `
                    -AffectedObjects @($behind | ForEach-Object { '{0} (patch {1})' -f $_.Name, $_.SecurityPatchLevel }) `
                    -Impact 'OEM firmware for room devices lags phone patch levels; these rooms fail compliance.' -Recommendation 'Align the patch requirement with the OEM firmware cadence.' -FixLocation 'Intune'
            }
        }
    }
    $noPolicy = @($aospDevices | Where-Object { -not $appliedAosp[$_.Id] })
    if ($noPolicy.Count -and $complianceCollected) {
        New-MtrFinding -CheckId 'AND-06' -Severity Medium -Category 'Intune Android' -Title "$($noPolicy.Count) AOSP Teams device(s) have no AOSP compliance policy" `
            -AffectedObjects @($noPolicy | ForEach-Object Name) `
            -Impact 'If Conditional Access requires a compliant device, Microsoft notes rooms sign out after moving to AOSP when no AOSP compliance policy is assigned.' `
            -Recommendation 'Create an AOSP compliance policy (block rooted, require encryption, realistic OS minimum) and assign it to the Teams devices or room accounts.' -FixLocation 'Intune' -Reference $links.AospEnrollment
    }

    # ---------- Windows ----------
    $hybrid = @($windows | Where-Object { $_.JoinType -eq 'hybridAzureADJoined' -or $_.TrustType -eq 'ServerAd' })
    if ($hybrid.Count) {
        New-MtrFinding -CheckId 'WIN-01' -Severity High -Category 'Intune Windows' -Title "$($hybrid.Count) Windows Teams Room(s) are hybrid joined" `
            -AffectedObjects @($hybrid | ForEach-Object { '{0} ({1} {2})' -f $_.Name, $_.Manufacturer, $_.Model }) `
            -Impact 'Password-less resource accounts need Entra-joined devices (hybrid join is not supported); Autopilot self-deploying does not support hybrid join; domain Group Policy can break the Teams Rooms app.' `
            -Recommendation 'Plan to re-provision as Entra joined (Autopilot + Autologin). Until then keep the computer objects in a dedicated OU with GPO inheritance blocked.' `
            -FixLocation 'Intune' -Reference $links.EntraJoin
    }
    $prefix = $Baseline.Devices.AutopilotMtrGroupTagPrefix
    $badTag = @($windows | Where-Object { $_.IsAutopilot -and $_.AutopilotGroupTag -and -not ([string]$_.AutopilotGroupTag).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) })
    $noAutopilot = @($windows | Where-Object { -not $_.IsAutopilot })
    if ($badTag.Count) {
        New-MtrFinding -CheckId 'WIN-02' -Severity Medium -Category 'Intune Windows' -Title "Autopilot group tag does not start with '$prefix'" `
            -AffectedObjects @($badTag | ForEach-Object { '{0} (tag {1})' -f $_.Name, $_.AutopilotGroupTag }) `
            -Impact 'The Pro Management Portal only picks up Autopilot devices whose group tag starts with MTR-, and MTR device groups rely on it.' `
            -Recommendation "Change the group tag to $prefix<something>." -FixLocation 'Intune' -Reference $links.AutopilotAutologin
    }
    if ($noAutopilot.Count) {
        New-MtrFinding -CheckId 'WIN-02' -Severity Low -Category 'Intune Windows' -Title "$($noAutopilot.Count) Windows Teams Room(s) are not registered in Autopilot" `
            -AffectedObjects @($noAutopilot | ForEach-Object Name) -Recommendation 'Register the hardware hash with an MTR- group tag so rebuilds can use Autopilot + Autologin.' -FixLocation 'Intune' -Reference $links.AutopilotAutologin
    }

    $winPolicies = @($intune.CompliancePolicies | Where-Object { $_.'@odata.type' -match 'windows10CompliancePolicy' })
    foreach ($policy in $winPolicies) {
        $hit = @($windows | Where-Object {
                $e = Get-MtrAssignmentEffect -Targets @($policy.assignments | ForEach-Object target) -DeviceGroupIds $_.GroupIds -UserGroupIds @($accountGroups[$_.Id])
                ($e.Device -or $e.User) -and -not $e.Excluded
            })
        if (-not $hit.Count) { continue }
        $bad = [System.Collections.Generic.List[string]]::new()
        if ($policy.passwordRequired) { $bad.Add('Require a password (password policies can stop the local Skype account signing in)') }
        if ($policy.osMinimumVersion -or $policy.osMaximumVersion) { $bad.Add("OS version min/max ($($policy.osMinimumVersion) / $($policy.osMaximumVersion)) - Teams Rooms updates Windows itself") }
        if ($policy.mobileOsMinimumVersion -or $policy.mobileOsMaximumVersion) { $bad.Add('Mobile OS version min/max') }
        if ((Get-MtrCount $policy.validOperatingSystemBuildRanges)) { $bad.Add('Valid operating system builds') }
        if ($policy.defenderVersion) { $bad.Add("Defender anti-malware minimum version ($($policy.defenderVersion))") }
        if ($bad.Count) {
            New-MtrFinding -CheckId 'WIN-03' -Severity High -Category 'Intune Windows' -Title "Windows compliance policy '$($policy.displayName)' uses settings not supported on Teams Rooms" `
                -Target "$($hit.Count) Windows rooms" -AffectedObjects @($hit | ForEach-Object Name) -Detail ('Unsupported: ' + ($bad -join '; ')) `
                -Impact 'Rooms become non-compliant (and blocked if Conditional Access requires compliance), or fail to sign in after Windows updates.' `
                -Recommendation 'Exclude the Windows Teams Rooms device group and give rooms their own compliance policy (firewall, Defender, Secure Boot, TPM, code integrity).' `
                -FixLocation 'Intune' -Reference $links.SupportedCA
        }
    }

    if ($windows.Count) {
        $broad = [System.Collections.Generic.List[string]]::new()
        $featureUpdates = [System.Collections.Generic.List[string]]::new()
        $userTargeted = [System.Collections.Generic.List[string]]::new()
        $inventory = [System.Collections.Generic.List[string]]::new()
        $lapsHit = $false
        foreach ($p in (Get-MtrArray $intune.ConfigurationProfiles)) {
            $targetsWindows = ([string]$p.Type -match '(?i)windows') -or ([string]$p.Platforms -match '(?i)windows') -or $p.Kind -in 'Feature update profile', 'Platform script', 'Remediation script', 'Administrative template'
            if (-not $targetsWindows) { continue }
            $deviceHits = 0; $allDeviceHits = 0; $userHits = 0
            foreach ($d in $windows) {
                $e = Get-MtrAssignmentEffect -Targets $p.Assignments -DeviceGroupIds $d.GroupIds -UserGroupIds @($accountGroups[$d.Id])
                if ($e.Excluded) { continue }
                if ($e.Device) { $deviceHits++; if ($e.Device -eq 'All devices') { $allDeviceHits++ } }
                elseif ($e.User) { $userHits++ }
            }
            $label = '{0}: {1}' -f $p.Kind, $p.Name
            if ($deviceHits) {
                $inventory.Add("$label ($deviceHits rooms)")
                if ($allDeviceHits) { $broad.Add("$label (All devices, $allDeviceHits rooms)") }
                if ($p.Kind -eq 'Feature update profile') { $featureUpdates.Add("$label ($(if ($p.FeatureUpdateVersion) { $p.FeatureUpdateVersion } else { 'version n/a' }))") }
                if ($p.Template -match $Baseline.Devices.LapsTemplatePattern -or $p.Name -match $Baseline.Devices.LapsTemplatePattern) { $lapsHit = $true }
            }
            if ($userHits) { $userTargeted.Add("$label ($userHits rooms)") }
        }
        if ($broad.Count) {
            New-MtrFinding -CheckId 'WIN-04' -Severity Medium -Category 'Intune Windows' -Title "$($broad.Count) 'All devices' Intune policies land on Windows Teams Rooms" -AffectedObjects $broad.ToArray() `
                -Impact 'General-purpose desktop settings (security baselines, restart rules, Edge/OneDrive, ASR, BitLocker PIN, etc.) can break the Teams Rooms app or reboot rooms during meetings.' `
                -Recommendation 'Add the Windows Teams Rooms device group as an exclusion on general policies and keep a small, deliberate set of MTR-specific policies.' -FixLocation 'Intune' -Reference $links.AutopilotAutologin
        }
        if ($featureUpdates.Count) {
            New-MtrFinding -CheckId 'WIN-05' -Severity Medium -Category 'Intune Windows' -Title 'Windows feature update profiles target Teams Rooms' -AffectedObjects $featureUpdates.ToArray() `
                -Impact 'Teams Rooms only take feature updates Microsoft has validated; pinning a version can hold rooms below the build needed for password-less accounts.' `
                -Recommendation 'Exclude Teams Rooms from feature update profiles unless you deliberately manage their version.' -FixLocation 'Intune' -Reference $links.WindowsUpdates
        }
        if ($inventory.Count) {
            New-MtrFinding -CheckId 'WIN-06' -Severity Info -Category 'Intune Windows' -Title 'Intune policies currently applied to Windows Teams Rooms' -AffectedObjects $inventory.ToArray()
        }
        if ($userTargeted.Count) {
            New-MtrFinding -CheckId 'WIN-07' -Severity Low -Category 'Intune Windows' -Title 'User-targeted policies will reach Windows rooms after password-less migration' -AffectedObjects $userTargeted.ToArray() `
                -Detail 'Today Windows rooms sign in to Windows with the local Skype account. After password-less migration the resource account signs in to Windows, so these user-targeted policies start applying.' `
                -Recommendation 'Exclude the Teams Rooms user group from these policies before migrating.' -FixLocation 'Intune' -Reference $links.Passwordless
        }
        if (-not $lapsHit) {
            New-MtrFinding -CheckId 'WIN-08' -Severity Low -Category 'Intune Windows' -Title 'No Windows LAPS policy found for Teams Rooms' `
                -Impact 'The local Admin account on each room may still use the default or a shared password.' -Recommendation 'Assign a Windows LAPS policy to the Teams Rooms device group.' -FixLocation 'Intune' -Reference $links.Laps
        }
        $win10 = @($windows | Where-Object { $v = ConvertTo-MtrVersion $_.OsVersion; $v -and $v.Build -lt 22000 })
        if ($win10.Count) {
            New-MtrFinding -CheckId 'WIN-09' -Severity High -Category 'Intune Windows' -Title "$($win10.Count) Windows Teams Room(s) still on Windows 10" `
                -AffectedObjects @($win10 | ForEach-Object { '{0} ({1})' -f $_.Name, $_.OsVersion }) -Impact 'Teams Rooms requires Windows 11.' `
                -Recommendation 'Upgrade to Windows 11 (check OEM support for the compute model).' -FixLocation 'Device' -Reference $links.RoomsPrep
        }
    }

    # ---------- Compliance and staleness (both platforms) ----------
    $nonCompliant = @($devices | Where-Object { $_.ComplianceState -and $_.ComplianceState -notin 'compliant', 'unknown', 'inGracePeriod' })
    if ($nonCompliant.Count) {
        New-MtrFinding -CheckId 'DEV-01' -Severity High -Category 'Intune Devices' -Title "$($nonCompliant.Count) Teams Rooms device(s) are not compliant" `
            -AffectedObjects @($nonCompliant | ForEach-Object {
                    $states = @(Get-MtrPropertyValue $intune.CompliancePolicyStates $_.Id | Where-Object { $_.State -notin 'compliant', 'notApplicable' } | ForEach-Object { '{0}: {1}' -f $_.PolicyName, ((@($_.FailedSettings) | Select-Object -First 4) -join ', ') })
                    '{0} [{1}] {2}' -f $_.Name, $_.ComplianceState, ($states -join ' | ')
                }) `
            -Impact 'With compliance-based Conditional Access the room is blocked from signing in.' -Recommendation 'Fix the failing settings or remove unsupported settings from the policy.' -FixLocation 'Intune' -Reference $links.SupportedCA
    }
    $stale = @($devices | Where-Object { $_.LastSync -and ($now - $_.LastSync).TotalDays -gt $Baseline.Thresholds.DeviceStaleDays })
    if ($stale.Count) {
        New-MtrFinding -CheckId 'DEV-02' -Severity Medium -Category 'Intune Devices' -Title "$($stale.Count) Teams Rooms device(s) have not checked in with Intune for over $($Baseline.Thresholds.DeviceStaleDays) days" `
            -AffectedObjects @($stale | ForEach-Object { '{0} (last sync {1:yyyy-MM-dd})' -f $_.Name, $_.LastSync }) `
            -Impact 'Offline, powered off, or stuck; compliance goes stale and eventually non-compliant.' -Recommendation 'Check the device in TAC/PMP.' -FixLocation 'Teams Admin Center'
    }
    if ($devices.Count) {
        $summary = @($devices | Group-Object { '{0} {1} ({2})' -f $_.Manufacturer, $_.Model, $_.Platform } | Sort-Object Count -Descending | ForEach-Object {
                $os = @($_.Group | ForEach-Object OsVersion | Where-Object { $_ } | Sort-Object -Unique)
                $apps = @($_.Group | ForEach-Object TeamsAppVersion | Where-Object { $_ } | Sort-Object -Unique)
                '{0} x{1}; OS {2}; Teams app {3}' -f $_.Name, $_.Count, (Format-MtrList -Items $os -Max 3), $(if ($apps.Count) { Format-MtrList -Items $apps -Max 3 } else { 'not reported' })
            })
        New-MtrFinding -CheckId 'DEV-03' -Severity Info -Category 'Intune Devices' -Title 'Teams Rooms device models and versions' -AffectedObjects $summary
    }

    # ---------- Teams devices API (best-effort) ----------
    $tw = @($intune.TeamworkDevices | Where-Object { $_ })
    if ($tw.Count) {
        $unhealthy = @($tw | Where-Object { $_.healthStatus -in 'offline', 'critical' })
        if ($unhealthy.Count) {
            New-MtrFinding -CheckId 'TDEV-01' -Severity Medium -Category 'Intune Devices' -Title "$($unhealthy.Count) Teams device(s) report offline or critical health" `
                -AffectedObjects @($unhealthy | ForEach-Object { '{0} {1} ({2}, {3})' -f $_.manufacturer, $_.model, $_.currentUserName, $_.healthStatus }) `
                -Recommendation 'Review in Teams Admin Center / Pro Management Portal.' -FixLocation 'Teams Admin Center'
        }
    }
}
