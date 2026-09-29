# Works out which accounts are Teams Rooms accounts without relying on naming conventions,
# and assembles one record per account (plus one per device) for the checks to use.

function Get-MtrDeviceRecord {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline)
    $intune = $Context.Intune
    if (-not $intune) { return , [object[]]@() }

    $teamsProfileNames = @($intune.EnrollmentProfiles | Where-Object { $_.isTeamsDeviceProfile } | ForEach-Object displayName)
    $autopilotByDevice = @{}
    foreach ($ap in (Get-MtrArray $intune.AutopilotDevices)) { if ($ap.managedDeviceId) { $autopilotByDevice[$ap.managedDeviceId] = $ap } }

    $records = foreach ($d in (Get-MtrArray $intune.Devices)) {
        if (-not $d) { continue }
        $platform = switch -Regex ([string]$d.operatingSystem) { 'Windows' { 'Windows'; break } 'Android' { 'Android'; break } default { 'Other' } }
        $isAosp = ($d.deviceEnrollmentType -in $Baseline.Devices.AospEnrollmentTypes) -or
            ($d.enrollmentProfileName -and $d.enrollmentProfileName -in $teamsProfileNames) -or ([string]$d.operatingSystem -match 'AOSP')
        $isDeviceAdmin = $platform -eq 'Android' -and -not $isAosp -and ([string]$d.deviceEnrollmentType -notmatch '^androidEnterprise')
        $entra = $null
        if ($d.azureADDeviceId -and (Get-MtrPropertyValue $intune.EntraDevices $d.azureADDeviceId)) { $entra = Get-MtrPropertyValue $intune.EntraDevices $d.azureADDeviceId }
        $groupIds = if ($entra) { Get-MtrArray (Get-MtrPropertyValue $intune.DeviceGroups $entra.id) } else { , [object[]]@() }
        $apps = Get-MtrArray (Get-MtrPropertyValue $intune.DetectedApps $d.id)
        $teamsApp = $apps | Where-Object { $_.displayName -match $Baseline.Devices.TeamsRoomsAppNamePattern } | Sort-Object { ConvertTo-MtrVersion $_.version } -Descending | Select-Object -First 1
        $authApp = $apps | Where-Object { $_.displayName -match $Baseline.Devices.AuthenticatorAppNamePattern } | Select-Object -First 1
        $ap = $autopilotByDevice[$d.id]
        [pscustomobject]@{
            Id                  = $d.id
            Name                = $d.deviceName
            Platform            = $platform
            Manufacturer        = $d.manufacturer
            Model               = $d.model
            SerialNumber        = $d.serialNumber
            OsVersion           = $d.osVersion
            SecurityPatchLevel  = $d.androidSecurityPatchLevel
            ComplianceState     = $d.complianceState
            LastSync            = ConvertTo-MtrDateTime $d.lastSyncDateTime
            EnrollmentType      = $d.deviceEnrollmentType
            EnrollmentProfileName = $d.enrollmentProfileName
            JoinType            = $d.joinType
            TrustType           = if ($entra) { $entra.trustType } else { $null }
            IsAosp              = [bool]$isAosp
            IsDeviceAdmin       = [bool]$isDeviceAdmin
            IsPanel             = [bool]($d.model -match $Baseline.Devices.AndroidPanelModelPattern)
            IsLogitech          = [bool]($d.manufacturer -match $Baseline.Devices.LogitechManufacturerPattern)
            UserId              = $d.userId
            UserPrincipalName   = $d.userPrincipalName
            AzureAdDeviceId     = $d.azureADDeviceId
            EntraObjectId       = if ($entra) { $entra.id } else { $null }
            PhysicalIds         = if ($entra) { @($entra.physicalIds) } else { @() }
            GroupIds            = $groupIds
            AutopilotGroupTag   = if ($ap) { $ap.groupTag } else { $null }
            IsAutopilot         = [bool]($ap -or $d.autopilotEnrolled)
            TeamsAppVersion     = if ($teamsApp) { $teamsApp.version } else { $null }
            AuthenticatorVersion = if ($authApp) { $authApp.version } else { $null }
            Sources             = Get-MtrArray (Get-MtrPropertyValue $intune.DeviceSources $d.id)
        }
    }
    Get-MtrArray $records
}

function Get-MtrNamePrefix {
    param([string]$UserPrincipalName)
    if (-not $UserPrincipalName) { return $null }
    $local = $UserPrincipalName.Split('@')[0]
    $m = [regex]::Match($local, '^[A-Za-z]+')
    if ($m.Success) { return $m.Value.ToUpperInvariant() }
    return '(numeric)'
}

function Resolve-MtrAccount {
    <#
    .SYNOPSIS
        Classifies each candidate account and returns the discovery model used by all checks.
    .OUTPUTS
        [pscustomobject] with Accounts, MtrAccounts, Devices, Groups (analysis), SkuById
    #>
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline)

    $lic = $Baseline.Licensing
    $skuById = @{}
    foreach ($s in (Get-MtrArray $Context.Licensing.Skus)) { if ($s) { $skuById[[string]$s.SkuId] = $s } }

    $exo = $Context.Exchange
    $roomByOid = @{}
    foreach ($r in (Get-MtrArray $exo.RoomMailboxes)) { if ($r.ExternalDirectoryObjectId) { $roomByOid[$r.ExternalDirectoryObjectId] = $r } }
    # Graph Places rooms stand in for room mailboxes when Exchange Online could not be read.
    foreach ($entry in @(Get-MtrMapEntry -Map $Context.Places.RoomAccounts)) {
        $account = $entry.Value
        if ($account -and $account.id -and -not $roomByOid[$account.id]) {
            $roomByOid[$account.id] = [pscustomobject]@{
                PrimarySmtpAddress = $entry.Key; UserPrincipalName = $account.userPrincipalName; ExternalDirectoryObjectId = $account.id
                RecipientTypeDetails = 'RoomMailbox'; IsDirSynced = [bool]$account.onPremisesSyncEnabled; HiddenFromAddressListsEnabled = $null; Source = 'Graph Places'
            }
        }
    }
    $exoByIdentity = @{}
    foreach ($c in (Get-MtrArray $exo.Candidates)) { if ($c.Identity) { $exoByIdentity[$c.Identity.ToLowerInvariant()] = $c } }
    $roomListsByOid = @{}
    $roomListsBySmtp = @{}
    foreach ($rl in (Get-MtrArray $exo.RoomLists)) {
        foreach ($m in (Get-MtrArray $rl.Members)) {
            if ($m.ExternalDirectoryObjectId) {
                if (-not $roomListsByOid[$m.ExternalDirectoryObjectId]) { $roomListsByOid[$m.ExternalDirectoryObjectId] = [System.Collections.Generic.List[string]]::new() }
                $roomListsByOid[$m.ExternalDirectoryObjectId].Add($rl.DisplayName)
            }
            if ($m.PrimarySmtpAddress) {
                $key = $m.PrimarySmtpAddress.ToLowerInvariant()
                if (-not $roomListsBySmtp[$key]) { $roomListsBySmtp[$key] = [System.Collections.Generic.List[string]]::new() }
                $roomListsBySmtp[$key].Add($rl.DisplayName)
            }
        }
    }
    $placeByEmail = @{}
    foreach ($p in (Get-MtrArray $Context.Places.Rooms)) { if ($p.emailAddress) { $placeByEmail[$p.emailAddress.ToLowerInvariant()] = $p } }
    $teamsByUpn = @{}
    foreach ($t in (Get-MtrArray $Context.Teams.Users)) { if ($t.UserPrincipalName) { $teamsByUpn[$t.UserPrincipalName.ToLowerInvariant()] = $t } }
    $sourcesById = @{}
    foreach ($c in (Get-MtrArray $Context.Identity.Candidates)) { if ($c) { $sourcesById[$c.Id] = Get-MtrArray $c.Sources } }

    $devices = Get-MtrArray (Get-MtrDeviceRecord -Context $Context -Baseline $Baseline)
    $ownersByDevice = @{}
    foreach ($entry in @(Get-MtrMapEntry -Map $Context.Intune.UserDevices)) {
        foreach ($deviceId in (Get-MtrArray $entry.Value)) {
            if (-not $deviceId) { continue }
            if (-not $ownersByDevice[$deviceId]) { $ownersByDevice[$deviceId] = [System.Collections.Generic.HashSet[string]]::new() }
            $null = $ownersByDevice[$deviceId].Add($entry.Key)
        }
    }
    $devicesByUserId = @{}
    foreach ($dev in $devices) {
        $owners = [System.Collections.Generic.HashSet[string]]::new()
        if ($dev.UserId) { $null = $owners.Add($dev.UserId) }
        if ($ownersByDevice[$dev.Id]) { foreach ($o in $ownersByDevice[$dev.Id]) { $null = $owners.Add($o) } }
        foreach ($o in $owners) {
            if (-not $devicesByUserId[$o]) { $devicesByUserId[$o] = [System.Collections.Generic.List[object]]::new() }
            $devicesByUserId[$o].Add($dev)
        }
    }
    $deviceByAadId = @{}
    foreach ($dev in $devices) { if ($dev.AzureAdDeviceId) { $deviceByAadId[$dev.AzureAdDeviceId] = $dev } }
    $teamworkByUserId = @{}
    foreach ($tw in (Get-MtrArray $Context.Intune.TeamworkDevices)) { if ($tw -and $tw.currentUserId) { $teamworkByUserId[$tw.currentUserId] = $tw } }

    $extra = $Context.Identity.Extra
    $accounts = foreach ($detail in (Get-MtrArray $Context.Identity.Users)) {
        if (-not $detail -or -not $detail.User) { continue }
        $u = $detail.User
        $upn = [string]$u.userPrincipalName
        $evidence = [System.Collections.Generic.List[string]]::new()
        $strong = 0
        $medium = 0

        # Licensing (licenseDetails carries service plan provisioning status)
        $skuParts = Get-MtrArray ($detail.LicenseDetails | ForEach-Object { $_.skuPartNumber })
        $assignedSkus = @($detail.LicenseDetails | ForEach-Object { $skuById[[string]$_.skuId] } | Where-Object { $_ })
        $mtrSkus = @($assignedSkus | Where-Object IsTeamsRooms)
        $enabledPlans = @($detail.LicenseDetails | ForEach-Object { $_.servicePlans } | Where-Object { $_.provisioningStatus -notin @('Disabled') } | ForEach-Object servicePlanName)
        $mtrDisabledPlans = @($detail.LicenseDetails | Where-Object { $skuById[[string]$_.skuId].IsTeamsRooms } | ForEach-Object { $_.servicePlans } | Where-Object { $_.provisioningStatus -eq 'Disabled' } | ForEach-Object servicePlanName)
        $tier = if (@($mtrSkus | Where-Object IsPro).Count) { 'Pro' } elseif (@($mtrSkus | Where-Object IsBasic).Count) { 'Basic' } elseif ($mtrSkus.Count) { 'Legacy/Other' } else { 'None' }
        if ($mtrSkus.Count) { $strong++; $evidence.Add("Teams Rooms license ($((@($mtrSkus | ForEach-Object SkuPartNumber)) -join ', '))") }
        $hasShared = @($assignedSkus | Where-Object IsSharedDevice).Count -gt 0
        if ($hasShared) { $evidence.Add('Teams Shared Devices license') }

        # Devices: Intune user association, plus devices seen in this account's sign-ins (Windows rooms often have no primary user)
        $signIns = Get-MtrArray (Get-MtrPropertyValue $extra.SignIns $u.id)
        $accountDevices = Get-MtrArray $devicesByUserId[$u.id]
        foreach ($aadId in @($signIns | ForEach-Object { $_.DeviceId } | Where-Object { $_ } | Sort-Object -Unique)) {
            $seen = $deviceByAadId[$aadId]
            if ($seen -and $seen.Id -notin @($accountDevices | ForEach-Object { $_.Id })) { $accountDevices = Get-MtrArray (@($accountDevices) + @($seen)) }
        }
        $teamsDevices = @($accountDevices | Where-Object { $_.Platform -in 'Windows', 'Android' })
        if ($teamsDevices.Count) {
            $strong++
            $evidence.Add("Signed in on device(s): $(Format-MtrList -Items @($teamsDevices | ForEach-Object { '{0} {1}' -f $_.Manufacturer, $_.Model }) -Max 4)")
        }
        $tw = $teamworkByUserId[$u.id]
        if ($tw) { $strong++; $evidence.Add("Teams device ($($tw.deviceType)) signed in") }

        # Sign-in device names: Android Teams devices pass make/model as the device display name
        $signInDevices = @($signIns | Where-Object { $_.DeviceDisplayName -match $Baseline.Devices.LogitechManufacturerPattern } | ForEach-Object DeviceDisplayName | Sort-Object -Unique)
        if ($signInDevices.Count -and -not $teamsDevices.Count) { $strong++; $evidence.Add("Sign-ins from $(Format-MtrList -Items $signInDevices -Max 3)") }

        # Explicit seeds
        $sources = Get-MtrArray $sourcesById[$u.id]
        $seedSources = @($sources | Where-Object { $_ -like 'Seed:*' })
        if ($seedSources.Count) { $strong++; $evidence.Add("Admin-supplied ($((@($seedSources | ForEach-Object { $_ -replace '^Seed:', '' })) -join '; '))") }

        # Mailbox
        $room = $roomByOid[$u.id]
        $exoRecord = $exoByIdentity[$upn.ToLowerInvariant()]
        $mailboxType = if ($room) { 'RoomMailbox' }
        elseif ($exoRecord -and $exoRecord.Mailbox) { $exoRecord.Mailbox.RecipientTypeDetails }
        elseif ($exoRecord -and $exoRecord.Recipient) { $exoRecord.Recipient.RecipientTypeDetails }
        else { $null }
        $mailbox = if ($exoRecord -and $exoRecord.Mailbox) { $exoRecord.Mailbox } else { $room }
        $primarySmtp = if ($mailbox) { [string]$mailbox.PrimarySmtpAddress } else { [string]$u.mail }
        if ($room -and $u.accountEnabled) { $medium++; $evidence.Add('Room mailbox with an enabled account') }

        # Places
        $place = if ($primarySmtp) { $placeByEmail[$primarySmtp.ToLowerInvariant()] } else { $null }
        $exoPlace = if ($exoRecord) { $exoRecord.Place } else { $null }
        if (($exoPlace -and $exoPlace.MTREnabled -eq $true) -or ($place -and $place.teamsEnabledState -eq 'enabled')) { $medium++; $evidence.Add('Place marked as Teams Room (MTREnabled)') }

        $roomLists = @()
        if ($roomListsByOid[$u.id]) { $roomLists = @($roomListsByOid[$u.id]) }
        elseif ($primarySmtp -and $roomListsBySmtp[$primarySmtp.ToLowerInvariant()]) { $roomLists = @($roomListsBySmtp[$primarySmtp.ToLowerInvariant()]) }

        $platforms = @($accountDevices | ForEach-Object Platform | Where-Object { $_ -in 'Windows', 'Android' } | Sort-Object -Unique)
        if (-not $platforms.Count) {
            $platforms = @($signIns | ForEach-Object { switch -Regex ([string]$_.DeviceOs) { 'Windows' { 'Windows' } 'Android' { 'Android' } } } | Sort-Object -Unique)
        }

        $signInActivity = $u.signInActivity
        $lastSignIn = @(
            ConvertTo-MtrDateTime $signInActivity.lastSuccessfulSignInDateTime
            ConvertTo-MtrDateTime $signInActivity.lastSignInDateTime
            ConvertTo-MtrDateTime $signInActivity.lastNonInteractiveSignInDateTime
        ) | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1

        [pscustomobject]@{
            Id                   = $u.id
            UserPrincipalName    = $upn
            DisplayName          = $u.displayName
            Mail                 = $u.mail
            PrimarySmtpAddress   = $primarySmtp
            NamePrefix           = Get-MtrNamePrefix -UserPrincipalName $upn
            Classification       = $null
            StrongSignals        = $strong
            MediumSignals        = $medium
            Evidence             = $evidence
            Sources              = $sources
            User                 = $u
            AccountEnabled       = [bool]$u.accountEnabled
            IsSynced             = [bool]$u.onPremisesSyncEnabled
            UpnDomain            = ($upn -split '@')[-1]
            SkuPartNumbers       = $skuParts
            LicenseTier          = $tier
            HasMtrLicense        = $mtrSkus.Count -gt 0
            HasSharedDeviceLicense = $hasShared
            HasUserSuiteLicense  = @($assignedSkus | Where-Object IsUserSuite).Count -gt 0
            HasIntunePlan        = @($enabledPlans | Where-Object { $_ -match $lic.IntunePlanPattern }).Count -gt 0
            HasEntraP1Plan       = @($enabledPlans | Where-Object { $_ -match $lic.EntraP1PlanPattern }).Count -gt 0
            HasTeamsPlan         = @($enabledPlans | Where-Object { $_ -match $lic.TeamsPlanPattern }).Count -gt 0
            DisabledMtrPlans     = $mtrDisabledPlans
            LicenseAssignmentStates = Get-MtrArray $u.licenseAssignmentStates
            GroupIds             = Get-MtrArray ($detail.Groups | ForEach-Object { $_.id })
            Groups               = Get-MtrArray $detail.Groups
            RoleTemplateIds      = Get-MtrArray ($detail.DirectoryRoles | ForEach-Object { $_.roleTemplateId })
            DirectoryRoles       = Get-MtrArray ($detail.DirectoryRoles | ForEach-Object { $_.displayName })
            RoleAssignments      = Get-MtrArray (Get-MtrPropertyValue $extra.RoleAssignments $u.id)
            AuthMethods          = Get-MtrArray (Get-MtrPropertyValue $extra.AuthMethods $u.id)
            RegisteredDeviceCount = Get-MtrPropertyValue $extra.RegisteredDevices $u.id
            SignIns              = $signIns
            LastSignIn           = $lastSignIn
            Devices              = $accountDevices
            Platforms            = $platforms
            IsPanelOnly          = ($accountDevices.Count -gt 0 -and @($accountDevices | Where-Object { -not $_.IsPanel }).Count -eq 0)
            MailboxType          = $mailboxType
            IsRoomMailbox        = $mailboxType -eq 'RoomMailbox'
            Mailbox              = $mailbox
            Exchange             = $exoRecord
            RoomLists            = $roomLists
            Place                = $place
            ExoPlace             = $exoPlace
            Teams                = $teamsByUpn[$upn.ToLowerInvariant()]
        }
    }
    $accounts = Get-MtrArray $accounts

    # First pass classification
    foreach ($a in $accounts) { Set-MtrAccountClassification -Account $a }

    # Group analysis: groups where most members are Teams Rooms accounts
    $groupAnalysis = Get-MtrGroupAnalysis -Context $Context -Accounts $accounts -Baseline $Baseline
    $mtrLikeIds = @($groupAnalysis | Where-Object IsMtrLike | ForEach-Object Id)
    foreach ($a in $accounts) {
        $inGroups = @($a.GroupIds | Where-Object { $_ -in $mtrLikeIds })
        if ($inGroups.Count) {
            $a.MediumSignals++
            $names = @($groupAnalysis | Where-Object { $_.Id -in $inGroups } | ForEach-Object DisplayName)
            $a.Evidence.Add("Member of Teams Rooms group(s): $(Format-MtrList -Items $names -Max 3)")
            Set-MtrAccountClassification -Account $a
        }
    }
    foreach ($a in $accounts) { $a.Evidence = Get-MtrArray $a.Evidence }

    $mtr = @($accounts | Where-Object { $_.Classification -in 'Confirmed', 'Probable' })
    [pscustomobject]@{
        Accounts    = $accounts
        MtrAccounts = $mtr
        Devices     = $devices
        Groups      = Get-MtrArray $groupAnalysis
        SkuById     = $skuById
    }
}

function Set-MtrAccountClassification {
    param([Parameter(Mandatory)]$Account)
    $Account.Classification = if ($Account.StrongSignals -ge 1) { 'Confirmed' }
    elseif ($Account.MediumSignals -ge 2) { 'Probable' }
    elseif ($Account.MediumSignals -eq 1) { 'Inconsistent' }
    else { 'BookableRoom' }
}

function Get-MtrGroupAnalysis {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Accounts, [Parameter(Mandatory)]$Baseline)
    $mtrIds = @($Accounts | Where-Object { $_.Classification -in 'Confirmed', 'Probable' } | ForEach-Object Id)
    $groups = @{}
    foreach ($a in $Accounts) {
        foreach ($g in (Get-MtrArray $a.Groups)) {
            if (-not $groups[$g.id]) { $groups[$g.id] = [pscustomobject]@{ Group = $g; Mtr = 0; Candidates = 0 } }
            $groups[$g.id].Candidates++
            if ($a.Id -in $mtrIds) { $groups[$g.id].Mtr++ }
        }
    }
    $counts = $Context.Groups.MemberCounts
    $minimum = [math]::Min(2, [math]::Max(1, $mtrIds.Count))
    foreach ($id in $groups.Keys) {
        $entry = $groups[$id]
        $memberCount = Get-MtrPropertyValue $counts $id
        $ratio = if ($memberCount) { [math]::Round($entry.Mtr / [double]$memberCount, 2) } else { $null }
        $g = $entry.Group
        [pscustomobject]@{
            Id              = $id
            DisplayName     = $g.displayName
            MemberCount     = $memberCount
            MtrMemberCount  = $entry.Mtr
            Ratio           = $ratio
            IsMtrLike       = ($null -ne $ratio -and $ratio -ge $Baseline.Thresholds.MtrGroupRatio -and $entry.Mtr -ge $minimum)
            IsDynamic       = @($g.groupTypes) -contains 'DynamicMembership'
            MembershipRule  = $g.membershipRule
            IsSynced        = [bool]$g.onPremisesSyncEnabled
            SecurityEnabled = [bool]$g.securityEnabled
            Members         = Get-MtrArray (Get-MtrPropertyValue $Context.Groups.Members $id)
        }
    }
}
