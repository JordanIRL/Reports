# Builds a synthetic collected context that resembles a real, imperfect tenant:
# mixed room naming by building, AD-synced accounts, Logitech Android and Windows rooms, a broad MFA policy,
# a human in the rooms group, a Basic-licensed room under a compliance policy, and so on.
# Used by the Pester tests and for offline smoke runs (-FromSnapshot).

function New-MtrSampleContext {
    $now = [datetime]::new(2026, 9, 28, 10, 0, 0, [DateTimeKind]::Utc)
    $iso = { param([datetime]$d) $d.ToString('yyyy-MM-ddTHH:mm:ssZ') }

    $skuPro = '4cde982a-ede4-4409-9ae6-b003453c8ea6'
    $skuBasic = '6af4b3d6-14bb-4a2a-960c-6c902aad34f3'
    $skuE3 = '05e9a617-0261-4cee-bb44-138d3ef5d965'
    $skuShared = '295a8eb0-f78d-45c7-8b5b-1eed5ed02dff'
    $plan = { param($id, $name) [pscustomobject]@{ servicePlanId = $id; servicePlanName = $name; appliesTo = 'User' } }
    $proPlans = @(
        (& $plan 'ecc74eae-eeb7-4ad5-9c88-e8b2bfca75b8' 'MTRProManagement'), (& $plan 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5' 'INTUNE_A'),
        (& $plan '41781fb2-bc02-4b7c-bd55-b576c07bb09d' 'AAD_PREMIUM'), (& $plan '57ff2da0-773e-42df-b2af-ffb7a2317929' 'TEAMS1')
    )
    $basicPlans = @((& $plan 'c8529366-cffd-4415-ab8f-be0144a33ab1' 'Teams_Rooms_Basic'), (& $plan '57ff2da0-773e-42df-b2af-ffb7a2317929' 'TEAMS1'))
    $e3Plans = @((& $plan '57ff2da0-773e-42df-b2af-ffb7a2317929' 'TEAMS1'), (& $plan 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5' 'INTUNE_A'), (& $plan '41781fb2-bc02-4b7c-bd55-b576c07bb09d' 'AAD_PREMIUM'))
    $sku = { param($id, $part, $enabled, $consumed, $plans, $isRooms, $isBasic, $isPro, $isShared, $isSuite)
        [pscustomobject]@{ SkuId = $id; SkuPartNumber = $part; CapabilityStatus = 'Enabled'; AppliesTo = 'User'; Enabled = $enabled; Warning = 0; Suspended = 0; Consumed = $consumed
            ServicePlans = @($plans); IsTeamsRooms = $isRooms; IsBasic = $isBasic; IsPro = $isPro; IsSharedDevice = $isShared; IsUserSuite = $isSuite }
    }
    $licensing = [pscustomobject]@{ Skus = @(
            (& $sku $skuPro 'Microsoft_Teams_Rooms_Pro' 10 5 $proPlans $true $false $true $false $false)
            (& $sku $skuBasic 'Microsoft_Teams_Rooms_Basic' 25 1 $basicPlans $true $true $false $false $false)
            (& $sku $skuE3 'SPE_E3' 500 480 $e3Plans $false $false $false $false $true)
            (& $sku $skuShared 'MCOCAP' 5 0 @() $false $false $false $true $false)
        )
    }

    $groupRooms = [pscustomobject]@{ id = 'g-rooms'; displayName = 'Teams Rooms'; groupTypes = @('DynamicMembership'); membershipRule = '(user.userPrincipalName -startsWith "lon-") -or (user.department -eq "Facilities")'; membershipRuleProcessingState = 'On'; onPremisesSyncEnabled = $null; securityEnabled = $true; mailEnabled = $false }
    $groupStaff = [pscustomobject]@{ id = 'g-staff'; displayName = 'All Staff'; groupTypes = @(); membershipRule = $null; membershipRuleProcessingState = $null; onPremisesSyncEnabled = $true; securityEnabled = $true; mailEnabled = $true }
    $licDetail = { param($skuId, $part, $plans, [string[]]$disabled = @()) [pscustomobject]@{ skuId = $skuId; skuPartNumber = $part; servicePlans = @($plans | ForEach-Object { [pscustomobject]@{ servicePlanId = $_.servicePlanId; servicePlanName = $_.servicePlanName; provisioningStatus = $(if ($_.servicePlanName -in $disabled) { 'Disabled' } else { 'Success' }) } }) } }
    $user = { param($id, $upn, $mail, $sam, [bool]$synced, [string[]]$skuIds, [datetime]$lastSignIn, [datetime]$pwdChanged, $ext10)
        [pscustomobject]@{
            id = $id; displayName = $upn.Split('@')[0]; userPrincipalName = $upn; mail = $mail; accountEnabled = $true; userType = 'Member'
            onPremisesSyncEnabled = $synced; onPremisesSamAccountName = $sam; onPremisesProvisioningErrors = @(); passwordPolicies = $null
            lastPasswordChangeDateTime = (& $iso $pwdChanged)
            onPremisesExtensionAttributes = [pscustomobject]@{ extensionAttribute10 = $ext10 }
            assignedLicenses = @($skuIds | ForEach-Object { [pscustomobject]@{ skuId = $_; disabledPlans = @() } })
            licenseAssignmentStates = @($skuIds | ForEach-Object { [pscustomobject]@{ skuId = $_; assignedByGroup = $null; state = 'Active'; error = 'None' } })
            signInActivity = [pscustomobject]@{ lastSignInDateTime = (& $iso $lastSignIn); lastNonInteractiveSignInDateTime = (& $iso $lastSignIn); lastSuccessfulSignInDateTime = (& $iso $lastSignIn) }
        }
    }
    $detail = { param($u, $licenses, $groups) [pscustomobject]@{ Id = $u.id; User = $u; LicenseDetails = @($licenses); Groups = @($groups); DirectoryRoles = @(); MemberOfError = $null } }

    $u1 = & $user 'u-lon101' 'lon-rm101@contoso.com' 'lon-rm101@contoso.com' 'lon-rm101' $true @($skuPro) $now.AddHours(-1) $now.AddDays(-40) 'TeamsRoom'
    $u2 = & $user 'u-lon102' 'lon-rm102@contoso.com' 'lon-rm102@contoso.com' 'lon-rm102' $true @($skuPro) $now.AddHours(-2) $now.AddDays(-400) 'TeamsRoom'
    $u3 = & $user 'u-lon103' 'lon-rm103@contoso.com' 'lon-rm103@contoso.com' 'lon-rm103' $true @($skuPro) $now.AddDays(-45) $now.AddDays(-10) 'TeamsRoom'
    $u4 = & $user 'u-nyc4a' 'nyc.conf.4a@contoso.com' 'nyc.conf.4a@corp.contoso.com' 'nycconf4a' $true @($skuPro) $now.AddHours(-3) $now.AddDays(-80) 'TeamsRoom'
    $u5 = & $user 'u-board' 'boardroom@contoso.com' 'boardroom@contoso.com' 'boardroom' $true @($skuBasic) $now.AddHours(-5) $now.AddDays(-5) $null
    $u6 = & $user 'u-mr7' 'meetingroom7@contoso.com' 'meetingroom7@contoso.com' 'meetingroom7' $false @($skuE3) $now.AddHours(-6) $now.AddDays(-100) $null
    $u6.passwordPolicies = $null
    $u7 = & $user 'u-old' 'oldroom@contoso.com' 'oldroom@contoso.com' 'oldroom' $true @() $now.AddDays(-300) $now.AddDays(-700) $null

    $users = @(
        (& $detail $u1 @((& $licDetail $skuPro 'Microsoft_Teams_Rooms_Pro' $proPlans)) @($groupRooms, $groupStaff))
        (& $detail $u2 @((& $licDetail $skuPro 'Microsoft_Teams_Rooms_Pro' $proPlans)) @($groupRooms, $groupStaff))
        (& $detail $u3 @((& $licDetail $skuPro 'Microsoft_Teams_Rooms_Pro' $proPlans 'INTUNE_A')) @($groupRooms, $groupStaff))
        (& $detail $u4 @((& $licDetail $skuPro 'Microsoft_Teams_Rooms_Pro' $proPlans)) @($groupStaff))
        (& $detail $u5 @((& $licDetail $skuBasic 'Microsoft_Teams_Rooms_Basic' $basicPlans)) @($groupRooms, $groupStaff))
        (& $detail $u6 @((& $licDetail $skuE3 'SPE_E3' $e3Plans)) @($groupStaff))
        (& $detail $u7 @() @($groupStaff))
    )
    $candidates = @(
        [pscustomobject]@{ Id = 'u-lon101'; Sources = @('License', 'RoomMailboxEnabledAccount') }
        [pscustomobject]@{ Id = 'u-lon102'; Sources = @('License', 'RoomMailboxEnabledAccount') }
        [pscustomobject]@{ Id = 'u-lon103'; Sources = @('License', 'RoomMailboxEnabledAccount') }
        [pscustomobject]@{ Id = 'u-nyc4a'; Sources = @('License', 'RoomMailboxEnabledAccount') }
        [pscustomobject]@{ Id = 'u-board'; Sources = @('License', 'RoomMailboxEnabledAccount') }
        [pscustomobject]@{ Id = 'u-mr7'; Sources = @('IntuneDevice') }
        [pscustomobject]@{ Id = 'u-old'; Sources = @('RoomMailboxEnabledAccount') }
    )

    $signIn = { param([datetime]$when, $code, $reason, $device, $os, $methods, $failed, $deviceId = $null) [pscustomobject]@{ CreatedDateTime = (& $iso $when); AppDisplayName = 'Microsoft Teams'; ResourceDisplayName = 'Microsoft Teams Services'; ClientAppUsed = 'Mobile Apps and Desktop clients'; ErrorCode = $code; FailureReason = $reason; ConditionalAccessStatus = $(if ($failed) { 'failure' } else { 'success' }); EventTypes = @('interactiveUser'); DeviceDisplayName = $device; DeviceId = $deviceId; DeviceOs = $os; DeviceTrustType = $null; DeviceIsCompliant = $false; DeviceIsManaged = $true; IpAddress = '203.0.113.10'; AuthMethods = @($methods); FailedCaPolicies = @($failed) } }
    $mfaFail = [pscustomobject]@{ Id = 'ca-mfa'; DisplayName = 'Require MFA for all users'; Grant = @('Mfa') }
    $extra = [pscustomobject]@{
        AuthMethods       = @{
            'u-lon101' = @([pscustomobject]@{ Type = '#microsoft.graph.passwordAuthenticationMethod'; Id = 'p1'; DisplayName = $null })
            'u-nyc4a'  = @([pscustomobject]@{ Type = '#microsoft.graph.passwordAuthenticationMethod'; Id = 'p2'; DisplayName = $null }, [pscustomobject]@{ Type = '#microsoft.graph.phoneAuthenticationMethod'; Id = 'ph'; DisplayName = '+1 555 0100' })
        }
        RoleAssignments   = @{}
        RegisteredDevices = @{ 'u-lon101' = 3; 'u-lon102' = 1; 'u-nyc4a' = 18 }
        SignIns           = @{
            'u-lon101' = @((& $signIn $now.AddHours(-1) '0' $null 'Logitech Rally Bar' 'Android' @('Password') $null))
            'u-lon102' = @((& $signIn $now.AddHours(-2) '0' $null 'LON-MTR-102' 'Windows' @('Password') $null 'aad-win102'))
            'u-nyc4a'  = @((& $signIn $now.AddHours(-3) '50076' 'MFA required' 'Logitech RoomMate' 'Android' @() $mfaFail), (& $signIn $now.AddHours(-4) '50076' 'MFA required' 'Logitech RoomMate' 'Android' @() $mfaFail))
        }
        SecurityDefaults  = [pscustomobject]@{ isEnabled = $false }
        AuthMethodsPolicy = [pscustomobject]@{ RegistrationEnforcement = [pscustomobject]@{ authenticationMethodsRegistrationCampaign = [pscustomobject]@{ state = 'enabled'; includeTargets = @([pscustomobject]@{ id = 'all_users'; targetType = 'group' }); excludeTargets = @() } } }
        DeviceRegistrationPolicy = [pscustomobject]@{ multiFactorAuthConfiguration = 'notRequired'; userDeviceQuota = 20 }
    }

    $allUsers = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }
    $policies = @(
        [pscustomobject]@{ id = 'ca-mfa'; displayName = 'Require MFA for all users'; state = 'enabled'
            conditions = [pscustomobject]@{ users = $allUsers; applications = [pscustomobject]@{ includeApplications = @('All'); excludeApplications = @() }; clientAppTypes = @('all'); platforms = $null; locations = $null }
            grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('mfa') }; sessionControls = $null }
        [pscustomobject]@{ id = 'ca-mtr'; displayName = 'Teams Rooms - compliant device'; state = 'enabled'
            conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @(); excludeUsers = @(); includeGroups = @('g-rooms'); excludeGroups = @(); includeRoles = @(); excludeRoles = @() }; applications = [pscustomobject]@{ includeApplications = @('Office365') }; clientAppTypes = @('all'); platforms = [pscustomobject]@{ includePlatforms = @('windows', 'android') } }
            grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('compliantDevice') }; sessionControls = $null }
        [pscustomobject]@{ id = 'ca-dcf'; displayName = 'Block device code flow'; state = 'enabled'
            conditions = [pscustomobject]@{ users = $allUsers; applications = [pscustomobject]@{ includeApplications = @('All') }; clientAppTypes = @('all'); authenticationFlows = [pscustomobject]@{ transferMethods = 'deviceCodeFlow' } }
            grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('block') }; sessionControls = $null }
        [pscustomobject]@{ id = 'ca-sif'; displayName = 'Sign-in frequency 12h'; state = 'enabledForReportingButNotEnforced'
            conditions = [pscustomobject]@{ users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @(); includeGroups = @(); excludeGroups = @('g-rooms'); includeRoles = @(); excludeRoles = @() }; applications = [pscustomobject]@{ includeApplications = @('Office365') }; clientAppTypes = @('all') }
            grantControls = $null; sessionControls = [pscustomobject]@{ signInFrequency = [pscustomobject]@{ isEnabled = $true; value = 12; type = 'hours' } } }
        [pscustomobject]@{ id = 'ca-legacy'; displayName = 'Block legacy auth'; state = 'enabled'
            conditions = [pscustomobject]@{ users = $allUsers; applications = [pscustomobject]@{ includeApplications = @('All') }; clientAppTypes = @('exchangeActiveSync', 'other') }
            grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('block') }; sessionControls = $null }
    )

    $mailbox = { param($upn, $smtp, $oid, [bool]$hidden = $false) [pscustomobject]@{ Identity = $upn; DisplayName = $upn.Split('@')[0]; Alias = $upn.Split('@')[0]; UserPrincipalName = $upn; PrimarySmtpAddress = $smtp; ExternalDirectoryObjectId = $oid; RecipientTypeDetails = 'RoomMailbox'; HiddenFromAddressListsEnabled = $hidden; IsDirSynced = $true; ResourceCapacity = 8; RoomMailboxAccountEnabled = $true; AccountDisabled = $false; Office = $null } }
    $roomMailboxes = @(
        (& $mailbox 'lon-rm101@contoso.com' 'lon-rm101@contoso.com' 'u-lon101')
        (& $mailbox 'lon-rm102@contoso.com' 'lon-rm102@contoso.com' 'u-lon102')
        (& $mailbox 'lon-rm103@contoso.com' 'lon-rm103@contoso.com' 'u-lon103')
        (& $mailbox 'nyc.conf.4a@contoso.com' 'nyc.conf.4a@corp.contoso.com' 'u-nyc4a' $true)
        (& $mailbox 'boardroom@contoso.com' 'boardroom@contoso.com' 'u-board')
        (& $mailbox 'oldroom@contoso.com' 'oldroom@contoso.com' 'u-old')
        (& $mailbox 'bookable-1@contoso.com' 'bookable-1@contoso.com' 'u-book1')
    )
    $member = { param($smtp, $oid) [pscustomobject]@{ DisplayName = $smtp; PrimarySmtpAddress = $smtp; ExternalDirectoryObjectId = $oid; RecipientTypeDetails = 'RoomMailbox' } }
    $roomLists = @(
        [pscustomobject]@{ DisplayName = 'London HQ'; Name = 'London HQ'; PrimarySmtpAddress = 'londonhq@contoso.com'; ExternalDirectoryObjectId = 'rl-lon'; IsDirSynced = $true; MemberError = $null
            Members = @((& $member 'lon-rm101@contoso.com' 'u-lon101'), (& $member 'lon-rm102@contoso.com' 'u-lon102'), (& $member 'lon-rm103@contoso.com' 'u-lon103'), (& $member 'nyc.conf.4a@corp.contoso.com' 'u-nyc4a'), (& $member 'boardroom@contoso.com' 'u-board')) }
        [pscustomobject]@{ DisplayName = 'NYC Tower'; Name = 'NYC Tower'; PrimarySmtpAddress = 'nyctower@contoso.com'; ExternalDirectoryObjectId = 'rl-nyc'; IsDirSynced = $true; MemberError = $null
            Members = @((& $member 'nyc.conf.4a@corp.contoso.com' 'u-nyc4a')) }
        [pscustomobject]@{ DisplayName = 'Old Annex'; Name = 'Old Annex'; PrimarySmtpAddress = 'oldannex@contoso.com'; ExternalDirectoryObjectId = 'rl-old'; IsDirSynced = $true; MemberError = $null; Members = @() }
    )
    $cp = { param([bool]$deleteComments = $false, [bool]$external = $true) [pscustomobject]@{ AutomateProcessing = 'AutoAccept'; AddOrganizerToSubject = $false; AllowRecurringMeetings = $true; DeleteAttachments = $true; DeleteComments = $deleteComments; DeleteSubject = $false; ProcessExternalMeetingMessages = $external; RemovePrivateProperty = $false; AddAdditionalResponse = $true; AllBookInPolicy = $true; AllRequestInPolicy = $false; BookInPolicy = @(); ResourceDelegates = @(); BookingWindowInDays = 180; MaximumDurationInMinutes = 1440; ScheduleOnlyDuringWorkHours = $false; AllowConflicts = $false; EnforceCapacity = $false } }
    $place = { param($city, $mtr, $floor = 1) [pscustomobject]@{ City = $city; State = $null; CountryOrRegion = 'GB'; Street = $null; PostalCode = $null; Building = $null; Floor = $floor; FloorLabel = $null; Capacity = 8; MTREnabled = $mtr; AudioDeviceName = $null; VideoDeviceName = $null; DisplayDeviceName = $null; IsWheelChairAccessible = $false; Tags = @(); Localities = @() } }
    $exoCandidate = { param($upn, $mbx, $cpv, $tz, $pl) [pscustomobject]@{ Identity = $upn; Recipient = $null; Mailbox = $mbx; CalendarProcessing = $cpv; Regional = [pscustomobject]@{ TimeZone = $tz; Language = 'en-GB' }; CalendarConfig = [pscustomobject]@{ WorkingHoursTimeZone = $tz }; Cas = [pscustomobject]@{ EwsEnabled = $true; EwsApplicationAccessPolicy = $null }; Place = $pl; Errors = @() } }
    $exoCandidates = @(
        (& $exoCandidate 'lon-rm101@contoso.com' $roomMailboxes[0] (& $cp $true) 'GMT Standard Time' (& $place 'London' $true))
        (& $exoCandidate 'lon-rm102@contoso.com' $roomMailboxes[1] (& $cp) 'Pacific Standard Time' (& $place 'London' $true))
        (& $exoCandidate 'lon-rm103@contoso.com' $roomMailboxes[2] (& $cp) 'GMT Standard Time' (& $place 'London' $true))
        (& $exoCandidate 'nyc.conf.4a@contoso.com' $roomMailboxes[3] (& $cp $false $false) 'GMT Standard Time' (& $place 'New York' $false))
        (& $exoCandidate 'boardroom@contoso.com' $roomMailboxes[4] (& $cp) 'GMT Standard Time' (& $place 'London' $true))
        [pscustomobject]@{ Identity = 'meetingroom7@contoso.com'; Recipient = [pscustomobject]@{ RecipientTypeDetails = 'UserMailbox'; PrimarySmtpAddress = 'meetingroom7@contoso.com'; IsDirSynced = $false }
            Mailbox = [pscustomobject]@{ Identity = 'meetingroom7'; PrimarySmtpAddress = 'meetingroom7@contoso.com'; ExternalDirectoryObjectId = 'u-mr7'; RecipientTypeDetails = 'UserMailbox'; HiddenFromAddressListsEnabled = $false; IsDirSynced = $false }
            CalendarProcessing = (& $cp); Regional = [pscustomobject]@{ TimeZone = $null; Language = $null }; CalendarConfig = $null; Cas = $null; Place = $null; Errors = @() }
        (& $exoCandidate 'oldroom@contoso.com' $roomMailboxes[5] (& $cp) 'GMT Standard Time' (& $place 'London' $false))
    )
    $graphRoom = { param($email, $city, $floor, $cap, $building, $teams) [pscustomobject]@{ id = "p-$email"; emailAddress = $email; displayName = $email; address = [pscustomobject]@{ city = $city }; floorNumber = $floor; floorLabel = $null; capacity = $cap; building = $building; teamsEnabledState = $teams; parentId = $null } }
    $graphRooms = @(
        (& $graphRoom 'lon-rm101@contoso.com' 'London' 1 8 'London HQ' 'enabled')
        (& $graphRoom 'lon-rm102@contoso.com' 'London' 1 8 'London HQ' 'enabled')
        (& $graphRoom 'lon-rm103@contoso.com' 'London' $null 8 $null 'enabled')
        (& $graphRoom 'nyc.conf.4a@corp.contoso.com' 'New York' 4 12 'NYC Tower' 'disabled')
        (& $graphRoom 'boardroom@contoso.com' 'London' 2 20 'London HQ' 'enabled')
        (& $graphRoom 'oldroom@contoso.com' $null $null 0 $null 'disabled')
        (& $graphRoom 'bookable-1@contoso.com' 'London' 3 4 'London HQ' 'disabled')
    )

    $device = { param($id, $name, $os, $osVer, $mfr, $model, $compliance, [datetime]$lastSync, $enrollType, $join, $aad, $upn, $userId, $patch = $null, $enrollProfile = $null)
        [pscustomobject]@{ id = $id; deviceName = $name; operatingSystem = $os; osVersion = $osVer; manufacturer = $mfr; model = $model; serialNumber = "SN-$id"; complianceState = $compliance
            lastSyncDateTime = (& $iso $lastSync); enrolledDateTime = (& $iso $lastSync.AddDays(-200)); managementAgent = 'mdm'; deviceEnrollmentType = $enrollType; joinType = $join; azureADDeviceId = $aad
            userPrincipalName = $upn; userId = $userId; enrollmentProfileName = $enrollProfile; managedDeviceOwnerType = 'company'; androidSecurityPatchLevel = $patch; deviceType = $null; autopilotEnrolled = ($os -eq 'Windows') }
    }
    $devices = @(
        (& $device 'd-rally101' 'LON-RM101-RALLY' 'Android' '10' 'Logitech' 'Rally Bar' 'compliant' $now.AddHours(-2) 'androidAOSPUserOwnedDeviceEnrollment' 'azureADRegistered' 'aad-rally101' 'lon-rm101@contoso.com' 'u-lon101' '2025-06-01' 'AOSP - Teams Devices')
        (& $device 'd-tap101' 'LON-RM101-TAPSCHED' 'Android' '10' 'Logitech' 'Tap Scheduler' 'compliant' $now.AddHours(-2) 'androidAOSPUserOwnedDeviceEnrollment' 'azureADRegistered' 'aad-tap101' 'lon-rm101@contoso.com' 'u-lon101' '2025-06-01' 'AOSP - Teams Devices')
        (& $device 'd-win102' 'LON-MTR-102' 'Windows' '10.0.26100.4652' 'Lenovo' 'ThinkSmart Core' 'noncompliant' $now.AddDays(-12) 'windowsAzureADJoin' 'hybridAzureADJoined' 'aad-win102' $null $null)
        (& $device 'd-roommate4a' 'NYC-4A' 'Android' '12' 'Logitech' 'RoomMate' 'compliant' $now.AddHours(-3) 'userEnrollment' 'azureADRegistered' 'aad-rm4a' 'nyc.conf.4a@contoso.com' 'u-nyc4a' '2026-01-01')
        (& $device 'd-winboard' 'BOARD-MTR' 'Windows' '10.0.26100.8700' 'HP' 'Elite Mini' 'compliant' $now.AddHours(-5) 'windowsAzureADJoin' 'azureADJoined' 'aad-board' $null $null)
        (& $device 'd-mr7' 'MR7-RALLYMINI' 'Android' '12' 'Logitech' 'Rally Bar Mini' 'compliant' $now.AddHours(-6) 'androidAOSPUserOwnedDeviceEnrollment' 'azureADRegistered' 'aad-mr7' 'meetingroom7@contoso.com' 'u-mr7' '2026-01-01' 'AOSP - Teams Devices')
    )
    $entra = { param($aad, $oid, $trust) [pscustomobject]@{ id = $oid; deviceId = $aad; displayName = $aad; trustType = $trust; physicalIds = @(); enrollmentProfileName = $null; isCompliant = $true; isManaged = $true; accountEnabled = $true } }
    $intune = [pscustomobject]@{
        Devices = $devices
        DeviceSources = @{ 'd-rally101' = @('Signed in with a room account', 'Logitech device'); 'd-tap101' = @('Logitech device'); 'd-win102' = @('Autopilot group tag MTR-LON'); 'd-roommate4a' = @('Logitech device'); 'd-winboard' = @('Autopilot group tag Rooms-Board'); 'd-mr7' = @('Logitech device') }
        EntraDevices = @{ 'aad-rally101' = (& $entra 'aad-rally101' 'e-rally101' 'Workplace'); 'aad-win102' = (& $entra 'aad-win102' 'e-win102' 'ServerAd'); 'aad-board' = (& $entra 'aad-board' 'e-board' 'AzureAd'); 'aad-rm4a' = (& $entra 'aad-rm4a' 'e-rm4a' 'Workplace') }
        DeviceGroups = @{ 'e-rally101' = @(); 'e-win102' = @('g-alldevices'); 'e-board' = @(); 'e-rm4a' = @() }
        AutopilotDevices = @(
            [pscustomobject]@{ id = 'ap1'; groupTag = 'MTR-LON'; serialNumber = 'SN-d-win102'; model = 'ThinkSmart Core'; manufacturer = 'Lenovo'; azureActiveDirectoryDeviceId = 'aad-win102'; managedDeviceId = 'd-win102'; enrollmentState = 'enrolled' }
            [pscustomobject]@{ id = 'ap2'; groupTag = 'Rooms-Board'; serialNumber = 'SN-d-winboard'; model = 'Elite Mini'; manufacturer = 'HP'; azureActiveDirectoryDeviceId = 'aad-board'; managedDeviceId = 'd-winboard'; enrollmentState = 'enrolled' }
        )
        EnrollmentProfiles = @([pscustomobject]@{ id = 'ep1'; displayName = 'AOSP - Teams Devices'; enrollmentMode = 'corporateOwnedAOSPUserAssociatedDevice'; isTeamsDeviceProfile = $true; tokenExpirationDateTime = (& $iso $now.AddDays(30)); tokenCreationDateTime = (& $iso $now.AddDays(-335)); enrolledDeviceCount = 3 })
        CompliancePolicies = @(
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'cp-win'; displayName = 'Windows - corporate baseline'; passwordRequired = $true; osMinimumVersion = '10.0.22631'; osMaximumVersion = $null; validOperatingSystemBuildRanges = @(); defenderVersion = $null
                assignments = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) }
            [pscustomobject]@{ '@odata.type' = '#microsoft.graph.aospDeviceOwnerCompliancePolicy'; id = 'cp-aosp'; displayName = 'Teams Android'; passwordRequired = $false; osMinimumVersion = '12'; minAndroidSecurityPatchLevel = $null
                assignments = @([pscustomobject]@{ target = [pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-rooms' } }) }
        )
        ConfigurationProfiles = @(
            [pscustomobject]@{ Kind = 'Configuration profile'; Id = 'cfg-edge'; Name = 'Windows - Edge and OneDrive'; Type = '#microsoft.graph.windows10CustomConfiguration'; Platforms = $null; Template = $null; TemplateFamily = $null; FeatureUpdateVersion = $null; Assignments = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }) }
            [pscustomobject]@{ Kind = 'Feature update profile'; Id = 'fu-23h2'; Name = 'Pin Windows 11 23H2'; Type = '#microsoft.graph.windowsFeatureUpdateProfile'; Platforms = $null; Template = $null; TemplateFamily = $null; FeatureUpdateVersion = 'Windows 11, version 23H2'; Assignments = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = 'g-alldevices' }) }
            [pscustomobject]@{ Kind = 'Settings catalog / endpoint security'; Id = 'cfg-ios'; Name = 'iOS restrictions'; Type = $null; Platforms = 'iOS'; Template = $null; TemplateFamily = $null; FeatureUpdateVersion = $null; Assignments = @([pscustomobject]@{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' }) }
        )
        CompliancePolicyStates = @{ 'd-win102' = @([pscustomobject]@{ PolicyName = 'Windows - corporate baseline'; State = 'nonCompliant'; FailedSettings = @('PasswordRequired (nonCompliant)', 'OsMinimumVersion (nonCompliant)') }) }
        DetectedApps = @{ 'd-rally101' = @([pscustomobject]@{ displayName = 'Microsoft Teams Rooms'; version = '1449/1.0.96.2026129709' }); 'd-winboard' = @([pscustomobject]@{ displayName = 'Microsoft Teams Rooms'; version = '5.6.135.0' }) }
        TeamworkDevices = $null
        UserDevices = @{ 'u-lon101' = @('d-rally101', 'd-tap101'); 'u-nyc4a' = @('d-roommate4a'); 'u-mr7' = @('d-mr7'); 'u-board' = @('d-winboard') }
    }

    $ctx = [pscustomobject]@{
        Meta = [pscustomobject]@{ SchemaVersion = 1; ToolVersion = 'test'; CollectedAt = $now; TenantId = '11111111-2222-3333-4444-555555555555'; TenantName = 'Contoso (sample)'; RunBy = 'auditor@contoso.com'
            Sections = @('Identity', 'Licensing', 'ConditionalAccess', 'Groups', 'Exchange', 'Places', 'Teams', 'Intune'); Parameters = @{} }
        Coverage = [System.Collections.Generic.List[object]]::new()
        Tenant = [pscustomobject]@{ Id = '11111111-2222-3333-4444-555555555555'; DisplayName = 'Contoso (sample)'; DefaultDomain = 'contoso.com'; OnPremisesSyncEnabled = $true; OnPremisesLastSyncDateTime = (& $iso $now.AddMinutes(-40))
            Domains = @([pscustomobject]@{ id = 'contoso.com'; authenticationType = 'Managed'; isVerified = $true; isDefault = $true; passwordValidityPeriodInDays = 90 }, [pscustomobject]@{ id = 'corp.contoso.com'; authenticationType = 'Federated'; isVerified = $true; isDefault = $false; passwordValidityPeriodInDays = 2147483647 })
            SyncFeatures = [pscustomobject]@{ cloudPasswordPolicyForPasswordSyncedUsersEnabled = $false; userForcePasswordChangeOnLogonEnabled = $true; passwordSyncEnabled = $true } }
        Licensing = $licensing
        Identity = [pscustomobject]@{ Candidates = $candidates; Users = $users; Extra = $extra; RoomAccountStatus = @{} }
        ConditionalAccess = [pscustomobject]@{ Policies = $policies; NamedLocations = @([pscustomobject]@{ Id = 'nl-hq'; DisplayName = 'Office egress'; Type = '#microsoft.graph.ipNamedLocation'; IsTrusted = $true; IpRanges = @('203.0.113.0/24'); Countries = @() }) }
        Groups = [pscustomobject]@{
            MemberCounts = @{ 'g-rooms' = 5; 'g-staff' = 900 }
            Members = @{ 'g-rooms' = @(
                    [pscustomobject]@{ Id = 'u-lon101'; Type = '#microsoft.graph.user'; DisplayName = 'lon-rm101'; UserPrincipalName = 'lon-rm101@contoso.com' }
                    [pscustomobject]@{ Id = 'u-lon102'; Type = '#microsoft.graph.user'; DisplayName = 'lon-rm102'; UserPrincipalName = 'lon-rm102@contoso.com' }
                    [pscustomobject]@{ Id = 'u-lon103'; Type = '#microsoft.graph.user'; DisplayName = 'lon-rm103'; UserPrincipalName = 'lon-rm103@contoso.com' }
                    [pscustomobject]@{ Id = 'u-board'; Type = '#microsoft.graph.user'; DisplayName = 'boardroom'; UserPrincipalName = 'boardroom@contoso.com' }
                    [pscustomobject]@{ Id = 'u-jane'; Type = '#microsoft.graph.user'; DisplayName = 'Jane Doe'; UserPrincipalName = 'jane.doe@contoso.com' }
                ) }
            DynamicGroups = @($groupRooms)
        }
        Exchange = [pscustomobject]@{ RoomMailboxes = $roomMailboxes; RoomLists = $roomLists; OrganizationConfig = [pscustomobject]@{ EwsEnabled = $true; EwsApplicationAccessPolicy = $null; EwsAllowList = @(); EwsBlockList = @() }; Candidates = $exoCandidates }
        Places = [pscustomobject]@{ Rooms = $graphRooms; RoomLists = @(); Buildings = @(); Floors = @(); Sections = @(); HierarchyAvailable = $true }
        Teams = [pscustomobject]@{
            Users = @(
                [pscustomobject]@{ UserPrincipalName = 'lon-rm101@contoso.com'; Found = $true; AccountType = 'User'; TeamsUpgradeEffectiveMode = 'TeamsOnly'; FeatureTypes = @('Teams', 'AudioConferencing'); TeamsIPPhonePolicy = $null; TeamsMeetingPolicy = $null; EnterpriseVoiceEnabled = $false }
                [pscustomobject]@{ UserPrincipalName = 'lon-rm102@contoso.com'; Found = $true; AccountType = 'User'; TeamsUpgradeEffectiveMode = 'TeamsOnly'; FeatureTypes = @('Teams'); TeamsIPPhonePolicy = $null; TeamsMeetingPolicy = $null; EnterpriseVoiceEnabled = $false }
                [pscustomobject]@{ UserPrincipalName = 'lon-rm103@contoso.com'; Found = $true; AccountType = 'User'; TeamsUpgradeEffectiveMode = 'Islands'; FeatureTypes = @('Teams'); TeamsIPPhonePolicy = $null; TeamsMeetingPolicy = $null; EnterpriseVoiceEnabled = $false }
                [pscustomobject]@{ UserPrincipalName = 'nyc.conf.4a@contoso.com'; Found = $true; AccountType = 'User'; TeamsUpgradeEffectiveMode = 'TeamsOnly'; FeatureTypes = @('Teams'); TeamsIPPhonePolicy = $null; TeamsMeetingPolicy = $null; EnterpriseVoiceEnabled = $false }
                [pscustomobject]@{ UserPrincipalName = 'boardroom@contoso.com'; Found = $true; AccountType = 'User'; TeamsUpgradeEffectiveMode = 'TeamsOnly'; FeatureTypes = @('Teams'); TeamsIPPhonePolicy = $null; TeamsMeetingPolicy = $null; EnterpriseVoiceEnabled = $false }
                [pscustomobject]@{ UserPrincipalName = 'meetingroom7@contoso.com'; Found = $true; AccountType = 'User'; TeamsUpgradeEffectiveMode = 'TeamsOnly'; FeatureTypes = @('Teams'); TeamsIPPhonePolicy = $null; TeamsMeetingPolicy = $null; EnterpriseVoiceEnabled = $false }
                [pscustomobject]@{ UserPrincipalName = 'oldroom@contoso.com'; Found = $false; Error = 'Management object not found' }
            )
            IpPhonePolicies = @([pscustomobject]@{ Identity = 'Global'; SignInMode = 'UserSignIn' })
        }
        Intune = $intune
        Seeds = @()
    }
    foreach ($item in 'Android (AOSP) enrollment profiles', 'Compliance policies') {
        $ctx.Coverage.Add([pscustomobject]@{ Section = 'Intune'; Item = $item; Status = 'OK'; Detail = $null })
    }
    $ctx
}
