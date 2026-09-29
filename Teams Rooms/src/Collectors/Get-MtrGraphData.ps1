# Graph collectors: tenant, licensing, identity, Conditional Access, groups, Places.
# All functions only read. Each returns plain objects that are stored in the context/snapshot.

$script:MtrUserSelect = @(
    'id', 'displayName', 'userPrincipalName', 'mail', 'accountEnabled', 'userType', 'usageLocation',
    'onPremisesSyncEnabled', 'onPremisesLastSyncDateTime', 'onPremisesProvisioningErrors', 'onPremisesExtensionAttributes',
    'onPremisesSamAccountName', 'onPremisesDistinguishedName', 'passwordPolicies', 'lastPasswordChangeDateTime',
    'assignedLicenses', 'licenseAssignmentStates', 'createdDateTime', 'proxyAddresses'
) -join ','

function Get-MtrTenantData {
    $org = @(Invoke-MtrGraphGet -Uri 'v1.0/organization?$select=id,displayName,verifiedDomains,onPremisesSyncEnabled,onPremisesLastSyncDateTime')[0]
    $domains = Invoke-MtrGraphGet -Uri 'v1.0/domains?$select=id,authenticationType,isVerified,isDefault,passwordValidityPeriodInDays' -All
    $syncFeatures = $null
    try {
        $sync = Invoke-MtrGraphGet -Uri 'v1.0/directory/onPremisesSynchronization' -All
        $syncFeatures = @($sync)[0].features
    }
    catch { Write-Verbose "onPremisesSynchronization unavailable: $($_.Exception.Message)" }

    [pscustomobject]@{
        Id                         = $org.id
        DisplayName                = $org.displayName
        DefaultDomain              = (@($org.verifiedDomains) | Where-Object isDefault | Select-Object -First 1).name
        OnPremisesSyncEnabled      = $org.onPremisesSyncEnabled
        OnPremisesLastSyncDateTime = $org.onPremisesLastSyncDateTime
        Domains                    = Get-MtrArray $domains
        SyncFeatures               = $syncFeatures
    }
}

function Get-MtrLicensingData {
    param([Parameter(Mandatory)]$Baseline)
    $skus = @(Invoke-MtrGraphGet -Uri 'v1.0/subscribedSkus' -All)
    $lic = $Baseline.Licensing
    $classified = foreach ($sku in $skus) {
        $planNames = @($sku.servicePlans | ForEach-Object servicePlanName)
        [pscustomobject]@{
            SkuId          = $sku.skuId
            SkuPartNumber  = $sku.skuPartNumber
            CapabilityStatus = $sku.capabilityStatus
            AppliesTo      = $sku.appliesTo
            Enabled        = [int]$sku.prepaidUnits.enabled
            Warning        = [int]$sku.prepaidUnits.warning
            Suspended      = [int]$sku.prepaidUnits.suspended
            Consumed       = [int]$sku.consumedUnits
            ServicePlans   = @($sku.servicePlans | Select-Object servicePlanId, servicePlanName, appliesTo)
            IsTeamsRooms   = ($sku.skuPartNumber -match $lic.TeamsRoomsSkuPattern) -or (@($planNames | Where-Object { $_ -match $lic.MtrServicePlanPattern }).Count -gt 0)
            IsBasic        = $sku.skuPartNumber -match $lic.TeamsRoomsBasicSkuPattern
            IsPro          = $sku.skuPartNumber -match $lic.TeamsRoomsProSkuPattern
            IsSharedDevice = $sku.skuPartNumber -match $lic.SharedDeviceSkuPattern
            IsUserSuite    = $sku.skuPartNumber -match $lic.UserSuiteSkuPattern
        }
    }
    [pscustomobject]@{ Skus = Get-MtrArray $classified }
}

function Get-MtrUsersBySku {
    # Users that hold any of the given SKUs (Teams Rooms and Shared Devices).
    param([string[]]$SkuIds)
    $users = @{}
    foreach ($skuId in $SkuIds) {
        $uri = "v1.0/users?`$filter=assignedLicenses/any(x:x/skuId eq $skuId)&`$select=id,userPrincipalName&`$count=true&`$top=999"
        foreach ($u in @(Invoke-MtrGraphGet -Uri $uri -All -Eventual)) { $users[$u.id] = $u.userPrincipalName }
    }
    $users
}

function Resolve-MtrUserIdentifier {
    # Maps UPNs / object IDs / external directory IDs to user objects via batch lookups.
    param([string[]]$Identifiers)
    $map = @{}
    $ids = @($Identifiers | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $ids.Count) { return $map }
    $requests = for ($i = 0; $i -lt $ids.Count; $i++) {
        [pscustomobject]@{ Id = "$i"; Url = "/users/$([uri]::EscapeDataString($ids[$i]))?`$select=id,userPrincipalName,accountEnabled,assignedLicenses" }
    }
    $responses = Invoke-MtrGraphBatch -Requests $requests
    for ($i = 0; $i -lt $ids.Count; $i++) {
        $r = $responses["$i"]
        if ($r -and $r.Status -eq 200) { $map[$ids[$i]] = $r.Body }
    }
    $map
}

function Get-MtrSeedUsers {
    # Admin-supplied discovery seeds: UPNs, CSV, group IDs, UPN regex patterns.
    param(
        [string[]]$ResourceAccountUpn,
        [string]$ResourceAccountCsv,
        [string[]]$MtrGroupId,
        [string[]]$UpnPattern
    )
    $seeds = [System.Collections.Generic.List[object]]::new()
    $upns = [System.Collections.Generic.List[string]]::new()
    foreach ($u in (Get-MtrArray $ResourceAccountUpn)) { if ($u) { $upns.Add($u.Trim()) } }
    if ($ResourceAccountCsv) {
        $rows = Import-Csv -LiteralPath $ResourceAccountCsv
        $column = @('UserPrincipalName', 'UPN', 'Upn', 'EmailAddress', 'Mail') | Where-Object { $rows -and $rows[0].PSObject.Properties.Name -contains $_ } | Select-Object -First 1
        if (-not $column) { throw "CSV '$ResourceAccountCsv' needs a UserPrincipalName (or UPN) column." }
        foreach ($row in $rows) { if ($row.$column) { $upns.Add(([string]$row.$column).Trim()) } }
    }
    if ($upns.Count) {
        $resolved = Resolve-MtrUserIdentifier -Identifiers $upns
        foreach ($upn in $upns) {
            if ($resolved[$upn]) { $seeds.Add([pscustomobject]@{ Id = $resolved[$upn].id; UserPrincipalName = $resolved[$upn].userPrincipalName; Source = "Seed:UPN" }) }
            else { Write-Warning "Seed account '$upn' was not found in Entra ID." }
        }
    }
    foreach ($groupId in (Get-MtrArray $MtrGroupId)) {
        if (-not $groupId) { continue }
        foreach ($m in @(Invoke-MtrGraphGet -Uri "v1.0/groups/$groupId/transitiveMembers/microsoft.graph.user?`$select=id,userPrincipalName&`$top=999" -All)) {
            $seeds.Add([pscustomobject]@{ Id = $m.id; UserPrincipalName = $m.userPrincipalName; Source = "Seed:Group:$groupId" })
        }
    }
    if (@($UpnPattern | Where-Object { $_ }).Count) {
        # No server-side regex, so enumerate members once (id + UPN only).
        $all = Invoke-MtrGraphGet -Uri 'v1.0/users?$select=id,userPrincipalName&$filter=userType eq ''Member''&$count=true&$top=999' -All -Eventual
        foreach ($u in (Get-MtrArray $all)) {
            foreach ($pattern in $UpnPattern) {
                if ($u.userPrincipalName -match $pattern) { $seeds.Add([pscustomobject]@{ Id = $u.id; UserPrincipalName = $u.userPrincipalName; Source = "Seed:Pattern:$pattern" }); break }
            }
        }
    }
    $seeds.ToArray()
}

function Get-MtrUserDetail {
    <#
    .SYNOPSIS
        Full user objects, license details and group/role memberships for the candidate accounts.
        signInActivity needs AuditLog.Read.All and Entra ID P1; when unavailable the rest still loads.
    #>
    param([Parameter(Mandatory)][string[]]$UserIds, [Parameter(Mandatory)]$Context)

    $users = @{}
    $withActivity = $true
    $requests = foreach ($id in $UserIds) { [pscustomobject]@{ Id = $id; Url = "/users/$id`?`$select=$script:MtrUserSelect,signInActivity" } }
    $responses = Invoke-MtrGraphBatch -Requests $requests
    $retry = @($UserIds | Where-Object { -not $responses[$_] -or $responses[$_].Status -ne 200 })
    if ($retry.Count) {
        $withActivity = $false
        $requests = foreach ($id in $retry) { [pscustomobject]@{ Id = $id; Url = "/users/$id`?`$select=$script:MtrUserSelect" } }
        $second = Invoke-MtrGraphBatch -Requests $requests
        foreach ($id in $retry) { $responses[$id] = $second[$id] }
    }
    foreach ($id in $UserIds) {
        if ($responses[$id] -and $responses[$id].Status -eq 200) { $users[$id] = $responses[$id].Body }
    }
    if (-not $withActivity) {
        Add-MtrCoverage -Context $Context -Section 'Identity' -Item 'signInActivity' -Status Partial -Detail 'signInActivity not readable for some accounts (needs AuditLog.Read.All and Entra ID P1). Stale-account checks are limited.'
    }

    $licenseRequests = foreach ($id in $users.Keys) { [pscustomobject]@{ Id = $id; Url = "/users/$id/licenseDetails" } }
    $licenseResponses = Invoke-MtrGraphBatch -Requests @($licenseRequests) -FollowNextLink

    $memberRequests = foreach ($id in $users.Keys) {
        [pscustomobject]@{ Id = $id; Url = "/users/$id/transitiveMemberOf?`$select=id,displayName,groupTypes,membershipRule,membershipRuleProcessingState,onPremisesSyncEnabled,securityEnabled,mailEnabled,roleTemplateId&`$top=999" }
    }
    $memberResponses = Invoke-MtrGraphBatch -Requests @($memberRequests) -FollowNextLink
    Add-MtrBatchCoverage -Context $Context -Section 'Identity' -Item 'License details' -Responses $licenseResponses
    Add-MtrBatchCoverage -Context $Context -Section 'Identity' -Item 'Group and role memberships' -Responses $memberResponses

    $details = foreach ($id in $users.Keys) {
        $u = $users[$id]
        $memberOf = Get-MtrArray $memberResponses[$id].Items
        [pscustomobject]@{
            Id             = $id
            User           = $u
            LicenseDetails = @((Get-MtrArray $licenseResponses[$id].Items) | Select-Object skuId, skuPartNumber, @{ n = 'servicePlans'; e = { @($_.servicePlans | Select-Object servicePlanId, servicePlanName, provisioningStatus) } })
            Groups         = @($memberOf | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.group' } | Select-Object id, displayName, groupTypes, membershipRule, membershipRuleProcessingState, onPremisesSyncEnabled, securityEnabled, mailEnabled)
            DirectoryRoles = @($memberOf | Where-Object { $_.'@odata.type' -eq '#microsoft.graph.directoryRole' } | Select-Object id, displayName, roleTemplateId)
            MemberOfError  = $memberResponses[$id].Error
        }
    }
    Get-MtrArray $details
}

function Get-MtrIdentityExtra {
    # Authentication methods, role assignments, registered device counts and sign-ins for candidates.
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$UserIds,
        [Parameter(Mandatory)]$Context,
        [int]$SignInLookbackDays = 7,
        [switch]$SkipSignInLogs,
        [int]$SignInsPerAccount = 100
    )
    $result = [pscustomobject]@{
        AuthMethods       = @{}
        RoleAssignments   = @{}
        RegisteredDevices = @{}
        SignIns           = @{}
        SecurityDefaults  = $null
        AuthMethodsPolicy = $null
        DeviceRegistrationPolicy = $null
    }

    # Tenant-wide settings first: they matter even when no room accounts were found.
    $result.SecurityDefaults = Invoke-MtrCollectorStep -Context $Context -Section 'Identity' -Item 'Security defaults' -ScriptBlock {
        Invoke-MtrGraphGet -Uri 'v1.0/policies/identitySecurityDefaultsEnforcementPolicy'
    }
    $result.AuthMethodsPolicy = Invoke-MtrCollectorStep -Context $Context -Section 'Identity' -Item 'Authentication methods policy' -ScriptBlock {
        $p = Invoke-MtrGraphGet -Uri 'beta/policies/authenticationMethodsPolicy'
        [pscustomobject]@{ RegistrationEnforcement = $p.registrationEnforcement; ReportSuspiciousActivity = $p.reportSuspiciousActivitySettings }
    }
    $result.DeviceRegistrationPolicy = Invoke-MtrCollectorStep -Context $Context -Section 'Identity' -Item 'Device registration policy' -ScriptBlock {
        Invoke-MtrGraphGet -Uri 'beta/policies/deviceRegistrationPolicy'
    }
    if (-not $UserIds.Count) {
        Add-MtrCoverage -Context $Context -Section 'Identity' -Item 'Per-account identity data' -Status Skipped -Detail 'No candidate accounts.'
        return $result
    }

    $null = Invoke-MtrCollectorStep -Context $Context -Section 'Identity' -Item 'Authentication methods' -ScriptBlock {
        $requests = foreach ($id in $UserIds) { [pscustomobject]@{ Id = $id; Url = "/users/$id/authentication/methods" } }
        $responses = Invoke-MtrGraphBatch -Requests @($requests)
        $denied = 0
        foreach ($id in $UserIds) {
            $r = $responses[$id]
            if ($r -and $r.Status -eq 200) {
                $result.AuthMethods[$id] = @((Get-MtrArray $r.Items) | ForEach-Object { [pscustomobject]@{ Type = $_.'@odata.type'; Id = $_.id; DisplayName = $_.displayName } })
            }
            elseif ($r -and $r.Status -eq 403) { $denied++ }
        }
        if ($denied) { throw [System.UnauthorizedAccessException]::new("403 on $denied accounts (needs UserAuthenticationMethod.Read.All and a role that can read methods)") }
    }

    $null = Invoke-MtrCollectorStep -Context $Context -Section 'Identity' -Item 'Directory role assignments' -ScriptBlock {
        $requests = foreach ($id in $UserIds) { [pscustomobject]@{ Id = $id; Url = "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$id'&`$expand=roleDefinition" } }
        $responses = Invoke-MtrGraphBatch -Requests @($requests)
        Add-MtrBatchCoverage -Context $Context -Section 'Identity' -Item 'Directory role assignments (lookups)' -Responses $responses
        foreach ($id in $UserIds) {
            $items = Get-MtrArray $responses[$id].Items
            if ($items.Count) { $result.RoleAssignments[$id] = @($items | ForEach-Object { [pscustomobject]@{ Role = $_.roleDefinition.displayName; TemplateId = $_.roleDefinition.templateId; Scope = $_.directoryScopeId } }) }
        }
    }

    $null = Invoke-MtrCollectorStep -Context $Context -Section 'Identity' -Item 'Registered devices per account' -ScriptBlock {
        $requests = foreach ($id in $UserIds) { [pscustomobject]@{ Id = $id; Url = "/users/$id/registeredDevices?`$select=id,displayName,operatingSystem,trustType,approximateLastSignInDateTime&`$top=999" } }
        $responses = Invoke-MtrGraphBatch -Requests @($requests) -FollowNextLink
        Add-MtrBatchCoverage -Context $Context -Section 'Identity' -Item 'Registered devices (lookups)' -Responses $responses
        foreach ($id in $UserIds) { if ($responses[$id] -and $responses[$id].Status -eq 200) { $result.RegisteredDevices[$id] = Get-MtrCount $responses[$id].Items } }
    }


    if ($SkipSignInLogs) {
        Add-MtrCoverage -Context $Context -Section 'Identity' -Item 'Sign-in logs' -Status Skipped -Detail 'Skipped by -SkipSignInLogs.'
    }
    else {
        $null = Invoke-MtrCollectorStep -Context $Context -Section 'Identity' -Item "Sign-in logs (last $SignInLookbackDays days)" -ScriptBlock {
            $since = [datetime]::UtcNow.AddDays(-$SignInLookbackDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
            $eventFilter = "(signInEventTypes/any(t: t eq 'interactiveUser') or signInEventTypes/any(t: t eq 'nonInteractiveUser'))"
            $requests = foreach ($id in $UserIds) {
                [pscustomobject]@{ Id = $id; Url = "/auditLogs/signIns?`$filter=userId eq '$id' and createdDateTime ge $since and $eventFilter&`$top=$SignInsPerAccount" }
            }
            $responses = Invoke-MtrGraphBatch -Requests @($requests) -Version beta
            $failedIds = @($UserIds | Where-Object { $responses[$_] -and $responses[$_].Status -eq 400 })
            if ($failedIds.Count) {
                # Event-type filter not accepted: fall back to interactive-only sign-ins.
                $requests = foreach ($id in $failedIds) { [pscustomobject]@{ Id = $id; Url = "/auditLogs/signIns?`$filter=userId eq '$id' and createdDateTime ge $since&`$top=$SignInsPerAccount" } }
                $fallback = Invoke-MtrGraphBatch -Requests @($requests) -Version beta
                foreach ($id in $failedIds) { $responses[$id] = $fallback[$id] }
            }
            $denied = 0
            foreach ($id in $UserIds) {
                $r = $responses[$id]
                if ($r -and $r.Status -eq 403) { $denied++; continue }
                $result.SignIns[$id] = @((Get-MtrArray $r.Items) | ForEach-Object {
                        [pscustomobject]@{
                            CreatedDateTime = $_.createdDateTime
                            AppDisplayName  = $_.appDisplayName
                            ResourceDisplayName = $_.resourceDisplayName
                            ClientAppUsed   = $_.clientAppUsed
                            ErrorCode       = [string]$_.status.errorCode
                            FailureReason   = $_.status.failureReason
                            ConditionalAccessStatus = $_.conditionalAccessStatus
                            EventTypes      = Get-MtrArray $_.signInEventTypes
                            DeviceDisplayName = $_.deviceDetail.displayName
                            DeviceId        = $_.deviceDetail.deviceId
                            DeviceOs        = $_.deviceDetail.operatingSystem
                            DeviceTrustType = $_.deviceDetail.trustType
                            DeviceIsCompliant = $_.deviceDetail.isCompliant
                            DeviceIsManaged = $_.deviceDetail.isManaged
                            IpAddress       = $_.ipAddress
                            AuthMethods     = @($_.authenticationDetails | ForEach-Object authenticationMethod | Where-Object { $_ } | Sort-Object -Unique)
                            FailedCaPolicies = @($_.appliedConditionalAccessPolicies | Where-Object { $_.result -eq 'failure' } | ForEach-Object { [pscustomobject]@{ Id = $_.id; DisplayName = $_.displayName; Grant = Get-MtrArray $_.enforcedGrantControls } })
                        }
                    })
            }
            if ($denied) { throw [System.UnauthorizedAccessException]::new("403 reading sign-in logs for $denied accounts (needs AuditLog.Read.All and Entra ID P1)") }
        }
    }
    $result
}

function Get-MtrConditionalAccessData {
    $policies = @(Invoke-MtrGraphGet -Uri 'beta/identity/conditionalAccess/policies' -All)
    $locations = @(Invoke-MtrGraphGet -Uri 'v1.0/identity/conditionalAccess/namedLocations' -All)
    [pscustomobject]@{
        Policies       = $policies
        NamedLocations = @($locations | ForEach-Object {
                [pscustomobject]@{
                    Id          = $_.id
                    DisplayName = $_.displayName
                    Type        = $_.'@odata.type'
                    IsTrusted   = $_.isTrusted
                    IpRanges    = @($_.ipRanges | ForEach-Object cidrAddress)
                    Countries   = Get-MtrArray $_.countriesAndRegions
                }
            })
    }
}

function Get-MtrGroupData {
    <#
    .SYNOPSIS
        Member counts for groups that contain candidate accounts, members of likely Teams Rooms groups,
        and all dynamic groups (to review rules).
    #>
    param(
        [Parameter(Mandatory)][hashtable]$CandidateGroupCounts,  # groupId -> number of candidate members
        [string[]]$ExtraGroupIds = @(),
        [int]$MinCandidates = 1
    )
    $groupIds = @(@($CandidateGroupCounts.Keys | Where-Object { $CandidateGroupCounts[$_] -ge $MinCandidates }) + @($ExtraGroupIds) |
            Where-Object { $_ } | Sort-Object -Unique)
    $countRequests = foreach ($g in $groupIds) { [pscustomobject]@{ Id = $g; Url = "/groups/$g/transitiveMembers/`$count"; Eventual = $true } }
    $countResponses = Invoke-MtrGraphBatch -Requests @($countRequests)
    $counts = @{}
    foreach ($g in $groupIds) {
        $r = $countResponses[$g]
        if ($r -and $r.Status -eq 200) { $counts[$g] = [int]$r.Body }
    }

    $dynamic = @(Invoke-MtrGraphGet -Uri "v1.0/groups?`$filter=groupTypes/any(c:c eq 'DynamicMembership')&`$select=id,displayName,membershipRule,membershipRuleProcessingState,securityEnabled&`$top=999" -All)
    [pscustomobject]@{
        MemberCounts  = $counts
        Members       = @{}
        DynamicGroups = $dynamic
    }
}

function Get-MtrGroupMember {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$GroupIds, [int]$MaxMembers = 2000)
    $members = @{}
    foreach ($g in $GroupIds) {
        $items = Invoke-MtrGraphGet -Uri "v1.0/groups/$g/transitiveMembers?`$select=id,displayName,userPrincipalName,mail,deviceId&`$top=999" -All -MaxPages ([math]::Ceiling($MaxMembers / 999))
        $members[$g] = @($items | ForEach-Object { [pscustomobject]@{ Id = $_.id; Type = $_.'@odata.type'; DisplayName = $_.displayName; UserPrincipalName = $_.userPrincipalName } })
    }
    $members
}

function Get-MtrGroupInfo {
    param([Parameter(Mandatory)][AllowEmptyCollection()][string[]]$GroupIds)
    $requests = foreach ($g in $GroupIds) { [pscustomobject]@{ Id = $g; Url = "/groups/$g`?`$select=id,displayName,groupTypes,membershipRule,membershipRuleProcessingState,onPremisesSyncEnabled,securityEnabled,mailEnabled" } }
    $responses = Invoke-MtrGraphBatch -Requests @($requests)
    $info = @{}
    foreach ($g in $GroupIds) { if ($responses[$g] -and $responses[$g].Status -eq 200) { $info[$g] = $responses[$g].Body } }
    $info
}

function Get-MtrPlacesData {
    param([Parameter(Mandatory)]$Context)
    $data = [pscustomobject]@{ Rooms = @(); RoomLists = @(); RoomListMembers = @{}; RoomAccounts = @{}; Buildings = @(); Floors = @(); Sections = @(); HierarchyAvailable = $false }
    $data.Rooms = @(Invoke-MtrGraphGet -Uri 'v1.0/places/microsoft.graph.room?$top=999' -All)
    $data.RoomLists = @(Invoke-MtrGraphGet -Uri 'v1.0/places/microsoft.graph.roomlist?$top=999' -All)

    # Room list membership from Graph, so Room Finder checks still work when Exchange is unavailable.
    $lists = @($data.RoomLists | Where-Object { $_.emailAddress })
    if ($lists.Count) {
        $requests = for ($i = 0; $i -lt $lists.Count; $i++) {
            [pscustomobject]@{ Id = "$i"; Url = "/places/$([uri]::EscapeDataString($lists[$i].emailAddress))/microsoft.graph.roomlist/rooms?`$select=emailAddress,displayName" }
        }
        $responses = Invoke-MtrGraphBatch -Requests @($requests) -FollowNextLink
        Add-MtrBatchCoverage -Context $Context -Section 'Places' -Item 'Room list membership (Graph)' -Responses $responses
        for ($i = 0; $i -lt $lists.Count; $i++) {
            $r = $responses["$i"]
            if ($r -and $r.Status -eq 200) { $data.RoomListMembers[$lists[$i].emailAddress] = @((Get-MtrArray $r.Items) | ForEach-Object { $_.emailAddress } | Where-Object { $_ }) }
        }
    }

    try {
        $data.Buildings = @(Invoke-MtrGraphGet -Uri 'v1.0/places/microsoft.graph.building?$top=999' -All)
        $data.Floors = @(Invoke-MtrGraphGet -Uri 'v1.0/places/microsoft.graph.floor?$top=999' -All)
        $data.Sections = @(Invoke-MtrGraphGet -Uri 'v1.0/places/microsoft.graph.section?$top=999' -All)
        $data.HierarchyAvailable = $true
    }
    catch {
        Add-MtrCoverage -Context $Context -Section 'Places' -Item 'Buildings/floors hierarchy' -Status Partial -Detail "Could not read the Places building hierarchy: $($_.Exception.Message)"
    }
    $data
}

function Get-MtrPlacesRoomAccount {
    <#
    .SYNOPSIS
        Maps each Places room (by email) to its Entra account: id, UPN, enabled, synced. Lets discovery find
        room accounts without Exchange Online.
    .OUTPUTS
        Hashtable: room emailAddress -> account
    #>
    param([AllowEmptyCollection()][object[]]$Rooms = @(), [Parameter(Mandatory)]$Context)
    $emails = @($Rooms | ForEach-Object { $_.emailAddress } | Where-Object { $_ } | Sort-Object -Unique)
    $map = @{}
    if (-not $emails.Count) { return $map }
    $select = 'id,userPrincipalName,mail,accountEnabled,onPremisesSyncEnabled'
    $requests = for ($i = 0; $i -lt $emails.Count; $i++) {
        $filter = [uri]::EscapeDataString("mail eq '$($emails[$i].Replace("'", "''"))'")
        [pscustomobject]@{ Id = "$i"; Url = "/users?`$filter=$filter&`$select=$select" }
    }
    $responses = Invoke-MtrGraphBatch -Requests @($requests)
    Add-MtrBatchCoverage -Context $Context -Section 'Places' -Item 'Room accounts behind Places rooms (lookups)' -Responses $responses
    for ($i = 0; $i -lt $emails.Count; $i++) {
        $account = (Get-MtrArray $responses["$i"].Items) | Select-Object -First 1
        if ($account) { $map[$emails[$i]] = $account }
    }
    $map
}
