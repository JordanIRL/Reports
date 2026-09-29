# Intune and Entra device collectors (Graph beta for Intune). Read-only.

$script:MtrDeviceSelect = @(
    'id', 'deviceName', 'operatingSystem', 'osVersion', 'manufacturer', 'model', 'serialNumber', 'complianceState',
    'lastSyncDateTime', 'enrolledDateTime', 'managementAgent', 'deviceEnrollmentType', 'joinType', 'azureADDeviceId',
    'userPrincipalName', 'userId', 'enrollmentProfileName', 'managedDeviceOwnerType', 'androidSecurityPatchLevel',
    'deviceType', 'autopilotEnrolled'
) -join ','

function Get-MtrManagedDeviceById {
    param([string[]]$DeviceIds)
    $devices = @{}
    $ids = @($DeviceIds | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $ids.Count) { return $devices }
    $requests = foreach ($id in $ids) { [pscustomobject]@{ Id = $id; Url = "/deviceManagement/managedDevices/$id`?`$select=$script:MtrDeviceSelect" } }
    $responses = Invoke-MtrGraphBatch -Requests @($requests) -Version beta
    foreach ($id in $ids) { if ($responses[$id] -and $responses[$id].Status -eq 200) { $devices[$id] = $responses[$id].Body } }
    $devices
}

function Get-MtrIntuneData {
    <#
    .SYNOPSIS
        Finds Teams Rooms devices (by account, Logitech manufacturer, Autopilot MTR- group tag, optional
        name pattern) and collects their Intune/Entra state plus the policies that could apply to them.
    #>
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Baseline,
        [string[]]$CandidateUserIds = @(),
        [string]$WindowsDeviceNamePattern
    )

    $data = [pscustomobject]@{
        Devices                 = @()     # managedDevice objects believed to be Teams Rooms devices
        DeviceSources           = @{}     # deviceId -> list of reasons it was included
        EntraDevices            = @{}     # azureADDeviceId -> Entra device
        DeviceGroups            = @{}     # Entra device object id -> group ids
        AutopilotDevices        = @()
        EnrollmentProfiles      = @()
        CompliancePolicies      = @()
        ConfigurationProfiles   = @()     # normalized: Kind, Id, Name, Type, Platforms, Assignments
        CompliancePolicyStates  = @{}     # deviceId -> states (non-compliant devices only)
        DetectedApps            = @{}     # deviceId -> relevant apps
        TeamworkDevices         = $null
        UserDevices             = @{}     # userId -> device ids
    }
    $devices = @{}
    $sources = @{}
    $addDevice = {
        param($Device, [string]$Reason)
        if (-not $Device -or -not $Device.id) { return }
        $devices[$Device.id] = $Device
        if (-not $sources.ContainsKey($Device.id)) { $sources[$Device.id] = [System.Collections.Generic.List[string]]::new() }
        if (-not $sources[$Device.id].Contains($Reason)) { $sources[$Device.id].Add($Reason) }
    }

    $null = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Devices of candidate accounts' -ScriptBlock {
        $requests = foreach ($id in $CandidateUserIds) { [pscustomobject]@{ Id = $id; Url = "/users/$id/managedDevices?`$select=$script:MtrDeviceSelect" } }
        $responses = Invoke-MtrGraphBatch -Requests @($requests) -Version beta -FollowNextLink
        # Intune answers 404 (ResourceNotFound) for accounts it has never seen, which simply means no devices.
        Add-MtrBatchCoverage -Context $Context -Section 'Intune' -Item 'Devices of candidate accounts (lookups)' -Responses $responses -IgnoreStatus 404
        foreach ($id in $CandidateUserIds) {
            $items = Get-MtrArray $responses[$id].Items
            $data.UserDevices[$id] = @($items | ForEach-Object id)
            foreach ($d in $items) { & $addDevice $d 'Signed in with a room account' }
        }
    }

    $null = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Logitech devices' -ScriptBlock {
        $found = $null
        try {
            $found = Invoke-MtrGraphGet -Uri "beta/deviceManagement/managedDevices?`$filter=manufacturer eq 'Logitech'&`$select=$script:MtrDeviceSelect" -All
        }
        catch {
            Write-Verbose "Server-side manufacturer filter not accepted; filtering Android devices client-side."
            $found = Invoke-MtrGraphGet -Uri "beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Android'&`$select=$script:MtrDeviceSelect" -All
        }
        foreach ($d in (Get-MtrArray $found)) {
            if ($d.manufacturer -match $Baseline.Devices.LogitechManufacturerPattern) { & $addDevice $d 'Logitech device' }
        }
    }

    $null = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Autopilot devices' -ScriptBlock {
        $all = @(Invoke-MtrGraphGet -Uri 'beta/deviceManagement/windowsAutopilotDeviceIdentities?$top=999' -All)
        $prefix = $Baseline.Devices.AutopilotMtrGroupTagPrefix
        $knownManaged = @($devices.Keys)
        $data.AutopilotDevices = @($all | Where-Object { ([string]$_.groupTag).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or ($_.managedDeviceId -and $_.managedDeviceId -in $knownManaged) } |
                Select-Object id, groupTag, serialNumber, model, manufacturer, azureActiveDirectoryDeviceId, managedDeviceId, enrollmentState, deploymentProfileAssignmentStatus, lastContactedDateTime)
        $tagged = @($data.AutopilotDevices | Where-Object { ([string]$_.groupTag).StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and $_.managedDeviceId -and $_.managedDeviceId -ne '00000000-0000-0000-0000-000000000000' })
        $missing = @($tagged | Where-Object { -not $devices.ContainsKey($_.managedDeviceId) } | ForEach-Object managedDeviceId)
        $fetched = Get-MtrManagedDeviceById -DeviceIds $missing
        foreach ($ap in $tagged) {
            $d = if ($devices.ContainsKey($ap.managedDeviceId)) { $devices[$ap.managedDeviceId] } else { $fetched[$ap.managedDeviceId] }
            & $addDevice $d "Autopilot group tag $($ap.groupTag)"
        }
    }

    if ($WindowsDeviceNamePattern) {
        $null = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Windows devices matching name pattern' -ScriptBlock {
            $all = @(Invoke-MtrGraphGet -Uri "beta/deviceManagement/managedDevices?`$filter=operatingSystem eq 'Windows'&`$select=id,deviceName" -All)
            $matched = @($all | Where-Object { $_.deviceName -match $WindowsDeviceNamePattern } | ForEach-Object id)
            $fetched = Get-MtrManagedDeviceById -DeviceIds $matched
            foreach ($id in $matched) { & $addDevice $fetched[$id] "Name matches '$WindowsDeviceNamePattern'" }
        }
    }

    $data.TeamworkDevices = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Teams devices API (deprecated, best-effort)' -ScriptBlock {
        @(Invoke-MtrGraphGet -Uri 'beta/teamwork/devices' -All | Select-Object id, deviceType, healthStatus, activityState, companyAssetTag,
            @{ n = 'currentUserId'; e = { $_.currentUser.id } }, @{ n = 'currentUserName'; e = { $_.currentUser.displayName } },
            @{ n = 'manufacturer'; e = { $_.hardwareDetail.manufacturer } }, @{ n = 'model'; e = { $_.hardwareDetail.model } },
            @{ n = 'serialNumber'; e = { $_.hardwareDetail.serialNumber } }, lastModifiedDateTime)
    }

    $data.Devices = @($devices.Values)
    foreach ($k in $sources.Keys) { $data.DeviceSources[$k] = @($sources[$k]) }

    $null = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Entra device objects and group membership' -ScriptBlock {
        $aadIds = @($data.Devices | ForEach-Object azureADDeviceId | Where-Object { $_ -and $_ -ne '00000000-0000-0000-0000-000000000000' } | Sort-Object -Unique)
        $requests = foreach ($aad in $aadIds) {
            [pscustomobject]@{ Id = $aad; Url = "/devices?`$filter=deviceId eq '$aad'&`$select=id,deviceId,displayName,trustType,physicalIds,enrollmentProfileName,isCompliant,isManaged,accountEnabled,approximateLastSignInDateTime,operatingSystem,operatingSystemVersion" }
        }
        $responses = Invoke-MtrGraphBatch -Requests @($requests)
        foreach ($aad in $aadIds) {
            $entra = @($responses[$aad].Items)[0]
            if ($entra) { $data.EntraDevices[$aad] = $entra }
        }
        $objectIds = @($data.EntraDevices.Values | ForEach-Object id)
        $requests = foreach ($oid in $objectIds) { [pscustomobject]@{ Id = $oid; Url = "/devices/$oid/transitiveMemberOf?`$select=id,displayName&`$top=999" } }
        $responses = Invoke-MtrGraphBatch -Requests @($requests) -FollowNextLink
        foreach ($oid in $objectIds) { $data.DeviceGroups[$oid] = Get-MtrArray ((Get-MtrArray $responses[$oid].Items) | ForEach-Object { $_.id }) }
    }

    $data.EnrollmentProfiles = @(Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Android (AOSP) enrollment profiles' -ScriptBlock {
            # Explicit $select: never read tokenValue / QR code content.
            Invoke-MtrGraphGet -Uri 'beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles?$select=id,displayName,enrollmentMode,isTeamsDeviceProfile,tokenExpirationDateTime,tokenCreationDateTime,enrolledDeviceCount,enrollmentTokenUsageCount' -All
        })

    $data.CompliancePolicies = @(Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Compliance policies' -ScriptBlock {
            Invoke-MtrGraphGet -Uri 'beta/deviceManagement/deviceCompliancePolicies?$expand=assignments' -All
        })

    $profiles = [System.Collections.Generic.List[object]]::new()
    $profileSources = @(
        @{ Kind = 'Configuration profile'; Uri = 'beta/deviceManagement/deviceConfigurations?$select=id,displayName&$expand=assignments'; Name = 'displayName' }
        @{ Kind = 'Settings catalog / endpoint security'; Uri = 'beta/deviceManagement/configurationPolicies?$select=id,name,platforms,technologies,templateReference&$expand=assignments'; Name = 'name' }
        @{ Kind = 'Feature update profile'; Uri = 'beta/deviceManagement/windowsFeatureUpdateProfiles?$expand=assignments'; Name = 'displayName' }
        @{ Kind = 'Platform script'; Uri = 'beta/deviceManagement/deviceManagementScripts?$select=id,displayName&$expand=assignments'; Name = 'displayName' }
        @{ Kind = 'Remediation script'; Uri = 'beta/deviceManagement/deviceHealthScripts?$select=id,displayName&$expand=assignments'; Name = 'displayName' }
        @{ Kind = 'Administrative template'; Uri = 'beta/deviceManagement/groupPolicyConfigurations?$select=id,displayName&$expand=assignments'; Name = 'displayName' }
    )
    foreach ($source in $profileSources) {
        $items = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item $source.Kind -ScriptBlock { Invoke-MtrGraphGet -Uri $source.Uri -All }
        foreach ($item in (Get-MtrArray $items)) {
            if (-not $item) { continue }
            $profiles.Add([pscustomobject]@{
                    Kind        = $source.Kind
                    Id          = $item.id
                    Name        = $item.($source.Name)
                    Type        = $item.'@odata.type'
                    Platforms   = $item.platforms
                    Template    = if ($item.templateReference) { $item.templateReference.templateDisplayName } else { $null }
                    TemplateFamily = if ($item.templateReference) { $item.templateReference.templateFamily } else { $null }
                    FeatureUpdateVersion = $item.featureUpdateVersion
                    Assignments = @($item.assignments | ForEach-Object { $_.target })
                })
        }
    }
    $data.ConfigurationProfiles = $profiles.ToArray()

    $nonCompliant = @($data.Devices | Where-Object { $_.complianceState -and $_.complianceState -notin @('compliant', 'unknown') } | ForEach-Object id)
    if ($nonCompliant.Count) {
        $null = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Compliance state of non-compliant devices' -ScriptBlock {
            $requests = foreach ($id in $nonCompliant) { [pscustomobject]@{ Id = $id; Url = "/deviceManagement/managedDevices/$id/deviceCompliancePolicyStates" } }
            $responses = Invoke-MtrGraphBatch -Requests @($requests) -Version beta
            foreach ($id in $nonCompliant) {
                $data.CompliancePolicyStates[$id] = @((Get-MtrArray $responses[$id].Items) | ForEach-Object {
                        [pscustomobject]@{
                            PolicyName = $_.displayName
                            State      = $_.state
                            FailedSettings = @($_.settingStates | Where-Object { $_.state -notin @('compliant', 'notApplicable') } | ForEach-Object { '{0} ({1})' -f $_.settingName, $_.state })
                        }
                    })
            }
        }
    }

    if ($data.Devices.Count) {
        $null = Invoke-MtrCollectorStep -Context $Context -Section 'Intune' -Item 'Detected app versions (best-effort)' -ScriptBlock {
            $ids = @($data.Devices | ForEach-Object id)
            $requests = foreach ($id in $ids) { [pscustomobject]@{ Id = $id; Url = "/deviceManagement/managedDevices/$id/detectedApps?`$select=displayName,version,platform&`$top=999" } }
            $responses = Invoke-MtrGraphBatch -Requests @($requests) -Version beta
            $pattern = '{0}|{1}' -f $Baseline.Devices.TeamsRoomsAppNamePattern, $Baseline.Devices.AuthenticatorAppNamePattern
            foreach ($id in $ids) {
                $data.DetectedApps[$id] = @((Get-MtrArray $responses[$id].Items) | Where-Object { $_.displayName -match $pattern } | Select-Object displayName, version)
            }
        }
    }
    $data
}
