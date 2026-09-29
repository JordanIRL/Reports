#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Drives the live collection path (Invoke-MtrCollection) against a fake Microsoft Graph that answers by URL,
# including $batch. Every collection returns MORE THAN ONE item: single-item responses hid a real bug
# (collections were nested one level deep) until the tool ran against a real tenant.

BeforeAll {
    $script:root = Split-Path -Path $PSScriptRoot -Parent
    $script:MtrToolVersion = 'test'
    foreach ($file in Get-ChildItem -Path (Join-Path $root 'src') -Recurse -Filter '*.ps1' | Where-Object Name -ne 'Invoke-MtrIsolatedCall.ps1') { . $file.FullName }
    $script:baseline = Import-PowerShellDataFile -Path (Join-Path $root 'config/MtrBaseline.psd1')
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        function global:Invoke-MgGraphRequest { param($Uri, $Method, $Body, $Headers, $OutputType, $ContentType) }
    }

    function script:Find-NestedArray {
        # Returns the paths of arrays that directly contain another array (the symptom of the nesting bug).
        param($Value, [string]$Path = '$', [int]$Depth = 0)
        if ($null -eq $Value -or $Depth -gt 30 -or $Value -is [string] -or $Value -is [datetime] -or $Value.GetType().IsPrimitive) { return }
        if ($Value -is [System.Collections.IDictionary]) {
            foreach ($k in @($Value.Keys)) { Find-NestedArray -Value $Value[$k] -Path "$Path.$k" -Depth ($Depth + 1) }
            return
        }
        if ($Value -is [System.Collections.IEnumerable]) {
            $i = 0
            foreach ($item in $Value) {
                if ($item -is [System.Collections.IList] -and $item -isnot [string]) { "$Path[$i]" }
                Find-NestedArray -Value $item -Path "$Path[$i]" -Depth ($Depth + 1)
                $i++
            }
            return
        }
        if ($Value -is [System.Management.Automation.PSCustomObject]) {
            foreach ($p in $Value.PSObject.Properties) { Find-NestedArray -Value $p.Value -Path "$Path.$($p.Name)" -Depth ($Depth + 1) }
        }
    }

    $script:calls = [System.Collections.Generic.List[object]]::new()
    $script:fakeScenario = 'normal'
    $script:fakeJson = { param($o) $o | ConvertTo-Json -Depth 20 | ConvertFrom-Json -Depth 20 }
    $script:fakeList = { param([object[]]$items) & $script:fakeJson @{ value = @($items) } }
    $script:fakePlans = @(
        @{ servicePlanId = 'ecc74eae-eeb7-4ad5-9c88-e8b2bfca75b8'; servicePlanName = 'MTRProManagement'; provisioningStatus = 'Success'; appliesTo = 'User' }
        @{ servicePlanId = 'c1ec4a95-1f05-45b3-a911-aa3fa01094f5'; servicePlanName = 'INTUNE_A'; provisioningStatus = 'Success'; appliesTo = 'User' }
        @{ servicePlanId = '57ff2da0-773e-42df-b2af-ffb7a2317929'; servicePlanName = 'TEAMS1'; provisioningStatus = 'Success'; appliesTo = 'User' }
    )
    $script:fakeUsers = @{
        u1 = @{ id = 'u1'; userPrincipalName = 'rm1@contoso.com'; displayName = 'Room 1'; mail = 'rm1@contoso.com'; accountEnabled = $true; onPremisesSyncEnabled = $true; assignedLicenses = @(@{ skuId = 'sku-pro' }); signInActivity = @{ lastSuccessfulSignInDateTime = '2026-09-28T07:00:00Z' } }
        u2 = @{ id = 'u2'; userPrincipalName = 'dub-rm2@contoso.com'; displayName = 'Dublin Room 2'; mail = 'dub-rm2@contoso.com'; accountEnabled = $true; onPremisesSyncEnabled = $false; assignedLicenses = @(); signInActivity = @{ lastSuccessfulSignInDateTime = '2026-09-27T07:00:00Z' } }
    }
    $script:fakeDevices = @{
        d1 = @{ id = 'd1'; deviceName = 'RALLY-1'; operatingSystem = 'Android'; osVersion = '12'; manufacturer = 'Logitech'; model = 'Rally Bar'; complianceState = 'compliant'; lastSyncDateTime = '2026-09-28T08:00:00Z'; deviceEnrollmentType = 'androidAOSPUserOwnedDeviceEnrollment'; azureADDeviceId = 'aad1'; userPrincipalName = 'rm1@contoso.com'; userId = 'u1' }
        d3 = @{ id = 'd3'; deviceName = 'TAP-1'; operatingSystem = 'Android'; osVersion = '10'; manufacturer = 'Logitech'; model = 'Tap Scheduler'; complianceState = 'compliant'; lastSyncDateTime = '2026-09-28T08:00:00Z'; deviceEnrollmentType = 'androidAOSPUserOwnedDeviceEnrollment'; azureADDeviceId = 'aad3'; userPrincipalName = 'rm1@contoso.com'; userId = 'u1' }
        d2 = @{ id = 'd2'; deviceName = 'LON-MTR-1'; operatingSystem = 'Windows'; osVersion = '10.0.26100.8700'; manufacturer = 'Lenovo'; model = 'ThinkSmart Core'; complianceState = 'noncompliant'; lastSyncDateTime = '2026-09-28T08:00:00Z'; deviceEnrollmentType = 'windowsAzureADJoin'; joinType = 'azureADJoined'; azureADDeviceId = 'aad2'; userPrincipalName = $null; userId = $null }
    }

    $script:fakeRoute = {
        param([string]$url)
        $u = [uri]::UnescapeDataString($url) -replace '^https://graph\.microsoft\.com/(v1\.0|beta)', '' -replace '^/(v1\.0|beta)', ''
        $empty = $script:fakeScenario -eq 'empty'
        switch -Regex ($u) {
            '^/organization' { return & $script:fakeList @(@{ id = 't1'; displayName = 'Contoso'; verifiedDomains = @(@{ name = 'contoso.com'; isDefault = $true }, @{ name = 'contoso.onmicrosoft.com'; isDefault = $false }); onPremisesSyncEnabled = $true; onPremisesLastSyncDateTime = '2026-09-28T09:30:00Z' }) }
            '^/domains' { return & $script:fakeList @(@{ id = 'contoso.com'; authenticationType = 'Managed'; passwordValidityPeriodInDays = 2147483647 }, @{ id = 'contoso.onmicrosoft.com'; authenticationType = 'Managed'; passwordValidityPeriodInDays = 2147483647 }) }
            '^/directory/onPremisesSynchronization' { return & $script:fakeList @(@{ id = 't1'; features = @{ cloudPasswordPolicyForPasswordSyncedUsersEnabled = $false } }) }
            '^/subscribedSkus' {
                return & $script:fakeList @(
                    @{ skuId = 'sku-pro'; skuPartNumber = 'Microsoft_Teams_Rooms_Pro'; capabilityStatus = 'Enabled'; consumedUnits = 1; prepaidUnits = @{ enabled = 5; warning = 0; suspended = 0 }; servicePlans = $script:fakePlans }
                    @{ skuId = 'sku-e3'; skuPartNumber = 'SPE_E3'; capabilityStatus = 'Enabled'; consumedUnits = 40; prepaidUnits = @{ enabled = 50; warning = 0; suspended = 0 }; servicePlans = @($script:fakePlans[1], $script:fakePlans[2]) }
                )
            }
            '^/users\?\$filter=assignedLicenses' { if ($empty) { return & $script:fakeList @() }; return & $script:fakeList @(@{ id = 'u1'; userPrincipalName = 'rm1@contoso.com' }) }
            "^/users\?\`$filter=mail eq '([^']+)'" {
                $mail = $Matches[1]
                $hit = @($script:fakeUsers.Values | Where-Object { $_.mail -eq $mail })
                return & $script:fakeList $hit
            }
            '^/users/(u1|u2)\?\$select' { return & $script:fakeJson $script:fakeUsers[$Matches[1]] }
            '^/users/u1/licenseDetails' { return & $script:fakeList @(@{ skuId = 'sku-pro'; skuPartNumber = 'Microsoft_Teams_Rooms_Pro'; servicePlans = $script:fakePlans }) }
            '^/users/u2/licenseDetails' { return & $script:fakeList @() }
            '^/users/(u1|u2)/transitiveMemberOf' { return & $script:fakeList @(@{ '@odata.type' = '#microsoft.graph.group'; id = 'g1'; displayName = 'Rooms'; groupTypes = @() }, @{ '@odata.type' = '#microsoft.graph.group'; id = 'g2'; displayName = 'All staff'; groupTypes = @() }) }
            '^/users/(u1|u2)/authentication/methods' { return & $script:fakeList @(@{ '@odata.type' = '#microsoft.graph.passwordAuthenticationMethod'; id = 'p' }, @{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; id = 'ph'; phoneNumber = '+1 555 0100' }) }
            '^/users/(u1|u2)/registeredDevices' { return & $script:fakeList @(@{ id = 'x1' }, @{ id = 'x2' }) }
            '^/users/u1/managedDevices' { return & $script:fakeList @($script:fakeDevices.d1, $script:fakeDevices.d3) }
            # Intune answers 404 ResourceNotFound for accounts it has never seen (seen on a real tenant).
            '^/users/u2/managedDevices' { throw [System.Net.Http.HttpRequestException]::new('Response status code does not indicate success: 404 (Not Found). ResourceNotFound') }
            '^/roleManagement/directory/roleAssignments' { return & $script:fakeList @() }
            '^/policies/identitySecurityDefaultsEnforcementPolicy' { return & $script:fakeJson @{ isEnabled = $false } }
            '^/policies/authenticationMethodsPolicy' { return & $script:fakeJson @{ registrationEnforcement = @{ authenticationMethodsRegistrationCampaign = @{ state = 'disabled' } } } }
            '^/policies/deviceRegistrationPolicy' { throw [System.Net.Http.HttpRequestException]::new('Response status code does not indicate success: 403 (Forbidden).') }
            '^/auditLogs/signIns' {
                return & $script:fakeList @(
                    @{ createdDateTime = '2026-09-28T07:00:00Z'; appDisplayName = 'Microsoft Teams'; status = @{ errorCode = 0 }; deviceDetail = @{ displayName = 'Logitech Rally Bar'; operatingSystem = 'Android'; deviceId = 'aad1' }; authenticationDetails = @(@{ authenticationMethod = 'Password' }); appliedConditionalAccessPolicies = @() }
                    @{ createdDateTime = '2026-09-28T06:00:00Z'; appDisplayName = 'Microsoft Teams'; status = @{ errorCode = 50126; failureReason = 'Invalid password' }; deviceDetail = @{ displayName = 'LON-MTR-1'; operatingSystem = 'Windows'; deviceId = 'aad2' }; authenticationDetails = @(); appliedConditionalAccessPolicies = @() }
                )
            }
            '^/identity/conditionalAccess/policies' { return & $script:fakeList @(@{ id = 'ca1'; displayName = 'MFA all'; state = 'enabled'; conditions = @{ users = @{ includeUsers = @('All') }; applications = @{ includeApplications = @('All') }; clientAppTypes = @('all') }; grantControls = @{ operator = 'OR'; builtInControls = @('mfa') } }, @{ id = 'ca2'; displayName = 'Rooms compliant'; state = 'enabled'; conditions = @{ users = @{ includeGroups = @('g1') }; applications = @{ includeApplications = @('Office365') }; clientAppTypes = @('all') }; grantControls = @{ operator = 'OR'; builtInControls = @('compliantDevice') } }) }
            '^/identity/conditionalAccess/namedLocations' { return & $script:fakeList @(@{ id = 'nl1'; displayName = 'HQ'; isTrusted = $true; ipRanges = @(@{ cidrAddress = '203.0.113.0/24' }) }, @{ id = 'nl2'; displayName = 'Branch'; isTrusted = $false; ipRanges = @(@{ cidrAddress = '198.51.100.0/24' }) }) }
            '^/groups/g1/transitiveMembers/\$count' { return 2 }
            '^/groups/g2/transitiveMembers/\$count' { return 500 }
            '^/groups/g1/transitiveMembers' { return & $script:fakeList @(@{ '@odata.type' = '#microsoft.graph.user'; id = 'u1'; userPrincipalName = 'rm1@contoso.com' }, @{ '@odata.type' = '#microsoft.graph.user'; id = 'u2'; userPrincipalName = 'dub-rm2@contoso.com' }) }
            '^/groups\?\$filter=groupTypes' { return & $script:fakeList @(@{ id = 'dg1'; displayName = 'MTR devices'; membershipRule = '(device.devicePhysicalIds -any _ -startswith "[OrderID]:MTR-")' }, @{ id = 'dg2'; displayName = 'Sales'; membershipRule = 'user.department -eq "Sales"' }) }
            '^/places/microsoft\.graph\.room\?' { if ($empty) { return & $script:fakeList @() }; return & $script:fakeList @(@{ id = 'r1'; emailAddress = 'rm1@contoso.com'; displayName = 'Room 1'; teamsEnabledState = 'enabled'; capacity = 6; address = @{ city = 'London' } }, @{ id = 'r2'; emailAddress = 'dub-rm2@contoso.com'; displayName = 'Dublin Room 2'; teamsEnabledState = 'disabled'; capacity = 0; address = $null }) }
            '^/places/microsoft\.graph\.roomlist\?' { if ($empty) { return & $script:fakeList @() }; return & $script:fakeList @(@{ id = 'l1'; displayName = 'London HQ'; emailAddress = 'lonhq@contoso.com' }, @{ id = 'l2'; displayName = 'Dublin HQ'; emailAddress = 'dubhq@contoso.com' }) }
            '^/places/lonhq@contoso\.com/microsoft\.graph\.roomlist/rooms' { return & $script:fakeList @(@{ emailAddress = 'rm1@contoso.com' }, @{ emailAddress = 'dub-rm2@contoso.com' }) }
            '^/places/dubhq@contoso\.com/microsoft\.graph\.roomlist/rooms' { return & $script:fakeList @(@{ emailAddress = 'dub-rm2@contoso.com' }) }
            '^/places/microsoft\.graph\.(building|floor|section)' { return & $script:fakeList @() }
            '^/deviceManagement/managedDevices\?\$filter=manufacturer' { if ($empty) { return & $script:fakeList @() }; return & $script:fakeList @($script:fakeDevices.d1, $script:fakeDevices.d3) }
            '^/deviceManagement/managedDevices/(d\d)\?' { return & $script:fakeJson $script:fakeDevices[$Matches[1]] }
            '^/deviceManagement/windowsAutopilotDeviceIdentities' { if ($empty) { return & $script:fakeList @() }; return & $script:fakeList @(@{ id = 'ap1'; groupTag = 'MTR-LON'; serialNumber = 'S1'; managedDeviceId = 'd2'; azureActiveDirectoryDeviceId = 'aad2' }, @{ id = 'ap2'; groupTag = 'Sales'; serialNumber = 'S2'; managedDeviceId = 'dx' }) }
            '^/teamwork/devices' { return & $script:fakeList @() }
            "^/devices\?\`$filter=deviceId eq '(aad\d)'" { return & $script:fakeList @(@{ id = "e-$($Matches[1])"; deviceId = $Matches[1]; trustType = 'AzureAd' }) }
            '^/devices/e-aad\d/transitiveMemberOf' { return & $script:fakeList @(@{ id = 'dg1' }, @{ id = 'dg9' }) }
            '^/deviceManagement/androidDeviceOwnerEnrollmentProfiles' { return & $script:fakeList @(@{ id = 'ep'; displayName = 'AOSP - Teams'; isTeamsDeviceProfile = $true; tokenExpirationDateTime = '2090-01-01T00:00:00Z' }, @{ id = 'ep2'; displayName = 'Kiosk'; isTeamsDeviceProfile = $false }) }
            '^/deviceManagement/deviceCompliancePolicies' { return & $script:fakeList @(@{ '@odata.type' = '#microsoft.graph.windows10CompliancePolicy'; id = 'c1'; displayName = 'Win'; assignments = @(@{ target = @{ '@odata.type' = '#microsoft.graph.allDevicesAssignmentTarget' } }) }, @{ '@odata.type' = '#microsoft.graph.aospDeviceOwnerCompliancePolicy'; id = 'c2'; displayName = 'AOSP'; assignments = @() }) }
            '^/deviceManagement/(deviceConfigurations|configurationPolicies|windowsFeatureUpdateProfiles|deviceManagementScripts|deviceHealthScripts|groupPolicyConfigurations)' { return & $script:fakeList @(@{ id = 'p1'; displayName = 'One'; name = 'One'; assignments = @() }, @{ id = 'p2'; displayName = 'Two'; name = 'Two'; assignments = @() }) }
            '^/deviceManagement/managedDevices/d\d/deviceCompliancePolicyStates' { return & $script:fakeList @(@{ displayName = 'Win'; state = 'nonCompliant'; settingStates = @(@{ settingName = 'PasswordRequired'; state = 'nonCompliant' }, @{ settingName = 'Firewall'; state = 'compliant' }) }) }
            '^/deviceManagement/managedDevices/d\d/detectedApps' { return & $script:fakeList @(@{ displayName = 'Microsoft Teams Rooms'; version = '1449/1.0.96.2026249711' }, @{ displayName = 'Notepad'; version = '1.0' }) }
            default { throw [System.Net.Http.HttpRequestException]::new("Response status code does not indicate success: 404 (Not Found). $u") }
        }
    }

    Mock Invoke-MgGraphRequest {
        $calls.Add([pscustomobject]@{ Method = $Method; Uri = $Uri; Body = $Body })
        if ($Method -eq 'POST') {
            $requests = ($Body | ConvertFrom-Json).requests
            $responses = foreach ($r in $requests) {
                try { @{ id = $r.id; status = 200; body = (& $script:fakeRoute $r.url) } }
                catch {
                    $status = if ($_.Exception.Message -match '\b(4\d\d)\b') { [int]$Matches[1] } else { 500 }
                    @{ id = $r.id; status = $status; body = @{ error = @{ code = 'Error'; message = $_.Exception.Message } } }
                }
            }
            return (@{ responses = @($responses) } | ConvertTo-Json -Depth 25 | ConvertFrom-Json -Depth 25)
        }
        & $script:fakeRoute $Uri
    }

    $script:sections = @('Identity', 'Licensing', 'ConditionalAccess', 'Groups', 'Places', 'Intune')
    $script:ctx = New-MtrContext -Parameters @{}
    $session = [pscustomobject]@{ Graph = 'InProcess'; Exchange = 'Unavailable'; Teams = 'Unavailable'; TenantId = 't1'; Upn = 'auditor@contoso.com'; SourceRoot = (Join-Path $root 'src'); Errors = @{} }
    Invoke-MtrCollection -Context $ctx -Session $session -Baseline $baseline -Sections $sections -SignInLookbackDays 7 6>$null 3>$null
}

Describe 'Live collection path against a fake Graph (multi-item responses)' {
    It 'never nests collections' {
        @(Find-NestedArray -Value $ctx) | Should -BeNullOrEmpty
        $path = Join-Path $TestDrive 'Snapshot.json'
        Export-MtrSnapshot -Context $ctx -Path $path
        @(Find-NestedArray -Value (Import-MtrSnapshot -Path $path)) | Should -BeNullOrEmpty
    }
    It 'classifies every SKU (multi-SKU tenants used to fail)' {
        @($ctx.Licensing.Skus).Count | Should -Be 2
        ($ctx.Licensing.Skus | Where-Object SkuPartNumber -eq 'Microsoft_Teams_Rooms_Pro').IsTeamsRooms | Should -BeTrue
        ($ctx.Licensing.Skus | Where-Object SkuPartNumber -eq 'SPE_E3').Enabled | Should -Be 50
    }
    It 'discovers the licensed room and the Places-only room account' {
        @($ctx.Identity.Candidates | ForEach-Object Id) | Should -Contain 'u1'
        @($ctx.Identity.Candidates | ForEach-Object Id) | Should -Contain 'u2'
        @($ctx.Identity.Users).Count | Should -Be 2
        @($ctx.Identity.Users | Where-Object Id -eq 'u1' | ForEach-Object { $_.Groups } | ForEach-Object id) | Should -Be @('g1', 'g2')
    }
    It 'collects every Places room, room list membership and room account' {
        @($ctx.Places.Rooms).Count | Should -Be 2
        @($ctx.Places.RoomLists).Count | Should -Be 2
        @(Get-MtrPropertyValue $ctx.Places.RoomListMembers 'lonhq@contoso.com') | Should -Be @('rm1@contoso.com', 'dub-rm2@contoso.com')
        (Get-MtrPropertyValue $ctx.Places.RoomAccounts 'dub-rm2@contoso.com').id | Should -Be 'u2'
    }
    It 'collects sign-ins, auth methods and device counts per account' {
        @(Get-MtrPropertyValue $ctx.Identity.Extra.SignIns 'u1').Count | Should -Be 2
        @(Get-MtrPropertyValue $ctx.Identity.Extra.AuthMethods 'u1').Count | Should -Be 2
        Get-MtrPropertyValue $ctx.Identity.Extra.RegisteredDevices 'u1' | Should -Be 2
    }
    It 'finds Logitech and Autopilot MTR- devices, their Entra objects and groups' {
        @($ctx.Intune.Devices | ForEach-Object id | Sort-Object) | Should -Be @('d1', 'd2', 'd3')
        @(Get-MtrPropertyValue $ctx.Intune.DeviceGroups 'e-aad2') | Should -Be @('dg1', 'dg9')
        @($ctx.Intune.AutopilotDevices).Count | Should -Be 1
        @(Get-MtrPropertyValue $ctx.Intune.DetectedApps 'd1').Count | Should -Be 1
        @(Get-MtrPropertyValue $ctx.Intune.CompliancePolicyStates 'd2')[0].FailedSettings | Should -Be @('PasswordRequired (nonCompliant)')
    }
    It 'does not invent Teams devices from an empty API response' {
        Get-MtrCount $ctx.Intune.TeamworkDevices | Should -Be 0
    }
    It 'collects policies and profiles as flat lists' {
        @($ctx.ConditionalAccess.Policies).Count | Should -Be 2
        @($ctx.ConditionalAccess.NamedLocations).Count | Should -Be 2
        @($ctx.Intune.CompliancePolicies).Count | Should -Be 2
        @($ctx.Intune.EnrollmentProfiles).Count | Should -Be 2
        @($ctx.Groups.DynamicGroups).Count | Should -Be 2
    }
    It 'reports failures with a reason' {
        $c = $ctx.Coverage | Where-Object Item -eq 'Device registration policy'
        $c.Status | Should -Be 'Failed'
        $c.Detail | Should -Match '403'
        @($ctx.Coverage | Where-Object { $_.Status -in 'Failed', 'Partial' -and -not $_.Detail }) | Should -BeNullOrEmpty
    }
    It 'has no unexpected collection failures' {
        @($ctx.Coverage | Where-Object { $_.Status -in 'Failed', 'Partial' -and $_.Item -ne 'Device registration policy' } | ForEach-Object { "$($_.Section)/$($_.Item): $($_.Detail)" }) | Should -BeNullOrEmpty
    }
    It 'treats an account unknown to Intune as having no devices' {
        Get-MtrPropertyValue $ctx.Intune.UserDevices 'u2' | Should -BeNullOrEmpty
        @($ctx.Coverage | Where-Object Item -like 'Devices of candidate accounts*' | Where-Object Status -ne 'OK') | Should -BeNullOrEmpty
    }
    It 'never reads enrollment tokens' {
        $profileCall = $calls | Where-Object Uri -like '*androidDeviceOwnerEnrollmentProfiles*' | Select-Object -First 1
        $profileCall.Uri | Should -Match '\$select='
        $profileCall.Uri | Should -Not -Match 'tokenValue|qrCode'
    }
    It 'only issued GET requests, plus GET-only batches' {
        @($calls | Where-Object { $_.Method -notin 'GET', 'POST' }) | Should -BeNullOrEmpty
        foreach ($post in @($calls | Where-Object Method -eq 'POST')) {
            $post.Uri | Should -Match '/\$batch$'
            @(($post.Body | ConvertFrom-Json).requests | Where-Object method -ne 'GET') | Should -BeNullOrEmpty
        }
    }
    It 'feeds discovery and every check without errors' {
        $model = Resolve-MtrAccount -Context $ctx -Baseline $baseline
        ($model.Accounts | Where-Object Id -eq 'u1').Classification | Should -Be 'Confirmed'
        ($model.Accounts | Where-Object Id -eq 'u2').IsRoomMailbox | Should -BeTrue
        @(($model.Accounts | Where-Object Id -eq 'u1').Devices | ForEach-Object Name) | Should -Contain 'LON-MTR-1'   # via sign-in device ID
        $settings = [pscustomobject]@{ Now = $ctx.Meta.CollectedAt; StaleDays = 30; OnPremMaxPasswordAgeDays = 0; SignInLookbackDays = 7; Sections = $sections }
        foreach ($fn in 'Test-MtrDiscovery', 'Test-MtrLicensing', 'Test-MtrIdentity', 'Test-MtrConditionalAccess', 'Test-MtrGroups', 'Test-MtrExchange', 'Test-MtrPlaces', 'Test-MtrTeams', 'Test-MtrIntune') {
            { & $fn -Model $model -Context $ctx -Baseline $baseline -Settings $settings } | Should -Not -Throw
        }
    }
    It 'runs Room Finder checks from Graph Places when Exchange is unavailable' {
        $model = Resolve-MtrAccount -Context $ctx -Baseline $baseline
        $settings = [pscustomobject]@{ Now = $ctx.Meta.CollectedAt; StaleDays = 30; OnPremMaxPasswordAgeDays = 0; SignInLookbackDays = 7; Sections = $sections }
        $f = @(Test-MtrPlaces -Model $model -Context $ctx -Baseline $baseline -Settings $settings)
        ($f | Where-Object CheckId -eq 'RF-02').AffectedObjects[0] | Should -Match 'dub-rm2@contoso\.com.*Dublin HQ, London HQ'
        $city = $f | Where-Object { $_.CheckId -eq 'RF-05' -and $_.Title -like '*no City*' }
        $city.Title | Should -Be '1 room(s) have no City'
        $city.RemediationCommand | Should -Be @("Set-Place -Identity 'dub-rm2@contoso.com' -City '<city>'")   # cloud-only room
        ($f | Where-Object { $_.CheckId -eq 'RF-05' -and $_.Title -like '*no Capacity*' }).AffectedObjects | Should -Be @('dub-rm2@contoso.com')
    }
}

Describe 'Tenant with no Teams Rooms' {
    BeforeAll {
        $script:fakeScenario = 'empty'
        $script:emptyCtx = New-MtrContext -Parameters @{}
        $session = [pscustomobject]@{ Graph = 'InProcess'; Exchange = 'Unavailable'; Teams = 'Unavailable'; TenantId = 't1'; Upn = 'auditor@contoso.com'; SourceRoot = (Join-Path $root 'src'); Errors = @{} }
        Invoke-MtrCollection -Context $emptyCtx -Session $session -Baseline $baseline -Sections $sections -SignInLookbackDays 7 6>$null 3>$null
        $script:fakeScenario = 'normal'
    }
    It 'still collects tenant-level settings' {
        @($emptyCtx.Identity.Users).Count | Should -Be 0
        $emptyCtx.Identity.Extra.SecurityDefaults.isEnabled | Should -BeFalse
        @($emptyCtx.ConditionalAccess.Policies).Count | Should -Be 2
        ($emptyCtx.Coverage | Where-Object Item -eq 'Candidate accounts').Status | Should -Be 'Skipped'
    }
    It 'has no collection failures (group analysis used to fail on an empty group list)' {
        @($emptyCtx.Coverage | Where-Object { $_.Status -in 'Failed', 'Partial' -and $_.Item -ne 'Device registration policy' } | ForEach-Object { "$($_.Section)/$($_.Item): $($_.Detail)" }) | Should -BeNullOrEmpty
        ($emptyCtx.Coverage | Where-Object Item -eq 'Group membership analysis').Status | Should -Be 'OK'
    }
    It 'runs every check without errors' {
        $model = Resolve-MtrAccount -Context $emptyCtx -Baseline $baseline
        $settings = [pscustomobject]@{ Now = $emptyCtx.Meta.CollectedAt; StaleDays = 30; OnPremMaxPasswordAgeDays = 0; SignInLookbackDays = 7; Sections = $sections }
        foreach ($fn in 'Test-MtrDiscovery', 'Test-MtrLicensing', 'Test-MtrIdentity', 'Test-MtrConditionalAccess', 'Test-MtrGroups', 'Test-MtrExchange', 'Test-MtrPlaces', 'Test-MtrTeams', 'Test-MtrIntune') {
            { & $fn -Model $model -Context $emptyCtx -Baseline $baseline -Settings $settings } | Should -Not -Throw
        }
    }
}

Describe 'Exchange and Teams collectors (stubbed cmdlets, in-process)' {
    BeforeAll {
        $script:fakeMailbox = { param($upn, $type, [bool]$disabled = $false) [pscustomobject]@{ Identity = $upn; DisplayName = $upn; Alias = $upn.Split('@')[0]; UserPrincipalName = $upn; PrimarySmtpAddress = $upn; ExternalDirectoryObjectId = 'u1'; RecipientTypeDetails = $type; HiddenFromAddressListsEnabled = $false; IsDirSynced = $true; ResourceCapacity = 6; RoomMailboxAccountEnabled = -not $disabled; AccountDisabled = $disabled; Office = $null } }
        function global:Get-Mailbox { param($Identity, $RecipientTypeDetails, $ResultSize, $ErrorAction) if ($RecipientTypeDetails) { & $script:fakeMailbox 'rm1@contoso.com' 'RoomMailbox'; & $script:fakeMailbox 'plain@contoso.com' 'RoomMailbox' $true } else { & $script:fakeMailbox $Identity 'RoomMailbox' } }
        function global:Get-DistributionGroup { param($RecipientTypeDetails, $ResultSize, $ErrorAction) [pscustomobject]@{ DisplayName = 'HQ'; Name = 'HQ'; PrimarySmtpAddress = 'hq@contoso.com'; ExternalDirectoryObjectId = 'rl1'; IsDirSynced = $true }; [pscustomobject]@{ DisplayName = 'Annex'; Name = 'Annex'; PrimarySmtpAddress = 'annex@contoso.com'; ExternalDirectoryObjectId = 'rl2'; IsDirSynced = $true } }
        function global:Get-DistributionGroupMember { param($Identity, $ResultSize, $ErrorAction) [pscustomobject]@{ DisplayName = 'Room 1'; PrimarySmtpAddress = 'rm1@contoso.com'; ExternalDirectoryObjectId = 'u1'; RecipientTypeDetails = 'RoomMailbox' }; [pscustomobject]@{ DisplayName = 'Plain'; PrimarySmtpAddress = 'plain@contoso.com'; ExternalDirectoryObjectId = 'u9'; RecipientTypeDetails = 'RoomMailbox' } }
        function global:Get-OrganizationConfig { param($ErrorAction) [pscustomobject]@{ EwsEnabled = $false; EwsApplicationAccessPolicy = $null; EwsAllowList = $null; EwsBlockList = $null } }
        function global:Get-Recipient { param($Identity, $ErrorAction) if ($Identity -eq 'dub-rm2@contoso.com') { throw 'Server is busy, try again later (throttled)' }; [pscustomobject]@{ RecipientTypeDetails = 'RoomMailbox'; PrimarySmtpAddress = $Identity; IsDirSynced = $true } }
        function global:Get-CalendarProcessing { param($Identity, $ErrorAction) [pscustomobject]@{ AutomateProcessing = 'AutoAccept'; DeleteComments = $true; ProcessExternalMeetingMessages = $true; AllBookInPolicy = $true; BookInPolicy = $null; ResourceDelegates = $null } }
        function global:Get-MailboxRegionalConfiguration { param($Identity, $ErrorAction) [pscustomobject]@{ TimeZone = 'GMT Standard Time'; Language = 'en-GB' } }
        function global:Get-MailboxCalendarConfiguration { param($Identity, $ErrorAction) [pscustomobject]@{ WorkingHoursTimeZone = 'GMT Standard Time' } }
        function global:Get-CASMailbox { param($Identity, $ErrorAction) [pscustomobject]@{ EwsEnabled = $false; EwsApplicationAccessPolicy = $null } }
        function global:Get-Place { param($Identity, $ErrorAction) [pscustomobject]@{ City = 'London'; Floor = 2; Capacity = 6; MTREnabled = $true; Tags = $null; Localities = $null } }
        function global:Get-CsOnlineUser { param($Identity, $ErrorAction) [pscustomobject]@{ AccountEnabled = $true; AccountType = 'User'; TeamsUpgradeEffectiveMode = 'TeamsOnly'; FeatureTypes = $null; TeamsIPPhonePolicy = $null } }
        function global:Get-CsTeamsIPPhonePolicy { param($ErrorAction) [pscustomobject]@{ Identity = 'Global'; SignInMode = 'UserSignIn' }; [pscustomobject]@{ Identity = 'Tag:Rooms'; SignInMode = 'MeetingSignIn' } }

        $script:ctx2 = New-MtrContext -Parameters @{}
        $session = [pscustomobject]@{ Graph = 'InProcess'; Exchange = 'InProcess'; Teams = 'InProcess'; TenantId = 't1'; Upn = 'auditor@contoso.com'; SourceRoot = (Join-Path $root 'src'); Errors = @{} }
        Invoke-MtrCollection -Context $ctx2 -Session $session -Baseline $baseline -Sections @('Identity', 'Licensing', 'Exchange', 'Places', 'Teams') -SkipSignInLogs 6>$null 3>$null
    }
    AfterAll {
        foreach ($name in 'Get-Mailbox', 'Get-DistributionGroup', 'Get-DistributionGroupMember', 'Get-OrganizationConfig', 'Get-Recipient', 'Get-CalendarProcessing',
            'Get-MailboxRegionalConfiguration', 'Get-MailboxCalendarConfiguration', 'Get-CASMailbox', 'Get-Place', 'Get-CsOnlineUser', 'Get-CsTeamsIPPhonePolicy') {
            Remove-Item -Path "Function:\global:$name" -ErrorAction SilentlyContinue
        }
    }
    It 'collects room mailboxes, room lists and organization EWS state in one pass' {
        @($ctx2.Exchange.RoomMailboxes).Count | Should -Be 2
        @($ctx2.Exchange.RoomLists).Count | Should -Be 2
        @($ctx2.Exchange.RoomLists[0].Members).Count | Should -Be 2
        $ctx2.Exchange.OrganizationConfig.EwsEnabled | Should -BeFalse
        @(Find-NestedArray -Value $ctx2.Exchange) | Should -BeNullOrEmpty
    }
    It 'collects mailbox detail for enabled room accounts and Graph candidates, not for disabled rooms' {
        $ids = @($ctx2.Exchange.Candidates | ForEach-Object Identity)
        $ids | Should -Contain 'rm1@contoso.com'
        $ids | Should -Not -Contain 'plain@contoso.com'
        $c = $ctx2.Exchange.Candidates | Where-Object Identity -eq 'rm1@contoso.com'
        $c.CalendarProcessing.DeleteComments | Should -BeTrue
        @($c.CalendarProcessing.BookInPolicy).Count | Should -Be 0
        @($c.Errors) | Should -BeNullOrEmpty
    }
    It 'records a failed (not "not found") mailbox lookup in Coverage instead of raising a false finding' {
        $c = $ctx2.Exchange.Candidates | Where-Object Identity -eq 'dub-rm2@contoso.com'
        $c.Recipient | Should -BeNullOrEmpty
        ($c.Errors -join ' ') | Should -Match 'throttled'
        ($ctx2.Coverage | Where-Object Item -eq 'Per-mailbox lookups').Status | Should -Be 'Partial'
        $model = Resolve-MtrAccount -Context $ctx2 -Baseline $baseline
        $settings = [pscustomobject]@{ Now = $ctx2.Meta.CollectedAt; StaleDays = 30; OnPremMaxPasswordAgeDays = 0; SignInLookbackDays = 7; Sections = @('Exchange') }
        $exo = @(Test-MtrExchange -Model $model -Context $ctx2 -Baseline $baseline -Settings $settings)
        @($exo | Where-Object { $_.CheckId -eq 'EXO-01' -and ($_.AffectedObjects -join ' ') -match 'dub-rm2' }) | Should -BeNullOrEmpty
    }
    It 'does not turn missing Teams feature types into a false finding' {
        @($ctx2.Teams.Users[0].FeatureTypes).Count | Should -Be 0
        @($ctx2.Teams.IpPhonePolicies).Count | Should -Be 2
    }
}

Describe 'Separate-process (isolated) Exchange and Teams calls' {
    BeforeAll {
        # A copy of src plus a stub file that loads last and replaces the real connect/cmdlets.
        $script:isoRoot = Join-Path $TestDrive 'src'
        Copy-Item -Path (Join-Path $root 'src') -Destination $isoRoot -Recurse
        $stubDir = New-Item -ItemType Directory -Path (Join-Path $isoRoot 'zzTest')
        Set-Content -Path (Join-Path $stubDir 'Stubs.ps1') -Encoding utf8 -Value @'
function Connect-MtrExchange { param([string]$UserPrincipalName) Write-Warning 'stub banner'; Write-Host 'stub host line'; Write-Output 'stray stdout line' | Out-Host }
function Connect-MtrTeams { param([string]$TenantId, [string]$AccountId) throw 'stub Teams sign-in failure' }
function Disconnect-ExchangeOnline { param([switch]$Confirm, $ErrorAction) }
function Disconnect-MicrosoftTeams { param($ErrorAction) }
function Get-Mailbox { param($Identity, $RecipientTypeDetails, $ResultSize, $ErrorAction) [pscustomobject]@{ Identity = 'rm1'; UserPrincipalName = 'rm1@contoso.com'; PrimarySmtpAddress = 'rm1@contoso.com'; ExternalDirectoryObjectId = 'u1'; RecipientTypeDetails = 'RoomMailbox'; AccountDisabled = $false } }
function Get-DistributionGroup { param($RecipientTypeDetails, $ResultSize, $ErrorAction) }
function Get-OrganizationConfig { param($ErrorAction) [pscustomobject]@{ EwsEnabled = $true } }
function Get-CalendarProcessing { param($Identity, $ErrorAction) [pscustomobject]@{ AutomateProcessing = 'AutoAccept'; DeleteComments = $false } }
function Get-MailboxRegionalConfiguration { param($Identity, $ErrorAction) [pscustomobject]@{ TimeZone = 'GMT Standard Time' } }
function Get-MailboxCalendarConfiguration { param($Identity, $ErrorAction) [pscustomobject]@{ WorkingHoursTimeZone = 'GMT Standard Time' } }
function Get-CASMailbox { param($Identity, $ErrorAction) [pscustomobject]@{ EwsEnabled = $true } }
function Get-Place { param($Identity, $ErrorAction) [pscustomobject]@{ City = 'London'; MTREnabled = $true } }
'@
        $script:isoSession = [pscustomobject]@{ Graph = 'InProcess'; Exchange = 'Isolated'; Teams = 'Isolated'; TenantId = 't1'; Upn = 'auditor@contoso.com'; SourceRoot = $isoRoot; Errors = @{} }
    }
    It 'runs Exchange collection in a child process and returns its data' {
        $r = Invoke-MtrServiceCall -Service Exchange -FunctionName 'Get-MtrExchangeData' -Session $isoSession -Arguments @{ Identities = @('rm1@contoso.com') } 6>$null
        # the child's console output (warnings, banners) must not be returned as data
        @($r).Count | Should -Be 1
        $r | Should -BeOfType [System.Management.Automation.PSCustomObject]
        @($r.RoomMailboxes).Count | Should -Be 1
        @($r.Candidates).Count | Should -Be 1
        $r.Candidates[0].CalendarProcessing.AutomateProcessing | Should -Be 'AutoAccept'
        $r.OrganizationConfig.EwsEnabled | Should -BeTrue
    }
    It 'carries a child-process failure back with its message' {
        { Invoke-MtrServiceCall -Service Teams -FunctionName 'Get-MtrTeamsData' -Session $isoSession -Arguments @{ UserPrincipalNames = @('rm1@contoso.com') } 6>$null 3>$null } |
            Should -Throw '*stub Teams sign-in failure*'
    }
}
