#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
# Run with:  Invoke-Pester -Path .\tests -Output Detailed

BeforeAll {
    $script:root = Split-Path -Path $PSScriptRoot -Parent
    $script:MtrToolVersion = 'test'
    foreach ($file in Get-ChildItem -Path (Join-Path $root 'src') -Recurse -Filter '*.ps1' | Where-Object Name -ne 'Invoke-MtrIsolatedCall.ps1') { . $file.FullName }
    . (Join-Path $PSScriptRoot 'fixtures/SampleTenant.ps1')
    if (-not (Get-Command Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        # Stub so the Graph client can be mocked without the Graph module installed.
        function global:Invoke-MgGraphRequest { param($Uri, $Method, $Body, $Headers, $OutputType, $ContentType) }
    }
    $script:baseline = Import-PowerShellDataFile -Path (Join-Path $root 'config/MtrBaseline.psd1')

    function Invoke-SampleAudit {
        param([scriptblock]$Mutate, $Context)
        $ctx = if ($Context) { $Context } else { New-MtrSampleContext }
        if ($Mutate) { & $Mutate $ctx }
        $settings = [pscustomobject]@{ Now = ConvertTo-MtrDateTime $ctx.Meta.CollectedAt; StaleDays = 30; OnPremMaxPasswordAgeDays = 90; SignInLookbackDays = 7; Sections = @($ctx.Meta.Sections) }
        $model = Resolve-MtrAccount -Context $ctx -Baseline $baseline
        $findings = foreach ($fn in 'Test-MtrDiscovery', 'Test-MtrLicensing', 'Test-MtrIdentity', 'Test-MtrConditionalAccess', 'Test-MtrGroups', 'Test-MtrExchange', 'Test-MtrPlaces', 'Test-MtrTeams', 'Test-MtrIntune') {
            & $fn -Model $model -Context $ctx -Baseline $baseline -Settings $settings
        }
        [pscustomobject]@{ Context = $ctx; Model = $model; Findings = @($findings | Where-Object { $_ }) }
    }
    function Get-Finding { param($Result, [string]$CheckId, [string]$TitleLike = '*') @($Result.Findings | Where-Object { $_.CheckId -eq $CheckId -and $_.Title -like $TitleLike }) }

    $script:sample = Invoke-SampleAudit
}

Describe 'Helpers' {
    It 'Get-MtrArray drops nulls and keeps an empty array for $null' {
        (Get-MtrArray $null).Count | Should -Be 0
        (Get-MtrArray @(1, $null, 2)).Count | Should -Be 2
        Get-MtrCount $null | Should -Be 0
    }
    It 'parses Teams Rooms and Windows version strings' {
        ConvertTo-MtrVersion '1449/1.0.96.2026129709' | Should -Be ([version]'1.0.96.2026129709')
        ConvertTo-MtrVersion '10.0.26100.8655' | Should -Be ([version]'10.0.26100.8655')
        ConvertTo-MtrVersion '14' | Should -Be ([version]'14.0')
        ConvertTo-MtrVersion 'n/a' | Should -BeNullOrEmpty
    }
    It 'parses dates null-safely' {
        ConvertTo-MtrDateTime $null | Should -BeNullOrEmpty
        ConvertTo-MtrDateTime '' | Should -BeNullOrEmpty
        (ConvertTo-MtrDateTime '2026-09-28T10:00:00Z').Hour | Should -Be 10
    }
    It 'reduces an Intune error (JSON inside the Graph message) to one readable line' {
        $raw = "ResourceNotFound: {`n  `"_version`": 3,`n  `"Message`": `"An error has occurred - Operation ID (for customer support): 0000 - Activity ID: c0c0 - Url: https://proxy.example/DeviceFE/users('x')/managedDevices?a=1`",`n  `"RetryAfter`": null`n}"
        Format-MtrErrorText $raw | Should -Be 'ResourceNotFound: An error has occurred - Operation ID (for customer support): 0000 - Activity ID: c0c0'
        (Format-MtrErrorText ('x' * 500)).Length | Should -Be 303
    }
    It 'ignores statuses that mean "nothing there" when recording batch coverage' {
        $ctx = New-MtrContext -Parameters @{}
        $responses = @{ a = [pscustomobject]@{ Status = 404; Error = 'ResourceNotFound' }; b = [pscustomobject]@{ Status = 200 } }
        Add-MtrBatchCoverage -Context $ctx -Section 'Intune' -Item 'x' -Responses $responses -IgnoreStatus 404
        @($ctx.Coverage).Count | Should -Be 0
        Add-MtrBatchCoverage -Context $ctx -Section 'Intune' -Item 'x' -Responses $responses
        ($ctx.Coverage | Select-Object -Last 1).Status | Should -Be 'Partial'
    }
}

Describe 'Discovery without naming conventions' {
    It 'classifies rooms from licenses, devices and mailbox signals' {
        $byUpn = @{}; foreach ($a in $sample.Model.Accounts) { $byUpn[$a.UserPrincipalName] = $a }
        $byUpn['nyc.conf.4a@contoso.com'].Classification | Should -Be 'Confirmed'
        $byUpn['meetingroom7@contoso.com'].Classification | Should -Be 'Confirmed'   # E3 + Logitech device, no room mailbox
        $byUpn['oldroom@contoso.com'].Classification | Should -Be 'Inconsistent'    # enabled room account, nothing else
        @($sample.Model.MtrAccounts).Count | Should -Be 6
    }
    It 'maps a Windows room with no Intune primary user through its sign-in device ID' {
        $a = $sample.Model.Accounts | Where-Object UserPrincipalName -eq 'lon-rm102@contoso.com'
        @($a.Devices | ForEach-Object Name) | Should -Contain 'LON-MTR-102'
    }
    It 'recognises the existing Teams Rooms group by membership ratio' {
        $g = $sample.Model.Groups | Where-Object Id -eq 'g-rooms'
        $g.IsMtrLike | Should -BeTrue
        ($sample.Model.Groups | Where-Object Id -eq 'g-staff').IsMtrLike | Should -BeFalse
    }
    It 'reports the mixed naming prefixes' {
        (Get-Finding $sample 'DISC-02').Count | Should -Be 1
    }
    It 'flags an enabled room account with no Teams Rooms use' {
        (Get-Finding $sample 'DISC-03').AffectedObjects | Should -Contain 'oldroom@contoso.com'
    }
    It 'still flags enabled room accounts when no Teams Rooms were identified' {
        $r = Invoke-SampleAudit -Mutate {
            param($c)
            $c.Identity.Users = @($c.Identity.Users | Where-Object { $_.User.userPrincipalName -eq 'oldroom@contoso.com' })
            $c.Identity.Candidates = @($c.Identity.Candidates | Where-Object { $_.Id -in @($c.Identity.Users.Id) })
        }
        (Get-Finding $r 'DISC-00').Detail | Should -Match 'Inconsistent: 1'
        (Get-Finding $r 'DISC-03').AffectedObjects | Should -Be @('oldroom@contoso.com')
    }
}

Describe 'Conditional Access' {
    It 'MFA for all users is Critical for Windows rooms and High for Android rooms' {
        (Get-Finding $sample 'CA-03' "*Require MFA for all users*Windows*").Severity | Should -Be 'Critical'
        (Get-Finding $sample 'CA-03' "*Require MFA for all users*Android*").Severity | Should -Be 'High'
    }
    It 'excluding the rooms group from the MFA policy clears the MFA finding' {
        $r = Invoke-SampleAudit -Mutate { param($c) ($c.ConditionalAccess.Policies | Where-Object id -eq 'ca-mfa').conditions.users = [pscustomobject]@{ includeUsers = @('All'); excludeUsers = @('u-nyc4a', 'u-mr7'); includeGroups = @(); excludeGroups = @('g-rooms'); includeRoles = @(); excludeRoles = @() } }
        (Get-Finding $r 'CA-03' "*Require MFA for all users*").Count | Should -Be 0
    }
    It 'MFA OR compliant device is only Low' {
        $r = Invoke-SampleAudit -Mutate { param($c) ($c.ConditionalAccess.Policies | Where-Object id -eq 'ca-mfa').grantControls = [pscustomobject]@{ operator = 'OR'; builtInControls = @('mfa', 'compliantDevice') } }
        @(Get-Finding $r 'CA-03' "*Require MFA for all users*" | ForEach-Object Severity) | Should -Be @('Low')
    }
    It 'flags blocking device code flow for Android rooms' {
        (Get-Finding $sample 'CA-04').Count | Should -Be 1
    }
    It 'lowers severity for report-only policies' {
        $f = Get-Finding $sample 'CA-07' '(Report-only)*Sign-in frequency*'
        $f.Severity | Should -Be 'Medium'
    }
    It 'ignores legacy-auth-only block policies' {
        @($sample.Findings | Where-Object Title -like "*Block legacy auth*").Count | Should -Be 0
    }
    It 'flags Basic-licensed rooms and rooms with Intune disabled under a compliance requirement' {
        $f = Get-Finding $sample 'CA-11'
        $f.AffectedObjects | Should -Contain 'boardroom@contoso.com (Basic)'
        ($f.AffectedObjects -join ' ') | Should -Match 'lon-rm103.*Intune service plan disabled'
    }
    It 'reports a missing dedicated policy' {
        $r = Invoke-SampleAudit -Mutate { param($c) $c.ConditionalAccess.Policies = @($c.ConditionalAccess.Policies | Where-Object id -ne 'ca-mtr') }
        (Get-Finding $r 'CA-01').Severity | Should -Be 'High'
    }
    It 'builds exclusion commands with the merged group list and no internal helpers' {
        $cmd = (Get-Finding $sample 'CA-10').RemediationCommand -join "`n"
        $cmd | Should -Match "excludeGroups = @\('g-rooms'\)"
        $cmd | Should -Not -Match 'Get-Mtr'
    }
}

Describe 'Groups' {
    It 'flags a person inside the Teams Rooms group' {
        (Get-Finding $sample 'GRP-04').AffectedObjects | Should -Contain 'jane.doe@contoso.com'
    }
    It 'flags a name-based dynamic rule' {
        (Get-Finding $sample 'GRP-03' "*selects rooms by name*").Count | Should -Be 1
    }
    It 'suggests a license rule built from the tenant''s Teams Rooms service plans' {
        $rules = Get-MtrSuggestedGroupRule -Model $sample.Model -Context $sample.Context -Baseline $baseline
        $rules.LicenseRule | Should -Match 'ecc74eae-eeb7-4ad5-9c88-e8b2bfca75b8'   # MTRProManagement
        $rules.LicenseRule | Should -Not -Match '57ff2da0-773e-42df-b2af-ffb7a2317929'   # TEAMS1 is shared with E3
        $rules.AndroidDeviceRule | Should -Match 'AOSP - Teams Devices'
    }
    It 'detects an extensionAttribute shared by the rooms' {
        $ctx = New-MtrSampleContext
        foreach ($u in $ctx.Identity.Users) { $u.User.onPremisesExtensionAttributes = [pscustomobject]@{ extensionAttribute10 = 'TeamsRoom' } }
        $r = Invoke-SampleAudit -Context $ctx
        (Get-MtrSuggestedGroupRule -Model $r.Model -Context $r.Context -Baseline $baseline).AttributeCandidate.Attribute | Should -Be 'extensionAttribute10'
    }
}

Describe 'Identity' {
    It 'cloud password expiry past due is Critical' {
        $f = Get-Finding $sample 'ID-03'
        $f.Severity | Should -Be 'Critical'
        ($f.AffectedObjects -join ' ') | Should -Match 'meetingroom7.*expired'
    }
    It 'synced accounts get an on-prem verification with AD commands, escalated by password age' {
        $f = Get-Finding $sample 'ID-04'
        $f.Severity | Should -Be 'High'
        $f.FixLocation | Should -Be 'On-prem AD'
        ($f.VerifyCommand -join ' ') | Should -Match 'Get-ADUser'
    }
    It 'security defaults are Critical' {
        $r = Invoke-SampleAudit -Mutate { param($c) $c.Identity.Extra.SecurityDefaults = [pscustomobject]@{ isEnabled = $true } }
        (Get-Finding $r 'ID-14').Severity | Should -Be 'Critical'
    }
    It 'security defaults are Medium while no Teams Rooms are identified' {
        $r = Invoke-SampleAudit -Mutate { param($c) $c.Identity.Users = @(); $c.Identity.Candidates = @(); $c.Identity.Extra.SecurityDefaults = [pscustomobject]@{ isEnabled = $true } }
        (Get-Finding $r 'ID-14').Severity | Should -Be 'Medium'
        (Get-Finding $r 'ID-14').Detail | Should -Match 'DISC-00'
    }
    It 'flags MFA methods registered on room accounts' {
        ((Get-Finding $sample 'ID-08').AffectedObjects -join ' ') | Should -Match 'nyc\.conf\.4a.*phone'
    }
    It 'surfaces the CA policy that fails room sign-ins' {
        (Get-Finding $sample 'ID-13' "*Require MFA for all users*").Count | Should -Be 1
    }
    It 'requires Pro for password-less migration' {
        $a = $sample.Model.Accounts | Where-Object UserPrincipalName -eq 'boardroom@contoso.com'
        (Get-MtrPasswordlessReadiness -Account $a -Baseline $baseline).Status | Should -Be 'Not ready'
    }
}

Describe 'Exchange and Room Finder' {
    It 'DeleteComments and ProcessExternalMeetingMessages deviations are High' {
        (Get-Finding $sample 'EXO-03' '*DeleteComments*').Severity | Should -Be 'High'
        (Get-Finding $sample 'EXO-03' '*ProcessExternalMeetingMessages*').Severity | Should -Be 'High'
    }
    It 'finds the Pacific time zone outlier in its room list' {
        ((Get-Finding $sample 'EXO-06').AffectedObjects -join ' ') | Should -Match 'lon-rm102.*Pacific'
    }
    It 'names the existing room lists and gives a membership command for rooms outside every list' {
        $f = Get-Finding $sample 'RF-01'
        $f.Detail | Should -Match 'Existing room lists: London HQ'
        $f.RemediationCommand | Should -Contain "Add-DistributionGroupMember -Identity '<room list>' -Member 'oldroom@contoso.com'"
    }
    It 'flags a room in two room lists and a list that mixes cities' {
        (Get-Finding $sample 'RF-02').Count | Should -Be 1
        (Get-Finding $sample 'RF-04' "*London HQ*").Count | Should -Be 1
    }
    It 'flags Teams Rooms not marked MTREnabled' {
        (Get-Finding $sample 'RF-06').AffectedObjects | Should -Contain 'nyc.conf.4a@contoso.com'
    }
    It 'points City fixes for synced rooms on-prem' {
        (Get-Finding $sample 'RF-05' '*no City*').FixLocation | Should -Be 'On-prem Exchange'
    }
    It 'warns about EWS retirement for Android rooms below the required app build' {
        (Get-Finding $sample 'EXO-09').Count | Should -Be 1
    }
}

Describe 'Intune' {
    It 'Teams AOSP token expiring within 90 days is High, expired is Critical' {
        (Get-Finding $sample 'AND-02').Severity | Should -Be 'High'
        $r = Invoke-SampleAudit -Mutate { param($c) $c.Intune.EnrollmentProfiles[0].tokenExpirationDateTime = '2026-09-01T00:00:00Z' }
        (Get-Finding $r 'AND-02').Severity | Should -Be 'Critical'
    }
    It 'flags Device Administrator enrollment and an AOSP OS minimum above the fleet' {
        (Get-Finding $sample 'AND-03').AffectedObjects[0] | Should -Match 'NYC-4A'
        ((Get-Finding $sample 'AND-05').AffectedObjects -join ' ') | Should -Match 'Rally Bar, Android 10'
    }
    It 'flags hybrid join, unsupported Windows compliance settings and All-devices policies' {
        (Get-Finding $sample 'WIN-01').Count | Should -Be 1
        (Get-Finding $sample 'WIN-03').Detail | Should -Match 'Require a password'
        ((Get-Finding $sample 'WIN-04').AffectedObjects -join ' ') | Should -Match 'Edge and OneDrive'
        ((Get-Finding $sample 'WIN-04').AffectedObjects -join ' ') | Should -Not -Match 'iOS'
    }
    It 'flags an Autopilot tag without the MTR- prefix' {
        ((Get-Finding $sample 'WIN-02' '*does not start*').AffectedObjects -join ' ') | Should -Match 'BOARD-MTR'
    }
}

Describe 'Robustness' {
    It 'runs when optional sections were not collected' {
        $r = Invoke-SampleAudit -Mutate { param($c) $c.Intune = $null; $c.Teams = $null; $c.Places = $null; $c.ConditionalAccess = $null; $c.Identity.Extra = $null }
        $r.Findings.Count | Should -BeGreaterThan 0
    }
    It 'runs with no candidate accounts at all' {
        $r = Invoke-SampleAudit -Mutate { param($c) $c.Identity.Users = @(); $c.Identity.Candidates = @() }
        (Get-Finding $r 'DISC-00').Count | Should -Be 1
    }
}

Describe 'Snapshot' {
    It 'produces identical findings after a JSON round trip' {
        $path = Join-Path $TestDrive 'Snapshot.json'
        Export-MtrSnapshot -Context (New-MtrSampleContext) -Path $path
        $reloaded = Invoke-SampleAudit -Context (Import-MtrSnapshot -Path $path)
        $key = { param($f) '{0}|{1}|{2}|{3}' -f $f.CheckId, $f.Severity, $f.Title, (@($f.AffectedObjects) -join ',') }
        $before = @($sample.Findings | ForEach-Object { & $key $_ } | Sort-Object)
        $after = @($reloaded.Findings | ForEach-Object { & $key $_ } | Sort-Object)
        $after | Should -Be $before
    }
    It 'runs end to end from a snapshot and keeps findings off the default console view' {
        $path = Join-Path $TestDrive 'E2E.json'
        Export-MtrSnapshot -Context (New-MtrSampleContext) -Path $path
        $out = Join-Path $TestDrive 'e2e-out'
        $result = & (Join-Path $root 'Invoke-MtrTenantAudit.ps1') -FromSnapshot $path -OutputPath $out 6>$null 3>$null
        $result.TeamsRooms | Should -Be 6
        @($result.Findings).Count | Should -BeGreaterThan 10
        ($result | Out-String) | Should -Not -Match 'Findings|CheckId'
        foreach ($file in 'Report.html', 'Findings.csv', 'Rooms.csv', 'Remediation-Plan.ps1') { Join-Path $out $file | Should -Exist }
    }
    It 'never persists enrollment tokens or script content' {
        $ctx = New-MtrSampleContext
        $ctx.Intune.EnrollmentProfiles[0] | Add-Member -NotePropertyName tokenValue -NotePropertyValue 'SECRET-TOKEN'
        $ctx.Intune.EnrollmentProfiles[0] | Add-Member -NotePropertyName qrCodeContent -NotePropertyValue 'SECRET-QR'
        $path = Join-Path $TestDrive 'Secret.json'
        Export-MtrSnapshot -Context $ctx -Path $path
        (Get-Content $path -Raw) | Should -Not -Match 'SECRET-'
    }
}

Describe 'Read-only guarantees' {
    BeforeAll {
        $script:sourceFiles = @(Get-ChildItem -Path (Join-Path $root 'src') -Recurse -Filter '*.ps1') + @(Get-Item (Join-Path $root 'Invoke-MtrTenantAudit.ps1'))
        $script:commands = foreach ($file in $sourceFiles) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                [pscustomobject]@{ File = $file.Name; Line = $c.Extent.StartLineNumber; Name = $c.GetCommandName(); Ast = $c }
            }
        }
    }
    It 'contains no state-changing commands outside the local allow-list' {
        $writeVerbs = '^(Set|New|Remove|Update|Add|Grant|Revoke|Enable|Disable|Clear|Reset|Restore|Move|Rename|Register|Unregister|Install|Uninstall|Send|Publish|Invoke|Start|Stop|Restart|Suspend|Resume|Approve|Deny|Block|Unblock|Lock|Unlock|Sync|Push|Import|Initialize|Submit)-'
        $localAllowed = @('New-Object', 'New-Item', 'Add-Member', 'Set-Content', 'Import-Module', 'Import-Csv', 'Import-PowerShellDataFile', 'Start-Sleep')
        $violations = @($commands | Where-Object {
                $_.Name -and $_.Name -match $writeVerbs -and $_.Name -notmatch '-Mtr' -and $_.Name -notin $localAllowed -and
                -not ($_.Name -eq 'Remove-Item' -and $_.File -eq 'Connection.ps1') -and
                -not ($_.Name -eq 'Invoke-MgGraphRequest' -and $_.File -eq 'GraphClient.ps1')
            } | ForEach-Object { '{0}:{1} {2}' -f $_.File, $_.Line, $_.Name })
        $violations | Should -BeNullOrEmpty
    }
    It 'only calls Get-* Exchange and Teams cmdlets' {
        $service = @($commands | Where-Object { $_.Name -cmatch '-(EXO|Cs[A-Z]|Mailbox|CalendarProcessing|Place|DistributionGroup|Recipient|OrganizationConfig|CASMailbox|Mg[A-Z])' -and $_.Name -notmatch '-Mtr' })
        $bad = @($service | Where-Object { $_.Name -notmatch '^(Get|Connect|Disconnect)-' -and $_.Name -ne 'Invoke-MgGraphRequest' } | ForEach-Object { '{0}:{1} {2}' -f $_.File, $_.Line, $_.Name })
        $bad | Should -BeNullOrEmpty
    }
    It 'loads only Get-* cmdlets into the Exchange session' {
        $script:MtrExoCommands | Should -Not -BeNullOrEmpty
        @($script:MtrExoCommands | Where-Object { $_ -notlike 'Get-*' }) | Should -BeNullOrEmpty
    }
    It 'requests only read Graph scopes' {
        @($script:MtrGraphScopes | Where-Object { $_ -notmatch '\.Read(\.|$)' }) | Should -BeNullOrEmpty
    }
    It 'never calls web endpoints other than through the Graph client' {
        @($commands | Where-Object { $_.Name -in 'Invoke-RestMethod', 'Invoke-WebRequest', 'irm', 'iwr', 'curl', 'wget' }) | Should -BeNullOrEmpty
    }
    It 'refuses non-batch POST and non-GET methods' {
        Mock Invoke-MgGraphRequest { @{ } }
        { Invoke-MtrGraphRequestWithRetry -Uri 'v1.0/users' -Method POST -Body '{}' } | Should -Throw '*Read-only guard*'
        { Invoke-MtrGraphRequestWithRetry -Uri 'v1.0/users' -Method PATCH } | Should -Throw
        Should -Invoke Invoke-MgGraphRequest -Times 0
    }
    It 'sends batches as GET-only requests' {
        Mock Invoke-MgGraphRequest { [pscustomobject]@{ responses = @([pscustomobject]@{ id = 'a'; status = 200; body = [pscustomobject]@{ id = 'a' } }) } }
        $null = Invoke-MtrGraphBatch -Requests @([pscustomobject]@{ Id = 'a'; Url = '/users/a' })
        Should -Invoke Invoke-MgGraphRequest -Times 1 -ParameterFilter { $Method -eq 'POST' -and $Uri -like '*/$batch' -and ($Body | ConvertFrom-Json).requests.method -eq 'GET' }
    }
    It 'generated remediation text never references the tool''s internal helpers' {
        $text = @($sample.Findings | ForEach-Object { $_.RemediationCommand; $_.VerifyCommand }) -join "`n"
        $text | Should -Not -Match 'Get-Mtr(Array|Count)'
    }
    It 'keeps tenant text with line breaks inside comments in Remediation-Plan.ps1' {
        $evil = New-MtrFinding -CheckId 'X-01' -Severity High -Category 'Test' -Title "Room`nWrite-Output INJECTED-TITLE" -FixLocation 'Entra ID' `
            -AffectedObjects @("name`r`nWrite-Output INJECTED-OBJECT") -RemediationCommand @("Set-Place -Identity 'x'`nWrite-Output INJECTED-COMMAND")
        $path = Join-Path $TestDrive 'Evil-Plan.ps1'
        New-MtrRemediationPlan -Findings @($evil) -Context $sample.Context -Path $path
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        $ast.EndBlock.Statements.Count | Should -Be 1
        (Get-Content $path -Raw) | Should -Match '# \[High\] X-01 - Room Write-Output INJECTED-TITLE'
    }
    It 'Remediation-Plan.ps1 contains no executable statement except the guard throw' {
        $path = Join-Path $TestDrive 'Remediation-Plan.ps1'
        New-MtrRemediationPlan -Findings $sample.Findings -Context $sample.Context -Path $path
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
        $errors | Should -BeNullOrEmpty
        $ast.EndBlock.Statements.Count | Should -Be 1
        $ast.EndBlock.Statements[0].Extent.Text | Should -Match '^throw '
    }
}
