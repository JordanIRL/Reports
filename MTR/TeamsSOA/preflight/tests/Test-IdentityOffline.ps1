#requires -Version 7.2
<# Offline only. Run in a fresh pwsh -NoProfile process. A temporary fake Graph
module supplies fixture responses; Connect/Disconnect are sentinels, never live. #>
[CmdletBinding()]
param([string]$ScriptPath = (Join-Path $PSScriptRoot '../scripts/Test-RoomIdentity.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('teamssoa-identity-fixture-' + [guid]::NewGuid())
$oldModulePath = $env:PSModulePath
$passed = 0; $failed = 0; $requestCount = 0
$failures = [System.Collections.Generic.List[string]]::new()
function Assert-True([bool]$Condition,[string]$Message) { if (-not $Condition) { throw $Message } }
function Test-Case([string]$Name,[scriptblock]$Body) {
    try {
        & $Body
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Method -ne 'GET').Count -eq 0) 'A mutation request was attempted.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object { ([uri]$_.Uri).Host -ne 'graph.microsoft.com' }).Count -eq 0) 'An external Graph request was attempted.'
        $script:passed++; Write-Host "PASS $Name"
    }
    catch { $script:failed++; $failures.Add("$Name : $($_.Exception.Message)"); Write-Host "FAIL $Name : $($_.Exception.Message)" -ForegroundColor Red }
    finally { $script:requestCount += $global:IdentityFixture.Calls.Count }
}
function New-Fixture {
    $global:IdentityFixture = [ordered]@{
        TenantId='11111111-1111-4111-8111-111111111111'
        UserId='22222222-2222-4222-8222-222222222222'
        GroupId='33333333-3333-4333-8333-333333333333'
        GroupId2='44444444-4444-4444-8444-444444444444'
        RoomListId='55555555-5555-4555-8555-555555555555'
        ContextMode='Correct'
        Scopes=@('User.Read.All','Group.Read.All','Domain.Read.All')
        AccountEnabled=$true
        SyncEnabled=$true
        LicencesFail=$false
        MembershipMode='Normal'
        MissingGroupMetadata=$false
        GroupSyncNull=$false
        DynamicRule=$false
        DynamicMissingRule=$false
        CloudManaged=$true
        Calls=[System.Collections.Generic.List[object]]::new()
    }
}
function Invoke-Fixture([hashtable]$More=@{}) {
    $args=@{ TenantId=$global:IdentityFixture.TenantId; UseExistingConnection=$true; PasswordlessMigrationConfirmed=$true; Ascii=$true; PassThru=$true }
    foreach ($key in $More.Keys) { $args[$key]=$More[$key] }
    @(& $ScriptPath @args 6>$null)
}
function Has-Result([object[]]$Rows,[string]$Name,[string]$Status) { @($Rows | Where-Object { $_.Name -like $Name -and $_.Status -eq $Status }).Count -gt 0 }
function Get-Issues([object[]]$Rows) { ($Rows | Where-Object { $_.Status -in @('Action','Unknown') } | ForEach-Object { $_.Name+': '+$_.Detail }) -join ' | ' }

try {
    $moduleRoot = Join-Path $testRoot 'Microsoft.Graph.Authentication/99.0.0'
    New-Item -Path $moduleRoot -ItemType Directory -Force | Out-Null
    $moduleSource = @'
Set-StrictMode -Version Latest
function Connect-MgGraph { [CmdletBinding()]param([string]$TenantId,[string[]]$Scopes,[string]$Environment,[string]$ContextScope,[switch]$NoWelcome) throw 'TEST SENTINEL: No live connection may be attempted.' }
function Disconnect-MgGraph { [CmdletBinding()]param() throw 'TEST SENTINEL: A reused Graph context may not be disconnected.' }
function Get-MgContext {
    [CmdletBinding()]param()
    if ($global:IdentityFixture.ContextMode -eq 'None') { return $null }
    $id = if ($global:IdentityFixture.ContextMode -eq 'WrongTenant') { '99999999-9999-4999-8999-999999999999' } elseif ($global:IdentityFixture.ContextMode -eq 'MissingTenant') { $null } else { $global:IdentityFixture.TenantId }
    [pscustomobject]@{ TenantId=$id; AuthType='Delegated'; Environment='Global'; Scopes=$global:IdentityFixture.Scopes }
}
function New-Member([string]$Id) { [pscustomobject]@{ '@odata.type'='#microsoft.graph.group'; id=$Id; displayName='Fixture group' } }
function New-Group([string]$Id) {
    if ($global:IdentityFixture.MissingGroupMetadata) { return [pscustomobject]@{ id=$Id; displayName='Fixture scoped group' } }
    $sync = if ($global:IdentityFixture.GroupSyncNull) { $null } else { $false }
    [pscustomobject]@{ id=$Id; displayName='Fixture group'; onPremisesSyncEnabled=$sync; groupTypes=@(); mailEnabled=$false; securityEnabled=$true; membershipRule=$null; visibility='Private' }
}
function Invoke-MgGraphRequest {
    [CmdletBinding()]param([string]$Method,[string]$Uri,[hashtable]$Headers,[string]$OutputType)
    $global:IdentityFixture.Calls.Add([pscustomobject]@{ Method=$Method; Uri=$Uri })
    if ($Method -ne 'GET') { throw 'TEST SENTINEL: Mutation attempted.' }
    $parsed = [uri]$Uri
    if ($parsed.Host -ne 'graph.microsoft.com') { throw 'TEST SENTINEL: External host attempted.' }
    $path=$parsed.AbsolutePath
    if ($path -eq '/beta/users/mtr%40meetingrooms.ie' -or $path -eq '/beta/users/mtr@meetingrooms.ie') {
        return [pscustomobject]@{ id=$global:IdentityFixture.UserId; displayName='Fixture Android Room'; userPrincipalName='mtr@meetingrooms.ie'; mail='mtr@meetingrooms.ie'; accountEnabled=$global:IdentityFixture.AccountEnabled; onPremisesSyncEnabled=$global:IdentityFixture.SyncEnabled; onPremisesImmutableId='fixture-anchor'; onPremisesLastSyncDateTime='2026-10-06T08:00:00Z'; assignedLicenses=@([pscustomobject]@{skuId='66666666-6666-4666-8666-666666666666';disabledPlans=@()}) }
    }
    if ($path.EndsWith('/licenseDetails')) {
        if ($global:IdentityFixture.LicencesFail) { throw 'Fixture license RBAC/throttle failure.' }
        return [pscustomobject]@{ value=@([pscustomobject]@{ skuId='66666666-6666-4666-8666-666666666666'; skuPartNumber='Microsoft_Teams_Rooms_Pro'; servicePlans=@([pscustomobject]@{ servicePlanId='77777777-7777-4777-8777-777777777777'; servicePlanName='TEAMS1'; provisioningStatus='Success'; appliesTo='User' }) }) }
    }
    if ($path.EndsWith('/transitiveMemberOf')) {
        $page=[ordered]@{ value=@((New-Member $global:IdentityFixture.GroupId)) }
        switch ($global:IdentityFixture.MembershipMode) {
            'TwoPages' { $page['@odata.nextLink']='https://graph.microsoft.com/beta/fixture/membership-page2' }
            'Repeated' { $page['@odata.nextLink']='https://graph.microsoft.com/beta/fixture/membership-page2' }
            'External' { $page['@odata.nextLink']='https://untrusted.invalid/beta/fixture/membership-page2' }
            'MissingValue' { $page.Remove('value') }
            'MissingType' { $page.value=@([pscustomobject]@{id=$global:IdentityFixture.GroupId;displayName='Fixture limited group'}) }
            'ScalarValue' { $page.value='not-a-collection' }
            'DictionaryValue' { $page.value=@{id=$global:IdentityFixture.GroupId} }
            'NullEntry' { $page.value=@($null) }
        }
        return [pscustomobject]$page
    }
    if ($path -eq '/beta/fixture/membership-page2') {
        $page=[ordered]@{value=@((New-Member $global:IdentityFixture.GroupId2))}
        if ($global:IdentityFixture.MembershipMode -eq 'Repeated') { $page['@odata.nextLink']=$Uri }
        return [pscustomobject]$page
    }
    if ($path -eq ('/beta/groups/'+$global:IdentityFixture.GroupId)) { return New-Group $global:IdentityFixture.GroupId }
    if ($path -eq ('/beta/groups/'+$global:IdentityFixture.GroupId2)) { return New-Group $global:IdentityFixture.GroupId2 }
    if ($path -eq '/beta/groups') {
        $groups=@()
        if ($global:IdentityFixture.DynamicRule) { $groups=@([pscustomobject]@{id='88888888-8888-4888-8888-888888888888';displayName='Fixture synced licensing';membershipRule='(user.dirSyncEnabled -eq true)';membershipRuleProcessingState='On'}) }
        if ($global:IdentityFixture.DynamicMissingRule) { $groups=@([pscustomobject]@{id='88888888-8888-4888-8888-888888888888';displayName='Fixture restricted dynamic group';membershipRuleProcessingState='On'}) }
        return [pscustomobject]@{value=$groups}
    }
    if ($path -eq '/beta/domains/meetingrooms.ie') { return [pscustomobject]@{id='meetingrooms.ie';isVerified=$true;authenticationType='Managed'} }
    if ($path.EndsWith('/onPremisesSyncBehavior')) { return [pscustomobject]@{isCloudManaged=$global:IdentityFixture.CloudManaged} }
    if ($path -eq '/beta/directory/onPremisesSynchronization') { return [pscustomobject]@{value=@([pscustomobject]@{id='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';features=[pscustomobject]@{blockCloudObjectTakeoverThroughHardMatchEnabled=$true}})} }
    throw ('TEST SENTINEL: Unexpected endpoint: '+$Uri)
}
Export-ModuleMember -Function *
'@
    Set-Content -LiteralPath (Join-Path $moduleRoot 'Microsoft.Graph.Authentication.psm1') -Value $moduleSource -Encoding utf8
    New-ModuleManifest -Path (Join-Path $moduleRoot 'Microsoft.Graph.Authentication.psd1') -RootModule 'Microsoft.Graph.Authentication.psm1' -ModuleVersion '99.0.0' -FunctionsToExport '*' -PowerShellVersion '7.2'
    $env:PSModulePath = $testRoot + [IO.Path]::PathSeparator + $oldModulePath
    $baselinePath=Join-Path $testRoot 'identity-before.json'

    Test-Case 'Managed-domain passwordless baseline needs no PHS/PTA query' {
        New-Fixture
        $rows=Invoke-Fixture @{ExportPath=$baselinePath}
        Assert-True (Has-Result $rows 'Tenant and access mode' 'Pass') ('Connection failed. '+(Get-Issues $rows))
        Assert-True (Has-Result $rows 'Account enabled' 'Pass') 'Enabled account did not pass.'
        Assert-True (Has-Result $rows 'Domain' 'Pass') 'Managed domain did not pass.'
        Assert-True (Has-Result $rows 'Room licence assignment' 'Pass') 'Rooms Pro licence was not recognized.'
        Assert-True (Has-Result $rows 'Teams service provisioning' 'Pass') 'TEAMS1 successful plan was not recognized.'
        Assert-True (Has-Result $rows 'AD-managed references' 'Pass') 'Complete cloud group metadata did not pass.'
        Assert-True (Test-Path -LiteralPath $baselinePath) 'Before baseline was not written.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Uri -match 'password|authenticationMethod|passThrough').Count -eq 0) 'Irrelevant password-path requests were made.'
    }
    Test-Case 'Disabled room account is Action' {
        New-Fixture; $global:IdentityFixture.AccountEnabled=$false
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Account enabled' 'Action') 'Disabled room passed.'
    }
    Test-Case 'Null room accountEnabled is Unknown' {
        New-Fixture; $global:IdentityFixture.AccountEnabled=$null
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Account enabled' 'Unknown') 'Null room enabled state passed.'
    }
    Test-Case 'String True synchronization metadata is Unknown' {
        New-Fixture; $global:IdentityFixture.SyncEnabled='True'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Synchronization state' 'Unknown') 'String True sync state was accepted as Boolean true.'
        Assert-True (-not (Has-Result $rows 'Synchronization state' 'Pass')) 'String synchronization value produced false Pass.'
    }
    Test-Case 'No existing context blocks reads' {
        New-Fixture; $global:IdentityFixture.ContextMode='None'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Collector incomplete' 'Unknown') 'Missing context not detected.'
        Assert-True ($global:IdentityFixture.Calls.Count -eq 0) 'Reads ran without a context.'
    }
    Test-Case 'Wrong tenant blocks reads' {
        New-Fixture; $global:IdentityFixture.ContextMode='WrongTenant'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Collector incomplete' 'Unknown') 'Wrong tenant not detected.'
        Assert-True ($global:IdentityFixture.Calls.Count -eq 0) 'Reads ran against wrong tenant.'
    }
    Test-Case 'Missing context tenant ID blocks reads' {
        New-Fixture; $global:IdentityFixture.ContextMode='MissingTenant'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Collector incomplete' 'Unknown') 'Missing tenant not detected.'
        Assert-True ($global:IdentityFixture.Calls.Count -eq 0) 'Reads ran with missing tenant binding.'
    }
    Test-Case 'Membership pagination reads both pages' {
        New-Fixture; $global:IdentityFixture.MembershipMode='TwoPages'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Visible membership read' 'Pass') ('Complete two-page membership did not pass. '+(Get-Issues $rows))
        Assert-True (@($rows | Where-Object { $_.Name -eq 'Visible membership read' -and $_.Detail -like '2 objects across 2 pages*' }).Count -eq 1) 'Both pages not represented in CLI.'
    }
    Test-Case 'Page limit preserves partial membership as Unknown' {
        New-Fixture; $global:IdentityFixture.MembershipMode='TwoPages'
        $rows=Invoke-Fixture @{MaxPages=1}
        Assert-True (Has-Result $rows 'Visible membership read' 'Unknown') 'Page limit produced false complete membership.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Uri -like '*membership-page2*').Count -eq 0) 'Next page read beyond page boundary.'
    }
    Test-Case 'Item limit with remaining pages is Unknown' {
        New-Fixture; $global:IdentityFixture.MembershipMode='TwoPages'
        $rows=Invoke-Fixture @{MaxItems=1}
        Assert-True (Has-Result $rows 'Visible membership read' 'Unknown') 'Item ceiling produced false complete membership.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Uri -like '*membership-page2*').Count -eq 0) 'Next page read beyond item boundary.'
    }
    Test-Case 'Repeated nextLink stops instead of looping or passing' {
        New-Fixture; $global:IdentityFixture.MembershipMode='Repeated'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Visible membership read' 'Unknown') 'Repeated nextLink produced false completeness.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Uri -like '*membership-page2*').Count -eq 1) 'Repeated link not bounded to one read.'
    }
    Test-Case 'External nextLink is blocked before the request' {
        New-Fixture; $global:IdentityFixture.MembershipMode='External'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Visible membership read' 'Unknown') 'External link produced false completeness.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Uri -like '*untrusted.invalid*').Count -eq 0) 'External pagination host was called.'
    }
    Test-Case 'Collection without value is incomplete' {
        New-Fixture; $global:IdentityFixture.MembershipMode='MissingValue'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Visible membership read' 'Unknown') 'Missing collection value produced false completeness.'
        Assert-True (-not (Has-Result $rows 'AD-managed references' 'Pass')) 'Missing membership collection was used to prove no AD dependency.'
    }
    foreach ($badValueMode in @('ScalarValue','DictionaryValue','NullEntry')) {
        Test-Case "Malformed membership collection $badValueMode is Unknown" {
            New-Fixture; $global:IdentityFixture.MembershipMode=$badValueMode
            $rows=Invoke-Fixture
            Assert-True (Has-Result $rows 'Visible membership read' 'Unknown') 'Malformed membership value produced false completeness.'
            Assert-True (-not (Has-Result $rows 'AD-managed references' 'Pass')) 'Malformed membership was used to prove no AD dependency.'
        }
    }
    Test-Case 'Limited group metadata cannot prove no AD dependencies' {
        New-Fixture; $global:IdentityFixture.MissingGroupMetadata=$true
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Group metadata' 'Unknown') 'Limited group response was not Unknown.'
        Assert-True (-not (Has-Result $rows 'AD-managed references' 'Pass')) 'Missing synchronization metadata produced false no-AD-dependencies Pass.'
    }
    Test-Case 'Explicit null sync property on native cloud group differs from omitted metadata' {
        New-Fixture; $global:IdentityFixture.GroupSyncNull=$true
        $rows=Invoke-Fixture
        Assert-True (-not (Has-Result $rows 'Group metadata' 'Unknown')) 'Known native-cloud null sync property treated as missing metadata.'
        Assert-True (Has-Result $rows 'AD-managed references' 'Pass') 'Complete native-cloud group metadata did not permit a visible-reference check.'
    }
    Test-Case 'Failed licence read remains Unknown' {
        New-Fixture; $global:IdentityFixture.LicencesFail=$true
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Licence evidence' 'Unknown') 'Unreadable licences were not Unknown.'
        Assert-True (-not (Has-Result $rows 'Room licence assignment' 'Pass')) 'Unreadable licences passed.'
    }
    Test-Case 'dirSyncEnabled dynamic rule requires review' {
        New-Fixture; $global:IdentityFixture.DynamicRule=$true
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Sync-state rules' 'Review') 'Sync-based dynamic group did not require review.'
        Assert-True (Has-Result $rows 'Fixture synced licensing' 'Review') 'Exact dynamic rule was not surfaced.'
    }
    Test-Case 'Missing dynamic membership rule cannot prove no sync-state rules' {
        New-Fixture; $global:IdentityFixture.DynamicMissingRule=$true
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Sync-state rules' 'Unknown') 'Missing dynamic rule produced false complete coverage.'
    }
    Test-Case 'Changed user ID fails baseline identity preservation' {
        New-Fixture; $global:IdentityFixture.UserId='bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
        $rows=Invoke-Fixture @{BaselinePath=$baselinePath}
        Assert-True (Has-Result $rows 'User object ID' 'Action') 'Changed user object ID passed baseline.'
    }
    Test-Case 'Empty GUID cannot be accepted as a valid user identity' {
        New-Fixture; $global:IdentityFixture.UserId=[guid]::Empty.ToString()
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Collector incomplete' 'Unknown') 'Empty GUID accepted as valid user identity.'
        Assert-True (-not (Has-Result $rows 'Exact identity' 'Pass')) 'Empty user GUID produced a false identity Pass.'
        Assert-True ($global:IdentityFixture.Calls.Count -eq 1) 'Target follow-up requests ran after invalid user identity.'
    }
    Test-Case 'Incomplete current membership cannot pass baseline comparison' {
        New-Fixture; $global:IdentityFixture.MembershipMode='MissingType'
        $rows=Invoke-Fixture @{BaselinePath=$baselinePath}
        Assert-True (Has-Result $rows 'Membership' 'Unknown') 'Incomplete membership produced preservation conclusion.'
    }
    Test-Case 'Exact same identity/group IDs pass baseline comparison' {
        New-Fixture
        $rows=Invoke-Fixture @{BaselinePath=$baselinePath}
        Assert-True (Has-Result $rows 'User object ID' 'Pass') 'Same user object ID did not pass.'
        Assert-True (Has-Result $rows 'Visible group IDs' 'Pass') ('Same group IDs did not pass. '+(Get-Issues $rows))
    }
    Test-Case 'After snapshot cannot be used as a Before baseline' {
        New-Fixture
        $afterSnapshot=Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
        $afterSnapshot.Phase='After'
        $afterPath=Join-Path $testRoot 'not-a-before-baseline.json'
        $afterSnapshot | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $afterPath -Encoding utf8
        $rows=Invoke-Fixture @{BaselinePath=$afterPath;Phase='After'}
        Assert-True (Has-Result $rows 'Baseline file' 'Unknown') 'An After capture was accepted as a Before baseline.'
        Assert-True (-not (Has-Result $rows 'User object ID' 'Pass')) 'An After capture produced identity-preservation Pass.'
    }
    Test-Case 'ForceExport cannot overwrite the comparison baseline' {
        New-Fixture
        $beforeHash=(Get-FileHash -LiteralPath $baselinePath).Hash
        $rows=Invoke-Fixture @{BaselinePath=$baselinePath;ExportPath=$baselinePath;ForceExport=$true}
        Assert-True ((Get-FileHash -LiteralPath $baselinePath).Hash -eq $beforeHash) 'The Before baseline was overwritten.'
        Assert-True ($global:IdentityFixture.Calls.Count -eq 0) 'Tenant reads ran after forbidden baseline overwrite was requested.'
        Assert-True (Has-Result $rows 'Collector incomplete' 'Unknown') 'The forbidden overwrite was not rejected before reads.'
        Assert-True (-not (Has-Result $rows 'Snapshot' 'Pass')) 'A forbidden baseline overwrite was reported as exported.'
    }
    Test-Case 'Optional SOA reads only use already approved user/group scopes' {
        New-Fixture
        $global:IdentityFixture.Scopes += @('User-OnPremisesSyncBehavior.ReadWrite.All','Group-OnPremisesSyncBehavior.ReadWrite.All')
        $rows=Invoke-Fixture @{IncludeSoaStatus=$true;RoomListObjectId=@($global:IdentityFixture.RoomListId)}
        Assert-True (Has-Result $rows ('users/'+$global:IdentityFixture.UserId) 'Pass') ('Approved user SOA read missing. '+(Get-Issues $rows))
        Assert-True (Has-Result $rows ('groups/'+$global:IdentityFixture.RoomListId) 'Pass') 'Approved group SOA read missing.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Uri -like '*onPremisesSyncBehavior*').Count -eq 2) 'SOA reads not limited to selected user/group.'
    }
    Test-Case 'SOA false in Before phase does not assert AD authority alone' {
        New-Fixture
        $global:IdentityFixture.Scopes += 'User-OnPremisesSyncBehavior.ReadWrite.All'
        $global:IdentityFixture.CloudManaged=$false
        $rows=Invoke-Fixture @{IncludeSoaStatus=$true;Phase='Before'}
        $soaRows=@($rows | Where-Object { $_.Name -eq ('users/'+$global:IdentityFixture.UserId) })
        Assert-True ($soaRows.Count -eq 1) 'SOA false observation absent.'
        Assert-True ($soaRows[0].Detail -notmatch '(?i)still AD authoritative|AD is authoritative|AD-authoritative') 'SOA false by itself asserted AD authority.'
        Assert-True ($soaRows[0].Detail -match '(?i)correlat|sync|rollback') 'SOA false omitted required correlation guidance.'
    }
    Test-Case 'Missing approved SOA scope adds no consent or SOA request' {
        New-Fixture
        $rows=Invoke-Fixture @{IncludeSoaStatus=$true}
        Assert-True (Has-Result $rows ('users/'+$global:IdentityFixture.UserId) 'Unknown') 'Absent SOA permission was not Unknown.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Uri -like '*onPremisesSyncBehavior*').Count -eq 0) 'SOA request ran without scope.'
    }
    Test-Case 'Approved user SOA scope does not authorize a group SOA read' {
        New-Fixture; $global:IdentityFixture.Scopes += 'User-OnPremisesSyncBehavior.ReadWrite.All'
        $rows=Invoke-Fixture @{IncludeSoaStatus=$true;RoomListObjectId=@($global:IdentityFixture.RoomListId)}
        Assert-True (Has-Result $rows ('users/'+$global:IdentityFixture.UserId) 'Pass') 'Approved user SOA read absent.'
        Assert-True (Has-Result $rows ('groups/'+$global:IdentityFixture.RoomListId) 'Unknown') 'Group SOA missing scope was not Unknown.'
        Assert-True (@($global:IdentityFixture.Calls | Where-Object Uri -like '*onPremisesSyncBehavior*').Count -eq 1) 'An unapproved group SOA read was attempted.'
    }
    Test-Case 'Optional SOA rejects non-reuse before authentication' {
        New-Fixture
        $rows=Invoke-Fixture @{IncludeSoaStatus=$true;UseExistingConnection=$false}
        Assert-True (Has-Result $rows 'Collector incomplete' 'Unknown') 'SOA accepted without connection reuse.'
        Assert-True ($global:IdentityFixture.Calls.Count -eq 0) 'Reads ran without explicit SOA context reuse.'
    }
    Test-Case 'Inherited write scope breadth requires review' {
        New-Fixture; $global:IdentityFixture.Scopes += 'Directory.ReadWrite.All'
        $rows=Invoke-Fixture
        Assert-True (Has-Result $rows 'Existing permission breadth' 'Review') 'Inherited write scope was not surfaced.'
    }
    Test-Case 'Existing context is not silently replaced' {
        New-Fixture
        $rows=Invoke-Fixture @{UseExistingConnection=$false}
        Assert-True (Has-Result $rows 'Collector incomplete' 'Unknown') 'Existing context accepted without reuse.'
        Assert-True ($global:IdentityFixture.Calls.Count -eq 0) 'Existing context replaced or tenant queried.'
    }
}
finally {
    Remove-Module Microsoft.Graph.Authentication -Force -ErrorAction SilentlyContinue
    $env:PSModulePath=$oldModulePath
    Remove-Variable -Name IdentityFixture -Scope Global -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "Offline identity tests: $passed passed, $failed failed. $requestCount simulated requests; GET only, no live connection."
if ($failed) { $failures | Write-Host; exit 1 }
