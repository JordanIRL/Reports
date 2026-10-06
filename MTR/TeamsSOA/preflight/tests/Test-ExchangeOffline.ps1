#requires -Version 7.2
<# Offline fixture tests only. Creates a temporary fake ExchangeOnlineManagement
module and fake evidence in a temporary directory. It never connects to a tenant. #>
[CmdletBinding()]
param([string]$ScriptPath = (Join-Path $PSScriptRoot '../scripts/Test-RoomMailboxAndLists.ps1'))
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('teamssoa-exchange-fixture-' + [guid]::NewGuid())
$oldModulePath = $env:PSModulePath
$passed = 0
$failed = 0
$failures = [System.Collections.Generic.List[string]]::new()

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try { & $Body; $script:passed++; Write-Host "PASS $Name" }
    catch { $script:failed++; $failures.Add("$Name : $($_.Exception.Message)"); Write-Host "FAIL $Name : $($_.Exception.Message)" -ForegroundColor Red }
}
function New-Fixture {
    $global:ExchangeFixture = [ordered]@{
        TenantId = '11111111-1111-4111-8111-111111111111'
        RoomId = '22222222-2222-4222-8222-222222222222'
        RoomGuid = '33333333-3333-4333-8333-333333333333'
        ListId = '44444444-4444-4444-8444-444444444444'
        OwnerId = '55555555-5555-4555-8555-555555555555'
        RoomUpn = 'mtr@meetingrooms.ie'
        UnreadableMembers = $false
        UnreadablePermissions = $false
        VanishedMember = $false
        WrongOrganization = $false
        NoLists = $false
        MissingMemberId = $false
        AdditionalRoom = $false
        ReverseArrays = $false
        MissingMailboxGuid = $false
        Calls = [System.Collections.Generic.List[string]]::new()
    }
}
function Invoke-Fixture {
    param([hashtable]$More = @{})
    $args = @{ TenantId = $global:ExchangeFixture.TenantId; UseExistingConnection = $true; Ascii = $true; PassThru = $true; ExpectedUserObjectId = $global:ExchangeFixture.RoomId }
    foreach ($key in $More.Keys) { $args[$key] = $More[$key] }
    @(& $ScriptPath @args 6>$null)
}
function Has-Result {
    param([object[]]$Rows, [string]$Name, [string]$Status)
    @($Rows | Where-Object { $_.Name -like $Name -and $_.Status -eq $Status }).Count -gt 0
}

try {
    $moduleRoot = Join-Path $testRoot 'ExchangeOnlineManagement/99.0.0'
    New-Item -Path $moduleRoot -ItemType Directory -Force | Out-Null
    $moduleSource = @'
Set-StrictMode -Version Latest
function Trace-Read([string]$Command) { $global:ExchangeFixture.Calls.Add($Command) }
function Connect-ExchangeOnline { [CmdletBinding()]param([string]$UserPrincipalName,[switch]$ShowBanner) throw 'TEST SENTINEL: A live connection must never be attempted.' }
function Disconnect-ExchangeOnline { [CmdletBinding()]param([string[]]$ConnectionId,[switch]$Confirm) throw 'TEST SENTINEL: A reused session must never be disconnected.' }
function Get-PSSession { [CmdletBinding()]param() @() }
function Get-ConnectionInformation {
    [CmdletBinding()]param()
    [pscustomobject]@{ ConnectionId='66666666-6666-4666-8666-666666666666'; State='Connected'; TokenStatus='Active'; IsEopSession=$false; ModulePrefix=''; TenantID=$global:ExchangeFixture.TenantId }
}
function Get-OrganizationConfig {
    [CmdletBinding()]param()
    Trace-Read 'Organization'
    $id = if ($global:ExchangeFixture.WrongOrganization) { '77777777-7777-4777-8777-777777777777' } else { $global:ExchangeFixture.TenantId }
    [pscustomobject]@{ ExternalDirectoryOrganizationId=$id }
}
function Get-Mailbox {
    [CmdletBinding()]param([string]$Identity)
    Trace-Read 'Mailbox'
    $aliases = @('SMTP:mtr@meetingrooms.ie','smtp:room-alias@meetingrooms.ie')
    if ($global:ExchangeFixture.ReverseArrays) { [array]::Reverse($aliases) }
    $obj = [ordered]@{ ExternalDirectoryObjectId=$global:ExchangeFixture.RoomId; ExchangeGuid=$global:ExchangeFixture.RoomGuid; Guid=$global:ExchangeFixture.RoomGuid; RecipientTypeDetails='RoomMailbox'; UserPrincipalName=$global:ExchangeFixture.RoomUpn; PrimarySmtpAddress=$global:ExchangeFixture.RoomUpn; Alias='mtr'; EmailAddresses=$aliases; LegacyExchangeDN='/o=Fixture/ou=Fixture/cn=Recipients/cn=mtr'; HiddenFromAddressListsEnabled=$false; GrantSendOnBehalfTo=@(); ForwardingAddress=$null; ForwardingSmtpAddress=$null; DeliverToMailboxAndForward=$false; ResourceCapacity=10; IsDirSynced=$true }
    if ($global:ExchangeFixture.MissingMailboxGuid) { $obj.Remove('ExchangeGuid') }
    [pscustomobject]$obj
}
function Get-CalendarProcessing {
    [CmdletBinding()]param([string]$Identity)
    Trace-Read 'Calendar'
    [pscustomobject]@{ AutomateProcessing='AutoAccept'; AllowConflicts=$false; BookingWindowInDays=180; MaximumDurationInMinutes=1440; MinimumDurationInMinutes=0; EnforceSchedulingHorizon=$true; ScheduleOnlyDuringWorkHours=$false; AllowRecurringMeetings=$true; AllBookInPolicy=$true; AllRequestInPolicy=$false; AllRequestOutOfPolicy=$false; BookInPolicy=@(); RequestInPolicy=@(); RequestOutOfPolicy=@(); ResourceDelegates=@(); ForwardRequestsToDelegates=$true; ProcessExternalMeetingMessages=$true; DeleteSubject=$true; AddOrganizerToSubject=$true; DeleteComments=$true; DeleteAttachments=$true; RemovePrivateProperty=$true; AddAdditionalResponse=$false; AdditionalResponse=''; EnableResponseDetails=$true; ConflictPercentageAllowed=0; MaximumConflictInstances=0 }
}
function Get-MailboxPermission {
    [CmdletBinding()]param([string]$Identity,[object]$ResultSize)
    Trace-Read 'MailboxPermission'
    if ($global:ExchangeFixture.UnreadablePermissions) { throw 'Fixture RBAC denied mailbox permissions.' }
    [pscustomobject]@{ User='NT AUTHORITY\SELF'; AccessRights=@('FullAccess'); Deny=$false; IsInherited=$false }
}
function Get-RecipientPermission {
    [CmdletBinding()]param([string]$Identity,[object]$ResultSize)
    Trace-Read 'RecipientPermission'
    [pscustomobject]@{ Trustee='NT AUTHORITY\SELF'; AccessRights=@('SendAs'); AccessControlType='Allow'; IsInherited=$false }
}
function Get-MailboxFolderStatistics {
    [CmdletBinding()]param([string]$Identity,[string]$FolderScope,[object]$ResultSize)
    Trace-Read 'CalendarFolder'
    [pscustomobject]@{ FolderType='Calendar'; FolderPath='/Kalender' }
}
function Get-MailboxFolderPermission {
    [CmdletBinding()]param([string]$Identity,[object]$ResultSize)
    Trace-Read 'CalendarPermission'
    if (-not $Identity.EndsWith(':\Kalender')) { throw 'Script hardcoded or malformed the localized calendar path.' }
    [pscustomobject]@{ User='Default'; AccessRights=@('AvailabilityOnly'); SharingPermissionFlags=@('None') }
}
function Get-DistributionGroup {
    [CmdletBinding()]param([string]$Identity,[string]$RecipientTypeDetails,[object]$ResultSize)
    Trace-Read 'DistributionGroup'
    if ($global:ExchangeFixture.NoLists) { return }
    if ($Identity -and $Identity -notin @($global:ExchangeFixture.ListId,'rooms@meetingrooms.ie')) { throw 'Fixture group not found.' }
    $aliases = @('SMTP:rooms@meetingrooms.ie','smtp:roomlist-alias@meetingrooms.ie')
    if ($global:ExchangeFixture.ReverseArrays) { [array]::Reverse($aliases) }
    [pscustomobject]@{ ExternalDirectoryObjectId=$global:ExchangeFixture.ListId; Guid=$global:ExchangeFixture.ListId; Identity='rooms@meetingrooms.ie'; RecipientTypeDetails='RoomList'; Name='Rooms'; DisplayName='Meeting Rooms'; Alias='rooms'; PrimarySmtpAddress='rooms@meetingrooms.ie'; EmailAddresses=$aliases; LegacyExchangeDN='/o=Fixture/ou=Fixture/cn=Recipients/cn=Rooms'; HiddenFromAddressListsEnabled=$false; RequireSenderAuthenticationEnabled=$true; MemberJoinRestriction='Closed'; MemberDepartRestriction='Closed'; ModerationEnabled=$false; ModeratedBy=@(); BypassModerationFromSendersOrMembers=@(); SendModerationNotifications='Always'; AcceptMessagesOnlyFromSendersOrMembers=@(); RejectMessagesFromSendersOrMembers=@(); GrantSendOnBehalfTo=@(); ManagedBy=@($global:ExchangeFixture.OwnerId); IsDirSynced=$true }
}
function Get-DistributionGroupMember {
    [CmdletBinding()]param([string]$Identity,[object]$ResultSize)
    Trace-Read 'DistributionGroupMember'
    if ($global:ExchangeFixture.UnreadableMembers) { throw 'Fixture membership unreadable.' }
    $members = @()
    if (-not $global:ExchangeFixture.VanishedMember) {
        $id = if ($global:ExchangeFixture.MissingMemberId) { $null } else { $global:ExchangeFixture.RoomId }
        $members += [pscustomobject]@{ ExternalDirectoryObjectId=$id; Guid=$global:ExchangeFixture.RoomGuid; PrimarySmtpAddress=$global:ExchangeFixture.RoomUpn; RecipientTypeDetails='RoomMailbox'; Identity=$global:ExchangeFixture.RoomUpn }
    }
    if ($global:ExchangeFixture.AdditionalRoom) { $members += [pscustomobject]@{ ExternalDirectoryObjectId='88888888-8888-4888-8888-888888888888'; Guid='99999999-9999-4999-8999-999999999999'; PrimarySmtpAddress='second@meetingrooms.ie'; RecipientTypeDetails='RoomMailbox'; Identity='second@meetingrooms.ie' } }
    if ($global:ExchangeFixture.ReverseArrays) { [array]::Reverse($members) }
    $members
}
function Get-Recipient {
    [CmdletBinding()]param([string]$Identity)
    Trace-Read 'Owner'
    if ($Identity -ne $global:ExchangeFixture.OwnerId) { throw 'Fixture owner not found.' }
    [pscustomobject]@{ ExternalDirectoryObjectId=$global:ExchangeFixture.OwnerId; Guid=$global:ExchangeFixture.OwnerId; PrimarySmtpAddress='owner@meetingrooms.ie'; RecipientTypeDetails='UserMailbox'; Identity='owner@meetingrooms.ie' }
}
Export-ModuleMember -Function *
'@
    Set-Content -LiteralPath (Join-Path $moduleRoot 'ExchangeOnlineManagement.psm1') -Value $moduleSource -Encoding utf8
    New-ModuleManifest -Path (Join-Path $moduleRoot 'ExchangeOnlineManagement.psd1') -RootModule 'ExchangeOnlineManagement.psm1' -ModuleVersion '99.0.0' -FunctionsToExport '*' -PowerShellVersion '7.2'
    $env:PSModulePath = $testRoot + [IO.Path]::PathSeparator + $oldModulePath
    $baselinePath = Join-Path $testRoot 'before.json'

    Test-Case 'Before snapshot binds tenant, mailbox, localized calendar and containing RoomList' {
        New-Fixture
        $global:ExchangeFixture.AdditionalRoom = $true
        $rows = Invoke-Fixture @{ ExportPath=$baselinePath }
        Assert-True (Has-Result $rows 'Expected tenant' 'Pass') 'Tenant binding did not pass.'
        Assert-True (Has-Result $rows 'Cross-check Entra identity' 'Pass') 'Mailbox/Entra object binding did not pass.'
        Assert-True (Has-Result $rows 'Target room membership' 'Pass') 'Containing RoomList was not found.'
        Assert-True (Has-Result $rows 'Calendar folder permissions' 'Pass') 'Localized calendar permission check did not pass.'
        Assert-True (Test-Path -LiteralPath $baselinePath) 'Before snapshot was not exported.'
        Assert-True (Has-Result $rows 'Sign-in and booking address' 'Pass') 'Room sign-in/booking address did not pass.'
        Assert-True (-not (Has-Result $rows '*' 'Action')) 'Unexpected action in complete fixture.'
        Assert-True (-not (Has-Result $rows '*' 'Unknown')) 'Unexpected incomplete evidence in complete fixture.'
    }
    Test-Case 'After same object preserves baseline and ignores array ordering' {
        New-Fixture
        $global:ExchangeFixture.AdditionalRoom = $true
        $global:ExchangeFixture.ReverseArrays = $true
        $rows = Invoke-Fixture @{ Mode='After'; BaselinePath=$baselinePath }
        Assert-True (Has-Result $rows 'Mailbox / ExchangeGuid' 'Pass') 'Mailbox GUID preservation did not pass.'
        Assert-True (Has-Result $rows 'RoomList * / Members' 'Pass') ("Member ID baseline preservation did not pass. " + (($rows | Where-Object Status -eq 'Unknown' | ForEach-Object { $_.Name + ': ' + $_.Detail }) -join ' | '))
        Assert-True (-not (Has-Result $rows '*' 'Action')) 'Harmless array reordering flagged Action.'
        Assert-True (-not (Has-Result $rows '*' 'Unknown')) 'Unexpected incomplete comparison.'
    }
    Test-Case 'After vanished room membership is detected even without explicit list identity' {
        New-Fixture
        $global:ExchangeFixture.VanishedMember = $true
        $rows = Invoke-Fixture @{ Mode='After'; BaselinePath=$baselinePath }
        Assert-True (Has-Result $rows 'Membership' 'Action') 'Empty RoomList did not produce Action.'
        Assert-True (Has-Result $rows 'RoomList * / Members' 'Action') 'Vanished target member did not produce baseline drift Action.'
    }
    Test-Case 'Unreadable membership never becomes empty/preserved evidence' {
        New-Fixture
        $global:ExchangeFixture.UnreadableMembers = $true
        $rows = Invoke-Fixture @{ Mode='After'; BaselinePath=$baselinePath }
        Assert-True (Has-Result $rows '*member read' 'Unknown') 'Membership read failure was not Unknown.'
        Assert-True (Has-Result $rows 'RoomList * / Members' 'Unknown') 'Incomplete members compared as preserved.'
        Assert-True (-not (Has-Result $rows 'RoomList * / Members' 'Pass')) 'Unreadable members produced false Pass.'
    }
    Test-Case 'Unreadable permissions never compare as preserved' {
        New-Fixture
        $global:ExchangeFixture.UnreadablePermissions = $true
        $rows = Invoke-Fixture @{ Mode='After'; BaselinePath=$baselinePath }
        Assert-True (Has-Result $rows 'Mailbox access baseline' 'Unknown') 'Permission read failure was not Unknown.'
        Assert-True (Has-Result $rows 'MailboxAccess permissions' 'Unknown') 'Incomplete permissions compared as preserved.'
    }
    Test-Case 'Organization tenant mismatch blocks all room reads' {
        New-Fixture
        $global:ExchangeFixture.WrongOrganization = $true
        $rows = Invoke-Fixture
        Assert-True (Has-Result $rows 'Stopped or incomplete' 'Unknown') 'Tenant mismatch was not detected.'
        Assert-True (-not $global:ExchangeFixture.Calls.Contains('Mailbox')) 'Room lookup ran after tenant mismatch.'
    }
    Test-Case 'Malformed baseline blocks tenant reads' {
        New-Fixture
        $malformed = Join-Path $testRoot 'malformed.json'
        Set-Content -LiteralPath $malformed -Value '{broken json'
        $rows = Invoke-Fixture @{ Mode='After'; BaselinePath=$malformed }
        Assert-True (Has-Result $rows 'Stopped or incomplete' 'Unknown') 'Malformed baseline was accepted.'
        Assert-True ($global:ExchangeFixture.Calls.Count -eq 0) 'A tenant read ran after malformed baseline.'
    }
    Test-Case 'Existing evidence file is never overwritten by default' {
        New-Fixture
        $hashBefore = (Get-FileHash -LiteralPath $baselinePath).Hash
        $rows = Invoke-Fixture @{ ExportPath=$baselinePath }
        Assert-True ((Get-FileHash -LiteralPath $baselinePath).Hash -eq $hashBefore) 'Existing evidence changed.'
        Assert-True ($global:ExchangeFixture.Calls.Count -eq 0) 'Reads ran even though export prevalidation failed.'
    }
    Test-Case 'Missing mailbox GUID is Unknown and not preserved' {
        New-Fixture
        $global:ExchangeFixture.MissingMailboxGuid = $true
        $rows = Invoke-Fixture @{ Mode='After'; BaselinePath=$baselinePath }
        Assert-True (Has-Result $rows 'Exchange GUID' 'Unknown') 'Missing GUID did not produce Unknown.'
        Assert-True (Has-Result $rows 'Mailbox / ExchangeGuid' 'Unknown') 'Missing GUID produced false preservation.'
    }
    Test-Case 'Missing member Entra ID requires review' {
        New-Fixture
        $global:ExchangeFixture.MissingMemberId = $true
        $rows = Invoke-Fixture
        Assert-True (Has-Result $rows 'Member IDs and addresses' 'Review') 'Missing member ID produced false Pass.'
    }
    Test-Case 'Empty scoped list inventory requires review' {
        New-Fixture
        $global:ExchangeFixture.NoLists = $true
        $rows = Invoke-Fixture
        Assert-True (Has-Result $rows 'Target dependency discovery' 'Review') 'Empty discovery produced false Pass.'
        Assert-True (Has-Result $rows 'Discovery scope' 'Review') 'RBAC-scoped discovery limitation was not surfaced.'
    }
    Test-Case 'No cross-object substitution when ExpectedUserObjectId mismatches' {
        New-Fixture
        $rows = Invoke-Fixture @{ ExpectedUserObjectId='77777777-7777-4777-8777-777777777777' }
        Assert-True (Has-Result $rows 'Cross-check Entra identity' 'Action') 'Expected-user mismatch was not Action.'
    }
    Test-Case 'Existing session requires explicit reuse and is not replaced' {
        New-Fixture
        $rows = Invoke-Fixture @{ UseExistingConnection=$false; AdminUpn='admin@meetingrooms.ie' }
        Assert-True (Has-Result $rows 'Stopped or incomplete' 'Unknown') 'Existing session was accepted without explicit reuse.'
        Assert-True ($global:ExchangeFixture.Calls.Count -eq 0) 'Reads ran without explicit connection reuse.'
        Assert-True (@($rows | Where-Object Detail -like '*already exists*').Count -gt 0) 'Existing-session refusal did not explain how to proceed.'
    }
}
finally {
    Remove-Module ExchangeOnlineManagement -Force -ErrorAction SilentlyContinue
    $env:PSModulePath = $oldModulePath
    Remove-Variable -Name ExchangeFixture -Scope Global -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "Offline Exchange tests: $passed passed, $failed failed. No tenant connected."
if ($failed) { $failures | Write-Host; exit 1 }
