#requires -Version 7.2
<#
.SYNOPSIS
Read-only Exchange Online and Microsoft Graph baseline for an approved room list.
.DESCRIPTION
No tenant configuration is changed. Local evidence files are created.
Requires ExchangeOnlineManagement 3.0.0 or later, Microsoft.Graph.Users and
Microsoft.Graph.Identity.DirectoryManagement. Supply an approved CSV with
RoomId,UPN,SiteType columns. SiteType must be Local or Remote.
This script covers Exchange Online mailboxes; use an Exchange Server procedure
for on-premises mailboxes. Hardware, CA, Intune and PMP eligibility are manual
evidence items. Review generated errors before using the baseline.
.EXAMPLE
./Teams-Rooms-Passwordless-Inventory.ps1 -TenantId '<tenant-id>' `
  -RoomListCsv './approved-rooms.csv' -OutputDirectory './evidence'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [Parameter(Mandatory)][string]$RoomListCsv,
    [Parameter(Mandatory)][string]$OutputDirectory,
    [ValidateRange(1,10000)][int]$ExpectedRooms = 50,
    [ValidateRange(0,10000)][int]$ExpectedLocal = 40,
    [ValidateRange(0,10000)][int]$ExpectedRemote = 10
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ErrorView = 'NormalView'
$rows = @(Import-Csv -LiteralPath $RoomListCsv)
if ($rows.Count -ne $ExpectedRooms) { throw "Expected $ExpectedRooms approved rooms; found $($rows.Count)." }
if ($ExpectedLocal + $ExpectedRemote -ne $ExpectedRooms) { throw 'Expected site counts must sum to ExpectedRooms.' }
foreach ($column in @('RoomId','UPN','SiteType')) {
    if ($column -notin $rows[0].PSObject.Properties.Name) { throw "CSV is missing $column." }
    if (@($rows | Where-Object { [string]::IsNullOrWhiteSpace($_.$column) }).Count) {
        throw "CSV contains a blank $column."
    }
}
if (@($rows | Where-Object { $_.SiteType -notin @('Local','Remote') }).Count) { throw 'SiteType must be Local or Remote.' }
if (@($rows | Where-Object SiteType -eq 'Local').Count -ne $ExpectedLocal -or
    @($rows | Where-Object SiteType -eq 'Remote').Count -ne $ExpectedRemote) { throw 'Approved site counts do not match expected counts.' }
foreach ($column in @('RoomId','UPN')) {
    $duplicates = @($rows | Group-Object -Property { $_.$column.Trim().ToLowerInvariant() } | Where-Object Count -gt 1)
    if ($duplicates.Count) { throw "CSV contains duplicate $column values." }
}

Import-Module ExchangeOnlineManagement -MinimumVersion 3.0.0
Import-Module Microsoft.Graph.Users
Import-Module Microsoft.Graph.Identity.DirectoryManagement
$stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmssZ')
$evidencePath = Join-Path $OutputDirectory "TeamsRooms-$stamp"
if (Test-Path -LiteralPath $evidencePath) { throw 'Evidence folder already exists; do not overwrite a baseline.' }
New-Item -ItemType Directory -Path $evidencePath | Out-Null
Copy-Item -LiteralPath $RoomListCsv -Destination (Join-Path $evidencePath 'ApprovedRooms.csv')
$failures = [System.Collections.Generic.List[object]]::new()
$baseline = [System.Collections.Generic.List[object]]::new()
$mailboxes = [System.Collections.Generic.List[object]]::new()
$calendars = [System.Collections.Generic.List[object]]::new()
$permissions = [System.Collections.Generic.List[object]]::new()
$places = [System.Collections.Generic.List[object]]::new()
$roomLists = [System.Collections.Generic.List[object]]::new()
$connectedExchange = $false
$connectedGraph = $false

function Add-CollectionError {
    param([string]$RoomId,[string]$Stage,[System.Management.Automation.ErrorRecord]$Record)
    # Error evidence can contain account identifiers. Restrict access to this folder.
    $failures.Add([pscustomobject]@{
        RoomId=$RoomId; Stage=$Stage; ErrorId=$Record.FullyQualifiedErrorId
        Message=$Record.Exception.Message; CollectedUtc=(Get-Date).ToUniversalTime().ToString('o')
    })
    Write-Warning "Collection failed for $RoomId at $Stage; see Errors.csv."
}

try {
    Connect-ExchangeOnline -ShowBanner:$false
    $connectedExchange = $true
    $exchangeConnection = @(Get-ConnectionInformation | Where-Object { $_.State -eq 'Connected' })
    if ($exchangeConnection.Count -ne 1 -or [string]$exchangeConnection[0].TenantID -ne [string]$TenantId) {
        throw 'Exchange connection does not uniquely match the requested tenant. Close other sessions and reconnect.'
    }
    Connect-MgGraph -TenantId $TenantId.ToString() -Scopes @('User.Read.All','LicenseAssignment.Read.All') -ContextScope Process -NoWelcome
    $connectedGraph = $true
    if ((Get-MgContext).TenantId -ne $TenantId.ToString()) { throw 'Graph connection tenant does not match the requested tenant.' }
    $skus = @(Get-MgSubscribedSku -All -Property @('skuId','skuPartNumber','servicePlans','capabilityStatus'))
    $skus | Export-Clixml -LiteralPath (Join-Path $evidencePath 'SubscribedSkus.xml')
    $skuMap = @{}
    foreach ($sku in $skus) { $skuMap[$sku.SkuId.ToString()] = $sku.SkuPartNumber }

    foreach ($row in $rows) {
        $roomIssues = [System.Collections.Generic.List[string]]::new()
        $result = [ordered]@{
            RoomId=$row.RoomId; ApprovedUPN=$row.UPN.Trim(); SiteType=$row.SiteType
            CollectedUtc=(Get-Date).ToUniversalTime().ToString('o')
            DisplayName=''; ObjectId=''; UPN=''; PrimarySMTP=''; UPNMatchesSMTP=$null
            RecipientTypeDetails=''; HiddenFromAddressLists=$null; AccountEnabled=$null
            OnPremisesSyncEnabled=$null; UsageLocation=''; Licenses=''; DisabledPlans=''
            AutomateProcessing=''; BookingWindowDays=$null; MaximumDurationMinutes=$null
            AllowRecurringMeetings=$null; ProcessExternalMeetings=$null; ResourceDelegates=''
            CalendarFolderIdentity=''; TimeZone=''; BaselineStatus='Incomplete'; Issues=''
        }
        $mailbox = $null
        try {
            $mailbox = Get-Mailbox -Identity $row.UPN.Trim()
            $mailboxes.Add([pscustomobject]@{RoomId=$row.RoomId; Mailbox=$mailbox})
            $result.DisplayName = $mailbox.DisplayName
            $result.UPN = [string]$mailbox.UserPrincipalName
            $result.PrimarySMTP = [string]$mailbox.PrimarySmtpAddress
            $result.RecipientTypeDetails = [string]$mailbox.RecipientTypeDetails
            $result.HiddenFromAddressLists = $mailbox.HiddenFromAddressListsEnabled
            $result.UPNMatchesSMTP = $result.UPN -ieq $result.PrimarySMTP
            if ($mailbox.RecipientTypeDetails -ne 'RoomMailbox') { $roomIssues.Add('NotRoomMailbox') }
            if ($result.UPN -ine $row.UPN.Trim()) { $roomIssues.Add('ApprovedUPNMismatch') }
            if (-not $result.UPNMatchesSMTP) { $roomIssues.Add('UPNSMTPMismatch') }
        } catch { Add-CollectionError $row.RoomId 'Mailbox' $_; $roomIssues.Add('MailboxCollectionFailed') }
        if ($null -ne $mailbox) {
            try {
                # Object ID avoids joining different accounts by renamed addresses.
                if (-not $mailbox.ExternalDirectoryObjectId) { throw 'Mailbox has no Entra object ID.' }
                $user = Get-MgUser -UserId $mailbox.ExternalDirectoryObjectId -Property @(
                    'id','userPrincipalName','accountEnabled','onPremisesSyncEnabled','usageLocation','assignedLicenses'
                )
                $result.ObjectId = $user.Id
                $result.AccountEnabled = $user.AccountEnabled
                $result.OnPremisesSyncEnabled = $user.OnPremisesSyncEnabled
                $result.UsageLocation = $user.UsageLocation
                if ($user.UserPrincipalName -ine $result.UPN) { $roomIssues.Add('GraphExchangeUPNMismatch') }
                if ($user.AccountEnabled -ne $true) { $roomIssues.Add('AccountNotEnabled') }
                $licenseNames = foreach ($license in $user.AssignedLicenses) {
                    $skuKey = $license.SkuId.ToString()
                    if ($skuMap.ContainsKey($skuKey)) { $skuMap[$skuKey] } else { "UnmappedSKU:$skuKey" }
                }
                $result.Licenses = @($licenseNames) -join ';'
                $result.DisabledPlans = @($user.AssignedLicenses | ForEach-Object {
                    "$($_.SkuId):$($_.DisabledPlans -join ',')"
                }) -join ';'
                if (@($user.AssignedLicenses).Count -eq 0) { $roomIssues.Add('NoAssignedLicense') }
            } catch { Add-CollectionError $row.RoomId 'GraphUser' $_; $roomIssues.Add('GraphUserCollectionFailed') }
            try {
                $calendar = Get-CalendarProcessing -Identity $mailbox.Identity
                $calendars.Add([pscustomobject]@{RoomId=$row.RoomId; Settings=$calendar})
                $result.AutomateProcessing = [string]$calendar.AutomateProcessing
                $result.BookingWindowDays = $calendar.BookingWindowInDays
                $result.MaximumDurationMinutes = $calendar.MaximumDurationInMinutes
                $result.AllowRecurringMeetings = $calendar.AllowRecurringMeetings
                $result.ProcessExternalMeetings = $calendar.ProcessExternalMeetingMessages
                $result.ResourceDelegates = @($calendar.ResourceDelegates) -join ';'
            } catch { Add-CollectionError $row.RoomId 'CalendarProcessing' $_; $roomIssues.Add('CalendarCollectionFailed') }
            try {
                $folders = @(Get-EXOMailboxFolderStatistics -Identity $mailbox.PrimarySmtpAddress -FolderScope Calendar |
                    Where-Object FolderType -eq 'Calendar')
                if ($folders.Count -ne 1) { throw 'Primary calendar folder was not resolved uniquely.' }
                $folderPath = ([string]$folders[0].FolderPath).Replace('/','\')
                $folderIdentity = '{0}:{1}' -f $mailbox.PrimarySmtpAddress,$folderPath
                $result.CalendarFolderIdentity = $folderIdentity
                # Preserve Default and Anonymous as well as explicit delegates.
                $folderPermissions = @(Get-EXOMailboxFolderPermission -Identity $folderIdentity)
                $permissions.Add([pscustomobject]@{RoomId=$row.RoomId; FolderIdentity=$folderIdentity; Permissions=$folderPermissions})
            } catch { Add-CollectionError $row.RoomId 'CalendarPermissions' $_; $roomIssues.Add('CalendarPermissionsFailed') }
            try {
                $place = Get-Place -Identity $mailbox.PrimarySmtpAddress
                $places.Add([pscustomobject]@{RoomId=$row.RoomId; Place=$place})
            } catch { Add-CollectionError $row.RoomId 'Place' $_; $roomIssues.Add('PlaceCollectionFailed') }
            try { $result.TimeZone = (Get-MailboxRegionalConfiguration -Identity $mailbox.Identity).TimeZone }
            catch { Add-CollectionError $row.RoomId 'RegionalConfiguration' $_; $roomIssues.Add('RegionalConfigurationFailed') }
        }
        if ($roomIssues.Count -eq 0) { $result.BaselineStatus = 'Collected' }
        $result.Issues = $roomIssues -join ';'
        $baseline.Add([pscustomobject]$result)
    }

    try {
        $inScopeSmtp = @($baseline | Where-Object PrimarySMTP | ForEach-Object { $_.PrimarySMTP.ToLowerInvariant() })
        foreach ($list in @(Get-DistributionGroup -RecipientTypeDetails RoomList -ResultSize Unlimited)) {
            try {
                foreach ($member in @(Get-DistributionGroupMember -Identity $list.Identity -ResultSize Unlimited)) {
                    if ($member.PrimarySmtpAddress -and ([string]$member.PrimarySmtpAddress).ToLowerInvariant() -in $inScopeSmtp) {
                        $roomLists.Add([pscustomobject]@{RoomList=[string]$list.PrimarySmtpAddress; RoomSMTP=[string]$member.PrimarySmtpAddress})
                    }
                }
            } catch { Add-CollectionError 'Estate' "RoomList:$($list.Identity)" $_ }
        }
    } catch { Add-CollectionError 'Estate' 'RoomLists' $_ }
} finally {
    $baseline | Export-Csv -LiteralPath (Join-Path $evidencePath 'Inventory.csv') -NoTypeInformation -Encoding utf8
    $failures | Export-Csv -LiteralPath (Join-Path $evidencePath 'Errors.csv') -NoTypeInformation -Encoding utf8
    $mailboxes | Export-Clixml -LiteralPath (Join-Path $evidencePath 'MailboxBaseline.xml')
    $calendars | Export-Clixml -LiteralPath (Join-Path $evidencePath 'CalendarProcessing.xml')
    $permissions | Export-Clixml -LiteralPath (Join-Path $evidencePath 'CalendarPermissions.xml')
    $places | Export-Clixml -LiteralPath (Join-Path $evidencePath 'Places.xml')
    $roomLists | Export-Csv -LiteralPath (Join-Path $evidencePath 'RoomLists.csv') -NoTypeInformation -Encoding utf8
    [pscustomobject]@{
        TenantId=$TenantId.ToString(); CollectedUtc=$stamp; RequestedRooms=$rows.Count
        ReturnedRows=$baseline.Count; CollectedRows=@($baseline | Where-Object BaselineStatus -eq 'Collected').Count
        ErrorCount=$failures.Count; GraphScopes='User.Read.All;LicenseAssignment.Read.All'
        Purpose='Read-only Exchange Online baseline; not migration eligibility'
    } | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $evidencePath 'Manifest.json') -Encoding utf8
    if ($connectedExchange) { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Continue }
    if ($connectedGraph) { Disconnect-MgGraph -ErrorAction Continue | Out-Null }
}
Write-Host "Evidence written to $evidencePath. Collected does not mean eligible for migration."
if ($failures.Count -gt 0 -or @($baseline | Where-Object BaselineStatus -ne 'Collected').Count -gt 0) {
    Write-Warning 'Baseline has errors or identity exceptions. Resolve them before rollout.'
    exit 2
}
