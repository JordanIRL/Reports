#requires -Version 7.2
<#
.SYNOPSIS
Read-only Exchange Online checks for an existing Teams room and its RoomLists.
.DESCRIPTION
Reads Exchange configuration only. No mailbox/group/device/tenant setting is changed.
Authentication creates a local session; -ExportPath optionally writes a local JSON file.
Pass means that individual check passed, never permission to perform an SOA change.
Unreadable or omitted evidence stays Unknown/Review. RoomList discovery is RBAC scoped.
Get-Mailbox is used for its object-specific baseline properties; no mailbox content is read.
.EXAMPLE
./Test-RoomMailboxAndLists.ps1 -TenantId '<tenant-guid>' -AdminUpn 'admin@example.com' -ExportPath './exchange-before.json'
.EXAMPLE
./Test-RoomMailboxAndLists.ps1 -TenantId '<tenant-guid>' -UseExistingConnection -Mode After -BaselinePath './exchange-before.json' -RoomListIdentity 'rooms@example.com'
.NOTES
Requires ExchangeOnlineManagement 3.2.0 or newer, and Exchange RBAC access to the reads.
Graph permissions are not used. Supply ExpectedUserObjectId from the Entra preflight to
bind the mailbox to the same Entra object. Keep the report private: it contains addresses,
delegates, memberships and configuration, but no messages, passwords or tokens.
Official cmdlet references: https://learn.microsoft.com/powershell/module/exchangepowershell/
See Get-Mailbox, Get-CalendarProcessing, Get-MailboxPermission, Get-RecipientPermission,
Get-MailboxFolderStatistics, Get-MailboxFolderPermission, Get-DistributionGroup,
Get-DistributionGroupMember, Get-Recipient, Get-OrganizationConfig,
Get-ConnectionInformation, Connect-ExchangeOnline and Disconnect-ExchangeOnline.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [ValidateNotNullOrEmpty()][string]$RoomUpn = 'mtr@meetingrooms.ie',
    [string[]]$RoomListIdentity,
    [string]$AdminUpn,
    [switch]$UseExistingConnection,
    [guid]$ExpectedUserObjectId = [guid]::Empty,
    [ValidateSet('Before', 'After')][string]$Mode = 'Before',
    [string]$BaselinePath,
    [string]$ExportPath,
    [switch]$ForceExport,
    [switch]$Ascii,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReadOnlyCheck.Common.ps1')
$results = [System.Collections.Generic.List[object]]::new()
$ownedConnectionId = $null
$snapshot = [ordered]@{
    SchemaVersion = 1
    Producer = 'Test-RoomMailboxAndLists'
    TenantId = $TenantId.ToString().ToLowerInvariant()
    RoomUpn = $RoomUpn.Trim().ToLowerInvariant()
    Mode = $Mode
    CapturedAtUtc = [DateTime]::UtcNow.ToString('o')
    Mailbox = $null
    Calendar = $null
    Permissions = [ordered]@{ MailboxAccess = $null; SendAs = $null; Calendar = $null }
    RoomLists = @()
    RoomListDiscovery = [ordered]@{ Method = 'NotRun'; VisibleCount = 0; UnreadableCount = 0; ScopeValidated = $false }
}
$baseline = $null

function Add-Result {
    param([string]$Section, [string]$Name, [string]$Status, [string]$Detail, [object]$Evidence = $null)
    $results.Add((New-CheckResult -Section $Section -Name $Name -Status $Status -Detail $Detail -Evidence $Evidence))
}

function ConvertTo-NormalStrings {
    param([AllowNull()][object]$Value)
    # Canonicalize sets so a harmless reordering/casing change does not flag drift.
    @(@($Value) | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Sort-Object -Unique)
}

function New-FieldSnapshot {
    param([object]$Object, [string[]]$Names, [string[]]$ArrayNames = @())
    $data = [ordered]@{}
    $missing = [System.Collections.Generic.List[string]]::new()
    foreach ($name in $Names) {
        if (-not (Test-DataProperty -InputObject $Object -Name $name)) {
            $missing.Add($name)
            $data[$name] = $null
            continue
        }
        $value = Get-DataValue -InputObject $Object -Name $name
        if ($name -in $ArrayNames) { $data[$name] = @(ConvertTo-NormalStrings $value) }
        elseif ($null -eq $value) { $data[$name] = $null }
        elseif ($value -is [bool]) { $data[$name] = [bool]$value }
        elseif ($name -in @('ExternalDirectoryObjectId','ExchangeGuid','Guid','RecipientTypeDetails','UserPrincipalName','PrimarySmtpAddress','Alias')) { $data[$name] = ([string]$value).Trim().ToLowerInvariant() }
        else { $data[$name] = [string]$value }
    }
    [pscustomobject]@{ Data = [pscustomobject]$data; MissingProperties = @($missing.ToArray()) }
}

function Test-NonEmptyGuid {
    param([object]$Value)
    $parsed = [guid]::Empty
    [guid]::TryParse([string]$Value, [ref]$parsed) -and $parsed -ne [guid]::Empty
}

function Get-RecipientStamp {
    param([object]$Recipient)
    $id = [string](Get-DataValue -InputObject $Recipient -Name 'ExternalDirectoryObjectId')
    $guid = [string](Get-DataValue -InputObject $Recipient -Name 'Guid')
    $smtp = [string](Get-DataValue -InputObject $Recipient -Name 'PrimarySmtpAddress')
    $type = [string](Get-DataValue -InputObject $Recipient -Name 'RecipientTypeDetails')
    $identity = [string](Get-DataValue -InputObject $Recipient -Name 'Identity')
    [pscustomobject]@{
        ExternalDirectoryObjectId = $id.Trim().ToLowerInvariant()
        Guid = $guid.Trim().ToLowerInvariant()
        PrimarySmtpAddress = $smtp.Trim().ToLowerInvariant()
        RecipientTypeDetails = $type.Trim().ToLowerInvariant()
        Identity = $identity
        StableEntraId = (Test-NonEmptyGuid $id)
    }
}

function ConvertTo-RecipientKeys {
    param([object[]]$Recipients)
    @(@($Recipients) | ForEach-Object {
        $r = $_
        "id=$($r.ExternalDirectoryObjectId);guid=$($r.Guid);smtp=$($r.PrimarySmtpAddress);type=$($r.RecipientTypeDetails)"
    } | Sort-Object -Unique)
}

function Read-PermissionSet {
    param([string]$Name, [scriptblock]$Reader, [string]$PrincipalName, [string[]]$ExtraNames)
    try {
        $rows = @(& $Reader)
        $keys = [System.Collections.Generic.List[string]]::new()
        $complete = $true
        foreach ($row in $rows) {
            $principal = [string](Get-DataValue -InputObject $row -Name $PrincipalName)
            if ([string]::IsNullOrWhiteSpace($principal) -or -not (Test-DataProperty -InputObject $row -Name 'AccessRights')) { $complete = $false }
            $parts = @("principal=$($principal.Trim().ToLowerInvariant())", "rights=$((ConvertTo-NormalStrings (Get-DataValue -InputObject $row -Name 'AccessRights')) -join ',')")
            foreach ($field in $ExtraNames) {
                if (-not (Test-DataProperty -InputObject $row -Name $field)) { $complete = $false }
                $parts += "$field=$((ConvertTo-NormalStrings (Get-DataValue -InputObject $row -Name $field)) -join ',')"
            }
            $keys.Add(($parts -join ';'))
        }
        $status = if ($complete -and $rows.Count -gt 0) { 'Pass' } else { 'Review' }
        Add-Result 'Permissions' $Name $status "$($rows.Count) permission entries read. Empty or incomplete responses require review; this is a preservation baseline, not a recommendation to grant access."
        [pscustomobject]@{ ReadComplete = $complete; Keys = @($keys.ToArray() | Sort-Object -Unique); Count = $rows.Count }
    }
    catch {
        Add-Result 'Permissions' $Name 'Unknown' "Read failed. Check Exchange RBAC and retry: $(Get-SafeErrorText $_)"
        [pscustomobject]@{ ReadComplete = $false; Keys = @(); Count = 0 }
    }
}

function Compare-FieldSnapshot {
    param([string]$Label, [object]$Old, [object]$New, [string[]]$Names)
    if ($null -eq $Old -or $null -eq $New) {
        Add-Result 'Baseline comparison' $Label 'Unknown' 'Before or current snapshot is absent. No preservation conclusion is possible.'
        return
    }
    $oldData = Get-DataValue -InputObject $Old -Name 'Data'
    $newData = Get-DataValue -InputObject $New -Name 'Data'
    $oldMissing = Get-DataValue -InputObject $Old -Name 'MissingProperties'
    $newMissing = Get-DataValue -InputObject $New -Name 'MissingProperties'
    foreach ($name in $Names) {
        if ($name -in $oldMissing -or $name -in $newMissing -or -not (Test-DataProperty -InputObject $oldData -Name $name) -or -not (Test-DataProperty -InputObject $newData -Name $name)) {
            Add-Result 'Baseline comparison' "$Label / $name" 'Unknown' 'Property was not returned in one snapshot. Missing evidence does not count as unchanged.'
            continue
        }
        $oldValue = Get-DataValue -InputObject $oldData -Name $name
        $newValue = Get-DataValue -InputObject $newData -Name $name
        if (($null -eq $oldValue -or $null -eq $newValue) -and $name -in @('ExternalDirectoryObjectId','ExchangeGuid','Guid','RecipientTypeDetails','UserPrincipalName','PrimarySmtpAddress','HiddenFromAddressListsEnabled','AutomateProcessing')) {
            Add-Result 'Baseline comparison' "$Label / $name" 'Unknown' 'An essential value is null. Missing evidence does not count as preserved.'
            continue
        }
        # Values already canonicalized at capture; serialized JSON preserves scalar/array types.
        $same = (ConvertTo-Json -InputObject $oldValue -Depth 20 -Compress) -ceq (ConvertTo-Json -InputObject $newValue -Depth 20 -Compress)
        $status = if ($same) { 'Pass' } else { 'Action' }
        $detail = if ($same) { 'Value preserved.' } else { 'Value changed. Reconcile the difference against the approved migration before accepting the result.' }
        Add-Result 'Baseline comparison' "$Label / $name" $status $detail ([pscustomobject]@{ Before = $oldValue; Current = $newValue })
    }
}

try {
    if ($TenantId -eq [guid]::Empty) { throw 'TenantId must be the expected non-empty tenant GUID.' }
    if ($RoomUpn -notmatch '^[^\s@]+@[^\s@]+\.[^\s@]+$') { throw 'RoomUpn must be a full sign-in address.' }
    if ($RoomListIdentity) {
        foreach ($identity in $RoomListIdentity) {
            if ([string]::IsNullOrWhiteSpace($identity) -or $identity.Contains('*')) { throw 'RoomListIdentity must contain explicit non-empty identities, without wildcards.' }
        }
    }
    if ($ForceExport -and -not $ExportPath) { throw 'ForceExport requires ExportPath.' }
    if ($ExportPath) {
        $exportFullPath = [System.IO.Path]::GetFullPath($ExportPath)
        if ((Test-Path -LiteralPath $exportFullPath) -and -not $ForceExport) { throw 'ExportPath already exists. Choose a new path or explicitly use ForceExport.' }
        if (-not (Test-Path -LiteralPath ([System.IO.Path]::GetDirectoryName($exportFullPath)) -PathType Container)) { throw 'The ExportPath parent directory must already exist.' }
        if ($BaselinePath -and $exportFullPath -eq [System.IO.Path]::GetFullPath($BaselinePath)) { throw 'ExportPath must not overwrite the baseline, even with ForceExport.' }
    }
    if ($BaselinePath) {
        $baseline = Get-Content -LiteralPath $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        if ((Get-DataValue -InputObject $baseline -Name 'Producer') -ne 'Test-RoomMailboxAndLists' -or (Get-DataValue -InputObject $baseline -Name 'SchemaVersion') -ne 1) { throw 'Baseline format is not a supported Exchange preflight snapshot.' }
        if ((Get-DataValue -InputObject $baseline -Name 'TenantId') -ne $TenantId.ToString() -or (Get-DataValue -InputObject $baseline -Name 'RoomUpn') -ne $RoomUpn.Trim()) { throw 'Baseline tenant or room differs from the requested target.' }
        if ((Get-DataValue -InputObject $baseline -Name 'Mode') -ne 'Before') { throw 'BaselinePath must point to a Before snapshot.' }
        Add-Result 'Baseline' 'Target binding' 'Pass' 'Baseline tenant, room and format match.'
    }
    elseif ($Mode -eq 'After') { Add-Result 'Baseline' 'Preservation evidence' 'Review' 'After mode needs a Before snapshot to prove identity/configuration preservation. Supply BaselinePath.' }

    $available = @(Get-Module -ListAvailable -Name ExchangeOnlineManagement | Where-Object Version -ge ([version]'3.2.0') | Sort-Object Version -Descending)
    if ($available.Count -eq 0) { throw 'ExchangeOnlineManagement 3.2.0+ is required. Install/update it separately, then rerun.' }
    Import-Module $available[0].Path -ErrorAction Stop
    Add-Result 'Connection' 'Exchange module' 'Pass' "ExchangeOnlineManagement $($available[0].Version) is available."
    $existing = @(Get-ConnectionInformation -ErrorAction Stop)
    $legacy = @(Get-PSSession -ErrorAction Stop | Where-Object { $_.ConfigurationName -eq 'Microsoft.Exchange' })
    if ($legacy.Count -gt 0) { throw 'A legacy Exchange remote session exists. Use a clean PowerShell process; the script will not replace or disconnect that session.' }
    if ($UseExistingConnection) {
        if ($existing.Count -ne 1) { throw 'UseExistingConnection requires exactly one Exchange REST session in this process. Use a clean shell if the connection is ambiguous.' }
    }
    else {
        if ($existing.Count -gt 0) { throw 'An Exchange REST session already exists. Explicitly use UseExistingConnection, or start a clean PowerShell process.' }
        if ([string]::IsNullOrWhiteSpace($AdminUpn)) { throw 'Supply AdminUpn for delegated sign-in, or explicitly reuse a validated session with UseExistingConnection.' }
        Connect-ExchangeOnline -UserPrincipalName $AdminUpn -ShowBanner:$false -ErrorAction Stop
        $existing = @(Get-ConnectionInformation -ErrorAction Stop)
        if ($existing.Count -eq 1) { $ownedConnectionId = [string](Get-DataValue -InputObject $existing[0] -Name 'ConnectionId') }
        if ($existing.Count -ne 1) { throw 'The newly opened connection is ambiguous. No mailbox or RoomList reads were attempted.' }
    }
    $connection = $existing[0]
    if ((Get-DataValue -InputObject $connection -Name 'State') -ne 'Connected' -or (Get-DataValue -InputObject $connection -Name 'TokenStatus') -ne 'Active') { throw 'Exchange REST session is not connected with an active token.' }
    if (-not (Test-DataProperty -InputObject $connection -Name 'IsEopSession') -or (Get-DataValue -InputObject $connection -Name 'IsEopSession') -ne $false) { throw 'Session cannot be verified as an Exchange Online session rather than Security & Compliance.' }
    if (-not [string]::IsNullOrEmpty([string](Get-DataValue -InputObject $connection -Name 'ModulePrefix'))) { throw 'Prefixed Exchange sessions are not supported. Use a clean unprefixed session.' }
    if ((Get-DataValue -InputObject $connection -Name 'TenantID') -ne $TenantId.ToString()) { throw 'The connected Exchange tenant ID does not match TenantId. No room reads were attempted.' }
    $organizations = @(Get-OrganizationConfig -ErrorAction Stop)
    if ($organizations.Count -ne 1) { throw 'Get-OrganizationConfig did not return exactly one organization.' }
    $orgId = [string](Get-DataValue -InputObject $organizations[0] -Name 'ExternalDirectoryOrganizationId')
    if (-not (Test-NonEmptyGuid $orgId) -or $orgId -ne $TenantId.ToString()) { throw 'Exchange organization tenant binding is missing or mismatched (ExternalDirectoryOrganizationId). No room reads were attempted.' }
    Add-Result 'Connection' 'Expected tenant' 'Pass' "Connection and organization both match tenant $TenantId."

    $mailboxes = @(Get-Mailbox -Identity $RoomUpn -ErrorAction Stop)
    if ($mailboxes.Count -ne 1) { throw 'Room lookup did not return exactly one mailbox. No unbounded follow-up reads will be made.' }
    $mailbox = $mailboxes[0]
    $mailboxNames = @('ExternalDirectoryObjectId','ExchangeGuid','Guid','RecipientTypeDetails','UserPrincipalName','PrimarySmtpAddress','Alias','EmailAddresses','LegacyExchangeDN','HiddenFromAddressListsEnabled','GrantSendOnBehalfTo','ForwardingAddress','ForwardingSmtpAddress','DeliverToMailboxAndForward','ResourceCapacity')
    $mailboxArrays = @('EmailAddresses','GrantSendOnBehalfTo')
    $snapshot.Mailbox = New-FieldSnapshot $mailbox $mailboxNames $mailboxArrays
    $mailboxId = [string](Get-DataValue -InputObject $mailbox -Name 'ExternalDirectoryObjectId')
    $mailboxGuid = [string](Get-DataValue -InputObject $mailbox -Name 'ExchangeGuid')
    $mailboxType = [string](Get-DataValue -InputObject $mailbox -Name 'RecipientTypeDetails')
    $mailboxSmtp = [string](Get-DataValue -InputObject $mailbox -Name 'PrimarySmtpAddress')
    $mailboxUpn = [string](Get-DataValue -InputObject $mailbox -Name 'UserPrincipalName')
    if ($mailboxType -eq 'RoomMailbox') { Add-Result 'Mailbox' 'Recipient type' 'Pass' 'Existing Exchange Online recipient is a RoomMailbox.' }
    elseif ([string]::IsNullOrWhiteSpace($mailboxType)) { Add-Result 'Mailbox' 'Recipient type' 'Unknown' 'RecipientTypeDetails was not returned.' }
    else { Add-Result 'Mailbox' 'Recipient type' 'Action' "Expected RoomMailbox; received $mailboxType. Resolve before migration." }
    if (Test-NonEmptyGuid $mailboxGuid) { Add-Result 'Mailbox' 'Exchange GUID' 'Pass' "Existing mailbox GUID captured: $mailboxGuid." }
    else { Add-Result 'Mailbox' 'Exchange GUID' 'Unknown' 'A valid, non-empty ExchangeGuid was not returned; mailbox preservation cannot be bound.' }
    if (Test-NonEmptyGuid $mailboxId) { Add-Result 'Mailbox' 'Entra object ID' 'Pass' "Mailbox ExternalDirectoryObjectId captured: $mailboxId." }
    else { Add-Result 'Mailbox' 'Entra object ID' 'Unknown' 'ExternalDirectoryObjectId is missing or invalid.' }
    if ($ExpectedUserObjectId -eq [guid]::Empty) { Add-Result 'Mailbox' 'Cross-check Entra identity' 'Review' 'Supply ExpectedUserObjectId from the Entra preflight to bind both checks to the same object.' }
    elseif ($mailboxId -eq $ExpectedUserObjectId.ToString()) { Add-Result 'Mailbox' 'Cross-check Entra identity' 'Pass' 'Mailbox Entra object ID matches the supplied user object ID.' }
    else { Add-Result 'Mailbox' 'Cross-check Entra identity' 'Action' 'Mailbox Entra object ID differs from ExpectedUserObjectId. Stop and resolve the target mismatch.' }
    $emailAddressValues = Get-DataValue -InputObject $mailbox -Name 'EmailAddresses'
    $emailAddresses = @($emailAddressValues | ForEach-Object { [string]$_ })
    $addressMatches = @($emailAddresses | Where-Object { $_ -ieq "smtp:$RoomUpn" }).Count -gt 0
    if ($mailboxUpn -ieq $RoomUpn -and $addressMatches -and -not [string]::IsNullOrWhiteSpace($mailboxSmtp)) { Add-Result 'Mailbox' 'Sign-in and booking address' 'Pass' "UPN is $mailboxUpn; address is on this mailbox; primary SMTP is $mailboxSmtp." }
    else { Add-Result 'Mailbox' 'Sign-in and booking address' 'Action' 'The supplied room address does not match a returned UPN/address baseline. Review aliases and identify the exact account before migration.' }
    if ($snapshot.Mailbox.MissingProperties.Count -gt 0) { Add-Result 'Mailbox' 'Baseline properties' 'Unknown' "Properties omitted: $($snapshot.Mailbox.MissingProperties -join ', '). Check RBAC/module output." }
    else { Add-Result 'Mailbox' 'Baseline properties' 'Pass' 'Identity, aliases, visibility, capacity, forwarding and Send on Behalf values captured for comparison.' }
    $syncState = Get-DataValue -InputObject $mailbox -Name 'IsDirSynced'
    if ($syncState -is [bool]) {
        Add-Result 'Mailbox' 'Exchange directory-sync projection' 'Review' "IsDirSynced=$syncState. This Exchange projection does not prove Entra SOA state or transfer eligibility; use the Entra preflight."
    }
    else { Add-Result 'Mailbox' 'Exchange directory-sync projection' 'Unknown' 'IsDirSynced was omitted/null. Do not interpret missing sync metadata as cloud-only.' }

    $calendarNames = @('AutomateProcessing','AllowConflicts','BookingWindowInDays','MaximumDurationInMinutes','MinimumDurationInMinutes','EnforceSchedulingHorizon','ScheduleOnlyDuringWorkHours','AllowRecurringMeetings','AllBookInPolicy','AllRequestInPolicy','AllRequestOutOfPolicy','BookInPolicy','RequestInPolicy','RequestOutOfPolicy','ResourceDelegates','ForwardRequestsToDelegates','ProcessExternalMeetingMessages','DeleteSubject','AddOrganizerToSubject','DeleteComments','DeleteAttachments','RemovePrivateProperty','AddAdditionalResponse','AdditionalResponse','EnableResponseDetails','ConflictPercentageAllowed','MaximumConflictInstances')
    $calendarArrays = @('BookInPolicy','RequestInPolicy','RequestOutOfPolicy','ResourceDelegates')
    try {
        $calendarRows = @(Get-CalendarProcessing -Identity $RoomUpn -ErrorAction Stop)
        if ($calendarRows.Count -ne 1) { throw 'Calendar processing did not return exactly one resource.' }
        $snapshot.Calendar = New-FieldSnapshot $calendarRows[0] $calendarNames $calendarArrays
        $automation = [string](Get-DataValue -InputObject $calendarRows[0] -Name 'AutomateProcessing')
        if ($automation -eq 'AutoAccept') { Add-Result 'Booking' 'Calendar processing' 'Pass' 'AutoAccept is set. Preserve the existing policy; a live test must confirm booking behavior.' }
        elseif ([string]::IsNullOrWhiteSpace($automation)) { Add-Result 'Booking' 'Calendar processing' 'Unknown' 'AutomateProcessing was not returned.' }
        else { Add-Result 'Booking' 'Calendar processing' 'Review' "AutomateProcessing=$automation. Confirm this matches the intended booking/delegate workflow; SOA transfer alone should not change it." }
        if ($snapshot.Calendar.MissingProperties.Count -gt 0) { Add-Result 'Booking' 'Policy and delegates baseline' 'Unknown' "Calendar properties omitted: $($snapshot.Calendar.MissingProperties -join ', ')." }
        else { Add-Result 'Booking' 'Policy and delegates baseline' 'Pass' 'Booking restrictions, delegates and meeting-content processing settings captured.' }
    }
    catch { Add-Result 'Booking' 'Calendar processing read' 'Unknown' "Read failed; migration validation is incomplete: $(Get-SafeErrorText $_)" }
    $snapshot.Permissions.MailboxAccess = Read-PermissionSet 'Mailbox access baseline' { Get-MailboxPermission -Identity $RoomUpn -ResultSize Unlimited -ErrorAction Stop } 'User' @('Deny','IsInherited')
    $snapshot.Permissions.SendAs = Read-PermissionSet 'Send As baseline' { Get-RecipientPermission -Identity $RoomUpn -ResultSize Unlimited -ErrorAction Stop } 'Trustee' @('AccessControlType','IsInherited')
    try {
        $folders = @(Get-MailboxFolderStatistics -Identity $RoomUpn -FolderScope Calendar -ResultSize Unlimited -ErrorAction Stop | Where-Object { (Get-DataValue -InputObject $_ -Name 'FolderType') -eq 'Calendar' })
        if ($folders.Count -ne 1) { throw 'Could not identify exactly one default calendar folder. No localized folder name was assumed.' }
        $folderPath = [string](Get-DataValue -InputObject $folders[0] -Name 'FolderPath')
        if (-not $folderPath.StartsWith('/')) { throw 'Default calendar FolderPath was not returned in the expected form.' }
        $calendarIdentity = $RoomUpn + ':' + $folderPath.Replace('/', '\')
        $snapshot.Permissions.Calendar = Read-PermissionSet 'Calendar folder permissions' { Get-MailboxFolderPermission -Identity $calendarIdentity -ResultSize Unlimited -ErrorAction Stop } 'User' @('SharingPermissionFlags')
    }
    catch { Add-Result 'Permissions' 'Calendar folder permissions' 'Unknown' "Read failed: $(Get-SafeErrorText $_)" }

    $groups = [System.Collections.Generic.List[object]]::new()
    $useExplicit = $RoomListIdentity -and $RoomListIdentity.Count -gt 0
    # In After mode, always reread baseline groups even if room membership disappeared.
    $identitiesToRead = @($RoomListIdentity | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    if ($baseline) {
        $baselineLists = Get-DataValue -InputObject $baseline -Name 'RoomLists'
        foreach ($oldList in $baselineLists) {
            $oldData = Get-DataValue -InputObject $oldList -Name 'Data'
            $oldId = [string](Get-DataValue -InputObject $oldData -Name 'ExternalDirectoryObjectId')
            if (-not (Test-NonEmptyGuid $oldId)) { $oldId = [string](Get-DataValue -InputObject $oldData -Name 'PrimarySmtpAddress') }
            if (-not [string]::IsNullOrWhiteSpace($oldId)) { $identitiesToRead += $oldId }
        }
    }
    if ($identitiesToRead.Count -gt 0) {
        $snapshot.RoomListDiscovery.Method = 'ExplicitAndBaseline'
        foreach ($identity in @($identitiesToRead | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)) {
            try {
                $matched = @(Get-DistributionGroup -Identity $identity -ErrorAction Stop)
                if ($matched.Count -ne 1) { throw 'Identity did not resolve to exactly one distribution group.' }
                $groups.Add($matched[0])
            }
            catch { $snapshot.RoomListDiscovery.UnreadableCount++; Add-Result 'RoomLists' "Lookup $identity" 'Unknown' "Group read failed or is not visible to this administrator: $(Get-SafeErrorText $_)" }
        }
    }
    else {
        $snapshot.RoomListDiscovery.Method = 'VisibleRoomListsContainingRoom'
        try {
            foreach ($group in @(Get-DistributionGroup -RecipientTypeDetails RoomList -ResultSize Unlimited -ErrorAction Stop)) { $groups.Add($group) }
        }
        catch { $snapshot.RoomListDiscovery.UnreadableCount++; Add-Result 'RoomLists' 'Discovery' 'Unknown' "RoomList discovery failed: $(Get-SafeErrorText $_)" }
    }
    $snapshot.RoomListDiscovery.VisibleCount = $groups.Count
    Add-Result 'RoomLists' 'Discovery scope' 'Review' 'Exchange results follow your recipient/RBAC scope. Confirm scope covers all relevant RoomLists, or rerun with the known RoomListIdentity values. A successful/empty discovery is not proof of no dependencies.'
    $listSnapshots = [System.Collections.Generic.List[object]]::new()
    $seenGroups = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $groupNames = @('ExternalDirectoryObjectId','Guid','RecipientTypeDetails','Name','DisplayName','Alias','PrimarySmtpAddress','EmailAddresses','LegacyExchangeDN','HiddenFromAddressListsEnabled','RequireSenderAuthenticationEnabled','MemberJoinRestriction','MemberDepartRestriction','ModerationEnabled','ModeratedBy','BypassModerationFromSendersOrMembers','SendModerationNotifications','AcceptMessagesOnlyFromSendersOrMembers','RejectMessagesFromSendersOrMembers','GrantSendOnBehalfTo')
    $groupArrays = @('EmailAddresses','ModeratedBy','BypassModerationFromSendersOrMembers','AcceptMessagesOnlyFromSendersOrMembers','RejectMessagesFromSendersOrMembers','GrantSendOnBehalfTo')
    foreach ($group in $groups) {
        $groupId = [string](Get-DataValue -InputObject $group -Name 'ExternalDirectoryObjectId')
        $groupSmtp = [string](Get-DataValue -InputObject $group -Name 'PrimarySmtpAddress')
        $identity = [string](Get-DataValue -InputObject $group -Name 'Identity')
        $lookup = if (Test-NonEmptyGuid $groupId) { $groupId } elseif (-not [string]::IsNullOrWhiteSpace($groupSmtp)) { $groupSmtp } else { $identity }
        if ([string]::IsNullOrWhiteSpace($lookup)) { Add-Result 'RoomLists' 'Group identity' 'Unknown' 'A group lacks a safe lookup identity. It was not passed to another cmdlet.'; continue }
        if (-not $seenGroups.Add($lookup)) { continue }
        $members = @()
        $memberReadComplete = $false
        try {
            $memberRows = @(Get-DistributionGroupMember -Identity $lookup -ResultSize Unlimited -ErrorAction Stop)
            $members = @($memberRows | ForEach-Object { Get-RecipientStamp $_ })
            $memberReadComplete = $true
        }
        catch { $snapshot.RoomListDiscovery.UnreadableCount++; Add-Result 'RoomLists' "$lookup / member read" 'Unknown' "Membership is unreadable; do not assume an empty list: $(Get-SafeErrorText $_)" }
        $hasRoom = @($members | Where-Object {
            ((Test-NonEmptyGuid $mailboxId) -and $_.ExternalDirectoryObjectId -eq $mailboxId) -or
            (-not [string]::IsNullOrWhiteSpace($mailboxSmtp) -and $_.PrimarySmtpAddress -ieq $mailboxSmtp)
        }).Count -gt 0
        # Discovery reports containing lists; unreadable lists still produce Unknown above.
        if (-not $useExplicit -and -not $baseline -and $memberReadComplete -and -not $hasRoom) { continue }
        $section = "RoomList $lookup"
        $list = New-FieldSnapshot $group $groupNames $groupArrays
        $owners = [System.Collections.Generic.List[object]]::new()
        $ownerReadComplete = Test-DataProperty -InputObject $group -Name 'ManagedBy'
        $ownerReferences = Get-DataValue -InputObject $group -Name 'ManagedBy'
        foreach ($ownerIdentity in $ownerReferences) {
            try {
                if ([string]::IsNullOrWhiteSpace([string]$ownerIdentity)) { throw 'A blank owner reference was returned.' }
                $ownerRows = @(Get-Recipient -Identity ([string]$ownerIdentity) -ErrorAction Stop)
                if ($ownerRows.Count -ne 1) { throw 'Owner did not resolve to exactly one recipient.' }
                $owners.Add((Get-RecipientStamp $ownerRows[0]))
            }
            catch { $ownerReadComplete = $false; Add-Result $section 'Owner resolution' 'Unknown' "Owner reference could not be resolved: $(Get-SafeErrorText $_)" }
        }
        $data = [ordered]@{}
        foreach ($prop in $list.Data.PSObject.Properties) { $data[$prop.Name] = $prop.Value }
        $data.Owners = @(ConvertTo-RecipientKeys $owners.ToArray())
        $data.Members = @(ConvertTo-RecipientKeys $members)
        $list.Data = [pscustomobject]$data
        $list | Add-Member -NotePropertyName MemberReadComplete -NotePropertyValue $memberReadComplete
        $list | Add-Member -NotePropertyName OwnerReadComplete -NotePropertyValue $ownerReadComplete
        $list | Add-Member -NotePropertyName IsDirSynced -NotePropertyValue (Get-DataValue -InputObject $group -Name 'IsDirSynced')
        $list | Add-Member -NotePropertyName MemberDetails -NotePropertyValue @($members)
        $list | Add-Member -NotePropertyName OwnerDetails -NotePropertyValue @($owners.ToArray())
        $listSnapshots.Add($list)
        $type = [string](Get-DataValue -InputObject $group -Name 'RecipientTypeDetails')
        if ($type -eq 'RoomList') { Add-Result $section 'RoomList subtype' 'Pass' 'Exchange subtype is RoomList.' }
        elseif ([string]::IsNullOrWhiteSpace($type)) { Add-Result $section 'RoomList subtype' 'Unknown' 'RecipientTypeDetails was omitted.' }
        else { Add-Result $section 'RoomList subtype' 'Action' "Subtype is $type. Confirm/restore RoomList behavior through a separately approved change." }
        if (Test-NonEmptyGuid $groupId) { Add-Result $section 'Entra group identity' 'Pass' "Existing Entra group ID captured: $groupId." }
        else { Add-Result $section 'Entra group identity' 'Unknown' 'ExternalDirectoryObjectId is missing/invalid; do not build a Graph SOA request from an SMTP address or name.' }
        if ($memberReadComplete -and $members.Count -gt 0) {
            if (@($members | Where-Object { $_.RecipientTypeDetails -ne 'roommailbox' }).Count -gt 0) { Add-Result $section 'Member types' 'Action' 'The list contains non-RoomMailbox recipients. Review all members before transfer.' }
            else { Add-Result $section 'Member types' 'Pass' "$($members.Count) room mailbox members read." }
            if (@($members | Where-Object { -not $_.StableEntraId -or [string]::IsNullOrWhiteSpace($_.PrimarySmtpAddress) }).Count -gt 0) { Add-Result $section 'Member IDs and addresses' 'Review' 'Some members lack a stable Entra object ID or SMTP address. Resolve exact identities before acceptance.' }
            else { Add-Result $section 'Member IDs and addresses' 'Pass' 'All members have stable Entra IDs and SMTP addresses captured.' }
            if ($hasRoom) { Add-Result $section 'Target room membership' 'Pass' "$RoomUpn is a direct member." }
            else { Add-Result $section 'Target room membership' 'Review' 'This explicit/baseline list does not contain the target room. Baseline comparison determines whether membership was lost.' }
        }
        elseif ($memberReadComplete) { Add-Result $section 'Membership' 'Action' 'The RoomList is empty. An empty result cannot demonstrate a usable list or preserved room membership.' }
        if ($ownerReadComplete -and $owners.Count -gt 0 -and @($owners.ToArray() | Where-Object { -not $_.StableEntraId }).Count -eq 0) { Add-Result $section 'Owners' 'Pass' "$($owners.Count) owner identities resolved." }
        else { Add-Result $section 'Owners' 'Review' 'Owners are empty, unreadable or lack stable Entra IDs. Confirm cloud management ownership before transfer.' }
        $hidden = Get-DataValue -InputObject $group -Name 'HiddenFromAddressListsEnabled'
        if ($hidden -isnot [bool]) { Add-Result $section 'Address-list visibility' 'Unknown' 'HiddenFromAddressListsEnabled was omitted/null.' }
        elseif ($hidden) { Add-Result $section 'Address-list visibility' 'Review' 'The RoomList is hidden. Confirm intended behavior and Room Finder visibility manually.' }
        else { Add-Result $section 'Address-list visibility' 'Pass' 'The group is not hidden from address lists. Room Finder still requires a client test.' }
        $synced = Get-DataValue -InputObject $group -Name 'IsDirSynced'
        if ($synced -isnot [bool]) { Add-Result $section 'Management classification' 'Unknown' 'IsDirSynced was omitted/null. Authority/eligibility remains unproven.' }
        elseif ($synced) { Add-Result $section 'Management classification' 'Review' 'Exchange reports a synchronized group. Use its exact Entra ID for a separate Group SOA/RoomList support pilot; this script proves no transfer eligibility.' }
        else { Add-Result $section 'Management classification' 'Pass' 'Exchange reports IsDirSynced=False. Corroborate Group SOA state and verify supported cloud management before declaring migration complete.' }
        if ($list.MissingProperties.Count -gt 0) { Add-Result $section 'Baseline properties' 'Unknown' "Group properties omitted: $($list.MissingProperties -join ', ')." }
        else { Add-Result $section 'Baseline properties' 'Pass' 'Group identity, addresses, delivery/moderation restrictions and visibility captured.' }
    }
    $snapshot.RoomLists = @($listSnapshots.ToArray())
    if ($snapshot.RoomLists.Count -eq 0) { Add-Result 'RoomLists' 'Target dependency discovery' 'Review' 'No containing RoomList was captured. Confirm the room truly has no dependency using a known list inventory and adequate RBAC; this is not a green migration gate.' }

    if ($baseline) {
        Compare-FieldSnapshot 'Mailbox' (Get-DataValue -InputObject $baseline -Name 'Mailbox') $snapshot.Mailbox $mailboxNames
        Compare-FieldSnapshot 'Calendar policy' (Get-DataValue -InputObject $baseline -Name 'Calendar') $snapshot.Calendar $calendarNames
        $oldPermissions = Get-DataValue -InputObject $baseline -Name 'Permissions'
        foreach ($permissionName in @('MailboxAccess','SendAs','Calendar')) {
            $oldPerm = Get-DataValue -InputObject $oldPermissions -Name $permissionName
            $newPerm = $snapshot.Permissions[$permissionName]
            if ($null -eq $oldPerm -or $null -eq $newPerm -or (Get-DataValue -InputObject $oldPerm -Name 'ReadComplete') -ne $true -or (Get-DataValue -InputObject $newPerm -Name 'ReadComplete') -ne $true) { Add-Result 'Baseline comparison' "$permissionName permissions" 'Unknown' 'One permission read was incomplete. No unchanged conclusion can be made.'; continue }
            $oldKeyValues = Get-DataValue -InputObject $oldPerm -Name 'Keys'
            $newKeyValues = Get-DataValue -InputObject $newPerm -Name 'Keys'
            $oldKeys = @($oldKeyValues | Sort-Object -Unique)
            $newKeys = @($newKeyValues | Sort-Object -Unique)
            $same = (ConvertTo-Json -InputObject $oldKeys -Compress) -ceq (ConvertTo-Json -InputObject $newKeys -Compress)
            $status = if ($same) { 'Pass' } else { 'Action' }
            Add-Result 'Baseline comparison' "$permissionName permissions" $status $(if ($same) { 'Permission baseline preserved.' } else { 'Permission baseline changed; review before acceptance.' })
        }
        $baselineLists = Get-DataValue -InputObject $baseline -Name 'RoomLists'
        foreach ($oldList in $baselineLists) {
            $oldData = Get-DataValue -InputObject $oldList -Name 'Data'
            $oldId = [string](Get-DataValue -InputObject $oldData -Name 'ExternalDirectoryObjectId')
            if (-not (Test-NonEmptyGuid $oldId)) { Add-Result 'Baseline comparison' 'RoomList identity' 'Unknown' 'A baseline list has no valid Entra ID; exact object preservation cannot be proven.'; continue }
            $current = @($snapshot.RoomLists | Where-Object { (Get-DataValue -InputObject $_.Data -Name 'ExternalDirectoryObjectId') -eq $oldId })
            if ($current.Count -ne 1) { Add-Result 'Baseline comparison' "RoomList $oldId" 'Action' 'The same Entra group object was not captured. Resolve lookup/visibility errors or an object replacement before accepting migration.'; continue }
            Compare-FieldSnapshot "RoomList $oldId" $oldList $current[0] $groupNames
            foreach ($relation in @('Members','Owners')) {
                $completeName = if ($relation -eq 'Members') { 'MemberReadComplete' } else { 'OwnerReadComplete' }
                if ((Get-DataValue -InputObject $oldList -Name $completeName) -ne $true -or (Get-DataValue -InputObject $current[0] -Name $completeName) -ne $true) { Add-Result 'Baseline comparison' "RoomList $oldId / $relation" 'Unknown' 'One relation read is incomplete. No preservation conclusion is possible.'; continue }
                $oldRelation = Get-DataValue -InputObject $oldData -Name $relation
                $newRelation = Get-DataValue -InputObject $current[0].Data -Name $relation
                if (@($oldRelation).Count -eq 0 -and @($newRelation).Count -eq 0) { Add-Result 'Baseline comparison' "RoomList $oldId / $relation" 'Review' 'Both captures are empty. This does not demonstrate a usable or properly owned RoomList.'; continue }
                Compare-FieldSnapshot "RoomList $oldId" $oldList $current[0] @($relation)
            }
        }
    }
    Add-Result 'Manual acceptance' 'Room Finder and booking' 'Review' 'Before and after migration: verify this list in Outlook/OWA Room Finder, existing bookings and a new test booking. PowerShell configuration reads do not prove client behavior.'
    Add-Result 'Manual acceptance' 'Android passwordless room' 'Review' 'Confirm Teams Rooms Pro Management passwordless status and health, reboot, calendar/meeting join and paired panel behavior. Avoid full sign-out/reset, which removes the Android device-bound credential.'
}
catch { Add-Result 'Execution' 'Stopped or incomplete' 'Unknown' (Get-SafeErrorText $_) }
finally {
    if (-not [string]::IsNullOrWhiteSpace($ownedConnectionId)) {
        try { Disconnect-ExchangeOnline -ConnectionId $ownedConnectionId -Confirm:$false -ErrorAction Stop }
        catch { Add-Result 'Connection' 'Owned session cleanup' 'Review' "Could not close the session opened by this script: $(Get-SafeErrorText $_)" }
    }
}

if ($ExportPath -and $snapshot.Mailbox) {
    try {
        $snapshot.Results = @($results.ToArray())
        $json = ConvertTo-Json -InputObject $snapshot -Depth 40
        $fileMode = if ($ForceExport) { [System.IO.FileMode]::Create } else { [System.IO.FileMode]::CreateNew }
        $stream = [System.IO.File]::Open([System.IO.Path]::GetFullPath($ExportPath), $fileMode, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            $writer = [System.IO.StreamWriter]::new($stream, [System.Text.UTF8Encoding]::new($false))
            try { $writer.Write($json) } finally { $writer.Dispose() }
        }
        finally { $stream.Dispose() }
        Add-Result 'Export' 'Local snapshot' 'Pass' "JSON snapshot written to $([System.IO.Path]::GetFullPath($ExportPath)). Protect this file as administrative evidence."
    }
    catch { Add-Result 'Export' 'Local snapshot' 'Unknown' "Local export failed: $(Get-SafeErrorText $_)" }
}
elseif ($ExportPath) { Add-Result 'Export' 'Local snapshot' 'Review' 'No mailbox snapshot was captured, so no baseline file was written.' }

Write-CheckReport -Title "Exchange room and RoomLists: $RoomUpn ($Mode)" -Results $results.ToArray() -Ascii:$Ascii -PassThru:$PassThru
