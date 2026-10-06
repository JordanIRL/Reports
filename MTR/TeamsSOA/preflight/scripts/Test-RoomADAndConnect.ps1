#requires -Version 7.2
<#
.SYNOPSIS
Read-only AD and local Entra Connect evidence for a Teams Rooms SOA preflight.
.DESCRIPTION
Run on the Windows Entra Connect server with PowerShell 7.2 or later. Uses the
current Windows identity for AD reads; does not sign in to Graph, install a module,
start synchronization, change the scheduler, or change AD. Windows PowerShell
compatibility may be used to load the installed ActiveDirectory/ADSync modules.

An AD object being readable does not prove that it remains in Connect sync scope.
The scheduler settings do not prove that the last export was successful. Direct
memberOf groups omit the primary group and do not enumerate nested membership.
RoomList candidates must also be checked in Exchange Online with the companion
Exchange script. Pass means only that the particular observation was verified.

Version support information was checked against Microsoft Learn on 2026-10-06.
The script does not fetch a release table at runtime. After 30 days, a supported
version from this snapshot is Review rather than Pass until the table is refreshed.

.PARAMETER RoomListIdentity
Optional exact AD group distinguished names, object GUIDs, or sAMAccountNames.
Use the identities mapped from the Exchange Online RoomList inventory. Wildcard
and display-name discovery are intentionally avoided.
.PARAMETER PassThru
Also emit structured check objects; Evidence contains the relevant AD snapshots.
.EXAMPLE
./Test-RoomADAndConnect.ps1 -RoomUpn mtr@meetingrooms.ie -ADServer dc01.meetingrooms.ie
.EXAMPLE
./Test-RoomADAndConnect.ps1 -RoomListIdentity 'CN=Dublin Rooms,OU=Groups,DC=meetingrooms,DC=ie' -PassThru
.LINK
https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduser
.LINK
https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adgroup
.LINK
https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler
.LINK
https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history
.LINK
https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure
.LINK
https://learn.microsoft.com/en-us/exchange/troubleshoot/calendars/room-list-not-viewable-in-outlook
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$RoomUpn = 'mtr@meetingrooms.ie',
    [string]$ADServer,
    [string[]]$RoomListIdentity = @(),
    [switch]$Ascii,
    [switch]$PassThru
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReadOnlyCheck.Common.ps1')
$results = [System.Collections.Generic.List[object]]::new()

function Add-LocalCheck {
    param(
        [string]$Section,
        [string]$Name,
        [ValidateSet('Pass', 'Action', 'Review', 'Unknown')][string]$Status,
        [string]$Detail,
        [object]$Evidence
    )
    $results.Add((New-CheckResult -Section $Section -Name $Name -Status $Status -Detail $Detail -Evidence $Evidence))
}

function ConvertTo-LdapLiteral {
    param([Parameter(Mandatory)][string]$Value)
    # RFC 4515 escaping prevents a UPN from becoming an LDAP filter expression.
    $Value.Replace('\', '\5c').Replace('*', '\2a').Replace('(', '\28').Replace(')', '\29').Replace([string][char]0, '\00')
}

function Get-ADIdentifierValues {
    param([AllowNull()][object]$Values)
    # Get-DataValue preserves property arrays. Enumerate those values explicitly
    # before filtering; piping the property getter directly would treat an entire
    # member/memberOf array as one item.
    foreach ($value in $Values) {
        if (-not [string]::IsNullOrWhiteSpace([string]$value)) { [string]$value }
    }
}

function Get-ConnectVersionChecks {
    param(
        [AllowNull()][AllowEmptyString()][string]$VersionText,
        [string]$ProductName = 'Microsoft Entra Connect Sync',
        [AllowNull()][object]$Evidence,
        [datetime]$Today = (Get-Date).Date
    )
    $parsedVersion = $null
    if (-not [version]::TryParse($VersionText, [ref]$parsedVersion)) {
        New-CheckResult -Section 'Connect' -Name 'Installed product version' -Status 'Unknown' -Detail "Connect product version is missing or unparseable: '$VersionText'. Verify in Programs and Features." -Evidence $Evidence
        return
    }
    New-CheckResult -Section 'Connect' -Name 'Installed product version' -Status 'Pass' -Detail "Programs evidence: $ProductName $parsedVersion." -Evidence $Evidence
    if ($parsedVersion -ge [version]'2.5.76.0') {
        New-CheckResult -Section 'Connect' -Name 'User SOA feature minimum' -Status 'Pass' -Detail 'Version meets the documented User SOA feature minimum 2.5.76.0. Support and security status are separate checks.'
    }
    else {
        New-CheckResult -Section 'Connect' -Name 'User SOA feature minimum' -Status 'Action' -Detail 'Installed version is below the documented User SOA minimum 2.5.76.0. Upgrade through the approved Connect process before cutover.'
    }

    # Exact version table, not a guessed >= threshold for support status.
    $endOfSupport = @{
        '2.5.79.0'  = '2026-10-23'
        '2.5.190.0' = '2027-02-02'
        '2.6.1.0'   = '2027-03-10'
        '2.6.3.0'   = '2027-07-07'
        '2.6.84.0'  = '2027-09-16'
        '2.6.91.0'  = '2027-09-23'
        '2.6.92.0'  = $null
    }
    $versionText = $parsedVersion.ToString()
    $verifiedOn = [datetime]'2026-10-06'
    if ($endOfSupport.ContainsKey($versionText)) {
        $expiry = $endOfSupport[$versionText]
        if ($expiry -and $today -ge [datetime]$expiry) {
            New-CheckResult -Section 'Connect' -Name 'Known support status' -Status 'Action' -Detail "$versionText has reached its documented support end date $expiry. Check the current Microsoft release table and upgrade before cutover."
        }
        elseif ($today -lt $verifiedOn -or $today -gt $verifiedOn.AddDays(30)) {
            New-CheckResult -Section 'Connect' -Name 'Known support status' -Status 'Review' -Detail "$versionText was supported in the release table verified 2026-10-06. This snapshot is outside its 30-day freshness window; verify the current release table."
        }
        else {
            $until = if ($expiry) { "Support end recorded as $expiry." } else { 'No end date was listed for this latest release.' }
            New-CheckResult -Section 'Connect' -Name 'Known support status' -Status 'Pass' -Detail "$versionText is in the known supported table verified 2026-10-06. $until"
        }
        if ($versionText -ne '2.6.92.0') {
            New-CheckResult -Section 'Connect' -Name 'Latest security release' -Status 'Review' -Detail 'The latest release verified 2026-10-06 is 2.6.92.0 and includes security fixes. Review upgrade readiness; support alone does not mean latest.'
        }
    }
    elseif ($parsedVersion -le [version]'2.5.76.0') {
        New-CheckResult -Section 'Connect' -Name 'Known support status' -Status 'Action' -Detail "$versionText is retired in the release table verified 2026-10-06. The SOA feature minimum is not an acceptable support baseline."
    }
    else {
        New-CheckResult -Section 'Connect' -Name 'Known support status' -Status 'Review' -Detail "$versionText is not in the exact release table in this script. It may be a newer build; verify its current support status against Microsoft Learn."
    }
}

function Get-SchedulerSettingCheck {
    param([AllowNull()][object]$Scheduler, [Parameter(Mandatory)][hashtable]$Setting)
    $actual = Get-DataValue -InputObject $Scheduler -Name $Setting.Name
    if ($null -eq $actual -or $actual -isnot [bool]) {
        New-CheckResult -Section 'Connect' -Name $Setting.Label -Status 'Unknown' -Detail "$($Setting.Name) is unavailable or is not a Boolean. Inspect Get-ADSyncScheduler on the active server."
    }
    elseif ($actual -eq $Setting.Expected) {
        New-CheckResult -Section 'Connect' -Name $Setting.Label -Status 'Pass' -Detail "$($Setting.Name)=$actual."
    }
    else {
        New-CheckResult -Section 'Connect' -Name $Setting.Label -Status $Setting.BadStatus -Detail $Setting.BadDetail
    }
}

function Import-LocalReadModule {
    param([Parameter(Mandatory)][string]$Name)
    try {
        if (-not (Get-Module -ListAvailable -Name $Name)) {
            Add-LocalCheck -Section 'Local prerequisites' -Name "$Name module" -Status 'Action' -Detail "The installed $Name module is not discoverable. Use the correct Connect server / installed RSAT AD tools; this script does not install anything."
            return $false
        }
        try {
            Import-Module -Name $Name -ErrorAction Stop | Out-Null
            Add-LocalCheck -Section 'Local prerequisites' -Name "$Name module" -Status 'Pass' -Detail 'Installed module imported.'
        }
        catch {
            Import-Module -Name $Name -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
            Add-LocalCheck -Section 'Local prerequisites' -Name "$Name module" -Status 'Pass' -Detail 'Installed module imported through the local Windows PowerShell compatibility session.'
        }
        return $true
    }
    catch {
        Add-LocalCheck -Section 'Local prerequisites' -Name "$Name module" -Status 'Unknown' -Detail "Cannot read with the installed module: $(Get-SafeErrorText $_)"
        return $false
    }
}

if (-not $IsWindows) {
    Add-LocalCheck -Section 'Local prerequisites' -Name 'Windows Connect server' -Status 'Unknown' -Detail 'Run this optional script on the Windows Entra Connect server. Use the cloud scripts from other platforms.'
    Write-CheckReport -Title "AD / Connect preflight: $RoomUpn" -Results $results -Ascii:$Ascii -PassThru:$PassThru
    return
}
Add-LocalCheck -Section 'Local prerequisites' -Name 'Windows host' -Status 'Pass' -Detail "Windows host: $([Environment]::MachineName). This alone does not identify the active Connect server."

# Programs / uninstall registry evidence avoids Win32_Product, which can trigger
# MSI consistency checks and repair installed products merely while querying.
try {
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $products = @(
        foreach ($registryPath in $uninstallPaths) {
            Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue |
                Where-Object {
                    $name = Get-DataValue -InputObject $_ -Name 'DisplayName'
                    $name -match '^(Microsoft (Azure AD|Entra) Connect( Sync)?|Azure AD Connect)$'
                }
        }
    )
    $distinctProducts = @($products | Sort-Object -Property DisplayName, DisplayVersion -Unique)
    if ($distinctProducts.Count -eq 0) {
        Add-LocalCheck -Section 'Connect' -Name 'Installed product version' -Status 'Unknown' -Detail 'No exact Connect Sync product entry was found in Programs / uninstall registry evidence. Check Programs and Features; no unrelated executable version is used as a substitute.'
    }
    elseif ($distinctProducts.Count -gt 1) {
        Add-LocalCheck -Section 'Connect' -Name 'Installed product version' -Status 'Review' -Detail 'Multiple distinct Connect product entries were found. Confirm the active installation in Programs and Features.' -Evidence @($distinctProducts | Select-Object DisplayName, DisplayVersion, InstallLocation)
    }
    else {
        $product = $distinctProducts[0]
        $displayVersion = [string](Get-DataValue -InputObject $product -Name 'DisplayVersion')
        foreach ($check in @(Get-ConnectVersionChecks -VersionText $displayVersion -ProductName ([string](Get-DataValue -InputObject $product -Name 'DisplayName')) -Evidence ($product | Select-Object DisplayName, DisplayVersion, InstallLocation))) {
            $results.Add($check)
        }
    }
}
catch {
    Add-LocalCheck -Section 'Connect' -Name 'Installed product version' -Status 'Unknown' -Detail "Cannot read Programs / registry evidence: $(Get-SafeErrorText $_)"
}

try {
    $syncService = Get-Service -Name 'ADSync' -ErrorAction Stop
    if ($syncService.Status -eq 'Running') {
        Add-LocalCheck -Section 'Connect' -Name 'ADSync service' -Status 'Pass' -Detail 'ADSync service is running; this does not prove successful exports.'
    }
    else {
        Add-LocalCheck -Section 'Connect' -Name 'ADSync service' -Status 'Action' -Detail "ADSync service status is $($syncService.Status). Investigate before cutover; this script does not start the service."
    }
}
catch {
    Add-LocalCheck -Section 'Connect' -Name 'ADSync service' -Status 'Unknown' -Detail "Cannot read the ADSync service: $(Get-SafeErrorText $_)"
}

$adSyncAvailable = Import-LocalReadModule -Name 'ADSync'
if ($adSyncAvailable) {
    try {
        $scheduler = Get-ADSyncScheduler -ErrorAction Stop
        if ($null -eq $scheduler) { throw 'The scheduler returned no object.' }
        foreach ($setting in @(
            @{ Name = 'SyncCycleEnabled'; Expected = $true; Label = 'Scheduled synchronization'; BadStatus = 'Action'; BadDetail = 'Scheduled synchronization is disabled. Confirm whether this is intentional and how imports / exports will complete before cutover.' },
            @{ Name = 'StagingModeEnabled'; Expected = $false; Label = 'Active export mode'; BadStatus = 'Review'; BadDetail = 'This server is in staging mode and suppresses exports. Identify the active Connect server and review its evidence.' },
            @{ Name = 'SchedulerSuspended'; Expected = $false; Label = 'Scheduler suspension'; BadStatus = 'Review'; BadDetail = 'The scheduler is suspended, for example during maintenance. Confirm that the active engine is ready before cutover.' }
        )) {
            $results.Add((Get-SchedulerSettingCheck -Scheduler $scheduler -Setting $setting))
        }
        Add-LocalCheck -Section 'Connect' -Name 'Scheduler snapshot' -Status 'Review' -Detail 'Settings were captured. Next scheduled time is not last-successful-sync evidence.' -Evidence ($scheduler | Select-Object SyncCycleEnabled, StagingModeEnabled, SchedulerSuspended, MaintenanceEnabled, CurrentlyEffectiveSyncCycleInterval, NextSyncCycleStartTimeInUTC, NextSyncCyclePolicyType)
    }
    catch {
        Add-LocalCheck -Section 'Connect' -Name 'Scheduler settings' -Status 'Unknown' -Detail "Cannot read the scheduler: $(Get-SafeErrorText $_)"
    }
}
Add-LocalCheck -Section 'Connect' -Name 'Last successful import / export' -Status 'Review' -Detail 'Review Operations in Synchronization Service Manager and Entra Connect Health for recent successful imports / exports and unresolved errors. Scheduler/service checks cannot prove this.'

$adAvailable = Import-LocalReadModule -Name 'ActiveDirectory'
$room = $null
$adReadParameters = @{}
if (-not [string]::IsNullOrWhiteSpace($ADServer)) { $adReadParameters.Server = $ADServer }
if ($adAvailable) {
    try {
        $escapedUpn = ConvertTo-LdapLiteral -Value $RoomUpn
        $matches = @(Get-ADUser -LDAPFilter "(userPrincipalName=$escapedUpn)" -Properties @('Enabled', 'memberOf', 'msDS-ConsistencyGuid', 'mail', 'whenChanged') @adReadParameters -ErrorAction Stop)
        if ($matches.Count -eq 0) {
            Add-LocalCheck -Section 'AD account' -Name 'Exact UPN lookup' -Status 'Action' -Detail "No exact UPN $RoomUpn was found in the selected AD server/domain search scope. Check the UPN and ADServer; do not create a replacement account."
        }
        elseif ($matches.Count -gt 1) {
            Add-LocalCheck -Section 'AD account' -Name 'Exact UPN lookup' -Status 'Action' -Detail "$($matches.Count) exact UPN matches were returned. Resolve identity ambiguity before migration." -Evidence @($matches | Select-Object DistinguishedName, ObjectGUID, UserPrincipalName)
        }
        else {
            $room = $matches[0]
            $roomDn = [string](Get-DataValue -InputObject $room -Name 'DistinguishedName')
            $roomObjectGuid = Get-DataValue -InputObject $room -Name 'ObjectGUID'
            if ([string]::IsNullOrWhiteSpace($roomDn) -or $null -eq $roomObjectGuid) {
                Add-LocalCheck -Section 'AD account' -Name 'Exact UPN lookup' -Status 'Unknown' -Detail 'The AD result did not include both distinguished name and objectGUID. Identity evidence is incomplete.'
                $room = $null
            }
            else {
                Add-LocalCheck -Section 'AD account' -Name 'Exact UPN lookup' -Status 'Pass' -Detail "One exact match in the selected AD search scope: $roomDn." -Evidence ($room | Select-Object DistinguishedName, ObjectGUID, UserPrincipalName, SamAccountName, mail, whenChanged)
                $enabled = Get-DataValue -InputObject $room -Name 'Enabled'
                if ($enabled -is [bool] -and $enabled) {
                    Add-LocalCheck -Section 'AD account' -Name 'AD account state' -Status 'Pass' -Detail 'The existing AD account is enabled.'
                }
                elseif ($enabled -is [bool]) {
                    Add-LocalCheck -Section 'AD account' -Name 'AD account state' -Status 'Review' -Detail 'The AD account is disabled. Confirm whether this is intentional after passwordless migration and record the current room health; do not enable it automatically.'
                }
                else {
                    Add-LocalCheck -Section 'AD account' -Name 'AD account state' -Status 'Unknown' -Detail 'AD Enabled state was not readable.'
                }
                try {
                    $guid = [guid]$roomObjectGuid
                    $consistencyGuid = Get-DataValue -InputObject $room -Name 'msDS-ConsistencyGuid'
                    $consistencyBase64 = $null
                    if ($null -ne $consistencyGuid -and @($consistencyGuid).Count -gt 0) {
                        $consistencyBase64 = [Convert]::ToBase64String([byte[]]$consistencyGuid)
                    }
                    $anchors = [pscustomobject]@{
                        DistinguishedName = $roomDn
                        ObjectGUID = $guid.ToString()
                        ObjectGuidBase64 = [Convert]::ToBase64String($guid.ToByteArray())
                        MsDSConsistencyGuidBase64 = $consistencyBase64
                    }
                    Add-LocalCheck -Section 'AD account' -Name 'Identity / anchor snapshot' -Status 'Pass' -Detail 'AD distinguished name, objectGUID and available msDS-ConsistencyGuid values captured. These are candidate anchors; they do not identify the configured sourceAnchor.' -Evidence $anchors
                }
                catch {
                    Add-LocalCheck -Section 'AD account' -Name 'Identity / anchor snapshot' -Status 'Unknown' -Detail "Anchor snapshot is incomplete: $(Get-SafeErrorText $_)"
                }
            }
        }
    }
    catch {
        Add-LocalCheck -Section 'AD account' -Name 'Exact UPN lookup' -Status 'Unknown' -Detail "Cannot read the room account: $(Get-SafeErrorText $_). Check AD connectivity, read permissions, and ADServer."
    }
}

if ($adAvailable -and $null -ne $room) {
    Add-LocalCheck -Section 'AD account' -Name 'Configured sourceAnchor / retained sync scope' -Status 'Review' -Detail 'Read the Connect configuration and connector-space lineage for this exact AD distinguished name and Entra object ID. Verify the configured sourceAnchor, domain/OU and rule scope. Leave the AD object and its sync scope intact for rollback; finding it in AD does not establish sync scope.'
    $groups = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $roomDn = [string](Get-DataValue -InputObject $room -Name 'DistinguishedName')
    $directGroupDns = @(Get-ADIdentifierValues -Values (Get-DataValue -InputObject $room -Name 'memberOf'))
    if (-not (Test-DataProperty -InputObject $room -Name 'memberOf')) {
        Add-LocalCheck -Section 'AD dependencies' -Name 'Direct group membership inventory' -Status 'Unknown' -Detail 'memberOf was not returned. Do not treat unreadable membership as an empty inventory.'
    }
    else {
        Add-LocalCheck -Section 'AD dependencies' -Name 'Direct group membership inventory' -Status 'Review' -Detail "$($directGroupDns.Count) direct memberOf groups returned. This excludes the primary group, nested membership, other-forest groups and external dependencies." -Evidence $directGroupDns
    }

    $groupIdentities = @(@($directGroupDns) + @($RoomListIdentity) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Sort-Object -Unique)
    foreach ($groupIdentity in $groupIdentities) {
        try {
            $exchangeAttributesReadable = $true
            try {
                $group = Get-ADGroup -Identity $groupIdentity -Properties @('member', 'managedBy', 'mail', 'proxyAddresses', 'msExchRecipientTypeDetails') @adReadParameters -ErrorAction Stop
            }
            catch {
                # An AD schema can lack Exchange attributes. Keep the base group
                # inventory useful, while making RoomList classification unknown.
                $group = Get-ADGroup -Identity $groupIdentity -Properties @('member', 'managedBy', 'mail') @adReadParameters -ErrorAction Stop
                $exchangeAttributesReadable = $false
            }
            if ($null -eq $group) { throw 'The exact group read returned no object.' }
            $dn = [string](Get-DataValue -InputObject $group -Name 'DistinguishedName')
            if ([string]::IsNullOrWhiteSpace($dn)) { throw 'The group distinguished name was not returned.' }
            if ($groups.ContainsKey($dn)) { continue }
            $groups.Add($dn, $group)
            $members = @(Get-ADIdentifierValues -Values (Get-DataValue -InputObject $group -Name 'member'))
            $membershipKnown = Test-DataProperty -InputObject $group -Name 'member'
            $containsRoom = if ($membershipKnown) { $members -contains $roomDn } else { $null }
            $recipientType = Get-DataValue -InputObject $group -Name 'msExchRecipientTypeDetails'
            $roomListFlag = $false
            if ($exchangeAttributesReadable -and $null -ne $recipientType) {
                try { $roomListFlag = ([long]$recipientType -eq 268435456) } catch { $exchangeAttributesReadable = $false }
            }
            $snapshot = [pscustomobject]@{
                DistinguishedName = $dn
                ObjectGUID = Get-DataValue -InputObject $group -Name 'ObjectGUID'
                Name = Get-DataValue -InputObject $group -Name 'Name'
                SamAccountName = Get-DataValue -InputObject $group -Name 'SamAccountName'
                GroupCategory = Get-DataValue -InputObject $group -Name 'GroupCategory'
                GroupScope = Get-DataValue -InputObject $group -Name 'GroupScope'
                Mail = Get-DataValue -InputObject $group -Name 'mail'
                ProxyAddresses = @(Get-ADIdentifierValues -Values (Get-DataValue -InputObject $group -Name 'proxyAddresses'))
                ManagedBy = Get-DataValue -InputObject $group -Name 'managedBy'
                MsExchRecipientTypeDetails = $recipientType
                ADHasRoomListFlag = if ($exchangeAttributesReadable) { $roomListFlag } else { $null }
                RoomIsDirectMember = $containsRoom
                MemberDistinguishedNames = $members
            }
            $classification = if ($roomListFlag) { 'AD RoomList flag present; confirm RoomList subtype in Exchange Online.' } elseif (-not $exchangeAttributesReadable) { 'Exchange attributes unreadable; RoomList classification unknown.' } else { 'No AD RoomList flag found; use Exchange Online for authoritative recipient subtype.' }
            Add-LocalCheck -Section 'AD dependencies' -Name "Group: $(Get-DataValue -InputObject $group -Name 'Name')" -Status 'Review' -Detail "$classification $($members.Count) direct members captured. Preserve the group and review mail, licensing, access, policy and nesting dependencies." -Evidence $snapshot
            if (-not $membershipKnown) {
                Add-LocalCheck -Section 'AD dependencies' -Name "Group members: $dn" -Status 'Unknown' -Detail 'The member property was not returned. Do not use this snapshot as a complete membership baseline.'
            }
            if ($RoomListIdentity -contains [string]$groupIdentity) {
                if ($membershipKnown -and $containsRoom) {
                    Add-LocalCheck -Section 'AD dependencies' -Name "Specified RoomList membership: $dn" -Status 'Pass' -Detail 'The exact room AD object is a direct member. Compare the complete list with Exchange Online; this is not group migration eligibility.'
                }
                elseif ($membershipKnown) {
                    Add-LocalCheck -Section 'AD dependencies' -Name "Specified RoomList membership: $dn" -Status 'Review' -Detail 'The exact room AD object is not a direct member of this supplied group. Confirm whether this is the intended RoomList or a group for other rooms.'
                }
            }
        }
        catch {
            $status = if ($_.Exception.GetType().Name -match 'IdentityNotFound') { 'Action' } else { 'Unknown' }
            Add-LocalCheck -Section 'AD dependencies' -Name "Group: $groupIdentity" -Status $status -Detail "Exact group inventory is incomplete: $(Get-SafeErrorText $_). Supply its AD distinguished name, objectGUID or sAMAccountName and check the selected server/domain."
        }
    }
}
elseif ($RoomListIdentity.Count -gt 0) {
    Add-LocalCheck -Section 'AD dependencies' -Name 'Specified RoomList groups' -Status 'Unknown' -Detail 'Room identity / AD access is incomplete, so the RoomList relationship was not checked. Resolve the account lookup first.'
}

Add-LocalCheck -Section 'Manual evidence' -Name 'Passwordless room / recovery baseline' -Status 'Review' -Detail 'Confirm the completed Pro Management passwordless migration and current Android room / panel health. PHS versus PTA is background, not a mandatory cutover gate for this passwordless room. Validate with reboot and calendar / join tests; do not sign out, reset the device, or reset the password as a test.'
Add-LocalCheck -Section 'Manual evidence' -Name 'Federation and other dependencies' -Status 'Review' -Detail 'Use the cloud preflight for domain authentication and licence / policy dependencies. Resolve the documented AD FS limitation before User SOA transfer. This AD script does not prove tenant eligibility.'

Write-CheckReport -Title "AD / Connect preflight: $RoomUpn" -Results $results -Ascii:$Ascii -PassThru:$PassThru
