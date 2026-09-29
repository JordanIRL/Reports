# Exchange Online and Teams collectors. These run either in-process or in an isolated child process
# (see Invoke-MtrServiceCall), so they take only simple arguments and return plain objects.
# Only Get-* cmdlets are used; the Exchange session only has the cmdlets in $script:MtrExoCommands loaded.

function ConvertTo-MtrExoMailbox {
    param($Mailbox)
    [pscustomobject]@{
        Identity                      = [string]$Mailbox.Identity
        DisplayName                   = $Mailbox.DisplayName
        Alias                         = $Mailbox.Alias
        UserPrincipalName             = $Mailbox.UserPrincipalName
        PrimarySmtpAddress            = [string]$Mailbox.PrimarySmtpAddress
        ExternalDirectoryObjectId     = [string]$Mailbox.ExternalDirectoryObjectId
        RecipientTypeDetails          = [string]$Mailbox.RecipientTypeDetails
        HiddenFromAddressListsEnabled = [bool]$Mailbox.HiddenFromAddressListsEnabled
        IsDirSynced                   = [bool]$Mailbox.IsDirSynced
        ResourceCapacity              = $Mailbox.ResourceCapacity
        RoomMailboxAccountEnabled     = $Mailbox.RoomMailboxAccountEnabled
        AccountDisabled               = $Mailbox.AccountDisabled
        Office                        = $Mailbox.Office
    }
}

function Get-MtrExchangeRoomData {
    <#
    .SYNOPSIS
        Phase A: every room mailbox, every room list with members, and organization EWS settings.
    #>
    [CmdletBinding()]
    param()

    $rooms = @(Get-Mailbox -RecipientTypeDetails RoomMailbox -ResultSize Unlimited -ErrorAction Stop | ForEach-Object { ConvertTo-MtrExoMailbox -Mailbox $_ })

    $roomLists = foreach ($list in @(Get-DistributionGroup -RecipientTypeDetails RoomList -ResultSize Unlimited -ErrorAction Stop)) {
        $members = @()
        $memberError = $null
        try {
            $members = @(Get-DistributionGroupMember -Identity ([string]$list.PrimarySmtpAddress) -ResultSize Unlimited -ErrorAction Stop | ForEach-Object {
                    [pscustomobject]@{
                        DisplayName               = $_.DisplayName
                        PrimarySmtpAddress        = [string]$_.PrimarySmtpAddress
                        ExternalDirectoryObjectId = [string]$_.ExternalDirectoryObjectId
                        RecipientTypeDetails      = [string]$_.RecipientTypeDetails
                    }
                })
        }
        catch { $memberError = $_.Exception.Message }
        [pscustomobject]@{
            DisplayName               = $list.DisplayName
            Name                      = $list.Name
            PrimarySmtpAddress        = [string]$list.PrimarySmtpAddress
            ExternalDirectoryObjectId = [string]$list.ExternalDirectoryObjectId
            IsDirSynced               = [bool]$list.IsDirSynced
            Members                   = $members
            MemberError               = $memberError
        }
    }

    $org = $null
    try {
        $o = Get-OrganizationConfig -ErrorAction Stop
        $org = [pscustomobject]@{
            EwsEnabled                 = $o.EwsEnabled
            EwsApplicationAccessPolicy = [string]$o.EwsApplicationAccessPolicy
            EwsAllowList               = Get-MtrArray $o.EwsAllowList
            EwsBlockList               = Get-MtrArray $o.EwsBlockList
        }
    }
    catch { Write-Warning "Get-OrganizationConfig failed: $($_.Exception.Message)" }

    [pscustomobject]@{
        RoomMailboxes      = $rooms
        RoomLists          = Get-MtrArray $roomLists
        OrganizationConfig = $org
    }
}

function Get-MtrExchangeCandidateData {
    <#
    .SYNOPSIS
        Phase B: mailbox type, calendar processing, time zone, EWS and Place data for each candidate account.
    .PARAMETER Identities
        UPNs / SMTP addresses of candidate Teams Rooms accounts.
    .PARAMETER KnownRoomIdentities
        Candidates already known to be room mailboxes (skips the recipient lookup).
    #>
    [CmdletBinding()]
    param(
        [string[]]$Identities = @(),
        [string[]]$KnownRoomIdentities = @()
    )

    $known = @{}
    foreach ($k in $KnownRoomIdentities) { if ($k) { $known[$k.ToLowerInvariant()] = $true } }
    $results = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($identity in $Identities) {
        $i++
        Write-Progress -Activity 'Exchange Online' -Status $identity -PercentComplete ([math]::Min(100, 100 * $i / [math]::Max(1, $Identities.Count)))
        $record = [ordered]@{
            Identity           = $identity
            Recipient          = $null
            Mailbox            = $null
            CalendarProcessing = $null
            Regional           = $null
            CalendarConfig     = $null
            Cas                = $null
            Place              = $null
            Errors             = @()
        }
        $errors = [System.Collections.Generic.List[string]]::new()

        if (-not $known[$identity.ToLowerInvariant()]) {
            try {
                $r = Get-Recipient -Identity $identity -ErrorAction Stop
                $record.Recipient = [pscustomobject]@{ RecipientTypeDetails = [string]$r.RecipientTypeDetails; PrimarySmtpAddress = [string]$r.PrimarySmtpAddress; IsDirSynced = [bool]$r.IsDirSynced }
            }
            catch {
                # Only a genuine "not found" means there is no Exchange recipient; anything else (throttling,
                # permissions, transient errors) is recorded as an error so no false "no mailbox" finding results.
                $notFound = "$($_.FullyQualifiedErrorId) $($_.CategoryInfo.Reason) $($_.Exception.GetType().Name)" -match 'NotFound' -or
                    $_.Exception.Message -match "couldn't be found|could not be found|wasn't found|was not found"
                if ($notFound) { $record.Recipient = [pscustomobject]@{ RecipientTypeDetails = 'NotFound'; PrimarySmtpAddress = $null; IsDirSynced = $null } }
                else { $errors.Add("Get-Recipient: $($_.Exception.Message)") }
            }
        }
        $isMailbox = $known[$identity.ToLowerInvariant()] -or ($record.Recipient -and $record.Recipient.RecipientTypeDetails -match 'Mailbox$' -and $record.Recipient.RecipientTypeDetails -notmatch '^Remote')

        if ($isMailbox) {
            try { $record.Mailbox = ConvertTo-MtrExoMailbox -Mailbox (Get-Mailbox -Identity $identity -ErrorAction Stop) } catch { $errors.Add("Get-Mailbox: $($_.Exception.Message)") }
            try {
                $cp = Get-CalendarProcessing -Identity $identity -ErrorAction Stop
                $record.CalendarProcessing = [pscustomobject]@{
                    AutomateProcessing             = [string]$cp.AutomateProcessing
                    AddOrganizerToSubject          = $cp.AddOrganizerToSubject
                    AllowRecurringMeetings         = $cp.AllowRecurringMeetings
                    DeleteAttachments              = $cp.DeleteAttachments
                    DeleteComments                 = $cp.DeleteComments
                    DeleteSubject                  = $cp.DeleteSubject
                    ProcessExternalMeetingMessages = $cp.ProcessExternalMeetingMessages
                    RemovePrivateProperty          = $cp.RemovePrivateProperty
                    AddAdditionalResponse          = $cp.AddAdditionalResponse
                    AllBookInPolicy                = $cp.AllBookInPolicy
                    AllRequestInPolicy             = $cp.AllRequestInPolicy
                    BookInPolicy                   = Get-MtrArray ($cp.BookInPolicy | Where-Object { $_ } | ForEach-Object { [string]$_ })
                    ResourceDelegates              = Get-MtrArray ($cp.ResourceDelegates | Where-Object { $_ } | ForEach-Object { [string]$_ })
                    BookingWindowInDays            = $cp.BookingWindowInDays
                    MaximumDurationInMinutes       = $cp.MaximumDurationInMinutes
                    ScheduleOnlyDuringWorkHours    = $cp.ScheduleOnlyDuringWorkHours
                    AllowConflicts                 = $cp.AllowConflicts
                    EnforceCapacity                = $cp.EnforceCapacity
                }
            }
            catch { $errors.Add("Get-CalendarProcessing: $($_.Exception.Message)") }
            try {
                $rc = Get-MailboxRegionalConfiguration -Identity $identity -ErrorAction Stop
                $record.Regional = [pscustomobject]@{ TimeZone = [string]$rc.TimeZone; Language = [string]$rc.Language }
            }
            catch { $errors.Add("Get-MailboxRegionalConfiguration: $($_.Exception.Message)") }
            try {
                # WarningAction: the cmdlet warns on every call that its Events from Email parameters are deprecated.
                $cc = Get-MailboxCalendarConfiguration -Identity $identity -ErrorAction Stop -WarningAction SilentlyContinue
                $record.CalendarConfig = [pscustomobject]@{ WorkingHoursTimeZone = [string]$cc.WorkingHoursTimeZone }
            }
            catch { $errors.Add("Get-MailboxCalendarConfiguration: $($_.Exception.Message)") }
            try {
                $cas = Get-CASMailbox -Identity $identity -ErrorAction Stop
                $record.Cas = [pscustomobject]@{ EwsEnabled = $cas.EwsEnabled; EwsApplicationAccessPolicy = [string]$cas.EwsApplicationAccessPolicy }
            }
            catch { $errors.Add("Get-CASMailbox: $($_.Exception.Message)") }
            try {
                $p = Get-Place -Identity $identity -ErrorAction Stop
                $record.Place = [pscustomobject]@{
                    City = $p.City; State = $p.State; CountryOrRegion = [string]$p.CountryOrRegion; Street = $p.Street; PostalCode = $p.PostalCode
                    Building = $p.Building; Floor = $p.Floor; FloorLabel = $p.FloorLabel; Capacity = $p.Capacity; MTREnabled = $p.MTREnabled
                    AudioDeviceName = $p.AudioDeviceName; VideoDeviceName = $p.VideoDeviceName; DisplayDeviceName = $p.DisplayDeviceName
                    IsWheelChairAccessible = $p.IsWheelChairAccessible; Tags = Get-MtrArray $p.Tags; Localities = Get-MtrArray ($p.Localities | Where-Object { $_ } | ForEach-Object { [string]$_ })
                }
            }
            catch { $errors.Add("Get-Place: $($_.Exception.Message)") }
        }
        $record.Errors = $errors.ToArray()
        $results.Add([pscustomobject]$record)
    }
    Write-Progress -Activity 'Exchange Online' -Completed
    , $results.ToArray()
}

function Get-MtrExchangeData {
    <#
    .SYNOPSIS
        One Exchange Online pass: the room inventory (unless -SkipRoomInventory) plus mailbox detail for every
        room mailbox whose account is enabled and for every identity supplied. Keeping it to one call means one
        separate-process sign-in instead of several.
    #>
    [CmdletBinding()]
    param(
        [string[]]$Identities = @(),
        [switch]$SkipRoomInventory
    )
    $roomData = if ($SkipRoomInventory) { $null } else { Get-MtrExchangeRoomData }
    $knownRooms = [System.Collections.Generic.List[string]]::new()
    $targets = [ordered]@{}
    foreach ($room in (Get-MtrArray $roomData.RoomMailboxes)) {
        $key = if ($room.UserPrincipalName) { $room.UserPrincipalName } else { $room.PrimarySmtpAddress }
        if (-not $key) { continue }
        $knownRooms.Add($key)
        if ($room.AccountDisabled -eq $false -or $room.RoomMailboxAccountEnabled -eq $true) { $targets[$key.ToLowerInvariant()] = $key }
    }
    foreach ($identity in $Identities) { if ($identity) { $targets[$identity.ToLowerInvariant()] = $identity } }

    $candidates = if ($targets.Count) { Get-MtrExchangeCandidateData -Identities @($targets.Values) -KnownRoomIdentities $knownRooms.ToArray() } else { @() }
    [pscustomobject]@{
        RoomMailboxes      = if ($roomData) { Get-MtrArray $roomData.RoomMailboxes } else { @() }
        RoomLists          = if ($roomData) { Get-MtrArray $roomData.RoomLists } else { @() }
        OrganizationConfig = if ($roomData) { $roomData.OrganizationConfig } else { $null }
        Candidates         = Get-MtrArray $candidates
    }
}

function Get-MtrTeamsData {
    <#
    .SYNOPSIS
        Teams user configuration for candidate accounts plus IP phone policies.
    #>
    [CmdletBinding()]
    param([string[]]$UserPrincipalNames = @())

    $users = [System.Collections.Generic.List[object]]::new()
    $i = 0
    foreach ($upn in $UserPrincipalNames) {
        $i++
        Write-Progress -Activity 'Microsoft Teams' -Status $upn -PercentComplete ([math]::Min(100, 100 * $i / [math]::Max(1, $UserPrincipalNames.Count)))
        try {
            $u = Get-CsOnlineUser -Identity $upn -ErrorAction Stop
            $users.Add([pscustomobject]@{
                    UserPrincipalName         = $upn
                    Found                     = $true
                    NotFound                  = $false
                    AccountEnabled            = $u.AccountEnabled
                    AccountType               = [string]$u.AccountType
                    InterpretedUserType       = [string]$u.InterpretedUserType
                    TeamsUpgradeEffectiveMode = [string]$u.TeamsUpgradeEffectiveMode
                    FeatureTypes              = Get-MtrArray ($u.FeatureTypes | Where-Object { $_ } | ForEach-Object { [string]$_ })
                    TeamsIPPhonePolicy        = [string]$u.TeamsIPPhonePolicy
                    TeamsMeetingPolicy        = [string]$u.TeamsMeetingPolicy
                    TeamsCallingPolicy        = [string]$u.TeamsCallingPolicy
                    TeamsUpdateManagementPolicy = [string]$u.TeamsUpdateManagementPolicy
                    EnterpriseVoiceEnabled    = $u.EnterpriseVoiceEnabled
                    LineUri                   = [string]$u.LineURI
                    UsageLocation             = [string]$u.UsageLocation
                    Error                     = $null
                })
        }
        catch {
            $notFound = "$($_.FullyQualifiedErrorId) $($_.Exception.GetType().Name)" -match 'NotFound' -or $_.Exception.Message -match "not found|couldn't be found|could not be found|does not exist"
            $users.Add([pscustomobject]@{ UserPrincipalName = $upn; Found = $false; NotFound = [bool]$notFound; Error = $_.Exception.Message })
        }
    }
    Write-Progress -Activity 'Microsoft Teams' -Completed

    $ipPolicies = @()
    $ipPolicyError = $null
    try {
        $ipPolicies = @(Get-CsTeamsIPPhonePolicy -ErrorAction Stop | ForEach-Object { [pscustomobject]@{ Identity = [string]$_.Identity; SignInMode = [string]$_.SignInMode } })
    }
    catch { $ipPolicyError = $_.Exception.Message }

    [pscustomobject]@{ Users = $users.ToArray(); IpPhonePolicies = $ipPolicies; IpPhonePolicyError = $ipPolicyError }
}
