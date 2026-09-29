# Exchange (EXO), Room Finder / Places (RF) and Teams (TMS) checks.

function Test-MtrExchange {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $mtr = Get-MtrArray $Model.MtrAccounts
    if (-not $Context.Exchange -or -not (Get-MtrCount $Context.Exchange.Candidates)) { return }

    # EXO-01 Mailbox type / location
    # Only a confirmed "not found" counts; accounts whose lookup failed are reported in Coverage instead.
    $noMailbox = @($mtr | Where-Object { $_.MailboxType -eq 'NotFound' })
    $onPrem = @($mtr | Where-Object { $_.MailboxType -in 'MailUser', 'GuestMailUser' })
    $notRoom = @($mtr | Where-Object { $_.MailboxType -and $_.MailboxType -notin 'RoomMailbox', 'NotFound', 'MailUser', 'GuestMailUser' })
    if ($noMailbox.Count) {
        New-MtrFinding -CheckId 'EXO-01' -Severity High -Category 'Exchange' -Title 'Teams Rooms accounts without an Exchange Online mailbox' `
            -Target "$($noMailbox.Count) accounts" -AffectedObjects @($noMailbox | ForEach-Object UserPrincipalName) `
            -Impact 'The room cannot be booked and the device shows no calendar.' `
            -Recommendation 'Create (or migrate) a room mailbox for the account. In hybrid, create the remote room mailbox on-prem with New-RemoteMailbox -Room.' -FixLocation 'On-prem Exchange' -Reference $links.ResourceAccount
    }
    if ($onPrem.Count) {
        New-MtrFinding -CheckId 'EXO-01' -Severity Medium -Category 'Exchange' -Title 'Teams Rooms mailboxes still hosted on-prem' `
            -Target "$($onPrem.Count) accounts" -AffectedObjects @($onPrem | ForEach-Object UserPrincipalName) `
            -Impact 'On-prem room mailboxes only work with Exchange hybrid and Autodiscover v2 published externally; room finder and Places features are cloud-only.' `
            -Recommendation 'Move these room mailboxes to Exchange Online.' -FixLocation 'On-prem Exchange' -Reference $links.ResourceAccount
    }
    if ($notRoom.Count) {
        New-MtrFinding -CheckId 'EXO-02' -Severity Medium -Category 'Exchange' -Title 'Teams Rooms accounts that are not room mailboxes' `
            -Target "$($notRoom.Count) accounts" -AffectedObjects @($notRoom | ForEach-Object { '{0} ({1})' -f $_.UserPrincipalName, $_.MailboxType }) `
            -Impact 'Only room mailboxes auto-accept bookings, appear in Room Finder / Places and carry room metadata.' `
            -Recommendation 'Convert to a room mailbox (for synced objects convert the remote mailbox type on-prem, then let sync update EXO).' -FixLocation 'On-prem Exchange' -Reference $links.ResourceAccount
    }

    # EXO-03 Calendar processing
    $withCp = @($mtr | Where-Object { $_.Exchange -and $_.Exchange.CalendarProcessing })
    foreach ($rule in $Baseline.CalendarProcessing) {
        $bad = @($withCp | Where-Object {
                $actual = Get-MtrPropertyValue $_.Exchange.CalendarProcessing $rule.Property
                if ($rule.Expected -is [bool]) { [bool]$actual -ne $rule.Expected } else { [string]$actual -ne [string]$rule.Expected }
            })
        if (-not $bad.Count) { continue }
        $value = if ($rule.Expected -is [bool]) { '$' + ([string]$rule.Expected).ToLowerInvariant() } else { $rule.Expected }
        $extraArg = if ($rule.Property -eq 'AddAdditionalResponse') { " -AdditionalResponse 'This is a Microsoft Teams Room.'" } else { '' }
        $identities = ($bad | ForEach-Object { ConvertTo-MtrPsLiteral $_.PrimarySmtpAddress }) -join ','
        New-MtrFinding -CheckId 'EXO-03' -Severity $rule.Severity -Category 'Exchange' -Title "Calendar processing: $($rule.Property) is not $($rule.Expected)" `
            -Target "$($bad.Count) rooms" -AffectedObjects @($bad | ForEach-Object { '{0} ({1})' -f $_.UserPrincipalName, (Get-MtrPropertyValue $_.Exchange.CalendarProcessing $rule.Property) }) `
            -Impact $rule.Reason -Recommendation "Set $($rule.Property) to $($rule.Expected) (Microsoft's recommended Teams Rooms setting). Calendar processing lives in Exchange Online even for synced rooms." `
            -FixLocation 'Exchange Online' -Reference $links.ResourceAccount `
            -RemediationCommand @("@($identities) | ForEach-Object { Set-CalendarProcessing -Identity `$_ -$($rule.Property) $value$extraArg }")
    }
    $bookIn = @($withCp | Where-Object { $_.Exchange.CalendarProcessing.AllBookInPolicy -eq $false -and -not (Get-MtrCount $_.Exchange.CalendarProcessing.BookInPolicy) })
    if ($bookIn.Count) {
        New-MtrFinding -CheckId 'EXO-04' -Severity Medium -Category 'Exchange' -Title 'Rooms that nobody can book automatically' `
            -AffectedObjects @($bookIn | ForEach-Object UserPrincipalName) `
            -Detail 'AllBookInPolicy is False and BookInPolicy is empty: every request needs delegate approval or is declined.' `
            -Impact 'Meetings are missing from the room calendar and the device.' -Recommendation 'Confirm this restriction is intended; otherwise set AllBookInPolicy $true.' -FixLocation 'Exchange Online'
    }

    # EXO-05 Time zone
    $withTz = @($mtr | Where-Object { $_.Exchange -and $_.Exchange.Regional })
    $noTz = @($withTz | Where-Object { -not $_.Exchange.Regional.TimeZone })
    if ($noTz.Count) {
        New-MtrFinding -CheckId 'EXO-05' -Severity Medium -Category 'Exchange' -Title 'Room mailboxes with no time zone set' `
            -AffectedObjects @($noTz | ForEach-Object UserPrincipalName) `
            -Impact 'Resource accounts default to Pacific Standard Time; working-hours booking rules and the device calendar can be wrong.' `
            -Recommendation 'Set the time zone of the physical room.' -FixLocation 'Exchange Online' -Reference $links.TimeZone `
            -RemediationCommand @($noTz | ForEach-Object { "Set-MailboxRegionalConfiguration -Identity $(ConvertTo-MtrPsLiteral $_.PrimarySmtpAddress) -TimeZone '<Windows time zone name>'; Set-MailboxCalendarConfiguration -Identity $(ConvertTo-MtrPsLiteral $_.PrimarySmtpAddress) -WorkingHoursTimeZone '<same>'" })
    }
    $outliers = [System.Collections.Generic.List[string]]::new()
    $outlierCmds = [System.Collections.Generic.List[string]]::new()
    $groups = $withTz | Where-Object { $_.Exchange.Regional.TimeZone } | Group-Object { if ((Get-MtrCount $_.RoomLists)) { 'List: ' + @($_.RoomLists)[0] } elseif ($_.ExoPlace -and $_.ExoPlace.City) { 'City: ' + $_.ExoPlace.City } else { '' } }
    foreach ($g in $groups) {
        if (-not $g.Name -or $g.Count -lt 3) { continue }
        $majority = $g.Group | Group-Object { $_.Exchange.Regional.TimeZone } | Sort-Object Count -Descending | Select-Object -First 1
        if ($majority.Count / [double]$g.Count -lt 0.6) { continue }
        foreach ($a in @($g.Group | Where-Object { $_.Exchange.Regional.TimeZone -ne $majority.Name })) {
            $outliers.Add(('{0}: {1} (others in {2} use {3})' -f $a.UserPrincipalName, $a.Exchange.Regional.TimeZone, $g.Name, $majority.Name))
            $outlierCmds.Add("Set-MailboxRegionalConfiguration -Identity $(ConvertTo-MtrPsLiteral $a.PrimarySmtpAddress) -TimeZone $(ConvertTo-MtrPsLiteral $majority.Name)")
        }
    }
    if ($outliers.Count) {
        New-MtrFinding -CheckId 'EXO-06' -Severity Medium -Category 'Exchange' -Title 'Room time zone differs from the other rooms in its room list or city' -AffectedObjects $outliers.ToArray() `
            -Impact 'Usually the Pacific default left in place; meeting times and working-hours rules are off for that room.' `
            -Recommendation 'Confirm the physical location and correct the time zone.' -FixLocation 'Exchange Online' -RemediationCommand $outlierCmds.ToArray() -Reference $links.TimeZone
    }
    $whMismatch = @($withTz | Where-Object { $_.Exchange.CalendarConfig -and $_.Exchange.Regional.TimeZone -and $_.Exchange.CalendarConfig.WorkingHoursTimeZone -and $_.Exchange.CalendarConfig.WorkingHoursTimeZone -ne $_.Exchange.Regional.TimeZone })
    if ($whMismatch.Count) {
        New-MtrFinding -CheckId 'EXO-07' -Severity Low -Category 'Exchange' -Title 'Working-hours time zone differs from the mailbox time zone' `
            -AffectedObjects @($whMismatch | ForEach-Object { '{0}: {1} vs {2}' -f $_.UserPrincipalName, $_.Exchange.Regional.TimeZone, $_.Exchange.CalendarConfig.WorkingHoursTimeZone }) `
            -Recommendation 'Align WorkingHoursTimeZone with the mailbox time zone.' -FixLocation 'Exchange Online' -Reference $links.TimeZone
    }

    # EXO-08 Hidden from address lists
    $hidden = @($mtr | Where-Object { $_.Mailbox -and $_.Mailbox.HiddenFromAddressListsEnabled })
    if ($hidden.Count) {
        New-MtrFinding -CheckId 'EXO-08' -Severity Medium -Category 'Exchange' -Title 'Teams Rooms hidden from the address book' `
            -AffectedObjects @($hidden | ForEach-Object UserPrincipalName) `
            -Impact 'Hidden rooms do not appear in Room Finder or Places finder, so users cannot book them.' `
            -Recommendation 'Unhide unless intentional. For synced rooms, clear msExchHideFromAddressLists on-prem (Set-RemoteMailbox -HiddenFromAddressListsEnabled $false).' `
            -FixLocation $(if (@($hidden | Where-Object IsSynced).Count) { 'On-prem Exchange' } else { 'Exchange Online' })
    }

    # EXO-09 EWS retirement
    $org = $Context.Exchange.OrganizationConfig
    $android = @($mtr | Where-Object { 'Android' -in $_.Platforms })
    if ($android.Count) {
        $minVersion = ConvertTo-MtrVersion $Baseline.Versions.AndroidAppMinForEwsRetirement
        $status = foreach ($a in $android) {
            $versions = @($a.Devices | Where-Object Platform -eq 'Android' | ForEach-Object { ConvertTo-MtrVersion $_.TeamsAppVersion } | Where-Object { $_ })
            $lowest = $versions | Sort-Object | Select-Object -First 1
            [pscustomobject]@{ Account = $a; Lowest = $lowest; Ok = ($lowest -and $lowest -ge $minVersion); MailboxEwsOff = ($a.Exchange -and $a.Exchange.Cas -and $a.Exchange.Cas.EwsEnabled -eq $false) }
        }
        $notOk = @($status | Where-Object { -not $_.Ok })
        $ewsOff = ($org -and $org.EwsEnabled -eq $false)
        $retire = ConvertTo-MtrDateTime $Baseline.Versions.EwsRetirementDate
        if ($notOk.Count) {
            $sev = if ($ewsOff -or @($notOk | Where-Object MailboxEwsOff).Count) { 'High' } elseif ($retire -and $Settings.Now -ge $retire.AddDays(-60)) { 'Medium' } else { 'Low' }
            New-MtrFinding -CheckId 'EXO-09' -Severity $sev -Category 'Exchange' -Title 'Android Teams Rooms may still use EWS for the room calendar' `
                -Target "$($notOk.Count) Android rooms" -AffectedObjects @($notOk | ForEach-Object { '{0} (Teams app {1}{2})' -f $_.Account.UserPrincipalName, $(if ($_.Lowest) { $_.Lowest } else { 'version not reported' }), $(if ($_.MailboxEwsOff) { '; EWS disabled on mailbox' }) }) `
                -Detail ("Exchange Online disables EWS starting {0}. Android rooms need Teams Rooms app {1} or later first. Organization EwsEnabled: {2}." -f $Baseline.Versions.EwsRetirementDate, $Baseline.Versions.AndroidAppMinForEwsRetirement, $(if ($org) { $org.EwsEnabled } else { 'unknown' })) `
                -Impact 'Rooms on older app builds lose their calendar (no scheduled meetings, no one-touch join) once EWS is off.' `
                -Recommendation 'Update the Teams Rooms app/firmware (Teams Admin Center or Logitech Sync) and confirm the version in TAC before EWS is disabled.' `
                -FixLocation 'Teams Admin Center' -Reference $links.EwsDeprecation
        }
    }
}

function Test-MtrPlaces {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $mtr = Get-MtrArray $Model.MtrAccounts
    $exo = $Context.Exchange
    $rooms = Get-MtrArray $exo.RoomMailboxes
    $lists = Get-MtrArray $exo.RoomLists
    $sourceNote = ''
    $membershipComplete = $true
    if (-not $rooms.Count -and $Context.Places -and (Get-MtrCount $Context.Places.Rooms)) {
        # Exchange data unavailable: build the room and room-list inventory from Graph Places instead.
        $sourceNote = ' (from Graph Places; Exchange Online data was unavailable)'
        $rooms = Get-MtrArray ((Get-MtrArray $Context.Places.Rooms) | ForEach-Object {
                $account = Get-MtrPropertyValue $Context.Places.RoomAccounts $_.emailAddress
                [pscustomobject]@{
                    PrimarySmtpAddress        = $_.emailAddress
                    ExternalDirectoryObjectId = if ($account) { $account.id } else { "place:$($_.emailAddress)" }
                    IsDirSynced               = [bool]($account -and $account.onPremisesSyncEnabled)
                }
            })
        $lists = Get-MtrArray ((Get-MtrArray $Context.Places.RoomLists) | ForEach-Object {
                $memberEmails = Get-MtrPropertyValue $Context.Places.RoomListMembers $_.emailAddress
                [pscustomobject]@{
                    DisplayName        = $_.displayName
                    PrimarySmtpAddress = $_.emailAddress
                    IsDirSynced        = $null
                    MemberError        = if ($null -eq $memberEmails) { 'Membership not collected' } else { $null }
                    Members            = @((Get-MtrArray $memberEmails) | ForEach-Object {
                            $account = Get-MtrPropertyValue $Context.Places.RoomAccounts $_
                            [pscustomobject]@{ PrimarySmtpAddress = $_; ExternalDirectoryObjectId = if ($account) { $account.id } else { "place:$_" } }
                        })
                }
            })
    }
    if (@($lists | Where-Object { $_.MemberError }).Count) { $membershipComplete = $false }
    $tenantSynced = [bool]($Context.Tenant -and $Context.Tenant.OnPremisesSyncEnabled)
    $mtrOids = @($mtr | ForEach-Object Id)
    $placeByEmail = @{}
    foreach ($p in (Get-MtrArray $Context.Places.Rooms)) { if ($p.emailAddress) { $placeByEmail[$p.emailAddress.ToLowerInvariant()] = $p } }
    $membership = @{}
    foreach ($l in $lists) { foreach ($m in (Get-MtrArray $l.Members)) { if ($m.ExternalDirectoryObjectId) { if (-not $membership[$m.ExternalDirectoryObjectId]) { $membership[$m.ExternalDirectoryObjectId] = [System.Collections.Generic.List[string]]::new() }; $membership[$m.ExternalDirectoryObjectId].Add($l.DisplayName) } } }
    $label = { param($r) if ($r.ExternalDirectoryObjectId -in $mtrOids) { "$($r.PrimarySmtpAddress) [Teams Room]" } else { $r.PrimarySmtpAddress } }

    if ($rooms.Count -and -not $lists.Count) {
        New-MtrFinding -CheckId 'RF-01' -Severity Medium -Category 'Room Finder' -Title 'No room lists exist' `
            -Impact 'Room Finder browses by room list (building); without lists users can only find rooms by name.' `
            -Detail "Rooms found: $($rooms.Count)$sourceNote." -Recommendation $(if ($tenantSynced) { 'Create one room list per building, named exactly like the building. Room lists are synced from AD in this tenant, so create them on-prem.' } else { 'Create one room list per building (New-DistributionGroup -RoomList), named exactly like the building.' }) -FixLocation $(if ($tenantSynced) { 'On-prem Exchange' } else { 'Exchange Online' }) -Reference $links.RoomFinder
    }
    $notListed = @($rooms | Where-Object { -not $membership[$_.ExternalDirectoryObjectId] })
    if ($lists.Count -and $notListed.Count -and $membershipComplete) {
        $mtrNotListed = @($notListed | Where-Object { $_.ExternalDirectoryObjectId -in $mtrOids })
        $listsSynced = @($lists | Where-Object IsDirSynced).Count -gt 0
        New-MtrFinding -CheckId 'RF-01' -Severity $(if ($mtrNotListed.Count) { 'Medium' } else { 'Low' }) -Category 'Room Finder' -Title "$($notListed.Count) room(s) are not in any room list ($($mtrNotListed.Count) Teams Rooms)" `
            -AffectedObjects @($notListed | ForEach-Object { & $label $_ }) `
            -Detail ("{0} of {1} room mailboxes are not a member of any room list. Existing room lists: {2}{3}." -f $notListed.Count, $rooms.Count, (Format-MtrList -Items @($lists | ForEach-Object DisplayName) -Max 10), $sourceNote) `
            -Impact 'Rooms outside a room list do not appear when users browse by building in Room Finder.' `
            -Recommendation $(if ($listsSynced) { 'Add each room to exactly one room list (its building). These room lists are synced from AD, so change membership on-prem (Add-DistributionGroupMember in Exchange Management Shell, or the group in AD).' } else { 'Add each room to exactly one room list (its building) with Add-DistributionGroupMember in Exchange Online.' }) `
            -FixLocation $(if ($listsSynced) { 'On-prem Exchange' } else { 'Exchange Online' }) -Reference $links.RoomFinder `
            -RemediationCommand @($notListed | Select-Object -First 200 | ForEach-Object { "Add-DistributionGroupMember -Identity '<room list>' -Member $(ConvertTo-MtrPsLiteral $_.PrimarySmtpAddress)" })
    }
    $multi = @($rooms | Where-Object { @($membership[$_.ExternalDirectoryObjectId]).Count -gt 1 })
    if ($multi.Count -and $membershipComplete) {
        New-MtrFinding -CheckId 'RF-02' -Severity Medium -Category 'Room Finder' -Title "$($multi.Count) room(s) are in more than one room list" `
            -AffectedObjects @($multi | ForEach-Object { '{0}: {1}' -f (& $label $_), ((@($membership[$_.ExternalDirectoryObjectId]) | Sort-Object -Unique) -join ', ') }) `
            -Impact 'Rooms show under the wrong building and Room Finder / Places finder disagree.' -Recommendation 'Keep each room in exactly one room list (its building).' `
            -FixLocation $(if (@($lists | Where-Object IsDirSynced).Count) { 'On-prem Exchange' } else { 'Exchange Online' }) -Reference $links.PlacesFinder
    }
    foreach ($l in $lists) {
        $count = (Get-MtrCount $l.Members)
        if ($l.MemberError) { continue }
        if ($count -eq 0) {
            New-MtrFinding -CheckId 'RF-03' -Severity Low -Category 'Room Finder' -Title "Room list '$($l.DisplayName)' is empty" -Recommendation 'Populate or remove the room list.' -FixLocation $(if ($l.IsDirSynced) { 'On-prem Exchange' } else { 'Exchange Online' })
            continue
        }
        if ($count -gt $Baseline.Thresholds.RoomListMaxMembers) {
            New-MtrFinding -CheckId 'RF-03' -Severity Low -Category 'Room Finder' -Title "Room list '$($l.DisplayName)' has $count rooms" `
                -Impact 'Room Finder returns at most 100 results; Microsoft recommends 50 or fewer per list.' -Recommendation 'Split by floor or wing.' -Reference $links.RoomFinder
        }
        $cities = @($l.Members | ForEach-Object { $p = $placeByEmail[([string]$_.PrimarySmtpAddress).ToLowerInvariant()]; if ($p -and $p.address.city) { $p.address.city } } | Sort-Object -Unique)
        if ($cities.Count -gt 1) {
            New-MtrFinding -CheckId 'RF-04' -Severity Medium -Category 'Room Finder' -Title "Room list '$($l.DisplayName)' mixes cities ($($cities -join ', '))" `
                -Impact 'Room Finder only shows the list when users filter by the majority city; rooms from the other cities are effectively hidden.' `
                -Recommendation 'Correct each room''s City (on-prem for synced rooms) or split the list.' -FixLocation 'On-prem AD' -Reference $links.RoomFinder
        }
    }

    # RF-05 Room metadata needed by Room Finder (from Graph Places, covers every room)
    if ($Context.Places -and (Get-MtrCount $Context.Places.Rooms)) {
        $graphRooms = Get-MtrArray $Context.Places.Rooms
        $syncedEmails = @($rooms | Where-Object IsDirSynced | ForEach-Object { ([string]$_.PrimarySmtpAddress).ToLowerInvariant() })
        $checks = @(
            @{ Name = 'City'; Test = { param($p) $p.address.city }; Severity = 'Medium'; OnPrem = $true; Cmd = { param($e, $synced) if ($synced) { "Set-User -Identity $(ConvertTo-MtrPsLiteral $e) -City '<city>'   # on-prem Exchange Management Shell (synced room)" } else { "Set-Place -Identity $(ConvertTo-MtrPsLiteral $e) -City '<city>'" } } }
            @{ Name = 'Floor'; Test = { param($p) $null -ne $p.floorNumber -or $p.floorLabel }; Severity = 'Medium'; OnPrem = $false; Cmd = { param($e) "Set-Place -Identity $(ConvertTo-MtrPsLiteral $e) -Floor <n> -FloorLabel '<label>'" } }
            @{ Name = 'Capacity'; Test = { param($p) $p.capacity -gt 0 }; Severity = 'Medium'; OnPrem = $false; Cmd = { param($e) "Set-Place -Identity $(ConvertTo-MtrPsLiteral $e) -Capacity <n>" } }
            @{ Name = 'Building'; Test = { param($p) $p.building }; Severity = 'Low'; OnPrem = $false; Cmd = { param($e) "Set-Place -Identity $(ConvertTo-MtrPsLiteral $e) -Building '<building>'" } }
        )
        foreach ($c in $checks) {
            $missing = @($graphRooms | Where-Object { -not (& $c.Test $_) })
            if (-not $missing.Count) { continue }
            $anySynced = @($missing | Where-Object { ([string]$_.emailAddress).ToLowerInvariant() -in $syncedEmails }).Count -gt 0
            New-MtrFinding -CheckId 'RF-05' -Severity $c.Severity -Category 'Room Finder' -Title "$($missing.Count) room(s) have no $($c.Name)" `
                -AffectedObjects @($missing | ForEach-Object emailAddress) `
                -Impact $(if ($c.Name -eq 'Building') { 'Needed for forward compatibility with Places.' } else { "Room Finder needs City, Floor and Capacity to browse and filter rooms." }) `
                -Recommendation $(if ($c.OnPrem -and $anySynced) { "Set $($c.Name) for these rooms. For synced rooms, Set-Place cannot change City/State/Street/Country/Postal code/Phone - set them on-prem (Set-User in Exchange Management Shell or the AD attribute) and let sync update Exchange Online." } else { "Set $($c.Name) with Set-Place (or Set-PlaceV3) in Exchange Online." }) `
                -FixLocation $(if ($c.OnPrem -and $anySynced) { 'On-prem Exchange' } else { 'Exchange Online' }) -Reference $links.RoomFinder `
                -RemediationCommand @($missing | Select-Object -First 200 | ForEach-Object { & $c.Cmd $_.emailAddress (([string]$_.emailAddress).ToLowerInvariant() -in $syncedEmails) })
        }
    }

    # RF-06 MTREnabled on Teams Rooms
    $notFlagged = @($mtr | Where-Object { $_.IsRoomMailbox -and (($_.ExoPlace -and $_.ExoPlace.MTREnabled -ne $true) -or (-not $_.ExoPlace -and $_.Place -and $_.Place.teamsEnabledState -ne 'enabled')) })
    if ($notFlagged.Count) {
        New-MtrFinding -CheckId 'RF-06' -Severity Medium -Category 'Room Finder' -Title 'Teams Rooms not marked as Teams Rooms (MTREnabled)' `
            -Target "$($notFlagged.Count) rooms" -AffectedObjects @($notFlagged | ForEach-Object UserPrincipalName) `
            -Impact 'Users filtering Room Finder for "Microsoft Teams Room" will not see these rooms, and the room cannot be offered as the audio source when joining.' `
            -Recommendation 'Set MTREnabled on the Place.' -FixLocation 'Exchange Online' -Reference $links.SetPlaceV3 `
            -RemediationCommand @($notFlagged | ForEach-Object { "Set-Place -Identity $(ConvertTo-MtrPsLiteral $_.PrimarySmtpAddress) -MTREnabled `$true" })
    }

    # RF-07 Places finder hierarchy
    if ($Context.Places -and $Context.Places.HierarchyAvailable) {
        $buildings = Get-MtrArray $Context.Places.Buildings
        if (-not $buildings.Count) {
            New-MtrFinding -CheckId 'RF-07' -Severity Low -Category 'Room Finder' -Title 'No Places buildings configured' `
                -Detail 'Places finder browses by building and floor; Microsoft is evaluating deprecating Room Finder and recommends starting with Places finder.' `
                -Recommendation 'Create buildings and floors (New-Place / Set-PlaceV3 in the MicrosoftPlaces module) and parent each room to its floor. Name each room list exactly like its building.' `
                -FixLocation 'Microsoft Places' -Reference $links.PlacesFinder
        }
        else {
            $unparented = @($mtr | Where-Object { $_.Place -and -not $_.Place.parentId })
            if ($unparented.Count) {
                New-MtrFinding -CheckId 'RF-07' -Severity Medium -Category 'Room Finder' -Title "$($unparented.Count) Teams Rooms are not placed in a building/floor" `
                    -AffectedObjects @($unparented | ForEach-Object UserPrincipalName) -Impact 'These rooms do not appear in Places finder.' `
                    -Recommendation 'Parent each room to its floor with Set-PlaceV3 -ParentId (and keep the room in the matching room list for Room Finder).' `
                    -FixLocation 'Microsoft Places' -Reference $links.SetPlaceV3
            }
            $buildingNames = @($buildings | ForEach-Object displayName)
            $mismatch = @($lists | Where-Object { $_.DisplayName -notin $buildingNames })
            if ($mismatch.Count) {
                New-MtrFinding -CheckId 'RF-08' -Severity Low -Category 'Room Finder' -Title 'Room list names do not match Places building names' `
                    -AffectedObjects @($mismatch | ForEach-Object DisplayName) -Detail "Buildings: $(Format-MtrList -Items $buildingNames -Max 10)" `
                    -Recommendation 'Name each room list exactly like its building so Room Finder and Places finder stay consistent.' -Reference $links.PlacesFinder
            }
        }
    }
    $synced = @($lists | Where-Object IsDirSynced)
    if ($synced.Count) {
        New-MtrFinding -CheckId 'RF-09' -Severity Info -Category 'Room Finder' -Title "$($synced.Count) of $($lists.Count) room lists are synced from on-prem" `
            -Detail 'Membership and names of synced room lists must be changed on-prem (Exchange Management Shell or AD); changes made in Exchange Online are rejected or overwritten.'
    }
}

function Test-MtrTeams {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $mtr = Get-MtrArray $Model.MtrAccounts
    if (-not $Context.Teams) { return }

    $notFound = @($mtr | Where-Object { $_.Teams -and -not $_.Teams.Found -and $_.Teams.NotFound -ne $false })
    if ($notFound.Count) {
        New-MtrFinding -CheckId 'TMS-01' -Severity High -Category 'Teams' -Title 'Teams Rooms accounts not found in Teams' `
            -AffectedObjects @($notFound | ForEach-Object { '{0}{1}' -f $_.UserPrincipalName, $(if ($_.Teams.Error) { " ($($_.Teams.Error))" }) }) `
            -Impact 'The account is not provisioned for Teams; the device cannot sign in to Teams.' -Recommendation 'Check the license (Teams service plan) and wait for provisioning.' -FixLocation 'Entra ID'
    }
    $found = @($mtr | Where-Object { $_.Teams -and $_.Teams.Found })
    $noTeams = @($found | Where-Object { (Get-MtrCount $_.Teams.FeatureTypes) -and @($_.Teams.FeatureTypes) -notcontains 'Teams' })
    if ($noTeams.Count) {
        New-MtrFinding -CheckId 'TMS-02' -Severity High -Category 'Teams' -Title 'Teams feature not enabled for room accounts' `
            -AffectedObjects @($noTeams | ForEach-Object { '{0} ({1})' -f $_.UserPrincipalName, (@($_.Teams.FeatureTypes) -join ', ') }) -FixLocation 'Entra ID'
    }
    $ineligible = @($found | Where-Object { $_.Teams.AccountType -eq 'IneligibleUser' })
    if ($ineligible.Count) {
        New-MtrFinding -CheckId 'TMS-02' -Severity High -Category 'Teams' -Title 'Room accounts are not eligible for Teams' -AffectedObjects @($ineligible | ForEach-Object UserPrincipalName) `
            -Impact 'No Teams license is effective for these accounts.' -FixLocation 'Entra ID'
    }
    $notTeamsOnly = @($found | Where-Object { $_.Teams.TeamsUpgradeEffectiveMode -and $_.Teams.TeamsUpgradeEffectiveMode -ne 'TeamsOnly' })
    if ($notTeamsOnly.Count) {
        New-MtrFinding -CheckId 'TMS-03' -Severity Medium -Category 'Teams' -Title 'Room accounts not in TeamsOnly mode' `
            -AffectedObjects @($notTeamsOnly | ForEach-Object { '{0} ({1})' -f $_.UserPrincipalName, $_.Teams.TeamsUpgradeEffectiveMode }) `
            -Recommendation 'Grant the TeamsOnly upgrade policy.' -FixLocation 'Teams PowerShell' `
            -RemediationCommand @($notTeamsOnly | ForEach-Object { "Grant-CsTeamsUpgradePolicy -Identity $(ConvertTo-MtrPsLiteral $_.UserPrincipalName) -PolicyName UpgradeToTeams" })
    }

    $policies = @{}
    foreach ($p in (Get-MtrArray $Context.Teams.IpPhonePolicies)) { $policies[($p.Identity -replace '^Tag:', '')] = $p.SignInMode }
    $globalMode = $policies['Global']
    $userLicensed = @($found | Where-Object { -not $_.HasMtrLicense -and $_.HasUserSuiteLicense -and 'Android' -in $_.Platforms })
    $wrongUi = @($userLicensed | Where-Object {
            $mode = if ($_.Teams.TeamsIPPhonePolicy) { $policies[$_.Teams.TeamsIPPhonePolicy] } else { $globalMode }
            $mode -ne 'MeetingSignIn'
        })
    if ($wrongUi.Count) {
        New-MtrFinding -CheckId 'TMS-04' -Severity Medium -Category 'Teams' -Title 'Android rooms on a user license without a MeetingSignIn IP phone policy' `
            -AffectedObjects @($wrongUi | ForEach-Object UserPrincipalName) `
            -Impact 'The device shows the personal user interface instead of the meeting room interface.' `
            -Recommendation 'Preferably license as Teams Rooms Pro; otherwise assign an IP phone policy with SignInMode MeetingSignIn.' -FixLocation 'Teams PowerShell' -Reference $links.IpPhonePolicy `
            -RemediationCommand (@('New-CsTeamsIPPhonePolicy -Identity ''Teams Rooms Meeting Sign-in'' -SignInMode MeetingSignIn') + @($wrongUi | ForEach-Object { "Grant-CsTeamsIPPhonePolicy -Identity $(ConvertTo-MtrPsLiteral $_.UserPrincipalName) -PolicyName 'Teams Rooms Meeting Sign-in'" }))
    }

    if ($found.Count) {
        $summary = @(
            ($found | Group-Object { if ($_.Teams.TeamsMeetingPolicy) { $_.Teams.TeamsMeetingPolicy } else { 'Global' } } | ForEach-Object { "Meeting policy $($_.Name): $($_.Count)" })
            ($found | Group-Object { if ($_.Teams.TeamsIPPhonePolicy) { $_.Teams.TeamsIPPhonePolicy } else { 'Global' } } | ForEach-Object { "IP phone policy $($_.Name): $($_.Count)" })
            ('Enterprise Voice enabled: {0}' -f @($found | Where-Object { $_.Teams.EnterpriseVoiceEnabled }).Count)
        )
        New-MtrFinding -CheckId 'TMS-05' -Severity Info -Category 'Teams' -Title 'Teams policy assignments on room accounts' -AffectedObjects $summary
    }
}
