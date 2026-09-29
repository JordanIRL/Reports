# Orchestrates collection:
#   A. find candidate accounts (licenses, seeds, Places, room mailboxes) - one Exchange call covers the room
#      inventory and every candidate known so far
#   B. devices, then detail for every candidate (identity, CA, groups, Exchange follow-up, Teams)
# Tenant-level data (CA policies, security defaults, registration policies, room lists) is collected even when
# no candidate accounts are found, so those checks still run.

function Invoke-MtrCollection {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Session,
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)][string[]]$Sections,
        [string[]]$ResourceAccountUpn,
        [string]$ResourceAccountCsv,
        [string[]]$MtrGroupId,
        [string[]]$UpnPattern,
        [string]$WindowsDeviceNamePattern,
        [int]$SignInLookbackDays = 7,
        [switch]$SkipSignInLogs
    )
    $ctx = $Context
    $candidates = @{}
    $upnById = @{}
    $addCandidate = {
        param([string]$Id, [string]$Source, [string]$Upn)
        if (-not $Id) { return }
        if (-not $candidates.ContainsKey($Id)) { $candidates[$Id] = [System.Collections.Generic.List[string]]::new() }
        if (-not $candidates[$Id].Contains($Source)) { $candidates[$Id].Add($Source) }
        if ($Upn -and -not $upnById[$Id]) { $upnById[$Id] = $Upn }
    }
    $useExchange = $Session.Exchange -ne 'Unavailable' -and ('Exchange' -in $Sections -or 'Places' -in $Sections)

    Write-Information 'Phase A: discovering Teams Rooms accounts' -InformationAction Continue
    $ctx.Tenant = Invoke-MtrCollectorStep -Context $ctx -Section 'Tenant' -Item 'Organization, domains, directory sync' -ScriptBlock { Get-MtrTenantData }
    if ($ctx.Tenant) { $ctx.Meta.TenantId = $ctx.Tenant.Id; $ctx.Meta.TenantName = $ctx.Tenant.DisplayName }
    $ctx.Licensing = Invoke-MtrCollectorStep -Context $ctx -Section 'Licensing' -Item 'Subscribed SKUs' -ScriptBlock { Get-MtrLicensingData -Baseline $Baseline }

    if ($ctx.Licensing) {
        $null = Invoke-MtrCollectorStep -Context $ctx -Section 'Licensing' -Item 'Accounts with Teams Rooms / Shared Devices licenses' -ScriptBlock {
            $skuIds = @($ctx.Licensing.Skus | Where-Object { $_.IsTeamsRooms -or $_.IsSharedDevice } | ForEach-Object { $_.SkuId })
            $licensed = Get-MtrUsersBySku -SkuIds $skuIds
            foreach ($id in $licensed.Keys) { & $addCandidate $id 'License' $licensed[$id] }
        }
    }

    $ctx.Seeds = Invoke-MtrCollectorStep -Context $ctx -Section 'Discovery' -Item 'Admin-supplied seeds' -ScriptBlock {
        Get-MtrSeedUsers -ResourceAccountUpn $ResourceAccountUpn -ResourceAccountCsv $ResourceAccountCsv -MtrGroupId $MtrGroupId -UpnPattern $UpnPattern
    }
    foreach ($s in (Get-MtrArray $ctx.Seeds)) { & $addCandidate $s.Id $s.Source $s.UserPrincipalName }

    if ('Places' -in $Sections) {
        $ctx.Places = Invoke-MtrCollectorStep -Context $ctx -Section 'Places' -Item 'Rooms, room lists, buildings (Graph Places)' -ScriptBlock { Get-MtrPlacesData -Context $ctx }
        if ($ctx.Places) {
            # Resolve each Place room to its account, so room accounts are found even if Exchange is unavailable.
            $null = Invoke-MtrCollectorStep -Context $ctx -Section 'Places' -Item 'Room accounts behind Places rooms' -ScriptBlock {
                $ctx.Places.RoomAccounts = Get-MtrPlacesRoomAccount -Rooms (Get-MtrArray $ctx.Places.Rooms) -Context $ctx
                foreach ($entry in @(Get-MtrMapEntry -Map $ctx.Places.RoomAccounts)) {
                    $account = $entry.Value
                    $room = @($ctx.Places.Rooms | Where-Object { $_.emailAddress -eq $entry.Key }) | Select-Object -First 1
                    if ($account.accountEnabled) { & $addCandidate $account.id 'RoomMailboxEnabledAccount' $account.userPrincipalName }
                    if ($room -and $room.teamsEnabledState -eq 'enabled') { & $addCandidate $account.id 'PlaceTeamsEnabled' $account.userPrincipalName }
                }
            }
        }
    }

    $ctx.Exchange = [pscustomobject]@{ RoomMailboxes = @(); RoomLists = @(); OrganizationConfig = $null; Candidates = @() }
    $exchangeOk = $false
    if ($useExchange) {
        $exo = Invoke-MtrCollectorStep -Context $ctx -Section 'Exchange' -Item 'Room mailboxes, room lists, org config and candidate mailboxes' -ScriptBlock {
            $identities = @($candidates.Keys | ForEach-Object { $upnById[$_] } | Where-Object { $_ })
            Invoke-MtrServiceCall -Service Exchange -FunctionName 'Get-MtrExchangeData' -Session $Session -Arguments @{ Identities = $identities }
        }
        if ($exo) {
            $ctx.Exchange.RoomMailboxes = Get-MtrArray $exo.RoomMailboxes
            $ctx.Exchange.RoomLists = Get-MtrArray $exo.RoomLists
            $ctx.Exchange.OrganizationConfig = $exo.OrganizationConfig
            $ctx.Exchange.Candidates = Get-MtrArray $exo.Candidates
            $exchangeOk = $true
        }
    }
    else {
        Add-MtrCoverage -Context $ctx -Section 'Exchange' -Item 'Exchange Online' -Status Skipped -Detail 'Exchange section not selected or Exchange unavailable. Room accounts are still found through Graph Places.'
    }

    $ctx.Identity = [pscustomobject]@{ Candidates = @(); Users = @(); Extra = $null; RoomAccountStatus = @{} }
    if ((Get-MtrCount $ctx.Exchange.RoomMailboxes)) {
        $null = Invoke-MtrCollectorStep -Context $ctx -Section 'Identity' -Item 'Room mailbox account status' -ScriptBlock {
            $ids = @($ctx.Exchange.RoomMailboxes | ForEach-Object { $_.ExternalDirectoryObjectId } | Where-Object { $_ })
            $requests = foreach ($id in $ids) { [pscustomobject]@{ Id = $id; Url = "/users/$id`?`$select=id,accountEnabled,userPrincipalName" } }
            $responses = Invoke-MtrGraphBatch -Requests @($requests)
            Add-MtrBatchCoverage -Context $ctx -Section 'Identity' -Item 'Room mailbox account status (lookups)' -Responses $responses
            foreach ($id in $ids) {
                $r = $responses[$id]
                if ($r -and $r.Status -eq 200) {
                    $ctx.Identity.RoomAccountStatus[$id] = [bool]$r.Body.accountEnabled
                    if ($r.Body.accountEnabled) { & $addCandidate $id 'RoomMailboxEnabledAccount' $r.Body.userPrincipalName }
                }
            }
        }
    }

    Write-Information "Phase B: devices and detail for $($candidates.Count) candidate account(s)" -InformationAction Continue
    if ('Intune' -in $Sections) {
        try { $ctx.Intune = Get-MtrIntuneData -Context $ctx -Baseline $Baseline -CandidateUserIds @($candidates.Keys) -WindowsDeviceNamePattern $WindowsDeviceNamePattern }
        catch { Add-MtrCoverage -Context $ctx -Section 'Intune' -Item 'Intune collection' -Status Failed -Detail $_.Exception.Message; Write-Warning "Intune collection failed: $($_.Exception.Message)" }
        foreach ($d in (Get-MtrArray $ctx.Intune.Devices)) { if ($d.userId) { & $addCandidate $d.userId 'IntuneDevice' $d.userPrincipalName } }
        foreach ($tw in (Get-MtrArray $ctx.Intune.TeamworkDevices)) { if ($tw.currentUserId) { & $addCandidate $tw.currentUserId 'TeamsDevice' $null } }
    }

    $ids = @($candidates.Keys)
    $ctx.Identity.Candidates = @($ids | ForEach-Object { [pscustomobject]@{ Id = $_; Sources = @($candidates[$_]) } })
    if ($ids.Count) {
        $ctx.Identity.Users = @(Invoke-MtrCollectorStep -Context $ctx -Section 'Identity' -Item 'Candidate accounts (profile, licenses, memberships)' -ScriptBlock {
                Get-MtrUserDetail -UserIds $ids -Context $ctx
            })
    }
    else {
        Write-Warning 'No candidate Teams Rooms accounts were found. Tenant-level checks still run. Use -ResourceAccountUpn, -ResourceAccountCsv, -MtrGroupId or -UpnPattern to seed discovery.'
        Add-MtrCoverage -Context $ctx -Section 'Discovery' -Item 'Candidate accounts' -Status Skipped -Detail 'No account had a Teams Rooms license, device, seed or enabled room mailbox; per-account checks had nothing to evaluate.'
    }

    if ('Identity' -in $Sections) {
        try { $ctx.Identity.Extra = Get-MtrIdentityExtra -UserIds $ids -Context $ctx -SignInLookbackDays $SignInLookbackDays -SkipSignInLogs:$SkipSignInLogs -SignInsPerAccount $Baseline.Thresholds.SignInsPerAccount }
        catch { Add-MtrCoverage -Context $ctx -Section 'Identity' -Item 'Identity collection' -Status Failed -Detail $_.Exception.Message; Write-Warning "Identity collection failed: $($_.Exception.Message)" }
    }

    if ('ConditionalAccess' -in $Sections) {
        $ctx.ConditionalAccess = Invoke-MtrCollectorStep -Context $ctx -Section 'ConditionalAccess' -Item 'Policies and named locations' -ScriptBlock { Get-MtrConditionalAccessData }
    }

    if ('Groups' -in $Sections -or 'ConditionalAccess' -in $Sections) {
        $null = Invoke-MtrCollectorStep -Context $ctx -Section 'Groups' -Item 'Group membership analysis' -ScriptBlock {
            $groupCounts = @{}
            foreach ($u in (Get-MtrArray $ctx.Identity.Users)) { foreach ($g in (Get-MtrArray $u.Groups)) { $groupCounts[$g.id] = 1 + [int]$groupCounts[$g.id] } }
            $caGroups = @($ctx.ConditionalAccess.Policies | ForEach-Object { @($_.conditions.users.includeGroups) + @($_.conditions.users.excludeGroups) } | Where-Object { $_ -and $groupCounts.ContainsKey($_) })
            $ctx.Groups = Get-MtrGroupData -CandidateGroupCounts $groupCounts -ExtraGroupIds (@($caGroups) + @($MtrGroupId))
            # Members of groups that look like Teams Rooms groups (or are used by CA and contain rooms), capped in size.
            $interesting = @($groupCounts.Keys | Where-Object {
                    $count = $ctx.Groups.MemberCounts[$_]
                    $count -and $count -le 2000 -and (($groupCounts[$_] / [double]$count) -ge 0.5 -or $_ -in $caGroups -or $_ -in @($MtrGroupId))
                })
            $ctx.Groups.Members = Get-MtrGroupMember -GroupIds $interesting
        }
    }

    # Exchange detail for candidates discovered after the Exchange call (for example from Intune devices)
    if ($exchangeOk) {
        $covered = @{}
        foreach ($c in (Get-MtrArray $ctx.Exchange.Candidates)) { if ($c.Identity) { $covered[$c.Identity.ToLowerInvariant()] = $true } }
        $missing = @($ctx.Identity.Users | ForEach-Object { $_.User.userPrincipalName } | Where-Object { $_ -and -not $covered[$_.ToLowerInvariant()] })
        if ($missing.Count) {
            $null = Invoke-MtrCollectorStep -Context $ctx -Section 'Exchange' -Item 'Mailboxes of candidates found after the first Exchange pass' -ScriptBlock {
                $more = Invoke-MtrServiceCall -Service Exchange -FunctionName 'Get-MtrExchangeData' -Session $Session -Arguments @{ Identities = $missing; SkipRoomInventory = $true }
                if ($more) { $ctx.Exchange.Candidates = Get-MtrArray (@($ctx.Exchange.Candidates) + (Get-MtrArray $more.Candidates)) }
            }
        }
    }

    if ($exchangeOk) {
        $withErrors = @($ctx.Exchange.Candidates | Where-Object { (Get-MtrCount $_.Errors) })
        if ($withErrors.Count) {
            Add-MtrCoverage -Context $ctx -Section 'Exchange' -Item 'Per-mailbox lookups' -Status Partial -Detail ("{0} of {1} mailbox lookups had errors, so their Exchange checks are incomplete. Example - {2}: {3}" -f $withErrors.Count, (Get-MtrCount $ctx.Exchange.Candidates), $withErrors[0].Identity, @($withErrors[0].Errors)[0])
        }
    }

    if ('Teams' -in $Sections) {
        $upns = @($ctx.Identity.Users | ForEach-Object { $_.User.userPrincipalName } | Where-Object { $_ })
        if ($Session.Teams -eq 'Unavailable') {
            Add-MtrCoverage -Context $ctx -Section 'Teams' -Item 'Microsoft Teams' -Status Failed -Detail "Not connected. $($Session.Errors['Teams'])"
        }
        elseif (-not $upns.Count) {
            Add-MtrCoverage -Context $ctx -Section 'Teams' -Item 'Microsoft Teams' -Status Skipped -Detail 'No candidate accounts to look up.'
        }
        else {
            $ctx.Teams = Invoke-MtrCollectorStep -Context $ctx -Section 'Teams' -Item 'Teams user configuration and IP phone policies' -ScriptBlock {
                Invoke-MtrServiceCall -Service Teams -FunctionName 'Get-MtrTeamsData' -Session $Session -Arguments @{ UserPrincipalNames = $upns }
            }
            $teamsErrors = @($ctx.Teams.Users | Where-Object { -not $_.Found -and -not $_.NotFound })
            if ($teamsErrors.Count) { Add-MtrCoverage -Context $ctx -Section 'Teams' -Item 'Per-account lookups' -Status Partial -Detail ("{0} of {1} Teams lookups failed. Example - {2}: {3}" -f $teamsErrors.Count, $upns.Count, $teamsErrors[0].UserPrincipalName, $teamsErrors[0].Error) }
            if ($ctx.Teams -and $ctx.Teams.IpPhonePolicyError) { Add-MtrCoverage -Context $ctx -Section 'Teams' -Item 'IP phone policies' -Status Failed -Detail $ctx.Teams.IpPhonePolicyError }
        }
    }
}
