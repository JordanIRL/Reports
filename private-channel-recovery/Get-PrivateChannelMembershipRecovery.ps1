#Requires -Version 7.0
<#
.TITLE
    Get Private Channel Membership Recovery Plan

.SYNOPSIS
    Rebuilds who should be in each Teams private channel after a membership loss, allowing for people already re-added and for changes made since.

.DESCRIPTION
    Read-only. Enumerates every private channel with its current owners and members, runs Microsoft
    Purview audit log queries for Teams membership events (MemberAdded, MemberRemoved,
    MemberRoleChanged, ChannelAdded), and replays those events per channel. It compares the roster
    the audit log says existed when the incident hit with who is in the channel right now, so people
    who were already re-added are left alone, people re-added without their owner role are proposed
    for promotion, and people removed again on purpose after being re-added are not proposed.
    Anything the evidence cannot settle is marked Review. Nothing in the tenant is changed.

.TAGS
    Operational,Monitoring

.PLATFORM
    Cross-platform

.PERMISSIONS
    Team.ReadBasic.All,Channel.ReadBasic.All,ChannelMember.Read.All,GroupMember.Read.All,User.Read.All,AuditLogsQuery.Read.All

.AUTHOR
    AI Generated (Claude, following IntuneAutomation.com conventions)

.VERSION
    1.3

.CHANGELOG
    1.0 - Initial release
    1.1 - Analyses every private channel, not only empty ones. Adds an incident window, detects manual
          re-adds, lost owner roles, removals after re-add and members new since the incident. Adds
          account status, a current-members report and an Action column in the plan.
    1.2 - Audit search split into windows, checked for truncation and resumable with -AuditQueryId.
          Role numbering checked against live roles, with -RoleNumbering to force it. Deterministic
          event order with same-second ties sent to Review. Handles removals the audit log missed,
          re-removals by the incident account, removals inside the window after a manual re-add,
          unreadable rosters and deleted channels that shared a name. Adds a UserId column, the
          ReviewOnly status and culture-independent timestamps.
    1.3 - Caps and retries audit query submission. Role numbering only trusts strong, consistent
          live evidence. Team-level removals outside the window, role changes inside the window,
          re-adds after a possibly deliberate removal and same-second ties all send rows to Review.
          The suggested incident start covers the whole removal burst.

.LASTUPDATE
    2026-10-03

.EXAMPLE
    .\Get-PrivateChannelMembershipRecovery.ps1 -TeamId 00000000-0000-0000-0000-000000000000
    Narrow first run against one affected team. Without -IncidentStart every removed user is marked Review
    and the script suggests an incident start time from the removal spike.

.EXAMPLE
    .\Get-PrivateChannelMembershipRecovery.ps1 -IncidentStart '2026-09-28T13:00:00Z' -IncidentEnd '2026-09-28T16:00:00Z'
    Tenant-wide run. Removals inside the window are treated as the incident and proposed for restore.

.EXAMPLE
    .\Get-PrivateChannelMembershipRecovery.ps1 -AuditRecordsPath .\audit-records.json -IncidentStart '2026-09-28T13:00:00Z'
    Re-runs the analysis against live channel state using a saved audit export instead of a new audit query.

.EXAMPLE
    .\Get-PrivateChannelMembershipRecovery.ps1 -AuditQueryId 1a2b...,3c4d... -IncidentStart '2026-09-28T13:00:00Z'
    Collects audit queries submitted by an earlier run that timed out, without submitting new ones.

.NOTES
    - Run as a Teams Administrator (or Global Administrator) who can also search the audit log.
      Teams service admins can read teams and private channels they are not a member of.
    - IncidentStart and IncidentEnd are UTC. IncidentEnd defaults to 24 hours after IncidentStart.
      Keep the window tight: a removal after the window is treated as a later change.
    - The audit log only goes back as far as your retention (180 days on Audit Standard, longer with
      Audit Premium). Members added before that and never touched since will not appear.
    - A saved audit export or a resumed query goes stale. Re-adds made after it are still seen
      (current state is always read live) but later removals are not, so use a fresh query before
      the final restore.
    - People are matched by user principal name. Someone renamed since the incident shows as
      AccountStatus NotFound and is marked Review.
    - Microsoft documents the audit Role value both as 0/1/2 and as 1/2/3. The script checks which
      numbering matches current channel roles, warns when it cannot tell, and marks every proposed
      owner Review in that case. Use -RoleNumbering to force it once you have checked.
    - Output files contain user names. Treat them as sensitive and delete them when you are done.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Limit the run to these team (group) IDs. Omit for all teams.")]
    [ValidateNotNullOrEmpty()]
    [string[]]$TeamId,

    [Parameter(Mandatory = $false, HelpMessage = "How many days of audit history to search")]
    [ValidateRange(1, 365)]
    [int]$DaysBack = 180,

    [Parameter(Mandatory = $false, HelpMessage = "UTC time the membership loss started")]
    [datetime]$IncidentStart,

    [Parameter(Mandatory = $false, HelpMessage = "UTC time the membership loss ended. Defaults to IncidentStart plus 24 hours.")]
    [datetime]$IncidentEnd,

    [Parameter(Mandatory = $false, HelpMessage = "Reuse a previously saved audit-records.json instead of running a new audit query")]
    [string]$AuditRecordsPath,

    [Parameter(Mandatory = $false, HelpMessage = "Collect audit queries submitted by an earlier run instead of submitting new ones")]
    [ValidateNotNullOrEmpty()]
    [string[]]$AuditQueryId,

    [Parameter(Mandatory = $false, HelpMessage = "Days covered by each audit query; smaller windows avoid the per-query record limit")]
    [ValidateRange(1, 90)]
    [int]$AuditWindowDays = 15,

    [Parameter(Mandatory = $false, HelpMessage = "Minutes to wait for the audit queries to finish")]
    [ValidateRange(5, 2880)]
    [int]$AuditTimeoutMinutes = 120,

    [Parameter(Mandatory = $false, HelpMessage = "Audit Role numbering: Auto, ZeroBased (0 Member/1 Owner/2 Guest) or OneBased (1 Member/2 Owner/3 Guest)")]
    [ValidateSet('Auto', 'ZeroBased', 'OneBased')]
    [string]$RoleNumbering = 'Auto',

    [Parameter(Mandatory = $false, HelpMessage = "Folder for the output files")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".",

    [Parameter(Mandatory = $false, HelpMessage = "Force module installation without prompting")]
    [switch]$ForceModuleInstall
)

# ============================================================================
# ENVIRONMENT DETECTION AND SETUP
# ============================================================================

function Initialize-RequiredModule {
    param(
        [string[]]$ModuleNames,
        [bool]$IsAutomationEnvironment,
        [bool]$ForceInstall = $false
    )

    foreach ($ModuleName in $ModuleNames) {
        $module = Get-Module -ListAvailable -Name $ModuleName | Select-Object -First 1

        if (-not $module) {
            if ($IsAutomationEnvironment) {
                throw "Module '$ModuleName' is not available in Azure Automation"
            }
            if (-not $ForceInstall) {
                $response = Read-Host "Install module '$ModuleName'? (Y/N)"
                if ($response -notmatch '^[Yy]') {
                    throw "Module '$ModuleName' is required but installation was declined."
                }
            }
            # CurrentUser keeps this working on macOS/Linux, where there is no Windows admin check
            Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -Repository PSGallery
            Write-Information "Installed '$ModuleName'" -InformationAction Continue
        }

        Import-Module -Name $ModuleName -Force -ErrorAction Stop
    }
}

$IsAzureAutomation = $null -ne $PSPrivateMetadata.JobId.Guid
$RequiredModules = @("Microsoft.Graph.Authentication")
$GraphBase = "https://graph.microsoft.com/beta"
# Custom date formats are culture-sensitive (':' becomes the culture's time separator), so pin them
$Inv = [Globalization.CultureInfo]::InvariantCulture

try {
    Initialize-RequiredModule -ModuleNames $RequiredModules -IsAutomationEnvironment $IsAzureAutomation -ForceInstall $ForceModuleInstall
}
catch {
    Write-Error "Module initialization failed: $_"
    exit 1
}

# ============================================================================
# AUTHENTICATION
# ============================================================================

try {
    if ($IsAzureAutomation) {
        Write-Output "Connecting to Microsoft Graph using Managed Identity..."
        Connect-MgGraph -Identity -NoWelcome -ErrorAction Stop
    }
    else {
        Write-Information "Connecting to Microsoft Graph..." -InformationAction Continue
        $Scopes = @(
            "Team.ReadBasic.All",
            "Channel.ReadBasic.All",
            "ChannelMember.Read.All",
            "GroupMember.Read.All",
            "User.Read.All"
        )
        if (-not $AuditRecordsPath) { $Scopes += "AuditLogsQuery.Read.All" }
        Connect-MgGraph -Scopes $Scopes -NoWelcome -ErrorAction Stop
    }
    Write-Information "Successfully connected to Microsoft Graph" -InformationAction Continue
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Get-HttpStatusCode {
    param($ErrorRecord)

    try { return [int]$ErrorRecord.Exception.Response.StatusCode } catch { return 0 }
}

function Get-MgGraphAllPage {
    param(
        [string]$Uri,
        [int]$DelayMs = 100
    )

    $allResults = [System.Collections.Generic.List[object]]::new()
    $nextLink = $Uri
    $attempt = 0

    while ($nextLink) {
        try {
            $response = Invoke-MgGraphRequest -Uri $nextLink -Method GET -ErrorAction Stop
            $attempt = 0

            # An empty collection must stay empty: a channel with no members is the case we are hunting
            if ($response.ContainsKey('value')) {
                foreach ($item in $response.value) { $allResults.Add($item) }
            }
            else {
                $allResults.Add($response)
            }

            $nextLink = $response.'@odata.nextLink'
            if ($nextLink) { Start-Sleep -Milliseconds $DelayMs }
        }
        catch {
            $err = $_
            $attempt++
            $code = Get-HttpStatusCode $err
            $transient = $code -in @(429, 502, 503, 504) -or
                $err.Exception.Message -match '\b(429|502|503|504)\b|TooManyRequests|BadGateway|ServiceUnavailable|GatewayTimeout|Too many retries'
            if ($transient -and $attempt -le 5) {
                Write-Information "Graph busy or throttled, waiting 60 seconds (attempt $attempt of 5)..." -InformationAction Continue
                Start-Sleep -Seconds 60
                continue
            }
            throw $err
        }
    }

    $allResults
}

function ConvertTo-UtcDate {
    param($Value)

    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Unspecified) { return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) }
        return $Value.ToUniversalTime()
    }
    $styles = [Globalization.DateTimeStyles]::AssumeUniversal -bor [Globalization.DateTimeStyles]::AdjustToUniversal
    return [datetime]::Parse("$Value", $Inv, $styles)
}

function Format-UtcDate {
    param($Value)

    if ($null -eq $Value) { return $null }
    return $Value.ToString('yyyy-MM-ddTHH:mm:ssZ', $Inv)
}

function Get-TeamsAuditRecord {
    param(
        [datetime]$Start,
        [datetime]$End,
        [int]$TimeoutMinutes,
        [int]$WindowDays,
        [string[]]$QueryId
    )

    $ids = [System.Collections.Generic.List[string]]::new()
    if ($QueryId) {
        foreach ($id in $QueryId) { $ids.Add($id) }
        Write-Information "Collecting $($ids.Count) existing audit query(ies); no new query submitted." -InformationAction Continue
    }
    else {
        # One query per window so no single query approaches the per-query record limit.
        # A tenant is only guaranteed 50 queued or running audit queries (429 beyond that) and 200 submissions a day.
        $windowCount = [int][math]::Ceiling(($End - $Start).TotalDays / $WindowDays)
        if ($windowCount -gt 40) {
            throw "-DaysBack and -AuditWindowDays would submit $windowCount audit queries, but a tenant is only guaranteed 50 queued or running at once. Raise -AuditWindowDays or lower -DaysBack so DaysBack / AuditWindowDays is 40 or less."
        }
        $from = $Start
        while ($from -lt $End) {
            $to = $from.AddDays($WindowDays)
            if ($to -gt $End) { $to = $End }
            $body = @{
                displayName         = "PrivateChannelRecovery-$($from.ToString('yyyyMMdd', $Inv))-$($to.ToString('yyyyMMdd', $Inv))"
                filterStartDateTime = $from.ToString('yyyy-MM-ddTHH:mm:ssZ', $Inv)
                filterEndDateTime   = $to.ToString('yyyy-MM-ddTHH:mm:ssZ', $Inv)
                recordTypeFilters   = @('microsoftTeams')
                operationFilters    = @('MemberAdded', 'MemberRemoved', 'MemberRoleChanged', 'ChannelAdded')
            } | ConvertTo-Json -Depth 5
            $query = $null
            $attempt = 0
            while ($null -eq $query) {
                try {
                    $query = Invoke-MgGraphRequest -Method POST -Uri "$GraphBase/security/auditLog/queries" -Body $body -ContentType 'application/json' -ErrorAction Stop
                }
                catch {
                    $err = $_
                    $attempt++
                    $code = Get-HttpStatusCode $err
                    $transient = $code -in @(429, 502, 503, 504) -or
                        $err.Exception.Message -match '\b(429|502|503|504)\b|TooManyRequests|BadGateway|ServiceUnavailable|GatewayTimeout|Too many retries'
                    if ($transient -and $attempt -le 4) {
                        Write-Information "Audit query submission throttled or unavailable, waiting $(60 * $attempt) seconds (attempt $attempt of 4)..." -InformationAction Continue
                        Start-Sleep -Seconds (60 * $attempt)
                        continue
                    }
                    if ($ids.Count -gt 0) {
                        Write-Warning "Submission stopped after $($ids.Count) of $windowCount window(s). These queries keep running and count against the tenant's audit query limits until they finish, but they cover only the oldest part of the range: do NOT pass them to -AuditQueryId. Wait for them to finish, then re-run without -AuditQueryId. IDs: $($ids -join ',')"
                    }
                    throw $err
                }
            }
            $ids.Add("$($query.id)")
            Write-Information "Submitted audit query $($query.id) for $($from.ToString('yyyy-MM-dd', $Inv)) to $($to.ToString('yyyy-MM-dd', $Inv))" -InformationAction Continue
            $from = $to
        }
        Write-Information "Submitted $($ids.Count) audit query window(s). If this run stops, re-run with -AuditQueryId $($ids -join ',') to collect them without submitting new ones." -InformationAction Continue
    }

    $deadline = (Get-Date).AddMinutes($TimeoutMinutes)
    $final = @{}
    while ($true) {
        foreach ($id in $ids) {
            if ($final.ContainsKey($id)) { continue }
            $q = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/security/auditLog/queries/$id" -ErrorAction Stop
            Write-Verbose "Audit query $id status: $($q.status)"
            if ($q.status -notin @('notStarted', 'running')) { $final[$id] = $q }
        }
        if ($final.Count -eq $ids.Count -or (Get-Date) -ge $deadline) { break }
        Start-Sleep -Seconds 30
    }

    $stillRunning = @($ids | Where-Object { -not $final.ContainsKey($_) })
    if ($stillRunning.Count -gt 0) {
        throw "$($stillRunning.Count) audit query(ies) still running after $TimeoutMinutes minutes. They keep running in the service; re-run later with -AuditQueryId $($ids -join ',') to collect them."
    }
    foreach ($id in $ids) {
        $q = $final[$id]
        if ($q.status -ne 'succeeded') {
            throw "Audit query $id ended with status '$($q.status)'. Re-run without -AuditQueryId to submit new queries."
        }
        if ($q.isRecordCountLimitExceeded) {
            throw "Audit query $id hit its record limit ($($q.recordCountLimit)), so its results are incomplete and must not be used to rebuild rosters. Re-run with a smaller -AuditWindowDays."
        }
    }

    $all = [System.Collections.Generic.List[object]]::new()
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($id in $ids) {
        foreach ($r in @(Get-MgGraphAllPage -Uri "$GraphBase/security/auditLog/queries/$id/records")) {
            # Adjacent windows share a boundary second; drop the duplicate, never a record without an id
            if (-not $r.id -or $seen.Add("$($r.id)")) { $all.Add($r) }
        }
    }
    $all
}

function Get-AuditPayload {
    param($Record)

    $data = $Record.auditData
    if ($null -eq $data) { return $null }
    # Graph documents the event fields under auditData.dynamicProperties; responses have also carried them on auditData itself
    if ($null -ne $data.dynamicProperties -and -not $data.ChannelGuid -and -not $data.AADGroupId -and -not $data.ChannelName -and -not $data.Members) {
        return $data.dynamicProperties
    }
    return $data
}

$script:AccountCache = @{}
function Get-AccountInfo {
    param(
        [string]$Upn,
        $TeamUsers
    )

    $key = $Upn.ToLowerInvariant()
    if ($TeamUsers -and $TeamUsers.ContainsKey($key)) {
        $u = $TeamUsers[$key]
        $status = if ($null -eq $u.Enabled) { 'Unknown' } elseif ($u.Enabled) { 'Active' } else { 'Disabled' }
        return @{ Status = $status; Id = $u.Id }
    }
    if ($script:AccountCache.ContainsKey($key)) { return $script:AccountCache[$key] }

    try {
        $user = Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/users/$([uri]::EscapeDataString($Upn))?`$select=id,accountEnabled" -ErrorAction Stop
        $status = if ($null -eq $user.accountEnabled) { 'Unknown' } elseif ($user.accountEnabled) { 'Active' } else { 'Disabled' }
        $info = @{ Status = $status; Id = $user.id }
    }
    catch {
        $notFound = (Get-HttpStatusCode $_) -eq 404 -or $_.Exception.Message -match 'NotFound|ResourceNotFound'
        $info = @{ Status = $(if ($notFound) { 'NotFound' } else { 'Unknown' }); Id = $null }
    }
    $script:AccountCache[$key] = $info
    return $info
}

# ============================================================================
# MAIN SCRIPT LOGIC
# ============================================================================

try {
    if ($AuditRecordsPath -and $AuditQueryId) { throw "Use either -AuditRecordsPath or -AuditQueryId, not both." }
    if (-not (Test-Path -Path $OutputPath)) { $null = New-Item -Path $OutputPath -ItemType Directory -ErrorAction Stop }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

    $incidentStartUtc = $null
    $incidentEndUtc = $null
    if ($PSBoundParameters.ContainsKey('IncidentStart')) {
        $incidentStartUtc = ConvertTo-UtcDate $IncidentStart
        $incidentEndUtc = if ($PSBoundParameters.ContainsKey('IncidentEnd')) { ConvertTo-UtcDate $IncidentEnd } else { $incidentStartUtc.AddHours(24) }
        if ($incidentEndUtc -le $incidentStartUtc) { throw "-IncidentEnd must be later than -IncidentStart." }
        Write-Information "Incident window (UTC): $(Format-UtcDate $incidentStartUtc) to $(Format-UtcDate $incidentEndUtc)" -InformationAction Continue
    }
    elseif ($PSBoundParameters.ContainsKey('IncidentEnd')) {
        throw "-IncidentEnd needs -IncidentStart."
    }

    # ----- 1. Current state of private channels -----
    if ($TeamId) {
        $teams = foreach ($id in $TeamId) {
            Invoke-MgGraphRequest -Method GET -Uri "$GraphBase/teams/$($id)?`$select=id,displayName" -ErrorAction Stop
        }
    }
    else {
        Write-Information "Listing all teams..." -InformationAction Continue
        $teams = @(Get-MgGraphAllPage -Uri "$GraphBase/teams?`$select=id,displayName")
    }
    $teams = @($teams)
    Write-Information "Checking $($teams.Count) team(s) for private channels..." -InformationAction Continue

    $channels = [System.Collections.Generic.List[object]]::new()
    $failedTeams = [System.Collections.Generic.List[object]]::new()
    $teamUsersById = @{}      # teamId -> @{ upn(lower) = @{ Id; Enabled } }

    foreach ($team in $teams) {
        try {
            $private = @(Get-MgGraphAllPage -Uri "$GraphBase/teams/$($team.id)/channels?`$filter=membershipType eq 'private'&`$select=id,displayName,membershipType,createdDateTime")
            if ($private.Count -eq 0) { continue }

            $idToUpn = @{}
            $teamUsers = @{}
            foreach ($u in @(Get-MgGraphAllPage -Uri "$GraphBase/groups/$($team.id)/members/microsoft.graph.user?`$select=id,userPrincipalName,accountEnabled&`$top=999")) {
                if (-not $u.userPrincipalName) { continue }
                $idToUpn[$u.id] = $u.userPrincipalName
                $teamUsers[$u.userPrincipalName.ToLowerInvariant()] = @{ Id = $u.id; Enabled = $u.accountEnabled }
            }
            $teamUsersById[$team.id] = $teamUsers

            foreach ($channel in $private) {
                $members = @()
                $readError = $null
                try {
                    $members = @(Get-MgGraphAllPage -Uri "$GraphBase/teams/$($team.id)/channels/$($channel.id)/members")
                }
                catch {
                    # Keep the channel in scope: an unreadable roster is not evidence that the channel is healthy
                    $readError = $_.Exception.Message
                    Write-Warning "Could not read members of '$($team.displayName) / $($channel.displayName)': $readError"
                }

                $current = @{}      # upn(lower) -> @{ Upn; DisplayName; Role }
                foreach ($m in $members) {
                    $upn = if ($m.userId -and $idToUpn.ContainsKey($m.userId)) { $idToUpn[$m.userId] } elseif ($m.email) { $m.email } else { $null }
                    if (-not $upn) { continue }
                    $role = if ($m.roles -contains 'owner') { 'Owner' } elseif ($m.roles -contains 'guest') { 'Guest' } else { 'Member' }
                    $current[$upn.ToLowerInvariant()] = @{ Upn = $upn; DisplayName = $m.displayName; Role = $role }
                }

                $created = ConvertTo-UtcDate $channel.createdDateTime
                $channels.Add([pscustomobject]@{
                        TeamName          = $team.displayName
                        TeamId            = $team.id
                        ChannelName       = $channel.displayName
                        ChannelId         = $channel.id
                        CreatedUtc        = Format-UtcDate $created
                        Status            = $null
                        OwnerCount        = if ($readError) { $null } else { @($members | Where-Object { $_.roles -contains 'owner' }).Count }
                        MemberCount       = if ($readError) { $null } else { $members.Count }
                        ReAddedCount      = 0
                        NewSinceIncident  = 0
                        PendingYes        = 0
                        PendingReview     = 0
                        AuditEvidenceRows = 0
                        ReadError         = $readError
                        CreatedDate       = $created
                        Current           = $current
                    })
            }
        }
        catch {
            Write-Warning "Could not read team '$($team.displayName)' ($($team.id)): $($_.Exception.Message)"
            $failedTeams.Add([pscustomobject]@{ TeamName = $team.displayName; TeamId = $team.id; Error = $_.Exception.Message })
        }
    }

    Write-Information "Private channels found: $($channels.Count)" -InformationAction Continue
    if ($channels.Count -eq 0) {
        Write-Warning "No private channels in scope; nothing to analyse."
        return
    }

    $byChannelId = @{}
    $byTeamAndName = @{}
    foreach ($c in $channels) {
        $byChannelId[$c.ChannelId] = $c
        $byTeamAndName["$($c.TeamId)|$($c.ChannelName)".ToLowerInvariant()] = $c
    }

    # ----- 2. Audit records -----
    if ($AuditRecordsPath) {
        Write-Information "Loading audit records from $AuditRecordsPath" -InformationAction Continue
        if (-not (Test-Path -LiteralPath $AuditRecordsPath -PathType Leaf)) { throw "Audit records file '$AuditRecordsPath' was not found." }
        $records = @(Get-Content -LiteralPath $AuditRecordsPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 30 -ErrorAction Stop | Where-Object { $null -ne $_ })
    }
    else {
        $endUtc = (Get-Date).ToUniversalTime()
        $fetched = @(Get-TeamsAuditRecord -Start $endUtc.AddDays(-$DaysBack) -End $endUtc -TimeoutMinutes $AuditTimeoutMinutes -WindowDays $AuditWindowDays -QueryId $AuditQueryId)
        $rawPath = Join-Path $OutputPath "audit-records-$stamp.json"
        ConvertTo-Json -InputObject $fetched -Depth 30 | Set-Content -Path $rawPath -Encoding utf8 -ErrorAction Stop
        # Reload what was saved so a live run and a -AuditRecordsPath run analyse identically shaped records
        $records = @(Get-Content -LiteralPath $rawPath -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 30 | Where-Object { $null -ne $_ })
        Write-Information "Saved $($records.Count) raw audit record(s) to $rawPath (reuse with -AuditRecordsPath)" -InformationAction Continue
    }
    if ($records.Count -eq 0) { Write-Warning "The audit data contains no records." }

    # ----- 3. Keep only events for private channels in scope -----
    $membershipEvents = [System.Collections.Generic.List[object]]::new()
    $skippedOtherChannel = 0
    $teamRemovals = @{}   # "teamId|upn(lower)" -> times of team-level MemberRemoved records
    foreach ($rec in $records) {
        $data = Get-AuditPayload $rec
        if ($null -eq $data) { continue }

        $channel = $null
        $matchedByName = $false
        $guid = "$($data.ChannelGuid)".Trim()
        if ($guid -and $byChannelId.ContainsKey($guid)) {
            $channel = $byChannelId[$guid]
        }
        elseif ($guid -like '19:*') {
            # Names a channel thread that is not a private channel in scope (deleted, shared, standard,
            # or another team). Never re-home it by display name.
            continue
        }
        elseif ($data.AADGroupId -and $data.ChannelName) {
            $channel = $byTeamAndName["$($data.AADGroupId)|$($data.ChannelName)".ToLowerInvariant()]
            $matchedByName = $true
        }
        if ($null -eq $channel -and -not $guid -and -not $data.ChannelName -and "$($rec.operation)" -eq 'MemberRemoved' -and
            $data.AADGroupId -and $teamUsersById.ContainsKey("$($data.AADGroupId)")) {
            # Team-level removal: Teams also removes the user from every private channel in that team
            $t = ConvertTo-UtcDate $rec.createdDateTime
            if ($t) {
                foreach ($m in @($data.Members)) {
                    if ($null -eq $m -or -not $m.UPN) { continue }
                    $k = "$($data.AADGroupId)|$("$($m.UPN)".ToLowerInvariant())"
                    if (-not $teamRemovals.ContainsKey($k)) { $teamRemovals[$k] = [System.Collections.Generic.List[datetime]]::new() }
                    $teamRemovals[$k].Add($t)
                }
            }
        }
        if ($null -eq $channel) { continue }

        $when = ConvertTo-UtcDate $rec.createdDateTime
        # A name-only match cannot predate the live channel that now holds the name
        if ($matchedByName -and $when -and $channel.CreatedDate -and $when -lt $channel.CreatedDate.AddMinutes(-10)) {
            $skippedOtherChannel++
            continue
        }

        $actor = if ($rec.userPrincipalName) { $rec.userPrincipalName } else { $data.UserId }
        $phase = if ($null -eq $incidentStartUtc -or $null -eq $when) { $null }
        elseif ($when -lt $incidentStartUtc) { 'PreIncident' }
        elseif ($when -le $incidentEndUtc) { 'Incident' }
        else { 'PostIncident' }

        if ($rec.operation -eq 'ChannelAdded') {
            # The creator of a private channel is its first owner
            if ($actor) {
                $membershipEvents.Add([pscustomobject]@{ Seq = $membershipEvents.Count; Channel = $channel; TimeUtc = $when; Phase = $phase; Operation = 'ChannelAdded'; Actor = $actor; Upn = $actor; DisplayName = $null; RawRole = $null })
            }
            continue
        }
        foreach ($m in @($data.Members)) {
            if ($null -eq $m -or -not $m.UPN) { continue }
            $membershipEvents.Add([pscustomobject]@{ Seq = $membershipEvents.Count; Channel = $channel; TimeUtc = $when; Phase = $phase; Operation = "$($rec.operation)"; Actor = $actor; Upn = $m.UPN; DisplayName = $m.DisplayName; RawRole = $m.Role })
        }
    }
    if ($skippedOtherChannel -gt 0) {
        Write-Information "Ignored $skippedOtherChannel audit record(s) from an older channel that had the same name as a current one." -InformationAction Continue
    }
    if ($records.Count -gt 0 -and $membershipEvents.Count -eq 0) {
        Write-Warning "$($records.Count) audit record(s) were returned but none matched a private channel in scope. If you expected matches, inspect one record's auditData in the saved JSON before trusting an empty plan."
    }

    # ----- Role numbering -----
    # Microsoft documents both 0/1/2 (Management Activity API) and 1/2/3 (Purview). Live roles are the only proof.
    $zeroMap = @{ 0 = 'Member'; 1 = 'Owner'; 2 = 'Guest' }
    $oneMap = @{ 1 = 'Member'; 2 = 'Owner'; 3 = 'Guest' }
    $roleCounts = @{}
    foreach ($rec in $records) {
        $data = Get-AuditPayload $rec
        if ($null -eq $data) { continue }
        foreach ($m in @($data.Members)) {
            if ($null -eq $m -or "$($m.Role)" -notmatch '^\d+$') { continue }
            $r = [int]"$($m.Role)"
            $roleCounts[$r] = 1 + [int]$roleCounts[$r]
        }
    }
    # Audit timestamps have one-second resolution: on a tie an add goes before a role change before a removal
    $opOrder = @{ ChannelAdded = 0; MemberAdded = 1; MemberRoleChanged = 2; MemberRemoved = 3 }
    $lastEvent = @{}
    # Same order as the replay, all operations: only a person whose last audited event leaves them present with a stated role is evidence
    foreach ($e in @($membershipEvents | Sort-Object -Property TimeUtc, @{ Expression = { $opOrder["$($_.Operation)"] } }, Seq)) {
        $lastEvent["$($e.Channel.ChannelId)|$("$($e.Upn)".ToLowerInvariant())"] = $e
    }
    $agreeZero = 0
    $agreeOne = 0
    foreach ($e in $lastEvent.Values) {
        # Last event a removal, or no numeric role: the live role came from a change the audit data does not hold
        if ($e.Operation -notin @('MemberAdded', 'MemberRoleChanged') -or "$($e.RawRole)" -notmatch '^\d+$') { continue }
        $live = $e.Channel.Current["$($e.Upn)".ToLowerInvariant()]
        if ($null -eq $live) { continue }
        $raw = [int]"$($e.RawRole)"
        if ($zeroMap[$raw] -eq $live.Role) { $agreeZero++ }
        if ($oneMap[$raw] -eq $live.Role) { $agreeOne++ }
    }
    $hasZero = $roleCounts.ContainsKey(0)
    $hasThree = $roleCounts.ContainsKey(3)
    $roleUncertain = $false
    if ($RoleNumbering -ne 'Auto') {
        $zeroBased = $RoleNumbering -eq 'ZeroBased'
        $basis = "-RoleNumbering $RoleNumbering"
    }
    elseif ($agreeZero -ne $agreeOne) {
        $zeroBased = $agreeZero -gt $agreeOne
        $basis = "agreement with current channel roles (0/1/2: $agreeZero, 1/2/3: $agreeOne)"
        # Live roles can come from re-adds or promotions the audit data lacks, so conflicting, thin or implausible votes are not proof
        $roleUncertain = ($zeroBased -and $hasThree) -or (-not $zeroBased -and $hasZero) -or
            (10 * [math]::Min($agreeZero, $agreeOne) -gt [math]::Max($agreeZero, $agreeOne)) -or
            ([math]::Max($agreeZero, $agreeOne) -lt 3) -or
            ($zeroBased -and [int]$roleCounts[0] -lt [int]$roleCounts[1])
    }
    elseif ($hasZero -xor $hasThree) {
        $zeroBased = $hasZero
        $basis = "Role value $(if ($hasZero) { '0' } else { '3' }) is present"
        # Plain members are normally the commonest role, so a rare 0 is weak evidence
        if ($zeroBased -and [int]$roleCounts[0] -lt [int]$roleCounts[1]) { $roleUncertain = $true }
    }
    else {
        $zeroBased = $false
        $basis = 'default; nothing in the data decides it'
        $roleUncertain = $true
    }
    $roleNames = if ($zeroBased) { $zeroMap } else { $oneMap }
    $roleRank = @{ Guest = 0; Member = 1; Owner = 2 }
    $numberingText = if ($zeroBased) { '0=Member,1=Owner,2=Guest' } else { '1=Member,2=Owner,3=Guest' }
    $seenRoles = (@($roleCounts.Keys | Sort-Object) | ForEach-Object { "$_ (x$($roleCounts[$_]))" }) -join ', '
    Write-Information "Audit role numbering used: $numberingText [$basis]" -InformationAction Continue
    if ($roleUncertain -and $membershipEvents.Count -gt 0) {
        Write-Warning "Audit role numbering is NOT certain (Role values seen: $seenRoles). Every proposed owner is marked Review. Check RawRole in the events CSV against people whose role you know, then re-run with -RoleNumbering ZeroBased or OneBased."
    }

    $eventsByChannel = @{}
    foreach ($e in $membershipEvents) {
        $id = $e.Channel.ChannelId
        if (-not $eventsByChannel.ContainsKey($id)) { $eventsByChannel[$id] = [System.Collections.Generic.List[object]]::new() }
        $eventsByChannel[$id].Add($e)
    }

    # Accounts with logged removals inside the window; used when a person's own incident removal was not audited
    $incidentRemovers = @{}
    foreach ($ev in $membershipEvents) {
        if ($ev.Operation -eq 'MemberRemoved' -and $ev.Phase -eq 'Incident' -and $ev.Actor) { $incidentRemovers["$($ev.Actor)"] = $true }
    }

    # ----- 4. Replay events per channel and compare with who is there now -----
    $plan = [System.Collections.Generic.List[object]]::new()
    $currentReport = [System.Collections.Generic.List[object]]::new()

    foreach ($channel in $channels) {
        $roster = @{}
        $channelEvents = if ($eventsByChannel.ContainsKey($channel.ChannelId)) {
            @($eventsByChannel[$channel.ChannelId] | Sort-Object -Property TimeUtc, @{ Expression = { $opOrder["$($_.Operation)"] } }, Seq)
        }
        else { @() }

        # An add and a remove for the same person in the same second cannot be ordered reliably
        $tied = @{}
        foreach ($g in @($channelEvents | Where-Object { $_.TimeUtc } | Group-Object { "$($_.Upn)".ToLowerInvariant() + '|' + $_.TimeUtc.Ticks })) {
            $ops = @($g.Group | ForEach-Object { $_.Operation })
            if ($ops -contains 'MemberAdded' -and $ops -contains 'MemberRemoved') { $tied[($g.Name -split '\|')[0]] = $true }
        }

        foreach ($e in $channelEvents) {
            $key = "$($e.Upn)".ToLowerInvariant()
            if (-not $roster.ContainsKey($key)) {
                $roster[$key] = @{
                    Upn = $e.Upn; DisplayName = $e.DisplayName; Role = 'Member'; Present = $false; FirstSeen = $e.TimeUtc
                    IncidentRemoved = $false; ImplicitRemoval = $false; RoleAtIncident = $null; IncidentTime = $null; IncidentActor = $null
                    ReAdded = $false; ReAddedTime = $null; ReAddedBy = $null; RoleChangedAfterReAdd = $null
                    RemovedAfterReAdd = $false; RemovedAfterReAddInWindow = $false; ReRemovedByIncidentActor = $false
                    LateRemoved = $false; RemovedBy = $null; LastOp = $null; LastTime = $null
                    RoleAtStart = $null; StartSeen = $false; RoleConflict = $null; InWindowRoleChange = $null
                }
            }
            $entry = $roster[$key]
            if ($e.DisplayName) { $entry.DisplayName = $e.DisplayName }
            $role = if ("$($e.RawRole)" -match '^\d+$' -and $roleNames.ContainsKey([int]"$($e.RawRole)")) { $roleNames[[int]"$($e.RawRole)"] } else { $null }
            if (-not $entry.StartSeen -and $e.Phase -in @('Incident', 'PostIncident')) {
                # Role as it stood when the incident window opened, before any in-window churn
                $entry.StartSeen = $true
                if ($entry.Present -and $entry.LastOp) { $entry.RoleAtStart = $entry.Role }
            }

            switch ($e.Operation) {
                'ChannelAdded' {
                    $entry.Present = $true
                    $entry.Role = 'Owner'
                }
                'MemberAdded' {
                    if ($entry.IncidentRemoved -and -not $entry.Present) {
                        # Someone put this person back after the incident took them out
                        $entry.ReAdded = $true
                        $entry.ReAddedTime = $e.TimeUtc
                        $entry.ReAddedBy = $e.Actor
                        # Put back without the owner role after a deliberate, or possibly deliberate (different account
                        # inside the window), later removal: not an incident gap, so the owner role needs review
                        $entry.RoleChangedAfterReAdd = if (($entry.RemovedAfterReAdd -or $entry.RemovedAfterReAddInWindow) -and $role -ne 'Owner') { 'Member' } else { $null }
                        $entry.RemovedAfterReAdd = $false
                        $entry.RemovedAfterReAddInWindow = $false
                        $entry.ReRemovedByIncidentActor = $false
                    }
                    elseif ($entry.Present -and -not $entry.IncidentRemoved -and $e.Phase -in @('Incident', 'PostIncident') -and
                        $entry.LastTime -and $entry.LastTime -lt $incidentStartUtc) {
                        # In the channel before the incident and added again since with no removal logged:
                        # the incident removal was not audited, and this add is the re-add
                        $entry.IncidentRemoved = $true
                        $entry.ImplicitRemoval = $true
                        $entry.RoleAtIncident = $entry.Role
                        $entry.ReAdded = $true
                        $entry.ReAddedTime = $e.TimeUtc
                        $entry.ReAddedBy = $e.Actor
                        $entry.RoleChangedAfterReAdd = $null
                    }
                    if ($role) { $entry.Role = $role } elseif (-not $entry.Present) { $entry.Role = 'Member' }
                    $entry.Present = $true
                }
                'MemberRoleChanged' {
                    # A role change inside the window before the incident removal may be Teams promoting a member
                    if ($e.Phase -eq 'Incident' -and -not $entry.IncidentRemoved -and $role) { $entry.InWindowRoleChange = $role }
                    if ($role) { $entry.Role = $role }
                    if ($role -and ($entry.ReAdded -or ($entry.IncidentRemoved -and $e.Phase -eq 'PostIncident'))) { $entry.RoleChangedAfterReAdd = $role }
                    $entry.Present = $true
                }
                'MemberRemoved' {
                    if ($e.Phase -eq 'Incident') {
                        if ($entry.IncidentRemoved -and $entry.ReAdded -and $e.Actor -ne $entry.IncidentActor) {
                            # Re-added, then removed inside the window by a different account: may be deliberate
                            $entry.RemovedAfterReAddInWindow = $true
                        }
                        else {
                            # Trust the replayed role only while the person is present; otherwise the record knows better
                            $roleBefore = if ($role -eq 'Owner') { 'Owner' }
                            elseif ($entry.Present -and $entry.LastOp) { $entry.Role }
                            elseif ($role) { $role }
                            elseif ($entry.LastOp) { $entry.Role }
                            else { 'Member' }
                            if (-not $entry.IncidentRemoved) {
                                $entry.RoleAtIncident = $roleBefore
                                $entry.IncidentTime = $e.TimeUtc
                                $entry.IncidentActor = $e.Actor
                                if ($entry.RoleAtStart -and $entry.RoleAtStart -ne $roleBefore) {
                                    # Role changed inside the window before the removal (Teams promotes a member when an owner
                                    # leaves the group, or an admin changed it mid-incident); the log cannot say which
                                    $entry.RoleConflict = "Role was $($entry.RoleAtStart) when the incident window opened but $roleBefore when removed."
                                    if ($roleRank[$entry.RoleAtStart] -gt $roleRank[$roleBefore]) { $entry.RoleAtIncident = $entry.RoleAtStart }
                                }
                                elseif (-not $entry.RoleAtStart -and $entry.InWindowRoleChange) {
                                    # No history before the window, but the role changed inside it before the removal
                                    $entry.RoleConflict = "Role was changed to $($entry.InWindowRoleChange) inside the incident window before the removal, and the role before the window is not in the audit data."
                                }
                            }
                            elseif ($roleRank[$roleBefore] -gt $roleRank[$entry.RoleAtIncident]) {
                                $entry.RoleAtIncident = $roleBefore
                            }
                            $entry.IncidentRemoved = $true
                            # A re-add undone inside the window by the incident account was part of the churn
                            $entry.ReAdded = $false
                            $entry.RoleChangedAfterReAdd = $null
                        }
                    }
                    elseif ($e.Phase -eq 'PostIncident') {
                        if ($entry.IncidentRemoved -and $entry.ReAdded) {
                            # When this person's own incident removal was not logged, any account that removed people inside the window counts
                            $byIncidentActor = [bool]$e.Actor -and (
                                ($entry.IncidentActor -and $e.Actor -eq $entry.IncidentActor) -or
                                (-not $entry.IncidentActor -and $incidentRemovers.ContainsKey("$($e.Actor)")))
                            if ($byIncidentActor) { $entry.ReRemovedByIncidentActor = $true }
                            else { $entry.RemovedAfterReAdd = $true }
                        }
                        else {
                            $entry.LateRemoved = $true
                        }
                        if ($role -eq 'Owner') { $entry.Role = 'Owner' }
                    }
                    elseif ($role -eq 'Owner') {
                        $entry.Role = 'Owner'
                    }
                    $entry.Present = $false
                    $entry.RemovedBy = $e.Actor
                }
            }
            $entry.LastOp = $e.Operation
            $entry.LastTime = $e.TimeUtc
        }

        $teamUsers = $teamUsersById[$channel.TeamId]

        foreach ($key in $roster.Keys) {
            $entry = $roster[$key]
            $now = $channel.Current[$key]
            $notes = [System.Collections.Generic.List[string]]::new()

            if ($null -ne $now) {
                # Already back in the channel: the only thing that can still be outstanding is a lost owner role
                if (-not ($entry.IncidentRemoved -and $entry.RoleAtIncident -eq 'Owner' -and $now.Role -ne 'Owner')) { continue }
                $action = 'Promote'
                $proposedRole = 'Owner'
                if ($entry.RoleChangedAfterReAdd -and $entry.RoleChangedAfterReAdd -ne 'Owner') {
                    $evidence = 'DemotedAfterReAdd'; $restore = 'Review'
                    $notes.Add('Owner role was changed, or not given back, after a post-incident re-add; confirm it is still wanted.')
                }
                elseif (-not $entry.Present -and ($entry.RemovedAfterReAdd -or $entry.RemovedAfterReAddInWindow)) {
                    # Last audited event is a removal after a re-add, yet the user is in the channel now:
                    # the later re-add is newer than the audit data (stale export) or was not audited
                    $evidence = 'DemotedAfterReAdd'; $restore = 'Review'
                    $notes.Add("Last audited event is a removal by $($entry.RemovedBy) after a re-add; the later re-add without the owner role is not in the audit data. Confirm the owner role is still wanted.")
                }
                elseif ($entry.ImplicitRemoval) {
                    $evidence = 'ReAddedWithoutOwnerRole'; $restore = 'Review'
                    $notes.Add('No removal was logged; inferred from a second add after the incident started. Confirm the owner role is still wanted.')
                }
                else {
                    $evidence = 'ReAddedWithoutOwnerRole'; $restore = 'Yes'
                }
            }
            else {
                $action = 'Add'
                $proposedRole = if ($entry.IncidentRemoved) { $entry.RoleAtIncident } else { $entry.Role }

                # Removed from the parent team after the last channel event and outside the incident window:
                # that also drops private channel membership, so the absence may be deliberate
                $teamGap = @(@($teamRemovals["$($channel.TeamId)|$key"]) | Where-Object {
                        $_ -and (-not $entry.LastTime -or $_ -gt $entry.LastTime) -and
                        ($null -eq $incidentStartUtc -or $_ -lt $incidentStartUtc -or $_ -gt $incidentEndUtc)
                    } | Sort-Object)
                $where = if ($null -eq $incidentStartUtc) { 'and no -IncidentStart was given to tell incident removals from deliberate ones' } else { 'and outside the incident window' }
                $teamGapNote = if ($teamGap.Count -gt 0) { "Removed from the parent team at $(Format-UtcDate $teamGap[0]), after their last channel event $where. That also removes private channel membership, so the absence may be deliberate." } else { $null }

                if ($null -eq $incidentStartUtc) {
                    if ($entry.Present -and $teamGap.Count -gt 0) { $evidence = 'RemovedFromTeam'; $restore = 'Review'; $notes.Add($teamGapNote) }
                    elseif ($entry.Present) { $evidence = 'AddedNeverRemoved'; $restore = 'Yes' }
                    else {
                        $evidence = 'Removed'; $restore = 'Review'
                        $notes.Add('Re-run with -IncidentStart to separate incident removals from deliberate ones.')
                    }
                }
                elseif ($entry.Present) {
                    if ($entry.IncidentRemoved -and $entry.ReAdded) {
                        $evidence = 'ReAddedThenMissing'; $restore = 'Review'
                        $notes.Add('Audit shows a re-add but the user is not in the channel now and no later removal was logged.')
                    }
                    elseif ($entry.LastTime -and $entry.LastTime -gt $incidentEndUtc) {
                        # Last seen in the channel after the window closed, so the incident cannot be what removed them
                        $evidence = 'PresentAfterIncidentThenMissing'; $restore = 'Review'
                        $notes.Add('Audit shows the user in the channel after the incident window, but they are not there now and no later removal was logged.')
                    }
                    elseif ($teamGap.Count -gt 0) {
                        $evidence = 'RemovedFromTeamOutsideWindow'; $restore = 'Review'
                        $notes.Add($teamGapNote)
                    }
                    else {
                        # Logged as added before the window closed and never removed, yet absent now: the removal was not audited per channel
                        $evidence = 'AddedNeverRemoved'; $restore = 'Yes'
                    }
                }
                elseif ($entry.ReRemovedByIncidentActor) {
                    $evidence = 'RemovedAgainByIncidentActor'; $restore = 'Review'
                    $who = if ($entry.IncidentActor) { 'the account behind the incident removal' } else { 'an account that removed other people inside the incident window (this person''s own incident removal was not logged with an account, so it is not shown to be the cause)' }
                    $notes.Add("Re-added by $($entry.ReAddedBy) and removed again by $($entry.RemovedBy), $who. The cause may still be active; fix it, then decide.")
                }
                elseif ($entry.RemovedAfterReAddInWindow) {
                    $evidence = 'RemovedAgainInsideWindow'; $restore = 'Review'
                    $notes.Add("Re-added by $($entry.ReAddedBy) and removed again by $($entry.RemovedBy) inside the incident window; confirm whether that removal was deliberate.")
                }
                elseif ($entry.RemovedAfterReAdd) {
                    $evidence = 'RemovedAgainAfterReAdd'; $restore = 'No'
                    $notes.Add("Re-added by $($entry.ReAddedBy) and then removed by $($entry.RemovedBy); treated as deliberate.")
                }
                elseif ($entry.LateRemoved) {
                    $evidence = 'RemovedAfterIncidentWindow'; $restore = 'Review'
                    $notes.Add('Removed after the incident window; either a deliberate change or the window is too short.')
                }
                elseif ($entry.IncidentRemoved) {
                    $evidence = 'RemovedDuringIncident'; $restore = 'Yes'
                }
                else {
                    $evidence = 'RemovedBeforeIncident'; $restore = 'No'
                }
            }

            if ($tied.ContainsKey($key)) {
                # Always say so: when the row is already Review, the note above assumed an add-before-remove order
                $restore = 'Review'
                $notes.Add('An add and a removal for this user share a timestamp, so their order could not be determined; the evidence and note above may have them the wrong way round.')
            }
            if ($entry.RoleConflict -and $proposedRole -eq 'Owner' -and $restore -ne 'No') {
                $restore = 'Review'
                $notes.Add("$($entry.RoleConflict) Teams promotes a channel member to owner when an owner is removed from the team's group, so confirm the owner role before restoring.")
            }
            if ($channel.ReadError) {
                # Live roster unknown: "absent now" is an assumption, so nothing may be applied automatically
                if ($restore -eq 'Yes') { $restore = 'Review' }
                $notes.Insert(0, 'Channel roster could not be read, so current membership is unknown and this row may already be satisfied. Re-run discovery before restoring.')
            }

            $inTeam = [bool]($teamUsers -and $teamUsers.ContainsKey($key))
            $account = if ($restore -eq 'No') {
                @{ Status = 'NotChecked'; Id = $(if ($inTeam) { $teamUsers[$key].Id } else { $null }) }
            }
            else { Get-AccountInfo -Upn $entry.Upn -TeamUsers $teamUsers }

            # Only rows the restore script can apply as they stand keep Restore = Yes
            if ($restore -eq 'Yes') {
                if ($account.Status -in @('NotFound', 'Disabled')) {
                    $restore = 'Review'
                    $notes.Add("Account is $($account.Status) (left, disabled or renamed since).")
                }
                elseif (-not $inTeam) {
                    $restore = 'Review'
                    $notes.Add('No longer in the parent team. Add them to the team first if they should still have access.')
                }
                elseif ($proposedRole -eq 'Owner' -and $roleUncertain) {
                    $restore = 'Review'
                    $notes.Add('Owner role rests on an audit Role numbering that could not be confirmed; check RawRole in the events CSV.')
                }
            }

            $channel.AuditEvidenceRows++
            if ($restore -eq 'Yes') { $channel.PendingYes++ } elseif ($restore -eq 'Review') { $channel.PendingReview++ }

            $plan.Add([pscustomobject]@{
                    TeamName           = $channel.TeamName
                    TeamId             = $channel.TeamId
                    ChannelName        = $channel.ChannelName
                    ChannelId          = $channel.ChannelId
                    UserPrincipalName  = $entry.Upn
                    UserId             = $account.Id
                    DisplayName        = $entry.DisplayName
                    Action             = $action
                    ProposedRole       = $proposedRole
                    CurrentRole        = if ($null -ne $now) { $now.Role } else { $null }
                    Evidence           = $evidence
                    IncidentRemovalUtc = Format-UtcDate $entry.IncidentTime
                    RemovedBy          = $entry.RemovedBy
                    ReAddedUtc         = Format-UtcDate $entry.ReAddedTime
                    ReAddedBy          = $entry.ReAddedBy
                    LastEvent          = $entry.LastOp
                    LastEventUtc       = Format-UtcDate $entry.LastTime
                    InParentTeam       = $inTeam
                    AccountStatus      = $account.Status
                    Restore            = $restore
                    Note               = ($notes -join ' ')
                })
        }

        # Who is in the channel today, and how they relate to the incident
        foreach ($key in $channel.Current.Keys) {
            $now = $channel.Current[$key]
            $entry = $roster[$key]
            $since = if ($null -eq $entry) { 'NoAuditHistory' }
            elseif ($null -eq $incidentStartUtc) { 'NotClassified' }
            elseif ($entry.IncidentRemoved -and $entry.ReAdded) { 'ReAddedAfterIncident' }
            elseif ($entry.IncidentRemoved) { 'PresentDespiteIncidentRemoval' }
            elseif ($entry.FirstSeen -and $entry.FirstSeen -ge $incidentStartUtc) { 'NewSinceIncident' }
            else { 'Unaffected' }

            if ($since -in @('ReAddedAfterIncident', 'PresentDespiteIncidentRemoval')) { $channel.ReAddedCount++ }
            elseif ($since -eq 'NewSinceIncident') { $channel.NewSinceIncident++ }

            $currentReport.Add([pscustomobject]@{
                    TeamName          = $channel.TeamName
                    ChannelName       = $channel.ChannelName
                    UserPrincipalName = $now.Upn
                    DisplayName       = $now.DisplayName
                    CurrentRole       = $now.Role
                    Since             = $since
                    RoleAtIncident    = if ($entry) { $entry.RoleAtIncident } else { $null }
                    ReAddedUtc        = if ($entry) { Format-UtcDate $entry.ReAddedTime } else { $null }
                    ReAddedBy         = if ($entry) { $entry.ReAddedBy } else { $null }
                })
        }

        $channel.Status = if ($channel.ReadError) { 'Unreadable' }
        elseif ($channel.MemberCount -eq 0) { 'Empty' }
        elseif ($channel.OwnerCount -eq 0) { 'Ownerless' }
        elseif ($channel.PendingYes -gt 0) { if ($channel.ReAddedCount -gt 0) { 'PartiallyRestored' } else { 'PendingRestore' } }
        elseif ($channel.PendingReview -gt 0) { 'ReviewOnly' }
        else { 'NoActionNeeded' }
    }

    # ----- 5. Output -----
    $statePath = Join-Path $OutputPath "private-channel-state-$stamp.csv"
    $currentPath = Join-Path $OutputPath "private-channel-current-members-$stamp.csv"
    $eventsPath = Join-Path $OutputPath "private-channel-events-$stamp.csv"
    $planPath = Join-Path $OutputPath "restore-plan-$stamp.csv"

    $channels | Select-Object * -ExcludeProperty Current, CreatedDate | Sort-Object TeamName, ChannelName | Export-Csv -Path $statePath -NoTypeInformation
    $currentReport | Sort-Object TeamName, ChannelName, UserPrincipalName | Export-Csv -Path $currentPath -NoTypeInformation
    $membershipEvents | Sort-Object -Property TimeUtc, Seq | Select-Object @{ n = 'TeamName'; e = { $_.Channel.TeamName } }, @{ n = 'ChannelName'; e = { $_.Channel.ChannelName } },
        @{ n = 'TimeUtc'; e = { Format-UtcDate $_.TimeUtc } }, Phase, Operation, Actor, Upn, DisplayName, RawRole |
        Export-Csv -Path $eventsPath -NoTypeInformation
    $plan | Sort-Object TeamName, ChannelName, Action, ProposedRole, UserPrincipalName | Export-Csv -Path $planPath -NoTypeInformation

    $removals = @($membershipEvents | Where-Object { $_.Operation -eq 'MemberRemoved' -and $_.TimeUtc })

    Write-Information "`n===== SUMMARY =====" -InformationAction Continue
    Write-Information "Channel status:" -InformationAction Continue
    $channels | Group-Object Status | Sort-Object Name | ForEach-Object { Write-Information ("  {0,-18} {1}" -f $_.Name, $_.Count) -InformationAction Continue }
    Write-Information "Restore plan rows:" -InformationAction Continue
    $plan | Group-Object Restore, Action | Sort-Object Name | ForEach-Object { Write-Information ("  {0,-18} {1}" -f $_.Name, $_.Count) -InformationAction Continue }
    Write-Information "Already re-added since the incident: $(@($currentReport | Where-Object { $_.Since -in @('ReAddedAfterIncident', 'PresentDespiteIncidentRemoval') }).Count)" -InformationAction Continue
    Write-Information "New members since the incident:      $(@($currentReport | Where-Object Since -eq 'NewSinceIncident').Count)" -InformationAction Continue

    $needOwner = @($channels | Where-Object { $_.Status -in @('Empty', 'Ownerless', 'Unreadable') } | Where-Object {
            $c = $_
            -not ($plan | Where-Object { $_.ChannelId -eq $c.ChannelId -and $_.ProposedRole -eq 'Owner' -and $_.Restore -ne 'No' })
        })
    if ($needOwner.Count -gt 0) {
        Write-Warning "$($needOwner.Count) ownerless channel(s) have no owner identified in the plan. Pick an owner by hand: $(($needOwner | ForEach-Object { "$($_.TeamName) / $($_.ChannelName)" }) -join '; ')"
    }

    if ($removals.Count -gt 0) {
        # Who removed people, and when, is the root-cause evidence
        Write-Information "`nRemovals by day and actor (top 10):" -InformationAction Continue
        $removals | Group-Object { $_.TimeUtc.ToString('yyyy-MM-dd', $Inv) }, Actor | Sort-Object Count -Descending | Select-Object -First 10 |
            ForEach-Object { Write-Information ("  {0,6}  {1}" -f $_.Count, $_.Name) -InformationAction Continue }

        if ($null -eq $incidentStartUtc) {
            $peak = $removals | Group-Object { $_.TimeUtc.ToString('yyyy-MM-ddTHH:00:00Z', $Inv) } | Sort-Object Count -Descending | Select-Object -First 1
            $peakStart = ConvertTo-UtcDate $peak.Name
            $peakEnd = $peakStart.AddHours(1)
            $sorted = @($removals | Sort-Object -Property TimeUtc, Seq)
            $lo = -1
            $hi = -1
            for ($i = 0; $i -lt $sorted.Count; $i++) {
                if ($sorted[$i].TimeUtc -ge $peakStart -and $sorted[$i].TimeUtc -lt $peakEnd) {
                    if ($lo -lt 0) { $lo = $i }
                    $hi = $i
                }
            }
            # The busiest hour is only the core of the burst: widen it to every removal less than 15 minutes from the next,
            # because a start inside the burst turns its earlier victims into RemovedBeforeIncident (Restore No)
            # Capped at 6 hours either side so steady everyday removals are not swept into the suggestion
            $gap = [timespan]::FromMinutes(15)
            $maxSpan = [timespan]::FromHours(6)
            while ($lo -gt 0 -and ($sorted[$lo].TimeUtc - $sorted[$lo - 1].TimeUtc) -le $gap -and ($peakStart - $sorted[$lo - 1].TimeUtc) -le $maxSpan) { $lo-- }
            while ($hi -lt $sorted.Count - 1 -and ($sorted[$hi + 1].TimeUtc - $sorted[$hi].TimeUtc) -le $gap -and ($sorted[$hi + 1].TimeUtc - $peakEnd) -le $maxSpan) { $hi++ }
            $capped = ($lo -gt 0 -and ($sorted[$lo].TimeUtc - $sorted[$lo - 1].TimeUtc) -le $gap) -or
                ($hi -lt $sorted.Count - 1 -and ($sorted[$hi + 1].TimeUtc - $sorted[$hi].TimeUtc) -le $gap)
            if ($capped) {
                Write-Warning "Removals continue more than 6 hours either side of the busiest hour without a 15-minute break, so the suggested window was cut there. Pick the window from the events CSV."
            }
            $sugStart = Format-UtcDate $sorted[$lo].TimeUtc.AddMinutes(-5)
            $sugEnd = Format-UtcDate $sorted[$hi].TimeUtc.AddMinutes(5)
            $reusePath = if ($AuditRecordsPath) { $AuditRecordsPath } else { $rawPath }
            Write-Information "`nBusiest hour for removals: $($peak.Name) ($($peak.Count) removals). The burst around it runs from $(Format-UtcDate $sorted[$lo].TimeUtc) to $(Format-UtcDate $sorted[$hi].TimeUtc) ($($hi - $lo + 1) removals). If that is the incident, check it against the events CSV, then re-run with -IncidentStart '$sugStart' -IncidentEnd '$sugEnd' -AuditRecordsPath '$reusePath'. Removals before -IncidentStart are treated as deliberate (Restore No)." -InformationAction Continue
        }
        else {
            $incidentActor = $removals | Where-Object Phase -eq 'Incident' | Group-Object Actor | Sort-Object Count -Descending | Select-Object -First 1
            if ($incidentActor) {
                $stillRemoving = @($removals | Where-Object { $_.Phase -eq 'PostIncident' -and $_.Actor -eq $incidentActor.Name })
                if ($stillRemoving.Count -gt 0) {
                    Write-Warning "$($incidentActor.Name) made most of the incident removals and has made $($stillRemoving.Count) more since the window closed. The cause may still be active; fix it before restoring."
                }
                # Removals by the same account just before the window are classed RemovedBeforeIncident (Restore No) with no note
                $justBeforeFloor = $incidentStartUtc.AddHours(-2)
                $justBefore = @($removals | Where-Object { $_.Phase -eq 'PreIncident' -and $_.Actor -eq $incidentActor.Name -and $_.TimeUtc -ge $justBeforeFloor } | Sort-Object TimeUtc)
                if ($justBefore.Count -gt 0) {
                    # Only people whose last event is that removal end up RemovedBeforeIncident
                    $beforeRows = @($plan | Where-Object {
                            $_.Evidence -eq 'RemovedBeforeIncident' -and $_.RemovedBy -eq $incidentActor.Name -and
                            $_.LastEventUtc -and (ConvertTo-UtcDate $_.LastEventUtc) -ge $justBeforeFloor
                        })
                    $reuse = if ($AuditRecordsPath) { $AuditRecordsPath } else { $rawPath }
                    Write-Warning "$($incidentActor.Name) also made $($justBefore.Count) removal(s) in the 2 hours before -IncidentStart, the earliest at $(Format-UtcDate $justBefore[0].TimeUtc). $($beforeRows.Count) plan row(s) are RemovedBeforeIncident (not restored automatically) because of them. If they belong to the incident, re-run with -IncidentStart '$(Format-UtcDate $justBefore[0].TimeUtc.AddMinutes(-5))' -IncidentEnd '$(Format-UtcDate $incidentEndUtc)' -AuditRecordsPath '$reuse'."
                }
            }
        }
    }
    else {
        Write-Warning "No MemberRemoved events were found for these channels. The removal was probably not audited per channel; check the Entra audit log for the parent group instead."
    }

    if ($failedTeams.Count -gt 0) {
        Write-Warning "$($failedTeams.Count) team(s) could not be read and are missing from the results: $($failedTeams.TeamName -join ', ')"
    }

    Write-Information "`nState:           $statePath`nCurrent members: $currentPath`nEvents:          $eventsPath`nPlan:            $planPath" -InformationAction Continue
    Write-Information "Review the Restore column in the plan before using it. Nothing was changed in the tenant." -InformationAction Continue
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    exit 1
}
finally {
    try {
        $null = Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Information "Disconnected from Microsoft Graph" -InformationAction Continue
    }
    catch {
        # Ignore disconnect errors
    }
}
