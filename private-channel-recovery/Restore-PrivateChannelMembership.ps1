#Requires -Version 7.2
<#
.TITLE
    Restore Private Channel Membership

.SYNOPSIS
    Re-adds owners and members to Teams private channels from a reviewed restore plan CSV, checking live state first.

.DESCRIPTION
    Reads the restore plan produced by Get-PrivateChannelMembershipRecovery.ps1 and, for every row
    marked Restore = Yes, adds the user back to the private channel with Add-TeamChannelUser and
    promotes them to owner where the plan says so. It reads each channel's live membership once, at
    that channel's first row, and the parent team's once, when first needed. Anyone re-added by hand
    before then is skipped rather than touched twice; changes other people make during the run are
    not seen. If live membership cannot be read, the row is reported as Unverified and nothing
    is changed. Supports -WhatIf, prompts before each change, never removes or demotes anyone, and
    writes a before-snapshot and a results CSV.

.TAGS
    Operational,Remediation

.PLATFORM
    Cross-platform

.PERMISSIONS
    None (uses the MicrosoftTeams PowerShell module; requires the Teams Administrator or Global Administrator role)

.AUTHOR
    AI Generated (Claude, following IntuneAutomation.com conventions)

.VERSION
    1.3

.CHANGELOG
    1.0 - Initial release
    1.1 - Checks live channel and team membership before every change, honours the plan's Action
          column (Add or Promote), connects during -WhatIf so the preview is accurate, and saves a
          before-snapshot of every channel it touches.
    1.2 - -WhatIf no longer suppresses sign-in. Rows are not applied when live membership cannot be
          read (Result Unverified). Live matching uses the object ID from the plan's UserId column as
          well as the UPN. The no-owner warning is accurate under -WhatIf and names channels readably.
    1.3 - The no-owner warning says when the owner row could not be checked or was skipped. A second
          row for someone this run already added reports Added, not Promoted. Empty channels are
          recorded in the before-snapshot.

.LASTUPDATE
    2026-10-03

.EXAMPLE
    .\Restore-PrivateChannelMembership.ps1 -PlanPath .\restore-plan-20261002-101500.csv -WhatIf
    Connects, reads live state and shows what would be added or promoted without changing anything.

.EXAMPLE
    .\Restore-PrivateChannelMembership.ps1 -PlanPath .\restore-plan-20261002-101500.csv
    Applies the plan, prompting for each change (answer A for Yes to All).

.NOTES
    - This GRANTS access to private channels. Review every row of the plan first; the audit log
      shows who was a member, not who should be one.
    - A user must already be in the parent team. That is checked live; users who are not are
      skipped and reported. This script never adds anyone to a parent team.
    - Rows are skipped, not failed, when the user is already in the channel with the right role.
    - A Promote row is skipped if the user is no longer in the channel: someone changed it since
      the plan was built, so re-run discovery.
    - A user is added as a member first and then promoted, because a channel owner must already be
      a channel member.
    - To undo, use the results CSV. Result Added or Partial: this run added the user; remove them with
      Remove-TeamChannelUser -GroupId <TeamId> -DisplayName <ChannelName> -User <UPN>.
      Result Promoted: the user was already a member; demote with the same command plus -Role Owner.
      The last owner of a private channel cannot be removed: add and promote the right owner first.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, HelpMessage = "Path to the reviewed restore plan CSV")]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]$PlanPath,

    [Parameter(Mandatory = $false, HelpMessage = "Folder for the snapshot and results CSVs")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = ".",

    [Parameter(Mandatory = $false, HelpMessage = "Force module installation without prompting")]
    [switch]$ForceModuleInstall
)

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

if (-not (Get-Module -ListAvailable -Name MicrosoftTeams)) {
    if (-not $ForceModuleInstall) {
        $response = Read-Host "Install module 'MicrosoftTeams'? (Y/N)"
        if ($response -notmatch '^[Yy]') {
            Write-Error "Module 'MicrosoftTeams' is required but installation was declined."
            exit 1
        }
    }
    Install-Module -Name MicrosoftTeams -Scope CurrentUser -Force -AllowClobber -Repository PSGallery -WhatIf:$false -Confirm:$false
}
Import-Module -Name MicrosoftTeams -ErrorAction Stop

# ============================================================================
# PLAN VALIDATION
# ============================================================================

$required = 'TeamName', 'TeamId', 'ChannelName', 'UserPrincipalName', 'ProposedRole', 'Restore'
$rows = @(Import-Csv -Path $PlanPath)
if ($rows.Count -eq 0) {
    Write-Error "Plan '$PlanPath' has no rows."
    exit 1
}
$missing = @($required | Where-Object { $_ -notin $rows[0].PSObject.Properties.Name })
if ($missing.Count -gt 0) {
    Write-Error "Plan is missing columns: $($missing -join ', ')"
    exit 1
}

$toApply = @($rows | Where-Object { "$($_.Restore)".Trim() -eq 'Yes' })
Write-Information "Plan rows: $($rows.Count). Marked Restore=Yes: $($toApply.Count)." -InformationAction Continue
if ($toApply.Count -eq 0) {
    Write-Warning "Nothing to apply."
    exit 0
}

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

$script:TeamCache = @{}       # groupId -> @{ key = $true } keyed by object ID and UPN, or $null if unreadable
$script:ChannelCache = @{}    # team|channel -> @{ key = @{ Role } } keyed by object ID and UPN, or $null if unreadable
$script:ChannelLabel = @{}
$snapshot = [System.Collections.Generic.List[object]]::new()

function Get-TeamKeySet {
    param([string]$GroupId)

    if (-not $script:TeamCache.ContainsKey($GroupId)) {
        $keys = $null
        for ($attempt = 1; $attempt -le 3 -and $null -eq $keys; $attempt++) {
            try {
                $users = @(Get-TeamUser -GroupId $GroupId -ErrorAction Stop)
                $keys = @{}
                foreach ($u in $users) {
                    if ($u.UserId) { $keys["$($u.UserId)".ToLowerInvariant()] = $true }
                    if ($u.User) { $keys["$($u.User)".ToLowerInvariant()] = $true }
                }
            }
            catch {
                $keys = $null
                Write-Warning "Could not read members of team $GroupId (attempt $attempt of 3): $($_.Exception.Message)"
                if ($attempt -lt 3) { Start-Sleep -Seconds 10 }
            }
        }
        $script:TeamCache[$GroupId] = $keys
    }
    return $script:TeamCache[$GroupId]
}

function Get-ChannelRoster {
    param(
        [string]$GroupId,
        [string]$TeamName,
        [string]$ChannelName
    )

    $cacheKey = "$GroupId|$ChannelName".ToLowerInvariant()
    if (-not $script:ChannelCache.ContainsKey($cacheKey)) {
        $script:ChannelLabel[$cacheKey] = "$TeamName / $ChannelName"
        $roster = $null
        for ($attempt = 1; $attempt -le 3 -and $null -eq $roster; $attempt++) {
            try {
                $users = @(Get-TeamChannelUser -GroupId $GroupId -DisplayName $ChannelName -ErrorAction Stop)
                $roster = @{}
                foreach ($u in $users) {
                    if (-not $u.UserId -and -not $u.User) { continue }
                    # One shared entry per person, reachable by object ID and by UPN, so a role change updates both
                    $member = @{ Role = "$($u.Role)"; RoleBefore = "$($u.Role)" }
                    if ($u.UserId) { $roster["$($u.UserId)".ToLowerInvariant()] = $member }
                    if ($u.User) { $roster["$($u.User)".ToLowerInvariant()] = $member }
                    $snapshot.Add([pscustomobject]@{ TeamName = $TeamName; TeamId = $GroupId; ChannelName = $ChannelName; UserId = $u.UserId; User = $u.User; Name = $u.Name; Role = $u.Role })
                }
                if ($roster.Count -eq 0) {
                    # Read successfully but empty: record it so the snapshot shows every channel the run touched
                    $snapshot.Add([pscustomobject]@{ TeamName = $TeamName; TeamId = $GroupId; ChannelName = $ChannelName; UserId = $null; User = $null; Name = $null; Role = 'NO MEMBERS' })
                }
            }
            catch {
                $roster = $null
                Write-Warning "Could not read members of '$TeamName / $ChannelName' (attempt $attempt of 3): $($_.Exception.Message)"
                if ($attempt -lt 3) { Start-Sleep -Seconds 10 }
            }
        }
        if ($null -eq $roster) {
            $snapshot.Add([pscustomobject]@{ TeamName = $TeamName; TeamId = $GroupId; ChannelName = $ChannelName; UserId = $null; User = $null; Name = $null; Role = 'ROSTER UNREADABLE' })
        }
        $script:ChannelCache[$cacheKey] = $roster
    }
    return $script:ChannelCache[$cacheKey]
}

# ============================================================================
# MAIN SCRIPT LOGIC
# ============================================================================

$results = [System.Collections.Generic.List[object]]::new()
$plannedOwner = @{}
$ownerRowBlocked = @{}   # channel key -> why a Restore=Yes owner row could not be checked or applied
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

try {
    # -WhatIf must not reach Connect: the preview is only accurate against live membership
    Write-Information "Connecting to Microsoft Teams..." -InformationAction Continue
    $null = Connect-MicrosoftTeams -WhatIf:$false -Confirm:$false -ErrorAction Stop

    foreach ($row in ($toApply | Sort-Object TeamName, ChannelName, UserPrincipalName)) {
        $target = "$($row.TeamName) / $($row.ChannelName)"
        $cacheKey = "$($row.TeamId)|$($row.ChannelName)".ToLowerInvariant()
        $upn = "$($row.UserPrincipalName)".Trim()
        $rowKeys = @(@("$($row.UserId)".Trim(), $upn) | Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
        $wantOwner = "$($row.ProposedRole)".Trim() -eq 'Owner'
        $planAction = if ($row.PSObject.Properties.Name -contains 'Action' -and $row.Action) { "$($row.Action)".Trim() } else { 'Add' }
        $result = 'Skipped'
        $detail = $null
        $needAdd = $false
        $needPromote = $false

        $roster = Get-ChannelRoster -GroupId $row.TeamId -TeamName $row.TeamName -ChannelName $row.ChannelName
        $member = $null
        if ($null -ne $roster) {
            foreach ($k in $rowKeys) {
                if ($roster.ContainsKey($k)) { $member = $roster[$k]; break }
            }
        }
        # RoleBefore describes the state before this run, not a membership an earlier row of this run created
        $liveRole = if ($null -eq $roster) { 'Unknown' } elseif ($null -eq $member) { $null } else { $member.RoleBefore }

        if ($null -eq $roster) {
            # Never change a channel whose current membership is unknown
            $result = 'Unverified'
            $detail = 'Channel roster could not be read (renamed, deleted, throttled or no access); nothing changed. Re-run.'
        }
        elseif ($null -eq $member) {
            if ($planAction -eq 'Promote') {
                $detail = 'No longer in the channel; re-run discovery'
            }
            else {
                $teamKeys = Get-TeamKeySet -GroupId $row.TeamId
                if ($null -eq $teamKeys) {
                    $result = 'Unverified'
                    $detail = 'Parent team membership could not be read; nothing changed. Re-run.'
                }
                elseif (-not @($rowKeys | Where-Object { $teamKeys.ContainsKey($_) }).Count) {
                    $detail = 'Not in the parent team'
                }
                else {
                    $needAdd = $true
                    $needPromote = $wantOwner
                }
            }
        }
        elseif ($member.Role -eq 'Owner') {
            $detail = if ($member.AddedThisRun) { 'Already added as owner by an earlier row of this run' }
            elseif ($member.RoleBefore -ne 'Owner') { 'Already promoted by an earlier row of this run' }
            else { 'Already an owner' }
        }
        elseif ($wantOwner) {
            $needPromote = $true
        }
        else {
            $detail = if ($member.AddedThisRun) { 'Already added by an earlier row of this run' } else { 'Already a member' }
        }

        if ($needAdd -or $needPromote) {
            $action = if ($needAdd -and $needPromote) { "Add $upn as owner" } elseif ($needAdd) { "Add $upn as member" } else { "Promote $upn to owner" }
            if ($needPromote) { $plannedOwner[$cacheKey] = $true }
            $result = if ($WhatIfPreference) { 'WhatIf' } else { 'Declined' }
            $detail = $action

            if ($PSCmdlet.ShouldProcess($target, $action)) {
                try {
                    if ($needAdd) {
                        Add-TeamChannelUser -GroupId $row.TeamId -DisplayName $row.ChannelName -User $upn -ErrorAction Stop
                        $result = 'Added'
                        $detail = 'Member'
                        $member = @{ Role = 'Member'; AddedThisRun = $true; RoleBefore = $null }
                        foreach ($k in $rowKeys) { $roster[$k] = $member }
                    }

                    if ($needPromote) {
                        # Promotion can fail until a new membership has propagated
                        $promoted = $false
                        $lastError = $null
                        for ($attempt = 1; $attempt -le 6 -and -not $promoted; $attempt++) {
                            try {
                                Add-TeamChannelUser -GroupId $row.TeamId -DisplayName $row.ChannelName -User $upn -Role Owner -ErrorAction Stop
                                $promoted = $true
                            }
                            catch {
                                $lastError = $_.Exception.Message
                                if ($attempt -lt 6) { Start-Sleep -Seconds 10 }
                            }
                        }
                        if ($promoted) {
                            $result = if ($needAdd -or $member.AddedThisRun) { 'Added' } else { 'Promoted' }
                            $detail = 'Owner'
                            $member.Role = 'Owner'
                        }
                        else {
                            $result = if ($needAdd -or $member.AddedThisRun) { 'Partial' } else { 'Failed' }
                            $detail = "Owner promotion failed: $lastError"
                            Write-Warning "$target - $($upn): $detail"
                        }
                    }
                }
                catch {
                    $result = 'Failed'
                    $detail = $_.Exception.Message
                    Write-Warning "$target - $($upn): $detail"
                }
            }
        }

        if ($wantOwner -and -not $needPromote -and $null -ne $roster -and $null -eq $member) {
            if ($result -eq 'Unverified') {
                # Parent team unreadable: the plan is fine, the check is not
                $ownerRowBlocked[$cacheKey] = "the owner row for $upn could not be checked because the parent team's membership could not be read. Nothing changed. Re-run; do not edit the plan."
            }
            elseif ($planAction -eq 'Promote' -and -not $ownerRowBlocked.ContainsKey($cacheKey)) {
                $ownerRowBlocked[$cacheKey] = "the Promote row for $upn was skipped because that person is no longer in the channel. Re-run discovery before choosing another owner."
            }
            # 'Not in the parent team' is left out: the generic message below is the right advice for it
        }

        $results.Add([pscustomobject]@{
                TeamName          = $row.TeamName
                TeamId            = $row.TeamId
                ChannelName       = $row.ChannelName
                UserPrincipalName = $upn
                PlanAction        = $planAction
                ProposedRole      = $row.ProposedRole
                RoleBefore        = $liveRole
                Result            = $result
                Detail            = $detail
            })
    }

    # A channel left without an owner stays unmanageable by its own users
    foreach ($cacheKey in @($script:ChannelCache.Keys)) {
        $roster = $script:ChannelCache[$cacheKey]
        if ($null -eq $roster) { continue }
        if (@($roster.Values | Where-Object { $_.Role -eq 'Owner' }).Count -gt 0) { continue }
        $label = $script:ChannelLabel[$cacheKey]
        if ($plannedOwner.ContainsKey($cacheKey)) {
            if (-not $WhatIfPreference) {
                Write-Warning "'$label' still has no owner: its owner row was declined or failed. See the results CSV, then re-run."
            }
        }
        elseif ($ownerRowBlocked.ContainsKey($cacheKey)) {
            Write-Warning "'$label' has no owner: $($ownerRowBlocked[$cacheKey])"
        }
        else {
            Write-Warning "'$label' has no owner, and no Restore=Yes row in this plan can give it one. Set ProposedRole to Owner for at least one person who is in the parent team, then re-run."
        }
    }
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
}
finally {
    if (-not (Test-Path -Path $OutputPath)) { $null = New-Item -Path $OutputPath -ItemType Directory -WhatIf:$false -Confirm:$false }
    $snapshotPath = Join-Path $OutputPath "restore-before-snapshot-$stamp.csv"
    $resultsPath = Join-Path $OutputPath "restore-results-$stamp.csv"
    $snapshot | Export-Csv -Path $snapshotPath -NoTypeInformation -WhatIf:$false -Confirm:$false
    $results | Export-Csv -Path $resultsPath -NoTypeInformation -WhatIf:$false -Confirm:$false

    Write-Information "`n===== SUMMARY =====" -InformationAction Continue
    $results | Group-Object Result | Sort-Object Name | ForEach-Object { Write-Information ("  {0,-10} {1}" -f $_.Name, $_.Count) -InformationAction Continue }
    Write-Information "Before-snapshot: $snapshotPath" -InformationAction Continue
    Write-Information "Results:         $resultsPath" -InformationAction Continue
    Write-Information "Teams clients can take a while to show the change. Re-run the discovery script to confirm the channels now have owners." -InformationAction Continue

    try { $null = Disconnect-MicrosoftTeams -WhatIf:$false -Confirm:$false -ErrorAction SilentlyContinue } catch { Write-Verbose "Disconnect failed: $_" }
}
