# Teams private channel membership recovery

Two PowerShell scripts for a tenant where private channels have lost their owners and members while the parent teams are fine. They take account of people who have already been re-added by hand and of membership changes made since the incident.

| File | Changes the tenant? | Purpose |
| --- | --- | --- |
| `Get-PrivateChannelMembershipRecovery.ps1` | No | Rebuilds each channel's roster from the audit log as it stood when the incident hit, compares it with who is there now, and writes a restore plan. |
| `Restore-PrivateChannelMembership.ps1` | Yes (adds and promotes only) | Applies the reviewed plan, checking live membership (read once per channel and team) before it changes anything. |

**These scripts have not been run.** They were written and reviewed without a PowerShell runtime or access to the tenant. Run discovery against one team first, and use `-WhatIf` on the restore before trusting either.

## Requirements

- PowerShell 7.2 or later. The MicrosoftTeams module is not supported on 7.0 or 7.1.
- An account with Teams Administrator (or Global Administrator) that can also search the Purview audit log.
- Modules, installed on first run if missing: `Microsoft.Graph.Authentication` (discovery) and `MicrosoftTeams` (restore). The restore script does not update a copy that is already installed.
- A current `MicrosoftTeams` module for the migration-status check below. `Get-TenantPrivateChannelMigrationStatus` only exists in recent versions.
- Discovery asks for these delegated Graph scopes: `Team.ReadBasic.All`, `Channel.ReadBasic.All`, `ChannelMember.Read.All`, `GroupMember.Read.All`, `User.Read.All`, `AuditLogsQuery.Read.All`.

## Before you restore anything: find the cause

Removing someone from a team removes them from all its private channels, and adding them back to the team does not put them back in the channels. If something is still churning group membership, a restore will be undone.

1. In Entra, open one affected team's group, go to Audit logs, and look for "Remove member from group" around the time it broke. Note the "initiated by" account.
2. Check Microsoft's private channel migration status, which lists ownerless channels:

   ```powershell
   # Installs the latest module alongside any older one; start a new session if MicrosoftTeams is already loaded
   Install-Module MicrosoftTeams -Scope CurrentUser -Force
   Connect-MicrosoftTeams
   $s = Get-TenantPrivateChannelMigrationStatus
   $s | Format-List
   ($s.Details | ConvertFrom-Json).ownerlessChannelsDetails
   ```

If step 1 shows no removals and the migration timing lines up, open a Microsoft support ticket before restoring.

## Step 1: discovery on one team

```powershell
./Get-PrivateChannelMembershipRecovery.ps1 -TeamId <group-id-of-one-affected-team>
```

Without `-IncidentStart` every removed user is marked `Review`. The summary prints removals by day and by account. It also suggests an incident window covering the whole burst of removals around the busiest hour, capped at 6 hours either side; check that against the events CSV before using it. The raw audit export is saved as `audit-records-<timestamp>.json`.

On this first run, also check:

- **Role numbering.** The summary line `Audit role numbering used:` says how the audit `Role` value was read. If it warns that the numbering is not certain, compare `RawRole` in the events CSV with people whose role you know, then re-run with `-RoleNumbering ZeroBased` or `-RoleNumbering OneBased`.
- **Matching.** If the summary says audit records were returned but none matched a private channel, open one record in the saved JSON and check its `auditData` before trusting an empty plan.

## Step 2: discovery with the incident window

```powershell
./Get-PrivateChannelMembershipRecovery.ps1 -IncidentStart '2026-09-28T13:00:00Z' -IncidentEnd '2026-09-28T16:00:00Z'
```

Times are UTC. `-IncidentEnd` defaults to 24 hours after the start. Keep the window tight, because a removal after the window is treated as a later change. Don't start it too late either: removals just before `-IncidentStart` are treated as deliberate. The summary warns if the main incident account also removed people in the two hours before the window.

| Parameter | Use |
| --- | --- |
| `-TeamId` | Limit to one or more teams. |
| `-AuditRecordsPath` | Reuse a saved audit export instead of querying again. |
| `-AuditQueryId` | Collect audit queries an earlier run submitted but timed out waiting for. The IDs are printed when the queries are submitted. |
| `-AuditWindowDays` | Days per audit query (default 15). Lower it if a query reports that it hit its record limit, keeping `-DaysBack` / `-AuditWindowDays` at 40 or less. A tenant is only guaranteed 50 queued or running audit queries, and the script refuses to submit more than 40. |
| `-AuditTimeoutMinutes` | How long to wait for the audit queries (default 120, maximum 2880). |
| `-RoleNumbering` | Force how the audit `Role` value is read once you have checked it. |

### Output files

| File | Contents |
| --- | --- |
| `private-channel-state-*.csv` | One row per private channel: status, owner and member counts, how many people were already re-added, how many are new since the incident, pending plan rows. |
| `private-channel-current-members-*.csv` | Everyone in each channel right now, tagged by how they relate to the incident. |
| `private-channel-events-*.csv` | Every audit event used, with its phase (pre-incident, incident, post-incident), actor and raw role value. |
| `restore-plan-*.csv` | The plan. Edit the `Restore` column, then feed it to the restore script. |
| `audit-records-*.json` | Raw audit export, reusable with `-AuditRecordsPath`. |

### How re-adds and later changes are handled

Current membership is always read live, so the plan only contains what is still outstanding.

| Situation | In the plan as | `Restore` |
| --- | --- | --- |
| Removed in the incident, still missing | `Add`, evidence `RemovedDuringIncident` | Yes |
| Audit shows them added before the window closed and never removed, but they are missing | `Add`, evidence `AddedNeverRemoved` | Yes |
| As above, but they were removed from the parent team after their last channel event and outside the window | `Add`, evidence `RemovedFromTeamOutsideWindow` (`RemovedFromTeam` when no `-IncidentStart` is given) | Review |
| No `-IncidentStart` given, and the audit shows them removed | `Add`, evidence `Removed` | Review |
| Audit last shows them in the channel after the window, but they are missing and no removal was logged | `Add`, evidence `PresentAfterIncidentThenMissing` | Review |
| Audit shows a re-add, but they are missing and no later removal was logged | `Add`, evidence `ReAddedThenMissing` | Review |
| Already re-added by hand with the right role | Not in the plan (listed in current members as `ReAddedAfterIncident`) | n/a |
| Re-added by hand as a member but was an owner | `Promote`, evidence `ReAddedWithoutOwnerRole` | Yes |
| As above, but the incident removal itself was not in the audit log (inferred from a second add) | `Promote`, evidence `ReAddedWithoutOwnerRole` | Review |
| Re-added, then someone changed their role to non-owner; or re-added without the owner role after a deliberate or possibly deliberate removal; or the last audited event is such a removal but they are back now | `Promote`, evidence `DemotedAfterReAdd` | Review |
| Re-added by hand, then removed again after the window by someone other than the incident account (if this person's own incident removal was not logged with an account: by an account that removed nobody inside the window) | `Add`, evidence `RemovedAgainAfterReAdd` | No |
| Re-added by hand, then removed again after the window by the account behind the incident removal (if this person's own incident removal was not logged with an account: by any account that removed people inside the window) | `Add`, evidence `RemovedAgainByIncidentActor` | Review |
| Re-added by hand, then removed again inside the window by a different account | `Add`, evidence `RemovedAgainInsideWindow` | Review |
| Removed after the window without a re-add | `Add`, evidence `RemovedAfterIncidentWindow` | Review |
| Removed before the incident | `Add`, evidence `RemovedBeforeIncident` | No |
| Added to the channel for the first time since the incident | Not in the plan (listed as `NewSinceIncident`) | n/a |
| An add and a removal for the person share a timestamp, so their order is unknown | Any of the above | Review |
| Proposed owner whose role changed inside the window before the removal (for example Teams promoting a member when an owner left) | Any of the above with `ProposedRole` Owner | `Yes` rows become `Review`; `No` rows stay `No` |
| The channel's roster could not be read | Any of the above, with a note that current membership is unknown | `Yes` rows become `Review`; `No` rows stay `No` |
| Account disabled, deleted or renamed since | Downgraded from Yes | Review |
| No longer in the parent team | Downgraded from Yes | Review |
| Proposed owner, but the audit role numbering could not be confirmed | Downgraded from Yes | Review |

Every `Review` row explains itself in the `Note` column.

Channel status values:

- `Empty` or `Ownerless`: as named.
- `PartiallyRestored`: someone was re-added, but `Yes` rows are still pending.
- `PendingRestore`: `Yes` rows are pending and nobody has been re-added yet.
- `ReviewOnly`: only `Review` rows remain, so nothing can be applied as it stands.
- `NoActionNeeded`: nothing outstanding.
- `Unreadable`: the channel's roster could not be read.

Nobody is ever proposed for removal or demotion. Members who are new since the incident are reported only.

## Step 3: review the plan

Open `restore-plan-*.csv` and check every row. The audit log shows who was a member, not who should be one.

- Set `Restore` to `Yes` or `No` on every `Review` row.
- Make sure each `Empty` or `Ownerless` channel has at least one row with `ProposedRole` = `Owner`. The discovery summary warns about channels where none was identified.
- Sanity-check proposed owners against the role numbering note from step 1.

## Step 4: restore

Preview first. This signs in and reads live state but changes nothing:

```powershell
./Restore-PrivateChannelMembership.ps1 -PlanPath ./restore-plan-<timestamp>.csv -WhatIf
```

Then apply. It prompts before each change; answer `A` for Yes to All:

```powershell
./Restore-PrivateChannelMembership.ps1 -PlanPath ./restore-plan-<timestamp>.csv
```

It reads each channel's membership once, at that channel's first `Restore` = `Yes` row. It reads the parent team's membership once, the first time someone missing from one of its channels needs adding. People are matched by object ID (the plan's `UserId` column) and by UPN. The script keeps those copies up to date with its own changes but does not see changes other people make while it runs, so **don't edit these channels by hand during a run**. If someone does, re-run discovery before re-running the restore.

Rows are handled like this:

- **Skipped, already done:** the person is already in the channel with the right role.
- **Skipped, not in team:** the person is no longer in the parent team.
- **Skipped, Promote row:** the person is no longer in the channel.
- **Unverified:** the channel or team membership could not be read; nothing is changed. Re-run.

The script writes two files:

- `restore-before-snapshot-*.csv`: the membership of every channel it touched, before changes. A channel that was empty has one row with Role `NO MEMBERS`; a channel that could not be read has one row with Role `ROSTER UNREADABLE`.
- `restore-results-*.csv`: the outcome of every row. `Result` is `Added`, `Promoted`, `Partial` (added, but promotion to owner failed), `Failed`, `Skipped`, `Unverified`, `WhatIf` or `Declined`. `RoleBefore` is the person's role before the run, even when an earlier row of the same run already changed it.

At the end it warns about any channel that still has no owner, and says which of these applies:

- The plan has no owner row the script can apply.
- The owner row could not be checked (re-run; don't edit the plan).
- A `Promote` owner row was skipped because the person left the channel (re-run discovery).
- The owner row was declined or failed.

### Undo

Work from `restore-results-*.csv`:

- **`Result` is `Added` or `Partial`:** this run added the user. Remove them:

  ```powershell
  Remove-TeamChannelUser -GroupId <TeamId> -DisplayName <ChannelName> -User <UPN>
  ```

- **`Result` is `Promoted`:** the user was already a member and was only made an owner. Demote them back to member with the same command plus `-Role Owner`. Without `-Role` it removes someone who was there before the run.
- **The user is the channel's only owner:** the last owner of a private channel cannot be removed or demoted. Add and promote the right owner first, then remove the wrong one.

## Step 5: verify

Re-run discovery with the same incident window, using a fresh audit query rather than `-AuditRecordsPath`. Teams clients can take a while to reflect the change.

- **Restored channels** should show `NoActionNeeded`, or `ReviewOnly` where only `Review` rows remain (for example a disabled account or a removal after the window).
- **Your decisions are not remembered.** Discovery does not read your edited plan, so a row you set to `No` is proposed again on every run. A channel where you declined a `Yes` row still shows `PendingRestore` or `PartiallyRestored`; compare the new plan with the one you reviewed.

## Limits

- **Audit retention.** 180 days on Audit Standard. Someone added before that and never touched since has no audit history; channels with `AuditEvidenceRows` = 0 need another source, such as who posted in the channel or the user list on the channel's SharePoint site.
- **Audit query time and size.** Queries are asynchronous and can take hours on a large tenant. The run stops rather than use a query that hit its record limit.
- **Stale audit data.** With `-AuditRecordsPath` or `-AuditQueryId`, re-adds made since are still seen, but removals made since are not. Use a fresh query before the final restore.
- **Matching is by user principal name.** A renamed user shows as `NotFound` and is marked `Review`; correct the UPN in the plan by hand.
- **Renamed and recreated channels.** Events are matched by channel ID. Name matching is used only when an audit record carries no channel ID, and never for events older than the current channel.
- **Output files contain user names.** Treat them as sensitive and delete them when finished.
