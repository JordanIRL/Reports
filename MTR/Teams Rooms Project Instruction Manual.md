# Teams Rooms Project Instruction Manual

Oct 2, 2026 · Version 1.0

Every wave in the Teams Rooms project runs the same way: prepare, check, change one account, test, observe and record. Gate criteria, acceptance tests and recovery tables are defined in Doc; the instructions here show how to carry them out.

## How to use this manual

Find the activity in hand below, follow its instructions, and check the pass criteria in the runbook section it names.

| Document | Use it for |
| --- | --- |
| CAB submission | Scope, approved decisions, wave sizes, risks and backout limits |
| Passwordless runbook | Gate 0 checklist, supported policies, per-account conversion, acceptance tests, device recovery |
| Cloud identity runbook | Gate 1 checklist, baseline register, RoomList and account transfer, rollback, AD retirement |
| This manual | Setting up, running windows, recording evidence, communicating and escalating |
| Change record | Named owners, window dates, phase releases, exceptions and the CAB decision |

| Role | Responsibilities in a window |
| --- | --- |
| Change owner | Go or no-go, phase release, stop and resume decisions, communications |
| Room engineer | Pre-checks, device work, acceptance tests, evidence capture |
| Teams Administrator | Pro Management migration, remote sign-out, update pauses |
| Identity engineer | Password cleanup, authority transfer, sync and audit checks |
| Exchange engineer | Mailbox and RoomList baselines, RoomList membership changes |
| Security owner | Policy exceptions, supervised rollback windows |
| Site contact | Physical access, restarts, sign-in at the device |

One person can hold several roles. Where staffing allows, the change owner and the person executing the change are different people.

## The change-window loop

Every window, passwordless or identity, follows the same loop: one account at a time, tested before the next begins.

&#91;embedded content: change-window loop · 5 steps, 2 decisions\]

A failed test sends the wave to stop, recover and review; only the change owner's recorded decision returns it to the loop.

## One-time setup

Complete these steps once, before the Gate 0 review. Each produces evidence for the readiness pack.

1. **Access.** Make the project roles eligible in Privileged Identity Management, activated per window: Teams Administrator, User Administrator, Exchange Administrator and Hybrid Identity Administrator. Global Administrator is eligible only for named people, for supervised rollback.
2. **Administrative unit.** In the Entra admin centre, create an administrative unit holding only the approved room accounts and project groups. Assign Hybrid Identity Administrator scoped to that unit.
3. **Graph consent.** An Application Administrator grants the chosen tool (Microsoft Graph Command Line Tools or the project app registration) these delegated scopes: User-OnPremisesSyncBehavior.ReadWrite.All, Group-OnPremisesSyncBehavior.ReadWrite.All, User.Read.All, GroupMember.Read.All, AuditLog.Read.All and OnPremDirectorySynchronization.Read.All.
4. **Tools.** Install the modules on the admin workstation. The ActiveDirectory module is used from a management server with RSAT.

```powershell
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups, Microsoft.Graph.Identity.DirectoryManagement, Microsoft.Graph.Reports -Scope CurrentUser
```

5. **Evidence location.** Create the restricted evidence folder, structured as described under Evidence and records, with access limited to project roles.
6. **Tenant baseline.** Record the directory-sync configuration ID and the hard-match protection value. Rollback depends on both.

```powershell
Connect-MgGraph -Scopes 'OnPremDirectorySynchronization.Read.All'
Get-MgDirectoryOnPremiseSynchronization |
  Select-Object Id, @{n='HardMatchBlocked'; e={$_.Features.BlockCloudObjectTakeoverThroughHardMatchEnabled}}
```

7. **Sync servers.** On the active and staging Connect Sync servers, record the installed version from Programs and Features, then record the scheduler state.

```powershell
Get-ADSyncScheduler | Select-Object SyncCycleEnabled, StagingModeEnabled, CurrentlyEffectiveSyncCycleInterval
```

8. **Recovery kit.** Reserve a spare Android device and a spare or scheduled Windows room for rehearsals. Stage the OEM recovery image or Microsoft recovery tool media, and record local administrator access for each Windows room.

## Manifest and baselines

The inventory script captures mailbox, calendar processing, permission and Places data for the approved list. The commands below add the identity, AD, RoomList and Windows fields the runbooks also need.

Work in this order: approved CSV, inventory script, the commands below, manual fields, then one reconciled register row per account. A failed query is entered as *Unknown*, never left blank.

**Identity and sync state** (Graph PowerShell)

```powershell
Connect-MgGraph -Scopes 'User.Read.All','User-OnPremisesSyncBehavior.ReadWrite.All'
$rooms = Import-Csv .\approved-rooms.csv
$identity = foreach ($r in $rooms) {
  $u = Get-MgUser -UserId $r.UPN -Property Id,UserPrincipalName,OnPremisesSyncEnabled,OnPremisesImmutableId,OnPremisesSecurityIdentifier,LicenseAssignmentStates
  $soa = Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$($u.Id)/onPremisesSyncBehavior?`$select=isCloudManaged"
  [pscustomobject]@{
    RoomId         = $r.RoomId
    UPN            = $u.UserPrincipalName
    ObjectId       = $u.Id
    SyncEnabled    = $u.OnPremisesSyncEnabled
    ImmutableId    = $u.OnPremisesImmutableId
    Sid            = $u.OnPremisesSecurityIdentifier
    IsCloudManaged = $soa.isCloudManaged
    LicenceGroups  = ($u.LicenseAssignmentStates | Where-Object AssignedByGroup).AssignedByGroup -join ';'
  }
}
$identity | Export-Csv .\evidence\baseline\identity.csv -NoTypeInformation
```

**AD anchors and Exchange attributes** (ActiveDirectory module)

```powershell
$ad = foreach ($r in $rooms) {
  Get-ADUser -Filter "UserPrincipalName -eq '$($r.UPN)'" -Properties ObjectGUID,ObjectSid,'mS-DS-ConsistencyGuid',msExchRemoteRecipientType,msExchRecipientTypeDetails,targetAddress,proxyAddresses |
    Select-Object UserPrincipalName, ObjectGUID, ObjectSid, DistinguishedName,
      @{n='ConsistencyGuid'; e={ if ($_.'mS-DS-ConsistencyGuid') { [guid]::new([byte[]]$_.'mS-DS-ConsistencyGuid') } }},
      msExchRemoteRecipientType, msExchRecipientTypeDetails, targetAddress,
      @{n='ProxyAddresses'; e={ $_.proxyAddresses -join ';' }}
}
$ad | Export-Csv .\evidence\baseline\ad-anchors.csv -NoTypeInformation
```

**RoomLists** (Exchange Online PowerShell)

```powershell
Connect-ExchangeOnline
Get-DistributionGroup -RecipientTypeDetails RoomList -ResultSize Unlimited |
  Select-Object Name, PrimarySmtpAddress, ExternalDirectoryObjectId, IsDirSynced, HiddenFromAddressListsEnabled,
    @{n='ManagedBy'; e={ $_.ManagedBy -join ';' }},
    @{n='Members'; e={ (Get-DistributionGroupMember $_.Identity -ResultSize Unlimited).PrimarySmtpAddress -join ';' }} |
  Export-Csv .\evidence\baseline\roomlists.csv -NoTypeInformation
```

**Windows room PC** (run in admin mode on each of the five PCs)

```powershell
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
"Edition $($cv.EditionID); version $($cv.DisplayVersion); build $($cv.CurrentBuild).$($cv.UBR)"
Get-Tpm | Select-Object TpmPresent, TpmReady
dsregcmd /status | Select-String 'AzureAdJoined|DomainJoined|TenantName'
netsh winhttp show proxy
```

**Manual fields.** Record the OEM and model, Teams Rooms app version and Pro Management eligibility from the Migration tab. For Android devices, record model, serial, MAC and live app versions from the Pro Management device page.

## Running a passwordless wave

A production wave takes about a week from first notice to cleanup. The account-level steps are the passwordless runbook's per-account procedure.

| When | Action | Owner |
| --- | --- | --- |
| 5 working days before | Confirm the wave's accounts and endpoints in the register; re-run the baseline; send the wave notice; reserve rooms and panels | Change owner |
| 2 working days before | Recheck Pro Management eligibility and live versions; pause any Android version due during the window; confirm the site contact | Room engineer, Teams Administrator |
| 1 working day before | Go or no-go review of the Gate 0 items for these accounts; record each room's backout decision point; request role activation | Change owner |
| Window start | Activate roles; confirm no meeting is in progress; open the wave evidence record | Room engineer |
| During the window | Convert one account at a time, following runbook steps 1 to 8 | Teams Administrator, room engineer |
| Window end | Publish availability, or declare an overrun | Change owner |
| Next business day | Review sign-ins, compliance and incidents per account; accept or hold the wave | Change owner |
| Cleanup day | Scramble each accepted account's password; restart and retest | Identity engineer, room engineer |
| After cleanup | Resume paused Android versions; record completion; brief the next wave | Teams Administrator, change owner |

The pilot differs in two ways: it holds 24 hours before cleanup, and five accepted business days after cleanup before any production wave starts.

**Pausing an Android version.** In Pro Management, open **Updates > Update management > Android updates**, select the version and pause it. The tenant-wide **Pause updates** action stops all Android updates for two weeks and needs change-owner approval.

**Windows waves.** On-site support is booked for the whole window, with recovery media and local administrator access to hand.

**Next-day sign-in review.** This returns interactive sign-ins; non-interactive sign-ins are reviewed in the Entra admin centre sign-in logs.

```powershell
Connect-MgGraph -Scopes 'AuditLog.Read.All'
$since = (Get-Date).ToUniversalTime().AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
Get-MgAuditLogSignIn -All -Filter "userPrincipalName eq 'room01@example.com' and createdDateTime ge $since" |
  Select-Object CreatedDateTime, AppDisplayName, ConditionalAccessStatus,
    @{n='ErrorCode'; e={ $_.Status.ErrorCode }}, @{n='Reason'; e={ $_.Status.FailureReason }}
```

## Running a cloud identity wave

Each identity wave converts one RoomList, then its member accounts one at a time. The account steps are the cloud identity runbook's account transfer and validation procedure.

| When | Action | Owner |
| --- | --- | --- |
| 5 working days before | Select the RoomList and its member accounts; confirm no members outside scope; re-run baselines; send the wave notice | Change owner |
| 1 working day before | Confirm Gate 1 still holds, no AD writer has touched the accounts, and the direct licence fallback is ready | Identity engineer |
| Window, first part | Convert the RoomList; run a sync; verify subtype, membership and Room Finder | Identity engineer, Exchange engineer |
| Window, second part | Transfer member accounts one at a time and verify each | Identity engineer |
| Window end | Restart and test the rooms; publish availability | Room engineer |
| Next business day | Review sign-ins; accept or hold the wave | Change owner |

**Convert the RoomList, then each account** (Graph PowerShell, scoped Hybrid Identity Administrator)

```powershell
Connect-MgGraph -Scopes 'Group-OnPremisesSyncBehavior.ReadWrite.All','User-OnPremisesSyncBehavior.ReadWrite.All'
Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/groups/$groupId/onPremisesSyncBehavior" -Body @{ isCloudManaged = $true }
# after the RoomList checks pass, per account:
Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$userId/onPremisesSyncBehavior" -Body @{ isCloudManaged = $true }
```

**Run a delta sync** (active Connect Sync server)

```powershell
Start-ADSyncSyncCycle -PolicyType Delta
```

**Check the RoomList** (Exchange Online). Expect RecipientTypeDetails of RoomList, IsDirSynced of False, and no output from the comparison.

```powershell
Get-DistributionGroup -Identity $roomList | Select-Object RecipientTypeDetails, IsDirSynced, PrimarySmtpAddress
$was = ((Import-Csv .\evidence\baseline\roomlists.csv | Where-Object PrimarySmtpAddress -eq $roomList).Members) -split ';'
$now = (Get-DistributionGroupMember $roomList -ResultSize Unlimited).PrimarySmtpAddress
Compare-Object $was $now
```

**Check each account.** Expect isCloudManaged of True, an empty onPremisesSyncEnabled, and one audit entry. Reading audit logs also needs a directory role that can read them, such as Reports Reader.

```powershell
(Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$userId/onPremisesSyncBehavior?`$select=isCloudManaged").isCloudManaged
(Get-MgUser -UserId $userId -Property OnPremisesSyncEnabled).OnPremisesSyncEnabled
Get-MgAuditLogDirectoryAudit -Filter "activityDisplayName eq 'Change Source of Authority from AD to cloud' and targetResources/any(t:t/id eq '$userId')" |
  Select-Object ActivityDateTime, Result, @{n='By'; e={ $_.InitiatedBy.User.UserPrincipalName }}
```

On the sync server, the object's Microsoft Entra connector entry shows blockOnPremisesSync as true (Synchronization Service Manager, Connectors, search, Lineage). Event 6956 is logged only when a later AD change is blocked, so its absence is not a failure.

Room Finder is checked by hand in Outlook and Teams: the list appears with every member room, and a direct booking succeeds.

## Evidence and records

Evidence is filed by phase, wave and account, so every room can be traced from baseline to retirement.

```text
TeamsRooms-Project/
  00-Readiness/        manifest, Gate 0 pack, tenant baseline, rehearsal results
  01-Baseline/         identity.csv, ad-anchors.csv, roomlists.csv, inventory output
  02-Passwordless/
    Pilot/<RoomId>/
    Wave-01/<RoomId>/  ... to Wave-08
  03-Groups/           RoomList before and after exports, audit references
  04-Identity/
    Pilot/<RoomId>/
    Wave-NN/<RoomId>/
  05-Retirement/       dependency checks, retirement actions, post-retirement tests
  06-Closure/          handover sign-off, incident comparison
```

Each account folder holds the before and after exports, the Pro Management job result, test results, the sign-in export and any audit reference. Files are named `<RoomId>_<phase>_<item>_<yyyymmdd>`, for example `LOCAL-001_PWL_tests_20261020.csv`.

**Register columns**

| Column | Content |
| --- | --- |
| RoomId, UPN, ObjectId | From the approved manifest |
| Platform, site | Android or Windows; local or remote |
| Endpoints | Count, models and device IDs on the account |
| Waves | Passwordless wave and identity wave |
| Passwordless dates | Converted, accepted, password cleaned |
| Cloud authority accepted | Date and audit reference |
| AD independence accepted | Date and retirement action |
| Exceptions | Change-record reference, owner and expiry |

Passwords, tokens and verification codes are never recorded. Screenshots are cropped before filing.

## When something goes wrong

A stop condition pauses the rest of the wave at once, and only the change owner resumes it.

1. **Stop.** Leave the affected account in its current state, pause the remaining accounts and note the time.
2. **Preserve.** Export the Pro Management job detail, sign-in logs and device state before changing anything.
3. **Inform.** Give the change owner the room, account, symptom and time.
4. **Decide.** The change owner compares the clock with the backout decision point. A fix forward is taken only if the cause is understood and fits; otherwise the runbook recovery is used.
5. **Recover.** Follow the platform recovery in the passwordless runbook, or the rollback in the cloud identity runbook.
6. **Escalate.** If recovery may pass the window end, raise an incident, ask facilities to tell the room's bookers and offer an alternative room.
7. **Review.** Before resuming, the change owner reviews the evidence and records the decision in the change record.

| Situation | Escalate to |
| --- | --- |
| Device will not sign in after recovery | OEM support and a Microsoft support case |
| Unexpected deletion, duplicate object or lost membership | Identity and security owners at once; all identity waves frozen |
| Conditional Access or compliance block | Security owner |
| Booking or RoomList fault | Exchange owner |
| Recovery passing the window end | Service desk incident and facilities |

**Supervised rollback window.** Used only for identity-authority rollback. The change owner, identity engineer, security owner and Global Administrator are on the same call, and no other sync-scope change runs in the tenant meanwhile.

1. The security owner opens the window and records the start time.
2. The Global Administrator relaxes hard-match protection.
3. The identity engineer completes the account rollback steps in the cloud identity runbook.
4. The Global Administrator restores the value recorded at setup and confirms it, whether or not the takeover succeeded.
5. The security owner records the end time and final value, and closes the window.

```powershell
Connect-MgGraph -Scopes 'OnPremDirectorySynchronization.ReadWrite.All'
$s = Get-MgDirectoryOnPremiseSynchronization
# step 2: relax
$s.Features.BlockCloudObjectTakeoverThroughHardMatchEnabled = $false
Update-MgDirectoryOnPremiseSynchronization -OnPremisesDirectorySynchronizationId $s.Id -Features $s.Features
# step 4: restore the recorded value, then confirm
$s.Features.BlockCloudObjectTakeoverThroughHardMatchEnabled = $true
Update-MgDirectoryOnPremiseSynchronization -OnPremisesDirectorySynchronizationId $s.Id -Features $s.Features
(Get-MgDirectoryOnPremiseSynchronization).Features.BlockCloudObjectTakeoverThroughHardMatchEnabled
```

## Communications templates

Four messages cover every wave; replace each bracketed field before sending.

**Wave notice**, to room users and organisers, five working days before

```text
Subject: Meeting room maintenance on [date]: [room names]

The rooms below are reserved for maintenance on [date] from [start] to [end]:
[room list]

The rooms cannot be used during this time. Meetings booked in that window have been moved to [alternative rooms].

After the work, each room's Teams account leaves the meeting chat when a meeting ends and no longer has access to files or recordings shared in that meeting. Your own access is unchanged.

Questions: [service desk contact], quoting [change reference].
```

**Service desk briefing**, internal, two working days before

```text
Subject: Teams Rooms change [change reference]: [date]

Rooms: [room list]
Window: [date], [start] to [end]
Expected after the change: rooms sign in automatically after restarts; room accounts leave meeting chats after meetings.
Route to the room engineer on call ([contact]) if a room shows a sign-in screen, panels show wrong availability, or a booking fails.
Do not sign out, reset or re-enrol a room device.
```

**Back in service**, to the same audience as the notice

```text
Subject: Meeting rooms back in service: [room names]

Maintenance on [room names] finished at [time]. All rooms passed testing and are available to book.

If anything does not work as expected, contact [service desk contact] quoting [change reference].
```

**Overrun**, sent as soon as the change owner declares it

```text
Subject: Meeting room maintenance extended: [room name]

Work on [room name] is taking longer than planned. The room stays unavailable until [time].

Please use [alternative room] until then. Facilities will contact organisers with affected bookings directly.

Updates: [service desk contact], quoting [change reference].
```

## Closure and handover

The project closes when every item below is ticked and the change owner records closure in the change record.

- [ ] Every register row shows passwordless, cloud authority and AD independence accepted, or a CAB-approved exception.
- [ ] Hard-match protection confirmed at the value recorded during setup.
- [ ] Listed AD objects retired, and every room retested afterwards.
- [ ] Paused Android versions resumed; no project pause left in Pro Management.
- [ ] Project role eligibility removed, administrative unit scope reviewed, and Graph consents removed where no longer needed.
- [ ] Operations accept the cloud password reset and device recovery procedure, including replacement devices: password set-up first, then conversion.
- [ ] Operations accept RoomList membership changes in Exchange Online, plus licence and Conditional Access monitoring for room accounts.
- [ ] Spare devices and recovery media returned to stock, with their state recorded.
- [ ] Authentication incidents and site visits compared with the pre-change baseline, and the result filed in 06-Closure.
- [ ] Evidence folder access reduced to the retention owner under the organisation's retention policy.

## Quick reference

The locations, calls and numbers used most often during the project.

| Task | Where or how |
| --- | --- |
| Convert an account | Pro Management: Planning > Resource Accounts > Migration > Schedule migration |
| Scramble a cloud-managed password | Pro Management: Planning > Resource Accounts > Migration > Cleanup password |
| Apply Set as Resource on its own | Pro Management: Planning > Resource Accounts > select accounts > Set as Resource |
| Pause one Android version | Pro Management: Updates > Update management > Android updates > select the version |
| Read authority state | `GET /v1.0/users/{id}/onPremisesSyncBehavior?$select=isCloudManaged` |
| Transfer authority | `PATCH /v1.0/users/{id}/onPremisesSyncBehavior` with `isCloudManaged: true` (groups use `/groups/{id}/`) |
| Audit activities | *Change Source of Authority from AD to cloud*; *Undo changes to Source of Authority from AD DS to cloud* |
| Run a delta sync | `Start-ADSyncSyncCycle -PolicyType Delta` |
| Windows join state | `dsregcmd /status` on the room PC |

| Item | Value |
| --- | --- |
| Estate | 50 rooms: 35 local Android, 10 remote Android, 5 local Windows |
| Pilot | 4 rooms: 2 local Android, 1 remote Android, 1 local Windows |
| Production waves | 3 of 11 local Android, 3 of 3 remote Android, 2 of 2 Windows |
| Passwordless pilot hold | 24 hours before cleanup, 5 accepted business days after |
| Production wave acceptance | 1 business day of normal use |
| Identity pilot hold | 5 accepted business days |
| Retention before AD retirement | 30 calendar days after the final identity wave |
| Android auto-update window | 00:00 to 05:00 device-local time |
| Tenant-wide Android pause | 2 weeks |
| Connect Sync deadline | 2.6.84.0 or later with application-based authentication by 7 April 2027 |
