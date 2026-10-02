# Teams Rooms Passwordless and Cloud Identity Change

## Change Advisory Board approval submission

Prepared 1 October 2026 | Version 1.1 | CAB decision pending

## Approval requested

We request conditional approval for one project to adopt passwordless authentication on the mixed Android and Windows Teams Rooms estate, transfer the existing room and panel resource identities and their assessed group dependencies to cloud management, and retire the related AD objects after acceptance and the rollback period. The existing Exchange Online mailboxes, room addresses, calendars, bookings and device associations must be preserved. Windows device preparation and recovery have separate release gates.

The corrected planning baseline is **50 rooms comprising 45 Android rooms and 5 Windows rooms**. All five Windows rooms are local: the site split is 35 local Android, 10 remote Android and 5 local Windows, retaining the total of 40 local and 10 remote rooms. The Android planning configuration includes Logitech Rally Bar, Tap IP controllers and Tap Scheduler panels; discover the Windows compute manufacturer, model, peripherals and join state separately. The approved object manifest must distinguish rooms, platforms, unique resource accounts, physical endpoints, RoomLists and policy or licensing groups. Shared-account panels follow their room account, including panels paired with Windows rooms; standalone panels add separately inventoried identities. Installed state requires discovery before implementation.

**Recommended classification:** planned normal change, with a High initial risk rating because it combines authentication, group authority and user authority changes across production rooms. CAB should set the final rating using the organisation's risk matrix. Conditional approval must not be recorded as evidence that readiness or pilot tests have passed.

| CAB decision item | Requested authority and conditions |
| --- | --- |
| One project approval | Approve the bounded scope, phased implementation, acceptance criteria and recovery procedures in this document |
| Phase releases | Delegate go or no go decisions to the change owner with the relevant service owners, after evidence satisfies each gate; record releases against the same change record |
| Security behaviour | Accept automatic resource-account classification and resulting post-meeting access restrictions; approve per-account password cleanup only after all associated endpoints pass |
| Exceptional recovery | Explicitly authorise the supervised, temporary tenant hard-match protection change required for User SOA rollback, subject to security-owner control and restoration |
| AD retirement | Authorise only manifest-listed objects and reviewed retirement actions, after dependencies are cleared and the 30-calendar-day retention period closes |

Names, change references, scheduled windows, approvers and the CAB decision are held in the associated change record. No tenant or device changes have been performed. The readiness and pilot results are evidence required for phase release, not completed findings.

## Purpose and expected outcome

Passwordless adoption is intended to reduce routine room sign-in interruptions caused by reusable password expiry or rotation. Cloud identity management will move the approved accounts and dependencies away from AD administration while retaining the working room service. These benefits will be measured against a pre-change incident baseline; no quantified saving is claimed.

Delivery requires coordinated room, identity, Exchange, security, Intune and service-desk effort, with local or remote site cover and suitable recovery equipment. Confirm licence availability, spare-device needs and any supplier support costs in the change record. Any additional procurement or licence cost needs the organisation's commercial approval before the affected phase is released.

| Current planning state | Intended state |
| --- | --- |
| Resource identities synchronised from AD; RoomLists administered on premises; mailboxes already in Exchange Online | Existing approved identities and assessed RoomLists managed in the cloud; mailbox identities and booking behaviour preserved |
| Password-based sign-in and current authoritative password recovery | Android Keystore and Windows TPM device-bound credentials, with platform-specific temporary-password bootstrap and recovery |
| AD references and provisioning dependencies may remain | Each retained dependency resolved before the relevant AD object is retired |

User Source of Authority (SOA) transfer changes identity authority in place. Exchange-only IsExchangeCloudManaged does not make an account cloud-only. A cloud-managed account can retain an AD object for references and rollback; final AD independence is a separate acceptance milestone within this project. [1][2][3]

## Scope and service impact

### Work included in this approval

- Read-only discovery, evidence capture and reconciliation of the approved room estate and complete account-to-endpoint mappings.
- Supported, room-scoped software, management and Windows Entra-join preparation where the exact versions, join actions, policy or profile changes and targets are recorded and reviewed before release. Discover existing join state first; account SOA does not migrate a Windows computer or replace its GPO, certificates or network dependencies.
- Passwordless conversion in Teams Rooms Pro Management, expected Set as Resource behaviour, per-account acceptance and password cleanup.
- In-place Group SOA for assessed RoomLists and dedicated groups, followed by in-place User SOA for the approved room and panel identities.
- Testing, communications, supervised recovery, observation, operational handover and gated retirement of the listed AD objects.

The complete membership, assignments and downstream use of every group form part of its blast radius. Converting a RoomList or shared group affects the entire group, including any rooms or users outside the four-room pilot. Such effects must be explicitly assessed and approved in the manifest; a pilot account count does not bound a group change.

### Changes requiring scope reassessment

This approval does not authorise tenant-wide sync shutdown, AD or Exchange infrastructure retirement, mailbox moves, federation/domain conversion, broad human-user policy changes, Security Defaults changes, tenant-wide compliance defaults, adoption of irreversible update rings, or changes to shared groups whose wider impact has not been assessed. Required sync-engine upgrades or Exchange remediation must be approved dependencies. RoomList replacement or SMTP cutover also requires an assessed amendment before execution. Windows computer objects are not included in routine resource-user/group AD retirement; any computer-object action requires a separately assessed dependency design and explicit manifest approval.

### Expected user impact

Reserve each changing room and all its panels for the approved maintenance window. Authentication transitions, restarts and functional testing can temporarily interrupt room use. Windows conversion also moves Windows sign-in from the local Skype account to the resource account and transfers Teams Rooms app settings; returning from admin mode then requires a PC reboot. Windows password-authentication backout requires device reset and recovery media and can take longer than Android sign-out/bootstrap. No zero-outage, fixed conversion duration or recovery time is promised. Release a room only after its calendar, meeting, peripheral, panel, security and management tests pass. Existing bookings and mailbox contents must remain intact. [2]

Passwordless conversion automatically applies Set as Resource: after a meeting ends, the room account leaves the meeting chat and loses access to shared files and recordings. Room users and service owners must accept this change, particularly where workflows relied on the room identity's continued access. SOA rollback or password sign-in recovery must not be described as reversing this classification. [2][4]

Shared-account room panels retain the room's Teams Rooms Pro entitlement. Standalone panels using passwordless require the appropriate Teams Shared Space licence. Remote recovery may require physical UI access and verification-code entry; management connectivity alone is insufficient recovery coverage. [2]

## Preconditions and release governance

The change owner records each release with the relevant identity, Exchange, Teams, security, Intune and site owners. A failed prerequisite holds the phase. Material changes to scope, recovery or security controls return for CAB reassessment; successful phase releases within the approved design remain under this project approval.

### Gate 0 Before any production implementation

1. Attach the reconciled object manifest with exact account, device, RoomList and group IDs, complete group memberships and assignments, site dependencies, and applicable software and configuration diffs. Confirm the correct tenant and cloud. Retain baseline exports in the restricted change-evidence location.
2. Record Entra IDs, UPN/SMTP aliases, ExchangeGuid, RoomMailbox type, calendar processing and permissions, delegates, Places, RoomList properties and bookings. Capture AD GUID/SID, source anchors, ImmutableId, OU and the AD remote-recipient representation separately for recovery.
3. Validate supported firmware and Microsoft applications, PMP visibility and eligibility, network access, effective CA and platform-specific compliance. Use AOSP requirements for Android endpoints and the Windows Rooms requirements for Windows PCs; attached Android panels retain their own checks. Room-scoped policy work must use exact IDs and effective targeting, including all-user policy overlap. Do not infer safe pilot coverage from a group name. [16]
4. Confirm working local and remote recovery, secret handling, current password authority, licence service plans, support cover and sufficient enrolment headroom. Do not delete active Entra or Intune device objects to tidy inventory.
5. Recheck supported sync builds on active and staging/failover systems and record the owning engine. The checked 1 October release snapshot is Connect Sync 2.6.92.0 and, where applicable, Cloud Sync agent 1.1.2505.0. The retired SOA minimum is not a deployment baseline. [5][6]
6. Before the initial pilot, establish support coverage, a recovery rehearsal and an interruption/recovery estimate sufficient for its reserved window. Before scaling, replace estimates with measured pilot timings. Each window must include validation and recovery margin before the next booking. Record the latest backout decision point as the window or booking deadline minus the tested recovery duration and agreed safety margin.

Android automatic updates use the fixed 00:00 to 05:00 device-local window, and mandatory management-agent updates cannot be paused. Account for coincident updates, check offered packages and record live versions at each change window. Software, AOSP and policy preparation must settle before the authentication or authority transition. [15]

### Windows eligibility and recovery gate

For each of the five local Windows rooms, record the compute OEM/model, supported Windows Enterprise or IoT Enterprise edition and build, Teams Rooms app, TPM and actual Entra/domain/hybrid join state. Microsoft's documented passwordless floor is Windows 11 24H2 build 26100.8655 or later and Teams Rooms app 5.6.135.0. The PC must be Entra joined to the resource-account tenant; hybrid join is unsupported. Use a currently supported offered OS/app combination, and verify passwordless eligibility for any later Windows release before scheduling. Do not downgrade a supported PC merely to match the published prerequisite example. Windows updates have their own supported delivery and maintenance controls; the Android 00:00 to 05:00 window does not apply. [2][17][18]

The current passwordless guidance excludes proxy-configured Windows PCs and Crestron Windows devices. Hold any affected room; an agent proxy workaround does not establish migration support. Before clearing the gate, recheck current official guidance or obtain an applicable supported resolution. Any domain/hybrid-join remediation must first replace required GPO, management, certificate, network and administrative-access dependencies under reviewed room-specific changes. Do not broaden device-join permissions to all users as a default preparation step. [2][17]

Validate Windows Intune enrolment and effective policies separately. Windows Rooms do not support Require MFA or authentication-strength grants, or Windows OS-version bounds, valid-build and password compliance policies. Use supported room controls; verify BitLocker is enabled before requiring it or encrypted storage. These restrictions also apply when a Windows room shares an account with an Android panel; evaluate the effective account and endpoint coverage together. [16]

Prove local administrative access, startup network availability, PMP operations under the new resource-account Windows profile, preserved application/peripheral configuration, and a tested OEM or Microsoft recovery route with available media and an approved configuration baseline. Record the Windows reset/rebuild interruption separately from Android bootstrap. An ineligible Windows room remains an open project item; partial delivery needs a CAB scope amendment before the full project outcome can be declared. [2][19]

### Gate 1 Before cloud authority changes

1. Complete passwordless acceptance and password cleanup across the approved project scope, with every shared-account endpoint accounted for. Observe the passwordless pilot for at least 24 hours before cleanup and five business days of stable operation after post-cleanup checks. These are proposed operational intervals. [2]
2. Confirm Microsoft's environment-wide User SOA prerequisites: all hybrid mailboxes in Exchange Online, no on-premises Exchange workloads, and the applicable preparation requirements satisfied. The earlier all-Exchange-Online planning assumption requires evidence; room mailboxes alone do not prove readiness. [7][8]
3. Confirm account eligibility and stop conflicting AD attribute writers. AD FS-federated users and on-premises password-dependent applications block User SOA. Third-party federation can retain AD/password dependencies; hold those accounts until a supported cloud authentication and recovery design exists. [8]
4. Validate the cloud reset/recovery design and privileges before SOA, using a suitable cloud-managed test identity where needed. Prove recovery for the actual transferred pilot accounts after SOA and before scaling. Do not assume PHS exists or the current AD password provides cloud recovery after PTA-based sign-in. Avoid forced password-change or interactive registration prompts for resource accounts. [9]
5. Validate the supported SOA API/tooling route. Microsoft's dedicated configuration guides show v1.0 while the linked method reference currently renders beta documentation. Resolve the discrepancy for the implementation route; do not substitute an unvalidated API or delete/restore procedure. [1][10]
6. Confirm forward permissions and the broader rollback prerequisites, including the directory-sync configuration ID, original hard-match protection setting, delegated Global Administrator availability and a bounded supervised recovery window.

## Implementation and phase release plan

Read-only discovery and dependency design can run in parallel with passwordless delivery. Production authority changes follow acceptance of the passwordless scope. Do not apply passwordless, group SOA and user SOA simultaneously to an account or its dependencies.

| Phase | Implementation and evidence required to advance |
| --- | --- |
| 0 Readiness | Complete Gate 0 and record the reviewed target and configuration manifest. Stabilise required software, management and security preparation |
| 1 Passwordless pilot | Convert two local Android rooms, one remote Android room and one eligible local Windows room through PMP. Include a shared-account scheduler and representative site/security patterns; add a standalone-panel identity if its account/licensing design differs. Validate all endpoints, observe, clean up at the current password authority, restart and retest. Complete five accepted business days after cleanup |
| 2 Passwordless production | Convert the remaining 33 local Android rooms in three waves of 11, the 9 remote Android rooms in three waves of 3, and the 4 local Windows rooms in two waves of 2. Keep Windows preparation, testing and recovery separate. Accept the previous wave through normal use before advancing; apply cleanup only after every endpoint sharing an account passes |
| 3 RoomLists and groups | After Gate 1, pilot a low-risk, fully assessed RoomList; convert approved dependent groups from the lowest nested level upward. Verify type, identity, addresses, owners, all memberships, discovery, licensing and policy coverage before cloud user changes |
| 4 User SOA pilot | Transfer the same four pilot room identities and any distinct standalone-panel pilot in place. Verify isCloudManaged=true, documented onPremisesSyncEnabled=null, authority-change audit and completed sync evidence. Prove unchanged identifiers, Android and Windows credential continuity and cloud bootstrap recovery, then observe five accepted business days |
| 5 User SOA production | Repeat the Android local 11/11/11, Android remote 3/3/3 and Windows local 2/2 pattern against the exact approved IDs. Separate panel accounts follow equivalent gates. Validate and clean up at the proven cloud password authority; keep AD references and sync scope while required |
| 6 AD retirement and closure | Retain AD objects, matching evidence and required sync scope for 30 calendar days after the final accepted SOA wave. Clear all dependencies, close authority rollback, review the exact retirement action per object, retire only listed objects, verify continued room service and hand over |

The waves total 50 rooms: four pilot rooms plus 33 remaining local Android, nine remaining remote Android and four remaining local Windows rooms. Unique account and endpoint counts may differ. Reorder by site or RoomList dependencies without increasing the approved blast radius. Treat each account and its associated endpoints as one acceptance unit. The pilot sizes and wave counts are proposed operating choices, not Microsoft requirements.

Allow approximately **8 to 10 working weeks after readiness** for both staged deployments and group work, followed by the proposed 30-calendar-day retention period before AD retirement. This revised planning allowance includes two separate Windows production waves in each deployment and assumes all five PCs have cleared the preparation gate. Actual windows are held in the change record. Additional panel identities, extensive group dependencies, failed tests or Windows join, software or recovery remediation extend this allowance. Pilot measurements determine implementation and recovery durations.

Group SOA documentation covers distribution groups generally but does not explicitly guarantee RoomList subtype preservation. Passwordless credential continuity through User SOA is also an expectation requiring pilot evidence. Failure of either test stops expansion. Converted mail-enabled groups are administered through Exchange Online tools. [1][2][10]

## Validation and acceptance

| Test area | Required evidence at account or wave exit |
| --- | --- |
| Authentication | Successful PMP conversion; restart without password before and after cleanup; fresh sign-in or token-refresh evidence without unexplained errors; after SOA, verified authority state and audit |
| Identity and mailbox | Unchanged Entra ID, ExchangeGuid, RoomMailbox type, UPN, addresses, device associations and required licence service plans; no duplicate or unexpected deleted object |
| Meeting experience | Scheduled meeting and Meet Now join; camera, microphone, speakers, controller, content ingest and deployed peripherals; representative external invitation |
| Calendar and discovery | New/direct booking, recurring invitation update, acceptance/delegate handling, calendar refresh, Room Finder/Places and each panel's availability/reservation display |
| Security and management | Expected CA coverage and exclusions, compliance and Intune targeting, active device mapping and PMP connectivity; accepted post-meeting resource-account restrictions |
| Windows operation | Same-tenant Entra join and required build/app eligibility; TPM-bound credential; automatic sign-in after reboot and return from admin mode; startup network, PMP agent operations and retained app/peripheral settings; associated Android panel tests |
| Group dependencies | Complete before/after membership and assignment comparison; RoomList subtype, owners, SMTP addresses and discovery; non-pilot members also checked |
| Recovery | Authorised temporary-password issuance at the current authority; tested bootstrap, management restoration, conversion and cleanup on a supported spare or scheduled recovery test for the room |
| Final independence | No required AD group, authentication, application, provisioning or Exchange dependency; retirement manifest/action reviewed and continued service verified |

No unresolved change-related service, identity, licensing or security defect may pass a wave gate. Any exception requires its scope, service condition, compensating control, owner and expiry in the change record. An exception that prevents the target outcome remains an open project item; a synced/passwordless room must not be reported as fully cloud-independent.

Stop the remaining account or wave for any unexplained sign-out, booking failure, failed conversion, lost membership/licence, policy or compliance failure, unexpected deletion, subtype change, broader-than-approved targeting or unavailable recovery. Preserve logs and the last proven state, notify the change owner and invoke the organisation's incident process. Resume only after recovery tests pass and the release decision is recorded. These are manual checkpoints, not an automatic rollout controller.

## Risk assessment and controls

| Material risk | Control and remaining exposure |
| --- | --- |
| Room or panel loses authentication | Prove recovery and support cover; preserve device identities; accept every shared-account endpoint before cleanup. Sign-out/reset can still require attended bootstrap |
| Windows preparation or reset extends outage | Clear OEM, proxy, build/app and Entra-join eligibility first; assess GPO/certificate/network dependencies; test available recovery media and rebuild timing, with local support and spare capacity |
| Booking or mailbox disruption | Export complete recipient/calendar evidence and compare after each transition. Preserve the same mailbox and address; stop on any identity or booking regression |
| RoomList or shared-group impact exceeds pilot | Assess all members and assignments before change. Preserve subtype and discovery in a group pilot; unassessed shared-group impact is a scope change |
| Licence or policy targeting changes | Verify effective assignments, dynamic rules and all-user policy overlap. When replacing assignments, prove the destination before removing the source |
| Credential does not survive User SOA | Require reboot, fresh authentication and normal-use pilot evidence. Retain temporary-password recovery at the proven authority; continuity is not assumed from a successful API response |
| Cloud recovery retains an AD dependency | Validate PHS/PTA/federation route and cloud bootstrap. Block final AD retirement while a provider, password, application or reference still depends on AD |
| Authority rollback widens tenant exposure | Supervise the temporary hard-match protection change with delegated GA and security oversight, monitor unrelated matching and restore protection immediately after takeover |
| AD retirement removes references or prevents rollback | Retain objects/anchors through 30-day retention, reconcile dependencies and formally close rollback. After deletion, do not promise the original authority rollback remains available |
| Post-meeting access change affects a workflow | Obtain service-owner acceptance of Set as Resource restrictions before conversion; sign-out and SOA reversal are not a validated inverse for this behaviour |
| Remote recovery or updates extend the window | Prove physical/UI support and recovery duration, check update activity and hold sufficient time before bookings. Remote sign-in remains an individual operation |

The remaining risk is production service interruption or supervised recovery despite the controls. CAB acceptance does not waive product prerequisites. Scope containment and demonstrated recovery must be reviewed before the initial risk rating is reduced.

## Backout and recovery plan

### Decision and timing

The change owner, with affected service and security owners, chooses restoration of the failing dependency, endpoint bootstrap or authority rollback. Start recovery when a stop condition cannot be resolved within the recorded margin. If recovery may overrun the window, declare the impact through the incident process and arrange alternative meeting facilities where available. Do not wait until the next booking to decide.

### Passwordless recovery

Before cleanup, preserve the existing bootstrap route. A failed migration may automatically revert, but inspect the actual job and endpoint state before relying on it. Restore the failing network, policy, software or management dependency first. [2]

For Android rooms and panels, full account sign-out removes the credential and enables password bootstrap. For Windows rooms, reverting to password authentication requires a device reset using the manufacturer's recovery image or Microsoft's recovery tool. Do not apply the Android remote-sign-out backout instruction to Windows. Preserve configuration evidence and confirm media, local access and the rebuild margin before approving a Windows conversion. [2][19]

After credential loss, reset, reimage or replacement, issue a temporary password at the authoritative source, bootstrap the endpoint, restore management/compliance and platform prerequisites, validate, reconvert and clean up only after account-wide acceptance. Returning to password sign-in is a temporary service recovery state; it does not recreate the lost credential or establish reversal of Set as Resource. Use the approved secret-handling process and keep passwords out of logs and CAB evidence. [2][4]

Changing the password does not revoke an accepted device-bound credential. Any security containment must identify the exact active device and use the approved disruptive procedure; routine device-record deletion is excluded. Deleting a Windows device's Entra record breaks its Entra join as well as invalidating its credential, so containment must include the Windows join and recovery consequences. [2]

### User authority rollback

Preserve and reconcile cloud edits into the retained AD record, maintain the original matching anchor and resolve unsupported cloud references. Under the approved supervised window, temporarily permit hard-match takeover through blockCloudObjectTakeoverThroughHardMatchEnabled, reverse the affected user's SOA setting to AD, and let the owning sync engine take over the retained in-scope object. Verify matching, completed sync, authority, audit and room service, then restore hard-match protection promptly. A setting change alone is not completed recovery. [1]

The tenant protection operation requires delegated Global Administrator with OnPremDirectorySynchronization.ReadWrite.All; application permission is unsupported. Forward SOA permissions are insufficient. Record the configuration ID, baseline setting, start/end, matching events and final protection state. Respect any intentional baseline exception through the recorded security decision. At the approved window's end, restore the recorded protection posture even if takeover is incomplete, unless a security-authorised extension within CAB-approved limits is recorded. Verify the final setting on both success and failure, escalate incomplete recovery and suspend unrelated matching changes. [11]

### Group rollback and final retirement limits

Resolve cloud-member and access-package references, reconcile cloud edits into the retained AD group, reverse its SOA setting and complete sync takeover and verification. Where cloud-managed rooms prevent a RoomList rollback, restore their AD authority and valid membership first. Do not remove members indiscriminately to satisfy a rollback constraint and break discovery, licensing or policy coverage. Mail-enabled membership remediation uses Exchange tools. [10]

AD retirement remains inside this project but requires its own recorded phase release. Select and review the exact action per object; disablement, scope removal and deletion have different effects. Retained AD-managed references block retirement. Do not clear source anchors/ImmutableId, recreate accounts, invoke Remove-RemoteMailbox or Disable-RemoteMailbox, purge recipients or disable tenant sync as housekeeping. These are not default conversion/backout steps. [12][13][14]

## Ownership communications and closure

| Responsibility | Required role or operational owner |
| --- | --- |
| CAB scope and risk acceptance | CAB and service owner; record the decision and conditions in the change system |
| Phase coordination and release | Change owner named in the change record, with relevant service-owner sign-off |
| Passwordless conversion and room testing | Teams Administrator for migration, room engineer and site support |
| Password cleanup and bootstrap | Correct authority and scoped reset rights; User Administrator for the built-in cleanup where sufficient |
| User and group authority | Hybrid Identity Administrator and the dedicated User/Group-OnPremisesSyncBehavior.ReadWrite.All permissions; use suitable AU scope where supported |
| RoomLists and mailbox evidence | Exchange owner with the required Exchange administration/read permissions |
| Security and management | Security and Intune owners for effective policy, compliance, evidence and exception review |
| Exceptional User SOA rollback | Security-supervised delegated Global Administrator access for the tenant protection operation |
| Incident handling and availability | Service desk, room engineer and local/remote site contacts |

Use time-bound elevation where available. The dedicated SOA read endpoint itself needs a ReadWrite-named permission; do not expand a routine read-only inventory to broad write privileges without a reviewed reason. [1][10][11]

Before each wave, notify service desk, facilities/site contacts and affected room users of the exact rooms, maintenance restrictions, support route and expected resource-account behaviour. At window start, confirm no active meetings and that room use is held. Publish verified availability at completion, or communicate an overrun and alternative arrangements. Review incidents and evidence daily during rollout.

Keep the manifest, before/after exports, migration jobs, sync/audit evidence, test results, incident links, phase releases and recovery records in the restricted evidence location referenced by the change record. Apply the organisation's retention policy; record no passwords or tokens.

Close only when all approved accounts and endpoints are accepted, required cloud authority and AD independence are proven, dependencies and retirement actions are complete, protection settings are verified, and service owners accept handover. Hand over cloud identity/Exchange administration, RoomList membership, licence/policy monitoring and tested replacement-device recovery. Measure authentication incidents and site visits against the baseline and review any regressions.

## Supporting documents and primary sources

The detailed passwordless runbook, cloud identity migration plan and read-only inventory script accompany this submission in the project evidence package. The inventory script has been statically reviewed but has not been executed against the tenant; it does not establish effective CA, Intune, PMP or SOA readiness or discover Windows OEM, build, join state, TPM or passwordless eligibility. Capture those fields in the reconciled manifest.

- [1] [Configure and roll back User SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure)
- [2] [Teams device passwordless migration and recovery](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts)
- [3] [Exchange attribute cloud management](https://learn.microsoft.com/en-us/exchange/hybrid-deployment/enable-exchange-attributes-cloud-management)
- [4] [Set as Resource behaviour](https://learn.microsoft.com/en-us/microsoftteams/rooms/set-as-resource-account-for-shared-teams-devices)
- [5] [Connect version history](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history)
- [6] [Cloud Sync version history](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/reference-version-history)
- [7] [Prepare the User SOA environment](https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment)
- [8] [User SOA prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview)
- [9] [Pass through authentication behaviour](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-how-it-works)
- [10] [Configure and roll back Group SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure)
- [11] [Directory sync protection API and permissions](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-update?view=graph-rest-1.0)
- [12] [User SOA operational guidance](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance)
- [13] [Remove RemoteMailbox](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/remove-remotemailbox)
- [14] [Disable RemoteMailbox](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/disable-remotemailbox)
- [15] [Android update management in Pro Management](https://learn.microsoft.com/en-us/microsoftteams/rooms/androidupdatemanagementinpmp)
- [16] [Supported Conditional Access and compliance policies](https://learn.microsoft.com/en-us/microsoftteams/rooms/supported-ca-and-compliance-policies)
- [17] [Entra join for Teams Rooms on Windows](https://learn.microsoft.com/en-us/microsoftteams/rooms/mtrw-entraid-join)
- [18] [Teams Rooms Windows lifecycle and support](https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-lifecycle-support)
- [19] [Teams Rooms Windows recovery tool](https://learn.microsoft.com/en-us/microsoftteams/rooms/recovery-tool)

[1]: https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure
[2]: https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts
[3]: https://learn.microsoft.com/en-us/exchange/hybrid-deployment/enable-exchange-attributes-cloud-management
[4]: https://learn.microsoft.com/en-us/microsoftteams/rooms/set-as-resource-account-for-shared-teams-devices
[5]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history
[6]: https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/reference-version-history
[7]: https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment
[8]: https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview
[9]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-how-it-works
[10]: https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure
[11]: https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-update?view=graph-rest-1.0
[12]: https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance
[13]: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/remove-remotemailbox
[14]: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/disable-remotemailbox
[15]: https://learn.microsoft.com/en-us/microsoftteams/rooms/androidupdatemanagementinpmp
[16]: https://learn.microsoft.com/en-us/microsoftteams/rooms/supported-ca-and-compliance-policies
[17]: https://learn.microsoft.com/en-us/microsoftteams/rooms/mtrw-entraid-join
[18]: https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-lifecycle-support
[19]: https://learn.microsoft.com/en-us/microsoftteams/rooms/recovery-tool
