# Teams Rooms Cloud Identity Migration Plan

## Follow on migration after Android and Windows passwordless deployment

Version 1.1 | Verified against Microsoft documentation on 1 October 2026

## Recommended approach

Complete and stabilise the Teams Rooms passwordless deployment, then transfer the existing room and standalone panel accounts from AD authority to Microsoft Entra cloud authority using Microsoft's per-object Source of Authority (SOA) process. Preserve their existing identities, Exchange Online mailboxes, booking addresses and device associations. Microsoft announced User SOA general availability in January 2026. [1][2]

This plan is the cloud-authority and AD-retirement phase of the same project approval as passwordless delivery. Read-only discovery and dependency design can run in parallel with that delivery; production authority changes follow full passwordless acceptance, assessed RoomList/group preparation, a mixed-platform account pilot and staged account rollout. AD retirement has a later recorded phase release within the same approval. Administrative fields, windows and release decisions are held in the associated change record. Keep Entra Connect or Cloud Sync running for identities outside this project.

The user-confirmed scope is 50 rooms: 35 local Android, 10 remote Android and 5 local Windows rooms, plus separately inventoried panel identities included in the assessed manifest. Count unique accounts as well as rooms: panels sharing a room account follow that account's acceptance gate, including Android panels used with a Windows room. Windows OEM/model, device-join, management and recovery state require discovery. Earlier planning recorded all mailboxes in Exchange Online, Entra Connect Sync, and RoomLists managed on premises. Reconfirm those inputs before scheduling. This plan contains no mailbox moves on that basis.

Preserve the appropriate licence for each account: Teams Rooms Pro for rooms and their shared-account panels, and Teams Shared Space for separate standalone panel accounts using passwordless. [3]

The outcome has two milestones. **Cloud authority** means Entra owns the resource account while a retained AD object may still support references or rollback. **AD independence** means the account, authentication, licensing, policy targeting and room discovery no longer need the AD object. For Windows, resource-account User SOA does not migrate the PC/computer identity, change device join or remove GPO, certificate, network or administrative dependencies. Assess those separately before claiming the room is independent of AD. This project does not retire AD, sync infrastructure or Exchange hybrid for the entire organisation. [23]

Exchange attribute management via IsExchangeCloudManaged is a separate capability that leaves identity authority synchronized. It can be assessed as an interim option, but it does not meet this plan's cloud-only identity outcome. [22]

## Phase 1 Establish the baseline and pass the eligibility gates

### Finish the passwordless phase first

Accept every Android and Windows room and panel endpoint using each account, complete the agreed password cleanup at its current authority, and record successful restart, calendar, meeting join and Pro Management checks. The passwordless pilot comprises two local Android rooms, one remote Android room and one local Windows room. Observe it for at least 24 hours before cleanup and five accepted business days after post-cleanup validation. Keep platform software, Android AOSP and Windows join/enrolment preparation, Conditional Access and update-ring changes outside the SOA maintenance windows.

Microsoft supports passwordless on both platforms, using Android Keystore and the Windows TPM, and documents credential survival after a normal reboot or password change. It does not explicitly guarantee survival through a User SOA transfer in the material reviewed. Preserving the account and device identities makes continuity the expected outcome; Android and Windows must each pass the combined transition pilot. Android sign-out can remove the credential; Windows password-authentication backout requires an OEM-image or Microsoft recovery-tool reset. Reset/reimage/replacement requires temporary-password bootstrap and conversion again. [3][24]

Before promising completion of all five Windows rooms, prove their specific passwordless eligibility: the dedicated article requires Windows 11 24H2 build 26100.8655 or later, Teams Rooms app 5.6.135.0 or later and Entra join to the resource account's tenant; hybrid join, proxy-configured Windows devices and Crestron Windows devices are currently unsupported. Windows 25H2 lifecycle support alone does not prove eligibility for this particular passwordless workflow. Hold blocked accounts and their shared-account cleanup. Complete the approved passwordless scope before authority changes, or obtain a recorded CAB scope amendment before accepting a partial scope; Windows rooms do not receive an automatic password-based exception. [3][23]

### Collect a per account and per group baseline

Maintain a secured migration register with one row per unique account and related rows for its endpoints and dependent groups. Record failed or incomplete queries as unknowns. Do not interpret missing permissions as missing objects.

| Area | Evidence to preserve |
| --- | --- |
| Identity and matching | Entra object ID, UPN, current SOA, sync state, AD object GUID and SID, sourceAnchor and onPremisesImmutableId, OU and owning sync engine |
| Mailbox and booking | ExchangeGuid, ExternalDirectoryObjectId, RoomMailbox type, primary SMTP and aliases including X500, calendar processing, delegates, permissions, bookings, archive state and Places properties |
| AD Exchange representation | Actual remote-recipient type, RemoteRecipientType, ExchangeGuid, target address and Exchange attributes needed for reconciliation; a RemoteRoomMailbox in AD can represent the existing cloud RoomMailbox |
| Room discovery | Every RoomList ID, RoomList recipient subtype, addresses, owners, members, visibility and Room Finder results |
| Licensing and policies | Direct and inherited assignments, group IDs and memberships, effective room or standalone panel licence and required service plans, dynamic rules, CA coverage and exclusions, Intune targeting |
| Devices and recovery | Android/Windows room and panel mappings, actual OEM/model, Entra and Intune device IDs, Pro Management status, installed versions, platform passwordless acceptance, remote support and recovery owner; Windows build, TPM, device join and local admin/LAPS recovery |
| AD dependencies | PHS, PTA or federation route; AD applications, password dependencies, provisioning scripts, Exchange workflows, certificates and other attribute writers; Windows AD computer, GPO, network/certificate and management dependencies recorded separately from the resource user |

Protect exports as administrative evidence. Keep passwords and tokens out of the register. Reuse the read-only passwordless inventory as a starting point: its Exchange/Graph baseline and 50-room/40-local/10-remote defaults apply to both platforms, but it does not identify Windows hardware, OS/site distribution, TPM, join/domain, GPO/certificate dependencies, effective CA, Intune or PMP readiness. It is not a complete SOA or Exchange dependency collector.

### Required go or no go checks

1. Confirm tenant cloud, feature availability and the actual supported API route. Confirm accounts are currently synced, have no administrative roles and satisfy Microsoft's attribute and reference constraints. Stop conflicting AD provisioning or attribute writers and allow the final intended changes to sync. [4]
2. Confirm the Exchange readiness gate across the environment. Microsoft's preparation guidance requires all hybrid mailboxes in Exchange Online before switching SOA for any users; the overview requires no on-premises Exchange workloads. Block User SOA until those conditions and the applicable preparation requirements are satisfied. Room mailboxes being online alone does not prove this. Have the Exchange owner validate the supported state; sign-off cannot waive a Microsoft prerequisite. Keep hybrid decommissioning outside this room project. [4][5]
3. Identify the authentication route. AD FS-federated users are unsupported for User SOA. Third-party federation can retain AD and provider password dependencies; exclude those accounts from these cloud-authentication waves until a supported cloud sign-in and recovery path is proven. LDAP binds and password-based Kerberos dependencies are blockers until a supported replacement exists. Teams passwordless eligibility does not override these SOA constraints. [5]
4. Establish cloud-admin password reset and device bootstrap recovery. PTA does not apply to cloud-only users; PTA deployments may have no PHS-seeded cloud password. Do not assume the current AD password will provide cloud recovery after transfer. [6][7]
5. Use a current supported sync build. The checked release snapshot is Connect Sync **2.6.92.0** and, where Cloud Sync is actually used, provisioning agent **1.1.2505.0**. Recheck at execution time, including staging and failover servers. The old Connect feature floor 2.5.76.0 is retired; upgrade and stabilise infrastructure separately. Do not install overlapping sync engines for this project. [8][9]
6. Prepare forward and rollback privileges before scheduling. For delegated User SOA, use Hybrid Identity Administrator and User-OnPremisesSyncBehavior.ReadWrite.All, scoped to a suitable Administrative Unit where supported. Dedicated SOA reads also require that ReadWrite-named scope. Rollback's tenant directory-sync protection change needs separate delegated permission and Global Administrator access. Record its configuration ID and current protection setting before the pilot. [2][10]
7. Confirm platform-specific device and policy readiness. Windows passwordless uses an Entra-joined PC; resource-user SOA does not migrate its computer object or management. Any join/GPO/network-certificate transition must be a discovered and reviewed exact prerequisite change, not a default domain exit or reimage. Validate Windows compliance and the Android AOSP policy separately, including mixed-platform panels. The Teams Rooms matrix does not support Require MFA on Windows, authentication strength or hybrid-joined-device grants on either platform; Windows OS-bound/valid-build and password-compliance settings are unsupported. [3][23][25]

**Gate 1:** Identity, Exchange, Teams, security and device owners sign off the account list, full passwordless acceptance, dependencies, supported path, recovery and rollback window. If eligibility remains unresolved, retain the affected account and endpoints at their last proven authentication and identity state and hold authority changes. Any reduction of the approved 50-room outcome requires a recorded CAB scope amendment.

## Phase 2 Move or resolve RoomList and group dependencies

User SOA does not convert groups. Review RoomLists, licensing groups, CA groups, Intune groups and nested dependencies separately. Choose a cloud authority or replacement strategy only for groups whose full dependency scope has been assessed. A shared organisation-wide group containing rooms can widen this project substantially. [11][12]

For dedicated groups to be converted, start with the lowest nested dependency and work upwards before converting their room users. Preserve group IDs and assignments through the in-place path, then prove effective membership and licensing. Where replacing a licence group, add the destination assignment and verify processing before removing the old assignment. Review rules based on sync status or on-premises attributes. For policy groups, prove equivalent effective coverage and exclusions before changing membership. [12][13]

### Pilot an on premises RoomList

Select a low-risk RoomList with a manageable dependency scope. Export its type, addresses, owner and complete membership; account for every room in that list, including rooms outside the user pilot. Follow the supported Group SOA procedure using Hybrid Identity Administrator and Group-OnPremisesSyncBehavior.ReadWrite.All. After conversion, administer distribution-group mail properties and membership through Exchange Online tools. [11][12]

Microsoft covers distribution groups and mail-enabled security groups generally; the reviewed SOA guidance does not explicitly name the RoomList subtype. Treat RoomList compatibility as a pilot gate. Verify the same group identity, RecipientTypeDetails of RoomList, addresses, owners, members, visibility and working Room Finder discovery before continuing. Check Outlook and Teams booking, direct invitations and recurring meeting updates. [14]

If subtype or discovery preservation fails, hold the RoomList rollout and establish a supported alternative. A separately designed replacement can use a temporary unique address and a controlled address cutover after validation. Do not create duplicate SMTP addresses or delete the existing list as an exploratory step.

If an AD-managed group is retained, document the remaining dependency. Microsoft requires a converted user referenced by an AD-managed group to remain in sync scope; deleting its AD account can remove cloud group membership. That can affect licensing and policy coverage. Retaining such a reference is an interim state, not final AD independence. [15]

**Gate 2:** RoomList discovery and group-derived licensing and policies pass. Any retained AD dependencies have named owners and a resolution plan.

## Phase 3 Pilot four room accounts in place

Use the same accepted passwordless pilot cohort: two local Android rooms, one remote Android room and one local Windows room. Include a shared-account panel and cover the actual authentication, Windows join/OEM and group patterns found during discovery. Add a separate panel identity to the pilot if its design differs and it is included in the approved manifest. Schedule local hands or equivalent remote recovery coverage.

For each pilot account, freeze unrelated changes, confirm all associated endpoints are healthy, capture the baseline and check rollback access. Use the exported Entra object ID throughout. The documented transfer changes the existing user; it does not require replacing the mailbox or account. [2]

The dedicated Microsoft procedure documents this operation:

```http
PATCH https://graph.microsoft.com/v1.0/users/{objectId}/onPremisesSyncBehavior
Content-Type: application/json

{ "isCloudManaged": true }
```

This is the proposed change mechanism, not a command to execute from this document. The dedicated User and Group SOA guides show v1.0, while the linked Graph method reference currently renders beta documentation. Resolve that publication discrepancy for the exact tenant and tooling before executing the pilot; do not silently substitute beta or switch to deletion and restoration. [2][12][16]

Allow the owning sync engine to complete its relevant cycle. Confirm isCloudManaged is true, the authority-change audit event is present, and onPremisesSyncEnabled has the documented post-transfer value of null. Null by itself does not prove successful SOA conversion. Inspect sync evidence for blocked inbound authority, unexpected exports, deletions and errors. [2][17]

### Acceptance for each pilot account

1. Identity remains intact: the same Entra object ID, ExchangeGuid, RoomMailbox, UPN, SMTP aliases and device associations; no duplicate or soft-deleted replacement object.
2. Calendar and discovery pass: existing and new bookings, recurrence edits, delegate actions, Room Finder, Places, panel display, calendar refresh and meeting join.
3. Security and management pass: effective licence service plans, intended platform-specific CA coverage, compliant device state, Intune targeting and Pro Management connectivity and passwordless status. Review fresh sign-in and token-refresh evidence rather than relying only on a cached session. On Windows, also preserve the PC join, TPM, settings and administrative access.
4. Restart passes for the Android room or Windows PC and its panels without password entry. On Windows, verify resource-account Windows sign-in and reboot return from admin mode to Rooms. Do not sign out, delete a device record, reset or re-enrol a healthy endpoint as a routine SOA step.
5. Recovery works at cloud authority: an authorised administrator can issue a temporary resource-account password without a forced first-sign-in change. Rehearse the Android bootstrap route and Windows OEM/recovery-tool reset, join/management restoration, bootstrap, conversion and cleanup on a supported spare or an explicitly scheduled recovery test for that room; avoid interrupting a healthy production room merely to demonstrate it. Record the evidence before scaling.
6. Complete cloud password cleanup only after every associated endpoint is accepted. For accounts with the validated managed cloud authentication path, AD password changes are no longer the password authority. Accounts retaining third-party federation require its documented AD and provider password maintenance and cannot pass the AD-independence gate. Repeat restart and functional checks after cleanup. [3][5]

Observe all four SOA pilots for five accepted business days including normal meeting use and scheduled sync cycles, retaining distinct Android and Windows evidence. This duration and the wave sizes below are operational recommendations, not Microsoft propagation guarantees.

**Gate 3:** All acceptance tests pass, cloud recovery is proven and the identity, security and room owners accept the pilot. Any failed test stops the next account or wave.

## Phase 4 Roll out by site and dependency

| Wave | Android local | Android remote | Windows local | Rooms | Advancement condition |
| --- | ---: | ---: | ---: | ---: | --- |
| Mixed-platform pilot | 2 | 1 | 1 | 4 | Five accepted business days and proven platform recovery |
| Android local 1 | 11 | 0 | 0 | 11 | Per-account checks and at least one business day of stable use |
| Android local 2 | 11 | 0 | 0 | 11 | Previous wave accepted with no unresolved defects |
| Android local 3 | 11 | 0 | 0 | 11 | Same checks and support coverage |
| Android remote 1 | 0 | 3 | 0 | 3 | Confirmed remote recovery coverage |
| Android remote 2 | 0 | 3 | 0 | 3 | Previous remote batch accepted |
| Android remote 3 | 0 | 3 | 0 | 3 | Previous remote batch accepted |
| Windows local 1 | 0 | 0 | 2 | 2 | Windows pilot accepted; PC and account checks pass |
| Windows local 2 | 0 | 0 | 2 | 2 | Previous Windows batch accepted |
| Total rooms | 35 | 10 | 5 | 50 | All room-account and endpoint gates pass |

The room rows total 50: 45 Android and 5 local Windows. Separate panel accounts add their inventoried identities and follow the same account/endpoint gates. Reorder by RoomList, building and policy dependencies without expanding the approved blast radius. Process only the exact approved object IDs; start with one account at a time within a wave. A shared account moves once, with all its endpoints checked together. Keep an exception list and leave failed accounts at their last proven state.

The combined CAB planning allowance is 8 to 10 working weeks after readiness for passwordless delivery, assessed group work and this authority migration, followed by the proposed 30-calendar-day retention period before AD retirement. This is an operational estimate, not a product guarantee. Actual windows and release decisions are held in the change record; platform preparation, failed tests, panel identities or dependency remediation can extend it.

## Phase 5 Retire AD dependencies and hand over

Retain the listed AD resource-user and group objects, anchors, matching evidence and the required sync scope for a proposed 30-calendar-day rollback period after the final accepted SOA wave. A designated AD OU can identify cloud ownership, but do not exclude that OU while the documented reference or rollback requirements remain. Windows computer objects are separate from the room resource users and are not routine retirement targets. [15][23]

Before retiring a listed AD resource-user or group object, confirm no AD-managed group membership, licensing, policy rule, authentication path, application, provisioning writer, Exchange workflow or rollback requirement still depends on it. On Windows, also resolve the separately inventoried PC/join, GPO, certificate, network and administrative dependencies before claiming room-wide AD independence. Resolve cloud group targeting and RoomList ownership first. Review the exact disablement, removal-from-scope or deletion action, expected sync behaviour and booking tests at the retirement phase release under the same project approval. Adding AD computer or infrastructure retirement requires an assessed scope amendment.

Do not use Remove-RemoteMailbox or Disable-RemoteMailbox as housekeeping: they are mailbox-removal operations. Do not clear ImmutableId or source anchors, remove licence plans, recreate room users or purge recipients as routine conversion steps. [18][19]

Hand over cloud identity and Exchange administration, password reset and device recovery ownership, cloud RoomList membership procedures, licensing and CA monitoring, and the evidence register. Close exceptions only when every in-scope account satisfies cloud authority and AD independence. Continue tenant sync for other users and groups. A whole-tenant move needs a broader plan covering users, groups, workstations, applications, certificates, network services and directory retirement.

## Stop conditions and recovery

Stop immediately if the supported route or permissions are unresolved, prerequisites fail, unexpected object deletion or duplication appears, mailbox identity or subtype changes, membership or licensing is lost, policy coverage drifts, authentication or booking fails, or cloud bootstrap recovery cannot be demonstrated. Pause remaining accounts, retain the evidence and diagnose the smallest affected scope.

A temporary bootstrap password supports a device recovery event; it is not an SOA rollback. Where the cloud identity is sound and only an endpoint needs recovery, follow its supported platform procedure. Android can return to password sign-in through full sign-out; a converted Windows room needs OEM-image or Microsoft recovery-tool reset to back out passwordless authentication, followed by join/management restoration and bootstrap. Do not use an ordinary Windows reset or Keep my files as a substitute for the supported recovery procedure. Preserve the mailbox and all healthy device records. [3][24]

### User authority rollback

Prearrange a supervised recovery window and reconcile cloud edits into the retained AD record before takeover so stale AD values do not overwrite intentional changes. Preserve its original matching anchor. Resolve unsupported cloud references and coordinate group membership first. [2]

Microsoft's User SOA rollback requires temporarily permitting hard-match takeover through the tenant-wide blockCloudObjectTakeoverThroughHardMatchEnabled feature, setting the affected user's isCloudManaged to false, and letting the owning sync engine take over the retained in-scope AD object. Verify authority, matching, audit and successful sync before declaring recovery complete. Setting false alone is not completion. Restore hard-match protection promptly after takeover and record the final state. If it was intentionally disabled beforehand, agree the protection posture with the security owner rather than silently changing policy. [2][10]

The directory-sync feature operation requires Global Administrator with delegated OnPremDirectorySynchronization.ReadWrite.All; application permission is unsupported. Forward user-transfer permissions alone do not provide this recovery path. The feature change affects the tenant, so bound the window and monitor unrelated matching activity. [10]

### RoomList and group rollback

Group rollback requires resolving cloud-only members and access-package references before AD takeover. Retain the original AD group in sync scope and reconcile cloud edits into its AD state. The documented operation sets isCloudManaged to false on v1.0/groups/{groupId}/onPremisesSyncBehavior, followed by a completed sync takeover and state and audit verification. Coordinate users and groups in dependency order; restoring user AD authority first can be necessary before returning a RoomList containing those users to AD authority. Do not automatically remove every cloud member to make rollback succeed and thereby break licensing, policy coverage or discovery. Mail-enabled membership changes use Exchange tools. [12]

### Approaches excluded from the default plan

Moving currently synced users out of scope can export deletions; a small room wave may not reach the accidental-deletion threshold. Delete and restore is therefore not the default cloud-only conversion. Turning off directory synchronization is tenant-wide and belongs to an explicit organisation-wide exit. Neither is needed for the selected in-place approach. [20][21]

## Required completion evidence

For each account retain the before and after identifiers, platform and site, supported-path and version checks, SOA state, audit reference, sync evidence, mailbox and RoomList comparisons, licence and policy validation, all-endpoint acceptance, platform recovery result, date and owner. For Windows, retain separate PC identity/join, TPM and administrative recovery evidence and dependency disposition. For each converted RoomList retain the subtype and complete membership comparison. Mark cloud authority accepted and AD independence accepted separately. The plan provides the decision gates; tenant readiness and successful migration require this evidence.

## Primary sources

- [1] [Microsoft Entra release notes and User SOA GA announcement](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new)
- [2] [Configure User Source of Authority](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure)
- [3] [Teams device passwordless resource accounts](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts)
- [4] [Prepare the environment for User SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment)
- [5] [User SOA overview and prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview)
- [6] [Pass through authentication behaviour](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-how-it-works)
- [7] [Password hash synchronization](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization)
- [8] [Entra Connect version history](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history)
- [9] [Cloud Sync agent version history](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/reference-version-history)
- [10] [Update directory synchronization configuration and permissions](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-update?view=graph-rest-1.0)
- [11] [Group Source of Authority overview](https://learn.microsoft.com/en-us/entra/identity/hybrid/concept-source-of-authority-overview)
- [12] [Configure and roll back Group SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure)
- [13] [Group based licensing](https://learn.microsoft.com/en-us/entra/identity/users/licensing-groups-assign)
- [14] [Manage resource mailboxes and RoomLists](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-resource-mailboxes)
- [15] [User SOA operational guidance](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance)
- [16] [Graph SOA update method reference](https://learn.microsoft.com/en-us/graph/api/onpremisessyncbehavior-update?view=graph-rest-beta)
- [17] [User SOA audit and monitoring](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-audit-monitor)
- [18] [Remove RemoteMailbox](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/remove-remotemailbox)
- [19] [Disable RemoteMailbox](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/disable-remotemailbox)
- [20] [Connect synchronization filtering behaviour](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering)
- [21] [Turn off directory synchronization](https://learn.microsoft.com/en-us/microsoft-365/enterprise/turn-off-directory-synchronization?view=o365-worldwide)
- [22] [Exchange attribute cloud management scope](https://learn.microsoft.com/en-us/exchange/hybrid-deployment/enable-exchange-attributes-cloud-management)
- [23] [Entra join for Teams Rooms on Windows](https://learn.microsoft.com/en-us/microsoftteams/rooms/mtrw-entraid-join)
- [24] [Teams Rooms Windows recovery tool](https://learn.microsoft.com/en-us/microsoftteams/rooms/recovery-tool)
- [25] [Supported platform CA and compliance policies](https://learn.microsoft.com/en-us/microsoftteams/rooms/supported-ca-and-compliance-policies)

[1]: https://learn.microsoft.com/en-us/entra/fundamentals/whats-new
[2]: https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure
[3]: https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts
[4]: https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment
[5]: https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview
[6]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-how-it-works
[7]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization
[8]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history
[9]: https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/reference-version-history
[10]: https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-update?view=graph-rest-1.0
[11]: https://learn.microsoft.com/en-us/entra/identity/hybrid/concept-source-of-authority-overview
[12]: https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure
[13]: https://learn.microsoft.com/en-us/entra/identity/users/licensing-groups-assign
[14]: https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-resource-mailboxes
[15]: https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance
[16]: https://learn.microsoft.com/en-us/graph/api/onpremisessyncbehavior-update?view=graph-rest-beta
[17]: https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-audit-monitor
[18]: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/remove-remotemailbox
[19]: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/disable-remotemailbox
[20]: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering
[21]: https://learn.microsoft.com/en-us/microsoft-365/enterprise/turn-off-directory-synchronization?view=o365-worldwide
[22]: https://learn.microsoft.com/en-us/exchange/hybrid-deployment/enable-exchange-attributes-cloud-management
[23]: https://learn.microsoft.com/en-us/microsoftteams/rooms/mtrw-entraid-join
[24]: https://learn.microsoft.com/en-us/microsoftteams/rooms/recovery-tool
[25]: https://learn.microsoft.com/en-us/microsoftteams/rooms/supported-ca-and-compliance-policies
