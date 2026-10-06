# Teams Rooms account: safe source-of-authority transfer

Prepared 6 October 2026. Status: documentation checked; no live tenant discovery or changes performed. The target account and migration prerequisites remain unverified.

For tomorrow, start with [the consolidated migration plan](/Users/jordan/Documents/ChatGPT/TeamsSOA/teams-room-soa-parallel-plans.md). There is one SOA procedure for this already-passwordless room. PHS/PTA is optional recovery background, not a branch-selection prerequisite. This document supplies the detailed prerequisites and baseline commands.

User-reported scope: **mtr@meetingrooms.ie**, Android Teams room, room mailbox in Exchange Online, all organisational mailboxes online, the latest Entra Connect Sync installed, and **passwordless migration completed through Teams Rooms Pro Management**. These statements are not live tenant verification. Group dependencies, federation eligibility, remaining Exchange workloads, and the operational/recovery baseline still need checking. The administrator has confirmed the Connect version requirement; record the installed version in the normal change evidence without making an upgrade part of this task.

## Intended outcome

Transfer management of one existing AD-synchronized Teams Rooms **user account** to Microsoft Entra ID. Preserve its Entra object ID, UPN, SMTP addresses, room mailbox, Exchange GUID, calendar, bookings, delegates, licences, and group dependencies. Retiring the AD account is a later decision after dependencies and rollback have been validated.

Microsoft recommends cloud-only Teams Rooms resource accounts. Its generic User SOA mechanism sets `onPremisesSyncBehavior.isCloudManaged=true` on the existing user. Applying that mechanism to this room requires the checks below; the reviewed documentation does not provide a room-specific assurance of unchanged authentication. [Teams Rooms resource accounts](https://learn.microsoft.com/en-us/microsoftteams/rooms/create-resource-account), [User SOA configuration](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure).

## Information needed

- Intended tenant ID; resolve `mtr@meetingrooms.ie` and record the exact Entra object ID and actual UPN.
- Active and staging Entra Connect Sync versions, sync health, and the room's current OU and sync scope.
- Android room software version, completed Pro Management passwordless migration status, account/device credential binding, all endpoints sharing this account, and physical or remote recovery access.
- Federation configuration applicable to this account, especially any AD FS use, and a documented bootstrap/recovery path. PHS versus PTA is secondary to this already-converted room's normal sign-in; record it if needed to understand the recovery path or another endpoint still using a password.
- Room mailbox location, and whether any Exchange workloads or mailboxes remain on-premises.
- AD-managed group memberships, RoomLists, group-based licensing, applicable Conditional Access, provisioning automation, and dependencies on AD authentication.
- An agreed maintenance window, acceptable downtime, and a credential recovery method. Do not put passwords or tokens in this document or chat.

## Preconditions and stop conditions

1. **Use a currently supported Connect build.** The User SOA feature minimum in the configuration guide is 2.5.76.0, but that build retired on 1 September 2026. The release history checked today lists 2.6.92.0 as the latest release. Check active and staging servers; an upgrade is a separate planned change. [Connect version history](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history).
2. **Resolve Exchange prerequisites.** Microsoft's environment preparation guidance requires all mailboxes to be in Exchange Online before any User SOA transfer in an Exchange hybrid environment. Its overview also requires no on-premises Exchange workloads. If workloads remain, stop and resolve support for this scenario with Microsoft. Do not dismantle hybrid, change DNS, or remove connectors as part of this one-room change. [Environment preparation](https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment), [User SOA prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview#prerequisites-for-transferring-user-soa).
3. **Validate passwordless operation and recovery.** This room has completed Pro Management passwordless migration according to the administrator. Microsoft says converted devices use a device-bound resource-account credential and supports both AD-synchronized and cloud-only accounts. It follows that PHS/PTA password validation is not the primary normal-sign-in check for this converted device. Preserve the Entra user and device identities, confirm successful conversion and operational health, and test reboot behaviour after cutover. Microsoft explicitly documents password-change resilience, but does not explicitly guarantee the outcome of an SOA transfer for the bound credential. Account-level SOA eligibility still matters: the User SOA guidance excludes users authenticating through AD FS and states third-party federation can retain AD/password dependencies. Check applicability to this account; federation elsewhere in the tenant alone is not proof that the room uses AD FS. [Passwordless resource accounts](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts), [User SOA guidance](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance).
4. **Preserve group dependencies.** Microsoft says groups should precede users when transferring their SOA. Inventory RoomLists and licensing/security/policy groups; do not automatically transfer shared groups for this one-room task. Any necessary group transfer is an additional scoped change. Generic Group SOA documentation does not specifically establish preservation of the Exchange `RoomList` subtype, so validate any proposed RoomList transfer separately. Keep the AD user in sync scope while it has references to AD-managed groups, devices, or contacts. Deleting the AD user can remove membership from both AD and Entra groups. [Environment preparation](https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment), [User SOA guidance](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance).
5. **Follow the documented production API.** Microsoft announced object-level User SOA as generally available in January 2026. The current configuration guide uses v1.0; an anonymous read of the public v1.0 Graph metadata on 6 October 2026 confirmed the `onPremisesSyncBehavior` resource and user navigation property are published there. Although an older API-reference page still displays beta, this is not a reason to block the documented v1.0 procedure or use beta for production. No tenant-specific API request was made. [GA announcement](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new#general-availability---ability-to-convert-source-of-authority-of-synced-on-premises-ad-users-to-cloud-users-is-now-available), [User SOA configuration](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure), [Published Graph v1.0 metadata](https://graph.microsoft.com/v1.0/$metadata).
6. **Confirm object eligibility.** It must already be synchronized, must not be an administrative account, and must satisfy Microsoft's rules for reference-valued attributes and attributes managed by other on-premises systems. Freeze AD, HR/MIM, and Exchange writes for this account after its final clean sync. [Object readiness](https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment#confirm-your-ad-objects-are-ready-to-have-their-soa-changed).

Stop if any prerequisite is unknown, discovery is incomplete, IDs disagree, sync has unresolved errors, or a safe recovery path is unavailable. A local command review is not a tenant dry run.

## Read-only baseline

Use existing approved access to the intended tenant. These examples are reads; a 403 means missing evidence, not permission to switch credentials or broaden consent. Save results securely in your normal change record.

In Entra, record the tenant ID, user object ID, UPN, account-enabled status, on-premises synchronization status, immutable ID/source anchor, assigned licences, and group memberships. Review the room's actual sign-in logs and applicable policies. In Programs and Features on each Connect server, record the installed Connect version and confirm the most recent successful sync runs.

For this already-converted room, start with **Teams Rooms Pro Management > Planning > Resource Accounts > Migration**: record the completed migration and confirm the associated room is healthy. Confirm the retained Entra account/device identities and review room sign-in failures, calendar access, and meeting behaviour. Every device sharing the account must have a known authentication/recovery path. Remote sign-in with a web/device code or marking an account as a resource does not by itself demonstrate the separate passwordless conversion; the administrator has confirmed that conversion here. [Passwordless migration and validation](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts).

Use **Microsoft Entra admin center > Entra ID > Entra Connect > Connect sync** to inspect federation configuration and, if needed for recovery or another password-based endpoint, **Password Hash Sync** and **Pass-through authentication**. If PTA is enabled, its detail page also lists authentication agents and their status. PHS can coexist with PTA or federation, so its Enabled status does not identify the effective password-validation method. PHS/PTA identification is no longer a prerequisite to verifying this converted room's normal device authentication. [Portal navigation](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-staged-rollout#enable-staged-rollout), [PTA status](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-pass-through-authentication#check-status-of-the-feature-and-authentication-agents).

If a password-validation path needs investigation, open **Entra ID > Users > mtr@meetingrooms.ie > Sign-in logs**, inspect an existing password-authentication event, and read **Authentication Details > Authentication method detail**. Check both interactive and non-interactive user sign-ins. Do not force the converted room to sign out or use a password merely to obtain such an event. If federation or staged rollout is enabled, verify which configuration applies to this account and its domain. Inspect settings without changing toggles. [Sign-in details](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-sign-in-log-activity-details), [PTA sign-in evidence](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-faq#how-do-i-capture-the-pta-agent-id-from-microsoft-entra-sign-in-logs-and-the-pta-server-to-validate-which-pta-server-was-used-for-a-sign-in-event).

The room's **Groups** page in Entra provides a starting membership inventory. Inspect each relevant group's source/synchronization status. Entra's generic group display does not establish the Exchange `RoomList` recipient subtype, booking settings, or delegates; verify those through Exchange using the commands below.

Also inspect dynamic rules and automation that distinguish synchronized and cloud users. User SOA changes sync state, so a rule such as one using `user.dirSyncEnabled` can alter the room's group membership, licensing, or Conditional Access applicability. Validate actual rule evaluation after transfer. See [the migration plan's risk and permission section](/Users/jordan/Documents/ChatGPT/TeamsSOA/teams-room-soa-parallel-plans.md) for the exact SOA and tenant-rollback scopes and their different administrator-role requirements.

If the portal evidence is unavailable or ambiguous, on the active Connect server open **Microsoft Entra Connect > Configure > View current configuration** and record the sign-in, password synchronization, and federation settings. Do not select options that change configuration. [Viewing current configuration](https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/user-prov-sync/pwd-hash-sync-auto-enable#resolution).

On a Windows machine with the ActiveDirectory module and access to the room's AD domain, the following read discovers direct AD memberships:

```powershell
$AdRoom = @(Get-ADUser -Filter "UserPrincipalName -eq 'mtr@meetingrooms.ie'" -ErrorAction Stop)
if ($AdRoom.Count -ne 1) {
    throw 'Expected exactly one AD account. Verify its on-premises UPN and domain before continuing.'
}
$AdRoom[0] | Select-Object SamAccountName,DistinguishedName,Enabled
Get-ADPrincipalGroupMembership -Identity $AdRoom[0].DistinguishedName -ErrorAction Stop |
    Select-Object Name,DistinguishedName,GroupCategory,GroupScope
```

This is not a complete dependency audit: inspect nested security groups, Entra memberships, licensing, and policy targeting separately. Failure or no AD match is unresolved evidence, not proof of no dependencies.

Using an existing Exchange Online PowerShell session:

```powershell
$RoomUpn = 'mtr@meetingrooms.ie'

Get-Mailbox -Identity $RoomUpn -ErrorAction Stop |
    Format-List ExternalDirectoryObjectId,RecipientTypeDetails,ExchangeGuid,
        PrimarySmtpAddress,EmailAddresses,IsDirSynced,IsExchangeCloudManaged,
        HiddenFromAddressListsEnabled

Get-CalendarProcessing -Identity $RoomUpn -ErrorAction Stop |
    Format-List AutomateProcessing,BookingWindowInDays,MaximumDurationInMinutes,
        AllBookInPolicy,BookInPolicy,AllRequestInPolicy,RequestInPolicy,
        AllRequestOutOfPolicy,RequestOutOfPolicy,ResourceDelegates,
        ForwardRequestsToDelegates,DeleteSubject,AddOrganizerToSubject

Get-MailboxPermission -Identity $RoomUpn -ErrorAction Stop

# Discover RoomLists containing this mailbox. Every member read must succeed.
$Mailbox = Get-Mailbox -Identity $RoomUpn -ErrorAction Stop
$RoomLists = @(Get-DistributionGroup -RecipientTypeDetails RoomList -ResultSize Unlimited -ErrorAction Stop)
$MatchingRoomLists = @(
    foreach ($List in $RoomLists) {
        $Members = @(Get-DistributionGroupMember -Identity $List.Identity -ResultSize Unlimited -ErrorAction Stop)
        $RoomMember = @($Members | Where-Object {
            ([string]$_.PrimarySmtpAddress) -eq ([string]$Mailbox.PrimarySmtpAddress)
        })
        if ($RoomMember.Count -gt 0) { $List }
    }
)
if ($MatchingRoomLists.Count -eq 0) {
    Write-Output 'No containing RoomLists found among the successfully read visible lists. Confirm that your Exchange RBAC scope covers all RoomLists.'
}
$MatchingRoomLists | Format-List Name,ExternalDirectoryObjectId,RecipientTypeDetails,
    IsDirSynced,PrimarySmtpAddress,EmailAddresses,ManagedBy,HiddenFromAddressListsEnabled
```

Confirm `RecipientTypeDetails=RoomMailbox` and that `ExternalDirectoryObjectId` matches the recorded Entra user ID. Record other relevant permissions, Places data, booking settings, and licences in the existing change record. The selected properties above are a starting point, not a complete mailbox backup.

If approved SOA access is already available, read `isCloudManaged` for the verified user object ID using the v1.0 GET in Microsoft's configuration guide. The API reference requires `User-OnPremisesSyncBehavior.ReadWrite.All` even for this GET, with the documented Hybrid Administrator role for delegated access. It is a write-capable permission despite that request being a read; do not acquire it as an automatic part of basic discovery. [Current v1.0 read procedure](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure#transfer-soa-for-a-test-user), [SOA GET permissions](https://learn.microsoft.com/en-us/graph/api/onpremisessyncbehavior-get?view=graph-rest-beta).

## Proposed cutover specification

Only proceed once the prerequisites, exact tenant/user IDs, maintenance window, and recovery plan are established through your approved change process. Follow the current documented v1.0 procedure. No executable mutation script has been created.

- Operation: update the existing user's `onPremisesSyncBehavior` resource, setting only `isCloudManaged` to `true`.
- Target: the verified user object ID in the intended tenant. Select no other account or group.
- Expected effect: Entra becomes authoritative for the complete user; subsequent AD user updates are blocked. This does not migrate the physical device's domain join, GPOs, certificates, or Intune enrolment.
- Permission: the documented `User-OnPremisesSyncBehavior.ReadWrite.All`, with the required delegated role and approved consent. General `User.ReadWrite.All` is not a replacement for this SOA permission.
- Preserve the AD object, its source anchor, and sync scope throughout initial validation. Do not delete/recreate the Entra user, clear the immutable ID, move the account out of sync, disable tenant-wide synchronization, or automatically reset its password as part of this cutover.

`IsExchangeCloudManaged=true` alone changes Exchange attribute authority while identity remains synchronized. It does not meet the requested outcome. After full User SOA transfer, a pre-existing separate Exchange-attribute SOA flag is cleared because it no longer applies to a cloud-authoritative user. [Exchange cloud-management FAQ](https://learn.microsoft.com/en-us/exchange/hybrid-deployment/enable-exchange-attributes-cloud-management#frequently-asked-questions).

## Acceptance

- Read back `isCloudManaged=true`; compare the user, object ID, UPN, licences, and mailbox baseline. The configuration guide's state table expects `onPremisesSyncEnabled=null` after transfer, but another step says the portal should show Yes. Use the SOA state, audit record, and sync connector evidence together rather than one portal label.
- Verify the SOA audit event and, after a successful Connect cycle, the connector's `blockOnPremisesSync=true` state and relevant event 6956. Avoid deliberately changing production AD attributes merely to test blocking.
- Confirm Exchange GUID, addresses, `RoomMailbox` type, booking configuration, delegates, RoomList membership, and Room Finder behaviour remain correct.
- Reboot and validate automatic sign-in using the retained passwordless credential; check subsequent Entra sign-in evidence, calendar loading, a new booking, meeting join, audio/video, and attached panels. **Do not perform a full Android sign-out, reset, reimage, device deletion, or replacement merely to test SOA.** Microsoft documents that full sign-out/reset removes the bound credential; replacement or reimage requires password-based setup followed by passwordless conversion again. Use those actions only as a separately planned recovery operation. [Passwordless recovery and restart behaviour](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts#troubleshooting-known-issues-and-faqs).
- Review sign-in logs, licences, applicable Conditional Access, and device compliance. Password-based room accounts must not require an interactive password change; review the documented nonexpiring-password requirements. Keep passwordless migration separate unless already established. Use the Android device's actual authentication and compliance requirements; the separate Teams Rooms on Windows authentication article does not establish Android behaviour. [Resource-account requirements](https://learn.microsoft.com/en-us/microsoftteams/rooms/create-resource-account).

## Rollback and later AD retirement

Rollback is a controlled change, not an automatic inverse PATCH. Microsoft's current procedure includes handling cloud references, temporarily disabling the tenant's `blockCloudObjectTakeoverThroughHardMatchEnabled` protection, reverting `isCloudManaged=false`, allowing Connect to take over, and re-enabling protection. Record the original protection state, identify the correct synchronization configuration, reconcile cloud edits against AD, and plan the wider exposure of temporarily changing that tenant setting. Rollback completes only after successful sync takeover and operational verification; AD values may overwrite cloud changes. [Rollback procedure](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure#roll-back-soa-update).

The tenant-configuration API requires delegated `OnPremDirectorySynchronization.ReadWrite.All` and Global Administrator for that protection change. Its read-only counterpart is `OnPremDirectorySynchronization.Read.All`; the read API also documents Global Administrator. Those API operations do not support application access even though application permissions appear in the permission catalog. The user's SOA change independently requires `User-OnPremisesSyncBehavior.ReadWrite.All` and its supported SOA role. [Tenant API read](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0), [Tenant API update](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-update?view=graph-rest-1.0).

Keep the original AD account intact until recovery and every dependency are understood. Consider retirement only after room acceptance and a separately agreed observation period, and after resolving AD-managed group references, authentication, automation, and device dependencies. There is no assumed automatic writeback of cloud password or profile changes to the retained AD account.
