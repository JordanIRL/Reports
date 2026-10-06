# RoomList source-of-authority migration plan

Prepared 6 October 2026 for the RoomList or RoomLists containing `mtr@meetingrooms.ie`. This is a plan for the administrator's existing change process. No tenant discovery or changes have been performed, and no mutation script is supplied.

The room uses Teams Rooms Pro Management passwordless authentication. The administrator reports that all mailboxes are in Exchange Online and Connect is current. RoomList names, tenant and object IDs, member inventories, exact Connect versions, remaining Exchange workloads, and rollback eligibility must still be established.

## Outcome and support basis

Transfer one existing AD-synchronized RoomList group to cloud authority **in place**, preserving its Entra group ID, Exchange identity, SMTP addresses, `RoomList` recipient subtype, owners, settings, and complete membership. The room mailbox and device credential are separate objects and are not replaced by this change.

Microsoft documents Group SOA for mail-enabled distribution groups. Its current Exchange guidance explicitly identifies Group SOA as the mechanism for moving mail-enabled groups' membership and mail-attribute management to the cloud; `IsExchangeCloudManaged` is a mailbox feature, not a group migration switch. [Group conversion](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure#convert-soa-for-a-test-group), [Exchange group authority](https://learn.microsoft.com/en-us/exchange/hybrid-deployment/decommission-last-exchange-server#2-exchange-attribute-soa-transferred-for-all-directory-synchronized-mailboxes).

A RoomList is a special distribution group containing room mailboxes. Applying the documented distribution-group SOA mechanism to it is an **inference from its documented group type**; the reviewed SOA articles do not separately guarantee preservation of the `RoomList` subtype. Verify that subtype and Room Finder behaviour in the pilot. Keep the group a RoomList; do not upgrade it to a Microsoft 365 group. [Exchange room lists](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-resource-mailboxes#create-room-lists).

After conversion, manage this mail-enabled group's ordinary properties and members through **Exchange Online PowerShell**, not generic Graph group-edit APIs. [Management after Group SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/concept-group-source-of-authority-guidance#how-to-manage-cloud-security-groups).

## Exact pilot scope

Choose one existing RoomList from the complete preflight inventory. Its entire group object is the pilot: every room in that list and every user relying on its Room Finder entry can be affected. Choosing `mtr@meetingrooms.ie` does not narrow the group change to that one member.

Record the following before scheduling the change:

| Identity or evidence | Required value |
|---|---|
| Tenant | Verified intended tenant ID and Exchange organisation |
| Target RoomList | Name, primary SMTP address, Exchange recipient `Guid`/identity, `ExternalDirectoryObjectId` |
| Entra target | Exact group object ID; must equal the Exchange `ExternalDirectoryObjectId` |
| Original AD group | Distinguished name, object GUID, SID, scope, current sync inclusion |
| Current authority | AD-synchronized state; SOA value if the authorised SOA read is available |
| Membership | Complete direct members with stable identifiers, recipient types, and cloud/AD authority |
| Other references | Parent/nested groups, access packages, automation, AD applications, Exchange dependencies |
| Impact and recovery | Group owner, maintenance window, accepted impact, snapshots, recovery access |

A display-name match alone is insufficient. A denied or incomplete read is **Unknown**, not an empty list. If the room belongs to several RoomLists, select and approve each group individually; do not batch-convert every discovered list.

Stop before a write if target identities disagree, membership cannot be read completely, the target is not the expected RoomList, sync has unresolved errors, a nested or non-room member is unexpected, other dependencies are unresolved, or recovery cannot preserve required membership. A local preview is not a tenant dry run.

## Before-and-after baseline

Use the supplied read-only preflight output to discover candidate lists. Immediately before cutover, capture a fresh baseline using approved existing Exchange/Graph/AD access. Save it in the secured change record, with timestamp and tenant identity.

At minimum, capture:

- The RoomList's complete `Get-DistributionGroup` result, including identities, `RecipientTypeDetails`, `IsDirSynced`, primary and proxy addresses, owners, visibility, moderation, sender restrictions, join/leave restrictions, custom attributes, and relevant permissions.
- All direct members, resolving each to a stable identifier and recipient type. Preserve the full member set, not only this room's entry. Read every relevant member's authority where rollback assessment requires it.
- AD group properties, complete membership, parent references, and the sync configuration evidence. Do not edit AD or force a sync during discovery.
- Each member room's mailbox identity/Exchange GUID and relevant Places attributes, including city, building, and capacity. Record the baseline Room Finder selection and an existing/new booking test for the target room and a representative other room.
- Graph group properties and SOA state when available, plus the room's memberships, licensing and applicable policies for comparison after its later user transfer.

These are useful read shapes once the exact list identity is known:

```powershell
# Read-only examples. Replace the placeholder with the verified list identity.
$RoomListIdentity = '<verified-RoomList-primary-SMTP-address>'
Get-DistributionGroup -Identity $RoomListIdentity -ErrorAction Stop |
    Format-List *
Get-DistributionGroupMember -Identity $RoomListIdentity -ResultSize Unlimited -ErrorAction Stop |
    Select-Object Identity,ExternalDirectoryObjectId,PrimarySmtpAddress,RecipientTypeDetails
```

Use Exchange PowerShell to establish `RoomList` subtype; a generic Entra distribution-group entry is not that proof. Room Finder also depends on room/Places attributes, which should not be changed as part of authority transfer. [RoomList verification](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-resource-mailboxes#how-do-you-know-you-successfully-created-updated-or-converted-a-room-list), [Places and Room Finder](https://learn.microsoft.com/en-us/microsoftteams/rooms/create-resource-account#exchange-room-finder--microsoft-places).

## Permissions and wider exposure

| Task | Access to arrange through the existing workflow |
|---|---|
| Baseline | Read-only Graph/Exchange/AD access specified by the preflight toolkit |
| Read or change group SOA | `Group-OnPremisesSyncBehavior.ReadWrite.All`; it is write-capable even for SOA GET |
| Delegated group SOA | Supported Hybrid Identity Administrator role (the configuration guide labels its prerequisite link “Hybrid Administrator”) plus approved consent |
| Subsequent RoomList administration | Exchange RBAC permitting the intended distribution-group operations |
| A later user SOA operation | Separate `User-OnPremisesSyncBehavior.ReadWrite.All` and its role |

The group SOA permission does not require adding general `Group.ReadWrite.All` merely to rename a group for testing. Avoid app-only permission for this one-off pilot unless explicitly required: its `.All` capability can reach other groups. Keep temporary access and any existing shared consent distinct. [SOA permissions](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure#prerequisites), [Graph permission definitions](https://learn.microsoft.com/en-us/graph/permissions-reference#group-onpremisessyncbehaviorreadwriteall).

If administrative-unit scoping is chosen, verify its actual role assignment and effective authorisation before the write. It scopes the operator's role, not a tenant-wide application permission. Shared CA, licensing, or RoomList membership changes remain separately scoped work. Do not broaden a shared policy or remove other rooms to make the pilot pass.

## Pilot sequence

1. **Establish readiness.** Resolve the target/impact record and rollback constraints. Verify supported versions on active and staging Connect servers. Do not use the historic feature minimum as evidence that an old build remains supported. Evaluate remaining Exchange and AD application dependencies; all mailboxes online alone is not the complete assessment. No server, connector, DNS, or tenant-authentication changes are included here.
2. **Freeze the target group.** After its last successful normal sync and fresh baseline, stop direct AD, on-premises Exchange, and automation edits to this RoomList. Retain its original AD object and sync scope during the pilot. Membership automation must have an identified owner and planned cloud management path.
3. **Transfer this group only.** Submit the reviewed request below through the approved administrative workflow. Do not delete/recreate the group or its members. Do not test conversion by renaming the production list.
4. **Validate and observe.** Re-read SOA; verify audit and Connect evidence after a successful normal sync. Compare every recorded group property and the complete member set. Confirm Exchange reports the expected cloud-managed state and still returns `RecipientTypeDetails=RoomList`; reconcile any disagreement before proceeding. Test Room Finder and booking for affected rooms. Agree an observation period based on operations, without assuming a fixed service propagation time.
5. **Then consider the room user.** If both group and user transfers are in scope, accept the relevant group transfer first, then apply the separate user SOA plan for `mtr@meetingrooms.ie`. Other RoomLists and AD-managed licensing/security groups may still reference the room. Keep its AD object and sync scope until those references are resolved. A RoomList transfer does not require converting every member room immediately.

This sequence follows Microsoft's guidance to transfer selected groups before selected users and retain sync scope for remaining AD-managed references. [User/group sequence](https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment#sequence-of-steps-for-using-soa), [Retained user references](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance#move-users-to-an-ou).

The device-bound passwordless credential is preserved operationally by leaving the room's user and device identities intact. Do not sign out, reset, reimage, or delete an Android device to test this group change. A later user SOA transfer still needs room acceptance; no uninterrupted credential-continuity guarantee is claimed. [Passwordless lifecycle](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts).

## Reviewed request specification

These HTTP examples describe the administrator's proposed operation. They have not been executed. Use the **verified group object ID** from the tenant-bound baseline.

```http
GET https://graph.microsoft.com/v1.0/groups/{verified-RoomList-group-object-id}/onPremisesSyncBehavior?$select=isCloudManaged
```

```http
PATCH https://graph.microsoft.com/v1.0/groups/{verified-RoomList-group-object-id}/onPremisesSyncBehavior
Content-Type: application/json

{
  "isCloudManaged": true
}
```

Use Microsoft's documented v1.0 Group SOA operation. After it succeeds, repeat the GET and require `isCloudManaged=true`. An already-converted group needs validation rather than another conversion. A 403 or missing value remains unresolved evidence. [Documented operation](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure#convert-soa-for-a-test-group).

Acceptance requires the stable group ID, subtype, addresses, owners/settings, full membership, and room-discovery behaviour to match the baseline. The audit record and sync evidence support that conclusion; a successful PATCH alone does not.

## Recovery and rollback

First inspect actual state after an ambiguous request; do not repeatedly write blindly. If SOA changed but Room Finder fails, compare subtype, membership, visibility and Places evidence before altering anything. Preserve the pre-change snapshots and make one diagnosed correction at a time.

Group rollback is conditional. Microsoft's procedure requires no cloud references, including cloud-user membership, and removal from access packages where applicable. That can constrain rollback **even before this room's user conversion**, depending on other members. Record those dependencies before the pilot. After user transfers or cloud membership edits, rollback must be reassessed.

Never copy the documentation's example cloud-member removal into an automatic recovery step: removing room members can itself break discovery. If restoring group authority would require temporary member/reference changes, prepare the exact affected objects, service impact, restoration sequence, and coordinated user/group recovery separately. Do not assume merely reverting this one room user makes all group rollback prerequisites true.

Once those conditions and AD/cloud differences are resolved, the documented group rollback specification sets this group's `isCloudManaged=false` and lets Connect reclaim the original in-scope AD group. Verify takeover, audit evidence, properties and complete membership afterwards. Preserve required cloud edits in the appropriate AD/Exchange baseline first. [Group rollback conditions](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure#roll-back-soa-update).

The Group SOA rollback article does **not** prescribe automatically disabling tenant hard-match protection. Do not import the separate User SOA rollback's tenant-wide switch into a group recovery script. If a coordinated user rollback needs that setting, handle it under the user plan with its separate privileged access and exposure. [Separate user rollback](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure#roll-back-soa-update).

Cloud Sync provisioning to AD does not support mail-enabled or distribution groups, so do not assume it supplies RoomList writeback. If on-premises applications still need changing RoomList membership, resolve their management dependency before committing to cloud-only group administration. Retire the AD group only in a separate change after acceptance, rollback assessment, and all parent/application/member references are understood. [Provisioning group limitations](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/overview-provision-entra-id-to-active-directory#what-isnt-supported).
