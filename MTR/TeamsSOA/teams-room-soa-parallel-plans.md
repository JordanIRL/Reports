# User SOA migration plan for mtr@meetingrooms.ie

Prepared 6 October 2026 for read-only checks tomorrow, 7 October. Your Android room has completed Teams Rooms Pro Management passwordless migration. There is **one in-place User SOA procedure** for this account. PHS versus PTA does not change the cutover request, the normal passwordless device sign-in, or the post-conversion cloud recovery procedure. Identifying PHS versus PTA is not a prerequisite for choosing this procedure.

Supplied facts: room mailbox and all organisational mailboxes are in Exchange Online; Connect is on the latest version; Pro Management passwordless migration completed. No live tenant discovery or changes have been performed. The exact tenant/user/device identities, group dependencies, federation applicability, remaining Exchange workloads, and recovery readiness are not yet verified.

## PHS and PTA: optional recovery background

PHS and PTA describe password validation for synchronized accounts: PHS checks synchronized password data in Entra, while PTA validates against AD through agents. A completed Teams Rooms passwordless conversion uses a device-bound resource-account credential for normal sign-in. Neither prior password method changes the planned User SOA operation. Both AD-synchronized and cloud-only accounts are supported for Teams Rooms passwordless conversion; Microsoft does not explicitly guarantee uninterrupted credential operation across an SOA transfer, so device validation remains necessary. [PHS](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-password-hash-synchronization), [PTA](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-how-it-works), [Passwordless resource accounts](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts).

After transfer, the recovery plan is the same: use an approved Entra password-reset/bootstrap route if a later sign-out, reset, or replacement loses the device-bound credential, then complete passwordless conversion again. PTA does not apply to cloud-only users. Prior PHS can explain existing cloud password data, but do not assume the old password is guaranteed to remain usable. There is no need to reset a password or switch tenant authentication during this cutover. Federation eligibility is a separate check described below.

## Tomorrow: verify prerequisites

1. In Entra, record the intended tenant ID, exact user object ID for `mtr@meetingrooms.ie`, actual UPN, immutable ID/source anchor, enabled state, licences, and the existing Android device identity. In Exchange, confirm the mailbox's `ExternalDirectoryObjectId` equals that user ID and record its `ExchangeGuid`, addresses, booking settings, and delegates.
2. Record Pro Management's completed passwordless migration and current room/panel health. Confirm every endpoint sharing this account and the administrator's cloud and AD recovery access. Do not reset any password as part of discovery.
3. Check whether the documented federation restrictions apply to this account, including any AD FS use or third-party federation dependency. Do not infer this from federation elsewhere in the tenant. Investigate PHS/PTA or staged rollout only if needed to understand another password-based endpoint, an existing sign-in issue, or recovery background; there is no PHS/PTA branch to select.
4. Inspect the user's Entra group memberships and the source of relevant groups. Verify RoomLists in Exchange, including recipient subtype and membership. Record group-based licensing, applicable Conditional Access, nested dependencies, and automation. Inspect dynamic rules that distinguish synchronized and cloud users, especially `user.dirSyncEnabled`; SOA transfer can change which groups match this account. The detailed runbook contains read-only AD and Exchange commands.
5. Confirm the documented User SOA object and Exchange prerequisites. All mailboxes online does not by itself prove that no Exchange workloads remain on-premises. Use an agreed maintenance window with room recovery access; do not assume a propagation time or guaranteed absence of downtime.

**Stop conditions:** wrong or ambiguous tenant/object identities; unresolved sync errors; incomplete dependency reads; unavailable recovery; or failure of the documented object/Exchange prerequisites. Microsoft's User SOA guidance excludes users authenticating through AD FS and provides no passwordless-room exception. If AD FS applies, keep the room operating as it is and plan a supported authentication transition separately. If third-party federation applies, assess the documented AD/password-maintenance dependency before claiming the account can become independent of AD. Federation in another part of the tenant alone does not establish that either condition applies to this room. [SOA prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview#prerequisites-for-transferring-user-soa), [Federation guidance](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance#third-party-federated-authentication).

AD-managed groups are not an instruction to migrate every shared group. Microsoft supports retained references by keeping the converted user's AD object in sync scope. Any planned group SOA transfer is separately scoped and sequenced before the affected user; validate RoomList behaviour explicitly. [Group references and AD retention](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance).

## Cutover

1. Complete the prerequisite checks and baseline. Confirm cloud credential recovery access and prepare the controlled SOA rollback before changing authority.
2. Freeze direct AD/Exchange/HR/MIM writes for this one account after its final successful sync. Leave tenant synchronization, authentication services, and the account's sync scope in place.
3. Through your approved administrative workflow, set `isCloudManaged=true` on the verified existing user using the request below. Preserve the passwordless credential, UPN, mailbox, user/device identities, and tenant authentication configuration.
4. Read back the SOA state, record the audit evidence, and verify Connect honours cloud authority after its next successful cycle.
5. Reboot and complete the room, mailbox, licence, policy and membership acceptance checks below. Do not fully sign the Android room out to test the transfer.
6. Retain the AD object during the agreed observation period and while AD-managed references remain. Resolve those dependencies separately before retirement.

## User SOA access

This is a reviewable request specification, not a script that has been run. Follow Microsoft's current production v1.0 procedure after the prerequisites and target are verified. Use an approved identity/application with `User-OnPremisesSyncBehavior.ReadWrite.All` and the delegated SOA role specified in the prerequisite table (listed there as Hybrid Administrator). Consent and any additional rollback access follow your established administrative process. This SOA permission is write-capable even when reading state. [User SOA configuration and permissions](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure).

## Tenant-wide risks and Graph permissions

The forward request changes only the specified user's authority. It does not change tenant PHS/PTA configuration, domain federation, Conditional Access policies, other users' SOA, or tenant-wide synchronization settings. This is the intended API scope, not a live verification of the tenant. Selecting a wrong user ID would affect that other user.

The wider risks are:

- **Permission exposure:** `User-OnPremisesSyncBehavior.ReadWrite.All` is not restricted to `mtr@meetingrooms.ie` by its OAuth grant. Application permission allows updates for all users without a signed-in administrator. Prefer delegated access for this one-off change. Microsoft's SOA guide documents a Hybrid Identity Administrator role assignment scoped to an Administrative Unit containing the target user. Such role scoping can narrow the administrator's authority; it does not narrow the OAuth grant, remove other tenant-wide role assignments, or constrain an app-only grant. Check actual grants and effective roles. AU-scoped administration requires a P1 licence for the scoped administrator. [Permission definition](https://learn.microsoft.com/en-us/graph/permissions-reference#user-onpremisessyncbehaviorreadwriteall), [SOA administrative-unit scoping](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure#scope-a-user-for-soa-operations-within-an-administrative-unit), [AU licensing](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units#license-requirements).
- **Rollback exposure:** the documented rollback temporarily disables tenant-wide `blockCloudObjectTakeoverThroughHardMatchEnabled`. Qualifying hard matches beyond the room can become possible during that window; disabling this protection does not itself convert every user. Snapshot the setting, inspect relevant sync activity, control the rollback window, and re-enable protection after the intended takeover. Keep this out of automatic recovery scripts. [Official rollback](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure#roll-back-soa-update).
- **Shared policy and group changes:** the room may enter or leave dynamic groups after its sync status changes. For example, rules using `user.dirSyncEnabled` can change licensing or Conditional Access applicability. This is a dependency risk to check against actual rules, not evidence that your tenant has such a rule. Modifying a shared group rule or CA policy to compensate could affect other accounts; scope that work separately. [Supported dynamic-rule properties](https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership#properties-of-type-boolean).
- **Expanding the change:** disabling tenant sync, changing federation, switching authentication methods, deleting AD objects, or migrating shared groups would broaden the affected scope. None is included in this account's forward transfer.

The following are **documented requirements for the planned calls**, not permissions verified on a live credential:

| Capability | Graph permission | Access and Entra role |
|---|---|---|
| Read or update this user's SOA resource | `User-OnPremisesSyncBehavior.ReadWrite.All` | Delegated with the documented Hybrid/SOA administrator role; application permission also exists but is broader. Admin consent required. |
| Read tenant synchronization configuration and takeover-protection state | `OnPremDirectorySynchronization.Read.All` | The API documents delegated access with Global Administrator; app-only is unsupported for this operation. |
| Change takeover-protection state during rollback | `OnPremDirectorySynchronization.ReadWrite.All` | The API documents delegated access with Global Administrator; app-only is unsupported. This also permits the configuration read. Reverting the user's SOA still needs the user-SOA permission above. |

Use these exact scope names: the tenant-sync scopes start with **OnPremDirectorySynchronization**, not Directory.OnPremisesSynchronization. Their existence as Application permissions in the catalog does not establish app-only support for these specific APIs. [Tenant configuration read](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0), [Tenant configuration update](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-update?view=graph-rest-1.0).

For the forward SOA-only operation, `User.ReadWrite.All`, `Directory.ReadWrite.All`, and group-SOA write permission are not needed. If you automate additional discovery, grant only the read scopes for the calls you actually include:

| Optional Graph read | Documented permission for the intended read |
|---|---|
| Room's full user profile, synchronization attributes and assigned-licence baseline | `User.Read.All` |
| Group membership | `GroupMember.Read.All`; add `Group.Read.All` only if full group properties or dynamic rules are required by the chosen calls |
| Sign-in and directory audit evidence | `AuditLog.Read.All` |
| Conditional Access policy definitions | `Policy.Read.All` |
| Domain authentication type | `Domain.Read.All` |
| Federation configuration details | `Domain-InternalFederation.Read.All` |

These optional reads have their own role/service prerequisites and expose data beyond this room at the permission-grant level. Select and filter the actual requests to the task. If baseline checks are done in the admin portals and Exchange Online PowerShell, do not automatically grant all these Graph scopes. Exchange mailbox/RoomList reads use separate Exchange RBAC. [User read](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0), [Group read](https://learn.microsoft.com/en-us/graph/api/group-get?view=graph-rest-1.0), [Sign-in read](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0), [CA policy read](https://learn.microsoft.com/en-us/graph/api/conditionalaccessroot-list-policies?view=graph-rest-1.0), [Domain read](https://learn.microsoft.com/en-us/graph/api/domain-get?view=graph-rest-1.0), [Federation read](https://learn.microsoft.com/en-us/graph/api/domain-list-federationconfiguration?view=graph-rest-1.0).

Plan temporary access cleanup for the role and new grants added for this change. Disconnecting a session does not remove the application's existing consent. Preserve pre-existing grants belonging to shared tools; do not revoke an entire shared app's consent as an automatic cleanup step.

## User SOA requests

Read the starting state using the **verified user object ID**, not an assumed ID:

```http
GET https://graph.microsoft.com/v1.0/users/{verified-user-object-id}/onPremisesSyncBehavior?$select=isCloudManaged
```

For an ordinary synchronized account, expect `isCloudManaged=false` and verify its synchronized state separately. If already cloud managed, do not apply another conversion; validate its existing state and remaining dependencies. A missing or unreadable value is unresolved evidence.

Transfer that same user's authority:

```http
PATCH https://graph.microsoft.com/v1.0/users/{verified-user-object-id}/onPremisesSyncBehavior
Content-Type: application/json

{
  "isCloudManaged": true
}
```

Re-read the resource and require `isCloudManaged=true`. Record the SOA audit event and, after a successful normal Connect cycle, verify the connector blocks AD attribute updates for this account. Compare IDs, licences, group memberships, and mailbox baseline. Do not deliberately alter production AD attributes just to prove blocking. A successful API response alone is not room acceptance. Request review is not a service-supported dry run.

`IsExchangeCloudManaged` alone transfers only Exchange-attribute authority and does not achieve this full user-object transfer. Do not recreate the account/mailbox, clear its source anchor, move it out of sync scope, or disable tenant-wide sync. [Exchange attribute authority](https://learn.microsoft.com/en-us/exchange/hybrid-deployment/enable-exchange-attributes-cloud-management#frequently-asked-questions).

## Acceptance, rollback, and AD retirement

**Acceptance:** reboot the Android room and verify automatic passwordless sign-in, successful service authentication, calendar loading, a new booking, meeting join, audio/video, panels, licence/compliance status, and Pro Management health. Compare the exact user/device IDs, mailbox GUID/addresses, delegates, and group/RoomList memberships with the baseline. Review dynamic membership, group-based licensing and policy applicability after their actual processing; an immediate static membership snapshot is not proof that later evaluations are complete. A reboot is a validation step, not proof of every possible credential-recovery scenario.

**Credential preservation:** do not fully sign out, reset, reimage, delete the device, or replace it merely to test SOA. Microsoft documents that those relevant destructive actions lose or invalidate the device-bound credential, and current replacement/reimage recovery requires password-based setup followed by passwordless conversion. Account password changes are not part of this cutover. [Passwordless lifecycle and recovery](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts#troubleshooting-known-issues-and-faqs).

**Failure handling:** after an ambiguous/failed write, read the actual state before retrying. If authority changed but room checks fail, inspect identity, licensing, policy, membership, and service evidence before choosing recovery. Retaining AD does not automatically restore authority or guarantee that cloud and AD password states match.

**Rollback:** prepare the official procedure before cutover. It includes reconciling cloud changes/references, temporarily changing tenant-wide hard-match takeover protection, setting this user's `isCloudManaged=false`, allowing successful Connect takeover, and re-enabling protection. That protection change has a broader scope than the room and must be explicitly controlled; do not put it in an automatic room-recovery script. AD values may reassert. Rollback is complete only after takeover and verification of identity, mailbox, membership, and room operation. [Official rollback](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure#roll-back-soa-update).

**AD retirement:** retain the AD account at cutover. Remove AD dependencies and resolve group references in a separate change before considering retirement. The result of cutover is a cloud-authoritative user; retained AD group references can still exist during this phase. [AD management after SOA](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance).

For baseline commands and additional technical detail, use [the detailed runbook](/Users/jordan/Documents/ChatGPT/TeamsSOA/teams-room-soa-plan.md).
