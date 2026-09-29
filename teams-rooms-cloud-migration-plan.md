**Teams Rooms migration to cloud-only accounts — proposed change plan**

Prepared 29 September 2026. Based on your confirmation that all room mailboxes and all user mailboxes are already in Exchange Online, while Teams Rooms accounts and RoomLists originate in on-premises AD. No tenant configuration has been inspected or changed.

The recommended approach is to transfer the source of authority (SOA) of the existing objects to the cloud, preserving the accounts and mailboxes. Microsoft recommends cloud-only Teams Rooms resource accounts. Existing room calendars stay in Exchange Online throughout this plan. [Teams Rooms account guidance](https://learn.microsoft.com/en-us/microsoftteams/rooms/create-resource-account).

| Component | Target state | Administration |
| --- | --- | --- |
| Teams Rooms resource accounts | Existing Entra user objects, cloud-managed | Entra/Microsoft 365 |
| Room mailboxes | Existing Exchange Online room mailboxes | Exchange Online |
| RoomLists | Cloud-managed Exchange RoomList distribution groups | Exchange Online PowerShell |
| Account credentials | Tested cloud authentication with supported device controls | Entra and room-device administration |
| Dependent security/licensing groups | Cloud-managed where needed to remove the rooms' AD dependency | Entra, or Exchange for mail-enabled groups |

Full object SOA transfer is distinct from setting `IsExchangeCloudManaged` on a mailbox: that setting alone leaves the identity synchronized from AD. Microsoft documents full User SOA as an alternative for the account that owns an Exchange Online mailbox. [Exchange SOA mechanisms](https://learn.microsoft.com/en-us/exchange/hybrid-deployment/decommission-last-exchange-server#soa-transfer-mechanisms).

**1. Establish scope and capture the baseline**

Owners: identity administrator, Exchange administrator, Teams Rooms/device administrator, and local room support.

Create an explicit target manifest rather than selecting every room mailbox. Include the existing Entra object ID, room SMTP address, associated RoomList IDs, room location, device and panel names, migration wave, support owner, and rollback record. Distinguish Teams Rooms from bookable rooms without Teams devices.

For each selected room, capture:

- Entra ID, AD distinguished name and source anchor; UPN, primary SMTP, aliases, and LegacyExchangeDN.
- Exchange GUID, recipient type, visibility, calendar processing, regional settings, delegates and booking restrictions.
- Room location, capacity, building/floor and other Places metadata used for discovery.
- Effective Teams Rooms licensing and whether it comes from a group or direct assignment.
- Security-group membership; effective Conditional Access and Intune targeting; dynamic-group rules that depend on synchronized attributes.
- Existing authentication method, UPN-domain authentication, device platform, join/enrollment state, associated panels, calling configuration and current health.
- Representative accepted future and recurring bookings to test after the change.

For each RoomList, capture its Entra ID, Exchange identity, `RecipientTypeDetails`, SMTP aliases, owners, visibility, members and relevant delivery settings. Compare the on-premises and cloud representations after a successful synchronization cycle.

These read-only Exchange Online commands illustrate the evidence collection for individual targets; replace the example addresses:

```powershell
Get-Mailbox -Identity 'room@example.com' |
    Format-List ExternalDirectoryObjectId,ExchangeGuid,RecipientTypeDetails,
                PrimarySmtpAddress,EmailAddresses,LegacyExchangeDN,IsDirSynced

Get-CalendarProcessing -Identity 'room@example.com' | Format-List
Get-MailboxRegionalConfiguration -Identity 'room@example.com'

Get-DistributionGroup -Identity 'roomlist@example.com' | Format-List
Get-DistributionGroupMember -Identity 'roomlist@example.com' -ResultSize Unlimited
```

Store the full baseline securely in the existing change-management workflow. RoomLists are specially designated distribution groups; verify them and their membership through Exchange. [RoomList administration](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-resource-mailboxes#create-room-lists).

**2. Complete readiness checks**

Check the active and staging Entra Connect servers first. As of this plan's date, Microsoft's latest release is **2.6.92.0**. Microsoft states that Connect synchronization stops on **30 September 2026** for versions below **2.5.79.0**. Upgrade to a current supported release and establish healthy synchronization before the room cutover. The old SOA feature minimum, 2.5.76.0, is already retired. [Connect version history](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history).

Confirm the selected accounts meet current User SOA prerequisites. Assess AD FS/federated authentication, LDAP/Kerberos password dependencies, provisioning systems and remaining on-premises Exchange workloads. All user and room mailboxes being online satisfies the mailbox-location requirement; it does not establish the absence of public folders, relay or routing dependencies. Resolve any applicable support prerequisite before proceeding. Microsoft's overview requires no on-premises Exchange workloads and excludes AD FS-authenticated users; its preparation guidance and newer Exchange guidance describe the transition sequence. Exchange-server retirement needs its own dependency review. [User SOA prerequisites](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview), [Exchange transition guidance](https://learn.microsoft.com/en-us/exchange/hybrid-deployment/decommission-last-exchange-server).

Prepare the supported administrative role and the dedicated SOA permissions, `User-OnPremisesSyncBehavior.ReadWrite.All` and `Group-OnPremisesSyncBehavior.ReadWrite.All`, through the existing access workflow. A denied read remains missing evidence; do not compensate with broader credentials.

Freeze AD-side writes and provisioning for the selected objects after their final successful sync. Keep their AD originals and source anchors available for rollback. Moving an account out of synchronization scope before transferring SOA can trigger deletion of its cloud representation.

Read-only dry run: resolve every manifest ID, confirm its current SOA and mailbox/list association, compare memberships and effective assignments, and list the exact proposed operations without submitting them. This checks selection and prerequisites; it does not simulate SOA transfer or device sign-in. Rehearse those behaviors on representative test objects before the production pilot.

**3. Resolve group dependencies and transfer a pilot RoomList**

Map every AD-managed group that the pilot rooms depend on, including licensing, policy targeting, delegates and booking access. Choose cloud equivalents or transfer suitable room-specific groups before retiring AD accounts. A shared group containing unrelated users requires its own scope decision.

Microsoft's preparation sequence specifies groups before users. Keep converted objects within sync scope while references to AD-managed objects remain. [SOA preparation and sequence](https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment#sequence-of-steps-for-using-soa).

Proposed pilot: one low-impact RoomList and one or two representative Teams Rooms, subject to the actual dependency map. Converting a RoomList affects the management of the entire list and every member's discovery path, even if only two room accounts are converted. If all production lists have broad exposure, rehearse using a separate test list before selecting a production list.

Transfer the existing pilot RoomList's Group SOA by changing `onPremisesSyncBehavior.isCloudManaged` to `true` on its exact existing Entra group ID. Verify the SOA readback, audit event and subsequent Connect behavior. Distribution-group settings and membership are administered in Exchange Online after conversion. [Group SOA procedure](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure), [Mail-enabled group management](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-source-of-authority-self-service-group-management).

**Support qualification:** Microsoft documents Group SOA for distribution groups and separately defines RoomLists as distribution groups, but the reviewed SOA guidance does not explicitly name the RoomList subtype. Applying that support to RoomLists is an inference to validate in the pilot. Require the same list identity, `RecipientTypeDetails=RoomList`, addresses, owners, complete membership, visibility and working Room Finder before proceeding. [Room Finder configuration](https://learn.microsoft.com/en-us/microsoft-365-apps/outlook/calendaring/configure-room-finder-rooms-workspaces).

If in-place conversion cannot preserve supported RoomList behavior, stop that rollout. Stage a new Exchange Online RoomList with a unique temporary address and validate membership/discovery while retaining the original. Releasing and reassigning its original addresses is a separate cutover; ensure address uniqueness and retain any required legacy address compatibility. Rebuilding the list does not require rebuilding the room mailboxes.

**4. Transfer the pilot room accounts**

For each exact target user ID, transfer full User SOA by changing `onPremisesSyncBehavior.isCloudManaged` to `true`. Verify readback, audit records, cloud administration and that a subsequent successful synchronization cycle honors the new authority. Compare the same Entra ID, mailbox GUID, addresses and licensing with the baseline. [User SOA procedure](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure).

For rooms using passwords, establish and test the cloud credential, configure non-expiring passwords and avoid a forced password change at next sign-in. Coordinate credential updates across every room device and panel using the account. A cloud-owned account does not by itself prove independence from an on-premises authentication path; PTA does not apply to cloud-only users. [Password requirements](https://learn.microsoft.com/en-us/microsoftteams/hybrid-meetings-device-config-password), [PTA behavior](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta-how-it-works).

Check actual Conditional Access assignments before introducing any policy change. Password-based unattended room sign-in must not encounter interactive MFA or registration prompts. Preserve effective licensing, compatible controls and required device compliance. Any remediation must be explicitly targeted; an existing all-user policy still applies to pilot accounts unless its targeting is changed. [Teams Rooms Conditional Access guidance](https://learn.microsoft.com/en-us/microsoftteams/rooms/conditional-access-and-compliance-for-devices).

Resource-account conversion does not migrate the device's AD join, GPOs or Intune enrollment. Inventory those dependencies separately. Microsoft now documents a passwordless shared-device transition with its own prerequisites and recovery consequences; schedule that independently unless it is already the deployed authentication method. [Teams Rooms device authentication](https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-authentication), [Passwordless transition](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts).

**5. Validate and progress through waves**

Use this proposed acceptance checklist for each pilot and wave:

| Test | Required result |
| --- | --- |
| Identity and mailbox comparison | Same Entra ID and Exchange GUID; expected addresses and room type |
| Calendar continuity | Existing future and recurring meetings remain present |
| Existing organizer operations | Update/cancel a test series and an individual occurrence successfully |
| New bookings | Single and recurring bookings follow existing acceptance/conflict rules |
| Room discovery | Expected list and rooms appear in Outlook on the web and desktop Room Finder |
| Direct booking | Booking by the existing room SMTP address succeeds |
| Device operation | Calendar and join button work; Teams meeting, audio/video and sharing succeed |
| Fresh authentication | Successful reauthentication and restart, including associated panels |
| Existing optional features | PSTN, third-party joins and delegates work where currently used |
| Policy and licensing | Intended groups, license service plans and compliance remain effective |
| Synchronization | Successful cycle preserves authority and membership without unexpected changes |

These are operational acceptance tests, not claims that the tenant has passed them. Compare both the member count and exact member identities. Inspect failures in sign-in, Exchange, device and synchronization logs.

Proposed observation period: two business days covering normal bookings and an overnight restart, adjusted to the room's usage. This is a rollout option, not a propagation guarantee. Allow Room Finder/client caches to settle and verify actual discovery before advancing.

Stop further waves for any identity/GUID mismatch, deleted object, missing booking, license loss, unexpected membership/policy change, sign-in failure, or failed room discovery. Use a manual checkpoint after each wave; this plan supplies no automatic rollout controller.

Roll out by building or RoomList, with waves small enough for available local support to recover every affected device during its maintenance window. Keep Entra Connect operating for other synchronized identities.

**6. Rollback and retirement**

Rehearse rollback on a disposable representative test account/group before the production pilot. Retain AD originals and the baseline throughout an agreed rollback window. Record every cloud-side change, including passwords and membership, so it can be reconciled before AD resumes authority.

User SOA rollback includes resolving cloud references, temporarily permitting the documented hard-match takeover, setting the selected object's SOA back to AD, and completing synchronization. Restore the hard-match protection afterward. Group rollback also requires resolving cloud-user references; coordinate RoomList and room-account reversal rather than reverting a list independently. Restore the recorded memberships and authentication configuration, maintain license entitlement, and rerun the acceptance checks. [User rollback requirements](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure#roll-back-soa-update), [Group rollback requirements](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure#roll-back-soa-update).

After successful rollout and the rollback window, retire AD objects only when no AD-managed group or application still needs them. Deleting a transferred account's AD object removes its membership from AD-managed groups and their cloud representation; that can affect licensing or access. Recheck every such dependency before retirement. [User SOA operational guidance](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-guidance).

Update the provisioning runbook so new Teams Rooms accounts and RoomLists are created and managed in the cloud. Assign named owners for credentials, booking rules, lists and device support. Any broader Exchange, AD or device-domain decommissioning proceeds as a separate change.

The plan is ready for tenant-specific discovery. Exact target IDs, current Connect version, authentication configuration, policy/group exposure, maintenance windows and rollback constraints remain to be established before an executable cutover runbook can be finalized.
