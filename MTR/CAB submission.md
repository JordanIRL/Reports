# Teams Rooms Passwordless and Cloud Identity Change

Change Advisory Board submission · Oct 2, 2026 · Version 2.0 · CAB decision pending

## Decision requested

The CAB is asked to grant conditional approval for one project. It moves all 50 Teams Rooms to passwordless sign-in, transfers their identities from Active Directory (AD) to Microsoft Entra ID, then retires the related AD objects.

Each phase starts only when its release gate is evidenced in the change record. Approval is not evidence that any gate has passed.

**Recommended classification:** normal change, initial risk High. The rating reflects authentication, group and identity-authority changes across production rooms. The CAB sets the final rating; a review to Medium is proposed after both pilots are accepted.

| Decision item | Authority requested | Condition |
| --- | --- | --- |
| Project scope | Approve the scope, phases, acceptance criteria and recovery procedures in this submission | Any change to scope, recovery or security controls returns to CAB |
| Phase releases | Delegate go or no-go for each phase to the change owner and affected service owners | Gate evidence attached to the change record before release |
| Resource-account behaviour | Accept that room accounts lose post-meeting chat, file and recording access | Service owners confirm no workflow depends on that access |
| Password cleanup | Approve scrambling each room account password | Every device using the account has passed acceptance |
| Rollback exception | Authorise a supervised, time-bound relaxation of the tenant hard-match protection, used only for identity-authority rollback | Global Administrator under security-owner supervision; protection restored and verified |
| AD retirement | Authorise retirement of manifest-listed AD objects only | 30-day retention elapsed, dependencies cleared, separate phase release |

Change references, windows, named owners and the CAB decision are held in the change record. No tenant or device changes have been made.

## Change summary

The change covers 50 rooms: 45 Android and 5 Windows, at local and remote sites.

| Platform | Local rooms | Remote rooms | Total |
| --- | --: | --: | --: |
| Teams Rooms on Android (Logitech Rally Bar, Tap IP controller, Tap Scheduler) | 35 | 10 | 45 |
| Teams Rooms on Windows (compute and peripherals confirmed in discovery) | 5 | 0 | 5 |
| Total | 40 | 10 | 50 |

Room count is not account count. A panel signed in with its room's account moves with that account. A standalone panel account is a separate identity and is added to the approved object manifest.

| Area | Current state | Target state |
| --- | --- | --- |
| Room sign-in | Stored resource-account password | Device-bound credential in Android Keystore or the Windows TPM; password scrambled |
| Identity authority | AD, synchronised by Entra Connect Sync | Microsoft Entra ID (cloud-managed) |
| Room lists | RoomLists managed in AD | RoomLists cloud-managed and administered in Exchange Online |
| Mailboxes and bookings | Exchange Online room mailboxes | Unchanged: same mailbox, addresses, calendar and bookings |

The project has two acceptance milestones. **Cloud authority** is reached when Entra ID owns each account while its AD object is retained for references and rollback. **AD independence** is reached when no authentication, licensing, policy, discovery or application path needs the AD object, and the listed objects are retired.

**Tenant-level dependency.** Microsoft supports identity-authority transfer only when all mailboxes are in Exchange Online and no on-premises Exchange workloads remain. The Exchange owner evidences this before Gate 1. If it is not met, phases 3 to 6 are held; the passwordless phases are unaffected.

**Out of scope:** sync shutdown, AD or Exchange hybrid decommissioning, mailbox moves, federation changes, Security Defaults, tenant-wide compliance defaults and Windows computer-object retirement. A RoomList or shared group with members outside the 50 rooms needs an assessed scope amendment before conversion.

## Service impact

Each room is unavailable for its change window, and existing bookings and room addresses are preserved.

- **Window reservation.** Each changing room and its panels are reserved for the window. Conversion, restarts and testing interrupt room use; no zero-downtime claim is made.
- **Return to service.** A room returns to service only after its meeting, calendar, panel, security and management tests pass.
- **Post-meeting access.** After conversion, the room account leaves meeting chats when meetings end and loses access to shared files and recordings. The migration applies this automatically, and no backout in this plan reverses it.
- **Windows sign-in.** Windows rooms sign in to Windows as the resource account instead of the local Skype account. Returning from admin mode to the room interface then needs a reboot.
- **Windows recovery.** Returning a Windows room to password sign-in needs a full device reset; Android only needs a sign-out. Windows recovery is longer and needs on-site support.
- **Identity transfer.** The authority transfer is a directory change with no planned device action. Pilot rooms are still reserved, because credential continuity through the transfer must be proven.
- **Licensing.** Unchanged. Teams Rooms Pro covers each room and any panel sharing its account; a standalone panel needs a Teams Shared Space licence.

## Delivery plan and release gates

Delivery runs as seven phases, and no identity-authority change starts until every approved account is passwordless.

&#91;embedded content: delivery roadmap · 7 phases, 6 release gates\]

Gate 1 is the hinge between the two tracks. A failed gate holds its phase; read-only discovery for later phases can continue meanwhile.

| Wave | Rooms | Composition |
| --- | --: | --- |
| Pilot | 4 | 2 local Android, 1 remote Android, 1 local Windows |
| 1 to 3 | 33 | Local Android, 11 per wave |
| 4 to 6 | 9 | Remote Android, 3 per wave |
| 7 to 8 | 4 | Local Windows, 2 per wave |
| Total | 50 | 45 Android, 5 Windows |

Phase 2 uses these waves. Local Android, remote Android and Windows run as separate tracks; each wave advances after the previous one is accepted in at least one business day of normal use.

Phase 5 keeps the same maximum wave sizes but groups accounts by RoomList. Each converted RoomList and its member rooms then move together, matching Microsoft's groups-before-users order.

**Planning allowance:** 8 to 10 working weeks from Gate 0 to the final identity wave, then the 30-day retention period. Measured pilot durations replace this estimate before production waves are scheduled.

## Risk assessment

The residual risk is service interruption to individual rooms during change or recovery windows; controls contain it to one account at a time.

| Risk | Control | Remaining exposure |
| --- | --- | --- |
| A room or panel loses sign-in | Password cleanup only after every device on the account passes; recovery rehearsed per platform before the pilot | Recovery needs attended sign-in with a temporary password |
| Windows reset extends an outage | Eligibility proven first: build, app, same-tenant Entra join, no proxy, not Crestron; rebuild time measured on a spare | A reset is the only Windows backout |
| Booking or Room Finder regression | Mailbox, calendar and RoomList baselines compared after every transition | Limited to what the tests cover |
| Group change wider than the pilot | Full membership and assignment review per RoomList and group; wider impact needs a scope amendment | Dependent on manifest accuracy |
| Credential does not survive the identity transfer | Pilot proves continuity by restart, fresh sign-in and normal use before scaling | Not documented by Microsoft; pilot evidence only |
| Identity rollback removes group membership | Microsoft requires a user to leave cloud-managed groups before rollback; direct licence assignment is staged first | Room missing from Room Finder until re-added after takeover |
| Tenant exposure during rollback | Hard-match protection relaxed only in a supervised window, then restored and verified | Short tenant-wide window per rollback |
| Exchange prerequisite unmet | Exchange owner evidence required at Gate 1 | Identity phases held; passwordless benefits retained |
| Sync engine falls out of support | Connect Sync on a supported build; 2.6.84.0 or later with application-based authentication is mandatory by 7 April 2027 | Separate infrastructure change if an upgrade is needed |
| Post-meeting access loss breaks a workflow | Service-owner acceptance before conversion; Set as Resource can be applied a wave early to surface issues | Not reversible within this plan |
| Android update collides with a window | Android auto-updates run 00:00 to 05:00 device-local time; specific versions paused in Pro Management during windows | Mandatory Admin Agent updates cannot be paused |

## Backout and recovery

Recovery starts when a stop condition cannot be cleared before the backout decision point: the window end, less the measured recovery time, less the agreed margin.

| Failure | Recovery | Limit |
| --- | --- | --- |
| Conversion fails | The migration reverts automatically; device state is verified, the cause fixed and the conversion retried | Actual device state is checked before relying on the automatic revert |
| Android room or panel needs password sign-in | Full account sign-out, locally or from Pro Management; sign-in with a temporary password issued at the current authority; reconversion after acceptance | The device-bound credential is lost and must be recreated |
| Windows room needs password sign-in | Reset with the OEM recovery image or Microsoft's recovery tool; Entra join and management restored; sign-in; reconversion | Longest recovery; on-site support required |
| Single account identity rollback | AD record reconciled; account removed from cloud-managed groups; hard-match block relaxed; authority returned to AD; next sync takes over; block restored | Global Administrator required; temporary Room Finder gap |
| RoomList rollback | Cloud members removed in Exchange Online; authority returned to AD; sync takeover; membership verified | Members restored once their accounts are AD-managed again |
| Compromised endpoint | Exact Entra device object deleted; the device signs out at its next token refresh | A Windows room also loses its Entra join |

Two outcomes are not reversible within this plan: the Set as Resource classification, and deleted AD objects after retirement. The 30-day retention period therefore closes identity-authority rollback.

If recovery may overrun the window, the impact is declared through the incident process and alternative meeting space is arranged. No decision waits for the next booking.

## Ownership, communications and closure

The change owner coordinates every phase release with the service owners below; named individuals are held in the change record.

| Activity | Role and access |
| --- | --- |
| Passwordless conversion | Teams Administrator in Teams Rooms Pro Management |
| Password cleanup | User Administrator for cloud-managed accounts; the AD password authority for synchronised accounts |
| User and group authority transfer | Hybrid Identity Administrator scoped to an administrative unit, with User- and Group-OnPremisesSyncBehavior.ReadWrite.All |
| Hard-match protection change | Global Administrator with delegated OnPremDirectorySynchronization.ReadWrite.All, under security-owner supervision |
| RoomList membership | Exchange Administrator, using Exchange Online tools |
| Conditional Access and compliance | Security and Intune owners |
| Room testing and site support | Room engineer and local or remote site contact |

Privileged roles are activated just in time for each window.

**Communications.** Before each wave, the service desk, facilities and affected room users receive the room list, window, support route and the post-meeting access change. At window start, the engineer confirms no meeting is in progress. At window end, verified availability or an overrun and its alternative is published.

**Closure criteria.**

- Every approved account and endpoint is accepted, with exceptions closed or formally re-scoped by CAB.
- Cloud authority and AD independence are each evidenced per account.
- Hard-match protection is verified at its recorded baseline value.
- Listed AD objects are retired and room service is re-verified afterwards.
- Operations accept handover of cloud identity, RoomList and recovery procedures.
- Authentication incidents and site visits are compared with the pre-change baseline.

## Supporting documents

The runbooks hold the gate checklists, procedures, tests and recovery steps that this submission approves.

- Passwordless runbook: Phases 0 to 2, from readiness to password cleanup.
- Cloud identity runbook: Phases 3 to 6, from RoomList conversion to AD retirement.
- References: Microsoft documentation supporting the product behaviour described.

The read-only inventory script and the reconciled object manifest are held in the restricted evidence location referenced by the change record.
