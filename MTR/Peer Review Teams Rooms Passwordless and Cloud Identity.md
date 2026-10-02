# Peer Review: Teams Rooms Passwordless and Cloud Identity

Oct 2, 2026 · Review of the CAB submission v1.1, passwordless runbook v1.1 and cloud identity migration plan v1.1

## Verdict

The product facts are largely accurate, but the set is not ready for CAB. Two rollback and dependency constraints from Microsoft's guidance are missing or understated, and the submission buries its decision under runbook detail.

Recommendation: revise before submission. The revised set restructures the material as one CAB submission of about 2,000 words, two runbooks and a reference list, and closes the gaps below.

## Material findings

Eleven findings change what the CAB is told or what operators do; two are High because they affect rollback and half the project's scope.

| # | Severity | Where | Finding | Revision |
| --- | --- | --- | --- | --- |
| 1 | High | Cloud plan, CAB backout | Microsoft requires an account to leave all cloud-managed groups and access packages before its authority returns to AD ([source](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure)). With RoomLists converted first, any rollback removes the room from Room Finder and group licensing. The documents' instruction not to remove members cannot be met | Rollback states the trade-off, stages a direct licence, and re-adds membership after takeover |
| 2 | High | CAB Gate 1, cloud plan | User authority transfer needs every mailbox in Exchange Online and no on-premises Exchange workloads ([source](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview)). This tenant-wide condition sits inside Gate 1 while Exchange decommissioning is out of scope, so CAB is not told it can stop phases 3 to 6 | Named as a tenant-level dependency in the change summary, risk register and Gate 1 |
| 3 | Medium | Gate 0, cloud plan | Connect Sync must run 2.6.84.0 or later with application-based authentication by 7 April 2027 or sync stops ([source](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history)). Not mentioned; nor that 2.5.76.0 left support on 1 September 2026 | Both dates added to Gate 1 and the risk register |
| 4 | Medium | Passwordless runbook | Pro Management can pause a single Android version, or all Android updates for two weeks, and its ring durations apply to Windows and Android alike ([source](https://learn.microsoft.com/en-us/microsoftteams/rooms/androidupdatemanagementinpmp)). Only the unpausable Admin Agent updates are mentioned | Version pauses used during windows |
| 5 | Medium | CAB, passwordless runbook | Set as Resource can be applied on its own before conversion ([source](https://learn.microsoft.com/en-us/microsoftteams/rooms/set-as-resource-account-for-shared-teams-devices)). Treating it as inseparable couples a behaviour change with the authentication change | Optional step one wave early, to isolate faults |
| 6 | Medium | Cloud plan phase 4 | Identity waves copy the eight platform and site waves, although the transfer is a directory change. Microsoft's sequence is groups before users | Identity waves grouped by RoomList, same maximum sizes |
| 7 | Medium | Cloud plan Gate 1 | Eligibility omits Microsoft's exclusions for reference-valued attributes and attributes written by other on-premises systems, such as Certificate Services ([source](https://learn.microsoft.com/en-us/entra/identity/hybrid/prepare-user-source-of-authority-environment)). Converted groups also lose extension attributes 1 to 15 | Added to Gate 1 and the group checks |
| 8 | Low | All three | GCC, GCC High, DoD and 21Vianet caveats, government Admin Agent builds and analyser limits do not apply to this commercial-cloud tenant | Removed |
| 9 | Low | CAB, cloud plan | A gate holds the pilot until a v1.0 and beta publication discrepancy is resolved. Microsoft's configuration guides use v1.0 for both transfer and rollback | Calls validated in the pilot instead of a separate gate |
| 10 | Low | Passwordless runbook | Dated snapshots of the latest Admin Agent, Authenticator, Intune and Logitech builds will be stale by the first window | Published floors only; live versions recorded per window |
| 11 | Low | CAB, passwordless runbook | The claimed September 2026 general-availability announcement is not needed for any decision, and Microsoft's migration article does not state it | Removed |

## Structure and readability

The set restates the same gates, waves and recovery steps up to three times, so a CAB reader cannot find the decision quickly and operators risk following a drifted copy.

- **Decision buried.** The submission runs to over 4,000 words, and its decision table is followed by Graph permissions, attribute lists and runbook steps. The revision keeps decision, impact, risk and backout in the submission and moves procedure to the runbooks.
- **Triple maintenance.** Wave tables, gates, recovery and stop conditions appear in all three documents with small wording differences. Each fact now lives in one place, and the submission links to it.
- **Sentence density.** Many sentences carry three or four conditions or chains of prohibitions, which hides the action. Steps are now numbered and imperative, one action each.
- **Review history in a deliverable.** The runbook's verification record describes changes from an earlier draft rather than how to operate. Removed.
- **Sequence told in prose.** Seven phases and their gates were only described in text. A roadmap diagram now shows the order and the hinge at Gate 1.
- **Gates as paragraphs.** Gate criteria could not be ticked off as evidence arrived. They are now checklists.

## Claims verified as accurate

The core product claims match Microsoft's current documentation and are carried into the revised set.

| Claim | Source |
| --- | --- |
| Windows floor: 24H2 build 26100.8655, app 5.6.135.0, same-tenant Entra join, hybrid join unsupported | [Passwordless migration article](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts) |
| Proxy-configured Windows PCs and Crestron Windows devices not yet supported | [Passwordless migration article](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts) |
| Android and panel floors for Teams app, Authenticator 6.2605.3066 and Admin Agent | [Passwordless migration article](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts) |
| Credential held in Keystore or TPM, no fixed expiry, lost on sign-out, reset or reimage | [Passwordless migration article](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts) |
| Windows backout by OEM image or recovery tool reset; Android by full sign-out | [Passwordless migration article](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts) |
| Deleting the Entra device object revokes the credential; Windows loses its Entra join | [Passwordless migration article](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts) |
| Migration applies Set as Resource, removing post-meeting chat, file and recording access | [Set as Resource article](https://learn.microsoft.com/en-us/microsoftteams/rooms/set-as-resource-account-for-shared-teams-devices) |
| Require MFA unsupported on Windows; authentication strength and hybrid-joined grants unsupported on both platforms | [Supported policies matrix](https://learn.microsoft.com/en-us/microsoftteams/rooms/supported-ca-and-compliance-policies) |
| Android updates only 00:00 to 05:00 device-local; ring confirmation irreversible; Admin Agent updates not pausable | [Android update management](https://learn.microsoft.com/en-us/microsoftteams/rooms/androidupdatemanagementinpmp) |
| User authority transfer generally available since January 2026 | [Entra releases](https://learn.microsoft.com/en-us/entra/fundamentals/whats-new) |
| After transfer, isCloudManaged is true and onPremisesSyncEnabled is null | [User SOA configuration](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-user-source-of-authority-configure) |
| AD FS federation blocks transfer; third-party federation needs manual AD password upkeep | [User SOA overview](https://learn.microsoft.com/en-us/entra/identity/hybrid/user-source-of-authority-overview) |
| Hard-match setting change: Global Administrator only, delegated permission only | [Graph update reference](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-update?view=graph-rest-1.0) |
| Nested groups convert one at a time, lowest first; mail-enabled groups then managed in Exchange Online | [Group SOA configuration](https://learn.microsoft.com/en-us/entra/identity/hybrid/how-to-group-source-of-authority-configure) |
| Connect Sync 2.6.92.0 and provisioning agent 1.1.2505.0 are the current releases | [Connect history](https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-version-history), [agent history](https://learn.microsoft.com/en-us/entra/identity/hybrid/cloud-sync/reference-version-history) |

## Scope of review

The three supplied documents were reviewed against Microsoft Learn on 2 October 2026; tenant configuration was not examined.

- **Not reviewed:** the inventory PowerShell script, which was referenced but not supplied, and Logitech release notes.
- **Not verified, so not carried forward:** the Pro Management provisioning-code details, AOSP record-deletion behaviour and the Entra and Intune enrolment limits. They do not affect any decision in the revised set.
- **Assumptions inherited from the originals:** Entra Connect Sync is the sync engine, all room mailboxes are in Exchange Online, and the estate is 50 rooms as stated.
