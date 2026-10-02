# Microsoft Teams Rooms Passwordless Migration

## Migration design and operational runbook

Version 1.1 | Verified against public Microsoft and Logitech documentation on 1 October 2026

## Executive recommendation

Migrate eligible Android and Windows rooms through Teams Rooms Pro Management while preserving their existing Exchange room mailboxes, booking addresses, calendars and Teams Rooms Pro assignments. The intended benefit is fewer incidents that require a person to re-enter a reusable room password. A normal restart and a later account-password change should preserve a successfully converted device's authentication credential. Android and Windows have different prerequisites, credential stores and recovery procedures. [1]

The user-confirmed planning scope is 50 rooms: 35 local Android, 10 remote Android and 5 local Windows rooms. Reconcile each room, account and physical endpoint before scheduling. Begin with four rooms: two local Android, one remote Android and one local Windows. Follow with three local Android waves of 11, three remote Android batches of 3 and two local Windows batches of 2. These counts are project recommendations, not Microsoft requirements.

Keep password cleanup behind an account-level acceptance gate. A room and its associated Teams panels can share one resource account; every endpoint still using that account must be accounted for before its password becomes unknown. Prepare platform-specific recovery and temporary-password bootstrap for credential loss, reset, reimage or replacement. Also validate the expected Set as Resource behaviour: after the meeting, the room account loses meeting-chat participation and access to shared files and recordings. [1][2]

This runbook supports one project approval covering passwordless delivery, assessed group and User SOA transfer, and gated AD retirement. Complete and accept the passwordless scope before production authority changes. A blocked Windows or Android account remains an open exception; accepting a reduced scope requires a recorded CAB amendment. Product claims have been checked against public documentation; tenant configuration, installed versions, the reconciled object manifest and pilot outcomes require live evidence. No tenant changes or migration jobs are implied by this report. Administrative fields and phase releases are held in the associated change record.

## Scope and evidence

### Reported estate

The supplied report originally described an Android-only estate. The user has corrected it to 45 Android rooms and 5 Windows rooms, with all Windows rooms local: 35 local Android, 10 remote Android and 5 local Windows. The Android design includes Logitech Rally Bar, touch controllers and Tap Scheduler panels; the Windows manufacturers, models, compute units, controllers and associated panel topology require inventory. Existing Exchange `RoomMailbox` objects and Teams Rooms Pro licences remain reported discovery inputs, not live-verified findings.

Record the actual tenant ID and cloud, room and endpoint platform, authoritative identity source, mailbox location, account UPN and SMTP address, licence service plans, installed components, Conditional Access policies, Intune records, scheduler account topology, network egress and recovery contacts. For Windows, also capture actual Entra/device join, AD computer dependencies, Windows build, TPM state, proxy/certificate configuration and administrative recovery access. For hybrid identities, identify the owner of password and attribute changes. A source-report statement that an account is synchronised does not establish the password writeback or federation design.

### Changes in scope

The project changes device authentication using existing resource identities. Retain mailbox contents, booking rules, delegates, room-list membership and Places attributes. Microsoft requires the resource-account UPN to match its SMTP address; discover any mismatch and resolve it as a separate identity exception. Migration automatically applies Set as Resource, so the chat, file and recording restrictions are an expected change to review with stakeholders. [1][2][3]

A Microsoft 365 room resource account is different from a Teams Phone resource account for an auto attendant or call queue. Use the existing room identity rather than creating a replacement mailbox or assigning a Teams Phone Resource Account licence. Each room installation needs its own identity; do not share one account across different rooms. [3][4]

A panel signed in with its room's resource account is covered by that room's Pro licence and transitions alongside the room. This account-level dependency also applies to Android panels associated with a Windows room: do not clean up the shared password until every endpoint is converted and accepted. A standalone panel account has a separate licensing and migration lifecycle; Teams Shared Space is the current standalone shared-device licence name. Teams Rooms Basic does not license panels, and Teams Shared Space does not license a Teams Room. A Tap IP controller is part of the Android room system, not an extra booking mailbox; discover the actual Windows controller design. [1][4][37]

### Availability and portal gates

Microsoft's September 2026 Entra announcement places resource accounts for Teams devices in general availability. This does not establish availability in every sovereign cloud. Teams Rooms Pro Management resource-account management is explicitly unavailable in GCC; verify other clouds with the tenant's current feature availability before committing to this workflow. [5][6]

If the inventory is empty, use the documented initial `Planning > Inventory > Get Data` process and allow approximately 15 minutes for replication. Hidden-from-address-list room accounts do not appear in this resource-account inventory. Investigate an intentional hidden-room design before changing visibility. A `Secured = Yes` value shows resource classification; it does not alone prove successful passwordless conversion. [2][6]

## Authentication and recovery model

Microsoft stores the device-bound credential in Android Keystore on Android and in the TPM on Windows. The existing account password remains immediately after conversion; this is not a personal Authenticator passkey enrolment or an administrator-managed certificate deployment. The credential has no specified expiry, while service tokens still refresh. Credential loss or device replacement requires the supported platform recovery, temporary-password bootstrap and conversion again. Android sign-out can discard its credential; returning a converted Windows room to password authentication requires an OEM-image or Microsoft recovery-tool reset. [1]

Windows conversion also changes the Windows sign-in from the local Skype account to the room resource account and migrates the Teams Rooms settings. Accessing administrative mode remains available; returning from admin mode to the Teams Rooms experience requires a reboot because the local Skype sign-in is no longer available. Record administrative access and recovery before conversion, and do not copy Android sign-out instructions onto Windows. The resource-account User SOA change planned later does not change the Windows computer's identity or join state. [1]

The desired operating sequence is:

```text
Existing room account and working device
  -> Inventory and readiness evidence
  -> Passwordless conversion
  -> Functional tests and restart
  -> Observation period
  -> All associated endpoints accepted
  -> Password cleanup
  -> Restart and functional tests again
```

For cloud-only identities, use the supported Pro Management cleanup workflow or an authorised reset process to make the password complex and unknown. For synchronised identities, scramble at the on-premises password authority and respect the actual synchronisation design. Do not infer that the cloud portal owns the password. Preserve the applicable non-expiring-password configuration unless a separately reviewed account-policy change justifies altering it. [1][3][7]

Password rotation is not credential revocation for a converted endpoint. For intentional containment, Microsoft documents deleting the exact associated Entra device identity; the endpoint is signed out at its next authentication refresh, while the account and its other devices remain unaffected. On Windows, this also breaks the PC's Entra join. Identify the correct device before acting and plan platform-specific service recovery. Separately, deleting an active Android Intune AOSP record can trigger a factory reset at check-in. These actions must not be used as routine inventory tidying. [1][8]

## Device and software readiness

### Published passwordless minimums

The following Android and panel values are the current published floors, not a recommendation to stop updating at these builds. They do not apply to Windows. Validate the installed packages and the account/device eligibility shown in Pro Management. [1]

| Component | Teams Rooms on Android | Teams panel |
| --- | --- | --- |
| Android | 10 or later | 10 or later |
| Teams application | `1449/1.0.96.2026129709` | `1449/1.0.97.2026164101` |
| Authenticator | `6.2605.3066` | `6.2605.3066` |
| Admin Agent as printed in migration article | `1.0.0202606082157` | `1.0.0202606082157` |
| Management | Account and device visible and eligible in Pro Management | Same requirement |

The migration article's Admin Agent spelling differs from the release history, which lists June's AA830 as `1.0.0.202606082157.product`. Do not invent a version-normalisation rule or approve a device solely by comparing date-like digits. Use the live package, the release history, actual cloud availability and portal eligibility together. [1][9]

### Android Logitech snapshot on 30 September 2026

| Endpoint | Microsoft firmware table | Bundled applications and action |
| --- | --- | --- |
| Rally Bar | `2.1.204` AOSP, released 28 September | Rooms `2026129709` and Authenticator `6.2606.4246` meet their floors; AA856 `1.0.0.202607160723.product` still requires confirmed portal eligibility |
| Tap IP controller | `2.1.328` AOSP | Verify pairing, supported controller software and OEM update coordination |
| Tap Scheduler | `2.1.303` AOSP, released 10 August | Panels `2026164101`, Authenticator `6.2605.3066`, AA820 `1.0.0.202604060507.product`; Admin Agent needs an eligible update |

These are documentation snapshots, not observed device versions. The older Rally Bar `2.1.176` bundle cited in the source report remains a useful example of stale Microsoft apps, but it is no longer the latest entry. Firmware and Microsoft app updates have separate lifecycles. [9][10][11][12]

Logitech publishes Tap Scheduler `2.1.328` with newer components, but the retrieved Microsoft panel table lists `2.1.303`. Verify Microsoft certification and the supported release actually offered to the model before broad deployment. Logitech's `2.1.303` notes specifically fix an Admin Agent update failure on Auto Proxy networks; check this when a scheduler remains on AA820. [11][13][14]

The current public Rooms release history lists `1449/1.0.96.2026261804`; the preceding `2026249711` addresses remaining EWS calendar fallback. Microsoft says to use that build or newer before disabling EWS. Keep Exchange API changes separate from this project, but add calendar readiness to the deployment checks. The certified-hardware table also has a distinct minimum-version column that must not be mistaken for its bundled-client column. [10][15]

The latest public management-app notes list AA870 `1.0.0.202609172331.product`, Authenticator `6.2607.4685` and Intune `26.6.3`. AA830 was not released to government clouds; newer releases have their own cloud rollout conditions. Use the supported release offered to the actual model and cloud, test it, then record installed values. A globally latest published build is not proof that it is available to every endpoint. [9]

### Android management transition and network

Use Pro Management as the primary operational view. Microsoft currently schedules retirement of overlapping Teams admin centre workflows for October 2026, while some related pages still show September. Tenant Message Center notices and actual rollout determine the available route. Confirm the device is connected and manageable in Pro Management, rather than merely listed. Import configuration profiles as Settings Templates and tags as device groups where needed. [16]

Keep management-ring adoption separate from passwordless rollout. Adopting Pro Management Android update rings is documented as irreversible and accelerates default deployment intervals. Review the rings, maintenance window and paired-device coordination before adopting them. Do not inadvertently opt into a new update timetable while performing the authentication change. [17]

Android automatic updates currently use the fixed 00:00 to 05:00 device-local window and postpone installation when a device is in use. Mandatory Pro Management Admin Agent updates cannot be paused. Record these constraints when assessing a pilot freeze or remote-site support coverage. [17]

Pro Management requires the supported Admin Agent and outbound access to its cloud-specific Android IoT Hub endpoints. Validate DNS, time, TLS, Microsoft 365 and Intune connectivity, proxy behaviour and IoT Hub connection state. Android devices do not support authenticated proxies or tenant restrictions. Use Microsoft's Android-specific endpoint list for the actual cloud, including `agent.rooms.microsoft.com` and the applicable regional/device IoT Hub hosts; do not copy a Windows-only allowlist. [18]

Logitech's transition guide contains known-issue links that are incomplete or mismatched. Record digital-signage use and update-path problems, then check applicability with current release notes or support before scheduling. Do not infer affected versions or apply an undocumented workaround from those broken links. [19]

### Windows readiness and support gates

Microsoft supports Windows passwordless resource accounts through the same Pro Management migration workflow, with separate Windows eligibility. The dedicated article requires Windows 11 24H2 build `26100.8655` or later, Teams Rooms app `5.6.135.0` or later, the PC Entra joined to the resource account's tenant, an appropriate licence and account/device visibility in Pro Management. Hybrid join is unsupported for this workflow. Check the TPM and the actual offered software and portal eligibility. Windows 11 25H2 is supported and recommended with Teams Rooms app `5.6.210.0` or later, but lifecycle support alone does not prove passwordless eligibility; confirm the specific installed-OS migration path before conversion. Do not downgrade an otherwise eligible 25H2 room merely to match the 24H2-named floor. The Windows app release snapshot is `5.7.112.0`, released 28 September 2026. Record the installed value and supported release offered to the device; Windows Teams Rooms app updates use Pro Management rather than Microsoft Store. [1][38][39]

Confirm the supported Windows Enterprise or IoT Enterprise edition and servicing channel. Windows Pro/Home and LTSC editions are unsupported for Teams Rooms; do not override the Teams Rooms servicing policies to force an unvalidated feature release. [38]

The current passwordless article does not support proxy-configured Windows rooms or Crestron Windows devices. Hold an affected room and its shared-account cleanup until a supported design is proven. All five Windows models and proxy paths must therefore be discovered before promising full-estate completion. Any needed device-join, GPO, network-certificate or management transition must be discovered and reviewed as an exact prerequisite change; this runbook does not prescribe a universal domain exit or reimage. Preserve local administrative access, OEM recovery media and configuration evidence, and test the Windows reset/recovery path on a suitable spare or scheduled scenario. [1][40][41]

Where Entra join preparation is required, use the supported existing deployment or manual-join route. Review the selected resource-account join permission rather than broadening it to every user. Autopilot and Autologin are supported deployment options, not prerequisites to rebuild an already working PC. Local administrator or LAPS recovery is distinct from the resource-account password; assess OEM peripheral-pairing implications before changing administrative password rotation. [40][42]

Use Windows-specific management, networking and device-security evidence. Android Admin Agent floors, AOSP enrolment, IoT Hub allowlists, update rings and MAC/verification-code provisioning are Android requirements and must not be applied to a Windows PC. Windows computer identity, Entra join, device compliance and the room resource account are separate objects and acceptance checks. [1][20][21]

## Conditional Access and Intune readiness

### Resource account policy design

Create or validate scoped groups of room resource accounts, then inspect every effective policy that targets them, including all-user policies and exclusions. Replace unsuitable human-user coverage with tested room-specific controls. A group name alone is not evidence of pilot scope or effective protection. Use the platform columns in the current supported-policy matrix; apply Android and Windows targeting deliberately, especially where Android panels share a Windows room account. [20][21]

| Control | Android and associated panels | Windows |
| --- | --- | --- |
| Require compliant device | Supported; establish healthy AOSP management and policy assignment first | Supported; prove Windows enrolment and compliance first |
| Named network location | Optional supported restriction; validate egress and bootstrap | Optional supported restriction; validate egress and bootstrap |
| Sign-in frequency | Unsupported | Unsupported |
| Authentication strength or hybrid-joined-device grant | Unsupported | Unsupported |
| Terms of Use, app protection, approved client, password-change grant | Unsupported | Unsupported |
| Require MFA | Some Android scenarios appear in the matrix; interactive prompts are unsuitable for unattended resource accounts | Unsupported |
| Interactive MFA or registration prompts | Unsupported for unattended resource accounts | Unsupported for unattended resource accounts |
| Authentication-flows condition | Unsupported; blocking device code can break Android bootstrap | Supported in the matrix; validate the exact Windows flow and mixed-platform account coverage |
| Customize continuous access evaluation | If configured, use Disabled per the device matrix | If configured, use Disabled per the device matrix |
| Disable resiliency defaults or token protection | Unsupported | Unsupported |

The Android matrix supports MFA in some scenarios; that does not permit interactive MFA or SSPR/authentication-registration prompts for shared room accounts. Require MFA is unsupported on Windows rooms. A compliant-device or location restriction must not be described as satisfying a `Require MFA` grant or phishing-resistant authentication strength. Preserve access to the required Teams, Office 365, SharePoint, Intune Enrollment and Device Registration services, and test each platform's actual sign-in and recovery path. [20][21][22]

Security Defaults is incompatible with Teams shared devices. If it is enabled, address it as a separate tenant-wide protection change with equivalent protection for human and administrator identities. Disabling it is not a room-only remediation. Pro licensing includes relevant Intune and Entra capabilities, but assignment alone does not prove enrolment, compliance or successful Conditional Access evaluation. [3][4]

### AOSP management and compliance

If Intune is used, validate the Teams-specific `Corporate-owned, user-associated` AOSP enrolment profile with `For Microsoft Teams devices` enabled. Only one Teams-enabled profile should exist. Verify token validity and the supported profile settings; Teams devices enrol through the resource-account flow rather than scanning its QR code. AOSP management migration and passwordless conversion are separate changes. [23]

Assign a compatible Android AOSP compliance policy before enforcing compliant-device access. Root detection, OS bounds, security-patch level and encryption are supported; generic phone unlock-password settings are unsuitable. Set thresholds the supported room firmware can meet. Verify the actual resource-account and device-group targeting, including associated panels. [20][23]

Document the noncompliance action and reporting-validity period separately. The default failed-setting action marks a device noncompliant at zero days; the default 30-day reporting-validity period governs missed compliance reports. Neither gives an automatic 30-day remediation grace for a failed setting. Review the tenant-wide default for devices with no assigned compliance policy; changing it has a wider blast radius than this project. [24][25]

Check enrolment headroom and active/stale records per account before bootstrap. Entra's default device limit is 50 per registering user, not 50 for the room estate. Validate Intune limit applicability for the actual AOSP flow rather than assuming a universal 15-device ceiling. AOSP does not support Device Enrollment Manager accounts and is unavailable in Intune operated by 21Vianet. [8][26][27][28]

### Windows management and compliance

Use the Windows enrolment and device-compliance design, with the actual Entra-joined PC and its resource-account sign-in. A Teams AOSP profile is not a Windows enrolment profile. The Teams Rooms matrix supports Windows Secure Boot, code integrity, TPM, firewall and Defender checks. BitLocker/encryption checks require the feature to be enabled and validated first. Windows OS minimum/maximum and valid-build compliance settings are unsupported in this matrix, as are password-compliance settings; enforce software readiness through the supported Windows servicing and passwordless prerequisites instead. Test the effective Windows policy and any Android panels separately before requiring compliant-device access. [20][21]

## Discovery and baseline evidence

Use an approved CSV containing one stable `RoomId`, `UPN` and `SiteType` per project room. Maintain platform and account-to-endpoint mappings in the signed migration register: 35 local Android, 10 remote Android and 5 local Windows. Record the platform of each associated panel as well as the room PC or appliance. A shared-account panel is an additional endpoint in that account's acceptance gate; a standalone panel account is an additional identity to plan and license.

| Evidence area | Required fields |
| --- | --- |
| Scope and identity | Approved room ID, Android or Windows, Local or Remote, account object ID, UPN, SMTP, account-enabled state, identity/password authority, cloud |
| Booking | RoomMailbox type, full CalendarProcessing, Default/Anonymous and explicit calendar permissions, delegates, timezone, room lists, Places and visibility |
| Licensing | Assigned SKU and enabled/disabled service plans; room versus standalone-panel entitlement |
| Physical endpoints | Actual appliance/Windows OEM and compute model, controller and panel serials, MACs, account UPNs, site, platform, live versions, digital-signage use; Windows build, TPM and device-join state |
| Management | Pro Management account visibility, migration eligibility and connection/manageability; supported OEM and remaining admin-centre route |
| Security | Effective CA policies and membership, sign-in evidence, active Entra/Intune IDs, compliance assignment/results, profile/token and limit headroom |
| Network | Public egress, proxy, DNS/time/TLS and platform-specific service access; Android IoT Hub connectivity; Windows proxy/certificate eligibility |
| Recovery | Named owner, remote hands, supported provisioning route, password-reset authority and maintenance window |

The accompanying `Teams-Rooms-Passwordless-Inventory.ps1` collects an Exchange Online baseline for the explicit approved list. It uses `User.Read.All` and `LicenseAssignment.Read.All`, selected Graph properties and paged SKU discovery. These replace the original unnecessary `Directory.Read.All` and broader SKU-discovery scope. Delegated consent and appropriate directory read access remain required; Exchange cmdlet permissions are separate. The script requires ExchangeOnlineManagement 3.0.0 or later. It reads tenant-wide subscribed SKUs and room-list memberships, exporting only project-room membership matches. [29][30]

The collector preserves full calendar, permissions and Places evidence, resolves localised calendar folders, includes Default/Anonymous permissions, verifies connection tenants and retains one result row per approved room even when a collection fails. A room with errors is not silently omitted. Its Exchange/Graph baseline applies to both Android and Windows resource accounts; the default 50-room, 40-local and 10-remote checks remain valid. `Collected` means baseline collection succeeded, not passwordless readiness. The script does not identify the five Windows rooms, validate the OS/site split, or collect Windows OEM/build, TPM, join/domain state, administrative recovery, proxy or certificate dependencies. It also does not query effective CA, physical devices, PMP or Intune, and does not perform migration or password cleanup. Platform metadata must remain in the separate reconciled register. [31][32]

Example invocation, after replacing the tenant placeholder and preparing the full approved CSV:

```powershell
./Teams-Rooms-Passwordless-Inventory.ps1 `
  -TenantId '<tenant-id>' `
  -RoomListCsv './approved-rooms.csv' `
  -OutputDirectory './evidence'
```

CSV schema example only; supply all 50 approved records:

```csv
RoomId,UPN,SiteType
LOCAL-001,room01@example.com,Local
REMOTE-001,remote01@example.com,Remote
```

The collector is for Exchange Online mailboxes. An on-premises calendar requires a separately adapted Exchange Server baseline and the correct hybrid validation. Evidence files contain operational identity and permission data; restrict access under the organisation's retention standard and keep passwords out of the package. CLI XML exports are evidence, not a one-command restore procedure.

## Roles and change ownership

| Responsibility | Access and owner |
| --- | --- |
| Schedule passwordless conversion | Teams Administrator per the dedicated migration article |
| Built-in password cleanup | User Administrator or Global Administrator per the wizard; use the lower sufficient role |
| Authorised manual password reset | Appropriate scoped reset rights and the correct identity authority |
| Baseline collection | Consented delegated Graph read scopes and Exchange read permissions |
| CA or compliance changes | Security and Intune owners through their existing change process |
| Per-room acceptance and recovery | Named room engineer and site contact |

General Pro Management access does not automatically establish rights to perform the conversion. The dedicated migration instructions currently specify Teams Administrator and describe broader role support as future work. Use time-bound elevation where available. Avoid granting Global Administrator merely to compensate for an unexamined portal failure. [1][33]

## Pilot and production rollout

### Entry gates

Start only when the approved mixed-platform scope and endpoint mappings are complete, eligibility is visible, software is supported, required management and network connections work, and effective CA/compliance has been proven for each platform. Stabilise Android AOSP and Windows join/enrolment preparation, CA and update-management changes before the authentication window. Do not combine unrelated mailbox or identity edits with the conversion. A Windows eligibility hold does not authorise bypassing the project's passwordless-first gate or silently reducing its scope.

Choose two local Android rooms, one representative remote Android room and one local Windows room. Cover scheduler/CA complexity, actual Windows OEM/join/network patterns and proven local or remote support. Keep executive and high-impact rooms for a later wave. Dates, maintenance windows, ownership and the release decision are recorded in the associated change record.

| Wave | Android local | Android remote | Windows local | Rooms |
| --- | ---: | ---: | ---: | ---: |
| Mixed-platform pilot | 2 | 1 | 1 | 4 |
| Android local A | 11 | 0 | 0 | 11 |
| Android local B | 11 | 0 | 0 | 11 |
| Android local C | 11 | 0 | 0 | 11 |
| Android remote A | 0 | 3 | 0 | 3 |
| Android remote B | 0 | 3 | 0 | 3 |
| Android remote C | 0 | 3 | 0 | 3 |
| Windows local A | 0 | 0 | 2 | 2 |
| Windows local B | 0 | 0 | 2 | 2 |
| Total | 35 | 10 | 5 | 50 |

Observe the four-room pilot for at least 24 hours before cleanup, then complete five accepted business days after post-cleanup validation before production expansion. These are proposed safety intervals, not published Microsoft minimums. Accept each subsequent wave through normal use before advancing. Process remote rooms individually or within the three-room site batches so support capacity remains available. Sequence the Android and Windows production waves according to assessed dependencies; retain the full 50-room target unless CAB records a scope amendment.

### Per account runbook

1. Confirm the approved account and every associated endpoint, licence, mailbox baseline and maintenance window. Record the last good meeting and management state.
2. Confirm no active meeting and adequate time before the next booking. Freeze unrelated changes.
3. Recheck platform-specific live software, supported firmware, PMP eligibility/manageability, CA, compliance and recovery readiness. For Windows, include Entra join, TPM, proxy/model eligibility and administrative recovery; for Android, include AOSP and the supported management components.
4. In Pro Management, open `Planning > Resource Accounts > Migration`, select the eligible account and schedule conversion now or for the approved maintenance window. [1]
5. Capture the job result and endpoint state. A failed transition may automatically roll back; verify the actual state before relying on that protection. [1]
6. Confirm the room appliance or Windows PC is healthy and restart it. Validate automatic sign-in, then run the acceptance tests below for the room and all panels. On Windows, verify the resource-account Windows sign-in, migrated app settings and continued admin access; reboot to return from admin mode to Rooms.
7. Record sign-in and compliance evidence, including policy failures and expected Set as Resource behaviour. Keep the usable bootstrap password during the agreed initial observation interval.
8. Apply the account-level cleanup gate: every dependent endpoint is converted and accepted, or has a documented supported exception that makes cleanup safe. A legacy endpoint still needing this password blocks cleanup.
9. Use the supported cleanup or authoritative password-reset process. Record completion without recording the password.
10. Confirm endpoints remain functional, restart again, repeat the core meeting/calendar tests and capture final evidence.
11. Mark the account complete only after migration, endpoint acceptance, cleanup and post-cleanup validation are recorded separately. Update recovery ownership and the support runbook.

### Acceptance tests

| Test | Required result |
| --- | --- |
| Migration state | Successful conversion in PMP for the account and intended endpoints |
| Reboot before and after cleanup | Automatic sign-in without entering the password |
| Scheduled meeting and Meet Now | Join works; camera, microphone and speakers pass |
| Content and peripherals | HDMI/content ingest, controller pairing and deployed room controls work |
| Calendar | New and recurring bookings, acceptance/delegates and updates match baseline |
| External meeting | Representative external/third-party invitation behaves as expected |
| Scheduler | Correct availability/reservations and expected account/migration state |
| Security and management | Required compliance and CA pass; no unexplained sign-in errors or lost PMP connection |
| Windows transition | Correct resource-account Windows sign-in, migrated settings, Entra join and TPM evidence; administrative access and reboot return to Rooms work |
| Platform recovery | Android sign-out/bootstrap and Windows OEM/recovery-tool reset paths proven on a suitable spare or scheduled recovery test |
| Resource governance | Expected post-meeting chat/file/recording restrictions understood and verified |

Stop widening the rollout for an unexplained sign-out, lost calendar function, migration failure, blocked CA/compliance, unexpected panel impact or unavailable recovery. Triage the affected account and its endpoints, restore service and repeat its tests. Advance only after the change owner reviews the wave evidence; there is no implied automatic stop or automatic production approval.

## Remote rooms and lifecycle recovery

### Remote readiness

All ten remote rooms in the confirmed scope are Android. For each remote site, prove the supported management connection, network, power-cycle procedure and local UI access. Assign a named person able to enter a verification code or perform a reset, plus an identity owner able to issue a temporary bootstrap password. Record the next booking, maintenance window and support escalation path. Test recovery on an appropriate spare or controlled pilot scenario before relying on it in production. The Android provisioning procedure below is not a Windows deployment or recovery procedure.

Pro Management provisioning uses `Planning > Android Devices`. The documented flow uses MAC inventory and a six-digit verification code, valid for 24 hours, entered on the physical endpoint before individual remote sign-in. Bulk remote sign-in is unsupported. It therefore still depends on local intervention and does not remove password bootstrap for a new/reset endpoint. [1][34]

The provisioning article's printed Admin Agent prerequisite does not align cleanly with the release-history numbering. Verify a current supported package with documented provisioning support and prove the actual flow; general PMP management eligibility alone is insufficient evidence of provisioning readiness. [9][34]

For an old factory image with Admin Agent earlier than AA794, Microsoft's transition guidance requires an OEM firmware update to a sufficiently recent Agent before Zero-Day Update can bring management components current. A stale signed-out endpoint must be updated and signed in once to onboard. Include that dependency in the replacement-device drill. [16]

### Failure and recovery decisions

| Situation | Recovery action |
| --- | --- |
| Conversion failed before cleanup | Preserve existing identity/licence and bootstrap path; inspect job detail, app eligibility, CA and compliance; retry after correction |
| Converted room has connectivity or policy failure | Inspect logs and management/network health before signing out; restore the actual failing dependency |
| Android credential lost after full sign-out/reset/replacement | Issue a temporary password at the authoritative source; bootstrap, restore management/compliance, validate, convert again and clean up |
| Windows reset/reimage/replacement or password-authentication backout | Use the supported OEM-image or Microsoft recovery-tool procedure; restore Windows join, configuration and management, bootstrap and reconvert when eligible |
| Suspected compromised endpoint | Use the approved security-containment procedure and exact active device ID; password change alone is insufficient revocation |
| Panel still depends on shared password | Hold account-wide cleanup until the endpoint is converted or the exception is resolved |

A deliberate return to password authentication is service recovery, not restoration of the previous device-bound credential. Android uses the documented full sign-out route; Windows requires a supported reset. Use the manufacturer's recovery image or the Microsoft recovery-tool-prepared procedure: an ordinary Windows reset can remove the Teams Rooms app, and Keep my files is not a supported substitute. Do not promise an instant undo after a destructive lifecycle event. Record the temporary exception, its owner and exit condition. Never transfer a credential to replacement hardware or permanently retain a known shared password as the recovery outcome. [1][41]

## Troubleshooting and ongoing operations

For an authentication incident, first determine whether a destructive sign-out/reset occurred. Inspect PMP migration and connection detail, installed versions and the matching active Entra/Intune objects. Review the resource account's interactive and noninteractive sign-ins at the incident time, including error code, failure reason, Additional Details and Conditional Access results. Microsoft's guidance identifies Teams, Teams Service and Teams Device Admin Agent events as relevant. [35]

Then inspect compliance assignment and failed settings, profile/token validity, enrolment headroom, network and time. Repeated sign-in attempts can create additional objects; match serial/MAC and active IDs before deleting records. A scheduler stuck on an older Agent may require its supported firmware/network fix. Intentional sign-out is a later recovery decision because it discards the Android credential. [1][13][35]

The Teams Rooms Remote Connectivity Analyzer test requires Global Administrator and is unavailable for GCC/GCC High. Use it only when its additional evidence warrants that access; routine room operators should first use device and Entra logs. [35]

Correlate PMP health, Entra sign-ins, platform-specific Intune compliance and actual OEM hardware/software evidence. Maintain daily review during rollout and an agreed steady-state alert owner afterward. Track failures by account, platform and endpoint, not only the room display name. Health signals support monitoring but a green migration job alone does not establish a working meeting experience. [36]

| Project measure | Proposed acceptance target |
| --- | --- |
| Room and account coverage | 50 rooms: 35 local Android, 10 remote Android and 5 local Windows, reconciled to the approved list; exceptions explicitly recorded |
| Pilot | All four accepted before wider rollout; Windows and Android evidence recorded separately |
| Reboot persistence | Every migrated endpoint passes before and after cleanup |
| Required compliance and CA | Every in-scope endpoint passes; failures explained and resolved |
| Booking and meeting regression | No unresolved change-related defect at wave exit |
| Routine password re-entry | Zero incidents caused solely by expiry/rotation on accepted passwordless endpoints |
| Support burden | Compare authentication incidents and site visits with a measured pre-change baseline |

These are project goals, not Microsoft SLAs. Define the measurement window, denominator and incident exclusions before reporting a success rate. Close out with the final room/account/endpoint register, exceptions, evidence, ownership and tested recovery instructions.

## Controlled Exchange exceptions

Passwordless conversion does not require room-account enablement or booking-policy standardisation. Use these only for a specifically diagnosed and separately authorised exception, respecting cloud/on-premises authority.

For an existing room mailbox whose account genuinely needs sign-in enablement, use an interactive secret rather than a literal example password: [3]

```powershell
$room = 'room01@example.com'
$bootstrapPassword = Read-Host 'Temporary bootstrap password' -AsSecureString
Set-Mailbox -Identity $room -EnableRoomMailboxAccount $true `
  -RoomMailboxPassword $bootstrapPassword
```

Before changing calendar processing, compare the complete baseline and the room's booking/privacy requirements. Microsoft publishes the following pattern; it is not a migration prerequisite or a bulk change instruction: [3]

```powershell
$calendarTarget = @{
  Identity = 'room01@example.com'
  AutomateProcessing = 'AutoAccept'
  AddOrganizerToSubject = $false
  AllowRecurringMeetings = $true
  DeleteAttachments = $true
  DeleteComments = $false
  DeleteSubject = $false
  ProcessExternalMeetingMessages = $true
  RemovePrivateProperty = $false
}
Set-CalendarProcessing @calendarTarget
```

For recovery passwords, do not require a password change at the first device sign-in. Do not change expiry policies or UPNs merely because an inventory column is flagged; assess the existing identity and booking design first. [3]

## Verification record

| Source-report issue | Verified improvement |
| --- | --- |
| Estate described as confirmed | Reclassified as reported planning assumptions; live discovery remains a gate |
| Android-only estate assumption | Applied the user's mixed-OS correction: 45 Android and 5 local Windows; added Windows eligibility, TPM/sign-in, policy and reset recovery and a four-room pilot |
| Authentication-only language | Added automatic Set as Resource and expected chat/file/recording consequences |
| No availability/visibility gate | Added GA evidence, GCC portal limit, hidden-account inventory behaviour and initial discovery |
| Rally Bar 2.1.176 treated as current | Updated to dated 2.1.204 snapshot; retained independent live-app verification |
| Scheduler firmware treated as sufficient | Distinguished Microsoft 2.1.303 table from OEM-published 2.1.328 and Agent readiness |
| Admin Agent date comparison | Preserved publication spelling discrepancy and required actual eligibility |
| CA supported-MFA ambiguity | Distinguished personal-user MFA from unattended room accounts and unsupported controls |
| Password cleanup per room | Added gate for every endpoint sharing the account and authoritative synced-account handling |
| Password reset/revocation ambiguity | Added exact device revocation and next-refresh impact; active Intune deletion warning |
| TAC-centred operation | Added PMP connection, transition timetable, irreversible ring adoption and IoT Hub prerequisites |
| Remote workflow too general | Added physical code entry, expiry, individual sign-in and provisioning-version discrepancy |
| Inventory omitted failed rooms and localised calendars | Added explicit approved scope, narrower read scopes, all-row reconciliation and complete baseline/error evidence |
| Stale reconstruction/download/ASCII claims | Removed conversation-history assertions, inaccessible links and unrepeatable integrity claims |

Public documentation does not resolve every deployment detail. Recheck versions and release availability at the maintenance window, verify sovereign-cloud support, reconcile the Admin Agent/provisioning discrepancies and the Microsoft/OEM scheduler listing, and validate the tenant's effective policies and object mappings. The supplied collector was reviewed without running it against a tenant; live module/RBAC behaviour requires a controlled first run.

## Primary sources

Sources were checked through 1 October 2026; the Android firmware tables retain their dated 30 September snapshot. Numbered references identify product documentation; rollout sizes, observation periods and project gates are recommendations in this runbook.

- [1] [Microsoft passwordless resource account migration](https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts)
- [2] [Set as Resource for shared Teams devices](https://learn.microsoft.com/en-us/microsoftteams/rooms/set-as-resource-account-for-shared-teams-devices)
- [3] [Create and configure room resource accounts](https://learn.microsoft.com/en-us/microsoftteams/rooms/create-resource-account)
- [4] [Teams Rooms licensing](https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-licensing)
- [5] [Microsoft Entra September 2026 announcement](https://techcommunity.microsoft.com/blog/microsoft-entra-blog/what%E2%80%99s-new-in-microsoft-entra-september-2026/4545179)
- [6] [Pro Management resource account inventory](https://learn.microsoft.com/en-us/microsoftteams/rooms/resource-accounts)
- [7] [Password scrambling and identity authority](https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-plan-password-scramble-phishing-resistant-passwordless-authentication)
- [8] [Intune AOSP user-associated management](https://learn.microsoft.com/en-us/intune/device-enrollment/android/setup-aosp-corporate-user-associated)
- [9] [Teams Android management-app release history](https://learn.microsoft.com/en-us/microsoftteams/devices/certified-device-apps)
- [10] [Microsoft certified Android room firmware](https://learn.microsoft.com/en-us/microsoftteams/devices/certified-hardware-android)
- [11] [Microsoft certified panel firmware](https://learn.microsoft.com/en-us/microsoftteams/devices/teams-panels-certified-hardware?tabs=firmware)
- [12] [Logitech Rally Bar 2.1.B 2.1.204](https://hub.sync.logitech.com/rallybar/post/collabos-2-1-b-2-1-204-nkoYxYMVkdCptpV)
- [13] [Logitech Tap Scheduler 2.1.A 2.1.303](https://hub.sync.logitech.com/tapscheduler/post/collabos-2-1-a-2-1-303-dMjjsNIVm2SDRhY)
- [14] [Logitech Tap Scheduler 2.1.B 2.1.328](https://hub.sync.logitech.com/tapscheduler/post/collabos-2-1-b-2-1-328-hGRmgANalrMvZ3h)
- [15] [Teams Rooms Android release notes](https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-release-note?tabs=Android)
- [16] [Android management transition to Pro Management](https://learn.microsoft.com/en-us/microsoftteams/rooms/aboutunifieddevicemanagement-pmp1)
- [17] [Android updates in Pro Management](https://learn.microsoft.com/en-us/microsoftteams/rooms/androidupdatemanagementinpmp)
- [18] [Teams Android security and network requirements](https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Android)
- [19] [Logitech guidance for TAC to PMP transition](https://hub.sync.logitech.com/collabosguides/post/teams-rooms-on-android-prepare-for-the-microsoft-tac-to-pmp-transition-TIN8sVSFE2RgcRx)
- [20] [Supported CA and compliance policy matrix](https://learn.microsoft.com/en-us/microsoftteams/rooms/supported-ca-and-compliance-policies)
- [21] [Conditional Access and compliance for Teams devices](https://learn.microsoft.com/en-us/microsoftteams/rooms/conditional-access-and-compliance-for-devices)
- [22] [Teams Android authentication best practices](https://learn.microsoft.com/en-us/microsoftteams/devices/authentication-best-practices-for-android-devices)
- [23] [Teams AOSP enrolment guide](https://learn.microsoft.com/en-us/microsoftteams/devices/teams-aosp-enrollment)
- [24] [Intune noncompliance actions](https://learn.microsoft.com/en-us/intune/device-security/compliance/configure-noncompliance-actions)
- [25] [Intune compliance settings and validity](https://learn.microsoft.com/en-us/intune/device-security/compliance/overview)
- [26] [Intune and Entra enrolment limits](https://learn.microsoft.com/en-us/intune/device-enrollment/limits-intune-entra)
- [27] [Entra device identity limits](https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-identities)
- [28] [Device Enrollment Manager limitations](https://learn.microsoft.com/en-us/intune/device-enrollment/setup-enrollment-manager)
- [29] [Microsoft Graph subscribed SKU permissions](https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0)
- [30] [Microsoft Graph user retrieval](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)
- [31] [Exchange Online calendar folder discovery](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailboxfolderstatistics?view=exchange-ps)
- [32] [Exchange Online folder permissions](https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailboxfolderpermission?view=exchange-ps)
- [33] [Pro Management enrolment and role access](https://learn.microsoft.com/en-us/microsoftteams/rooms/enrolling-mtrp-managed-service)
- [34] [Android provisioning in Pro Management](https://learn.microsoft.com/en-us/microsoftteams/rooms/provisionandroiddevicespromanagementportal)
- [35] [Teams Android CA troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-rooms-and-devices/teams-android-devices-conditional-access-issues)
- [36] [Pro Management health signals](https://learn.microsoft.com/en-us/microsoftteams/rooms/signals)
- [37] [Teams Shared Space licensing](https://learn.microsoft.com/en-us/microsoftteams/teams-add-on-licensing/teams-shared-device-license)
- [38] [Teams Rooms Windows lifecycle support](https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-lifecycle-support)
- [39] [Teams Rooms Windows release notes](https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-release-note?tabs=Windows)
- [40] [Entra join for Teams Rooms on Windows](https://learn.microsoft.com/en-us/microsoftteams/rooms/mtrw-entraid-join)
- [41] [Teams Rooms Windows recovery tool](https://learn.microsoft.com/en-us/microsoftteams/rooms/recovery-tool)
- [42] [Windows local administrator and LAPS considerations](https://learn.microsoft.com/en-us/microsoftteams/rooms/laps-authentication)

[1]: https://learn.microsoft.com/en-us/microsoftteams/rooms/passwordlessentraresourceaccounts
[2]: https://learn.microsoft.com/en-us/microsoftteams/rooms/set-as-resource-account-for-shared-teams-devices
[3]: https://learn.microsoft.com/en-us/microsoftteams/rooms/create-resource-account
[4]: https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-licensing
[5]: https://techcommunity.microsoft.com/blog/microsoft-entra-blog/what%E2%80%99s-new-in-microsoft-entra-september-2026/4545179
[6]: https://learn.microsoft.com/en-us/microsoftteams/rooms/resource-accounts
[7]: https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-plan-password-scramble-phishing-resistant-passwordless-authentication
[8]: https://learn.microsoft.com/en-us/intune/device-enrollment/android/setup-aosp-corporate-user-associated
[9]: https://learn.microsoft.com/en-us/microsoftteams/devices/certified-device-apps
[10]: https://learn.microsoft.com/en-us/microsoftteams/devices/certified-hardware-android
[11]: https://learn.microsoft.com/en-us/microsoftteams/devices/teams-panels-certified-hardware?tabs=firmware
[12]: https://hub.sync.logitech.com/rallybar/post/collabos-2-1-b-2-1-204-nkoYxYMVkdCptpV
[13]: https://hub.sync.logitech.com/tapscheduler/post/collabos-2-1-a-2-1-303-dMjjsNIVm2SDRhY
[14]: https://hub.sync.logitech.com/tapscheduler/post/collabos-2-1-b-2-1-328-hGRmgANalrMvZ3h
[15]: https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-release-note?tabs=Android
[16]: https://learn.microsoft.com/en-us/microsoftteams/rooms/aboutunifieddevicemanagement-pmp1
[17]: https://learn.microsoft.com/en-us/microsoftteams/rooms/androidupdatemanagementinpmp
[18]: https://learn.microsoft.com/en-us/microsoftteams/rooms/security?tabs=Android
[19]: https://hub.sync.logitech.com/collabosguides/post/teams-rooms-on-android-prepare-for-the-microsoft-tac-to-pmp-transition-TIN8sVSFE2RgcRx
[20]: https://learn.microsoft.com/en-us/microsoftteams/rooms/supported-ca-and-compliance-policies
[21]: https://learn.microsoft.com/en-us/microsoftteams/rooms/conditional-access-and-compliance-for-devices
[22]: https://learn.microsoft.com/en-us/microsoftteams/devices/authentication-best-practices-for-android-devices
[23]: https://learn.microsoft.com/en-us/microsoftteams/devices/teams-aosp-enrollment
[24]: https://learn.microsoft.com/en-us/intune/device-security/compliance/configure-noncompliance-actions
[25]: https://learn.microsoft.com/en-us/intune/device-security/compliance/overview
[26]: https://learn.microsoft.com/en-us/intune/device-enrollment/limits-intune-entra
[27]: https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-identities
[28]: https://learn.microsoft.com/en-us/intune/device-enrollment/setup-enrollment-manager
[29]: https://learn.microsoft.com/en-us/graph/api/subscribedsku-list?view=graph-rest-1.0
[30]: https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0
[31]: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailboxfolderstatistics?view=exchange-ps
[32]: https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-exomailboxfolderpermission?view=exchange-ps
[33]: https://learn.microsoft.com/en-us/microsoftteams/rooms/enrolling-mtrp-managed-service
[34]: https://learn.microsoft.com/en-us/microsoftteams/rooms/provisionandroiddevicespromanagementportal
[35]: https://learn.microsoft.com/en-us/troubleshoot/microsoftteams/teams-rooms-and-devices/teams-android-devices-conditional-access-issues
[36]: https://learn.microsoft.com/en-us/microsoftteams/rooms/signals
[37]: https://learn.microsoft.com/en-us/microsoftteams/teams-add-on-licensing/teams-shared-device-license
[38]: https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-lifecycle-support
[39]: https://learn.microsoft.com/en-us/microsoftteams/rooms/rooms-release-note?tabs=Windows
[40]: https://learn.microsoft.com/en-us/microsoftteams/rooms/mtrw-entraid-join
[41]: https://learn.microsoft.com/en-us/microsoftteams/rooms/recovery-tool
[42]: https://learn.microsoft.com/en-us/microsoftteams/rooms/laps-authentication
