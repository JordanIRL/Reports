# Teams Rooms tenant audit (read-only)

`Invoke-MtrTenantAudit.ps1` inventories an existing Microsoft Teams Rooms estate and checks it against Microsoft's current guidance. It covers Conditional Access, Intune (Windows and Android/AOSP), licensing, resource accounts, password expiry, password-less readiness, groups, Exchange calendar settings, time zones, EWS retirement, Room Finder / Places, and Teams policies. It explains every finding, says **where** the fix has to be made, and writes a commented-out fix plan.

It never changes the tenant:
- **Graph:** only GET requests (plus GET-only `$batch`), with read-only scopes.
- **Exchange Online:** the session loads only the `Get-*` cmdlets listed in `src/Core/Connection.ps1`.
- **Teams:** only `Get-Cs*` cmdlets are used.
- **Tests:** Pester tests fail the build if a write cmdlet or non-GET Graph call appears in the code.

## Built for this environment

- **No naming convention needed.** Rooms are identified by evidence, not names:
  - Teams Rooms license
  - Logitech/Windows device signed in with the account (Intune, sign-in logs)
  - room mailbox with an enabled account
  - `MTREnabled` on the Place
  - membership of an existing rooms group

  Every room's evidence is listed in `Rooms.csv`. You can also seed discovery with `-UpnPattern` (one regex per building prefix), `-ResourceAccountUpn`, `-ResourceAccountCsv` or `-MtrGroupId`.
- **AD-synced accounts and room lists.** Settings that live on-prem are reported as "verify on-prem", because Graph can't read them. This covers password never expires, City/Street, room list membership and hide-from-GAL. These findings come with the AD / Exchange Management Shell commands to check and fix them. Nothing on-prem is queried.
- **Logitech rooms.** Android devices (Rally Bar / Mini / Huddle, RoomMate, Tap IP, Tap Scheduler) are found by manufacturer. Windows rooms (Logitech kits on Lenovo/HP/Dell/ASUS compute) are found by Autopilot `MTR-` group tag, account association, sign-in device ID, or `-WindowsDeviceNamePattern`.

## Requirements

| | |
|---|---|
| PowerShell | 7.4 or later, on Windows (WAM needs Windows) |
| Modules | `Microsoft.Graph.Authentication` 2.25+, `ExchangeOnlineManagement` 3.7.2+ (WAM), `MicrosoftTeams` 7.8.1+ (WAM) |
| Role | **Global Reader** covers everything. Sign-in logs and `signInActivity` need Entra ID P1 in the tenant (included in Teams Rooms Pro). |

```powershell
Install-Module Microsoft.Graph.Authentication, ExchangeOnlineManagement, MicrosoftTeams -Scope CurrentUser
```

The tool checks module versions before connecting and stops with instructions if something is missing. It does not install anything itself.

### Authentication (delegated, WAM)

Sign-in uses the Windows Web Account Manager broker for Graph, Exchange Online and Teams. There are no secrets, certificates or app-only permissions.

By default, Graph uses the shared *Microsoft Graph Command Line Tools* app. Tokens for that app carry **every scope ever consented to it**, which can include write scopes. The tool only issues GET requests either way. For a token that is read-only by construction, register a dedicated app and pass `-ClientId`:

1. In **Entra admin center > App registrations > New registration**, create a single-tenant app. Add a **Public client/native** redirect URI `http://localhost`.
2. Under **Authentication**, add a **Mobile and desktop** redirect URI `ms-appx-web://Microsoft.AAD.BrokerPlugin/<client-id>`. This one is for WAM.
3. Under **API permissions > Microsoft Graph > Delegated**, add these scopes and grant admin consent:
   - `User.Read.All`
   - `Group.Read.All`
   - `Directory.Read.All`
   - `OnPremDirectorySynchronization.Read.All`
   - `Policy.Read.All`
   - `Policy.Read.DeviceConfiguration`
   - `AuditLog.Read.All`
   - `UserAuthenticationMethod.Read.All`
   - `Device.Read.All`
   - `RoleManagement.Read.Directory`
   - `Place.Read.All`
   - `DeviceManagementManagedDevices.Read.All`
   - `DeviceManagementConfiguration.Read.All`
   - `DeviceManagementServiceConfig.Read.All`
   - `TeamworkDevice.Read.All`
4. Optionally, set **Assignment required** on the enterprise app and assign only your auditors.

## Usage

```powershell
# Full audit
.\Invoke-MtrTenantAudit.ps1

# Seed discovery with building prefixes and estimate on-prem password expiry (your AD max password age)
.\Invoke-MtrTenantAudit.ps1 -UpnPattern '^LON-','^NYC\.','^conf-' -OnPremMaxPasswordAgeDays 90

# Dedicated read-only app, only CA and groups
.\Invoke-MtrTenantAudit.ps1 -ClientId <client-id> -Sections ConditionalAccess,Groups

# Re-run all checks offline against saved data (no sign-in)
.\Invoke-MtrTenantAudit.ps1 -FromSnapshot .\MtrAudit-Contoso-20260928-1030\Snapshot.json
```

| Parameter | Purpose |
|---|---|
| `-Sections` | Identity, Licensing, ConditionalAccess, Groups, Exchange, Places, Teams, Intune (default: all) |
| `-ResourceAccountUpn` / `-ResourceAccountCsv` / `-MtrGroupId` / `-UpnPattern` | Discovery seeds |
| `-WindowsDeviceNamePattern` | Regex for Windows room device names not tagged `MTR-` in Autopilot |
| `-SignInLookbackDays` (7) / `-SkipSignInLogs` | Sign-in log analysis |
| `-StaleDays` (30) | Report room accounts with no sign-in for longer than this |
| `-OnPremMaxPasswordAgeDays` | AD max password age, used to estimate expiry of synced room passwords |
| `-InProcessExchangeAndTeams` | Connect Exchange/Teams in this session instead of a separate process (see Troubleshooting) |
| `-OutputPath` / `-NoHtml` | Output location / skip HTML |

## Output

| File | Contents |
|---|---|
| `Report.html` | Self-contained report: severity summary, **Coverage**, filterable findings, room inventory, Conditional Access vs. rooms matrix, manual checks |
| `Findings.csv` | Every finding with severity, where to fix, affected objects and doc link |
| `Rooms.csv` | One row per candidate account: classification, evidence, license, room list, building, city/floor/capacity, time zone, devices, CA policies, password-less readiness |
| `Snapshot.json` | Raw collected data for `-FromSnapshot` and run-to-run comparison. Enrollment tokens and script content are never stored. |
| `Remediation-Plan.ps1` | Starts with `throw`. Every command is commented out and grouped by **RUN IN** (On-prem AD, On-prem Exchange, Exchange Online, Entra ID, Intune, Teams, PMP). Includes read-only verification commands for on-prem items. |
| `templates\` | Report-only Conditional Access policies for Teams Rooms (compliant device, block outside trusted locations, block other platforms, block legacy auth), plus `DynamicGroup-Rules.txt` with rules that don't use names (license-based, AD attribute, Autopilot `MTR-` devices, Teams AOSP devices). |

**Severity:**
- **Critical:** rooms are failing now, or a tenant-wide blocker.
- **High:** unsupported configuration, or failure is likely.
- **Medium:** best-practice gap with user or management impact.
- **Low / Info:** hygiene and inventory.

Always check **Coverage** first. A section that could not be read produces no findings, and that is not a pass.

## What is checked

| Area | Examples |
|---|---|
| Discovery | Evidence-based inventory, naming prefixes by building, enabled-but-unused room accounts |
| Licensing | Rooms without Teams Rooms licenses, Shared Devices license on a room, E3/E5 on rooms, more than 25 Basic, disabled Intune/Teams/P1 plans, assignment errors |
| Identity | UPN ≠ SMTP, disabled accounts, cloud and synced password expiry, sync health, MFA methods on rooms, admin roles, stale rooms, sign-in failures mapped to causes, security defaults, registration campaign, MFA-to-join, device quota, password-less readiness |
| Conditional Access | Per-room evaluation of every policy: MFA / auth strength / hybrid join / ToU / sign-in frequency / CAE / token protection / insider risk, device code flow blocks, blocked required resources, report-only impact, missing dedicated policy, rooms outside it, general policies without a rooms exclusion (with merged exclusion lists), Basic rooms under compliance |
| Groups | Existing rooms group(s) and coverage, **people inside the rooms group**, name-based dynamic rules, Windows MTR device group |
| Exchange | Not a room mailbox / on-prem mailbox, calendar processing vs. Microsoft's recommended values, book-in restrictions, time zone missing or out of line with its building, hidden from GAL, **EWS retirement vs. Android app build** |
| Room Finder / Places | Rooms outside or in several room lists, empty/large/mixed-city lists, missing City/Floor/Capacity/Building, `MTREnabled`, Places buildings and floor parenting |
| Teams | Not provisioned, not TeamsOnly, user-licensed Android rooms without MeetingSignIn, policy inventory |
| Intune Android | Teams AOSP profile and token expiry, Device Administrator devices, AOSP compliance settings vs. the Logitech fleet's OS/patch level |
| Intune Windows | Hybrid join, Autopilot `MTR-` tag, unsupported compliance settings, "All devices" policies and feature-update profiles landing on rooms, user-targeted policies that will apply after password-less migration, LAPS, Windows 10 |
| Devices | Non-compliant devices with failing settings, stale check-ins, model/OS/app inventory |

Items that no API exposes are listed as **manual checks** in the report. These include PMP "Set as Resource" and migration status, Logitech Sync firmware, and SSPR registration.

## Keeping it current

Microsoft's recommended values, version floors and unsupported controls live in `config/MtrBaseline.psd1`. This includes the Windows build and app versions for password-less, the Android build for EWS retirement, calendar processing values, the CA app IDs, sign-in error meanings and doc links. Update that file when guidance changes; no code changes are needed.

## Tests

```powershell
Install-Module Pester -MinimumVersion 5.5 -Scope CurrentUser -SkipPublisherCheck
Invoke-Pester -Path .\tests -Output Detailed
```

The tests run every check against a synthetic tenant (`tests/fixtures/SampleTenant.ps1`) and verify the snapshot round-trip. They also enforce the read-only guarantees: a static scan for write cmdlets, the GET-only Graph client, Get-only Exchange cmdlets, and read-only scopes.

## Troubleshooting

- **Exchange Online and Teams sign in from a separate PowerShell process.** In one session, their sign-in libraries clash with Microsoft Graph's. A real run showed `Connect-ExchangeOnline` failing with "Object reference not set to an instance of an object" and `Connect-MicrosoftTeams` with "Only some brokers (WAM) can log in the current OS account". So by default each Exchange/Teams step runs in a child `pwsh` process in the same Windows session, and WAM still works. You may see a sign-in prompt for each. The child's errors are reported in Coverage. `-InProcessExchangeAndTeams` tries the same session first and falls back to a separate process on failure.
- **WAM errors under RunAs or a scheduled task.** WAM needs an interactive session of the signed-in Windows user. Run the tool from your own session.
- **403 in Coverage.** A scope wasn't consented, or your role can't read that area. The rest of the audit still runs.
- **No rooms found.** Tenant-level checks (security defaults, Conditional Access, registration policies, Room Finder metadata) still run. Room accounts are also found through Graph Places when Exchange Online can't be read.
- **Teams devices API unavailable.** Microsoft deprecated the Graph `teamworkDevice` API. The tool uses Intune/Autopilot/sign-in data instead; check device health in TAC or PMP.
