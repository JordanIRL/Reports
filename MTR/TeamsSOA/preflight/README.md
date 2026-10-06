# Teams Rooms SOA: read-only preflight toolkit

Prepared 6 October 2026 for `mtr@meetingrooms.ie`, an Android room whose Teams Rooms Pro Management passwordless migration is reported complete. All mailboxes are reported online and Entra Connect current. Those are administrator-supplied facts, not live findings from this package.

Run these scripts before changing authority, then rerun the cloud collectors after the controlled change. They display coloured checkmarks and export optional local evidence. They do not convert users/groups, change passwords, alter membership, start synchronization, install modules, or change services or policies. Graph requests use GET only. Authentication opens a local session; evidence export writes only the local file you specify.

Use [the RoomList migration plan](roomlist-migration-plan.md) for the group and [the room account plan](room-account-migration-plan.md) for the subsequent user transfer. The plans contain reviewable HTTP change specifications; the supplied PowerShell scripts perform reads only.

## What each script checks

| Script | Useful evidence | Where to run |
|---|---|---|
| `scripts/Test-RoomIdentity.ps1` | Expected tenant; exact user ID; enabled/sync state and anchor; Rooms licence/service-plan state; visible transitive group references; dynamic rules using `dirSyncEnabled`; domain federation classification; optional SOA/protection reads | PowerShell 7.2+ with Microsoft Graph access |
| `scripts/Test-RoomMailboxAndLists.ps1` | Same tenant and Entra user ID; room mailbox/Exchange GUID/aliases; calendar settings and delegate permissions; containing RoomLists, subtype, IDs, owners and **all direct members**; before/after preservation | PowerShell 7.2+ with Exchange Online access |
| `scripts/Test-RoomADAndConnect.ps1` | Exact AD account, candidate source-anchor attributes, direct AD groups and explicitly supplied AD RoomLists; installed local Connect version/service/scheduler evidence | Windows Connect server, PowerShell 7.2+ |
| `scripts/ReadOnlyCheck.Common.ps1` | Shared display, bounded Graph GET, error and export helpers | Keep beside the three collectors; do not run separately |

The AD/Connect script is optional for the cloud inventory. Entra cannot prove a Connect server's installed build, sync scope, successful export, or all AD application dependencies. Its local version table was checked on 6 October 2026 and flags stale evidence after 30 days. A scheduler check does not prove successful synchronization.

## Reading the output

| Marker | Meaning | Your next step |
|---|---|---|
| ✓ PASS | This particular observation matched the expected condition | Retain its evidence |
| ✗ ACTION | Observed mismatch or unmet requirement | Resolve before accepting the affected change |
| ! REVIEW | An operational decision or manual dependency check remains | Review the stated condition |
| ? UNKNOWN | Evidence was missing, inaccessible, malformed, bounded or not requested | Obtain the evidence; do not treat it as ready |

The summary prioritises Action, then Unknown, then Review. A report is evidence, not change approval. A green account-enabled or licence check does not approve the migration. Default SOA-state reads are skipped and remain Unknown because they require a write-capable permission. Manual room/device and recovery checks remain Review.

Illustrative output, **not a tenant result**:

```text
[Room account]
✓ PASS    Exact identity: mtr@meetingrooms.ie resolved to <verified-user-id>.
✓ PASS    Account enabled: Observed value: True.

[Group dependencies]
! REVIEW  AD-managed references: Keep the room AD object/sync scope until dependencies are resolved.

[SOA state]
? UNKNOWN Exact SOA flag: Not requested; requires a separately approved SOA scope.

INCOMPLETE - unknown evidence | Pass 8, Action 0, Review 5, Unknown 1
```

Add `-Ascii` for `[OK]`, `[ACTION]`, `[REVIEW]` and `[UNKNOWN]` if your terminal cannot display the symbols. Add `-PassThru` to also return structured objects with `Section`, `Name`, `Status`, `Detail`, `ObservedAtUtc` and `Evidence`. Console display uses the information stream; results do not rely on parsing coloured text. Collectors do not use readiness exit codes: inspect the status objects or displayed summary.

## Requirements and permissions

Use your approved module installation process. No modules are installed automatically.

- PowerShell **7.2 or newer**. Windows PowerShell 5.1 is not the entry point, although the Windows collector can load existing AD/ADSync modules through compatibility sessions.
- `Microsoft.Graph.Authentication` for the identity collector.
- `ExchangeOnlineManagement` **3.2.0 or newer**, using a supported current version for your PowerShell release, for the Exchange collector.
- Existing `ActiveDirectory` and `ADSync` modules on Windows for the AD/Connect collector, with access to read the intended AD objects and local sync configuration.

| Identity collector option | Delegated Graph permissions | Additional condition |
|---|---|---|
| Default | `User.Read.All`, `Group.Read.All`, `Domain.Read.All` | Approved admin consent and an operator authorised for these reads |
| `-IncludeFederationDetails` | Adds `Domain-InternalFederation.Read.All` | Needed only to read federation configuration details |
| `-IncludeTenantSyncProtection` | Adds `OnPremDirectorySynchronization.Read.All` | API documents delegated **Global Administrator** access; app-only is unsupported |
| `-IncludeSoaStatus` for the user | Existing `User-OnPremisesSyncBehavior.ReadWrite.All` | Requires `-UseExistingConnection`; supported SOA administrator role |
| `-IncludeSoaStatus -RoomListObjectId ...` for groups | Existing `Group-OnPremisesSyncBehavior.ReadWrite.All` | Separate group permission and effective SOA authorisation |

**The SOA permission is write-capable even for GET.** The scripts never request it during sign-in or execute a write. Only reuse an already approved SOA session if that access is part of your change process. User SOA permission does not authorise a group SOA read. Otherwise leave these options off and verify SOA through your authorised workflow. Ordinary `onPremisesSyncEnabled`/`IsDirSynced` labels alone are insufficient proof of authority.

Default scopes expose directory information beyond this room at the grant level. The identity collector reads this user, referenced groups, the sign-in domain, and a bounded tenant-wide dynamic-group rule inventory. It does not download other users or mailbox messages. `Group.Read.All` is used because group classification and dynamic rules are required; the collector's transitive-membership API accepts `User.Read.All` for another user's memberships. The licence-details API accepts `User.Read.All` as a higher permission, so an additional `LicenseAssignment.Read.All` grant is unnecessary for this collector. Its delegated licence read still requires a supported role, such as Directory Readers; a denied read is Unknown. [Membership API](https://learn.microsoft.com/en-us/graph/api/user-list-transitivememberof?view=graph-rest-1.0), [Licence-details API](https://learn.microsoft.com/en-us/graph/api/user-list-licensedetails?view=graph-rest-1.0).

The default does not request `AuditLog.Read.All`, CA policy permissions, or write scopes. It does not prove effective Conditional Access, sign-in history, eligible/PIM roles, device compliance, or Pro Management completion. Review those separately. Hidden memberships and Exchange recipient/RBAC scopes can limit discovery. Optional federation metadata does not by itself prove whether this account authenticates through AD FS.

The Exchange collector uses **no Graph permissions**. Exchange RBAC must permit `Get-OrganizationConfig`, `Get-Mailbox`, `Get-CalendarProcessing`, `Get-MailboxPermission`, `Get-RecipientPermission`, `Get-MailboxFolderStatistics`, `Get-MailboxFolderPermission`, `Get-DistributionGroup`, `Get-DistributionGroupMember`, and `Get-Recipient` for the relevant objects, plus connection-status reads. Do not assume one named read-only role covers every command or every recipient scope. The script reports denied reads without escalating access.

The Windows collector uses **no Graph permissions** and your current Windows identity for AD. Direct `memberOf` excludes primary-group and nested membership. Candidate anchors are captured, not assumed to be the configured Connect source anchor.

## Run the before checks

Extract the ZIP and start PowerShell in its `TeamsSOA-ReadOnly-Preflight` folder. Replace tenant/admin/ID placeholders with verified values. `RoomUpn` defaults to this room; supply `-RoomUpn` to check a different room.

```powershell
$TenantId = '<actual-Entra-tenant-GUID>'
New-Item -ItemType Directory -Path './reports' -Force | Out-Null

./scripts/Test-RoomIdentity.ps1 -TenantId $TenantId `
    -PasswordlessMigrationConfirmed `
    -ExportPath './reports/identity-before.json'
```

`-PasswordlessMigrationConfirmed` records your attestation. It does not query Pro Management. Review the output and confirm the exact Entra ID before using it for the mailbox cross-check:

```powershell
$RoomObjectId = '<verified-room-user-object-GUID-from-Entra-report>'

./scripts/Test-RoomMailboxAndLists.ps1 -TenantId $TenantId `
    -AdminUpn 'your-admin@meetingrooms.ie' `
    -ExpectedUserObjectId $RoomObjectId `
    -ExportPath './reports/exchange-before.json'
```

Without `-RoomListIdentity`, Exchange discovery reads visible RoomLists, checks complete direct membership, and records lists containing this room. It always flags discovery scope for review; an empty scoped inventory is not proof that no dependency exists. Once you know the exact list address, explicitly baseline each selected pilot list:

```powershell
./scripts/Test-RoomMailboxAndLists.ps1 -TenantId $TenantId `
    -AdminUpn 'your-admin@meetingrooms.ie' `
    -ExpectedUserObjectId $RoomObjectId `
    -RoomListIdentity '<verified-RoomList-primary-SMTP-address>' `
    -ExportPath './reports/exchange-pilot-before.json'
```

On the Windows Connect server, optionally run:

```powershell
./scripts/Test-RoomADAndConnect.ps1 -ADServer 'your-dc.meetingrooms.ie' `
    -RoomListIdentity '<verified-AD-RoomList-distinguished-name>'
```

Omit `-ADServer` to use normal AD discovery. Omit `-RoomListIdentity` for the account/direct-group checks only. Multiple exact AD group identities are accepted. The Windows collector returns evidence via `-PassThru`; it has no JSON-export parameter:

```powershell
$AdChecks = ./scripts/Test-RoomADAndConnect.ps1 -PassThru
$AdChecks | ConvertTo-Json -Depth 20 |
    Set-Content -LiteralPath './reports/ad-before.json' -Encoding utf8
```

The last example explicitly writes local evidence and can overwrite that chosen path; use a new filename for each capture.

## Existing sessions and optional reads

Collectors refuse to replace an existing cloud connection silently. Use `-UseExistingConnection` if you intend to reuse it, or disconnect it yourself through your normal workflow first. Newly created sessions are disconnected at completion; reused sessions are left open. Tenant and access mode are verified before target reads. This package supports the Microsoft Graph **global** endpoint and delegated access only.

For a read-only existing Graph session, the corresponding explicit sign-in is:

```powershell
Connect-MgGraph -TenantId $TenantId -Environment Global -ContextScope Process `
    -Scopes 'User.Read.All','Group.Read.All','Domain.Read.All' -NoWelcome
./scripts/Test-RoomIdentity.ps1 -TenantId $TenantId -UseExistingConnection
```

Only on an existing, separately approved SOA session:

```powershell
./scripts/Test-RoomIdentity.ps1 -TenantId $TenantId -UseExistingConnection `
    -IncludeSoaStatus -RoomListObjectId '<verified-RoomList-Entra-group-GUID>'
```

This uses GET only and reports missing User/Group SOA scopes as Unknown. It does not narrow any write-capable permissions already held by that session. If you omit `-RoomListObjectId`, only the room's user SOA is requested.

To request the optional read of tenant hard-match protection, run the identity collector with `-IncludeTenantSyncProtection` using the documented delegated Global Administrator access. That read does not change the setting. Its value is recovery-preparation evidence, not a forward-transfer requirement to disable protection. [Configuration read](https://learn.microsoft.com/en-us/graph/api/onpremisesdirectorysynchronization-get?view=graph-rest-1.0).

Graph collections are capped at 100 pages/5,000 items by default. Limits, errors, malformed responses or unexpected next links remain Unknown with partial evidence. Increase `-MaxPages`/`-MaxItems` only when needed; `-SkipDynamicGroupScan` deliberately leaves that dependency check Unknown. General identity/discovery reads use beta; SOA GET uses the v1.0 endpoint documented in the current SOA guides. API failures stay visible and are never retried with broader access.

## Run the after comparisons

Use the same tenant, user and exact list identities, with the captured **Before** files. Use different output paths. Neither cloud collector permits overwriting the baseline, even with `-ForceExport`.

```powershell
./scripts/Test-RoomIdentity.ps1 -TenantId $TenantId -Phase After `
    -PasswordlessMigrationConfirmed `
    -BaselinePath './reports/identity-before.json' `
    -ExportPath './reports/identity-after.json'

./scripts/Test-RoomMailboxAndLists.ps1 -TenantId $TenantId -Mode After `
    -AdminUpn 'your-admin@meetingrooms.ie' `
    -ExpectedUserObjectId $RoomObjectId `
    -RoomListIdentity '<verified-RoomList-primary-SMTP-address>' `
    -BaselinePath './reports/exchange-pilot-before.json' `
    -ExportPath './reports/exchange-pilot-after.json'
```

Identity comparison checks preservation of the user ID and visible group IDs. It checks current licence/service state but does not simulate future dynamic-group evaluation or compare every user property. Exchange comparison covers captured mailbox/list identities and configuration, all captured member/owner sets, calendar settings and permissions. It re-reads baseline lists even if the room disappears from them; missing/incomplete reads are not a successful preservation result. The automated subset does not replace the fuller group baseline in the RoomList plan, including Places attributes, parent references, access packages and other member authority.

For exact authority verification after the change, rerun the identity collector with the approved existing SOA session and `-IncludeSoaStatus`; ordinary after mode does not obtain that grant. Compare after a successful normal sync and after dynamic licensing/policy processing, using actual service evidence rather than an assumed wait duration.

Validate the Android room with a controlled reboot, calendar, booking and meeting test, plus Pro Management health. **Do not fully sign out, reset or reimage it to test SOA**: that can lose its device-bound credential. Retain AD objects/sync scope while AD-managed references remain. A RoomList conversion changes the entire group's authority and can affect every room in that list.

Exports contain addresses, IDs, memberships, delegates and configuration. Store them in your secured change record. Passwords, tokens and mailbox message contents are not deliberately collected. Exports refuse overwrite by default; `-ForceExport` is an explicit local-file choice. Disconnecting a session does not revoke application consent.

## Offline validation

See [VALIDATION.md](VALIDATION.md) for the completed local test results and limits. Included tests use temporary fake modules or function stubs and no real tenant connection. Run each in a **fresh** PowerShell process:

```powershell
pwsh -NoLogo -NoProfile -File ./tests/Test-CommonOffline.ps1
pwsh -NoLogo -NoProfile -File ./tests/Test-IdentityOffline.ps1
pwsh -NoLogo -NoProfile -File ./tests/Test-ExchangeOffline.ps1
pwsh -NoLogo -NoProfile -File ./tests/Test-ADOffline.ps1
```

Offline tests confirm script behaviour against fixtures. They do not prove actual grants, Exchange RBAC, Windows module interoperability, room service health or migration success. No live tenant/device execution has been performed.
