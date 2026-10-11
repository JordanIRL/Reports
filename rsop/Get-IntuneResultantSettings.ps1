<#
.TITLE
    Intune Lens — resultant settings for Intune-managed devices.

.SYNOPSIS
    Intune Lens — resultant settings (RSOP) for Intune-managed devices.
    Answers: "What are ALL the settings that apply to this device / these devices?"
    Run with no parameters for a guided interactive menu.

.DESCRIPTION
    Aggregates every configuration source across platforms in an Intune tenant:
      - Settings Catalog policies            (deviceManagement/configurationPolicies)
      - Endpoint Security policies (ASR, AV, Firewall, BitLocker, EDR, ...) - modern (configurationPolicies) and legacy (intents)
      - Security Baselines                   (modern: configurationPolicies, legacy: intents)
      - Device Configuration templates       (deviceManagement/deviceConfigurations, incl. custom OMA-URI)
      - Administrative Templates / ADMX      (deviceManagement/groupPolicyConfigurations)
      - Compliance policies                  (classic deviceCompliancePolicies incl. actions for
                                              noncompliance + custom compliance scripts, and
                                              Settings Catalog compliancePolicies) [optional]
      - Windows Update profiles              (feature / expedited quality / quality update
                                              (hotpatch) policies / driver) [optional]
      - Platform scripts                     (Windows PowerShell, macOS shell, macOS custom
                                              attributes - decoded script content, searchable) [optional]
      - Remediations                         (deviceHealthScripts: detection + remediation script
                                              content, run schedule per assignment) [optional]
      - App Configuration policies           (managed devices: mobileAppConfigurations;
                                              managed apps: targetedManagedAppConfigurations) [optional]
      - App Protection policies              (iOS / Android / Windows MAM, legacy WIP) [optional]
      - Enrollment configurations            (Enrollment Status Page, Windows Hello for Business,
                                              platform restrictions, device limits, co-management -
                                              resolved by priority) [optional]
      - Windows Autopilot deployment profiles (resolved by Intune's oldest-profile rule and
                                              All devices fallback, cross-checked with the
                                              device's Autopilot record) [optional]
      - Applications                         (deviceAppManagement/mobileApps - ONE entry per app with
                                              its Required / Available / Uninstall assignments, the
                                              resolved intent for the device using Intune's documented
                                              intent-conflict rules, install details, supersedence /
                                              dependencies, and the device-reported install state;
                                              the tenant-wide view also lists unassigned apps) [optional]
      - BIOS configurations, App Control supplemental policies, Properties catalog policies

    The tenant-wide report (-All) adds a "Tenant setup" view - the non-policy half of Intune that
    a rebuild after a disaster needs: tenant switches, clean-up rules, managed installer,
    consents and licences, Intune roles / scope tags / multi admin approval, Company Portal
    branding, terms and conditions, notification templates, device and app categories,
    Entra MDM / MAM user scope, device join and BitLocker recovery settings, Autopilot
    registrations and corporate identifiers, Apple and Android Enterprise enrollment,
    connectors (Defender / MTD, certificate, AD, partners, Tunnel sites and configurations,
    Cloud PKI), Zebra FOTA deployments, Windows 365, reusable settings, imported ADMX,
    compliance scripts, policy sets, eSIM pools, default app protection, Endpoint analytics,
    Entra branding and Intune-related Conditional Access (named locations and terms of use).
    Every referenced Entra group and filter is listed; nested group definitions, members and
    owners are captured for recovery. The checklist records expiring credentials, missing or
    empty groups, failed reads and configuration requiring manual capture.
    -BackupPath writes raw Graph JSON with typed secrets redacted and explicit capture gaps.

    For each target device it resolves:
      - Entra ID transitive group membership of the DEVICE object
      - Entra ID transitive group membership of the PRIMARY USER (user-targeted policies)
      - "All devices" / "All users" virtual assignments
      - Assignment filters (local rule evaluation against live inventory first; server-side
        /deviceManagement/evaluateAssignmentFilter for rules that are not locally decidable),
        combined with Intune's filter-mode precedence when several assignments reach the
        device: Exclude-mode filter > no filter > Include-mode filter (same mode = OR)
      - Group exclusions (kind-aware: user-group exclusions do not undo device-targeted
        includes and vice versa, per the Intune support matrix)
      - Priority / precedence where Intune picks one winner (ESP, enrollment restrictions,
        device limits, Autopilot profiles) - losers are reported as Superseded
      - Enrollment configuration predictions describe the current assignment snapshot,
        not historical enforcement at enrollment. Known userless/default and Windows
        device-limit exceptions are accounted for when exposed in device inventory.

    ...then flattens every individual setting (name + value) from every applicable policy,
    detects conflicts (same setting defined with different values by multiple applicable
    policies), and optionally cross-checks against what the device actually reported
    (reports/getConfigurationPoliciesReportForDevice - the data behind the portal's
    per-device Configuration blade).

    Targets can be specified by serial number, device name, Entra ID group, or assignment filter.

    Output: console summary + self-contained interactive HTML report (searchable, with
    CSV download). Optional raw CSV / JSON exports.

    Requires module: Microsoft.Graph.Authentication (only; raw REST is used for everything else).
    Delegated scopes: DeviceManagementConfiguration.Read.All,
                      DeviceManagementManagedDevices.Read.All,
                      Directory.Read.All,
                      DeviceManagementRBAC.Read.All (scope tag names),
                      DeviceManagementApps.Read.All (unless -SkipApps and -SkipAppPolicies),
                      DeviceManagementScripts.Read.All (unless -SkipScripts),
                      DeviceManagementServiceConfig.Read.All (unless -SkipEnrollment),
                      Policy.Read.All, CloudPC.Read.All,
                      DeviceManagementCloudCA.Read.All, Agreement.Read.All
                        (tenant setup view: -All, -BackupPath and the interactive menu,
                         unless -SkipTenantConfig)

.PARAMETER SerialNumber
    One or more device serial numbers.

.PARAMETER DeviceName
    One or more Intune device names.

.PARAMETER Group
    Entra ID group display name or object id. All *device* members (transitive) are resolved.

.PARAMETER GroupAssignedOnly
    With -Group: instead of resolving member devices, list the policies/settings whose
    assignments directly reference this group (fast; no per-device evaluation).

.PARAMETER AssignmentFilter
    Assignment filter display name or id. The filter is evaluated server-side and all
    matching devices become targets.

.PARAMETER All
    Tenant-wide inventory: every policy (assigned or not) with all settings and a
    resolved assignment summary (group names, filters, exclusions). Great for cleanup.

.PARAMETER ScopeGroup
    With -All: narrow the inventory to policies whose assignments reach this Entra ID
    group (display name or object id) - directly, via a parent group (transitive), or
    via an All devices / All users assignment. Policies that only EXCLUDE the scope
    stay visible as Excluded (their settings land in the shadow set); everything else
    is dropped. Answers "what policies apply to this group?" without per-device math.

.PARAMETER ScopeFilter
    With -All: narrow the inventory to policies with at least one assignment carrying
    this assignment filter (display name or id). The include/exclude mode of the
    filter usage is spelled out per policy. Combinable with -ScopeGroup (both must match).

.PARAMETER SkipUpdates
    Skip Windows Update profiles (feature / expedite / driver).

.PARAMETER SkipScripts
    Skip platform scripts, remediations and macOS shell scripts / custom attributes (their
    decoded content is otherwise pulled and made searchable - that is how you catch a script
    that silently uninstalls an app). Script endpoints sit behind the dedicated
    DeviceManagementScripts.Read.All scope (only requested when scripts are included).

.PARAMETER SkipApps
    Skip applications. When apps are included (default) the report gets an Apps tab with
    one entry per app showing its Required / Available / Uninstall assignments side by side
    and - per device - the intent Intune resolves using its documented conflict rules
    (Required beats Uninstall, Uninstall beats Available, ...), so "what is uninstalling
    app X on this device" is a direct lookup. Requires DeviceManagementApps.Read.All.

.PARAMETER SkipAppPolicies
    Skip App Configuration policies (managed devices + managed apps) and App Protection
    policies. Requires DeviceManagementApps.Read.All when included.

.PARAMETER SkipEnrollment
    Skip enrollment configurations (ESP, Windows Hello for Business, restrictions, limits,
    co-management) and Windows Autopilot deployment profiles / the device's Autopilot
    record. Requires DeviceManagementServiceConfig.Read.All when included.

.PARAMETER SkipTenantConfig
    With -All: leave out the Tenant setup view (and its extra permissions:
    Policy.Read.All, CloudPC.Read.All,
    DeviceManagementCloudCA.Read.All, Agreement.Read.All).

.PARAMETER BackupPath
    Folder for a raw JSON backup of everything the run reads: one file per object exactly as
    Microsoft Graph returns it, with the sub-collections fetched alongside (Settings Catalog
    settings, assignments, ADMX definition values, script bodies, certificate links, driver
    approvals, imported ADMX content ...), group definitions, static members and owners,
    device inventory, and manifest.json listing id mappings, failed reads and manual steps.
    Typed secrets (enrollment tokens, QR codes, passwords, pre-shared keys and eSIM activation
    codes) are redacted. Custom OMA-URI plaintext, arbitrary app configuration values, custom
    XML payloads, Office XML, script bodies and BIOS files are retained for restore and may
    contain credentials. Store the backup like a password-vault export. Reissued credentials
    and manual recovery steps remain necessary; this is a capture tool, not a restore engine.
    Always re-reads from Graph (the policy cache is bypassed). Combine with any mode, typically
    -All -BackupPath D:\IntuneBackups.

.PARAMETER ExportHtml
    Path for the interactive HTML report. Default: .\IntuneLens-<tenant>-<scope>-<timestamp>.html
    (pass -NoHtml to suppress).

.PARAMETER ExportCsv
    Optional path for a flat CSV (one row per device x setting).

.PARAMETER ExportJson
    Optional path for the full structured JSON result.

.PARAMETER NoHtml
    Suppress the default HTML report.

.PARAMETER SkipCompliance
    Do not include compliance policies.

.PARAMETER SkipReportedStatus
    Skip the per-device "what did the device actually report" cross-check (faster).

.PARAMETER MaxDevices
    Safety cap for group/filter modes (default 25). 0 = unlimited.

.PARAMETER CacheMinutes
    The policy corpus (all policies + settings + assignments) is cached on disk to make
    repeat queries fast. Default TTL 60 minutes. Use -Refresh to force a re-pull.

.PARAMETER ThrottleLimit
    How many Microsoft Graph /$batch requests (up to 20 reads each) go out at once. Default 4;
    1 sends one at a time. When Graph throttles the tenant the script waits for its Retry-After
    and halves this for the rest of the run.

.PARAMETER Refresh
    Ignore the on-disk policy cache and re-pull everything from Graph.

.PARAMETER PassThru
    Emit the per-device result objects to the pipeline.

.PARAMETER TenantId
    Optional tenant id/domain for Connect-MgGraph.

.PARAMETER ClientId
    Optional app registration client id for Connect-MgGraph (defaults to the Graph SDK app).

.PARAMETER Environment
    Graph environment: Global (default), USGov, USGovDoD, China.

.PARAMETER UseDeviceCode
    Use device-code sign-in (handy over SSH / in containers).

.PARAMETER LogPath
    Folder for the run log. Default: a 'logs' folder next to the script. Every run writes
    IntuneLens-<timestamp>.log there - the command, versions, every error and warning, the
    tenant setup checklist, capture gaps and the full console output - and rewrites it after
    each report or backup and when the run ends, including when it fails or is stopped.

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -SerialNumber 5CD1234XYZ

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -SerialNumber 5CD1234XYZ,PF2ABCDE -ExportCsv rsop.csv

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -Group "Sales Laptops"

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -Group "Pilot Ring 1" -GroupAssignedOnly

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -AssignmentFilter "Corp Windows 11" -MaxDevices 10

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -All -ScopeGroup "Sales Laptops" -ExportCsv sales-scope.csv

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -All -ScopeFilter "Corp Windows 11"

.EXAMPLE
    ./Get-IntuneResultantSettings.ps1 -All -BackupPath D:\IntuneBackups -ExportCsv tenant.csv
    The disaster-recovery picture: the tenant-wide report with its Tenant setup view and recovery
    checklist, a CSV of everything, and a raw JSON backup of every object.

.TAGS
    Microsoft Intune, Microsoft Graph, RSOP, Windows, reporting, troubleshooting

.PLATFORM
    PowerShell 7.4 or later on Windows, macOS, or Linux.

.PERMISSIONS
    Delegated: DeviceManagementConfiguration.Read.All,
    DeviceManagementManagedDevices.Read.All, Directory.Read.All,
    DeviceManagementApps.Read.All, DeviceManagementScripts.Read.All,
    DeviceManagementServiceConfig.Read.All, DeviceManagementRBAC.Read.All,
    Policy.Read.All, CloudPC.Read.All, DeviceManagementCloudCA.Read.All, Agreement.Read.All.
    The Cloud PKI list API currently documents a write permission; this tool requests only
    read permission and flags licensed CAs it cannot capture. Terms-of-use agreement reads
    support delegated access only and require a supported Microsoft Entra role.

.AUTHOR
    Jordan

.VERSION
    3.3.6

.CHANGELOG
    3.3.6 (2026-10-11) — HTML and CSV filenames use minute precision for capture timestamps.
    3.3.5 (2026-10-11) — automatic HTML and CSV filenames identify the tenant, query or
    device scope, and capture time; browser CSV downloads also identify their report section.
    3.3.4 (2026-10-11) — preserves independent device and user paths through mixed groups,
    complete setting values for conflict detection, and console summaries in run logs.
    Encodes lookup values safely, rejects ambiguous filter names, isolates automatically
    named reports, logs and backups, and fixes mobile navigation and Troubleshoot focus.
    3.3.3 (2026-10-11) — enriched Cloud PKI certification authority names with certificate
    Common Name and role (Root vs Issuing CA); unified secondary typography in Essentials overview.

    3.3.2 (2026-10-11) — aligned CSV exports with Platform and PolicyStatus metadata;
    clarified conflict diagnostics in non-device (-All) scope; interactive menu option [7]
    defaults backup destination to .\backups; interactive policy status strata bar segments
    and clickable unassigned policy count in overview.

    3.3.1 (2026-10-11) — calendar-day precision for token and licence expiry diagnostics;
    extended JSON serialization depth to prevent truncation; parameter validation on
    MaxDevices and CacheMinutes; fixed automatic variable collision on $matches; updated
    cross-platform help synopsis; excluded real reports and run logs from source control.

    3.3.0 (2026-10-11) — uncertain and unreadable assignments remain Unknown, including
    priority winners and app intents; only definite applicable policies create conflicts.
    Paging retains completeness evidence, fresh queries and corpus pulls reset stale caches,
    cached tenant warnings survive reloads, Retry-After is honored in full, and logs are private.
    Report CSV follows the selected section, inspector keyboard navigation is contained,
    matrix states are distinct, and app configuration settings use a per-policy index.
    Offline regression and browser checks cover the fixes. Requires PowerShell 7.4 or later.

    3.2.11 (2026-10-11) — built for large tenants. Microsoft Graph /$batch requests go out several
    at a time over the one sign-in (-ThrottleLimit, default 4); reads Graph throttles inside a
    batch wait for its Retry-After and go again, and fewer requests go out at once for the rest of
    the run. Settings Catalog policies are read without their setting definitions, and each
    definition is read once for the whole tenant. Encrypted custom OMA-URI values are decrypted in
    batches, and the policy cache now works in tenants that have them: it holds a placeholder and
    decrypts again when read. Tenant setup reads its fixed endpoints ahead in batches, counts the
    members of assigned groups instead of reading every member (a backup still keeps them all),
    tallies managed devices page by page and shows its progress by section. A list whose next page
    repeats one already read stops with a note, and an expanded list Graph cut short (a policy's
    assignments) is completed or flagged as incomplete. A progress bar no longer stays on screen
    after a failed read, the apparent hang at "Properties catalog". Device runs reuse the group
    memberships and policy lookups already read, and a device that cannot be evaluated is left out
    with an error instead of ending the run. A tenant-wide or many-device run's console summary
    points to the report instead of listing every policy and conflict, and checklist entries keep
    the same order on every run.
    3.2.10 (2026-10-10) — the report's navigation puts Apps above Endpoint security, as the admin
    center does, and every area opens on its policies. Tenant administration gains Assignment
    filters: each filter with its platform, what it applies to, its rule and every assignment
    that uses it, with its own search and CSV. An Exclude-mode filter reads "Exclude <name>".
    The run log reads "Report written" while the guided menu asks whether to open the report or
    write a CSV, instead of "In progress".
    3.2.9 (2026-10-10) — report polish. The masthead drops the print command. Conflicts appear in
    the navigation, the overview and Essentials only when the report has some. The overview is a
    dashboard without the filter bar: Policy status with Policies by area beneath it, the checklist
    or device and the apps beside them. The details pane leads with the value, then a description,
    the basics and the assignments as Intune lists them (included groups with their filter and
    filter mode, then excluded groups). Badges, icons and grid text share one baseline. An
    assignment filter reads 'filter' in Intune's default Include mode and 'exclude filter' only in
    the Exclude mode, in the report, the CSV and the reasons a policy applies.
    3.2.8 (2026-10-10) — the report navigates by Intune's own areas instead of one flat
    'Settings' list: Devices (Configuration, Compliance, Scripts and remediations, Updates,
    Enrollment), Endpoint security (Security baselines, Antivirus, Disk encryption, Firewall,
    Endpoint detection and response, Attack surface reduction, Account protection, App Control for
    Business, Endpoint Privilege Management), Apps (All apps, App protection policies, App
    configuration policies), Tenant administration and Reports (All policies, All settings,
    Conflicts, Device matrix). Each area page has Policies and Settings pivots and follows the
    'By platform' choice, which now sits under Overview. The overview maps policies by area, and
    the Investigate view is named Troubleshoot.
    3.2.7 (2026-10-10) — the report is laid out like the Intune admin center: a masthead with the
    tenant and snapshot time, a grouped left navigation (Configuration, Apps, Tenant
    administration, Devices) with a 'By platform' list - Windows, iOS/iPadOS, macOS, Android,
    Linux and cross-platform - that filters the whole report, breadcrumbs and blade titles such
    as 'Policies | Windows', a toolbar band with search, filter pills and commands, Fluent data
    grids with status icons, message bars for the recovery checklist, and an overview with an
    Essentials panel and dashboard tiles. Conflicts are a grid. One stylesheet replaces the
    layered overrides of earlier versions; below 1024 px the navigation becomes a drawer.
    3.2.6 (2026-10-10) — report redesign: a light sidebar, a header that labels tenant, scope and
    snapshot time, a summary band with the outcome of every policy in the report (click a segment
    to list those policies), dot status badges with plain words ('Not assigned', not
    'NotAssigned'), sentence-case labels, Segoe UI Variable / Cascadia Mono type and a petrol
    accent in light and dark themes. Copying is one icon beside every group name, filter name,
    policy id, app id, setting key and value; 'Copy intent' is gone and an app's assignments copy
    as a whole from the apps table or its details. The guided menu records each choice in the run
    log and the log reads 'Waiting at the guided menu' between actions.
    3.2.5 (2026-10-10) — the on-premises Exchange connector is no longer read (it is retired and
    the endpoint answers 501). Properties catalog failures are capture gaps rather than warnings,
    capture gaps found while loading policies survive the policy cache, and Intune's nested
    service messages are compacted to the message plus operation / activity ids. The report
    names the tenant (organisation name and default domain, also in the page title), shows the
    snapshot time as yyyy-MM-dd HH:mm with its UTC offset, opens the overview on what needs
    attention (tenant checklist and conflicts first), hides the scope picker when there is one
    scope, drops emoji from Investigate topics, mutes empty counts, hides the device-reported
    column outside device reports and prints cleanly. The decrypted custom OMA-URI finding lists
    the policies and settings concerned. The guided menu's CSV prompt accepts y / yes for a CSV
    next to the report, and the run log is rewritten after every menu action. Corpus cache
    schema 16.
    3.2.4 (2026-10-10) — every run writes logs\IntuneLens-<timestamp>.log next to the script (or
    -LogPath): the command, PowerShell and Graph SDK versions, every error and warning, the tenant
    setup checklist, capture gaps and the full console output, rewritten after each report or
    backup and when the run ends - also when it fails or is stopped. Graph errors are reduced to
    the service message, error code and request id also when the SDK puts the HTTP dump in
    ErrorDetails (3.2.3 only handled the exception message). Tenant-setup reads the tenant does
    not serve - access denied, not implemented, the legacy managed-installer and Exchange
    connector endpoints - are capture gaps: listed in the Tenant setup view and the backup
    manifest ('captureGaps') instead of run warnings. Read problems are no longer printed twice;
    unassigned policies are summarised in one console line; a missing collection in a Graph
    response no longer aborts a tenant setup section. Exports given as relative paths
    (-ExportCsv rsop.csv) get their restricted permissions again - .NET resolved them against
    the process directory, so the step failed or hit a same-named file elsewhere. Corpus cache
    schema 15.
    3.2.3 (2026-10-10) — Graph failures read as Graph's own message, error code and request id
    instead of the SDK's raw HTTP dump (request line, headers, nested JSON) in warnings, the
    console, the backup manifest and the report. Per-policy reads (Settings Catalog settings, ADMX
    values, intent settings / assignments / templates, compliance settings and actions, script
    bodies, managed-app configuration and Properties catalog settings) go through /$batch - one
    request per 5 to 20 policies instead of one per policy - with an identical corpus. Group mode looks
    up a small group's devices instead of indexing every managed device, and evaluates the most
    recently synced record of a re-enrolled device (the index kept an arbitrary, possibly stale
    one). Paths containing [ ] work for the template, exports and cache; console tables no longer
    end every line with '?' on Windows; empty collections back up as [] instead of [null];
    expiry wording no longer reads 'in 1 days'. Corpus cache schema 14 refreshes older warnings.
    3.2.2 (2026-10-10) — tenant-read failures retain Graph error codes, service messages and
    request ids with endpoint-specific checks. Access-denied responses remain capture gaps,
    without implying a feature is off. Managed-installer 500 and Exchange 501 failures are
    visible in the report as well as the manifest. Exchange is described as deprecated,
    not universally retired. Corpus cache schema 13 refreshes older status diagnostics.
    3.2.1 (2026-10-10) — completes the remaining disaster-recovery review. Nested managed
    configuration and plist secrets, command arguments, legacy intents, custom XML and BIOS
    payloads are protected in reports; CSV formulas and console controls are neutralised.
    Exports receive explicit Windows ACLs or owner-only Unix permissions. Tenant text cannot
    introduce template substitutions. Capture adds Tunnel links, nested groups, joined-device
    administrators, BitLocker self-service policy, Zebra deployments, extra certificate links
    and terms-of-use agreements; read failures and API limitations stay visible in manifest.
    Report fixes cover assigned-app counts, mobile cards, empty-read wording, dates, app
    metadata, jump offsets and filter modes. Cache version 12 invalidates older snapshots.
    3.2.0 (2026-10-08) — disaster-recovery coverage. The tenant-wide report gains a Tenant setup
    view (tenant switches, licences, roles / scope tags / multi admin approval, Company Portal,
    terms and conditions, notification templates, Entra MDM / MAM scope and join settings,
    Autopilot registrations, corporate identifiers, Apple APNs / ADE / VPP, Android Enterprise,
    connectors, Windows 365, reusable settings, imported ADMX, compliance scripts, policy sets,
    Intune-related Conditional Access), every group (with membership rule) and filter that
    assignments use, and a recovery checklist: expiring tokens / certificates / trial licences,
    deleted groups still referenced, silent connectors, what Graph cannot export. New
    -BackupPath writes a raw JSON backup of every object (secrets redacted) with a manifest.
    Unassigned apps are inventoried with their package file; BIOS configurations, App Control
    supplemental policies and Properties catalog policies are evaluated like other policies;
    compliance e-mail actions name their template and copied groups; policies show scope tags.
    Template schema 4.
    3.1.0 (2026-10-08) — report: quick filters (status / policy type / intent) plus a "More
    filters" drawer, an App configurations tab with readable and copyable settings, and
    expandable, copyable Required / Available / Uninstall assignments per app. Engine: app
    configuration / protection conflicts are compared per targeted app; device-limit and
    platform-restriction exceptions for non-user-driven enrollments; Autopilot prefers a
    specific group assignment over an All-devices fallback; an app replaced by a Required
    superseding app (supersedence type replace) is flagged as being uninstalled; script and
    remediation options no longer raise false conflicts; dates are culture-proof (the
    Autopilot oldest-profile rule, deadlines and device ordering were wrong on non-US
    locales and from the policy cache); permanent Graph errors (400/403/404) are no longer
    retried with a delay; device facts use admin-center wording.
    3.0.0 (2026-10-07) — adds App Configuration (managed devices + managed apps), App
    Protection, Remediations, macOS scripts, enrollment configurations (ESP / WHfB /
    restrictions / limits, priority-resolved), Autopilot profiles + device record,
    Settings Catalog compliance, actions for noncompliance, custom compliance scripts and
    hotpatch quality update policies. Apps become one entry per app with Required /
    Available / Uninstall side by side and Intune's documented intent-conflict resolution
    per device, plus supersedence / dependencies and device-reported install state.
    Applicability now honours Intune's filter-mode precedence (Exclude > no filter >
    Include) and records a per-assignment hit for every device. Device-reported status
    is added for compliance policies and remediations. The report (template schema 3)
    gains an Apps tab, faceted multi-select filters with live counts, field-qualified
    search, removable filter pills, Settings group-by and shareable view state.
    2.6.0 (2026-07-12) — redesigns the rich report around a clearer diagnostic shell,
    compact grouped filters, responsive setting cards, reduced keyboard tab stops,
    and an accessible modal detail drawer.
    2.5.3 (2026-07-12) — correctly renders ADMX multi-text string collections while
    preserving structured name/value presentation lists.
    2.5.2 (2026-07-12) — isolates cache options, prevents decrypted OMA-URI values
    from being cached, honours explicit Graph context selectors, and fixes paging limits.

.LASTUPDATE
    2026-10-11

.NOTES
    Version 3.3.6 (2026-10-11)
    Run with NO parameters for a guided interactive menu.
    Read-only: performs GET/report POST calls only; never modifies tenant data.
    Encrypted custom OMA-URI values are decrypted into the report - treat the export as sensitive.
    Keep report-template.html next to this script for the full-featured HTML report.
#>
#Requires -Version 7.4
[CmdletBinding(DefaultParameterSetName = 'Interactive')]
param(
    [Parameter(ParameterSetName = 'BySerial', Mandatory = $true, Position = 0)]
    [string[]]$SerialNumber,

    [Parameter(ParameterSetName = 'ByDeviceName', Mandatory = $true)]
    [string[]]$DeviceName,

    [Parameter(ParameterSetName = 'ByGroup', Mandatory = $true)]
    [string]$Group,

    [Parameter(ParameterSetName = 'ByGroup')]
    [switch]$GroupAssignedOnly,

    [Parameter(ParameterSetName = 'ByFilter', Mandatory = $true)]
    [string]$AssignmentFilter,

    # Tenant-wide inventory: every policy + every setting + assignment summary (no device math)
    [Parameter(ParameterSetName = 'All', Mandatory = $true)]
    [switch]$All,

    # -All scoping (additive): narrow the inventory to a group and/or an assignment filter
    [Parameter(ParameterSetName = 'All')]
    [string]$ScopeGroup,

    [Parameter(ParameterSetName = 'All')]
    [string]$ScopeFilter,

    [switch]$SkipUpdates,   # skip feature/quality/driver update profiles
    [switch]$SkipScripts,   # skip platform scripts
    [switch]$SkipApps,      # skip applications (Required / Available / Uninstall per app)
    [switch]$SkipAppPolicies, # skip App Configuration + App Protection policies
    [switch]$SkipEnrollment,  # skip enrollment configurations + Autopilot profiles
    [switch]$SkipTenantConfig, # -All: skip the Tenant setup view (roles, tokens, connectors, groups ...)

    # Raw JSON backup of every object read (secrets redacted) - the restorable record
    [string]$BackupPath,

    [string]$ExportHtml,
    [string]$ExportCsv,
    [string]$ExportJson,
    [switch]$NoHtml,

    [switch]$SkipCompliance,
    [switch]$SkipReportedStatus,

    [ValidateRange(0, [int]::MaxValue)]
    [int]$MaxDevices = 25,
    [ValidateRange(0, [int]::MaxValue)]
    [int]$CacheMinutes = 60,
    [ValidateRange(1, 8)]
    [int]$ThrottleLimit = 4,
    [switch]$Refresh,
    [switch]$PassThru,

    [string]$TenantId,
    [string]$ClientId,
    [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
    [string]$Environment = 'Global',
    [switch]$UseDeviceCode,

    [string]$LogPath
)

Set-StrictMode -Off
$ErrorActionPreference = 'Stop'
$script:Version = '3.3.6'
$script:TemplateSchema = 5
$script:StartTime = Get-Date
$script:GraphThrottle = [math]::Max(1, [int]$ThrottleLimit)   # /$batch requests in flight at once
$script:ContainsDecryptedSecrets = $false
$script:DecryptedOmaSettings = [System.Collections.Generic.List[string]]::new()   # 'policy: name (OMA-URI)'
$script:OmaSecretRows = [System.Collections.Generic.List[object]]::new()   # where each decrypted value sits (policy id, row key, secret reference)
$script:OmaCachePlaceholder = '(encrypted value - decrypted again when the cache is read)'

#region ---------- console helpers ----------------------------------------------------------

function ConvertTo-RsopConsoleText {
    # Tenant text must not drive the terminal (escape sequences, carriage-return overwrites).
    # Line breaks stay: Windows line endings (Out-String writes CRLF there) become plain LF.
    param([string]$Text)
    return (($Text -replace "`r`n", "`n") -replace '[\x00-\x08\x0B-\x1F\x7F-\x9F]', '?')
}
function Write-RsopConsole {
    param([Parameter(Position = 0)]$Object, [System.ConsoleColor]$ForegroundColor, [switch]$NoNewline, [switch]$SkipSessionLog)
    $options = @{}
    if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $options.ForegroundColor = $ForegroundColor }
    if ($NoNewline) { $options.NoNewline = $true }
    $text = ConvertTo-RsopConsoleText ([string]$Object)
    if (-not $SkipSessionLog) { Add-SessionLog 'console' $text }
    Microsoft.PowerShell.Utility\Write-Host $text @options
}
# Session log: everything the console shows plus info-level entries, for the whole run
# (all interactive queries). Save-RsopRunLogFile writes it to logs\IntuneLens-<start>.log.
$script:SessionLog = [System.Collections.Generic.List[object]]::new()
function Add-SessionLog {
    param([string]$Level, [string]$Message)
    [void]$script:SessionLog.Add([pscustomobject]@{ Time = (Get-Date).ToString('HH:mm:ss'); Level = $Level; Message = (ConvertTo-RsopConsoleText $Message) })
}

function Write-Step  { param([string]$Text) Add-SessionLog 'step' $Text; Write-RsopConsole ("==> " + $Text) -ForegroundColor Cyan -SkipSessionLog }
function Write-Info  { param([string]$Text) Add-SessionLog 'info' $Text; Write-RsopConsole ("    " + $Text) -ForegroundColor DarkGray -SkipSessionLog }
function Write-Good  { param([string]$Text) Add-SessionLog 'ok' $Text; Write-RsopConsole ("    " + $Text) -ForegroundColor Green -SkipSessionLog }
function Write-Warn2 { param([string]$Text, [string]$Level = 'warn') Add-SessionLog $Level $Text; Write-RsopConsole ("    ! " + $Text) -ForegroundColor Yellow -SkipSessionLog }

# Run log: every notable event (esp. Graph call failures) is collected here and embedded
# in the HTML report's Warnings panel, so problems are visible without scrollback.
$script:RunLog = [System.Collections.Generic.List[object]]::new()

function Add-RunLog {
    param([ValidateSet('info', 'warn', 'error')][string]$Level, [string]$Message)
    [void]$script:RunLog.Add([pscustomobject]@{
        Time    = (Get-Date).ToString('HH:mm:ss')
        Level   = $Level
        Message = $Message
    })
    if ($Level -eq 'info') { Add-SessionLog 'info' $Message } else { Write-Warn2 $Message -Level $Level }
}

$script:RunLogFile = $null
$script:RunQueries = [System.Collections.Generic.List[object]]::new()
$script:RunFailure = $null
$script:RunOutcome = 'In progress (a window closed mid-run leaves it at this)'

function Initialize-RsopRunLogFile {
    # logs\IntuneLens-<start>.log next to the script (or -LogPath). A folder that cannot be
    # created leaves the run without a log file, never without a report.
    param([string]$Folder)
    try {
        if (-not $Folder) { $Folder = Join-Path $PSScriptRoot 'logs' }
        if (-not (Test-Path -LiteralPath $Folder)) { New-Item -ItemType Directory -Path $Folder -Force | Out-Null }
        $script:RunLogFile = New-RsopOutputFile -Path (Join-Path (Resolve-Path -LiteralPath $Folder).Path ("IntuneLens-{0}.log" -f $script:StartTime.ToString('yyyyMMdd-HHmmss')))
    }
    catch {
        $script:RunLogFile = $null
        Write-RsopConsole ("    ! No run log file: the folder '{0}' is not writable ({1})." -f $Folder, $_.Exception.Message) -ForegroundColor Yellow
    }
}

function Save-RsopRunLogFile {
    # Rewritten after every report / backup and when the run ends (completed, failed or
    # stopped), so the latest state is on disk even if the script never finishes: what ran and
    # where, every error and warning, the tenant setup checklist, then the whole run in order.
    if (-not $script:RunLogFile) { return }
    try {
        $now = Get-Date
        $entries = @($script:SessionLog)
        $problems = @($entries | Where-Object { $_.Level -in @('error', 'warn') })
        $count = { param($l) @($entries | Where-Object { $_.Level -eq $l }).Count }
        $sdk = Get-Module -Name Microsoft.Graph.Authentication | Select-Object -First 1
        $lines = [System.Collections.Generic.List[string]]::new()
        $add = { param($t) [void]$lines.Add([string]$t) }
        & $add ("Intune Lens {0} - run log" -f $script:Version)
        & $add ("Started     {0}" -f $script:StartTime.ToString('yyyy-MM-dd HH:mm:ss zzz'))
        & $add ("Updated     {0} ({1:n0} s)" -f $now.ToString('yyyy-MM-dd HH:mm:ss zzz'), ($now - $script:StartTime).TotalSeconds)
        & $add ("Outcome     {0}" -f $script:RunOutcome)
        & $add ("Command     {0}" -f $script:CommandText)
        & $add ("PowerShell  {0} ({1}) on {2}" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, [System.Runtime.InteropServices.RuntimeInformation]::OSDescription)
        & $add ("Graph SDK   {0}" -f $(if ($sdk) { "Microsoft.Graph.Authentication $($sdk.Version)" } else { 'not loaded' }))
        & $add ("Tenant      {0}" -f $(if ($script:LogTenant) { $script:LogTenant } else { 'not signed in' }))
        $gaps = @($script:SessionCaptureGaps | Where-Object { $_ })
        & $add ("Summary     {0} error(s), {1} warning(s), {2} capture gap(s), {3} info entries" -f (& $count 'error'), (& $count 'warn'), $gaps.Count, (& $count 'info'))
        foreach ($q in $script:RunQueries) {
            & $add ("Query       {0}  {1}" -f $q.Time, $q.Label)
            foreach ($o in @($q.Outputs)) { & $add ("              -> {0}" -f $o) }
            foreach ($r in @($q.Results)) { & $add ("              {0}" -f $r) }
        }
        & $add ''
        & $add '== Errors and warnings =='
        if ($problems.Count) { foreach ($e in $problems) { & $add ("{0} {1,-5} {2}" -f $e.Time, $e.Level.ToUpper(), $e.Message) } } else { & $add '(none)' }
        if ($script:RunFailure) {
            & $add ''
            & $add '== Run stopped with =='
            & $add (Format-RsopError $script:RunFailure)
            & $add ([string]$script:RunFailure.InvocationInfo.PositionMessage)
            & $add ([string]$script:RunFailure.ScriptStackTrace)
        }
        $checks = @($script:RunQueries | ForEach-Object { @($_.Findings) } | Where-Object { $_ } | Select-Object -Unique)
        if ($checks.Count) {
            & $add ''
            & $add '== Tenant setup checklist (act now / check) =='
            foreach ($c in $checks) { & $add $c }
        }
        if ($gaps.Count) {
            & $add ''
            & $add '== Capture gaps (areas this tenant does not serve) =='
            foreach ($g in $gaps) { & $add ("{0} ({1}): {2}" -f $g.Uri, $g.Code, $g.Message) }
        }
        & $add ''
        & $add '== Full log =='
        foreach ($e in $entries) { & $add ("{0} {1,-5} {2}" -f $e.Time, $e.Level.ToUpper(), $e.Message) }
        Set-Content -LiteralPath $script:RunLogFile -Value $lines -Encoding UTF8
        Set-RsopPrivateFile $script:RunLogFile
    }
    catch { Write-RsopConsole ("    ! Could not write the run log '{0}': {1}" -f $script:RunLogFile, $_.Exception.Message) -ForegroundColor Yellow }
}

function Add-RsopRunQuery {
    # One finished query for the run log: label, files written, a line per result, checklist.
    param([string]$Label, $Results, [string[]]$Outputs)
    $Results = @($Results | Where-Object { $null -ne $_ })   # a backup has files, no results
    $lines = foreach ($r in $Results) {
        $p = @($r.Policies)
        "{0}: {1} applying / assigned, {2} excluded or filtered, {3} unknown, {4} settings, {5} conflicts, {6} apps" -f $r.Device.DeviceName,
            @($p | Where-Object { $_.Status -in @('Applies', 'Assigned') }).Count, @($p | Where-Object { $_.Status -in @('Excluded', 'FilteredOut') }).Count,
            @($p | Where-Object { $_.Status -in @('Unknown', 'ReportedOnly') }).Count, @($r.Settings).Count, @($r.Conflicts).Count, @($r.Apps).Count
    }
    $findings = foreach ($r in $Results) {
        if ($r.PSObject.Properties['Tenant'] -and $r.Tenant) {
            foreach ($f in @($r.Tenant.Findings | Where-Object { $_.Severity -in @('bad', 'warn') })) { "{0}: {1}" -f $(if ($f.Severity -eq 'bad') { 'ACT NOW' } else { 'CHECK' }), $f.Title }
        }
    }
    [void]$script:RunQueries.Add([pscustomobject]@{ Time = (Get-Date).ToString('HH:mm:ss'); Label = $Label; Outputs = @($Outputs | Where-Object { $_ }); Results = @($lines); Findings = @($findings) })
    Save-RsopRunLogFile
}

#endregion

#region ---------- graph plumbing -----------------------------------------------------------

$script:RequiredScopes = @(
    'DeviceManagementConfiguration.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'Directory.Read.All',
    'DeviceManagementRBAC.Read.All'   # scope tag names on every policy and app
)
if (-not $SkipApps -or -not $SkipAppPolicies) { $script:RequiredScopes += 'DeviceManagementApps.Read.All' }
# Platform scripts / remediations live behind their own permission; a token holding only
# DeviceManagementConfiguration.Read.All gets 403 from the script endpoints.
if (-not $SkipScripts) { $script:RequiredScopes += 'DeviceManagementScripts.Read.All' }
# Enrollment configurations, Autopilot profiles and Autopilot device records.
if (-not $SkipEnrollment) { $script:RequiredScopes += 'DeviceManagementServiceConfig.Read.All' }
# The tenant setup view (-All, -BackupPath, interactive): Intune roles and scope tags, the
# Entra MDM / MAM user scope and Conditional Access dependencies, Windows 365.
$script:WantTenantConfig = (-not $SkipTenantConfig) -and ($PSCmdlet.ParameterSetName -in @('All', 'Interactive') -or $BackupPath)
if ($script:WantTenantConfig) {
    $script:RequiredScopes += @('DeviceManagementRBAC.Read.All', 'Policy.Read.All', 'CloudPC.Read.All', 'DeviceManagementCloudCA.Read.All', 'Agreement.Read.All')
    # the tenant setup also reads enrollment programs and app-side objects (VPP tokens, iOS
    # provisioning profiles, policy sets, e-books, default app protection) - even with the skips
    if ($SkipEnrollment) { $script:RequiredScopes += 'DeviceManagementServiceConfig.Read.All' }
    if ($SkipApps -and $SkipAppPolicies) { $script:RequiredScopes += 'DeviceManagementApps.Read.All' }
}
$script:RequiredScopes = @($script:RequiredScopes | Select-Object -Unique)

function Connect-RsopGraph {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw "Module 'Microsoft.Graph.Authentication' is not installed. Run: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop | Out-Null

    $ctx = $null
    try { $ctx = Get-MgContext } catch { $ctx = $null }

    $needConnect = $true
    if ($ctx -and $ctx.Scopes) {
        $missing = @($script:RequiredScopes | Where-Object { $ctx.Scopes -notcontains $_ })
        $contextMatches =
            (-not $TenantId -or [string]$ctx.TenantId -ieq $TenantId) -and
            (-not $ClientId -or [string]$ctx.ClientId -ieq $ClientId) -and
            ([string]$ctx.Environment -ieq $Environment)
        if ($missing.Count -eq 0 -and $contextMatches) {
            $needConnect = $false
            Write-Info ("Reusing existing Graph session: {0} ({1})" -f $ctx.Account, $ctx.TenantId)
        }
        elseif (-not $contextMatches) {
            Write-Info 'Existing Graph session does not match the requested tenant, client, or environment; reconnecting.'
        }
    }

    if ($needConnect) {
        Write-Step "Signing in to Microsoft Graph (read-only scopes)"
        $cp = @{ Scopes = $script:RequiredScopes; Environment = $Environment; NoWelcome = $true; ContextScope = 'Process' }
        if ($TenantId)      { $cp['TenantId'] = $TenantId }
        if ($ClientId)      { $cp['ClientId'] = $ClientId }
        if ($UseDeviceCode) { $cp['UseDeviceCode'] = $true }
        Connect-MgGraph @cp
        $ctx = Get-MgContext
        Reset-RsopCorpusCaches
        $script:FilterEvalVariant = 0
        $script:DeviceReportShape = 0
        $script:GraphThrottle = [math]::Max(1, [int]$ThrottleLimit)
    }
    return $ctx
}

# ---------- pacing and progress ------------------------------------------------------------
# Progress bars this run has open, and when each was last drawn. A bar that an error leaves open
# stays on screen and makes the run look stuck, so bars close in finally blocks and any bar still
# open is cleared before a prompt.
$script:ProgressOpen = @{}
$script:ProgressClock = [System.Diagnostics.Stopwatch]::StartNew()

function Write-RsopProgress {
    # Write-Progress, redrawn at most five times a second per bar: thousands of redraws cost real
    # time on a large tenant. -Force draws regardless.
    param([int]$Id, [string]$Activity, [string]$Status, [int]$Percent = -1, [switch]$Force)
    $now = $script:ProgressClock.ElapsedMilliseconds
    if (-not $Force -and $script:ProgressOpen.ContainsKey($Id) -and ($now - $script:ProgressOpen[$Id]) -lt 200) { return }
    $script:ProgressOpen[$Id] = $now
    $bar = @{ Id = $Id; Activity = $(if ($Activity) { $Activity } else { ' ' }); Status = $(if ($Status) { $Status } else { ' ' }) }
    if ($Percent -ge 0) { $bar['PercentComplete'] = [math]::Min(100, $Percent) }
    Write-Progress @bar
}

function Complete-RsopProgress {
    # Closes one progress bar, or every bar this run has open.
    param([int]$Id = -1)
    $ids = $(if ($Id -ge 0) { @($Id) } else { @($script:ProgressOpen.Keys) })
    foreach ($i in $ids) {
        if ($script:ProgressOpen.ContainsKey($i)) { $script:ProgressOpen.Remove($i) }
        Write-Progress -Id $i -Activity ' ' -Completed
    }
}

function Wait-RsopThrottle {
    # The pause before a retry (its own function, so the offline tests can skip the wait).
    param([double]$Seconds)
    if ($Seconds -gt 0) { Start-Sleep -Seconds $Seconds }
}

function Get-RsopRetryDelay {
    # Seconds to wait before retry $Attempt: the service's Retry-After (seconds or an HTTP date)
    # when it sent one, else bounded 2, 4, 8 ... seconds. Never shorten a service delay.
    param($RetryAfter, [int]$Attempt)
    $seconds = 0.0
    if ($null -ne $RetryAfter) {
        $v = $(if ($RetryAfter -is [timespan]) { $RetryAfter.TotalSeconds } else { [string]@($RetryAfter)[0] })
        $d = 0.0
        if ([double]::TryParse([string]$v, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$d)) { $seconds = $d }
        else {
            $when = [datetimeoffset]::MinValue
            if ([datetimeoffset]::TryParse([string]$v, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$when)) { $seconds = ($when - [datetimeoffset]::UtcNow).TotalSeconds }
        }
    }
    if ($seconds -gt 0 -and -not [double]::IsInfinity($seconds) -and -not [double]::IsNaN($seconds)) { return $seconds }
    return [math]::Min(120, [math]::Pow(2, [math]::Min(6, [math]::Max(1, $Attempt))))
}

function Get-RsopErrorRetryAfter {
    # The Retry-After of a failed call, when the exception carries the HTTP response.
    param($ErrorRecord)
    try {
        $ra = $ErrorRecord.Exception.Response.Headers.RetryAfter
        if ($ra -and $ra.Delta) { return $ra.Delta }
        if ($ra -and $ra.Date) { return [timespan]::FromSeconds([math]::Max(0, ($ra.Date - [datetimeoffset]::UtcNow).TotalSeconds)) }
    } catch { }
    return $null
}

function Invoke-Rsop {
    # Thin wrapper over Invoke-MgGraphRequest. The SDK already retries 429 / 503 / 504 after their
    # Retry-After; throttling that outlasts those retries gets three more tries, any other
    # transient failure (5xx, timeout) one more, each after the service's Retry-After or 2, 4, 8 s.
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory = $true)][string]$Uri,
        [object]$Body,
        [System.Collections.IDictionary]$Headers
    )
    $extra = @{}
    if ($Headers -and $Headers.Count) { $extra['Headers'] = $Headers }
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            if ($null -ne $Body) {
                $json = $Body | ConvertTo-Json -Depth 12
                return Invoke-MgGraphRequest -Method $Method -Uri $Uri -Body $json -ContentType 'application/json' -OutputType HashTable @extra
            }
            return Invoke-MgGraphRequest -Method $Method -Uri $Uri -OutputType HashTable @extra
        }
        catch {
            # a rejected request (bad $expand, missing scope, unlicensed feature) won't succeed
            # on a retry - fail fast so the caller's fallback runs without a pointless wait
            if (Test-RsopPermanentError -ErrorRecord $_) { throw }
            $throttled = (Get-RsopServiceError -ErrorRecord $_).Code -in @(429, 503)
            if ($attempt -ge $(if ($throttled) { 4 } else { 2 })) { throw }
            Wait-RsopThrottle -Seconds (Get-RsopRetryDelay -RetryAfter (Get-RsopErrorRetryAfter $_) -Attempt $attempt)
        }
    }
}

function Test-RsopRetryable {
    # $true for failures that a later identical request can get past: throttling, 5xx, timeouts.
    # Report endpoints use it to keep their request shape instead of trying another one.
    param($ErrorRecord)
    if (Test-RsopPermanentError -ErrorRecord $ErrorRecord) { return $false }
    $code = (Get-RsopServiceError -ErrorRecord $ErrorRecord).Code
    if ($code -in @(408, 429, 500, 502, 503, 504)) { return $true }
    return ([string]$ErrorRecord.Exception.Message -match 'timed? ?out|task was cancel|TaskCanceled|temporarily unavailable')
}

function Test-RsopPermanentError {
    # $true for client errors (400/401/403/404/405) - transient failures (429, 5xx,
    # timeouts) stay retryable.
    param($ErrorRecord)
    $code = 0
    try { $code = [int]$ErrorRecord.Exception.Response.StatusCode } catch { $code = 0 }
    if ($code -in @(400, 401, 403, 404, 405, 410, 501)) { return $true }
    $msg = [string]$ErrorRecord.Exception.Message
    return ($msg -match '\b(400|401|403|404|405|410|501)\b|BadRequest|Bad Request|Unauthorized|Forbidden|NotFound|Not Found|MethodNotAllowed|NotImplemented|Not Implemented')
}

function Get-RsopServiceError {
    # Graph's own account of a failed call: HTTP status, service message, error code and request
    # id. Invoke-MgGraphRequest puts the whole exchange (request line, response headers, JSON
    # body) in the exception message and in ErrorDetails; the service error is the JSON body at
    # the end of it, and Intune often nests a second JSON document in error.message. Errors that
    # are not Graph responses keep their own message.
    param($ErrorRecord)
    $raw = [string]$ErrorRecord.Exception.Message
    $details = [string](Get-Prop (Get-Prop $ErrorRecord 'ErrorDetails') 'Message')
    $texts = @(@($details, $raw) | Where-Object { $_ })
    $code = 0; $codeKnown = $true
    try { $code = [int]$ErrorRecord.Exception.Response.StatusCode } catch { $code = 0 }
    if (-not $code) { try { $code = [int]$ErrorRecord.Exception.StatusCode } catch { $code = 0 } }
    foreach ($t in $texts) { if (-not $code -and $t -match 'HTTP/\d(?:\.\d)?\s+(\d{3})\b') { $code = [int]$Matches[1] } }
    if (-not $code -and $raw -match '\b(400|401|403|404|405|410|429|500|501|502|503|504)\b') { $code = [int]$Matches[1]; $codeKnown = $false }

    $msg = $(if ($details) { $details } else { $raw }); $errorCode = ''; $requestId = ''
    $parsed = $null
    foreach ($t in $texts) {
        # the JSON error body: all of ErrorDetails, or the end of an HTTP dump (a header such as
        # x-ms-ags-diagnostic can carry JSON too, so look for the "error" document itself)
        $at = [regex]::Match($t, '\{\s*"error"\s*:')
        $body = $(if ($at.Success) { $t.Substring($at.Index) } elseif ($t -eq $details) { $t } else { '' })
        if (-not $body) { continue }
        # anything after the body's last brace is not part of it
        foreach ($candidate in @($body, $body.Substring(0, $body.LastIndexOf('}') + 1))) {
            if (-not $candidate) { continue }
            try { $parsed = ConvertFrom-Json -InputObject $candidate -AsHashtable -ErrorAction Stop; break } catch { $parsed = $null }
        }
        if ($parsed -is [System.Collections.IDictionary]) { break }
    }
    if ($parsed -is [System.Collections.IDictionary]) {
        $serviceError = Get-Prop $parsed 'error'
        if ($serviceError -isnot [System.Collections.IDictionary]) { $serviceError = $parsed }
        $serviceMessage = [string](Get-Prop $serviceError 'message')
        if ($serviceMessage) {
            if ($serviceMessage.TrimStart().StartsWith('{')) {   # Intune nests a JSON document in error.message
                try {
                    $nested = ConvertFrom-Json -InputObject $serviceMessage -AsHashtable -ErrorAction Stop
                    $innerMessage = [string](Get-Prop $nested 'Message')
                    if ($innerMessage) { $serviceMessage = $innerMessage }
                } catch { }
            }
            # Intune's own text: '<message> - Operation ID (for customer support): <id> - Activity ID:
            # <id> - Url: <internal proxy url>'. Keep the message and the ids support can use.
            if ($serviceMessage -match '^(?<text>.*?)\s+-\s+Operation ID \(for customer support\):\s*(?<op>[0-9a-fA-F-]+)\s+-\s+Activity ID:\s*(?<act>[0-9a-fA-F-]+)(?:\s+-\s+Url:\s*\S+)?\s*$') {
                $text = $Matches['text']; $operationId = $Matches['op']; $activityId = $Matches['act']
                $ids = @("activity id $activityId")
                if ($operationId -notmatch '^[0-]+$') { $ids = @("operation id $operationId") + $ids }
                $serviceMessage = "{0} ({1})" -f $text.TrimEnd('.', ' '), ($ids -join ', ')
            }
            $msg = $serviceMessage
        }
        $errorCode = [string](Get-Prop $serviceError 'code')
        $inner = Get-Prop $serviceError 'innerError'
        $requestId = [string](Get-Prop $inner 'request-id')
        if (-not $requestId) { $requestId = [string](Get-Prop $inner 'requestId') }
    }
    else {
        # an HTTP dump without a JSON error body (gateway pages ...): the status line says it
        foreach ($t in $texts) {
            if ($t -match '^\s*(?:GET|POST|PUT|PATCH|DELETE)\s+\S+\s+(HTTP/\d(?:\.\d)?\s+\d{3}(?:[ \t]+[A-Za-z]+(?![\w-]*:))*)') { $msg = $Matches[1].Trim(); break }
        }
    }
    if (-not $requestId) {
        try {
            $headers = $ErrorRecord.Exception.Response.Headers
            if ($headers -is [System.Collections.IDictionary]) { $requestId = [string](Get-Prop $headers 'request-id') }
            elseif ($headers) { $requestId = @($headers.GetValues('request-id')) -join ', ' }
        } catch { }
    }
    foreach ($t in $texts) { if (-not $requestId -and $t -match '(?<![\w-])request-id:\s*([0-9a-fA-F-]{36})') { $requestId = $Matches[1] } }

    $msg = ($msg -replace '\s*[\r\n]+\s*', ' ').Trim()
    if ($msg.Length -gt 2000) { $msg = $msg.Substring(0, 2000) + ' ...(truncated)' }
    $facts = @()
    if ($code -and $codeKnown) { $facts += "HTTP $code" }
    if ($errorCode) { $facts += "Graph code $errorCode" }
    if ($requestId) { $facts += "request-id $requestId" }
    $text = $msg
    if ($facts.Count -and ($parsed -or $details -or $msg -ne $raw)) { $text = ("{0} ({1})" -f $msg, ($facts -join ', ')) }
    return [pscustomobject]@{ Code = $code; Message = $msg; ErrorCode = $errorCode; RequestId = $requestId; Text = $text }
}

function Format-RsopError {
    # One readable line for a caught error (warnings, run log, backup manifest).
    param($ErrorRecord)
    return (Get-RsopServiceError -ErrorRecord $ErrorRecord).Text
}

function Invoke-RsopStream {
    # POST for report-style endpoints that answer with a Stream (octet-stream +
    # Content-Disposition): the SDK refuses to hand those back inline regardless of
    # -OutputType and demands -OutputFilePath, so land the body in a temp file and
    # parse from there. Works just as well when the tenant answers with plain JSON.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][object]$Body
    )
    $json = $Body | ConvertTo-Json -Depth 12
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('IntuneLens-' + [guid]::NewGuid().ToString('n') + '.json')
    try {
        # throttling and transient failures are retried here (as Invoke-Rsop does); a rejected
        # request shape comes straight back to the caller
        $attempt = 0
        while ($true) {
            $attempt++
            try { Invoke-MgGraphRequest -Method POST -Uri $Uri -Body $json -ContentType 'application/json' -OutputFilePath $tmp | Out-Null; break }
            catch {
                if (-not (Test-RsopRetryable -ErrorRecord $_)) { throw }
                $throttled = (Get-RsopServiceError -ErrorRecord $_).Code -in @(429, 503)
                if ($attempt -ge $(if ($throttled) { 4 } else { 2 })) { throw }
                Wait-RsopThrottle -Seconds (Get-RsopRetryDelay -RetryAfter (Get-RsopErrorRetryAfter $_) -Attempt $attempt)
            }
        }
        if (-not (Test-Path -LiteralPath $tmp)) { return $null }
        $raw = [System.IO.File]::ReadAllText($tmp)
        if (-not $raw) { return $null }
        # ConvertFrom-ReportGrid also copes with raw strings (JSON-in-string / base64)
        try { return $raw | ConvertFrom-Json -AsHashtable } catch { return $raw }
    }
    finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Get-RsopPaged {
    # Array callers require a complete list. Completion-aware callers retain captured items
    # and an explicit failure, including cyclic links. -OnPage streams without retaining items.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [string]$Activity,
        [System.Collections.IDictionary]$Headers,
        [scriptblock]$OnPage,
        [switch]$IncludeCompletion,
        [string[]]$VisitedLinks = @(),
        [string]$CollectionUri
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $seen = 0
    $visited = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $normalize = { param([string]$Link) $Link -replace '^https://[^/]+/', '' -replace '^/?(beta|v1\.0)/', '' -replace '^/', '' }
    foreach ($link in $VisitedLinks) { [void]$visited.Add((& $normalize $link)) }
    if (-not $CollectionUri) { $CollectionUri = $Uri }
    $next = $Uri
    $page = 0
    $failure = $null
    try {
        while ($next) {
            # compare without the host: the first request is relative, next links are absolute
            if (-not $visited.Add((& $normalize ([string]$next)))) {
                throw [System.IO.InvalidDataException]::new('The next link pointed back at a page already read.')
            }
            $page++
            if ($Activity) { Write-RsopProgress -Id 7 -Activity $Activity -Status ("page {0} ({1} items so far)" -f $page, $seen) }
            $resp = Invoke-Rsop -Uri $next -Headers $Headers
            if ($resp -and $resp.ContainsKey('value')) {
                $pageItems = @($resp['value'])
                $seen += $pageItems.Count
                # Continuation URLs may encode or omit $expand. Trust navigation markers
                # in the returned objects rather than the spelling of the request URL.
                foreach ($i in $pageItems) { Complete-RsopNavLinks -Item $i }
                if ($OnPage) { & $OnPage $pageItems }
                else { foreach ($i in $pageItems) { [void]$items.Add($i) } }
            }
            $next = $null
            if ($resp -and $resp.ContainsKey('@odata.nextLink')) { $next = $resp['@odata.nextLink'] }
        }
    }
    catch {
        $failure = $_
        if ($page -gt 1 -or $VisitedLinks.Count -gt 0 -or $_.Exception -is [System.IO.InvalidDataException]) {
            $logicalUri = (& $normalize ($CollectionUri -replace '\?.*$', ''))
            $message = "{0}: list incomplete after {1} captured item(s) ({2})." -f $logicalUri, $seen, (Format-RsopError $_)
            Add-RsopReadProblem -Message $message -Key ("paging:$logicalUri")
            # Do not classify a failed continuation as an unavailable whole collection.
            $exception = [System.IO.InvalidDataException]::new($message, $_.Exception)
            $failure = [System.Management.Automation.ErrorRecord]::new($exception, 'IntuneLens.IncompleteRead', 'ReadError', $CollectionUri)
        }
    }
    finally {
        if ($Activity) { Complete-RsopProgress -Id 7 }
    }
    if ($IncludeCompletion) { return [pscustomobject]@{ Items = $items.ToArray(); Complete = ($null -eq $failure); Error = $failure } }
    if ($failure) { throw $failure }
    return $items.ToArray()
}

function Complete-RsopNavLinks {
    # An expanded navigation (assignments ...) that Graph cut short carries '<nav>@odata.nextLink':
    # read the rest, or flag the navigation unreadable so a partial list never passes as whole.
    param($Item)
    if ($Item -isnot [System.Collections.IDictionary]) { return }
    foreach ($k in @($Item.Keys)) {
        $key = [string]$k
        if (-not $key.EndsWith('@odata.nextLink') -or $key.StartsWith('@')) { continue }
        $nav = $key.Substring(0, $key.Length - '@odata.nextLink'.Length)
        $link = [string]$Item[$k]
        if (-not $link) { continue }
        $read = Get-RsopPaged -Uri $link -IncludeCompletion
        $Item[$nav] = @(@($Item[$nav] | Where-Object { $null -ne $_ }) + @($read.Items))
        if ($read.Complete) { $Item.Remove($k) }
        else {
            $Item['@intuneLens.unreadable'] = @(@($Item['@intuneLens.unreadable']) + $nav | Where-Object { $_ })
            $label = $(if ($Item['displayName']) { $Item['displayName'] } elseif ($Item['name']) { $Item['name'] } else { $Item['id'] })
            if ($read.Error.FullyQualifiedErrorId -notlike 'IntuneLens.IncompleteRead*') {
                Add-RsopReadProblem ("Only part of the {0} of '{1}' could be read ({2}) - the list is incomplete." -f $nav, $label, (Format-RsopError $read.Error))
            }
        }
    }
}

function Get-Prop {
    # Case-insensitive property/key lookup that works on hashtables and PSObjects.
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return , $Object[$Name] }   # the usual case: the exact name
        foreach ($k in $Object.Keys) {
            # unary comma: stop the pipeline from unrolling single-element arrays
            # (a one-row report grid would otherwise lose its shape)
            if ([string]$k -ieq $Name) { return , $Object[$k] }
        }
        return $null
    }
    $p = $Object.PSObject.Properties[$Name]   # (case-insensitive)
    if ($p) { return , $p.Value }
    return $null
}

function Get-PropList {
    # Enumerate collection items on the pipeline. Callers needing a stable array use
    # @(Get-PropList ...); Get-Prop itself preserves arrays and report-grid row shape.
    param($Object, [string]$Name)
    $v = Get-Prop $Object $Name
    if ($null -eq $v) { return }
    return @($v)
}

function Format-GraphDate {
    # The SDK converts ISO JSON dates to DateTime. Preserve an unambiguous ISO value
    # before formatting or sorting; [string]DateTime otherwise depends on culture.
    param($Value)
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) {
        if ($Value.Year -le 1) { return '' }
        return $Value.ToString('o', [Globalization.CultureInfo]::InvariantCulture)
    }
    if ([string]$Value -match '^0001-01-01(?:T|$)') { return '' }
    return [string]$Value
}

function ConvertTo-GraphDateTime {
    # Culture-proof date for comparisons: accepts a DateTime (the SDK and ConvertFrom-Json
    # both turn ISO strings into DateTime) or an ISO / invariant string. Returns MaxValue
    # when the value cannot be read, so unknown dates sort last.
    param($Value)
    if ($Value -is [datetime]) { return $Value.ToUniversalTime() }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $d = [datetime]::MaxValue
    $styles = [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal
    if ([string]$Value -and [datetime]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$d)) { return $d }
    return [datetime]::MaxValue
}

function Add-RsopQuery {
    # Appends an OData query option to a URI that may or may not already carry one.
    param([string]$Uri, [string]$Query)
    if ($Uri.Contains('?')) { return "$Uri&$Query" }
    return "$Uri`?$Query"
}

function Complete-RsopBatchBody {
    # A collection body with @odata.nextLink gets its remaining pages; if they cannot be read the
    # body is marked truncated and the problem recorded (a partial member list is not complete).
    param([string]$Url, $Body, [System.Collections.IDictionary]$Headers)
    # items whose expanded navigation Graph cut short get the rest of it
    if ($Url -match '[?&]\$expand=' -and $Body -is [System.Collections.IDictionary] -and $Body.ContainsKey('value')) {
        foreach ($i in @($Body['value'])) { Complete-RsopNavLinks -Item $i }
    }
    if ($Body -is [System.Collections.IDictionary] -and $Body.ContainsKey('@odata.nextLink') -and $Body['@odata.nextLink']) {
        $read = Get-RsopPaged -Uri ([string]$Body['@odata.nextLink']) -Headers $Headers -IncludeCompletion -VisitedLinks @($Url) -CollectionUri $Url
        $Body['value'] = @(@($Body['value']) + @($read.Items))
        if ($read.Complete) { $Body.Remove('@odata.nextLink') }
        else {
            $Body['@intuneLens.truncated'] = $true
        }
    }
    return $Body
}

function Test-RsopParallelGraph {
    # Parallel requests need Invoke-MgGraphRequest from a module that every runspace can load: the
    # Graph SDK keeps one sign-in per process (Connect-MgGraph -ContextScope Process), which the
    # runspaces share. A stand-in function defined only in this session is invisible to them.
    if ([int]$script:GraphThrottle -le 1) { return $false }
    $cmd = Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue
    return [bool]($cmd -and $cmd.ModuleName -eq 'Microsoft.Graph.Authentication')
}

function Disable-RsopParallelGraph {
    param([string]$Reason)
    if ([int]$script:GraphThrottle -gt 1) {
        $script:GraphThrottle = 1
        Add-RunLog -Level info -Message ("Parallel Graph requests are off for the rest of this run ({0}); reads continue one batch at a time." -f $Reason)
    }
}

function Send-RsopBatchPayloads {
    # POSTs /$batch bodies and returns one result per body, in order: .Response (hashtable) or
    # .Error (ErrorRecord). With -ThrottleLimit above 1 the bodies go out several at a time from
    # parallel runspaces that share the SDK sign-in. A runspace that cannot use the sign-in turns
    # parallel requests off for the run; anything that failed there is sent again here, in turn.
    # $OnResult runs for each body as its answer arrives (progress).
    param([object[]]$Bodies, [scriptblock]$OnResult)
    $count = @($Bodies).Count
    $results = [object[]]::new($count)
    $sendOne = {
        param([int]$Index)
        try { [pscustomobject]@{ Index = $Index; Response = (Invoke-Rsop -Method POST -Uri 'beta/$batch' -Body $Bodies[$Index]); Error = $null } }
        catch { [pscustomobject]@{ Index = $Index; Response = $null; Error = $_ } }
    }
    if ($count -gt 1 -and (Test-RsopParallelGraph)) {
        $work = @(for ($i = 0; $i -lt $count; $i++) { [pscustomobject]@{ Index = $i; Json = ($Bodies[$i] | ConvertTo-Json -Depth 12 -Compress) } })
        try {
            $work | ForEach-Object -ThrottleLimit ([int]$script:GraphThrottle) -Parallel {
                $w = $_
                try { [pscustomobject]@{ Index = $w.Index; Response = (Invoke-MgGraphRequest -Method POST -Uri 'beta/$batch' -Body $w.Json -ContentType 'application/json' -OutputType HashTable); Error = $null } }
                catch { [pscustomobject]@{ Index = $w.Index; Response = $null; Error = $_ } }
            } | ForEach-Object {
                if ($_ -and $null -ne $_.Index) {
                    $results[[int]$_.Index] = $_
                    if ($OnResult -and -not $_.Error) { & $OnResult ([int]$_.Index) }
                }
            }
        }
        catch { Disable-RsopParallelGraph ('parallel batch requests failed: ' + (Format-RsopError $_)) }
        foreach ($r in $results) {
            if ($r -and $r.Error -and ([string]$r.Error.Exception.Message -match 'Authentication needed|Connect-MgGraph|not connected|No account')) {
                Disable-RsopParallelGraph ('a parallel request could not use the sign-in: ' + (Format-RsopError $r.Error))
                break
            }
        }
        # whatever failed or never came back goes again, one body at a time (with Invoke-Rsop's retries)
        for ($i = 0; $i -lt $count; $i++) {
            if ($results[$i] -and -not $results[$i].Error) { continue }
            $results[$i] = & $sendOne $i
            if ($OnResult) { & $OnResult $i }
        }
        return , $results
    }
    for ($i = 0; $i -lt $count; $i++) {
        $results[$i] = & $sendOne $i
        if ($OnResult) { & $OnResult $i }
    }
    return , $results
}

function Invoke-RsopBatch {
    # GETs many relative URLs ('/deviceAppManagement/mobileApps/{id}/assignments') through
    # /$batch, 20 per request (Graph's maximum; pass a smaller -ChunkSize for heavy responses),
    # several requests at once with -ThrottleLimit. Returns @{ url = response body (hashtable) or
    # $null }. Collection bodies that page (@odata.nextLink) are completed with Get-RsopPaged.
    # Sub-requests the service throttles (429, 503) wait for its Retry-After and go out again in
    # a later round, up to three times, and fewer requests go out at once for the rest of the run;
    # a 5xx, a request still throttled after that, and every URL of a batch call that failed
    # outright are read on their own (-NoDirectReads: left $null for a caller that reads them
    # itself). -Headers go with every request (ConsistencyLevel for $count); -FirstPageOnly keeps
    # each body as its first page (a $top=1 probe never pages on).
    param([string[]]$Urls, [string]$Activity, [ValidateRange(1, 20)][int]$ChunkSize = 20,
        [System.Collections.IDictionary]$Headers, [switch]$FirstPageOnly, [switch]$NoDirectReads)
    $complete = {
        param([string]$Url, $Body)
        if ($FirstPageOnly) { return $Body }
        return Complete-RsopBatchBody -Url $Url -Body $Body -Headers $Headers
    }
    $out = @{}
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $pending = [System.Collections.Generic.List[string]]::new()
    foreach ($u in @($Urls)) { if ($u -and $seen.Add($u)) { $pending.Add($u) } }
    $total = $pending.Count
    $throttled = @{}
    $done = 0
    try {
        while ($pending.Count) {
            $chunks = [System.Collections.Generic.List[object]]::new()
            for ($i = 0; $i -lt $pending.Count; $i += $ChunkSize) {
                $chunks.Add([string[]]$pending.GetRange($i, [math]::Min($ChunkSize, $pending.Count - $i)).ToArray())
            }
            $pending = [System.Collections.Generic.List[string]]::new()
            $bodies = @(foreach ($chunk in $chunks) {
                    @{ requests = @(for ($j = 0; $j -lt $chunk.Count; $j++) {
                                $req = @{ id = [string]$j; method = 'GET'; url = $chunk[$j] }
                                if ($Headers -and $Headers.Count) { $req['headers'] = $Headers }
                                $req
                            }) }
                })
            $onResult = $null
            if ($Activity) {
                $onResult = {
                    param([int]$Index)
                    $script:BatchDone += $chunks[$Index].Count
                    Write-RsopProgress -Id 8 -Activity $Activity -Status ("{0}/{1}" -f [math]::Min($script:BatchDone, $total), $total) -Percent ([int](100 * $script:BatchDone / [math]::Max(1, $total)))
                }
                $script:BatchDone = $done
                Write-RsopProgress -Id 8 -Activity $Activity -Status ("{0}/{1}" -f $done, $total) -Percent ([int](100 * $done / [math]::Max(1, $total))) -Force
            }
            $results = Send-RsopBatchPayloads -Bodies $bodies -OnResult $onResult
            $again = [System.Collections.Generic.List[string]]::new()
            $alone = [System.Collections.Generic.List[string]]::new()
            $wait = 0.0
            for ($c = 0; $c -lt $chunks.Count; $c++) {
                $chunk = $chunks[$c]; $res = $results[$c]
                if (-not $res -or $res.Error -or $res.Response -isnot [System.Collections.IDictionary]) { foreach ($u in $chunk) { $alone.Add($u) }; continue }
                $answered = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                foreach ($r in @($res.Response['responses'])) {
                    $idx = -1
                    if (-not ($r -is [System.Collections.IDictionary]) -or -not [int]::TryParse([string]$r['id'], [ref]$idx) -or $idx -lt 0 -or $idx -ge $chunk.Count) { continue }
                    $url = $chunk[$idx]
                    [void]$answered.Add($url)
                    $status = [int]$r['status']
                    if ($status -ge 200 -and $status -lt 300) { $out[$url] = & $complete $url $r['body'] }
                    elseif ($status -eq 429 -or $status -eq 503) {
                        $n = 1 + [int]$throttled[$url]
                        $throttled[$url] = $n
                        $retryAfter = $null
                        if ($r['headers'] -is [System.Collections.IDictionary]) { foreach ($hk in @($r['headers'].Keys)) { if ([string]$hk -ieq 'Retry-After') { $retryAfter = $r['headers'][$hk] } } }
                        if ($n -le 3 -or -not $NoDirectReads) { $wait = [math]::Max($wait, (Get-RsopRetryDelay -RetryAfter $retryAfter -Attempt $n)) }
                        if ($n -le 3) {
                            $again.Add($url)
                        }
                        else { $alone.Add($url) }
                    }
                    elseif ($status -ge 500) { $alone.Add($url) }
                    else { $out[$url] = $null }
                }
                # a request the batch answer left out is read on its own
                foreach ($u in $chunk) { if (-not $answered.Contains($u)) { $alone.Add($u) } }
            }
            if ($wait -gt 0) {
                if ([int]$script:GraphThrottle -gt 1) {
                    $script:GraphThrottle = [math]::Max(1, [int][math]::Floor([int]$script:GraphThrottle / 2))
                    Add-RunLog -Level info -Message ("Microsoft Graph is throttling this tenant: {0} batch request(s) at a time from now on." -f $script:GraphThrottle)
                }
                Add-SessionLog 'info' ("Throttled: waiting {0:n0} s before batch or direct retries." -f $wait)
                Wait-RsopThrottle -Seconds $wait
            }
            foreach ($u in $alone) {
                if ($NoDirectReads) { $out[$u] = $null; continue }
                try { $out[$u] = & $complete $u (Invoke-Rsop -Uri ('beta' + $u) -Headers $Headers) } catch { $out[$u] = $null }
            }
            $done = $total - $again.Count
            if ($again.Count) {
                $pending = $again
            }
        }
    }
    finally {
        if ($Activity) { Complete-RsopProgress -Id 8 }
    }
    return $out
}

function Get-RsopBatchedCollections {
    # Prefetch for per-item reads (a policy's /settings, /assignments ...): one /$batch request
    # per chunk instead of one round trip per item. Returns @{ url = items } for each collection
    # that came back complete; a failed or partial read is left out, so the caller's
    # Get-RsopCollection reads it directly and reports the failure exactly as before.
    param([string[]]$Urls, [string]$Activity, [int]$ChunkSize = 20)
    $out = @{}
    if (-not @($Urls).Count) { return $out }
    $got = Invoke-RsopBatch -Urls $Urls -Activity $Activity -ChunkSize $ChunkSize
    foreach ($u in $got.Keys) {
        $b = $got[$u]
        if ($b -is [System.Collections.IDictionary] -and $b.ContainsKey('value') -and -not $b['@intuneLens.truncated']) { $out[$u] = ConvertTo-RsopList $b['value'] }
    }
    return $out
}

function Get-RsopCollection {
    # One per-item collection: the prefetched copy, else a direct paged read (throws on failure).
    param([hashtable]$Prefetched, [Parameter(Mandatory = $true)][string]$Url)
    if ($Prefetched -and $Prefetched.ContainsKey($Url)) { return $Prefetched[$Url] }
    return Get-RsopPaged -Uri ('beta' + $Url)
}

function Get-RsopItemsWithAssignments {
    # LIST a collection together with each item's assignments. $expand on LIST calls is not
    # documented for most Intune collections, so: try the expand once; if the call is
    # rejected, list plainly; then fetch /{id}/<nav> in batches for every item that came back
    # without the navigation property. Extra navigations (e.g. 'apps') are completed the same way.
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [string[]]$Navigations = @('assignments'),
        [string]$Activity
    )
    $read = Get-RsopPaged -Uri (Add-RsopQuery $Uri ('$expand=' + ($Navigations -join ','))) -Activity $Activity -IncludeCompletion
    # A rejected first-page expand can be retried plainly. A failed continuation retains
    # its captured objects and diagnostic rather than discarding the successful pages.
    if (-not $read.Complete -and -not $read.Items.Count) { $read = Get-RsopPaged -Uri $Uri -Activity $Activity -IncludeCompletion }
    if (-not $read.Complete -and -not $read.Items.Count) { throw $read.Error }
    $items = @($read.Items)

    $base = ($Uri -replace '^(beta|v1\.0)', '') -replace '\?.*$', ''
    foreach ($nav in $Navigations) {
        $missing = @($items | Where-Object { $_ -is [System.Collections.IDictionary] -and -not $_.ContainsKey($nav) -and $_['id'] })
        if ($missing.Count -eq 0) { continue }
        $urls = @($missing | ForEach-Object { '{0}/{1}/{2}' -f $base, $_['id'], $nav })
        $got = Invoke-RsopBatch -Urls $urls -Activity $(if ($Activity) { "$Activity ($nav)" } else { $null })
        foreach ($it in $missing) {
            $u = '{0}/{1}/{2}' -f $base, $it['id'], $nav
            $b = $got[$u]
            if ($b -is [System.Collections.IDictionary] -and $b.ContainsKey('value')) {
                $it[$nav] = ConvertTo-RsopList $b['value']
                if ($b['@intuneLens.truncated']) {
                    $it['@intuneLens.unreadable'] = @(@($it['@intuneLens.unreadable']) + $nav | Where-Object { $_ } | Select-Object -Unique)
                    if ($b['@odata.nextLink']) { $it[($nav + '@odata.nextLink')] = $b['@odata.nextLink'] }
                }
            }
            else {
                # unknown is not empty: flag it so the report / backup never present it as 'not assigned'
                $it[$nav] = @()
                $it['@intuneLens.unreadable'] = @(@($it['@intuneLens.unreadable']) + $nav | Where-Object { $_ })
                $label = $(if ($it['displayName']) { $it['displayName'] } elseif ($it['name']) { $it['name'] } else { $it['id'] })
                Add-RsopReadProblem ("Could not read the {0} of '{1}' ({2}) - shown without them." -f $nav, $label, $base)
            }
        }
    }
    return , $items
}

#endregion

#region ---------- raw backup (-BackupPath) -------------------------------------------------

$script:BackupRoot = $null
$script:BackupFiles = [System.Collections.Generic.List[object]]::new()
$script:BackupProblems = New-Object System.Collections.Generic.List[string]
$script:ReadProblems = New-Object System.Collections.Generic.List[string]
$script:ReadProblemKeys = @{}
# Never written to a backup or shown in a report: enrollment / VPP tokens, QR codes,
# passwords and private key material. (Matched case-insensitively on property names.)
$script:SecretProps = @('tokenValue', 'token', 'qrCodeContent', 'qrCodeImage', 'password', 'preSharedKey',
    'sharedSecret', 'privateKey', 'certificatePassword', 'pfxBlob', 'encryptedPfxBlob', 'encryptedPfxPassword',
    'enrollmentToken', 'appleIdPassword', 'clientSecret', 'secretValue', 'wifiPassword', 'adminAccountPassword',
    'adDomainPassword', 'deviceAccountPassword', 'productKey', 'advancedThreatProtectionOnboardingBlob',
    'advancedThreatProtectionOffboardingBlob', 'azureOperationalInsightsWorkspaceKey', 'kioskModeExitCode', 'activationCodes')

function New-RsopBackupDirectory {
    # Each capture owns a new directory. A second run in the same second (or an existing
    # capture copied back into this folder) must not overwrite objects or its manifest.
    param([string]$ParentPath, [string]$TenantKey)
    if (-not (Test-Path -LiteralPath $ParentPath)) { New-Item -ItemType Directory -Path $ParentPath -Force | Out-Null }
    $parent = (Resolve-Path -LiteralPath $ParentPath).ProviderPath
    $name = 'IntuneBackup-{0}-{1}' -f $TenantKey, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $suffix = 1
    while ($true) {
        $candidate = Join-Path $parent ($name + $(if ($suffix -gt 1) { "-$suffix" } else { '' }))
        if (Test-Path -LiteralPath $candidate) { $suffix++; continue }
        $reservationPath = $candidate + '.reserve'
        $reservation = $null
        try {
            # CreateNew claims a name atomically. Directory creation alone can race because
            # the filesystem may return an existing directory to two simultaneous creators.
            $reservation = [System.IO.FileStream]::new($reservationPath, [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write, [System.IO.FileShare]::None, 1, [System.IO.FileOptions]::DeleteOnClose)
        }
        catch {
            if (Test-Path -LiteralPath $reservationPath) { $suffix++; continue }
            throw
        }
        try {
            if (Test-Path -LiteralPath $candidate) { $suffix++; continue }
            $created = New-Item -ItemType Directory -Path $candidate -ErrorAction Stop
            $path = $created.FullName
            Set-RsopPrivateFile -Path $path -Directory
            return $path
        }
        catch {
            # Only an occupied name is recoverable. Permission/disk/path errors still fail.
            if (-not (Test-Path -LiteralPath $candidate)) { throw }
            $suffix++
        }
        finally { $reservation.Dispose() }
    }
}

function Protect-RsopSecrets {
    # Deep copy of a Graph object with secret-bearing properties replaced by a marker.
    param($Value, [int]$Depth = 0)
    if ($Depth -gt 80) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) {
            $ks = [string]$k
            $v = $Value[$k]
            if ($script:SecretProps -contains $ks -and $null -ne $v -and "$v" -ne '') { $o[$ks] = '<redacted by Intune Lens>'; continue }
            $o[$ks] = Protect-RsopSecrets -Value $v -Depth ($Depth + 1)
        }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $arr = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $Value) { [void]$arr.Add((Protect-RsopSecrets -Value $e -Depth ($Depth + 1))) }
        return , $arr.ToArray()
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        # deserialized (cached) objects: walk them like dictionaries
        $o = [ordered]@{}
        foreach ($pp in $Value.PSObject.Properties) {
            $v = $pp.Value
            if ($script:SecretProps -contains $pp.Name -and $null -ne $v -and "$v" -ne '') { $o[$pp.Name] = '<redacted by Intune Lens>'; continue }
            $o[$pp.Name] = Protect-RsopSecrets -Value $v -Depth ($Depth + 1)
        }
        return $o
    }
    return $Value
}

function ConvertTo-SafeFileName {
    param([string]$Text, [int]$Max = 80)
    $t = ([string]$Text -replace '[\\/:*?"<>|\x00-\x1f]', '_').Trim().TrimEnd('.')
    if (-not $t) { $t = 'unnamed' }
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max).TrimEnd() }
    return $t
}

function Get-RsopExportBaseName {
    # The same portable name is used by automatic reports and their browser CSV downloads.
    # Keep Unicode names readable, bound component lengths, and exclude path/control characters.
    param([string]$Label, $Results, [string]$Tenant, [datetime]$Timestamp = (Get-Date))
    $slug = {
        param([string]$Text, [int]$Max)
        $part = ([regex]::Replace(([string]$Text).Normalize(), '[^\p{L}\p{N}-]+', '-') -replace '-+', '-').Trim('-')
        if ($part.Length -gt $Max) { $part = $part.Substring(0, $Max).TrimEnd('-') }
        if (-not $part) { $part = 'unknown' }
        return $part
    }
    $tenantPart = [string]$script:TenantDomain
    if (-not $tenantPart) { $tenantPart = [string]$script:TenantName }
    if (-not $tenantPart) { $tenantPart = $Tenant }
    $items = @($Results | Where-Object { $null -ne $_ })
    $scope = $Label
    if ($items.Count -eq 1 -and $items[0].Device.Scope -eq 'device') {
        $device = $items[0].Device
        $parts = @('Device')
        if ($device.DeviceName) { $parts += & $slug ([string]$device.DeviceName) 55 }
        if ($device.SerialNumber) { $parts += & $slug ([string]$device.SerialNumber) 30 }
        $scope = $parts -join '-'
    }
    elseif ($items.Count -eq 1 -and $items[0].Device.Scope -eq 'group') { $scope = 'Assignments-' + $Label }
    elseif ($items.Count -gt 1) { $scope = $items.Count.ToString() + '-devices-' + $Label }
    return 'IntuneLens-{0}-{1}-{2}' -f (& $slug $tenantPart 45), (& $slug $scope 100), $Timestamp.ToString('yyyy-MM-dd-HHmm')
}

function Remove-RsopKeys {
    # Copies of hashtables without the named keys (e.g. bulky settingDefinitions). Nulls are
    # dropped: an empty read arrives here as $null and must back up as [], not [null].
    param($Items, [string[]]$Keys)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($it in @($Items)) {
        if ($null -eq $it) { continue }
        if ($it -isnot [System.Collections.IDictionary]) { [void]$out.Add($it); continue }
        $c = [ordered]@{}
        foreach ($k in $it.Keys) { if ($Keys -notcontains [string]$k) { $c[[string]$k] = $it[$k] } }
        [void]$out.Add($c)
    }
    return , $out.ToArray()
}

function ConvertTo-RsopList {
    # Always a real array (nulls dropped): a one-element collection must stay a JSON array in
    # the backup - Graph rejects an object where it expects a collection on restore.
    param($Value)
    return , @(@($Value) | Where-Object { $null -ne $_ })
}

function Add-RsopReadProblem {
    # A read that failed or came back incomplete: shown in the report warnings and listed in
    # the backup manifest, so a partial object is never mistaken for a complete one.
    param([string]$Message, [string]$Key)
    if ($Key) {
        if ($script:ReadProblemKeys.ContainsKey($Key) -and $script:ReadProblems.Contains($script:ReadProblemKeys[$Key])) { return }
        $script:ReadProblemKeys[$Key] = $Message
    }
    if ($script:ReadProblems -notcontains $Message) {
        [void]$script:ReadProblems.Add($Message)
        Add-RunLog -Level warn -Message $Message
    }
}

function Save-RsopBackupItem {
    # -BackupPath: writes one Graph object exactly as Graph returned it (secrets redacted),
    # plus the sub-collections fetched alongside it (settings, assignments, definition
    # values ...), to <backup>\<Area>\<name>__<id>.json - the restorable record behind the report.
    param([string]$Area, $Item, [hashtable]$Extra = @{}, [string]$Name)
    if (-not $script:BackupRoot -or $null -eq $Item) { return }
    $id = ''
    try {
        $id = [string](Get-Prop $Item 'id')
        if (-not $Name) { $Name = [string](Get-Prop $Item 'displayName') }
        if (-not $Name) { $Name = [string](Get-Prop $Item 'name') }
        if (-not $Name) { $Name = $(if ($id) { $id } else { $Area }) }
        $doc = [ordered]@{}
        if ($Item -is [System.Collections.IDictionary]) { foreach ($k in $Item.Keys) { $doc[[string]$k] = $Item[$k] } }
        else { foreach ($pp in $Item.PSObject.Properties) { $doc[$pp.Name] = $pp.Value } }
        foreach ($k in $Extra.Keys) { $doc[[string]$k] = $Extra[$k] }
        $doc.Remove('@odata.context')
        $dir = Join-Path $script:BackupRoot (ConvertTo-SafeFileName $Area)
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        # ids are unique per collection but can share a long prefix (enrollment defaults are
        # '<tenant id>_DefaultLimit', ...). Long ids become prefix~hash: unique, stable between
        # backups, and short enough to keep paths under the 260-character Windows limit.
        $idPart = ConvertTo-SafeFileName $id 400
        if ($idPart.Length -gt 36) {
            $hash = [Convert]::ToHexString([System.Security.Cryptography.SHA1]::HashData([Text.Encoding]::UTF8.GetBytes($id))).Substring(0, 12).ToLowerInvariant()
            $idPart = $idPart.Substring(0, 8) + '~' + $hash
        }
        $suffix = $(if ($id -and $id -ne $Name) { '__' + $idPart } else { '' })
        $file = Join-Path $dir ((ConvertTo-SafeFileName $Name 50) + $suffix + '.json')
        $n = 1
        while ($script:BackupFiles.Count -and (Test-Path -LiteralPath $file) -and @($script:BackupFiles | Where-Object { $_.File -eq [IO.Path]::GetRelativePath($script:BackupRoot, $file) }).Count) {
            $n++; $file = Join-Path $dir ((ConvertTo-SafeFileName $Name 50) + $suffix + "_$n.json")
        }
        (Protect-RsopSecrets -Value $doc) | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $file -Encoding UTF8
        [void]$script:BackupFiles.Add([pscustomobject]@{ Area = $Area; Name = $Name; Id = $id; File = [IO.Path]::GetRelativePath($script:BackupRoot, $file) })
    }
    catch {
        $msg = "Backup: could not write '{0}' ({1}): {2}" -f $Name, $Area, (Format-RsopError $_)
        [void]$script:BackupProblems.Add($msg)
        Write-Warn2 $msg
    }
}

function Complete-RsopBackup {
    # manifest.json next to the backed-up objects: counts per area, the group / filter /
    # scope tag maps that assignments refer to by id, the redaction list and the checklist.
    param($Corpus, [string]$TenantKey, [string]$Account)
    if (-not $script:BackupRoot) { return }
    $tc = $Corpus.tenantConfig
    $areas = [ordered]@{}
    foreach ($f in ($script:BackupFiles | Sort-Object Area, Name)) { if (-not $areas.Contains($f.Area)) { $areas[$f.Area] = 0 }; $areas[$f.Area]++ }
    $manifest = [ordered]@{
        tool                     = "Intune Lens $script:Version"
        tenantId                 = $TenantKey
        account                  = $Account
        generated                = (Get-Date).ToString('o')
        note                     = 'Raw Microsoft Graph (beta) objects exactly as read, one file per object, plus the sub-collections fetched with them (settings, assignments, definition values, ...). Assignments reference groups, assignment filters and scope tags by id - the maps below resolve them. This is a read-only export: restoring means recreating objects (they get new ids) and re-pointing assignments.'
        containsDecryptedSecrets = [bool]$script:ContainsDecryptedSecrets
        redactedProperties       = $script:SecretProps
        sensitiveContent         = 'Kept for a faithful restore, treat as sensitive: decrypted custom OMA-URI values (see containsDecryptedSecrets), custom configuration / imported Wi-Fi payloads (may embed credentials), free-form app configuration values (keys such as password / apiKey are hidden in the report but kept here), Office configuration XML (may hold a PIDKEY), script bodies, BIOS configuration files, group member lists.'
        objectCounts             = $areas
        groups                   = @($(if ($tc) { $tc.Groups | Select-Object Id, Name, Membership, Rule, RuleState, Synced, Missing, MemberCount, Owners, @{ n = 'UsedBy'; e = { @($_.UsedBy | ForEach-Object { "{0} ({1}, {2})" -f $_.Name, $_.Kind, $_.Mode }) } } }))
        assignmentFilters        = @($Corpus.filters)
        scopeTags                = $(if ($tc) { $tc.ScopeTags } else { $null })
        checklist                = @($(if ($tc) { $tc.Findings }))
        # files that could not be written, then reads that failed or came back partial (objects
        # affected carry '@intuneLens.incomplete' / '@intuneLens.unreadable'), then whole areas
        # that could not be listed - an area missing from objectCounts is NOT proof it is empty
        problems                 = $script:BackupProblems.ToArray()
        readProblems             = @(@($Corpus.warnings) + @($script:ReadProblems) + @($script:RunLog | Where-Object { $_.Level -in @('warn', 'error') } | ForEach-Object { $_.Message }) | Where-Object { $_ } | Select-Object -Unique)
        # tenant-setup reads this tenant does not serve (not licensed, access denied, legacy API):
        # nothing of them is in the backup - record their configuration elsewhere if it exists
        captureGaps              = @($script:CaptureGaps | ForEach-Object { [ordered]@{ read = $_.Uri; status = $_.Code; detail = $_.Diagnostic } })
        files                    = $script:BackupFiles.ToArray()
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:BackupRoot 'manifest.json') -Encoding UTF8
    Write-Good ("Backup: {0} objects in {1} areas -> {2}" -f $script:BackupFiles.Count, $areas.Count, $script:BackupRoot)
    if ($script:ContainsDecryptedSecrets) { Write-Warn2 'The backup contains decrypted custom OMA-URI values - store it like a password export.' }
    if ($script:BackupProblems.Count) { Write-Warn2 ("{0} object(s) could not be written - see manifest.json 'problems'." -f $script:BackupProblems.Count) }
    $longest = ($script:BackupFiles | ForEach-Object { (Join-Path $script:BackupRoot $_.File).Length } | Measure-Object -Maximum).Maximum
    if ($longest -gt 259) { Write-Warn2 ("Some backup paths are {0} characters long - Explorer and zip tools stop at 260. Use a shorter -BackupPath (for example D:\IB)." -f $longest) }
    $nRead = @($manifest.readProblems).Count
    if ($nRead) { Write-Warn2 ("{0} read(s) failed or were incomplete - the backup is partial there; see manifest.json 'readProblems'." -f $nRead) }
    $nGaps = @($manifest.captureGaps).Count
    if ($nGaps) { Write-Info ("{0} tenant-setup area(s) this tenant does not serve (not licensed, access denied, legacy API) are listed in manifest.json 'captureGaps'." -f $nGaps) }
    Add-RsopRunQuery -Label ("Backup: {0} objects" -f $script:BackupFiles.Count) -Outputs @($script:BackupRoot)
}

#endregion

#region ---------- report-grid parsing ------------------------------------------------------

function ConvertFrom-ReportGrid {
    # Normalizes Intune report responses ({Schema:[{Column}],Values:[[...]]}) and the
    # evaluateAssignmentFilter stream (raw JSON, JSON-in-string, or base64-in-'value')
    # into an array of PSCustomObjects.
    param($Response)

    if ($null -eq $Response) { return @() }

    if ($Response -is [string]) {
        $s = $Response.Trim()
        if ($s.StartsWith('{') -or $s.StartsWith('[')) {
            try { return ConvertFrom-ReportGrid -Response ($s | ConvertFrom-Json -AsHashtable) } catch { }
            try { return ConvertFrom-ReportGrid -Response ($s | ConvertFrom-Json) } catch { return @() }
        }
        try {
            $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($s))
            if ($decoded.TrimStart().StartsWith('{') -or $decoded.TrimStart().StartsWith('[')) {
                return ConvertFrom-ReportGrid -Response $decoded
            }
        } catch { }
        return @()
    }

    $schema = Get-Prop $Response 'Schema'
    $values = Get-Prop $Response 'Values'
    if ($schema -and $null -ne $values) {
        $cols = @()
        foreach ($c in @($schema)) {
            $cn = Get-Prop $c 'Column'
            if (-not $cn) { $cn = [string]$c }
            $cols += $cn
        }
        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($v in @($values)) {
            $row = [ordered]@{}
            $arr = @($v)
            for ($i = 0; $i -lt $cols.Count -and $i -lt $arr.Count; $i++) { $row[$cols[$i]] = $arr[$i] }
            [void]$rows.Add([pscustomobject]$row)
        }
        return $rows.ToArray()
    }

    $val = Get-Prop $Response 'value'
    if ($null -ne $val) {
        if ($val -is [string]) { return ConvertFrom-ReportGrid -Response $val }
        $out = @()
        foreach ($item in @($val)) {
            if ($item -is [System.Collections.IDictionary]) { $out += [pscustomobject]$item } else { $out += $item }
        }
        return $out
    }

    return @()
}

#endregion

#region ---------- value rendering helpers --------------------------------------------------

function Format-SettingValue {
    # Values are also used for conflict comparisons and exports. Preserve their full
    # content here; the report clips lengthy values when it presents them.
    param($Value, [switch]$FreeFormKeys)
    if ($null -eq $Value) { return '' }
    if ($Value -is [datetime] -or $Value -is [datetimeoffset]) { return (Format-GraphDate $Value) }
    if ($Value -is [bool]) { if ($Value) { return 'True' } else { return 'False' } }
    if ($Value -is [System.Collections.IDictionary] -or ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string])) {
        try {
            $clean = Remove-JsonNoise -Value $Value -FreeFormKeys:$FreeFormKeys
            $j = $clean | ConvertTo-Json -Depth 100 -Compress
            return $j
        } catch { return [string]$Value }
    }
    return [string]$Value
}

function Remove-JsonNoise {
    # Strips null-valued keys and @odata.type annotations from nested objects so JSON
    # values in the report show only what is actually configured.
    param($Value, [int]$Depth = 0, [switch]$FreeFormKeys)
    if ($Depth -gt 80) { return '(nested value - not shown)' }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $props = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) { $props[$p.Name] = $p.Value }
        $Value = $props
    }
    if ($Value -is [System.Collections.IDictionary]) {
        # free-form name / value pairs (VPN custom data, SSO extension keys, Tunnel advanced
        # settings, custom app settings): the NAME says whether the value is a secret
        $pairName = $null
        foreach ($nk in @('name', 'key', 'keyName', 'settingName', 'appConfigKey')) {
            if ($Value.Contains($nk) -and $Value[$nk] -is [string]) { $pairName = [string]$Value[$nk]; break }
        }
        $hidePair = ($pairName -and (Test-RsopSecretName $pairName))
        $o = [ordered]@{}
        foreach ($k in $Value.Keys) {
            $ks = [string]$k
            if ($ks.StartsWith('@') -or $ks.Contains('@odata')) { continue }
            $v = $Value[$k]
            if ($null -eq $v) { continue }
            # nested secrets (e.g. companyCodes[].enrollmentToken) never reach a report value
            if (($script:SecretProps -contains $ks -or ($FreeFormKeys -and (Test-RsopSecretName $ks) -and $v -isnot [bool])) -and "$v" -ne '') { $o[$ks] = '(secret - not shown)'; continue }
            if ($hidePair -and $ks -in @('value', 'keyValue', 'stringValue', 'appConfigKeyValue', 'valueString', 'valueInteger', 'valueStringArray', 'valueBundle', 'valueBundleArray', 'valueInt', 'valueFloat', 'valueBoolean') -and $v -isnot [bool] -and "$v" -ne '') { $o[$ks] = '(secret - not shown)'; continue }
            $o[$ks] = Remove-JsonNoise -Value $v -Depth ($Depth + 1) -FreeFormKeys:$FreeFormKeys
        }
        return $o
    }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $arr = @()
        foreach ($e in $Value) { $arr += , (Remove-JsonNoise -Value $e -Depth ($Depth + 1) -FreeFormKeys:$FreeFormKeys) }
        return , $arr
    }
    return $Value
}

function Format-IsoDuration {
    # 'P5D' -> 'P5D (5 days)', 'PT30M' -> 'PT30M (30 minutes)'. Non-durations pass through.
    param([string]$Text)
    if ($Text -notmatch '^P(?=\d|T\d)(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+(?:\.\d+)?)S)?)?$') { return $Text }
    $units = @('year', 'month', 'week', 'day', 'hour', 'minute', 'second')
    $parts = @()
    for ($i = 1; $i -le 7; $i++) {
        if ($Matches[$i]) {
            $n = [double]$Matches[$i]
            $parts += ("{0} {1}{2}" -f $Matches[$i], $units[$i - 1], $(if ($n -eq 1) { '' } else { 's' }))
        }
    }
    if ($parts.Count -eq 0) { return "$Text (immediately)" }
    return ("{0} ({1})" -f $Text, ($parts -join ' '))
}

function ConvertFrom-Base64Text {
    # Base64 -> UTF-8 text (BOM stripped). Returns $null when the input isn't base64.
    param([string]$Value)
    if (-not $Value) { return $null }
    try {
        $t = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Value))
        return $t.TrimStart([char]0xFEFF).Trim()
    } catch { return $null }
}

function ConvertTo-FriendlyName {
    # 'defenderSecurityCenterDisableAppBrowserUI' -> 'Defender Security Center Disable App Browser UI'
    param([string]$Text)
    if (-not $Text) { return $Text }
    $t = $Text -creplace '([a-z0-9])([A-Z])', '$1 $2'
    $t = $t -replace '[_\.]+', ' '
    $t = $t.Trim()
    if ($t.Length -gt 0) { $t = $t.Substring(0, 1).ToUpper() + $t.Substring(1) }
    return $t
}

function Get-DefinitionTail {
    # Last meaningful chunk of a settings-catalog / intent definition id.
    param([string]$DefinitionId)
    if (-not $DefinitionId) { return $DefinitionId }
    $tail = ($DefinitionId -split '_')[-1]
    return ConvertTo-FriendlyName $tail
}

#endregion

#region ---------- settings catalog flattening ----------------------------------------------

$script:ReusableSettingNames = @{}

function Resolve-ReusableSettingName {
    param([string]$Id)
    if (-not $Id) { return $Id }
    if ($script:ReusableSettingNames.ContainsKey($Id)) { return $script:ReusableSettingNames[$Id] }
    $name = $Id
    try {
        $r = Invoke-Rsop -Uri ("beta/deviceManagement/reusablePolicySettings/{0}?`$select=id,displayName" -f $Id)
        if ($r -and $r['displayName']) { $name = ("{0} (reusable setting)" -f $r['displayName']) }
    } catch { }
    $script:ReusableSettingNames[$Id] = $name
    return $name
}

function Expand-CatalogInstance {
    # Recursively flattens a deviceManagementConfigurationSettingInstance tree into rows.
    param(
        $Instance,
        [hashtable]$Defs,
        [string]$Prefix,
        [System.Collections.Generic.List[object]]$Rows
    )
    if ($null -eq $Instance) { return }

    $odata = [string](Get-Prop $Instance '@odata.type')
    $defId = [string](Get-Prop $Instance 'settingDefinitionId')
    $def = $null
    if ($defId -and $Defs.ContainsKey($defId)) { $def = $Defs[$defId] }

    $name = $null
    if ($def) { $name = [string](Get-Prop $def 'displayName') }
    if (-not $name) { $name = Get-DefinitionTail $defId }
    $display = if ($Prefix) { "$Prefix > $name" } else { $name }

    # Microsoft reference for this setting, straight from the setting definition Graph already
    # expanded: a concise description (prefer 'description', fall back to 'helpText') and the
    # first infoUrls entry (usually a learn.microsoft.com deep link). Surfaced in the report's
    # detail inspector as "Microsoft Learn".
    $rowInfo = ''
    $rowInfoUrl = ''
    if ($def) {
        $desc = [string](Get-Prop $def 'description')
        if (-not $desc) { $desc = [string](Get-Prop $def 'helpText') }
        if ($desc) {
            $desc = ($desc -replace '\s+', ' ').Trim()
            if ($desc.Length -gt 400) { $desc = $desc.Substring(0, 397) + '...' }
            $rowInfo = $desc
        }
        foreach ($u in (Get-PropList $def 'infoUrls')) { if ($u) { $rowInfoUrl = [string]$u; break } }
    }

    switch -Wildcard ($odata) {

        '*choiceSettingInstance' {
            $cv = Get-Prop $Instance 'choiceSettingValue'
            $optId = [string](Get-Prop $cv 'value')
            $optName = $null
            if ($def) {
                $opts = Get-Prop $def 'options'
                foreach ($o in @($opts)) {
                    if ([string](Get-Prop $o 'itemId') -eq $optId) { $optName = [string](Get-Prop $o 'displayName'); break }
                }
            }
            if (-not $optName) { $optName = Get-DefinitionTail $optId }
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = $optName; Info = $rowInfo; InfoUrl = $rowInfoUrl })
            foreach ($child in (Get-PropList $cv 'children')) {
                Expand-CatalogInstance -Instance $child -Defs $Defs -Prefix $display -Rows $Rows
            }
        }

        '*choiceSettingCollectionInstance' {
            $vals = @(Get-PropList $Instance 'choiceSettingCollectionValue')
            $labels = @()
            foreach ($cv in $vals) {
                $optId = [string](Get-Prop $cv 'value')
                $optName = $null
                if ($def) {
                    $opts = Get-Prop $def 'options'
                    foreach ($o in @($opts)) {
                        if ([string](Get-Prop $o 'itemId') -eq $optId) { $optName = [string](Get-Prop $o 'displayName'); break }
                    }
                }
                if (-not $optName) { $optName = Get-DefinitionTail $optId }
                $labels += $optName
            }
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = ($labels -join '; '); Info = $rowInfo; InfoUrl = $rowInfoUrl })
            $idx = 0
            foreach ($cv in $vals) {
                foreach ($child in (Get-PropList $cv 'children')) {
                    Expand-CatalogInstance -Instance $child -Defs $Defs -Prefix ("{0} [{1}]" -f $display, $idx) -Rows $Rows
                }
                $idx++
            }
        }

        '*simpleSettingInstance' {
            $sv = Get-Prop $Instance 'simpleSettingValue'
            $svType = [string](Get-Prop $sv '@odata.type')
            $val = Get-Prop $sv 'value'
            if ($svType -like '*Secret*') { $val = '(secret - not shown)' }
            elseif ($svType -like '*Reference*') { $val = Resolve-ReusableSettingName ([string]$val) }
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = (Format-SettingValue $val); Info = $rowInfo; InfoUrl = $rowInfoUrl })
        }

        '*simpleSettingCollectionInstance' {
            $vals = @()
            foreach ($sv in (Get-PropList $Instance 'simpleSettingCollectionValue')) {
                $svType = [string](Get-Prop $sv '@odata.type')
                if ($svType -like '*Secret*') { $vals += '(secret)' } else { $vals += (Format-SettingValue (Get-Prop $sv 'value')) }
            }
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = ($vals -join '; '); Info = $rowInfo; InfoUrl = $rowInfoUrl })
        }

        '*groupSettingCollectionInstance' {
            $groups = @(Get-PropList $Instance 'groupSettingCollectionValue')
            $idx = 0
            foreach ($g in $groups) {
                $p = if ($groups.Count -gt 1) { "{0} [{1}]" -f $display, $idx } else { $display }
                foreach ($child in (Get-PropList $g 'children')) {
                    Expand-CatalogInstance -Instance $child -Defs $Defs -Prefix $p -Rows $Rows
                }
                $idx++
            }
            if ($groups.Count -eq 0) {
                [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = '(configured, empty)'; Info = $rowInfo; InfoUrl = $rowInfoUrl })
            }
        }

        '*groupSettingInstance' {
            $g = Get-Prop $Instance 'groupSettingValue'
            foreach ($child in (Get-PropList $g 'children')) {
                Expand-CatalogInstance -Instance $child -Defs $Defs -Prefix $display -Rows $Rows
            }
        }

        default {
            # Unknown instance type: record what we can.
            $val = Get-Prop $Instance 'value'
            [void]$Rows.Add([pscustomobject]@{ Key = $defId; Setting = $display; Value = (Format-SettingValue $val); Info = $rowInfo; InfoUrl = $rowInfoUrl })
        }
    }
}

$script:CatalogDefinitionCache = @{}   # settingDefinitionId -> definition, or $null when configurationSettings has none by that id

function Get-CatalogDefinitionIds {
    # Every settingDefinitionId in the setting instances of one policy (the definitions
    # Expand-CatalogInstance looks up). Iterative: policies hold thousands of nested instances.
    param($SettingItems)
    $ids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $stack = [System.Collections.Generic.Stack[object]]::new()
    foreach ($item in @($SettingItems)) { if ($item -is [System.Collections.IDictionary] -and $null -ne $item['settingInstance']) { $stack.Push($item['settingInstance']) } }
    while ($stack.Count) {
        $node = $stack.Pop()
        if ($node -is [System.Collections.IDictionary]) {
            foreach ($k in $node.Keys) {
                $v = $node[$k]
                if ($null -eq $v) { continue }
                if ([string]$k -eq 'settingDefinitionId') { [void]$ids.Add([string]$v) }
                elseif ($v -is [System.Collections.IDictionary] -or $v -is [System.Collections.IList]) { $stack.Push($v) }
            }
        }
        elseif ($node -is [System.Collections.IList]) {
            foreach ($x in $node) { if ($x -is [System.Collections.IDictionary] -or $x -is [System.Collections.IList]) { $stack.Push($x) } }
        }
    }
    return , $ids
}

function Read-CatalogDefinitions {
    # Reads each setting definition once (deviceManagement/configurationSettings/{id}), batched.
    # Policies share most of their definitions, so this replaces downloading every definition
    # again with each policy. An id the catalog does not serve is remembered as $null and its
    # policies are read the old way, with their definitions expanded.
    param([string[]]$Ids)
    $todo = @($Ids | Where-Object { $_ -and -not $script:CatalogDefinitionCache.ContainsKey($_) })
    if (-not $todo.Count) { return }
    $urlOf = @{}
    foreach ($id in $todo) { $urlOf[$id] = '/deviceManagement/configurationSettings/' + [uri]::EscapeDataString($id) }
    $got = Invoke-RsopBatch -Urls @($urlOf.Values) -Activity 'Setting definitions'
    foreach ($id in $todo) {
        $b = $got[$urlOf[$id]]
        $script:CatalogDefinitionCache[$id] = $(if ($b -is [System.Collections.IDictionary] -and $b['id']) { $b } else { $null })
    }
}

function Convert-CatalogSettings {
    # $SettingItems = items from configurationPolicies/{id}/settings, either with their
    # definitions expanded (?$expand=settingDefinitions) or without them and -Definitions
    # holding them (the shared definition cache)
    param($SettingItems, [hashtable]$CategoryMap = @{}, [hashtable]$Definitions)
    $defs = $(if ($Definitions) { $Definitions } else { @{} })
    foreach ($item in @($SettingItems)) {
        foreach ($d in (Get-PropList $item 'settingDefinitions')) {
            $did = [string](Get-Prop $d 'id')
            if ($did -and -not $defs.ContainsKey($did)) { $defs[$did] = $d }
        }
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($item in @($SettingItems)) {
        $inst = Get-Prop $item 'settingInstance'
        $before = $rows.Count
        Expand-CatalogInstance -Instance $inst -Defs $defs -Prefix '' -Rows $rows
        # stamp the root setting's category (matches how the portal groups settings)
        $cat = ''
        $rootDefId = [string](Get-Prop $inst 'settingDefinitionId')
        if ($rootDefId -and $defs.ContainsKey($rootDefId)) {
            $catId = [string](Get-Prop $defs[$rootDefId] 'categoryId')
            if ($catId -and $CategoryMap.ContainsKey($catId)) { $cat = $CategoryMap[$catId] }
        }
        for ($ri = $before; $ri -lt $rows.Count; $ri++) {
            $rows[$ri] | Add-Member -NotePropertyName Category -NotePropertyValue $cat -Force
        }
    }
    return $rows.ToArray()
}

#endregion

#region ---------- legacy / admx / intent flattening ----------------------------------------

function Read-OmaPlainTexts {
    # Decrypts many encrypted OMA-URI values at once (getOmaSettingPlainTextValue through
    # /$batch) into the cache Get-OmaPlainText reads. $Refs: @(configId, secretReferenceValueId) pairs.
    param([object[]]$Refs)
    if (-not $script:OmaPlainCache) { $script:OmaPlainCache = @{} }
    $urlOf = @{}
    foreach ($r in @($Refs)) {
        if (-not $r -or @($r).Count -lt 2 -or -not $r[0] -or -not $r[1]) { continue }
        $ck = "{0}|{1}" -f $r[0], $r[1]
        if (-not $script:OmaPlainCache.ContainsKey($ck)) { $urlOf[$ck] = "/deviceManagement/deviceConfigurations/{0}/getOmaSettingPlainTextValue(secretReferenceValueId='{1}')" -f $r[0], $r[1] }
    }
    if (-not $urlOf.Count) { return }
    $got = Invoke-RsopBatch -Urls @($urlOf.Values) -Activity 'Encrypted custom OMA-URI values'
    foreach ($ck in $urlOf.Keys) {
        $b = $got[$urlOf[$ck]]
        $script:OmaPlainCache[$ck] = $(if ($b -is [System.Collections.IDictionary] -and $b.Contains('value')) { [string]$b['value'] } else { $null })
    }
}

function Get-OmaPlainText {
    # Resolves an encrypted custom OMA-URI value to plaintext via the deviceConfiguration
    # getOmaSettingPlainTextValue function. Returns $null on any failure (permissions, missing
    # id, transient error) so the caller can fall back to a placeholder. NOTE: this writes the
    # decrypted secret into the report/CSV - the export must then be treated as sensitive.
    param([string]$ConfigId, [string]$SecretRefId)
    if (-not $ConfigId -or -not $SecretRefId) { return $null }
    if (-not $script:OmaPlainCache) { $script:OmaPlainCache = @{} }
    $ck = "$ConfigId|$SecretRefId"
    if ($script:OmaPlainCache.ContainsKey($ck)) { return $script:OmaPlainCache[$ck] }
    $result = $null
    try {
        $uri = "beta/deviceManagement/deviceConfigurations/{0}/getOmaSettingPlainTextValue(secretReferenceValueId='{1}')" -f $ConfigId, $SecretRefId
        $resp = Invoke-Rsop -Uri $uri
        if ($resp -and $resp.ContainsKey('value')) { $result = [string]$resp['value'] }
    }
    catch { $result = $null }
    $script:OmaPlainCache[$ck] = $result
    return $result
}

function Convert-LegacyProperties {
    # Flattens a deviceConfiguration / deviceCompliancePolicy object's non-null typed properties.
    # Rows get a Category derived from the item's @odata.type so legacy settings group and
    # match like everything else; $FallbackCategory covers collections whose items carry no
    # @odata.type (e.g. windows update profiles).
    param($Policy, [string]$FallbackCategory = '', [string[]]$Skip = @(), [string]$Category = '')
    $metaProps = @(
        'id', 'displayname', 'description', 'createddatetime', 'lastmodifieddatetime', 'version',
        'supportsscopetags', 'rolescopetagids', 'assignments',
        'devicemanagementapplicabilityruleosedition', 'devicemanagementapplicabilityruleosversion',
        'devicemanagementapplicabilityruledevicemode', 'scheduledactionsforrule',
        'devicestatuses', 'userstatuses', 'devicestatusoverview', 'userstatusoverview',
        'devicesettingstatesummaries', 'devicestatussummary', 'userstatussummary',
        'scriptcontent', 'filename', 'isassigned', 'deployedappcount', 'deploymentsummary', 'apps',
        'runsummary', 'devicerunstates', 'userrunstates', 'groupassignments'
    ) + @($Skip | ForEach-Object { ([string]$_).ToLower() })
    $rows = [System.Collections.Generic.List[object]]::new()
    $cfgId = [string](Get-Prop $Policy 'id')   # needed to decrypt encrypted OMA-URI values
    $odataShort = ([string](Get-Prop $Policy '@odata.type')) -replace '#microsoft.graph.', ''
    $rowCategory = $FallbackCategory
    if ($odataShort) {
        $trimmed = $odataShort -replace '(Configuration|Policy|Profile)$', ''
        if ($trimmed) { $rowCategory = ConvertTo-FriendlyName $trimmed }
    }
    if ($Category) { $rowCategory = $Category }

    foreach ($key in @($Policy.Keys)) {
        $k = [string]$key
        if ($k.StartsWith('@') -or $k.Contains('@odata')) { continue }
        if ($metaProps -contains $k.ToLower()) { continue }
        $v = $Policy[$key]
        if ($null -eq $v) { continue }
        if ($v -is [string] -and $v -eq '') { continue }
        if (($v -is [System.Collections.IEnumerable]) -and ($v -isnot [string]) -and (@($v).Count -eq 0)) { continue }

        if ($k -ieq 'omaSettings') {
            foreach ($oma in @($v)) {
                $omaName = [string](Get-Prop $oma 'displayName')
                $omaUri = [string](Get-Prop $oma 'omaUri')
                $omaVal = Get-Prop $oma 'value'
                $omaType = [string](Get-Prop $oma '@odata.type')
                if ($omaType -like '*StringXml*' -or ($omaVal -is [string] -and $omaVal.Length -gt 400)) {
                    $omaVal = (Format-SettingValue $omaVal)
                }
                $enc = Get-Prop $oma 'isEncrypted'
                if ($enc) {
                    # encrypted OMA values come back null; fetch the plaintext via the
                    # getOmaSettingPlainTextValue function (writes the secret into the report)
                    $secretRef = [string](Get-Prop $oma 'secretReferenceValueId')
                    $plain = Get-OmaPlainText -ConfigId $cfgId -SecretRefId $secretRef
                    if ($null -ne $plain -and $plain -ne '') {
                        $omaVal = $plain
                        $script:ContainsDecryptedSecrets = $true
                        $label = "{0}: {1} ({2})" -f (Get-Prop $Policy 'displayName'), $omaName, $omaUri
                        if (-not $script:DecryptedOmaSettings.Contains($label)) { [void]$script:DecryptedOmaSettings.Add($label) }
                        [void]$script:OmaSecretRows.Add([pscustomobject]@{ PolicyId = $cfgId; Key = "oma:$omaUri"; Setting = "Custom OMA-URI: $omaName ($omaUri)"; SecretRef = $secretRef; Label = $label })
                    }
                    else { $omaVal = '(encrypted value - could not decrypt; view in portal)' }
                }
                [void]$rows.Add([pscustomobject]@{
                    Key      = "oma:$omaUri"
                    Setting  = "Custom OMA-URI: $omaName ($omaUri)"
                    Value    = (Format-SettingValue $omaVal)
                    Category = 'Custom OMA-URI'
                })
            }
            continue
        }

        if ($script:SecretProps -contains $k) {
            # tokens / passwords / QR codes never reach a report
            [void]$rows.Add([pscustomobject]@{ Key = "legacy:$odataShort/$k"; Setting = (ConvertTo-FriendlyName $k); Value = '(secret - not shown)'; Category = $rowCategory })
            continue
        }
        if ($k -in @('payload', 'configurationXml', 'customXml', 'eapXml') -and $v -is [string] -and $v.Length -gt 0) {
            # custom configuration (.mobileconfig) / imported Wi-Fi XML payloads can embed
            # credentials: describe them here, the full payload is in the backup
            $fn = [string](Get-Prop $Policy 'payloadFileName')
            if (-not $fn) { $fn = [string](Get-Prop $Policy 'fileName') }
            $size = [System.Text.Encoding]::UTF8.GetByteCount($v)
            try { $size = [Convert]::FromBase64String($v).Length } catch { }
            [void]$rows.Add([pscustomobject]@{ Key = "legacy:$odataShort/$k"; Setting = (ConvertTo-FriendlyName $k); Value = ("(file{0}, {1:N0} bytes - in the backup)" -f $(if ($fn) { " $fn" } else { '' }), $size); Category = $rowCategory })
            continue
        }
        if ($v -is [System.Collections.IDictionary] -and $v.Contains('value') -and ([string](Get-Prop $v 'type')) -match '^image/') {
            # mimeContent (Company Portal logos and the like): describe, don't dump base64
            $sz = [math]::Floor(([string]$v['value']).Length * 3 / 4)
            [void]$rows.Add([pscustomobject]@{ Key = "legacy:$odataShort/$k"; Setting = (ConvertTo-FriendlyName $k); Value = ("(image, {0}, {1:N0} KB - in the backup)" -f (Get-Prop $v 'type'), ($sz / 1KB)); Category = $rowCategory })
            continue
        }
        $fv = Format-SettingValue $v
        if ($v -is [string]) { $fv = Format-IsoDuration $fv }
        [void]$rows.Add([pscustomobject]@{
            Key      = "legacy:$odataShort/$k"
            Setting  = (ConvertTo-FriendlyName $k)
            Value    = $fv
            Category = $rowCategory
        })
    }
    return $rows.ToArray()
}

function Get-AppIdentifierText {
    # managedMobileApp.mobileAppIdentifier -> bundle id / package id / Windows app id.
    param($ManagedApp)
    $ident = Get-Prop $ManagedApp 'mobileAppIdentifier'
    if ($null -eq $ident) { return '' }
    foreach ($k in @('bundleId', 'packageId', 'windowsAppId')) {
        $v = [string](Get-Prop $ident $k)
        if ($v) { return $v }
    }
    if ($ident -is [System.Collections.IDictionary]) {
        foreach ($k in $ident.Keys) { if (-not ([string]$k).StartsWith('@') -and $ident[$k] -is [string]) { return [string]$ident[$k] } }
    }
    return ''
}

function Get-AppIdentifierPlatform {
    param($ManagedApp)
    $t = [string](Get-Prop (Get-Prop $ManagedApp 'mobileAppIdentifier') '@odata.type')
    if ($t -match 'ios') { return 'ios' }
    if ($t -match 'android') { return 'android' }
    if ($t -match 'windows') { return 'windows' }
    return 'other'
}

function Test-RsopSecretName {
    # Name-based secret check for free-form keys (app configuration keys, plist keys, Android
    # managed properties, MAM custom settings). Typed Graph properties use $script:SecretProps.
    param([string]$Name)
    if (-not $Name) { return $false }
    if ($script:SecretProps -contains $Name) { return $true }
    if ($Name -match '(?i)(pass(word|phrase|code)|passwd|secret|token|credential|connection.?string|pre.?shared|psk|(^|[^a-z])(pwd|pin)([^a-z]|$)|(api|private|licen[cs]e|product|access|shared|wpa|wep|network|encryption|signing|auth|account|master|enrollment|subscription|client|nessus).?key)') { return $true }
    # camelCase / upper-case parts: wifiPsk, WPAPSK, userPwd, devicePin, PIN
    return ($Name -cmatch '(Psk|PSK|Pwd|PWD|Pin|PIN)([^a-z]|$)')
}

function Protect-RsopSecretValue {
    # Secret values can also be numeric PINs, arrays or bundles. Boolean policy flags stay visible.
    param([string]$Name, $Value)
    if ($null -ne $Value -and $Value -isnot [bool] -and "$Value" -ne '' -and (Test-RsopSecretName $Name)) { return '(secret - not shown)' }
    return (Format-SettingValue $Value -FreeFormKeys)
}

function Protect-RsopCommandLine {
    param([string]$Text)
    # Preserve argument names and ordinary options; replace only secret-bearing values.
    $pattern = @'
(?x)
(?<quote>")(?<prefix>(?:--?|/)?(?<name>[A-Za-z_][\w.-]*)\s*[=:]\s*)(?<value>(?:\\.|`.|""|[^"\\])*)"
|(?<quote>')(?<prefix>(?:--?|/)?(?<name>[A-Za-z_][\w.-]*)\s*[=:]\s*)(?<value>(?:''|[^'])*)'
|(?<prefix>(?<![\w.-])(?:--?|/)?(?:"(?<name>[A-Za-z_][\w.-]*)"|'(?<name>[A-Za-z_][\w.-]*)'|(?<name>[A-Za-z_][\w.-]*))\s*[=:]\s*)
 (?<value>(?:"(?:\\.|`.|""|[^"\\])*(?:"|$)|'(?:''|[^'])*(?:'|$)|[^\s"']+)+)
'@
    $Text = [regex]::Replace($Text, $pattern, {
        param($m)
        if (Test-RsopSecretName $m.Groups['name'].Value) {
            $quote = $m.Groups['quote'].Value
            if ($quote) { return $quote + $m.Groups['prefix'].Value + '(secret - not shown)' + $quote }
            return $m.Groups['prefix'].Value + '"(secret - not shown)"'
        }
        return $m.Value
    })
    $spacedPattern = @'
(?x)
(?<prefix>(?<!\S)(?:--?|/)(?:"(?<name>[A-Za-z_][\w.-]*)"|'(?<name>[A-Za-z_][\w.-]*)'|(?<name>[A-Za-z_][\w.-]*))\s+)
(?<value>(?:"(?:\\.|`.|""|[^"\\])*(?:"|$)|'(?:''|[^'])*(?:'|$)|[^\s"']+)+)
'@
    return [regex]::Replace($Text, $spacedPattern, {
        param($m)
        if (Test-RsopSecretName $m.Groups['name'].Value) { return $m.Groups['prefix'].Value + '"(secret - not shown)"' }
        return $m.Value
    })
}

function Protect-RsopPlistText {
    param([string]$Text)
    try {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Ignore
        $settings.XmlResolver = $null
        $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($Text), $settings)
        $doc = [System.Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        $doc.PreserveWhitespace = $true
        try { $doc.Load($reader) } finally { $reader.Dispose() }
        foreach ($key in @($doc.SelectNodes('//*[local-name()="key"]'))) {
            if (-not (Test-RsopSecretName $key.InnerText)) { continue }
            $value = $key.NextSibling
            while ($value -and $value.NodeType -ne [System.Xml.XmlNodeType]::Element) { $value = $value.NextSibling }
            if ($value -and $value.LocalName -ne 'key') {
                $marker = $doc.CreateElement('string')
                $marker.InnerText = '(secret - not shown)'
                [void]$value.ParentNode.ReplaceChild($marker, $value)
            }
        }
        return $doc.OuterXml
    } catch { return '(configuration XML could not be parsed - in the backup)' }
}

function Convert-AppConfigDeviceSettings {
    # managedDeviceMobileAppConfiguration (iOS keys / plist XML, Android managed properties
    # + runtime permissions) -> setting rows. The key carries the targeted app ids so that two
    # app-config policies setting the same key for the same app surface as a conflict.
    param($Policy)
    $rows = [System.Collections.Generic.List[object]]::new()
    $appKey = ((@(Get-PropList $Policy 'targetedMobileApps') | Sort-Object) -join ',')

    foreach ($it in (Get-PropList $Policy 'settings')) {
        $k = [string](Get-Prop $it 'appConfigKey')
        if (-not $k) { continue }
        $kt = ([string](Get-Prop $it 'appConfigKeyType')) -replace 'Type$', ''
        [void]$rows.Add([pscustomobject]@{
            Key = "appcfg:${appKey}:$k"; Setting = $k; Value = (Protect-RsopSecretValue $k (Get-Prop $it 'appConfigKeyValue'))
            Category = $(if ($kt) { "Configuration key ($kt)" } else { 'Configuration key' })
        })
    }
    $xml = [string](Get-Prop $Policy 'encodedSettingXml')
    if ($xml) {
        $dec = ConvertFrom-Base64Text $xml
        if (-not $dec) { $dec = $xml }
        $dec = Protect-RsopPlistText $dec
        if ($dec.Length -gt 6000) { $dec = $dec.Substring(0, 6000) + "`n...(truncated)" }
        [void]$rows.Add([pscustomobject]@{ Key = "appcfg:${appKey}:xml"; Setting = 'Configuration XML (plist)'; Value = $dec; Category = 'Configuration XML' })
    }
    $payload = [string](Get-Prop $Policy 'payloadJson')
    if ($payload) {
        $json = $null
        foreach ($cand in @((ConvertFrom-Base64Text $payload), $payload)) {
            if (-not $cand) { continue }
            try { $json = $cand | ConvertFrom-Json -AsHashtable -ErrorAction Stop; break } catch { }
        }
        $props = @()
        if ($json) { $props = @(Get-PropList $json 'managedProperty') }
        if ($props.Count -gt 0) {
            foreach ($mp in $props) {
                $k = [string](Get-Prop $mp 'key')
                $val = $null
                foreach ($vk in @('valueString', 'valueInteger', 'valueBool', 'valueStringArray', 'valueBundle', 'valueBundleArray')) {
                    $cv = Get-Prop $mp $vk
                    if ($null -ne $cv) { $val = $cv; break }
                }
                [void]$rows.Add([pscustomobject]@{ Key = "appcfg:${appKey}:$k"; Setting = $k; Value = (Protect-RsopSecretValue $k $val); Category = 'Managed configuration' })
            }
        }
        else {
            $raw = $(if ($json) { Format-SettingValue $json -FreeFormKeys } else { '(configuration payload could not be parsed - in the backup)' })
            [void]$rows.Add([pscustomobject]@{ Key = "appcfg:${appKey}:payload"; Setting = 'Configuration payload (JSON)'; Value = $raw; Category = 'Managed configuration' })
        }
    }
    foreach ($pa in (Get-PropList $Policy 'permissionActions')) {
        $perm = [string](Get-Prop $pa 'permission')
        if (-not $perm) { continue }
        [void]$rows.Add([pscustomobject]@{ Key = "appcfg:${appKey}:perm:$perm"; Setting = "Permission: $perm"; Value = [string](Get-Prop $pa 'action'); Category = 'Runtime permissions' })
    }
    foreach ($r in (Convert-LegacyProperties -Policy $Policy -Category 'Policy options' -Skip @('targetedMobileApps', 'settings', 'encodedSettingXml', 'payloadJson', 'permissionActions'))) {
        [void]$rows.Add($r)
    }
    return $rows.ToArray()
}

function Set-AppSettingConflictKeys {
    # Keep one displayed row per setting, but compare each explicitly targeted app.
    # Whole app-set keys miss overlaps such as {A,B} and {B,C}.
    param($Rows, [string[]]$Scopes, [string]$Prefix, [string]$PolicyId, [string]$CombinedScope)
    $scopes0 = @($Scopes | Where-Object { $_ } | Sort-Object -Unique)
    if (-not $scopes0.Count) { $scopes0 = @("policy:$PolicyId") }
    $oldPrefix = "${Prefix}:${CombinedScope}:"
    foreach ($r in $Rows) {
        $key = [string]$r.Key
        if ($key.StartsWith($oldPrefix, [StringComparison]::OrdinalIgnoreCase)) { $key = $key.Substring($oldPrefix.Length) }
        elseif ($key.StartsWith("${Prefix}:", [StringComparison]::OrdinalIgnoreCase)) { $key = $key.Substring($Prefix.Length + 1) }
        # Target selection and management-level metadata are policy options, not
        # conflicting app settings. Their rows remain inspectable by policy.
        $keys = if ($r.Category -eq 'Policy options') { @("${Prefix}:policy:${PolicyId}:$key") } else { @($scopes0 | ForEach-Object { "${Prefix}:${_}:$key" }) }
        $r | Add-Member -NotePropertyName ConflictKeys -NotePropertyValue $keys -Force
    }
}

$script:ComplianceActionNames = @{
    block = 'Mark device noncompliant'; notification = 'Send email to end user'; pushNotification = 'Send push notification to end user'
    remoteLock = 'Remotely lock the noncompliant device'; retire = 'Add device to retire list'; wipe = 'Wipe device'
    removeResourceAccessProfiles = 'Remove resource access profiles'; noAction = 'No action'
}

function Get-ComplianceCcGroupIds {
    # Groups that compliance e-mail actions copy in (notificationMessageCCList).
    param($Rules)
    return @(foreach ($rule in @($Rules)) { foreach ($act in (Get-PropList $rule 'scheduledActionConfigurations')) { Get-PropList $act 'notificationMessageCCList' } }) |
        ForEach-Object { [string]$_ } | Where-Object { $_ } | Select-Object -Unique
}

function Convert-ComplianceActions {
    # scheduledActionsForRule[].scheduledActionConfigurations[] -> "Actions for noncompliance" rows.
    param($Rules, [string]$PolicyId)
    $rows = [System.Collections.Generic.List[object]]::new()
    $n = 0
    foreach ($rule in @($Rules)) {
        foreach ($act in (Get-PropList $rule 'scheduledActionConfigurations')) {
            $n++
            $type = [string](Get-Prop $act 'actionType')
            $label = $script:ComplianceActionNames[$type]
            if (-not $label) { $label = ConvertTo-FriendlyName $type }
            $h = 0; [void][int]::TryParse([string](Get-Prop $act 'gracePeriodHours'), [ref]$h)
            $when = 'immediately'
            if ($h -gt 0) {
                if ($h % 24 -eq 0) { $when = ("after {0} day{1}" -f ($h / 24), $(if ($h / 24 -eq 1) { '' } else { 's' })) }
                else { $when = ("after {0} hour{1}" -f $h, $(if ($h -eq 1) { '' } else { 's' })) }
            }
            # e-mail actions reference a notification template and extra recipient groups by
            # id - both have to be recreated (and re-pointed) after a rebuild
            $tid = [string](Get-Prop $act 'notificationTemplateId')
            if ($tid -and $tid -ne '00000000-0000-0000-0000-000000000000') {
                $tn = $(if ($script:NotificationTemplateNames -and $script:NotificationTemplateNames[$tid]) { $script:NotificationTemplateNames[$tid] } else { $tid })
                $when += (" · template '{0}'" -f $tn)
            }
            $cc = @(Get-PropList $act 'notificationMessageCCList' | ForEach-Object { [string]$_ } | Where-Object { $_ })
            if ($cc.Count) {
                Resolve-GroupNames -Ids $cc
                $when += (" · also e-mails: {0}" -f ((@($cc | ForEach-Object { Get-GroupName $_ })) -join ', '))
            }
            [void]$rows.Add([pscustomobject]@{
                Key = ("compliance:{0}:action:{1}" -f $PolicyId, $n); Setting = "Action for noncompliance: $label"; Value = $when; Category = 'Actions for noncompliance'
            })
        }
    }
    return $rows.ToArray()
}

function Format-Win32Rule {
    # One win32LobApp detection / requirement rule -> a readable line.
    param($Rule)
    $t = ([string](Get-Prop $Rule '@odata.type')) -replace '#microsoft.graph.win32LobApp', ''
    $op = [string](Get-Prop $Rule 'operationType'); $cmpOp = [string](Get-Prop $Rule 'operator'); $cv = [string](Get-Prop $Rule 'comparisonValue')
    $cmp = ''
    if ($cmpOp -and $cmpOp -ne 'notConfigured') { $cmp = (" {0} {1}" -f $cmpOp, $cv) }
    switch -Wildcard ($t) {
        'FileSystemRule' {
            $p = ('{0}\{1}' -f (Get-Prop $Rule 'path'), (Get-Prop $Rule 'fileOrFolderName')) -replace '\\\\', '\'
            return (Protect-RsopCommandLine ("File: {0} - {1}{2}" -f $p, $op, $cmp))
        }
        'RegistryRule' {
            $vn = [string](Get-Prop $Rule 'valueName')
            if ($cv -and (Test-RsopSecretName $vn)) { $cmp = " $cmpOp (secret - not shown)" }
            return (Protect-RsopCommandLine ("Registry: {0}{1} - {2}{3}" -f (Get-Prop $Rule 'keyPath'), $(if ($vn) { " [$vn]" } else { '' }), $op, $cmp))
        }
        'ProductCodeRule' {
            $pv = [string](Get-Prop $Rule 'productVersion'); $pvo = [string](Get-Prop $Rule 'productVersionOperator')
            return ("MSI product code {0}{1}" -f (Get-Prop $Rule 'productCode'), $(if ($pvo -and $pvo -ne 'notConfigured') { " - version $pvo $pv" } else { '' }))
        }
        'PowerShellScriptRule' {
            $body = ConvertFrom-Base64Text ([string](Get-Prop $Rule 'scriptContent'))
            if ($body -and $body.Length -gt 1500) { $body = $body.Substring(0, 1500) + "`n...(truncated)" }
            $nm = [string](Get-Prop $Rule 'displayName')
            return ("PowerShell script{0} (runs as {1}){2}`n{3}" -f $(if ($nm) { " '$nm'" } else { '' }), (Get-Prop $Rule 'runAsAccount'), $cmp, $body)
        }
        default { return (Format-SettingValue (Remove-JsonNoise -Value $Rule)) }
    }
}

function Get-AppInfoRows {
    # Install / detection / packaging facts worth seeing next to an app's assignments.
    # Returns @(@{ Label; Value }) - only populated fields.
    param($App)
    $rows = [System.Collections.Generic.List[object]]::new()
    $add = { param($l, $v) if ($null -ne $v -and "$v" -ne '') { [void]$rows.Add([pscustomobject]@{ Label = $l; Value = [string]$v }) } }

    & $add 'Publisher' (Get-Prop $App 'publisher')
    & $add 'Version' (Get-Prop $App 'displayVersion')
    foreach ($p in @(
            @('packageIdentifier', 'Package identifier'), @('mobileAppCatalogPackageId', 'Catalog package id'), @('bundleId', 'Bundle id'),
            @('packageId', 'Package id'), @('identityName', 'Package identity'), @('appStoreUrl', 'Store URL'), @('appUrl', 'App URL'),
            @('setupFilePath', 'Setup file'), @('installCommandLine', 'Install command'), @('uninstallCommandLine', 'Uninstall command'),
            @('commandLine', 'MSI command line'), @('productCode', 'MSI product code'), @('minimumSupportedWindowsRelease', 'Minimum Windows release'))) {
        $infoValue = Get-Prop $App $p[0]
        if ($p[0] -in @('installCommandLine', 'uninstallCommandLine', 'commandLine', 'setupFilePath')) { $infoValue = Protect-RsopCommandLine ([string]$infoValue) }
        & $add $p[1] $infoValue
    }
    $ie = Get-Prop $App 'installExperience'
    if ($ie) {
        & $add 'Install context' (Get-Prop $ie 'runAsAccount')
        & $add 'Restart behaviour' (Get-Prop $ie 'deviceRestartBehavior')
        $mr = Get-Prop $ie 'maxRunTimeInMinutes'; if ($mr) { & $add 'Max install time' ("{0} minutes" -f $mr) }
    }
    $arch = [string](Get-Prop $App 'allowedArchitectures')
    if (-not $arch -or $arch -eq 'none') { $arch = [string](Get-Prop $App 'applicableArchitectures') }
    if ($arch -and $arch -ne 'none') { & $add 'Architectures' $arch }
    $aau = Get-Prop $App 'allowAvailableUninstall'; if ($aau -eq $true) { & $add 'Allow uninstall from Company Portal' 'Yes' }
    $msi = Get-Prop $App 'msiInformation'
    if ($msi -and (Get-Prop $msi 'productCode')) { & $add 'MSI product code' ("{0} (v{1})" -f (Get-Prop $msi 'productCode'), (Get-Prop $msi 'productVersion')) }

    $rules = @(Get-PropList $App 'rules')
    if ($rules.Count -gt 0) {
        $det = @($rules | Where-Object { [string](Get-Prop $_ 'ruleType') -ne 'requirement' } | ForEach-Object { Format-Win32Rule $_ })
        $req = @($rules | Where-Object { [string](Get-Prop $_ 'ruleType') -eq 'requirement' } | ForEach-Object { Format-Win32Rule $_ })
    }
    else {
        # legacy collections on older Win32 apps
        $det = @(Get-PropList $App 'detectionRules' | ForEach-Object { Format-Win32Rule $_ })
        $req = @(Get-PropList $App 'requirementRules' | ForEach-Object { Format-Win32Rule $_ })
    }
    if ($det.Count) { & $add 'Detection rules' ($det -join "`n") }
    if ($req.Count) { & $add 'Requirement rules' ($req -join "`n") }
    $rc = @(Get-PropList $App 'returnCodes' | ForEach-Object { "{0} = {1}" -f (Get-Prop $_ 'returnCode'), (Get-Prop $_ 'type') })
    if ($rc.Count) { & $add 'Return codes' ($rc -join ', ') }

    # Microsoft 365 Apps: apps deselected from the suite are actively REMOVED from devices
    $excluded = Get-Prop $App 'excludedApps'
    if ($excluded) {
        $exNames = @()
        if ($excluded -is [System.Collections.IDictionary]) { foreach ($k in $excluded.Keys) { if ($excluded[$k] -eq $true) { $exNames += [string]$k } } }
        else { foreach ($pp in $excluded.PSObject.Properties) { if ($pp.Value -eq $true) { $exNames += $pp.Name } } }
        if ($exNames.Count -gt 0) { & $add 'Excluded Microsoft 365 apps (uninstalled if present)' (($exNames | Sort-Object) -join ', ') }
    }
    $pids = @(Get-PropList $App 'productIds'); if ($pids.Count) { & $add 'Products' ($pids -join ', ') }
    & $add 'Update channel' (Get-Prop $App 'updateChannel')
    $opa = [string](Get-Prop $App 'officePlatformArchitecture'); if ($opa -and $opa -ne 'none') { & $add 'Office architecture' $opa }
    if ((Get-Prop $App 'useSharedComputerActivation') -eq $true) { & $add 'Shared computer activation' 'Yes' }
    if ((Get-Prop $App 'shouldUninstallOlderVersionsOfOffice') -eq $true) { & $add 'Remove older Office versions (MSI)' 'Yes' }
    & $add 'Target Office version' (Get-Prop $App 'targetVersion')
    $ocx = ConvertFrom-Base64Text ([string](Get-Prop $App 'officeConfigurationXml'))
    if ($ocx) {
        # volume licence keys (PIDKEY) stay out of the report; the backup keeps the full XML
        $ocx = $ocx -replace '(?i)(\bPIDKEY\s*=\s*)(["''])[^"'']*\2', '$1$2(secret - not shown)$2'
        & $add 'Office configuration XML' (Format-SettingValue $ocx)
    }
    # PowerShell install / uninstall scripts (used instead of a command line)
    foreach ($pair in @(@('activeInstallScript', 'Install script (PowerShell)'), @('activeUninstallScript', 'Uninstall script (PowerShell)'))) {
        if (-not (Get-Prop (Get-Prop $App $pair[0]) 'targetId')) { continue }
        $sb = Get-Prop $App ('_' + $pair[0] + 'Body')
        $txt = $(if ($sb) { ConvertFrom-Base64Text ([string](Get-Prop $sb 'content')) } else { $null })
        if ($txt) {
            if ($txt.Length -gt 6000) { $txt = $txt.Substring(0, 6000) + "`n...(truncated)" }
            & $add $pair[1] ("{0}`n{1}" -f $(if (Get-Prop $sb 'displayName') { "[$(Get-Prop $sb 'displayName')]" } else { '' }), $txt).Trim()
        }
        else { & $add $pair[1] '(script content not readable)' }
    }
    $cats = @(Get-PropList $App 'categories' | ForEach-Object { [string](Get-Prop $_ 'displayName') } | Where-Object { $_ })
    if ($cats.Count) { & $add 'Company Portal categories' ($cats -join ', ') }

    # recovery facts: which package file to keep, who owns the app, where it surfaces
    $fn = [string](Get-Prop $App 'fileName')
    if ($fn) {
        $sz = 0.0; [void][double]::TryParse([string](Get-Prop $App 'size'), [ref]$sz)
        & $add 'Package file (keep a copy - Graph cannot download it)' $(if ($sz -gt 0) { "{0} ({1:N1} MB)" -f $fn, ($sz / 1MB) } else { $fn })
    }
    $minOs = Get-Prop $App 'minimumSupportedOperatingSystem'
    if ($minOs) {
        $on = @()
        if ($minOs -is [System.Collections.IDictionary]) { foreach ($k in $minOs.Keys) { if ($minOs[$k] -eq $true) { $on += [string]$k } } }
        else { foreach ($pp in $minOs.PSObject.Properties) { if ($pp.Value -eq $true) { $on += $pp.Name } } }
        if ($on.Count) { & $add 'Minimum operating system' ((@($on | ForEach-Object { ($_ -replace '^v', '') -replace '_', '.' }) | Sort-Object) -join ', ') }
    }
    foreach ($p in @(
            @('minimumFreeDiskSpaceInMB', 'Minimum free disk (MB)'), @('minimumMemoryInMB', 'Minimum memory (MB)'),
            @('minimumNumberOfProcessors', 'Minimum processors'), @('minimumCpuSpeedInMHz', 'Minimum CPU speed (MHz)'),
            @('owner', 'Owner'), @('developer', 'Developer'), @('notes', 'Notes'),
            @('informationUrl', 'Information URL'), @('privacyInformationUrl', 'Privacy URL'),
            @('vppTokenAppleId', 'VPP token Apple ID'), @('vppTokenOrganizationName', 'VPP organization'), @('licensingType', 'Licensing'))) {
        $v = Get-Prop $App $p[0]
        if ($null -ne $v -and $v -isnot [System.Collections.IDictionary] -and "$v" -ne '' -and "$v" -ne '0') { & $add $p[1] (Format-SettingValue $v) }
    }
    $used = Get-Prop $App 'usedLicenseCount'; $total = Get-Prop $App 'totalLicenseCount'
    if ($null -ne $total -and "$total" -ne '') { & $add 'Licenses used' ("{0} of {1}" -f $used, $total) }
    if ((Get-Prop $App 'isFeatured') -eq $true) { & $add 'Featured in Company Portal' 'Yes' }
    $ps = [string](Get-Prop $App 'publishingState')
    if ($ps -and $ps -ne 'published') { & $add 'Publishing state' (ConvertTo-FriendlyName $ps) }
    return $rows.ToArray()
}

function Format-AssignmentOptions {
    # Per-assignment delivery options (app notifications / deadline / restart grace,
    # remediation run schedule, policy-set origin) -> one readable line.
    param($Assignment)
    $parts = @()
    $s = Get-Prop $Assignment 'settings'
    if ($s) {
        $n = [string](Get-Prop $s 'notifications')
        if ($n) {
            $nl = @{ showAll = 'show all'; showReboot = 'restart only'; hideAll = 'hide all' }[$n]
            if (-not $nl) { $nl = $n }
            $parts += "notifications: $nl"
        }
        $its = Get-Prop $s 'installTimeSettings'
        if ($its) {
            $tz = $(if ((Get-Prop $its 'useLocalTime') -eq $true) { 'device time' } else { 'UTC' })
            $st = Format-GraphDate (Get-Prop $its 'startDateTime'); $dl = Format-GraphDate (Get-Prop $its 'deadlineDateTime')
            # 'yyyy-MM-ddTHH:mm:ss...(Z|+hh:mm)' -> 'yyyy-MM-dd HH:mm'
            $short = { param($v) ([string]$v) -replace '^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}).*$', '$1 $2' }
            if ($st) { $parts += ("available from {0} ({1})" -f (& $short $st), $tz) }
            if ($dl) { $parts += ("deadline {0} ({1})" -f (& $short $dl), $tz) }
        }
        $rs = Get-Prop $s 'restartSettings'
        if ($rs -and (Get-Prop $rs 'gracePeriodInMinutes')) {
            $parts += ("restart grace {0} min" -f (Get-Prop $rs 'gracePeriodInMinutes'))
            if (Get-Prop $rs 'countdownDisplayBeforeRestartInMinutes') { $parts += ("restart countdown {0} min" -f (Get-Prop $rs 'countdownDisplayBeforeRestartInMinutes')) }
            if (Get-Prop $rs 'restartNotificationSnoozeDurationInMinutes') { $parts += ("snooze {0} min" -f (Get-Prop $rs 'restartNotificationSnoozeDurationInMinutes')) }
        }
        if ([string](Get-Prop $s 'deliveryOptimizationPriority') -eq 'foreground') { $parts += 'delivery optimization: foreground' }
        $au = Get-Prop $s 'autoUpdateSettings'
        if ($au) {
            $aus = [string](Get-Prop $au 'autoUpdateSupersededAppsState'); if (-not $aus) { $aus = [string](Get-Prop $au 'autoUpdateSupersededApps') }
            if ($aus -eq 'enabled') { $parts += 'auto-update superseded versions' }
        }
        if ((Get-Prop $s 'useDeviceContext') -eq $true) { $parts += 'device context' }
        if ((Get-Prop $s 'useDeviceLicensing') -eq $true) { $parts += 'device licensing' }
        if ((Get-Prop $s 'uninstallOnDeviceRemoval') -eq $false) { $parts += 'kept on device removal' }
        if ((Get-Prop $s 'isRemovable') -eq $false) { $parts += 'user cannot remove' }
        if ((Get-Prop $s 'preventAutoAppUpdate') -eq $true) { $parts += 'auto-update blocked' }
        if ((Get-Prop $s 'preventManagedAppBackup') -eq $true) { $parts += 'app backup blocked' }
        $vpn = [string](Get-Prop $s 'vpnConfigurationId')
        if ($vpn) { $parts += ("per-app VPN '{0}'" -f $(if ($script:PolicyNameById -and $script:PolicyNameById[$vpn]) { $script:PolicyNameById[$vpn] } else { $vpn })) }
        $aum = [string](Get-Prop $s 'autoUpdateMode'); if ($aum -and $aum -ne 'default') { $parts += "update mode: $aum" }
        $tracks = @(Get-PropList $s 'androidManagedStoreAppTrackIds' | Where-Object { $_ })
        if ($tracks.Count) { $parts += ("Google Play track(s): {0}" -f ($tracks -join ', ')) }
        # anything else the settings object carries (Apple declarative app settings, newer
        # options ...) - shown generically so no delivery option is silently dropped
        $known = @('@odata.type', 'notifications', 'installTimeSettings', 'restartSettings', 'deliveryOptimizationPriority', 'autoUpdateSettings',
            'useDeviceContext', 'useDeviceLicensing', 'uninstallOnDeviceRemoval', 'isRemovable', 'preventAutoAppUpdate', 'preventManagedAppBackup',
            'vpnConfigurationId', 'autoUpdateMode', 'androidManagedStoreAppTrackIds')
        $keys = $(if ($s -is [System.Collections.IDictionary]) { @($s.Keys) } else { @($s.PSObject.Properties.Name) })
        foreach ($k in $keys) {
            if ($known -contains [string]$k) { continue }
            $v = Get-Prop $s $k
            if ($null -eq $v -or ($v -is [bool] -and -not $v) -or "$v" -eq '' -or ($v -is [System.Collections.IEnumerable] -and $v -isnot [string] -and @($v).Count -eq 0)) { continue }
            if ($v -is [bool]) { $parts += (ConvertTo-FriendlyName ([string]$k)).ToLower() }
            elseif ($v -is [System.Collections.IDictionary] -or ($v -is [System.Collections.IEnumerable] -and $v -isnot [string])) { $parts += ("{0}: {1}" -f (ConvertTo-FriendlyName ([string]$k)).ToLower(), (Format-SettingValue $v)) }
            else {
                $vs = [string]$v
                if ($script:PolicyNameById -and $script:PolicyNameById[$vs]) { $vs = "'{0}'" -f $script:PolicyNameById[$vs] }
                $parts += ("{0}: {1}" -f (ConvertTo-FriendlyName ([string]$k)).ToLower(), $vs)
            }
        }
    }
    $sch = Get-Prop $Assignment 'runSchedule'
    if ($sch) {
        $st = ([string](Get-Prop $sch '@odata.type')) -replace '#microsoft.graph.deviceHealthScript', '' -replace 'Schedule$', ''
        $iv = [int](Get-Prop $sch 'interval'); $tm = [string](Get-Prop $sch 'time'); $dt = [string](Get-Prop $sch 'date')
        $utc = $(if ((Get-Prop $sch 'useUtc') -eq $true) { ' UTC' } else { '' })
        if ($tm) { $tm = $tm -replace '(\d\d:\d\d):\d\d(\.\d+)?', '$1' }
        switch ($st) {
            'Hourly'  { $parts += ("runs every {0} hour{1}" -f $iv, $(if ($iv -eq 1) { '' } else { 's' })) }
            'Daily'   { $parts += ("runs every {0} day{1}{2}" -f $iv, $(if ($iv -eq 1) { '' } else { 's' }), $(if ($tm) { " at $tm$utc" } else { '' })) }
            'RunOnce' { $parts += ("runs once {0} {1}{2}" -f $dt, $tm, $utc).Trim() }
            default   { if ($iv) { $parts += ("runs every {0}" -f $iv) } }
        }
    }
    if ((Get-Prop $Assignment 'runRemediationScript') -eq $false) { $parts += 'detection only' }
    if ([string](Get-Prop $Assignment 'source') -eq 'policySets') { $parts += 'via policy set' }
    return ($parts -join '; ')
}

function Convert-AdmxValues {
    # $DefinitionValues = items from groupPolicyConfigurations/{id}/definitionValues?$expand=...
    param($DefinitionValues)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($dv in @($DefinitionValues)) {
        $def = Get-Prop $dv 'definition'
        $defId = [string](Get-Prop $def 'id')
        $defName = [string](Get-Prop $def 'displayName')
        if (-not $defName) { $defName = '(unknown ADMX setting)' }
        $classType = [string](Get-Prop $def 'classType')
        $scope = if ($classType -ieq 'user') { ' (User)' } else { ' (Computer)' }
        $enabled = Get-Prop $dv 'enabled'
        $state = if ($enabled) { 'Enabled' } else { 'Disabled' }
        $cat = ''
        $catPath = [string](Get-Prop $def 'categoryPath')
        if ($catPath) { $cat = @($catPath -split '\\' | Where-Object { $_ })[-1] }

        [void]$rows.Add([pscustomobject]@{
            Key      = "admx:$defId"
            Setting  = "$defName$scope"
            Value    = $state
            Category = $cat
        })

        if ($enabled) {
            foreach ($pv in (Get-PropList $dv 'presentationValues')) {
                $pres = Get-Prop $pv 'presentation'
                $label = [string](Get-Prop $pres 'label')
                if (-not $label) { $label = 'Value' }
                $pvId = [string](Get-Prop $pv 'id')
                $val = $null
                $vv = Get-Prop $pv 'value'
                $vvs = @(Get-PropList $pv 'values')
                if ($null -ne $vv) { $val = Format-SettingValue $vv }
                elseif ($vvs.Count -gt 0) {
                    $parts = @()
                    foreach ($e in $vvs) {
                        if ($null -eq $e) { continue }
                        # Multi-text presentations return a String collection; list-style
                        # presentations return objects with name/value fields.
                        if ($e -is [string] -or $e -is [System.ValueType]) {
                            $parts += (Format-SettingValue $e)
                            continue
                        }
                        $en = Get-Prop $e 'name'
                        $ev = Get-Prop $e 'value'
                        if ($null -ne $en -and "$en" -ne '') {
                            $parts += ("{0}={1}" -f $en, (Format-SettingValue $ev))
                        }
                        elseif ($null -ne $ev) {
                            $parts += (Format-SettingValue $ev)
                        }
                    }
                    $val = $parts -join '; '
                }
                if ($null -ne $val -and "$val" -ne '') {
                    [void]$rows.Add([pscustomobject]@{
                        Key      = "admx:$defId#$pvId"
                        Setting  = "$defName$scope :: $label"
                        Value    = $val
                        Category = $cat
                    })
                }
            }
        }
    }
    return $rows.ToArray()
}

function Convert-IntentSettings {
    # $Settings = items from intents/{id}/settings; $DefMap: definitionId -> @{Name;Category}
    # (built from templates/{id}/categories?$expand=settingDefinitions)
    param($Settings, [hashtable]$DefMap = @{})
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($Settings)) {
        $defId = [string](Get-Prop $s 'definitionId')
        $val = Get-Prop $s 'value'
        if ($null -eq $val) {
            $jsonValue = Get-Prop $s 'valueJson'
            if ($jsonValue -is [string] -and $jsonValue -ne '') {
                try { $val = ConvertFrom-Json -InputObject $jsonValue -AsHashtable -ErrorAction Stop }
                catch { $val = '(setting JSON could not be parsed - in the backup)' }
            } else { $val = $jsonValue }
        }
        if ($null -eq $val) { continue }
        if ($val -is [string]) {
            $trim = $val.Trim('"')
            if ($trim -eq 'null' -or $trim -eq '') { continue }
            $val = $trim
        }
        $name = Get-DefinitionTail $defId
        $cat = ''
        if ($defId -and $DefMap.ContainsKey($defId)) {
            $m = $DefMap[$defId]
            if ($m.Name) { $name = $m.Name }
            if ($m.Category) { $cat = $m.Category }
        }
        [void]$rows.Add([pscustomobject]@{
            Key      = "intent:$defId"
            Setting  = $name
            Value    = $(if ($script:SecretProps -contains (($defId -split '_')[-1]) -and "$val" -ne '') { '(secret - not shown)' } else { Format-SettingValue $val })
            Category = $cat
        })
    }
    return $rows.ToArray()
}

#endregion

#region ---------- policy corpus (all families) + cache -------------------------------------

function Get-PolicyPlatformTag {
    # Coarse platform tag so we don't show iOS profiles against Windows devices.
    param([string]$Family, $Raw)
    switch ($Family) {
        'admx'   { return 'windows' }
        'intent' { return 'windows' }
        'catalog' {
            $p = [string](Get-Prop $Raw 'platforms')
            if ($p -match 'windows') { return 'windows' }
            if ($p -match 'macOS') { return 'macos' }
            if ($p -match 'iOS|visionOS|tvOS') { return 'ios' }
            if ($p -match 'android|aosp') { return 'android' }
            if ($p -match 'linux') { return 'linux' }
            return 'other'
        }
        default {
            $t = ([string](Get-Prop $Raw '@odata.type')).ToLower()
            if ($t -match 'ios|iphone|ipad') { return 'ios' }
            if ($t -match 'macos') { return 'macos' }
            if ($t -match 'android|aosp') { return 'android' }
            if ($t -match 'windows|editionupgrade|sharedpc|domainjoin') { return 'windows' }
            return 'other'
        }
    }
}

function ConvertTo-CompactAssignments {
    param($Assignments)
    $out = @()
    foreach ($a in @($Assignments)) {
        $t = Get-Prop $a 'target'
        if ($null -eq $t) {
            # legacy script groupAssignments: { targetGroupId } only
            $tg = [string](Get-Prop $a 'targetGroupId')
            if ($tg) { $out += [pscustomobject]@{ Type = 'groupAssignmentTarget'; GroupId = $tg; FilterId = ''; FilterType = ''; Intent = ''; Options = '' } }
            continue
        }
        $gid = [string](Get-Prop $t 'groupId')
        if (-not $gid) { $gid = [string](Get-Prop $t 'entraObjectId') }   # scopeTagGroupAssignmentTarget
        $out += [pscustomobject]@{
            Type       = ([string](Get-Prop $t '@odata.type')) -replace '#microsoft.graph.', ''
            GroupId    = $gid
            CollectionId = [string](Get-Prop $t 'collectionId')   # tenant-attach ConfigMgr collection targets
            FilterId   = [string](Get-Prop $t 'deviceAndAppManagementAssignmentFilterId')
            FilterType = [string](Get-Prop $t 'deviceAndAppManagementAssignmentFilterType')
            Intent     = [string](Get-Prop $a 'intent')
            Options    = (Format-AssignmentOptions -Assignment $a)
        }
    }
    return $out
}

function Get-FamilyLabel {
    param([string]$Family, $Raw, [hashtable]$TemplateMap)
    switch ($Family) {
        'catalog' {
            $tr = Get-Prop $Raw 'templateReference'
            $tf = [string](Get-Prop $tr 'templateFamily')
            $tn = [string](Get-Prop $tr 'templateDisplayName')
            if ($tf -and $tf -ne 'none') {
                $nice = switch -Wildcard ($tf) {
                    'baseline'                          { 'Security Baseline' }
                    'endpointSecurityAntivirus'         { 'Endpoint Security - Antivirus' }
                    'endpointSecurityAttackSurfaceReduction*' { 'Endpoint Security - ASR' }
                    'endpointSecurityDiskEncryption'    { 'Endpoint Security - Disk Encryption' }
                    'endpointSecurityFirewall'          { 'Endpoint Security - Firewall' }
                    'endpointSecurityEndpointDetectionAndResponse' { 'Endpoint Security - EDR' }
                    'endpointSecurityAccountProtection' { 'Endpoint Security - Account Protection' }
                    'endpointSecurityApplicationControl' { 'Endpoint Security - App Control' }
                    'endpointSecurityEndpointPrivilegeManagement' { 'Endpoint Security - Privilege Management (EPM)' }
                    'enrollmentConfiguration'           { 'Autopilot device preparation' }
                    'appQuietTime'                      { 'App quiet time' }
                    'deviceConfigurationScripts'        { 'Settings Catalog (script template)' }
                    'deviceConfigurationPolicies'       { 'Settings Catalog (template)' }
                    'windowsOsRecoveryPolicies'         { 'Windows OS recovery' }
                    'companyPortal'                     { 'Company Portal settings' }
                    default { "Settings Catalog ($tf)" }
                }
                if ($tn) { return "$nice" } else { return $nice }
            }
            return 'Settings Catalog'
        }
        'legacy' {
            $t = ([string](Get-Prop $Raw '@odata.type')) -replace '#microsoft.graph.', ''
            if ($t -ieq 'windows10CustomConfiguration') { return 'Template - Custom OMA-URI' }
            return "Template - $(ConvertTo-FriendlyName $t)"
        }
        'admx' { return 'Administrative Templates (ADMX)' }
        'intent' {
            $tid = [string](Get-Prop $Raw 'templateId')
            if ($tid -and $TemplateMap.ContainsKey($tid)) { return "$($TemplateMap[$tid]) (legacy intent)" }
            return 'Endpoint Security / Baseline (legacy intent)'
        }
        'compliance' { return 'Compliance Policy' }
    }
    return $Family
}

function Get-CorpusCachePath {
    param([string]$TenantKey)
    return (Join-Path $HOME (".intune-rsop-cache-{0}.json" -f ($TenantKey -replace '[^a-zA-Z0-9\-]', '')))
}

function Reset-RsopQueryCaches {
    # Live inventory and membership are shared within a query, never across queries.
    $script:MemberGroupCache = @{}
    $script:DeviceIndex = $null
    $script:FilterEvalCache = @{}
    $script:FilterMatchSetCache = @{}
}

function Reset-RsopCorpusCaches {
    # A new active snapshot must not inherit definitions, names, plaintext or evaluations.
    Reset-RsopQueryCaches
    $script:GroupNameCache = @{}
    $script:GroupInfoCache = @{}
    $script:GroupMissing = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $script:CatalogDefinitionCache = @{}
    $script:ReusableSettingNames = @{}
    $script:OmaPlainCache = @{}
    $script:OmaSecretRows.Clear()
    $script:DecryptedOmaSettings.Clear()
    $script:ContainsDecryptedSecrets = $false
    $script:EvalCorpus = $null
    $script:EvalPolicies = @()
    $script:EvalGroupIds = @()
    $script:TenantPrefetch = @{}
    $script:FilterById = @{}
    $script:ReadProblems.Clear()
    $script:ReadProblemKeys = @{}
    $script:CaptureGaps.Clear()
}

function ConvertFrom-RsopCacheJson {
    # PowerShell 7.4 lacks -DateKind String. Preserve Graph's strings on that runtime too.
    param([string]$Json)
    if ($PSVersionTable.PSVersion -ge [version]'7.5') { return ConvertFrom-Json -InputObject $Json -DateKind String }
    $doc = [System.Text.Json.JsonDocument]::Parse($Json)
    $convert = {
        param([System.Text.Json.JsonElement]$Element)
        switch ([string]$Element.ValueKind) {
            'Object' {
                $properties = [ordered]@{}
                foreach ($p in $Element.EnumerateObject()) { $properties[$p.Name] = & $convert $p.Value }
                return [pscustomobject]$properties
            }
            'Array' { return , @(foreach ($v in $Element.EnumerateArray()) { & $convert $v }) }
            'String' { return $Element.GetString() }
            'Number' { $n = 0L; if ($Element.TryGetInt64([ref]$n)) { return $n }; return $Element.GetDouble() }
            'True' { return $true }
            'False' { return $false }
            default { return $null }
        }
    }
    try { return & $convert $doc.RootElement } finally { $doc.Dispose() }
}

function Set-RsopPrivateFile {
    # Restrict snapshots even when an export goes outside the user's profile.
    param([string]$Path, [switch]$Directory)
    if (-not $Path -or -not (Test-Path -LiteralPath $Path)) { return }
    try {
        # .NET resolves relative paths against the process directory, not PowerShell's location
        $Path = (Resolve-Path -LiteralPath $Path).ProviderPath
        if ($IsWindows) {
            $acl = if ($Directory) { [System.Security.AccessControl.DirectorySecurity]::new() } else { [System.Security.AccessControl.FileSecurity]::new() }
            $acl.SetAccessRuleProtection($true, $false)
            $owner = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
            $acl.SetOwner($owner)
            $inherit = if ($Directory) { [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' } else { [System.Security.AccessControl.InheritanceFlags]::None }
            foreach ($sid in @($owner, [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))) {
                $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($sid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
                [void]$acl.AddAccessRule($rule)
            }
            if ($Directory) { [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.DirectoryInfo]::new($Path), $acl) }
            else { [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]::new($Path), $acl) }
            return
        }
        $mode = $(if ($Directory) { [System.IO.UnixFileMode]'UserRead, UserWrite, UserExecute' } else { [System.IO.UnixFileMode]'UserRead, UserWrite' })
        [System.IO.File]::SetUnixFileMode($Path, $mode)
    } catch { Add-RunLog -Level warn -Message ("Could not restrict permissions for '{0}': {1}" -f $Path, (Format-RsopError $_)) }
}

function New-RsopOutputFile {
    # Reserve a generated file before writing tenant data. Keep explicit export paths
    # under the caller's control; use this only for automatically named reports/logs.
    param([string]$Path)
    $parent = (Resolve-Path -LiteralPath (Split-Path -Parent $Path) -ErrorAction Stop).ProviderPath
    $name = [IO.Path]::GetFileNameWithoutExtension($Path)
    $extension = [IO.Path]::GetExtension($Path)
    $suffix = 1
    while ($true) {
        $candidate = Join-Path $parent ($name + $(if ($suffix -gt 1) { "-$suffix" } else { '' }) + $extension)
        $file = $null
        try {
            $file = [IO.FileStream]::new($candidate, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        }
        catch {
            if (Test-Path -LiteralPath $candidate) { $suffix++; continue }
            throw
        }
        finally { if ($file) { $file.Dispose() } }
        Set-RsopPrivateFile -Path $candidate
        return $candidate
    }
}

function Save-CorpusCache {
    # Writes the corpus to the on-disk cache. Decrypted custom OMA-URI values never go to disk:
    # their rows are written with a placeholder and a reference (policy, setting, secret id), and
    # Restore-CorpusSecrets decrypts them again when the cache is read.
    param($Corpus)
    if ($CacheMinutes -le 0) { return }
    $cacheFile = Get-CorpusCachePath -TenantKey ([string]$Corpus.tenant)
    $restore = [System.Collections.Generic.List[object]]::new()
    $secrets = @($script:OmaSecretRows | Sort-Object PolicyId, Key, Setting -Unique)
    try {
        if ($script:ContainsDecryptedSecrets) {
            $byId = @{}
            foreach ($cp in @($Corpus.policies)) { $byId[[string]$cp.Id] = $cp }
            $unplaced = 0
            foreach ($e in $secrets) {
                $pol = $byId[[string]$e.PolicyId]
                $hit = $false
                foreach ($row in @($(if ($pol) { $pol.Settings }))) {
                    if ($row.Key -eq $e.Key -and $row.Setting -eq $e.Setting) {
                        $hit = $true
                        if ($row.Value -ne $script:OmaCachePlaceholder) { $restore.Add(@($row, $row.Value)); $row.Value = $script:OmaCachePlaceholder }
                    }
                }
                if (-not $hit) { $unplaced++ }
            }
            # a decrypted value whose row cannot be found could still be in the corpus: no cache then
            if ($unplaced -gt 0 -or $script:OmaSecretRows.Count -lt $script:DecryptedOmaSettings.Count) {
                if (Test-Path -LiteralPath $cacheFile) { Remove-Item -LiteralPath $cacheFile -Force -ErrorAction SilentlyContinue }
                Add-SessionLog 'info' 'Policy cache not written: a decrypted custom OMA-URI value could not be replaced by a placeholder.'
                return
            }
        }
        $Corpus | Add-Member -NotePropertyName omaSecrets -NotePropertyValue @($secrets | Select-Object PolicyId, Key, Setting, SecretRef, Label) -Force
        $Corpus | ConvertTo-Json -Depth 100 -Compress | Set-Content -LiteralPath $cacheFile -Encoding UTF8
        Set-RsopPrivateFile $cacheFile
    }
    catch {
        Add-SessionLog 'warn' ("Policy cache not written: {0}" -f (Format-RsopError $_))
        if (Test-Path -LiteralPath $cacheFile) { Remove-Item -LiteralPath $cacheFile -Force -ErrorAction SilentlyContinue }
    }
    finally {
        foreach ($r in $restore) { $r[0].Value = $r[1] }
    }
}

function Restore-CorpusSecrets {
    # After a cache read: decrypts the custom OMA-URI values the cache holds placeholders for
    # (batched) and puts them back into their rows.
    param($Corpus)
    $entries = @($Corpus.omaSecrets | Where-Object { $_ -and $_.PolicyId -and $_.SecretRef })
    if (-not $entries.Count) { return }
    Read-OmaPlainTexts -Refs @($entries | ForEach-Object { , @([string]$_.PolicyId, [string]$_.SecretRef) })
    $byId = @{}
    foreach ($cp in @($Corpus.policies)) { $byId[[string]$cp.Id] = $cp }
    foreach ($e in $entries) {
        $plain = $script:OmaPlainCache[("{0}|{1}" -f $e.PolicyId, $e.SecretRef)]
        $pol = $byId[[string]$e.PolicyId]
        if ($null -eq $pol) { continue }
        foreach ($row in @($pol.Settings)) {
            if ($row.Key -ne $e.Key -or $row.Setting -ne $e.Setting) { continue }
            if ($null -ne $plain -and $plain -ne '') { $row.Value = (Format-SettingValue $plain) }
            else { $row.Value = '(encrypted value - could not decrypt; view in portal)' }
        }
        if ($null -ne $plain -and $plain -ne '') {
            $script:ContainsDecryptedSecrets = $true
            if (-not $script:DecryptedOmaSettings.Contains([string]$e.Label)) { [void]$script:DecryptedOmaSettings.Add([string]$e.Label) }
            [void]$script:OmaSecretRows.Add([pscustomobject]@{ PolicyId = [string]$e.PolicyId; Key = [string]$e.Key; Setting = [string]$e.Setting; SecretRef = [string]$e.SecretRef; Label = [string]$e.Label })
        }
    }
}

function Get-PolicyCorpus {
    param([string]$TenantKey)

    $cacheFile = Get-CorpusCachePath -TenantKey $TenantKey
    $cacheOptions = [pscustomobject]@{
        IncludeCompliance  = [bool](-not $SkipCompliance)
        IncludeUpdates     = [bool](-not $SkipUpdates)
        IncludeScripts     = [bool](-not $SkipScripts)
        IncludeApps        = [bool](-not $SkipApps)
        IncludeAppPolicies = [bool](-not $SkipAppPolicies)
        IncludeEnrollment  = [bool](-not $SkipEnrollment)
    }
    # Version 5 and earlier may contain decrypted custom OMA-URI values. Remove those
    # files on every run, even when cache reads are disabled with -Refresh/-CacheMinutes 0.
    # (One parse serves that check and the cache read.)
    $cached = $null; $ver = 0
    if (Test-Path -LiteralPath $cacheFile) {
        try {
            # keep ISO date strings as strings (otherwise a cached run turns setting values into
            # DateTime and the report / CSV differ from a fresh run)
            $cached = ConvertFrom-RsopCacheJson -Json ([System.IO.File]::ReadAllText($cacheFile))
            try { $ver = [int]$cached.cacheVersion } catch { $ver = 0 }
            if ($ver -lt 6) {
                $cached = $null
                Remove-Item -LiteralPath $cacheFile -Force -ErrorAction Stop
                Write-Warn2 'Removed a legacy policy cache that may contain decrypted OMA-URI values.'
            }
        }
        catch {
            $cached = $null
            Remove-Item -LiteralPath $cacheFile -Force -ErrorAction SilentlyContinue
            Write-Warn2 'Removed an unreadable policy cache.'
        }
    }
    if (-not $Refresh -and $CacheMinutes -gt 0 -and $null -ne $cached) {
        try {
            $age = (Get-Date) - [datetime]$cached.generated
            $optionsMatch = $ver -eq 19 -and $null -ne $cached.cacheOptions -and
                [bool]$cached.cacheOptions.IncludeCompliance -eq $cacheOptions.IncludeCompliance -and
                [bool]$cached.cacheOptions.IncludeUpdates -eq $cacheOptions.IncludeUpdates -and
                [bool]$cached.cacheOptions.IncludeScripts -eq $cacheOptions.IncludeScripts -and
                [bool]$cached.cacheOptions.IncludeApps -eq $cacheOptions.IncludeApps -and
                [bool]$cached.cacheOptions.IncludeAppPolicies -eq $cacheOptions.IncludeAppPolicies -and
                [bool]$cached.cacheOptions.IncludeEnrollment -eq $cacheOptions.IncludeEnrollment
            if ($optionsMatch -and $age.TotalMinutes -lt $CacheMinutes) {
                Reset-RsopCorpusCaches
                Write-Step ("Using cached policy data from {0:HH:mm:ss} ({1:n0} min old; -Refresh to re-pull)" -f [datetime]$cached.generated, $age.TotalMinutes)
                # the cached pull's warnings stay in the report; the run log notes them too
                foreach ($w in @($cached.warnings)) { if ($w) { Add-SessionLog 'warn' ("(cached pull) {0}" -f $w) } }
                $script:CaptureGaps.Clear()
                foreach ($g in @($cached.captureGaps)) { if ($g) { [void]$script:CaptureGaps.Add($g); Add-RsopSessionGap $g } }
                $script:ScopeTagNames = @{ '0' = 'Default' }
                foreach ($pp in @($cached.scopeTags.PSObject.Properties)) { $script:ScopeTagNames[$pp.Name] = [string]$pp.Value }
                Restore-CorpusSecrets -Corpus $cached
                return $cached
            }
        } catch { Write-Warn2 "Cache unreadable; re-pulling." }
    }
    $cached = $null
    Reset-RsopCorpusCaches

    $policies = [System.Collections.Generic.List[object]]::new()
    $appObjs = [System.Collections.Generic.List[object]]::new()
    $warnings = New-Object System.Collections.Generic.List[string]
    $script:ReadProblems.Clear()   # a fresh pull: earlier failed reads no longer apply
    $script:CaptureGaps.Clear()
    # app id -> display name, and bundle / package id -> app id (lets app-config and
    # app-protection policies name the apps they target)
    $appNameById = @{}
    $appIdByIdentifier = @{}

    # -- templates map for legacy intents ------------------------------------------------
    $templateMap = @{}
    try {
        foreach ($t in (Get-RsopPaged -Uri 'beta/deviceManagement/templates?$select=id,displayName')) {
            $templateMap[[string]$t['id']] = [string]$t['displayName']
        }
    } catch { }

    # -- settings catalog category names (groups the report like the portal does) --------
    Write-Step "Pulling setting category names"
    $catMap = @{}
    try {
        foreach ($c in (Get-RsopPaged -Uri 'beta/deviceManagement/configurationCategories?$select=id,displayName' -Activity 'configurationCategories')) {
            $catMap[[string]$c['id']] = [string]$c['displayName']
        }
        Write-Info ("{0} categories" -f $catMap.Count)
    } catch { [void]$warnings.Add("Could not list setting categories: $(Format-RsopError $_)") }

    # -- scope tag names (policies and apps carry tag ids) ----------------------------------
    $scopeTagMap = @{ '0' = 'Default' }
    $scopeTagsRead = $false
    try {
        foreach ($t in (Get-RsopPaged -Uri 'beta/deviceManagement/roleScopeTags?$select=id,displayName')) { $scopeTagMap[[string]$t['id']] = [string]$t['displayName'] }
        $scopeTagsRead = $true
    } catch { Add-RunLog -Level info -Message ("Scope tag names not readable (needs DeviceManagementRBAC.Read.All): {0}" -f (Format-RsopError $_)) }
    $script:ScopeTagNames = $scopeTagMap

    function Get-PolicyMeta {
        param($Raw)
        $mod = Format-GraphDate (Get-Prop $Raw 'lastModifiedDateTime')
        if ($mod.Length -ge 10) { $mod = $mod.Substring(0, 10) }
        return @{
            Desc     = [string](Get-Prop $Raw 'description')
            Modified = $mod
            Created  = Format-GraphDate (Get-Prop $Raw 'createdDateTime')
        }
    }

    function Add-CorpusPolicy {
        # Single constructor for corpus policy entries so every family carries the same shape.
        param([string]$Id, [string]$Name, [string]$Family, [string]$FamilyLabel, [string]$Platform, $Raw,
              $Assignments, $Settings, [string]$Detail = '', [hashtable]$Extra = @{},
              [string]$BackupArea, [hashtable]$BackupExtra = @{})
        if ($BackupArea) { Save-RsopBackupItem -Area $BackupArea -Item $Raw -Name $Name -Extra $BackupExtra }
        $meta = Get-PolicyMeta -Raw $Raw
        $o = [ordered]@{
            Id          = $Id
            Name        = $Name
            Family      = $Family
            FamilyLabel = $FamilyLabel
            Platform    = $Platform
            Desc        = $meta.Desc
            Modified    = $meta.Modified
            Created     = $meta.Created
            Detail      = $Detail
            ScopeTags   = @(Get-PropList $Raw 'roleScopeTagIds' | ForEach-Object { [string]$_ })
            Assignments = @($Assignments | Where-Object { $null -ne $_ })
            Settings    = @($Settings | Where-Object { $null -ne $_ })
            # assignments that could not be READ are unknown, never 'not assigned'
            AssignmentsUnreadable = ($Raw -is [System.Collections.IDictionary] -and @($Raw['@intuneLens.unreadable']) -contains 'assignments')
        }
        foreach ($k in $Extra.Keys) { $o[$k] = $Extra[$k] }
        [void]$policies.Add([pscustomobject]$o)
    }

    function Resolve-TargetApps {
        # mobileApp ids and/or bundle / package identifiers -> @(@{ AppId; Name })
        param([string[]]$AppIds, $ManagedApps)
        $out = @()
        foreach ($aid in @($AppIds | Where-Object { $_ })) {
            $nm = $appNameById[$aid]
            if (-not $nm) {
                try { $r = Invoke-Rsop -Uri ("beta/deviceAppManagement/mobileApps/{0}?`$select=id,displayName" -f $aid); $nm = [string]$r['displayName']; $appNameById[$aid] = $nm } catch { $nm = $aid }
            }
            $out += [pscustomobject]@{ AppId = $aid; Name = $nm }
        }
        foreach ($managedApp in $ManagedApps) {
            $ident = Get-AppIdentifierText $managedApp
            if (-not $ident) { continue }
            $identPlatform = Get-AppIdentifierPlatform $managedApp
            $aid = $appIdByIdentifier["${identPlatform}|$($ident.ToLower())"]
            $out += [pscustomobject]@{ AppId = $(if ($aid) { $aid } else { '' }); Name = $(if ($aid -and $appNameById[$aid]) { "{0} ({1})" -f $appNameById[$aid], $ident } else { $ident }) }
        }
        return $out
    }

    function Get-ScriptBodyRows {
        # Fetches one platform script individually (list responses omit the body),
        # decodes the base64 content and returns it as a searchable setting row. This is
        # how the report can answer "which script is removing app X". $Prefetched holds the
        # batched GET-by-id bodies; a script missing from it is read directly.
        param([string]$BaseUri, $Item, [string]$BackupArea, $Assignments, [hashtable]$Prefetched)
        $id = [string](Get-Prop $Item 'id')
        if (-not $id) { return , @() }
        $detail = $null
        $cached = $(if ($Prefetched) { $Prefetched[('{0}/{1}' -f ($BaseUri -replace '^beta', ''), $id)] } else { $null })
        if ($cached -is [System.Collections.IDictionary] -and $cached['id']) { $detail = $cached }
        else {
            try { $detail = Invoke-Rsop -Uri ("{0}/{1}" -f $BaseUri, $id) } catch {
                [void]$warnings.Add(("Could not fetch script body for '{0}': {1}" -f (Get-Prop $Item 'displayName'), (Format-RsopError $_)))
                Save-RsopBackupItem -Area $BackupArea -Item $Item -Extra @{ assignments = (ConvertTo-RsopList $Assignments) }
                return , @()
            }
        }
        Save-RsopBackupItem -Area $BackupArea -Item $detail -Extra @{ assignments = (ConvertTo-RsopList $Assignments) }
        $b64 = [string](Get-Prop $detail 'scriptContent')
        if (-not $b64) { return , @() }
        $text = ''
        try { $text = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64)).Trim() } catch { return , @() }
        if (-not $text) { return , @() }
        if ($text.Length -gt 6000) { $text = $text.Substring(0, 6000) + "`n...(truncated)" }
        $label = 'Script content'
        $fname = [string](Get-Prop $detail 'fileName')
        if ($fname) { $label = ("Script content ({0})" -f $fname) }
        return , @([pscustomobject]@{
            Key      = ("script:{0}:scriptContent" -f $id)
            Setting  = $label
            Value    = $text
            Category = 'Script body'
        })
    }

    # -- 1) Settings Catalog + modern Endpoint Security + modern Baselines ---------------
    Write-Step "Pulling Settings Catalog / Endpoint Security / Baseline policies (configurationPolicies)"
    $cfgPolicies = Get-RsopPaged -Uri 'beta/deviceManagement/configurationPolicies?$expand=assignments&$top=100' -Activity 'configurationPolicies'
    # Every policy's settings in /$batch requests WITHOUT their definitions (20 per request),
    # then each definition they use once for the whole tenant: policies share most definitions,
    # and expanding them per policy downloads the same ones again and again. A policy whose
    # settings did not come back, or that uses a definition the catalog does not serve by id, is
    # read the old way: its settings with the definitions expanded (5 per request, they are large).
    $liteUrl = '/deviceManagement/configurationPolicies/{0}/settings'
    $settingsUrl = '/deviceManagement/configurationPolicies/{0}/settings?$expand=settingDefinitions'
    $cfgIds = @($cfgPolicies | Where-Object { $_ -and $_['id'] } | ForEach-Object { [string]$_['id'] })
    $lite = Get-RsopBatchedCollections -Urls @($cfgIds | ForEach-Object { $liteUrl -f $_ }) -Activity 'Settings Catalog settings'
    $defIdsOf = @{}
    $allDefIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($id in $cfgIds) {
        $u = $liteUrl -f $id
        if (-not $lite.ContainsKey($u)) { continue }
        $defIdsOf[$id] = Get-CatalogDefinitionIds -SettingItems $lite[$u]
        $allDefIds.UnionWith($defIdsOf[$id])
    }
    Read-CatalogDefinitions -Ids ([string[]]@($allDefIds))
    $needExpanded = @(foreach ($id in $cfgIds) {
            $ok = $defIdsOf.ContainsKey($id)
            if ($ok) { foreach ($d in $defIdsOf[$id]) { if ($null -eq $script:CatalogDefinitionCache[$d]) { $ok = $false; break } } }
            if (-not $ok) { $settingsUrl -f $id }
        })
    $prefetched = Get-RsopBatchedCollections -Urls $needExpanded -Activity 'Settings Catalog settings (expanded)' -ChunkSize 5
    $expandedSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$needExpanded, [System.StringComparer]::OrdinalIgnoreCase)
    $n = 0
    foreach ($p in $cfgPolicies) {
        $n++
        $pname = [string]$p['name']
        Write-RsopProgress -Id 3 -Activity 'Fetching settings (Settings Catalog & Endpoint Security)' -Status ("{0}/{1}  {2}" -f $n, @($cfgPolicies).Count, $pname) -Percent ([int](100 * $n / [math]::Max(1, @($cfgPolicies).Count)))
        $rows = @()
        $settings = @()
        $bx = @{}
        try {
            $liteKey = $liteUrl -f $p['id']
            if ($defIdsOf.ContainsKey([string]$p['id']) -and -not $expandedSet.Contains(($settingsUrl -f $p['id']))) {
                $settings = $lite[$liteKey]
                $rows = Convert-CatalogSettings -SettingItems $settings -CategoryMap $catMap -Definitions $script:CatalogDefinitionCache
            }
            else {
                $settings = Get-RsopCollection -Prefetched $prefetched -Url ($settingsUrl -f $p['id'])
                $rows = Convert-CatalogSettings -SettingItems $settings -CategoryMap $catMap
            }
        } catch {
            [void]$warnings.Add("Could not fetch settings for '$pname': $(Format-RsopError $_)")
            $bx['@intuneLens.incomplete'] = "settings not readable: $(Format-RsopError $_)"
        }
        $tref = $p['templateReference']
        $detail = ''
        if ($tref) { $detail = [string](Get-Prop $tref 'templateDisplayName') }
        $fl = Get-FamilyLabel -Family 'catalog' -Raw $p -TemplateMap $templateMap
        if ($script:BackupRoot) { $bx['settings'] = Remove-RsopKeys -Items $settings -Keys @('settingDefinitions') }   # (a copy: only a backup needs it)
        Save-RsopBackupItem -Area $(if ($fl -like 'Endpoint Security*') { 'Endpoint security' } elseif ($fl -eq 'Security Baseline') { 'Security baselines' } else { 'Settings catalog' }) `
            -Item $p -Name $pname -Extra $bx
        Add-CorpusPolicy -Id ([string]$p['id']) -Name $pname -Family 'catalog' -FamilyLabel $fl -Platform (Get-PolicyPlatformTag -Family 'catalog' -Raw $p) `
            -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows -Detail $detail
    }
    Complete-RsopProgress -Id 3

    # -- 2) Legacy device configuration templates ----------------------------------------
    Write-Step "Pulling classic Device Configuration templates (deviceConfigurations)"
    $legacy = Get-RsopPaged -Uri 'beta/deviceManagement/deviceConfigurations?$expand=assignments&$top=100' -Activity 'deviceConfigurations'
    # Intune encrypts custom OMA-URI string values: decrypt them all in /$batch requests now
    # (Get-OmaPlainText then answers from its cache) instead of one request per value
    $omaRefs = @(foreach ($lp in $legacy) {
            foreach ($o in @(Get-PropList $lp 'omaSettings')) {
                if ((Get-Prop $o 'isEncrypted') -and (Get-Prop $o 'secretReferenceValueId')) { , @([string]$lp['id'], [string](Get-Prop $o 'secretReferenceValueId')) }
            }
        })
    Read-OmaPlainTexts -Refs $omaRefs
    # Certificate, Wi-Fi, VPN, e-mail and wired-network profiles chain to trusted-root and
    # identity certificate profiles through navigation links the list leaves out. Read them
    # (batched) - a rebuild has to recreate the certificates first and re-link them.
    $navFor = {
        param([string]$Type)
        switch -Regex ($Type) {
            'CertificateProfile$'                                   { return @('rootCertificate') }
            'EasEmailProfile'                                       { return @('identityCertificate', 'smimeSigningCertificate', 'smimeEncryptionCertificate', 'derivedCredentialSettings') }
            '(GmailEas|NineWorkEas)Configuration$'                   { return @('identityCertificate') }
            'DerivedCredentialAuthenticationConfiguration$'        { return @('derivedCredentialSettings') }
            'VpnConfiguration$'                                     { return @('identityCertificate', 'derivedCredentialSettings') }
            '(EnterpriseWiFi|WifiEnterpriseEAP|WiredNetwork)Configuration$' {
                return @('identityCertificateForClientAuthentication', 'secondaryIdentityCertificateForClientAuthentication', 'rootCertificateForServerValidation',
                    'rootCertificatesForServerValidation', 'rootCertificateForClientValidation', 'secondaryRootCertificateForClientValidation', 'derivedCredentialSettings')
            }
            'DeviceFeaturesConfiguration$'                          { return @('identityCertificateForClientAuthentication', 'singleSignOnExtensionPkinitCertificate') }
            'ZtdnsConfiguration$'                                   { return @('rootCertificatesForClientValidation', 'rootCertificatesForServerValidation') }
            '^windowsDomainJoinConfiguration$'                      { return @('networkAccessConfigurations') }
        }
        return @()
    }
    $linkUrls = @{}
    foreach ($p in $legacy) {
        $t = ([string]$p['@odata.type']) -replace '^#', ''
        foreach ($nav in @(& $navFor ($t -replace '^microsoft\.graph\.', ''))) {
            $linkUrls[('/deviceManagement/deviceConfigurations/{0}/{1}/{2}?$select=id,displayName' -f $p['id'], $t, $nav)] = @([string]$p['id'], $nav)
        }
    }
    $linkBodies = $(if ($linkUrls.Count) { Invoke-RsopBatch -Urls @($linkUrls.Keys) -Activity 'Certificate profile links' } else { @{} })
    $certLinks = @{}   # config id -> ordered nav -> @(names)
    foreach ($u in $linkUrls.Keys) {
        $b = $linkBodies[$u]
        if ($b -isnot [System.Collections.IDictionary]) { continue }
        $targets = $(if ($b.Contains('value')) { @($b['value']) } else { @($b) })
        $names = @($targets | Where-Object { $_ -is [System.Collections.IDictionary] -and $_['id'] } | ForEach-Object { $(if ($_['displayName']) { [string]$_['displayName'] } else { [string]$_['id'] }) })
        if (-not $names.Count) { continue }
        $cid, $nav = $linkUrls[$u]
        if (-not $certLinks.ContainsKey($cid)) { $certLinks[$cid] = [ordered]@{} }
        $certLinks[$cid][$nav] = $names
    }

    foreach ($p in $legacy) {
        $rows = @(Convert-LegacyProperties -Policy $p)
        if ($certLinks.ContainsKey([string]$p['id'])) {
            foreach ($nav in $certLinks[[string]$p['id']].Keys) {
                $rows += [pscustomobject]@{ Key = ("link:{0}:{1}" -f $p['id'], $nav); Setting = ("Linked profile: {0}" -f (ConvertTo-FriendlyName $nav)); Value = ($certLinks[[string]$p['id']][$nav] -join '; '); Category = 'Certificate and profile links' }
            }
        }
        if ($script:BackupRoot) {
            # encrypted custom OMA-URI values come back null: back up the decrypted value
            # (Convert-LegacyProperties already resolved it) so the profile can be rebuilt
            $omaExtra = @{}
            $oma = @(Get-PropList $p 'omaSettings')
            if (@($oma | Where-Object { Get-Prop $_ 'isEncrypted' }).Count) {
                $patched = Remove-RsopKeys -Items $oma -Keys @()   # (emits one array - no @())
                foreach ($o in $patched) {
                    $ref = [string]$o['secretReferenceValueId']
                    $ck = "{0}|{1}" -f $p['id'], $ref
                    if ($o['isEncrypted'] -and $ref -and $script:OmaPlainCache -and $script:OmaPlainCache[$ck]) { $o['value'] = $script:OmaPlainCache[$ck] }
                }
                $omaExtra['omaSettings'] = $patched
            }
            if ($certLinks.ContainsKey([string]$p['id'])) { $omaExtra['linkedProfiles'] = $certLinks[[string]$p['id']] }
            Save-RsopBackupItem -Area 'Device configuration profiles' -Item $p -Extra $omaExtra
        }
        Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'legacy' `
            -FamilyLabel (Get-FamilyLabel -Family 'legacy' -Raw $p -TemplateMap $templateMap) -Platform (Get-PolicyPlatformTag -Family 'legacy' -Raw $p) `
            -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows
    }

    # -- 3) Administrative templates (ADMX) ----------------------------------------------
    Write-Step "Pulling Administrative Templates (groupPolicyConfigurations)"
    $admx = Get-RsopPaged -Uri 'beta/deviceManagement/groupPolicyConfigurations?$expand=assignments&$top=100' -Activity 'groupPolicyConfigurations'
    $valuesUrl = '/deviceManagement/groupPolicyConfigurations/{0}/definitionValues?$expand=definition($select=id,classType,displayName,categoryPath),presentationValues($expand=presentation)'
    $prefetched = Get-RsopBatchedCollections -Urls @($admx | Where-Object { $_ -and $_['id'] } | ForEach-Object { $valuesUrl -f $_['id'] }) -Activity 'ADMX definition values' -ChunkSize 10
    $n = 0
    foreach ($p in $admx) {
        $n++
        $pname = [string]$p['displayName']
        Write-RsopProgress -Id 3 -Activity 'Fetching ADMX definition values' -Status ("{0}/{1}  {2}" -f $n, @($admx).Count, $pname) -Percent ([int](100 * $n / [math]::Max(1, @($admx).Count)))
        $rows = @()
        $dv = @()
        try {
            $dv = Get-RsopCollection -Prefetched $prefetched -Url ($valuesUrl -f $p['id'])
            $rows = Convert-AdmxValues -DefinitionValues $dv
        } catch {
            [void]$warnings.Add("Could not fetch ADMX values for '$pname': $(Format-RsopError $_)")
            $p['@intuneLens.incomplete'] = "definition values not readable: $(Format-RsopError $_)"
        }
        Save-RsopBackupItem -Area 'Administrative templates' -Item $p -Extra @{ definitionValues = (ConvertTo-RsopList $dv) }
        Add-CorpusPolicy -Id ([string]$p['id']) -Name $pname -Family 'admx' -FamilyLabel 'Administrative Templates (ADMX)' -Platform 'windows' `
            -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows
    }
    Complete-RsopProgress -Id 3

    # -- 4) Legacy endpoint security / baselines (intents) -------------------------------
    Write-Step "Pulling legacy Endpoint Security / Security Baselines (intents)"
    $intents = @()
    try { $intents = Get-RsopPaged -Uri 'beta/deviceManagement/intents' -Activity 'intents' } catch {
        [void]$warnings.Add("Could not list intents: $(Format-RsopError $_)")
    }
    $intentDefMaps = @{}   # templateId -> (definitionId -> @{Name;Category})
    # template categories (once per template), settings and assignments of every intent: batched
    $categoriesUrl = '/deviceManagement/templates/{0}/categories?$expand=settingDefinitions'
    $intentSettingsUrl = '/deviceManagement/intents/{0}/settings'
    $intentAssignmentsUrl = '/deviceManagement/intents/{0}/assignments'
    $intentList = @($intents | Where-Object { $_ -and $_['id'] })
    $prefetched = Get-RsopBatchedCollections -Urls @($intentList | ForEach-Object { [string]$_['templateId'] } | Where-Object { $_ } | ForEach-Object { $categoriesUrl -f $_ }) -Activity 'Intent templates' -ChunkSize 5
    $more = Get-RsopBatchedCollections -Urls @($intentList | ForEach-Object { ($intentSettingsUrl -f $_['id']), ($intentAssignmentsUrl -f $_['id']) }) -Activity 'Intent settings and assignments'
    foreach ($k in $more.Keys) { $prefetched[$k] = $more[$k] }
    $n = 0
    foreach ($p in $intents) {
        $n++
        $pname = [string]$p['displayName']
        Write-RsopProgress -Id 3 -Activity 'Fetching intent settings' -Status ("{0}/{1}  {2}" -f $n, @($intents).Count, $pname) -Percent ([int](100 * $n / [math]::Max(1, @($intents).Count)))

        # real setting display names live on the intent's template categories
        $tid = [string]$p['templateId']
        if ($tid -and -not $intentDefMaps.ContainsKey($tid)) {
            $dm = @{}
            try {
                $cats = Get-RsopCollection -Prefetched $prefetched -Url ($categoriesUrl -f $tid)
                foreach ($c in @($cats)) {
                    $cname = [string](Get-Prop $c 'displayName')
                    foreach ($sd in (Get-PropList $c 'settingDefinitions')) {
                        $sdid = [string](Get-Prop $sd 'id')
                        if ($sdid -and -not $dm.ContainsKey($sdid)) {
                            $dm[$sdid] = @{ Name = [string](Get-Prop $sd 'displayName'); Category = $cname }
                        }
                    }
                }
            } catch { }
            $intentDefMaps[$tid] = $dm
        }
        $defMap = @{}
        if ($tid -and $intentDefMaps.ContainsKey($tid)) { $defMap = $intentDefMaps[$tid] }

        $rows = @(); $asg = @(); $isettings = @(); $ia = @()
        try {
            $isettings = Get-RsopCollection -Prefetched $prefetched -Url ($intentSettingsUrl -f $p['id'])
            $rows = Convert-IntentSettings -Settings $isettings -DefMap $defMap
        } catch {
            [void]$warnings.Add("Could not fetch settings for intent '$pname': $(Format-RsopError $_)")
            $p['@intuneLens.incomplete'] = "settings not readable: $(Format-RsopError $_)"
        }
        try {
            $ia = Get-RsopCollection -Prefetched $prefetched -Url ($intentAssignmentsUrl -f $p['id'])
            $asg = @(ConvertTo-CompactAssignments -Assignments $ia)
        } catch {
            [void]$warnings.Add("Could not fetch assignments for intent '$pname': $(Format-RsopError $_)")
            $p['@intuneLens.unreadable'] = @('assignments')
        }
        Save-RsopBackupItem -Area 'Endpoint security (legacy intents)' -Item $p -Extra @{ settings = (ConvertTo-RsopList $isettings); assignments = (ConvertTo-RsopList $ia) }
        Add-CorpusPolicy -Id ([string]$p['id']) -Name $pname -Family 'intent' -FamilyLabel (Get-FamilyLabel -Family 'intent' -Raw $p -TemplateMap $templateMap) `
            -Platform 'windows' -Raw $p -Assignments $asg -Settings $rows `
            -Detail $(if ($tid -and $templateMap.ContainsKey($tid)) { $templateMap[$tid] } else { '' })
    }
    Complete-RsopProgress -Id 3

    # -- 5) Compliance policies (optional) ------------------------------------------------
    if (-not $SkipCompliance) {
        Write-Step "Pulling Compliance policies"
        # e-mail actions name their notification template
        $script:NotificationTemplateNames = @{}
        try {
            foreach ($t in (Get-RsopPaged -Uri 'beta/deviceManagement/notificationMessageTemplates?$select=id,displayName')) {
                $script:NotificationTemplateNames[[string]$t['id']] = [string]$t['displayName']
            }
        } catch { Add-RunLog -Level info -Message ("Could not list notification message templates: {0}" -f (Format-RsopError $_)) }
        # custom compliance discovery scripts are referenced by id from Windows policies
        $complianceScripts = @{}
        if (-not $SkipScripts) {
            try {
                foreach ($cs in (Get-RsopPaged -Uri 'beta/deviceManagement/deviceComplianceScripts')) {
                    $complianceScripts[[string]$cs['id']] = $cs
                }
            } catch { Add-RunLog -Level info -Message ("Could not list custom compliance scripts: {0}" -f (Format-RsopError $_)) }
        }
        try {
            $comp = $null
            $actionsExpanded = $true
            try { $comp = Get-RsopPaged -Uri 'beta/deviceManagement/deviceCompliancePolicies?$expand=assignments,scheduledActionsForRule($expand=scheduledActionConfigurations)&$top=100' -Activity 'compliancePolicies' }
            catch {
                $actionsExpanded = $false
                $comp = Get-RsopPaged -Uri 'beta/deviceManagement/deviceCompliancePolicies?$expand=assignments&$top=100' -Activity 'compliancePolicies'
            }
            $actionMap = @{}
            if (-not $actionsExpanded) {
                $urls = @($comp | ForEach-Object { '/deviceManagement/deviceCompliancePolicies/{0}/scheduledActionsForRule?$expand=scheduledActionConfigurations' -f $_['id'] })
                $got = Invoke-RsopBatch -Urls $urls -Activity 'compliance actions'
                foreach ($p in $comp) {
                    $b = $got['/deviceManagement/deviceCompliancePolicies/{0}/scheduledActionsForRule?$expand=scheduledActionConfigurations' -f $p['id']]
                    if ($b) { $actionMap[[string]$p['id']] = @($b['value']) }
                }
            }
            foreach ($p in $comp) {
                $pid0 = [string]$p['id']
                $rows = @(Convert-LegacyProperties -Policy $p -Skip @('deviceCompliancePolicyScript'))
                $rules = $(if ($actionsExpanded) { @(Get-PropList $p 'scheduledActionsForRule') } else { @($actionMap[$pid0]) })
                Save-RsopBackupItem -Area 'Compliance policies' -Item $p -Extra @{ scheduledActionsForRule = (ConvertTo-RsopList $rules) }
                $rows += @(Convert-ComplianceActions -Rules $rules -PolicyId $pid0)
                $scr = Get-Prop $p 'deviceCompliancePolicyScript'
                if ($scr) {
                    $sid = [string](Get-Prop $scr 'deviceComplianceScriptId')
                    $sobj = $complianceScripts[$sid]
                    $sname = $(if ($sobj) { [string]$sobj['displayName'] } else { $sid })
                    $rows += [pscustomobject]@{ Key = "compliance:${pid0}:script"; Setting = 'Custom compliance: discovery script'; Value = $sname; Category = 'Custom compliance'; Ref = $sid }
                    $body = $(if ($sobj) { ConvertFrom-Base64Text ([string]$sobj['detectionScriptContent']) } else { $null })
                    if ($body) {
                        if ($body.Length -gt 6000) { $body = $body.Substring(0, 6000) + "`n...(truncated)" }
                        $rows += [pscustomobject]@{ Key = "compliance:${pid0}:scriptBody"; Setting = "Custom compliance: discovery script content ($sname)"; Value = $body; Category = 'Script body' }
                    }
                    $rj = ConvertFrom-Base64Text ([string](Get-Prop $scr 'rulesContent'))
                    if ($rj) { $rows += [pscustomobject]@{ Key = "compliance:${pid0}:rules"; Setting = 'Custom compliance: rules (JSON)'; Value = $rj; Category = 'Custom compliance' } }
                }
                Add-CorpusPolicy -Id $pid0 -Name ([string]$p['displayName']) -Family 'compliance' -FamilyLabel 'Compliance Policy' `
                    -Platform (Get-PolicyPlatformTag -Family 'compliance' -Raw $p) -Raw $p `
                    -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows `
                    -Extra @{ ExtraGroupRefs = @(Get-ComplianceCcGroupIds -Rules $rules) }
            }
        } catch { [void]$warnings.Add("Could not list compliance policies: $(Format-RsopError $_)") }

        # Settings Catalog based compliance (Linux, and any other platform authored this way)
        try {
            $cp2 = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/compliancePolicies' -Activity 'compliancePolicies (settings catalog)'
            $cpSettingsUrl = '/deviceManagement/compliancePolicies/{0}/settings?$expand=settingDefinitions'
            $cpActionsUrl = '/deviceManagement/compliancePolicies/{0}/scheduledActionsForRule?$expand=scheduledActionConfigurations'
            $cpList = @($cp2 | Where-Object { $_ -and $_['id'] })
            $prefetched = Get-RsopBatchedCollections -Urls @($cpList | ForEach-Object { $cpSettingsUrl -f $_['id'] }) -Activity 'Compliance policy settings' -ChunkSize 5
            $more = Get-RsopBatchedCollections -Urls @($cpList | ForEach-Object { $cpActionsUrl -f $_['id'] }) -Activity 'Actions for noncompliance'
            foreach ($k in $more.Keys) { $prefetched[$k] = $more[$k] }
            foreach ($p in $cp2) {
                $pid0 = [string]$p['id']
                $rows = @(); $st = @(); $acts = @()
                try {
                    $st = Get-RsopCollection -Prefetched $prefetched -Url ($cpSettingsUrl -f $pid0)
                    $rows = @(Convert-CatalogSettings -SettingItems $st -CategoryMap $catMap)
                } catch {
                    [void]$warnings.Add("Could not fetch settings for compliance policy '$($p['name'])': $(Format-RsopError $_)")
                    $p['@intuneLens.incomplete'] = "settings not readable: $(Format-RsopError $_)"
                }
                try {
                    $acts = Get-RsopCollection -Prefetched $prefetched -Url ($cpActionsUrl -f $pid0)
                    $rows += @(Convert-ComplianceActions -Rules $acts -PolicyId $pid0)
                } catch {
                    [void]$warnings.Add("Could not fetch the actions for noncompliance of '$($p['name'])': $(Format-RsopError $_)")
                    $p['@intuneLens.unreadable'] = @('scheduledActionsForRule')
                }
                Save-RsopBackupItem -Area 'Compliance policies' -Item $p -Name ([string]$p['name']) `
                    -Extra $(if ($script:BackupRoot) { @{ settings = (Remove-RsopKeys -Items $st -Keys @('settingDefinitions')); scheduledActionsForRule = (ConvertTo-RsopList $acts) } } else { @{} })
                Add-CorpusPolicy -Id $pid0 -Name ([string]$p['name']) -Family 'compliance' -FamilyLabel 'Compliance Policy (Settings Catalog)' `
                    -Platform (Get-PolicyPlatformTag -Family 'catalog' -Raw $p) -Raw $p `
                    -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows `
                    -Extra @{ ExtraGroupRefs = @(Get-ComplianceCcGroupIds -Rules $acts) }
            }
        } catch {
            $failure = Get-RsopReadError -ErrorRecord $_ -Uri 'beta/deviceManagement/compliancePolicies'
            if ($failure.Code -in @(403, 501)) { Add-RsopCaptureGap -Uri 'beta/deviceManagement/compliancePolicies' -Failure $failure }
            else { [void]$warnings.Add("Settings Catalog compliance policies were not captured: $(Format-RsopError $_)") }
        }
    }

    # -- 6) Windows Update profiles + platform scripts (assignment-relevant extras) --------
    $extraSources = @(
        @{ Uri = 'beta/deviceManagement/windowsFeatureUpdateProfiles'; Label = 'Windows Update - Feature'; Gate = [bool]$SkipUpdates; Platform = 'windows' },
        @{ Uri = 'beta/deviceManagement/windowsQualityUpdateProfiles'; Label = 'Windows Update - Quality (expedite)'; Gate = [bool]$SkipUpdates; Platform = 'windows' },
        @{ Uri = 'beta/deviceManagement/windowsQualityUpdatePolicies'; Label = 'Windows Update - Quality update policy (hotpatch)'; Gate = [bool]$SkipUpdates; Platform = 'windows'; Soft = $true },
        @{ Uri = 'beta/deviceManagement/windowsDriverUpdateProfiles'; Label = 'Windows Update - Drivers'; Gate = [bool]$SkipUpdates; Platform = 'windows' },
        @{ Uri = 'beta/deviceManagement/deviceManagementScripts'; Label = 'Platform Script (PowerShell)'; Gate = [bool]$SkipScripts; HasBody = $true; Platform = 'windows' },
        @{ Uri = 'beta/deviceManagement/deviceShellScripts'; Label = 'Platform Script (macOS shell)'; Gate = [bool]$SkipScripts; HasBody = $true; Platform = 'macos'; Soft = $true },
        @{ Uri = 'beta/deviceManagement/deviceCustomAttributeShellScripts'; Label = 'Custom Attribute (macOS)'; Gate = [bool]$SkipScripts; HasBody = $true; Platform = 'macos'; Soft = $true }
    )
    foreach ($src in $extraSources) {
        if ($src.Gate) { continue }
        Write-Step ("Pulling {0}" -f $src.Label)
        $items = @()
        try {
            $items = Get-RsopItemsWithAssignments -Uri $src.Uri -Activity $src.Label
        } catch {
            $hint = ''
            if ($src.HasBody -and $_.Exception.Message -match 'Forbidden') {
                $hint = ' (script endpoints need the DeviceManagementScripts.Read.All scope - re-run and consent, or -SkipScripts to silence)'
            }
            $msg = ("Could not list {0}: {1}{2}" -f $src.Label, (Format-RsopError $_), $hint)
            if ($src.Soft) { Add-RunLog -Level info -Message $msg } else { [void]$warnings.Add($msg) }
            continue
        }
        $scriptBodies = @{}; $prefetched = @{}
        $groupAssignmentsUrl = ($src.Uri -replace '^beta', '') + '/{0}/groupAssignments'
        if ($src.HasBody) {
            # script bodies (the list omits them) and the legacy groupAssignments of scripts that
            # came back unassigned, in /$batch requests instead of one round trip per script
            $listed = @($items | Where-Object { $_ -and $_['id'] })
            $scriptBodies = Invoke-RsopBatch -Urls @($listed | ForEach-Object { '{0}/{1}' -f ($src.Uri -replace '^beta', ''), $_['id'] }) -Activity ("{0} content" -f $src.Label)
            $prefetched = Get-RsopBatchedCollections -Urls @($listed | Where-Object { @($_['assignments']).Count -eq 0 } | ForEach-Object { $groupAssignmentsUrl -f $_['id'] }) -Activity ("{0} group assignments" -f $src.Label)
        }
        foreach ($p in $items) {
            $asg = $p['assignments']
            # legacy scripts may only carry groupAssignments { targetGroupId }
            if (@($asg).Count -eq 0 -and $src.HasBody) {
                try { $asg = Get-RsopCollection -Prefetched $prefetched -Url ($groupAssignmentsUrl -f $p['id']) } catch { $asg = @() }
            }
            $rows = @(Convert-LegacyProperties -Policy $p -FallbackCategory $src.Label)
            $extraBackup = @{}
            if ($src.Uri -like '*windowsDriverUpdateProfiles') {
                # with manual approval the approve / decline / suspend decisions ARE the policy
                $inv = @()
                try { $inv = @(Get-RsopPaged -Uri ("{0}/{1}/driverInventories" -f $src.Uri, $p['id'])) }
                catch { Add-RunLog -Level info -Message ("Driver inventory of '{0}' not readable: {1}" -f $p['displayName'], (Format-RsopError $_)) }
                $extraBackup['driverInventories'] = $inv
                $decided = @($inv | Where-Object { [string]$_['approvalStatus'] -and [string]$_['approvalStatus'] -ne 'needsReview' } |
                    Sort-Object { [string]$_['approvalStatus'] }, { [string]$_['name'] })
                foreach ($dv in ($decided | Select-Object -First 1000)) {
                    $dd = Format-GraphDate $dv['deployDateTime']; if ($dd.Length -ge 10) { $dd = $dd.Substring(0, 10) }
                    $rows += [pscustomobject]@{
                        Key = ("driver:{0}:{1}" -f $p['id'], $dv['id']); Setting = ("Driver: {0} {1} ({2})" -f $dv['name'], $dv['version'], $dv['manufacturer'])
                        Value = ("{0}{1}" -f $dv['approvalStatus'], $(if ($dd -and [string]$dv['approvalStatus'] -eq 'approved') { ", deploy from $dd" } else { '' })); Category = 'Driver approvals'
                    }
                }
                if ($decided.Count -gt 1000) { $rows += [pscustomobject]@{ Key = ("driver:{0}:more" -f $p['id']); Setting = 'Driver approvals'; Value = ("{0} more decisions in the backup" -f ($decided.Count - 1000)); Category = 'Driver approvals' } }
                $pending = @($inv | Where-Object { [string]$_['approvalStatus'] -eq 'needsReview' }).Count
                if ($pending) { $rows += [pscustomobject]@{ Key = ("driver:{0}:pending" -f $p['id']); Setting = 'Drivers awaiting review'; Value = [string]$pending; Category = 'Driver approvals' } }
            }
            if ($src.HasBody) {
                # every script runs on its own: its options (run as, 32-bit, ...) never compete
                # with another script's, so they must not share conflict keys
                foreach ($r in $rows) { $r.Key = ("script:{0}:{1}" -f $p['id'], $r.Key) }
                # (Get-ScriptBodyRows returns ", @(...)": iterate it - @() around it would nest)
                foreach ($br in (Get-ScriptBodyRows -BaseUri $src.Uri -Item $p -BackupArea $src.Label -Assignments $asg -Prefetched $scriptBodies)) { if ($br) { $rows += $br } }
            }
            else { Save-RsopBackupItem -Area $src.Label -Item $p -Extra $extraBackup }
            Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'extra' -FamilyLabel $src.Label `
                -Platform $src.Platform -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $asg) -Settings $rows
        }
    }

    # -- 6b) Remediations (device health scripts) -----------------------------------------
    if (-not $SkipScripts) {
        Write-Step "Pulling Remediations (deviceHealthScripts)"
        $hs = @()
        try { $hs = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/deviceHealthScripts' -Activity 'Remediations' }
        catch {
            Add-RsopReadProblem ("Remediations and group-targeted managed-installer scripts were not captured. Check DeviceManagementScripts.Read.All, user access and entitlement: {0}" -f (Format-RsopError $_))
            $hs = @()
        }
        # list responses may omit script bodies: fetch those individually (batched)
        $needBody = @($hs | Where-Object { -not $_['detectionScriptContent'] -and -not $_['isGlobalScript'] })
        $bodies = @{}
        if ($needBody.Count -gt 0) {
            $bodies = Invoke-RsopBatch -Urls @($needBody | ForEach-Object { '/deviceManagement/deviceHealthScripts/{0}' -f $_['id'] }) -Activity 'Remediation script bodies'
        }
        foreach ($p in $hs) {
            $pid0 = [string]$p['id']
            $full = $p
            $b = $bodies['/deviceManagement/deviceHealthScripts/{0}' -f $pid0]
            if ($b) { $full = $b }
            # Microsoft-published scripts too: their assignments and schedules are tenant config
            Save-RsopBackupItem -Area 'Remediations' -Item $full -Extra @{ assignments = (ConvertTo-RsopList $p['assignments']) }
            $rows = @(Convert-LegacyProperties -Policy $full -Category 'Remediation options' -Skip @('detectionScriptContent', 'remediationScriptContent', 'highestAvailableVersion'))
            foreach ($r in $rows) { $r.Key = ("remediation:{0}:{1}" -f $pid0, $r.Key) }   # per-script options never conflict
            foreach ($pair in @(@('detectionScriptContent', 'Detection script'), @('remediationScriptContent', 'Remediation script'))) {
                $txt = ConvertFrom-Base64Text ([string](Get-Prop $full $pair[0]))
                if (-not $txt) { continue }
                if ($txt.Length -gt 6000) { $txt = $txt.Substring(0, 6000) + "`n...(truncated)" }
                $rows += [pscustomobject]@{ Key = ("remediation:{0}:{1}" -f $pid0, $pair[0]); Setting = $pair[1]; Value = $txt; Category = 'Script body' }
            }
            $detail = $(if ($p['isGlobalScript']) { 'Microsoft-published' } else { '' })
            # (the full GET carries roleScopeTagIds - the list answers them empty)
            Add-CorpusPolicy -Id $pid0 -Name ([string]$p['displayName']) -Family 'remediation' -FamilyLabel 'Remediation' -Platform 'windows' `
                -Raw $full -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows -Detail $detail
        }
        if (@($hs).Count) { Write-Info ("{0} remediation script packages" -f @($hs).Count) }
    }

    # -- 7) Applications: one entry per app ------------------------------------------------
    # Assignments keep their intent (required / available / uninstall /
    # availableWithoutEnrollment); the per-device engine resolves which intent wins using
    # Intune's documented conflict rules, so an app shows up once with all three sections.
    if (-not $SkipApps) {
        # app assignments reference profiles by id (per-app VPN, DDM app config ...): name them
        $script:PolicyNameById = @{}
        foreach ($pp in $policies) { $script:PolicyNameById[[string]$pp.Id] = [string]$pp.Name }
        Write-Step "Pulling applications (mobileApps)"
        # Every app the admin center's "All apps" list shows - assigned or not (a complete
        # inventory matters for recovery). The filter is the portal's own: it hides the
        # Microsoft-published 'global' apps that exist only as App Protection targets.
        $apps = @()
        $portalFilter = "(microsoft.graph.managedApp/appAvailability eq null or microsoft.graph.managedApp/appAvailability eq 'lineOfBusiness' or isAssigned eq true)"
        $apps = $null
        # categories (Company Portal) come along with $expand=categories - no extra calls
        foreach ($q in @(('$filter=' + [uri]::EscapeDataString($portalFilter) + '&$expand=categories'), ('$filter=' + [uri]::EscapeDataString($portalFilter)), '$expand=categories', '')) {
            try {
                $apps = @(Get-RsopPaged -Uri ('beta/deviceAppManagement/mobileApps' + $(if ($q) { "?$q" } else { '' })) -Activity 'mobileApps')
                if ($q -notlike '*filter*') {
                    $apps = @($apps | Where-Object { $_['isAssigned'] -eq $true -or -not $_.ContainsKey('appAvailability') -or $_['appAvailability'] -in @($null, 'lineOfBusiness') })
                }
                break
            } catch { $apps = $null }
        }
        if ($null -eq $apps) {
            [void]$warnings.Add("Could not list applications (missing DeviceManagementApps.Read.All? -SkipApps to silence)")
            $apps = @()
        }
        # The app LIST answers roleScopeTagIds empty; a GET by id carries the real tags. Read them
        # (batched, $select'ed) unless the tenant has only the Default tag.
        # (if the tag list was not readable, assume custom tags exist and read them per app)
        $customTags = (-not $scopeTagsRead) -or ($scopeTagMap.Count -gt 1)
        if ($customTags -and $apps.Count) {
            $tagged = Invoke-RsopBatch -Urls @($apps | ForEach-Object { '/deviceAppManagement/mobileApps/{0}?$select=id,roleScopeTagIds' -f $_['id'] }) -Activity 'App scope tags'
            foreach ($app in $apps) {
                $b = $tagged['/deviceAppManagement/mobileApps/{0}?$select=id,roleScopeTagIds' -f $app['id']]
                if ($b -is [System.Collections.IDictionary] -and $b.Contains('roleScopeTagIds')) { $app['roleScopeTagIds'] = @($b['roleScopeTagIds']) }
            }
        }
        elseif (-not $customTags) {
            foreach ($app in $apps) { if (-not @($app['roleScopeTagIds'] | Where-Object { $_ }).Count) { $app['roleScopeTagIds'] = @('0') } }
        }
        # Win32 apps installed by a PowerShell script (instead of a command line): the script
        # bodies live under the app's committed content version
        $scriptRefs = @()
        foreach ($app in $apps) {
            foreach ($sk in @('activeInstallScript', 'activeUninstallScript')) {
                $tid = [string](Get-Prop (Get-Prop $app $sk) 'targetId')
                if ($tid -and $app['committedContentVersion']) { $scriptRefs += ('/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions/{1}/scripts/{2}' -f $app['id'], $app['committedContentVersion'], $tid) }
            }
        }
        $appScripts = $(if ($scriptRefs.Count) { Invoke-RsopBatch -Urls $scriptRefs -Activity 'App install scripts' } else { @{} })
        foreach ($app in $apps) {
            foreach ($sk in @('activeInstallScript', 'activeUninstallScript')) {
                $tid = [string](Get-Prop (Get-Prop $app $sk) 'targetId')
                if (-not $tid) { continue }
                $body = $appScripts['/deviceAppManagement/mobileApps/{0}/microsoft.graph.win32LobApp/contentVersions/{1}/scripts/{2}' -f $app['id'], $app['committedContentVersion'], $tid]
                # stashed on the raw app so Get-AppInfoRows and the backup both see it
                if ($body -is [System.Collections.IDictionary]) { $app[('_' + $sk + 'Body')] = $body }
            }
        }
        # Listing apps with $expand=assignments is deprecated: fetch each assigned app's
        # assignments (batched, 20 per request).
        $asgUrls = @($apps | Where-Object { $_['isAssigned'] -ne $false } | ForEach-Object { '/deviceAppManagement/mobileApps/{0}/assignments' -f $_['id'] })
        $asgMap = @{}
        if ($asgUrls.Count) { $asgMap = Invoke-RsopBatch -Urls $asgUrls -Activity 'Application assignments' }
        $asgRead = [System.Collections.Generic.HashSet[string]]::new([string[]]$asgUrls, [System.StringComparer]::OrdinalIgnoreCase)

        # Supersedence / dependency graph: one tenant-wide call, per-app fallback.
        $relRows = @()
        try { $relRows = @(Get-RsopPaged -Uri 'beta/deviceAppManagement/mobileAppRelationships' -Activity 'mobileAppRelationships') }
        catch {
            $withRel = @($apps | Where-Object { [int]$_['dependentAppCount'] -gt 0 -or [int]$_['supersedingAppCount'] -gt 0 -or [int]$_['supersededAppCount'] -gt 0 })
            if ($withRel.Count) {
                $rb = Invoke-RsopBatch -Urls @($withRel | ForEach-Object { '/deviceAppManagement/mobileApps/{0}/relationships' -f $_['id'] }) -Activity 'App relationships'
                foreach ($a in $withRel) {
                    $b = $rb['/deviceAppManagement/mobileApps/{0}/relationships' -f $a['id']]
                    if ($b -isnot [System.Collections.IDictionary]) { continue }
                    foreach ($r in @($b['value'])) { if ($r -and -not $r['sourceId']) { $r['sourceId'] = [string]$a['id'] }; if ($r) { $relRows += $r } }
                }
            }
        }
        $relsByApp = @{}
        $relSeen = New-Object 'System.Collections.Generic.HashSet[string]'
        $addRel = {
            param([string]$Owner, [string]$Relation, [string]$Type, [string]$TargetId, [string]$TargetName, [string]$TargetVersion)
            if (-not $Owner -or -not $TargetId) { return }
            if (-not $relSeen.Add(("{0}|{1}|{2}" -f $Owner, $Relation, $TargetId))) { return }
            if (-not $relsByApp.ContainsKey($Owner)) { $relsByApp[$Owner] = [System.Collections.Generic.List[object]]::new() }
            $note = ''
            if ($Relation -eq 'Supersedes' -and $Type -eq 'replace') { $note = 'uninstalls the superseded app before installing this one (even if it is not assigned)' }
            elseif ($Relation -eq 'Superseded by' -and $Type -eq 'replace') { $note = 'installing the superseding app uninstalls this one' }
            elseif ($Relation -eq 'Depends on' -and $Type -eq 'autoInstall') { $note = 'installed automatically first, even if not assigned' }
            [void]$relsByApp[$Owner].Add([pscustomobject]@{ Relation = $Relation; Type = $Type; TargetId = $TargetId; TargetName = $TargetName; TargetVersion = $TargetVersion; Note = $note })
        }
        foreach ($r in $relRows) {
            $src = [string]$r['sourceId']
            $tgt = [string]$r['targetId']
            if (-not $src) {
                $parts = ([string]$r['id']) -split '_'
                if ($parts.Count -eq 2) { $src = $(if ($parts[1] -eq $tgt) { $parts[0] } else { $parts[1] }) }
            }
            $isSup = ([string]$r['@odata.type']) -match 'Supersedence'
            $kind = $(if ($isSup) { [string]$r['supersedenceType'] } else { [string]$r['dependencyType'] })
            $tt = [string]$r['targetType']
            $fwd = $null; $inv = $null
            if ($isSup) { if ($tt -eq 'child') { $fwd = 'Supersedes'; $inv = 'Superseded by' } else { $fwd = 'Superseded by'; $inv = 'Supersedes' } }
            else { if ($tt -eq 'child') { $fwd = 'Depends on'; $inv = 'Required by' } else { $fwd = 'Required by'; $inv = 'Depends on' } }
            & $addRel $src $fwd $kind $tgt ([string]$r['targetDisplayName']) ([string]$r['targetDisplayVersion'])
            if ($r['sourceDisplayName']) {
                & $addRel $tgt $inv $kind $src ([string]$r['sourceDisplayName']) ([string]$r['sourceDisplayVersion'])
            }
        }

        $typeLabels = @{
            win32LobApp                  = 'Win32 app'
            win32CatalogApp              = 'Enterprise App Catalog (Win32)'
            winGetApp                    = 'Microsoft Store app (winget)'
            officeSuiteApp               = 'Microsoft 365 Apps suite'
            windowsMobileMSI             = 'MSI line-of-business'
            windowsUniversalAppX         = 'AppX / MSIX line-of-business'
            windowsAppX                  = 'AppX / MSIX line-of-business'
            microsoftStoreForBusinessApp = 'Store for Business (legacy)'
            windowsMicrosoftEdgeApp      = 'Microsoft Edge'
            windowsWebApp                = 'Web link (Windows)'
            webApp                       = 'Web link'
            iosStoreApp                  = 'iOS store app'
            iosVppApp                    = 'iOS volume-purchased app'
            iosLobApp                    = 'iOS line-of-business'
            managedIOSStoreApp           = 'iOS store app (managed)'
            macOSLobApp                  = 'macOS line-of-business'
            macOSDmgApp                  = 'macOS DMG app'
            macOSPkgApp                  = 'macOS PKG app'
            macOsVppApp                  = 'macOS volume-purchased app'
            macOSMicrosoftEdgeApp        = 'Microsoft Edge (macOS)'
            macOSOfficeSuiteApp          = 'Microsoft 365 Apps (macOS)'
            macOSMicrosoftDefenderApp    = 'Microsoft Defender (macOS)'
            androidManagedStoreApp       = 'Managed Google Play app'
            androidStoreApp              = 'Android store app'
            androidLobApp                = 'Android line-of-business'
            managedAndroidStoreApp       = 'Android store app (managed)'
        }
        $nApps = 0
        foreach ($app in $apps) {
            $nApps++
            $appId = [string](Get-Prop $app 'id')
            if (-not $appId) { continue }
            $appName = [string](Get-Prop $app 'displayName')
            Write-RsopProgress -Id 3 -Activity 'Indexing applications' -Status ("{0}/{1}  {2}" -f $nApps, $apps.Count, $appName) -Percent ([int](100 * $nApps / [math]::Max(1, $apps.Count)))
            $aType = ([string](Get-Prop $app '@odata.type')) -replace '#microsoft.graph.', ''
            $friendly = $typeLabels[$aType]
            if (-not $friendly) { $friendly = ConvertTo-FriendlyName $aType }
            $platform = 'other'
            if ($aType -match '^macO[Ss]') { $platform = 'macos' }
            elseif ($aType -match '^(ios|managedIOS)') { $platform = 'ios' }
            elseif ($aType -match '^(android|managedAndroid)') { $platform = 'android' }
            elseif ($aType -match '^(win32|windows|winGet|officeSuite|microsoftStore)') { $platform = 'windows' }

            $appNameById[$appId] = $appName
            foreach ($ik in @('bundleId', 'packageId', 'packageIdentifier', 'identityName', 'appIdentifier')) {
                $iv = [string](Get-Prop $app $ik)
                if ($iv) { $appIdByIdentifier["${platform}|$($iv.ToLower())"] = $appId }
            }

            $asgUrl = '/deviceAppManagement/mobileApps/{0}/assignments' -f $appId
            $asgBody = $asgMap[$asgUrl]
            $asgRaw = $(if ($asgBody) { @($asgBody['value']) } else { @(Get-PropList $app 'assignments') })
            $asgUnreadable = $asgRead.Contains($asgUrl) -and ($asgBody -isnot [System.Collections.IDictionary])
            if ($asgUnreadable) {
                $app['@intuneLens.unreadable'] = @('assignments')
                Add-RsopReadProblem ("Could not read the assignments of app '{0}' - shown as Unknown." -f $appName)
            }
            $rels = @($(if ($relsByApp.ContainsKey($appId)) { $relsByApp[$appId].ToArray() } else { @() }))
            Save-RsopBackupItem -Area 'Apps' -Item $app -Extra @{ assignments = (ConvertTo-RsopList $asgRaw) }
            $meta = Get-PolicyMeta -Raw $app
            [void]$appObjs.Add([pscustomobject]@{
                Id            = $appId
                Name          = $appName
                Type          = $friendly
                OdataType     = $aType
                Platform      = $platform
                Publisher     = [string](Get-Prop $app 'publisher')
                Version       = [string](Get-Prop $app 'displayVersion')
                Desc          = $meta.Desc
                Modified      = $meta.Modified
                Created       = $meta.Created
                ScopeTags     = @(Get-PropList $app 'roleScopeTagIds' | ForEach-Object { [string]$_ })
                Info          = @(Get-AppInfoRows -App $app)
                Relationships = $rels
                Assignments   = @(ConvertTo-CompactAssignments -Assignments $asgRaw)
                AssignmentsUnreadable = $asgUnreadable
            })
        }
        Complete-RsopProgress -Id 3
        if ($relRows.Count) { Save-RsopBackupItem -Area 'Apps' -Name 'App relationships (supersedence and dependencies)' -Item @{ id = 'mobileAppRelationships'; value = $relRows } }
        $nAssignedApps = @($appObjs | Where-Object { @($_.Assignments).Count -gt 0 }).Count
        Write-Info ("{0} apps indexed, {1} assigned ({2} supersedence / dependency links)" -f $appObjs.Count, $nAssignedApps, $relSeen.Count)
    }

    # -- 8) App Configuration policies --------------------------------------------------------
    if (-not $SkipAppPolicies) {
        Write-Step "Pulling App Configuration policies (managed devices)"
        try {
            $acfg = Get-RsopItemsWithAssignments -Uri 'beta/deviceAppManagement/mobileAppConfigurations' -Activity 'mobileAppConfigurations'
            foreach ($p in $acfg) {
                $t = ([string]$p['@odata.type']).ToLower()
                $plat = $(if ($t -match 'ios') { 'ios' } elseif ($t -match 'android') { 'android' } elseif ($t -match 'macos') { 'macos' } else { 'other' })
                $targets = @(Resolve-TargetApps -AppIds @(Get-PropList $p 'targetedMobileApps'))
                $rows = @(Convert-AppConfigDeviceSettings -Policy $p)
                $scopeIds = @(Get-PropList $p 'targetedMobileApps')
                Set-AppSettingConflictKeys -Rows $rows -Scopes $scopeIds -Prefix 'appcfg' -PolicyId ([string]$p['id']) -CombinedScope (($scopeIds | Sort-Object) -join ',')
                Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'appconfig' -FamilyLabel 'App Configuration (managed devices)' `
                    -Platform $plat -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows `
                    -Detail (($targets | ForEach-Object { $_.Name }) -join ', ') -Extra @{ TargetApps = @($targets) } -BackupArea 'App configuration (managed devices)'
            }
        } catch { [void]$warnings.Add("Could not list App Configuration policies (managed devices): $(Format-RsopError $_)") }

        Write-Step "Pulling App Configuration policies (managed apps)"
        try {
            $mcfg = Get-RsopItemsWithAssignments -Uri 'beta/deviceAppManagement/targetedManagedAppConfigurations' -Navigations @('apps', 'assignments') -Activity 'targetedManagedAppConfigurations'
            $mcfgSettingsUrl = '/deviceAppManagement/targetedManagedAppConfigurations/{0}/settings?$expand=settingDefinitions'
            $prefetched = Get-RsopBatchedCollections -Urls @($mcfg | Where-Object { $_ -and $_['id'] } | ForEach-Object { $mcfgSettingsUrl -f $_['id'] }) -Activity 'Managed-app configuration settings' -ChunkSize 5
            foreach ($p in $mcfg) {
                $pid0 = [string]$p['id']
                $mapps = @(Get-PropList $p 'apps')
                $idents = @($mapps | ForEach-Object { Get-AppIdentifierText $_ } | Where-Object { $_ })
                $plats = @($mapps | ForEach-Object { Get-AppIdentifierPlatform $_ } | Select-Object -Unique)
                $plat = $(if ($plats.Count -eq 1) { [string]$plats[0] } else { 'other' })
                $agt = [string]$p['appGroupType']
                $appKey = (($idents | Sort-Object) -join ',')
                if (-not $appKey) { $appKey = $agt }
                $rows = [System.Collections.Generic.List[object]]::new()
                foreach ($cs in (Get-PropList $p 'customSettings')) {
                    $nm = [string](Get-Prop $cs 'name')
                    if (-not $nm) { continue }
                    [void]$rows.Add([pscustomobject]@{ Key = "mamcfg:${appKey}:$nm"; Setting = $nm; Value = (Protect-RsopSecretValue $nm (Get-Prop $cs 'value')); Category = 'Configuration key' })
                }
                # newer MAM app config (e.g. Edge / Outlook settings) lives in a settings-catalog collection
                $st = @()
                try {
                    $st = Get-RsopCollection -Prefetched $prefetched -Url ($mcfgSettingsUrl -f $pid0)
                    foreach ($r in (Convert-CatalogSettings -SettingItems $st -CategoryMap $catMap)) { [void]$rows.Add($r) }
                } catch {
                    [void]$warnings.Add("Could not fetch settings for managed-app configuration '$($p['displayName'])': $(Format-RsopError $_)")
                    $p['@intuneLens.unreadable'] = @(@($p['@intuneLens.unreadable']) + @('settings') | Where-Object { $_ } | Select-Object -Unique)
                }
                if ($agt) { [void]$rows.Add([pscustomobject]@{ Key = "mamcfg:${pid0}:appGroupType"; Setting = 'Targeted apps'; Value = (ConvertTo-FriendlyName $agt); Category = 'Policy options' }) }
                $lvl = [string]$p['targetedAppManagementLevels']
                if ($lvl) { [void]$rows.Add([pscustomobject]@{ Key = "mamcfg:${pid0}:levels"; Setting = 'Device management types'; Value = $lvl; Category = 'Policy options' }) }
                $targets = @(Resolve-TargetApps -ManagedApps $mapps)
                Set-AppSettingConflictKeys -Rows $rows.ToArray() -Scopes $idents -Prefix 'mamcfg' -PolicyId $pid0 -CombinedScope $appKey
                Add-CorpusPolicy -Id $pid0 -Name ([string]$p['displayName']) -Family 'appconfig-mam' -FamilyLabel 'App Configuration (managed apps)' `
                    -Platform $plat -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows.ToArray() `
                    -Detail $(if ($idents.Count) { ($targets | ForEach-Object { $_.Name }) -join ', ' } else { ConvertTo-FriendlyName $agt }) `
                    -Extra @{ TargetApps = @($targets); ManagementLevels = $lvl } `
                    -BackupArea 'App configuration (managed apps)' -BackupExtra $(if ($script:BackupRoot) { @{ settings = (Remove-RsopKeys -Items $st -Keys @('settingDefinitions')) } } else { @{} })
            }
        } catch { [void]$warnings.Add("Could not list App Configuration policies (managed apps): $(Format-RsopError $_)") }

        # -- 9) App Protection policies (MAM) -------------------------------------------------
        Write-Step "Pulling App Protection policies"
        $mamSources = @(
            @{ Uri = 'beta/deviceAppManagement/iosManagedAppProtections'; Label = 'App Protection - iOS/iPadOS'; Platform = 'ios'; Apps = $true },
            @{ Uri = 'beta/deviceAppManagement/androidManagedAppProtections'; Label = 'App Protection - Android'; Platform = 'android'; Apps = $true },
            @{ Uri = 'beta/deviceAppManagement/windowsManagedAppProtections'; Label = 'App Protection - Windows (Edge)'; Platform = 'windows'; Apps = $true; UnmanagedOnly = $true },
            @{ Uri = 'beta/deviceAppManagement/mdmWindowsInformationProtectionPolicies'; Label = 'Windows Information Protection (legacy)'; Platform = 'windows'; Apps = $false },
            @{ Uri = 'beta/deviceAppManagement/windowsInformationProtectionPolicies'; Label = 'Windows Information Protection without enrollment (legacy)'; Platform = 'windows'; Apps = $false; UnmanagedOnly = $true }
        )
        foreach ($src in $mamSources) {
            $navs = $(if ($src.Apps) { @('apps', 'assignments') } else { @('assignments') })
            $items = @()
            try { $items = Get-RsopItemsWithAssignments -Uri $src.Uri -Navigations $navs -Activity $src.Label }
            catch { Add-RunLog -Level info -Message ("Could not list {0}: {1}" -f $src.Label, (Format-RsopError $_)); continue }
            foreach ($p in $items) {
                $mapps = @(Get-PropList $p 'apps')
                $idents = @($mapps | ForEach-Object { Get-AppIdentifierText $_ } | Where-Object { $_ })
                $rows = @(Convert-LegacyProperties -Policy $p -Category 'Protection settings' -Skip @('targetedAppManagementLevels', 'appGroupType'))
                $agt = [string]$p['appGroupType']
                if ($agt) { $rows += [pscustomobject]@{ Key = "mam:appGroupType"; Setting = 'Targeted apps'; Value = (ConvertTo-FriendlyName $agt); Category = 'Policy options' } }
                $lvl = [string]$p['targetedAppManagementLevels']
                if ($lvl) { $rows += [pscustomobject]@{ Key = "mam:levels"; Setting = 'Device management types'; Value = $lvl; Category = 'Policy options' } }
                $appKey = (($idents | Sort-Object) -join ',')
                if (-not $appKey) { $appKey = $agt }
                # MAM settings only conflict when the same app is protected twice: scope keys by app set
                foreach ($r in $rows) { $r.Key = ("mam:{0}:{1}" -f $appKey, $r.Key) }
                $targets = @(Resolve-TargetApps -ManagedApps $mapps)
                if ($targets.Count) { $rows += [pscustomobject]@{ Key = "mam:apps"; Setting = 'Protected apps'; Value = (($targets | ForEach-Object { $_.Name }) -join ', '); Category = 'Policy options' } }
                Set-AppSettingConflictKeys -Rows $rows -Scopes $idents -Prefix 'mam' -PolicyId ([string]$p['id']) -CombinedScope $appKey
                Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'mam' -FamilyLabel $src.Label -Platform $src.Platform `
                    -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows `
                    -Detail $(if ($agt) { ConvertTo-FriendlyName $agt } else { '' }) `
                    -Extra @{ TargetApps = @($targets); ManagementLevels = $lvl; UnmanagedOnly = [bool]$src.UnmanagedOnly } -BackupArea $src.Label
            }
        }
    }

    # -- 10) Enrollment configurations + Autopilot profiles -----------------------------------
    if (-not $SkipEnrollment) {
        Write-Step "Pulling enrollment configurations (ESP, Windows Hello, restrictions, limits)"
        try {
            $ecs = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/deviceEnrollmentConfigurations' -Activity 'deviceEnrollmentConfigurations'
            foreach ($p in $ecs) {
                $pid0 = [string]$p['id']
                $ot = ([string]$p['@odata.type']) -replace '#microsoft.graph.', ''
                $et = [string]$p['deviceEnrollmentConfigurationType']
                $isDefault = ($et -like 'default*') -or ($pid0 -match '_Default') -or ($ot -eq 'windowsRestoreDeviceEnrollmentConfiguration')
                $label = 'Enrollment - other'; $class = 'other'; $plat = 'other'; $kinds = 'both'
                switch -Wildcard ($ot) {
                    'windows10EnrollmentCompletionPageConfiguration' { $label = 'Enrollment Status Page'; $class = 'esp'; $plat = 'windows' }
                    'deviceEnrollmentWindowsHelloForBusinessConfiguration' { $label = 'Windows Hello for Business (enrollment)'; $class = 'whfb'; $plat = 'windows' }
                    'deviceEnrollmentPlatformRestrictionConfiguration' {
                        $pt = [string]$p['platformType']
                        $label = 'Enrollment restriction (platform)'; $kinds = 'user'
                        $plat = $(switch -Wildcard ($pt) { 'windows*' { 'windows' } 'ios' { 'ios' } 'mac' { 'macos' } 'android*' { 'android' } 'linux' { 'linux' } default { 'other' } })
                        # Android device administrator and Android Enterprise use
                        # independent restriction profiles and priority lists.
                        $class = $(if ($pt -ieq 'androidForWork') { 'restriction:androidForWork' } else { "restriction:$plat" })
                    }
                    'deviceEnrollmentPlatformRestrictionsConfiguration' { $label = 'Enrollment restriction (platform)'; $class = 'restriction:*'; $kinds = 'user' }
                    'deviceEnrollmentLimitConfiguration' { $label = 'Enrollment restriction (device limit)'; $class = 'limit'; $kinds = 'user' }
                    'deviceComanagementAuthorityConfiguration' { $label = 'Co-management authority'; $class = 'comanagement'; $plat = 'windows' }
                    'deviceEnrollmentNotificationConfiguration' { $label = 'Enrollment notifications'; $class = "notification:$pid0" }
                    'windowsRestoreDeviceEnrollmentConfiguration' { $label = 'Windows restore (enrollment)'; $class = 'restore'; $plat = 'windows' }
                }
                $rows = @(Convert-LegacyProperties -Policy $p -Category $label -Skip @('priority', 'deviceEnrollmentConfigurationType', 'selectedMobileAppIds'))
                if ($ot -eq 'windows10EnrollmentCompletionPageConfiguration') {
                    $sel = @(Get-PropList $p 'selectedMobileAppIds')
                    $names = @(Resolve-TargetApps -AppIds $sel | ForEach-Object { $_.Name })
                    $rows += [pscustomobject]@{ Key = "esp:blockingApps"; Setting = 'Blocking apps (selected)'; Value = $(if ($names.Count) { $names -join '; ' } else { '(none selected)' }); Category = $label }
                }
                $asg = @(ConvertTo-CompactAssignments -Assignments $p['assignments'])
                if ($isDefault) {
                    # default configurations apply to everyone unless a higher-priority one wins
                    $asg = @(
                        [pscustomobject]@{ Type = 'allDevicesAssignmentTarget'; GroupId = ''; FilterId = ''; FilterType = ''; Intent = ''; Options = 'default configuration' },
                        [pscustomobject]@{ Type = 'allLicensedUsersAssignmentTarget'; GroupId = ''; FilterId = ''; FilterType = ''; Intent = ''; Options = 'default configuration' }
                    )
                }
                $prio = $(if ($isDefault) { 'Default' } else { [string]$p['priority'] })
                Add-CorpusPolicy -Id $pid0 -Name ([string]$p['displayName']) -Family 'enrollment' -FamilyLabel $label -Platform $plat -Raw $p `
                    -Assignments $asg -Settings $rows -Detail $(if ($isDefault) { 'Default (applies when nothing else does)' } else { "Priority $prio" }) `
                    -Extra @{ Priority = $prio; PriorityClass = $class; IsDefault = [bool]$isDefault; TargetKinds = $kinds } -BackupArea 'Enrollment configurations'
            }
        } catch { [void]$warnings.Add("Could not list enrollment configurations (needs DeviceManagementServiceConfig.Read.All; -SkipEnrollment to silence): $(Format-RsopError $_)") }

        Write-Step "Pulling Windows Autopilot deployment profiles"
        try {
            $aps = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/windowsAutopilotDeploymentProfiles' -Activity 'Autopilot profiles'
            foreach ($p in $aps) {
                # prefer the current property names over their deprecated twins
                $skip = @('language', 'extractHardwareHash', 'enableWhiteGlove', 'managementServiceAppId', 'assignedDevices')
                if ($p['outOfBoxExperienceSetting']) { $skip += 'outOfBoxExperienceSettings' }
                $rows = @(Convert-LegacyProperties -Policy $p -Category 'Autopilot profile' -Skip $skip)
                $mode = $(if (([string]$p['@odata.type']) -match 'activeDirectory') { 'Hybrid Entra join' } else { 'Entra join' })
                Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['displayName']) -Family 'autopilot' -FamilyLabel 'Autopilot deployment profile' -Platform 'windows' `
                    -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows -Detail $mode `
                    -Extra @{ PriorityClass = 'autopilot'; TargetKinds = 'device' } -BackupArea 'Autopilot deployment profiles'
            }
        } catch { [void]$warnings.Add("Could not list Autopilot deployment profiles: $(Format-RsopError $_)") }
    }

    # -- 11) BIOS configurations, App Control supplemental policies, Properties catalog -------
    # Device-targeted objects outside the main configuration collections. Their payload is a
    # file (BIOS settings package / policy XML), decoded when it is text.
    $fileSources = @(
        @{ Uri = 'beta/deviceManagement/hardwareConfigurations'; Label = 'BIOS configuration'; Family = 'hardware'; Content = 'configurationFileContent'; Backup = 'BIOS configurations' },
        @{ Uri = 'beta/deviceAppManagement/wdacSupplementalPolicies'; Label = 'App Control supplemental policy (legacy)'; Family = 'wdac'; Content = 'content'; Backup = 'App Control supplemental policies' }
    )
    foreach ($src in $fileSources) {
        $items = @()
        try { $items = Get-RsopItemsWithAssignments -Uri $src.Uri -Activity $src.Label }
        catch { Add-RunLog -Level info -Message ("Could not list {0}: {1}" -f $src.Label, (Format-RsopError $_)); continue }
        if (@($items).Count -eq 0) { continue }
        Write-Step ("Pulling {0} ({1})" -f $src.Label, @($items).Count)
        $base = $src.Uri -replace '^beta', ''
        $needBody = @($items | Where-Object { -not $_[$src.Content] })
        $bodies = $(if ($needBody.Count) { Invoke-RsopBatch -Urls @($needBody | ForEach-Object { '{0}/{1}' -f $base, $_['id'] }) -Activity $src.Label } else { @{} })
        foreach ($p in $items) {
            $full = $p
            $b = $bodies['{0}/{1}' -f $base, $p['id']]
            if ($b) { $full = $b; $full['assignments'] = $p['assignments'] }
            $rows = @(Convert-LegacyProperties -Policy $full -Category $src.Label -Skip @($src.Content))
            $b64 = [string]$full[$src.Content]
            if ($b64) {
                $txt = ConvertFrom-Base64Text $b64
                $val = $(if ($src.Family -eq 'hardware') { "(file{0}, {1:N0} bytes - in the backup)" -f $(if ($full['fileName']) { ' ' + $full['fileName'] } else { '' }), ([math]::Floor($b64.Length * 3 / 4)) }
                         elseif ($txt -and -not $txt.Contains([char]0)) { $(if ($txt.Length -gt 6000) { $txt.Substring(0, 6000) + "`n...(truncated)" } else { $txt }) }
                         else { "(binary file, {0:N0} bytes - in the backup)" -f ([math]::Floor($b64.Length * 3 / 4)) })
                $rows += [pscustomobject]@{ Key = ("{0}:{1}:file" -f $src.Family, $p['id']); Setting = 'File content'; Value = $val; Category = 'File' }
            }
            Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$full['displayName']) -Family $src.Family -FamilyLabel $src.Label -Platform 'windows' `
                -Raw $full -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows -BackupArea $src.Backup
        }
    }
    # Properties catalog (device inventory collection) - settings-catalog shaped
    try {
        $inv = Get-RsopItemsWithAssignments -Uri 'beta/deviceManagement/inventoryPolicies' -Activity 'Properties catalog'
        $invSettingsUrl = '/deviceManagement/inventoryPolicies/{0}/settings?$expand=settingDefinitions'
        $prefetched = Get-RsopBatchedCollections -Urls @($inv | Where-Object { $_ -and $_['id'] } | ForEach-Object { $invSettingsUrl -f $_['id'] }) -Activity 'Properties catalog settings' -ChunkSize 5
        if (@($inv).Count) { Write-Step ("Pulling Properties catalog policies ({0})" -f $inv.Count) }
        foreach ($p in $inv) {
            $st = @(); $rows = @()
            try {
                $st = Get-RsopCollection -Prefetched $prefetched -Url ($invSettingsUrl -f $p['id'])
                $rows = @(Convert-CatalogSettings -SettingItems $st -CategoryMap $catMap)
            } catch {
                [void]$warnings.Add("Could not fetch settings for Properties catalog policy '$($p['name'])': $(Format-RsopError $_)")
                $p['@intuneLens.incomplete'] = "settings not readable: $(Format-RsopError $_)"
            }
            Add-CorpusPolicy -Id ([string]$p['id']) -Name ([string]$p['name']) -Family 'catalog' -FamilyLabel 'Properties catalog (inventory)' `
                -Platform (Get-PolicyPlatformTag -Family 'catalog' -Raw $p) -Raw $p -Assignments (ConvertTo-CompactAssignments -Assignments $p['assignments']) -Settings $rows `
                -BackupArea 'Properties catalog' -BackupExtra $(if ($script:BackupRoot) { @{ settings = (Remove-RsopKeys -Items $st -Keys @('settingDefinitions')) } } else { @{} })
        }
    } catch {
        # a tenant without Properties catalog (feature not enabled / not licensed) answers 403, 400
        # or a bare 'An error has occurred': any service answer is a capture gap, not a warning
        $failure = Get-RsopReadError -ErrorRecord $_ -Uri 'beta/deviceManagement/inventoryPolicies'
        if ($failure.Code -ge 400) { Add-RsopCaptureGap -Uri 'beta/deviceManagement/inventoryPolicies' -Failure $failure }
        else { [void]$warnings.Add("Properties catalog was not captured: $(Format-RsopError $_)") }
    }

    # -- assignment filters ----------------------------------------------------------------
    Write-Step "Pulling assignment filters"
    $filters = @()
    try {
        foreach ($f in (Get-RsopPaged -Uri 'beta/deviceManagement/assignmentFilters')) {
            Save-RsopBackupItem -Area 'Assignment filters' -Item $f
            $filters += [pscustomobject]@{
                Id       = [string]$f['id']
                Name     = [string]$f['displayName']
                Platform = [string]$f['platform']
                Rule     = [string]$f['rule']
                Desc     = [string]$f['description']
                ManagementType = [string]$f['assignmentFilterManagementType']
                ScopeTags = @(Get-PropList $f 'roleScopeTags' | ForEach-Object { [string]$_ })
                Modified = (Format-GraphDate $f['lastModifiedDateTime'])
            }
        }
    } catch { [void]$warnings.Add("Could not list assignment filters: $(Format-RsopError $_)") }
    # failed / partial sub-reads (assignments, member pages ...) travel with the corpus
    foreach ($rp in $script:ReadProblems) { if (-not $warnings.Contains($rp)) { [void]$warnings.Add($rp) } }

    $corpus = [pscustomobject]@{
        cacheVersion = 19
        cacheOptions = $cacheOptions
        generated    = (Get-Date).ToString('o')
        tenant       = $TenantKey
        policies     = $policies.ToArray()
        apps         = $appObjs.ToArray()
        filters      = $filters
        warnings     = $warnings.ToArray()
        scopeTags    = [pscustomobject]$scopeTagMap
        tenantConfig = $null   # filled on demand by Get-TenantConfiguration (-All / -BackupPath)
        captureGaps  = $script:CaptureGaps.ToArray()   # areas the tenant does not serve
    }
    Save-CorpusCache -Corpus $corpus

    $assignedCount = @($corpus.policies | Where-Object { @($_.Assignments).Count -gt 0 }).Count
    Write-Good ("Loaded {0} policies ({1} with assignments), {2} apps, {3} assignment filters" -f @($corpus.policies).Count, $assignedCount, @($corpus.apps).Count, @($corpus.filters).Count)
    # (read problems were printed as they happened)
    foreach ($w in $corpus.warnings) { if ($script:ReadProblems -notcontains $w) { Write-Warn2 $w } }
    return $corpus
}

#endregion

#region ---------- tenant setup (recovery view) ---------------------------------------------

# 'Intune Provisioning Client' (some tenants: 'Intune Autopilot ConfidentialClient'): owner of
# every enrollment-time group (Autopilot device preparation, enrollment time grouping).
$script:ProvisioningClientAppId = 'f1346770-5b25-470b-88bd-d5744ab7952c'

# Mobile Threat Defense connector ids are per-vendor constants; Graph carries no display name.
$script:MtdPartnerNames = @{
    'fc780465-2017-40d4-a0c5-307022471b92' = 'Microsoft Defender for Endpoint'
}
$script:ScopeTagNames = @{}

function Get-RsopReadError {
    # A failed tenant-setup read: Graph's service message, error code and request id (see
    # Get-RsopServiceError) plus endpoint-specific advice.
    param($ErrorRecord, [string]$Uri)
    if ($ErrorRecord.FullyQualifiedErrorId -like 'IntuneLens.IncompleteRead*') {
        return [pscustomobject]@{ Code = 0; Message = $ErrorRecord.Exception.Message; ErrorCode = 'IncompleteRead'; RequestId = ''; Advice = 'Retry with -Refresh.'; EndpointAdvice = $false; Diagnostic = $ErrorRecord.Exception.Message }
    }
    $serviceError = Get-RsopServiceError -ErrorRecord $ErrorRecord
    $code = $serviceError.Code
    $msg = $serviceError.Message
    $errorCode = $serviceError.ErrorCode
    $requestId = $serviceError.RequestId
    $advice = switch -Regex ($Uri) {   # endpoint-specific advice first, then advice by status
        '/windowsManagementApp(?:\?|$)' {
            if ($code -ge 500) { 'Graph could not return the tenant-wide managed-installer state. Check Endpoint security > App Control for Business > Managed installer in Intune and retry with -Refresh; retain the request id for Microsoft support if it persists. Current managed-installer policies can be group-targeted; this legacy singleton alone does not establish their state.' }
            elseif ($code -eq 403) { 'Check consent for DeviceManagementApps.Read.All and the signed-in user''s Intune read permissions.' }
            break
        }
        '/remoteAssistanceSettings(?:\?|$)' {
            if ($code -eq 403) { 'Check Remote Assistance Connector - Read in Intune RBAC, Remote Help entitlement and consent for DeviceManagementConfiguration.Read.All or DeviceManagementServiceConfig.Read.All. Access denied does not establish whether Remote Help is configured.' }
            break
        }
        '/virtualEndpoint/' {
            if ($code -eq 403) { 'Check consent for CloudPC.Read.All, Cloud PC Reader or equivalent Provisioning Policies - Read access, scope tags and Windows 365 licensing. Access denied does not establish whether Cloud PCs are configured.' }
            break
        }
    }
    $endpointAdvice = [bool]$advice
    if (-not $advice) {
        $advice = switch ($code) {
            403 { 'Access denied: check the endpoint''s consented read scope, user role and feature entitlement. Configuration was not captured.' }
            501 { 'The service did not implement this request. Capture any required configuration separately.' }
            { $_ -in @(429, 500, 502, 503, 504) } { 'The service could not complete the read. Retry with -Refresh; retain the request id if the failure persists.' }
            default { '' }
        }
    }
    $diagnostic = $msg
    if ($errorCode) { $diagnostic += " [Graph code: $errorCode]" }
    if ($requestId) { $diagnostic += " [request-id: $requestId]" }
    if ($advice) { $diagnostic += " $advice" }
    return [pscustomobject]@{ Code = $code; Message = $msg; ErrorCode = $errorCode; RequestId = $requestId; Advice = [string]$advice; EndpointAdvice = $endpointAdvice; Diagnostic = $diagnostic }
}

$script:CaptureGaps = [System.Collections.Generic.List[object]]::new()
# every gap seen this session, for the run log: a menu refresh starts CaptureGaps afresh, but the
# gaps a tenant inventory found earlier in the session still belong in the log
$script:SessionCaptureGaps = [System.Collections.Generic.List[object]]::new()
function Add-RsopSessionGap {
    param($Gap)
    if ($Gap -and -not @($script:SessionCaptureGaps | Where-Object { $_.Uri -eq $Gap.Uri }).Count) { [void]$script:SessionCaptureGaps.Add($Gap) }
}

function Add-RsopCaptureGap {
    # A tenant-setup read this tenant does not serve: access denied (feature not licensed, scope
    # not consented, Intune role), not implemented, or a legacy endpoint that failed. Normal for
    # most tenants, so it is not a run warning: the Tenant setup view lists it under capture
    # gaps, the backup manifest records it and the run log keeps it at info level.
    param([string]$Uri, $Failure)
    if (@($script:CaptureGaps | Where-Object { $_.Uri -eq $Uri }).Count) { return }
    $gap = [pscustomobject]@{ Uri = $Uri; Code = $Failure.Code; Message = $Failure.Message; RequestId = $Failure.RequestId; Advice = $Failure.Advice; Diagnostic = $Failure.Diagnostic }
    [void]$script:CaptureGaps.Add($gap)
    Add-RsopSessionGap $gap
    Add-RunLog -Level info -Message ("Capture gap: '{0}' answered {1}: {2}" -f $Uri, $Failure.Code, $Failure.Diagnostic)
}

function Register-TenantReadFailure {
    # Not configured (404) and a rejected $expand the caller retries without stay silent;
    # access denied / not implemented (and any failure of a legacy -Optional read) is a capture
    # gap; everything else is a read problem (warning) that a re-run may fix.
    param([string]$Uri, $Failure, [switch]$Optional, [switch]$DeferRejectedExpand)
    $code = $Failure.Code
    if ($Failure.ErrorCode -eq 'IncompleteRead') { return } # paging already recorded this problem
    if ($code -eq 404 -or ($DeferRejectedExpand -and $code -in @(400, 405) -and $Uri -match '\$expand=')) { return }
    if ($Optional -or $code -in @(403, 501)) { Add-RsopCaptureGap -Uri $Uri -Failure $Failure; return }
    Add-RsopReadProblem ("Tenant setup read '{0}' failed ({1}): {2}" -f $Uri, $code, $Failure.Diagnostic)
}

$script:TenantPrefetch = @{}   # 'beta/...' tenant-setup URI -> body read ahead in /$batch

function Initialize-TenantPrefetch {
    # Reads every fixed tenant-setup URI (a beta literal in Get-TenantConfiguration) up front, in
    # /$batch requests, instead of one round trip each. Invoke-TenantRead answers from here; what
    # failed or was not read ahead it reads on its own, so a failure keeps Graph's own error.
    $script:TenantPrefetch = @{}
    $fn = Get-Command -Name Get-TenantConfiguration -CommandType Function -ErrorAction SilentlyContinue
    if (-not $fn) { return }
    $uris = @($fn.ScriptBlock.Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-TenantRead' }, $true) |
            ForEach-Object { $a = $_.CommandElements[1]; if ($a -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $a.Value } } |
            Where-Object { $_ -like 'beta/*' } | Select-Object -Unique)
    if (-not $uris.Count) { return }
    $got = Invoke-RsopBatch -Urls @($uris | ForEach-Object { $_.Substring(4) }) -Activity 'Tenant setup (read ahead)' -NoDirectReads
    foreach ($u in $uris) {
        $b = $got[$u.Substring(4)]
        if ($b -is [System.Collections.IDictionary] -and -not $b['@intuneLens.truncated']) { $script:TenantPrefetch[$u] = $b }
    }
}

function Invoke-TenantRead {
    # One read for the tenant setup view. Never throws: @{ Ok; Value; Code; Message; Uri }.
    # -Optional: a legacy endpoint whose failure is a capture gap whatever the status.
    param([string]$Uri, [switch]$Paged, [switch]$DeferRejectedExpand, [switch]$Optional, [scriptblock]$OnPage)
    if ($script:TenantPrefetch.ContainsKey($Uri)) {
        # read ahead (once: a second read of the same URI goes to Graph again)
        $b = $script:TenantPrefetch[$Uri]
        $script:TenantPrefetch.Remove($Uri)
        if (-not $Paged) { return [pscustomobject]@{ Ok = $true; Value = $b; Code = 200; Message = ''; Uri = $Uri } }
        if ($b.ContainsKey('value')) {
            $items = [System.Collections.Generic.List[object]]::new()
            foreach ($i in @($b['value'])) { [void]$items.Add($i) }
            if ($OnPage) { & $OnPage $items.ToArray(); $items.Clear() }
            return [pscustomobject]@{ Ok = $true; Value = $items.ToArray(); Code = 200; Message = ''; Uri = $Uri }
        }
    }
    try {
        if ($Paged) {
            $read = Get-RsopPaged -Uri $Uri -OnPage $OnPage -IncludeCompletion
            if (-not $read.Complete) {
                $failure = Get-RsopReadError -ErrorRecord $read.Error -Uri $Uri
                Register-TenantReadFailure -Uri $Uri -Failure $failure -Optional:$Optional -DeferRejectedExpand:$DeferRejectedExpand
                foreach ($item in $read.Items) {
                    if ($item -is [System.Collections.IDictionary]) { $item['@intuneLens.collectionIncomplete'] = $Uri }
                }
                # Ok means usable captured data; Complete is still false. Existing tenant
                # consumers retain these objects, and raw backups carry the collection marker.
                $usable = $read.Items.Count -gt 0 -or ($OnPage -and $failure.ErrorCode -eq 'IncompleteRead')
                return [pscustomobject]@{ Ok = [bool]$usable; Complete = $false; Value = $read.Items; Code = $failure.Code; Message = $failure.Message; ErrorCode = $failure.ErrorCode; RequestId = $failure.RequestId; Advice = $failure.Advice; EndpointAdvice = $failure.EndpointAdvice; Diagnostic = $failure.Diagnostic; Uri = $Uri }
            }
            $v = $read.Items
        }
        else { $v = Invoke-Rsop -Uri $Uri }
        return [pscustomobject]@{ Ok = $true; Value = $v; Code = 200; Message = ''; Uri = $Uri }
    }
    catch {
        $failure = Get-RsopReadError -ErrorRecord $_ -Uri $Uri
        Register-TenantReadFailure -Uri $Uri -Failure $failure -Optional:$Optional -DeferRejectedExpand:$DeferRejectedExpand
        # a failed collection read is an EMPTY collection (never @($null) - callers loop over it)
        return [pscustomobject]@{ Ok = $false; Value = $(if ($Paged) { , @() } else { $null }); Code = $failure.Code; Message = $failure.Message; ErrorCode = $failure.ErrorCode; RequestId = $failure.RequestId; Advice = $failure.Advice; EndpointAdvice = $failure.EndpointAdvice; Diagnostic = $failure.Diagnostic; Uri = $Uri }
    }
}

function Invoke-TenantList {
    # Collection + navigation properties (assignments, items ...) as one read result.
    param([string]$Uri, [string[]]$Navigations = @('assignments'))
    # (Get-RsopItemsWithAssignments emits its array as ONE object - don't wrap it in @())
    try { $items = Get-RsopItemsWithAssignments -Uri $Uri -Navigations $Navigations; return [pscustomobject]@{ Ok = $true; Value = $items; Code = 200; Message = ''; Uri = $Uri } }
    catch {
        $failure = Get-RsopReadError -ErrorRecord $_ -Uri $Uri
        Register-TenantReadFailure -Uri $Uri -Failure $failure
        return [pscustomobject]@{ Ok = $false; Value = @(); Code = $failure.Code; Message = $failure.Message; ErrorCode = $failure.ErrorCode; RequestId = $failure.RequestId; Advice = $failure.Advice; Diagnostic = $failure.Diagnostic; Uri = $Uri }
    }
}

function Get-TenantConfiguration {
    # The non-policy half of Intune that a rebuild needs: tenant switches and licences, roles
    # and scope tags, end-user experience, enrollment programs with their tokens and
    # certificates, connectors, Windows 365, building blocks (reusable settings, imported
    # ADMX, compliance scripts, policy sets ...) and the Entra settings Intune depends on -
    # plus every group and filter assignments point at, and a recovery checklist (expiring
    # tokens, assignments to deleted groups, what Graph cannot export). Pulled on demand
    # (-All / -BackupPath) and cached with the corpus.
    param($Corpus)
    if ($null -ne $Corpus.tenantConfig) {
        $script:ScopeTagNames = @{}
        foreach ($pp in @($Corpus.tenantConfig.ScopeTags.PSObject.Properties)) { $script:ScopeTagNames[$pp.Name] = [string]$pp.Value }
        return $Corpus.tenantConfig
    }
    Write-Step 'Pulling tenant setup (tenant settings, roles, enrollment programs, connectors, groups)'
    Initialize-TenantPrefetch
    $now = [datetime]::UtcNow
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $sections = [ordered]@{}
    $sectionNotes = @{}
    $findings = [System.Collections.Generic.List[object]]::new()
    $refs = [System.Collections.Generic.List[object]]::new()          # non-assignment group references
    $notInUse = [System.Collections.Generic.List[object]]::new()      # optional features that are off / unreadable
    $reportedGaps = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)   # read URIs Add-NotInUse named
    $tenantId = [string]$Corpus.tenant
    $cloudPkiLicensed = $false

    function Add-Section([string]$Area, [string]$Note) {
        Write-RsopProgress -Id 3 -Activity 'Tenant setup' -Status $Area
        if (-not $sections.Contains($Area)) { $sections[$Area] = [System.Collections.Generic.List[object]]::new() }
        if ($Note) { $sectionNotes[$Area] = $Note }
    }
    function Add-Finding([string]$Severity, [string]$Area, [string]$Title, [string]$Detail) {
        [void]$findings.Add([pscustomobject]@{ Severity = $Severity; Area = $Area; Title = $Title; Detail = $Detail })
        if ($Area -eq 'Tenant setup' -and $Title -like "Section '*' is incomplete*") { Add-RsopReadProblem $Title }
    }
    function Add-GroupRef([string]$GroupId, [string]$Name, [string]$Kind, [string]$Mode = 'Include') {
        if ($GroupId) { [void]$refs.Add([pscustomobject]@{ GroupId = $GroupId; Name = $Name; Kind = $Kind; Mode = $Mode }) }
    }
    function Add-NotInUse([string]$Feature, $Read, [string]$Permission) {
        if (-not $Permission) { $Permission = "the endpoint's read permission" }
        if ($Read.Uri) { [void]$reportedGaps.Add([string]$Read.Uri) }
        $why = switch ($Read.Code) {
            403 { 'Not readable (403): access denied, so its configuration is unknown.' }
            404 { 'Not configured (404).' }
            501 { 'Unavailable (501): the service does not implement this request, so its configuration is unknown.' }
            default { "Not available ({0}): {1}" -f $Read.Code, $Read.Message }
        }
        if ($Read.EndpointAdvice) { $why += ' ' + $Read.Advice }
        elseif ($Read.Code -eq 403) { $why += " Check consent for $Permission, the user's Intune role and the feature's licence." }
        elseif ($Read.Advice) { $why += ' ' + $Read.Advice }
        if ($Read.RequestId) { $why += " [request-id: $($Read.RequestId)]" }
        [void]$notInUse.Add([pscustomobject]@{ Setting = $Feature; Value = $why; Category = 'Capture gaps and unavailable features' })
    }
    function New-Row([string]$Setting, $Value, [string]$Category = '') {
        if ($null -eq $Value -or "$Value" -eq '') { return }
        [pscustomobject]@{ Setting = $Setting; Value = $(if ($Value -is [bool]) { if ($Value) { 'Yes' } else { 'No' } } else { [string]$Value }); Category = $Category }
    }
    function Add-Item {
        param([string]$Area, [string]$Kind, $Raw, [string]$Name, [string]$State, [string]$Health,
              $Expires, [string]$Owner, $Assignments, [string]$Note, [string[]]$Skip = @(), $Rows,
              [string]$Backup, [hashtable]$BackupExtra = @{}, [int]$WarnDays = 30, [string]$ExpiredHealth = 'bad', [string]$Advice)
        Add-Section $Area
        if (-not $Name -and $null -ne $Raw) {
            foreach ($np in @('displayName', 'name', 'profileName', 'tokenName')) { $Name = [string](Get-Prop $Raw $np); if ($Name) { break } }
        }
        $exp = ''
        if ($Expires) {
            $d = ConvertTo-GraphDateTime $Expires
            if ($d.Year -gt 2000 -and $d.Year -lt 9000) {
                $exp = $d.ToString('yyyy-MM-dd', $inv)
                $days = [int]($d.Date - $now.Date).TotalDays
                $phrase = $null
                if ($days -lt 0 -or ($days -eq 0 -and $d -lt $now)) {
                    $Health = $ExpiredHealth
                    $ago = if ($days -lt 0) { -$days } else { 0 }
                    $State = if ($ago -eq 0) { 'Expired today' } else { ("Expired {0} day{1} ago" -f $ago, $(if ($ago -eq 1) { '' } else { 's' })) }
                    $phrase = if ($ago -eq 0) { "expired today ($exp)" } else { "expired on $exp" }
                }
                elseif ($days -le $WarnDays) {
                    if ($Health -ne 'bad') { $Health = 'warn' }
                    $timePhrase = if ($days -eq 0) { 'today' } else { "in $days day$(if ($days -eq 1) { '' } else { 's' })" }
                    $State = if ($days -eq 0) { 'Expires today' } else { ("Expires in {0} day{1}" -f $days, $(if ($days -eq 1) { '' } else { 's' })) }
                    $phrase = "expires on $exp ($timePhrase)"
                }
                elseif (-not $State) { $State = 'Valid'; if (-not $Health) { $Health = 'ok' } }
                if ($phrase) { Add-Finding $(if ($Health -eq 'bad') { 'bad' } else { 'warn' }) $Area ("{0} '{1}' {2}" -f $Kind, $Name, $phrase) $Advice }
            }
        }
        $r = $Rows
        if ($null -eq $r -and $null -ne $Raw) { $r = @(Convert-LegacyProperties -Policy $Raw -Category $Kind -Skip $Skip) }
        if ($Backup -and $null -ne $Raw) { Save-RsopBackupItem -Area $Backup -Item $Raw -Name $Name -Extra $BackupExtra }
        $it = [ordered]@{
            Kind = $Kind; Name = $Name; Id = [string](Get-Prop $Raw 'id'); State = $State; Health = $Health; Expires = $exp
            Owner = $Owner; Note = $Note
            Rows = @(@($r) | Where-Object { $null -ne $_ } | ForEach-Object { [pscustomobject]@{ Setting = [string]$_.Setting; Value = [string]$_.Value; Category = [string]$_.Category } })
            Asg = @(@($Assignments) | Where-Object { $null -ne $_ }); Assignment = ''; AssignmentDetail = @()
            AsgUnreadable = ($Raw -is [System.Collections.IDictionary] -and @($Raw['@intuneLens.unreadable']) -contains 'assignments')
        }
        [void]$sections[$Area].Add($it)
        return $it
    }
    function Get-Single($Read) {
        # singletons are sometimes wrapped in { value: {...} }
        $v = $Read.Value
        if ($v -is [System.Collections.IDictionary] -and $v.Contains('value') -and $v['value'] -is [System.Collections.IDictionary]) { return $v['value'] }
        return $v
    }

    # ---- tenant and licensing --------------------------------------------------------------
    try {
        $AreaName = 'Tenant and licensing'
        Add-Section $AreaName 'Tenant-wide switches a rebuilt tenant needs set by hand, the data-sharing consents behind Apple / Google / Windows features, and the licences that unlock Intune add-ons.'
        $org = Invoke-TenantRead ("v1.0/organization/{0}?`$select=id,displayName,mobileDeviceManagementAuthority,verifiedDomains" -f $tenantId)
        $root = Invoke-TenantRead 'beta/deviceManagement?$select=id,intuneAccountId,unlicensedAdminstratorsEnabled,maximumDepTokens,legacyPcManangementEnabled,accountMoveCompletionDateTime'
        $subState = Invoke-TenantRead 'beta/deviceManagement/subscriptionState'
        $rows = @()
        $mdmAuth = ''
        if ($org.Ok) {
            $o = $org.Value
            $mdmAuth = [string]$o['mobileDeviceManagementAuthority']
            $defDom = @((ConvertTo-RsopList $o['verifiedDomains']) | Where-Object { $_['isDefault'] } | ForEach-Object { $_['name'] })[0]
            $initDom = @((ConvertTo-RsopList $o['verifiedDomains']) | Where-Object { $_['isInitial'] } | ForEach-Object { $_['name'] })[0]
            $rows += New-Row 'Organization' $o['displayName'] 'Tenant'
            $rows += New-Row 'Default domain' $defDom 'Tenant'
            $rows += New-Row 'Initial domain' $initDom 'Tenant'
        }
        $rows += New-Row 'Tenant id' $tenantId 'Tenant'
        $rows += New-Row 'MDM authority' $mdmAuth 'Tenant'
        if ($root.Ok) {
            $rv = $root.Value
            $rows += New-Row 'Intune account id (Microsoft support asks for it)' $rv['intuneAccountId'] 'Tenant'
            if ($null -ne $rv['unlicensedAdminstratorsEnabled']) { $rows += New-Row 'Administrator licensing: unlicensed admins allowed (cannot be turned off once on)' ([bool]$rv['unlicensedAdminstratorsEnabled']) 'Tenant' }
            $rows += New-Row 'Maximum ADE tokens' $rv['maximumDepTokens'] 'Tenant'
            $amd = ConvertTo-GraphDateTime $rv['accountMoveCompletionDateTime']
            if ($amd.Year -gt 2000 -and $amd.Year -lt 9000) { $rows += New-Row 'Account move completed' $amd.ToString('yyyy-MM-dd', $inv) 'Tenant' }
        }
        if ($subState.Ok) { $rows += New-Row 'Intune subscription state' $subState.Value['value'] 'Tenant' }
        $null = Add-Item -Area $AreaName -Kind 'Tenant' -Name 'Intune tenant' -Rows $rows `
            -State $(if ($mdmAuth) { "MDM authority: $mdmAuth" } else { '' }) -Health $(if (-not $mdmAuth -or $mdmAuth -eq 'intune') { 'ok' } else { 'bad' })
        if ($mdmAuth -and $mdmAuth -ne 'intune') { Add-Finding 'bad' $AreaName ("MDM authority is '{0}', not Intune" -f $mdmAuth) 'Devices cannot enroll into Intune until the MDM authority is Intune.' }

        $set = Invoke-TenantRead 'beta/deviceManagement/settings'
        if ($set.Ok) {
            $s = $set.Value
            $rows = @()
            $rows += New-Row 'Mark devices with no compliance policy assigned as' $(if ($s['secureByDefault']) { 'Not compliant' } else { 'Compliant' }) 'Compliance policy settings'
            $ct = [int]$s['deviceComplianceCheckinThresholdDays']
            $rows += New-Row 'Compliance status validity period (days)' $(if ($ct -gt 0) { $ct } else { '0 (not set - service default)' }) 'Compliance policy settings'
            $rows += New-Row 'Enhanced jailbreak detection' $s['enhancedJailBreak'] 'Compliance policy settings'
            $rows += New-Row 'Scheduled actions for noncompliance enabled' $s['isScheduledActionEnabled'] 'Compliance policy settings'
            $rows += New-Row 'Ignore devices for unsupported settings' $s['ignoreDevicesForUnsupportedSettingsEnabled'] 'Compliance policy settings'
            $rows += New-Row 'Collect diagnostics (log collection)' $s['enableLogCollection'] 'Device diagnostics'
            $rows += New-Row 'Autopilot diagnostics' $s['enableAutopilotDiagnostics'] 'Device diagnostics'
            $rows += New-Row 'Microsoft 365 app diagnostics' $s['m365AppDiagnosticsEnabled'] 'Device diagnostics'
            $rows += New-Row 'Enhanced troubleshooting experience' $s['enableEnhancedTroubleshootingExperience'] 'Device diagnostics'
            $rows += New-Row 'Device group membership report' $s['enableDeviceGroupMembershipReport'] 'Device diagnostics'
            $rows += New-Row 'Android device administrator enrollment' $s['androidDeviceAdministratorEnrollmentEnabled'] 'Enrollment'
            $ret = [int]$s['deviceInactivityBeforeRetirementInDay']
            # (the per-platform clean-up rules below replaced this tenant-wide value)
            if ($ret -gt 0) { $rows += New-Row 'Legacy device cleanup (days of inactivity)' $ret 'Device cleanup (legacy, tenant-wide)' }
            $dcp = [string]$s['derivedCredentialProvider']
            if ($dcp -and $dcp -ne 'notConfigured') { $rows += New-Row 'Derived credential provider' $dcp 'Derived credentials'; $rows += New-Row 'Derived credential help URL' $s['derivedCredentialUrl'] 'Derived credentials' }
            $null = Add-Item -Area $AreaName -Kind 'Tenant settings' -Name 'Compliance, diagnostics and enrollment switches' -Rows $rows -Backup 'Tenant' -Raw $s `
                -Note 'Restore "Mark devices with no compliance policy" before Conditional Access depends on compliance again.'
        }
        else { Add-NotInUse 'Tenant settings (compliance policy settings, diagnostics)' $set 'DeviceManagementConfiguration.Read.All' }

        # per-platform device clean-up rules (Devices > Device clean-up rules)
        $cr = Invoke-TenantRead 'beta/deviceManagement/managedDeviceCleanupRules' -Paged
        if ($cr.Ok) {
            foreach ($p in $cr.Value) {
                $null = Add-Item -Area $AreaName -Kind 'Device clean-up rule' -Raw $p -Backup 'Tenant' -Health 'info' `
                    -State ("{0}: {1} days" -f (ConvertTo-FriendlyName ([string]$p['deviceCleanupRulePlatformType'])), $p['deviceInactivityBeforeRetirementInDays']) `
                    -Note 'Restore only after devices have checked in again following an outage - a short threshold hides devices that were offline during it.'
            }
        }
        else { Add-NotInUse 'Device clean-up rules' $cr 'DeviceManagementManagedDevices.Read.All' }

        # Intune Management Extension as managed installer (App Control for Business trusts
        # apps it installs) - a tenant switch, not a policy
        # (legacy singleton, superseded by group-targeted managed-installer policies: a failure is a capture gap)
        $mi = Invoke-TenantRead 'beta/deviceAppManagement/windowsManagementApp' -Optional
        $miState = $(if ($mi.Ok) { Get-Single $mi } else { $null })
        if ($miState -and [string]$miState['managedInstaller']) {
            $on = ([string]$miState['managedInstaller'] -eq 'enabled')
            $null = Add-Item -Area $AreaName -Kind 'Managed installer' -Raw $miState -Name 'Managed installer (legacy tenant-wide state)' -Backup 'Tenant' `
                -State $(if ($on) { 'Enabled' } else { 'Disabled' }) -Health $(if ($on) { 'ok' } else { 'info' }) `
                -Note 'This is the legacy tenant-wide state. Current group-targeted managed-installer scripts are inventoried with Remediations when scripts are included and readable; review their assignments before restoring App Control policies.'
        }
        elseif (-not $mi.Ok) { Add-NotInUse 'Managed installer (App Control for Business)' $mi 'DeviceManagementApps.Read.All' }

        $rows = @()
        $wd = Invoke-TenantRead 'beta/deviceManagement/dataProcessorServiceForWindowsFeaturesOnboarding'
        if ($wd.Ok) {
            $rows += New-Row 'Windows license verification (attest Windows E3/E5)' ([bool]$wd.Value['hasValidWindowsLicense']) 'Windows data'
            $rows += New-Row 'Enable features that require Windows diagnostic data' ([bool]$wd.Value['areDataProcessorServiceForWindowsFeaturesEnabled']) 'Windows data'
        }
        $ac = Invoke-TenantRead 'beta/deviceManagement/adminConsent'
        if ($ac.Ok) {
            $rows += New-Row 'Share Endpoint analytics data' $ac.Value['shareUserExperienceAnalyticsData'] 'Consents'
            $rows += New-Row 'Share APNs data' $ac.Value['shareAPNSData'] 'Consents'
        }
        foreach ($cid in @('appleMDMPushCertificate', 'androidManagedStore')) {
            $c = Invoke-TenantRead ("beta/deviceManagement/dataSharingConsents/{0}" -f $cid)
            if ($c.Ok) {
                $cv = $c.Value
                $who = $(if ($cv['granted']) { ("granted by {0} on {1}" -f $cv['grantedByUpn'], (Format-GraphDate $cv['grantDateTime'])) } else { 'not granted' })
                $rows += New-Row ("Data sharing consent: {0}" -f $cv['serviceDisplayName']) $who 'Consents'
            }
        }
        $uea = Invoke-TenantRead 'beta/deviceManagement?$select=userExperienceAnalyticsSettings'
        if ($uea.Ok -and $uea.Value['userExperienceAnalyticsSettings']) {
            $rows += New-Row 'Endpoint analytics: Configuration Manager data connector' ([bool]$uea.Value['userExperienceAnalyticsSettings']['configurationManagerDataConnectorConfigured']) 'Endpoint analytics'
        }
        if ($rows.Count) {
            $null = Add-Item -Area $AreaName -Kind 'Connectors and consents' -Name 'Windows data, data sharing and Endpoint analytics' -Rows $rows `
                -Note 'Consents and the Windows data toggles have to be granted again by hand in a rebuilt tenant.'
        }

        $skus = Invoke-TenantRead 'v1.0/subscribedSkus?$select=skuId,skuPartNumber,capabilityStatus,consumedUnits,prepaidUnits,servicePlans'
        $subs = Invoke-TenantRead 'v1.0/directory/subscriptions?$select=skuId,skuPartNumber,status,isTrial,nextLifecycleDateTime,totalLicenses' -Paged
        if ($skus.Ok) {
            $planRx = '(?i)intune|remote_help|cloud_pki|cpc_|windows_365|autopatch|winatp|windefatp|mde_|epm|mam_tunnel|advancedea|3_party_app_patch'
            # one SKU can have several subscriptions (trial next to paid, old one winding down)
            $subsBySku = @{}
            if ($subs.Ok) {
                foreach ($sb in @($subs.Value)) {
                    $sk0 = [string]$sb['skuId']
                    if (-not $subsBySku.ContainsKey($sk0)) { $subsBySku[$sk0] = [System.Collections.Generic.List[object]]::new() }
                    [void]$subsBySku[$sk0].Add($sb)
                }
            }
            $rows = @()
            foreach ($k in (ConvertTo-RsopList $skus.Value['value'])) {
                if ([string]$k['skuPartNumber'] -match '(?i)intune_suite|cloud_pki' -or @((ConvertTo-RsopList $k['servicePlans']) | Where-Object { [string]$_['servicePlanName'] -match '(?i)cloud_pki' }).Count) { $cloudPkiLicensed = $true }
                $plans = @((ConvertTo-RsopList $k['servicePlans']) | Where-Object { [string]$_['servicePlanName'] -match $planRx } | ForEach-Object { [string]$_['servicePlanName'] } | Select-Object -Unique)
                if (-not $plans.Count) { continue }
                $life = ''; $lapsing = @(); $covered = $false
                foreach ($sub in @($subsBySku[[string]$k['skuId']])) {
                    if (-not $sub) { continue }
                    $nl = ConvertTo-GraphDateTime $sub['nextLifecycleDateTime']
                    $hasDate = ($nl.Year -gt 2000 -and $nl.Year -lt 9000)
                    if ($hasDate) { $life += (" · {0}{1} until {2}" -f $(if ($sub['isTrial']) { 'trial, ' } else { '' }), $sub['status'], $nl.ToString('yyyy-MM-dd', $inv)) }
                    $dd = $(if ($hasDate) { [int]($nl.Date - $now.Date).TotalDays } else { [int]::MaxValue })
                    if ($dd -le 30 -and ($sub['isTrial'] -or [string]$sub['status'] -ne 'Enabled')) { $lapsing += [pscustomobject]@{ Sub = $sub; Date = $nl; Days = $dd } }
                    elseif ([string]$sub['status'] -eq 'Enabled' -and -not $sub['isTrial']) { $covered = $true }
                }
                # warn only when no enabled paid subscription of the same SKU keeps the features on
                if (-not $covered) {
                    foreach ($l in $lapsing) {
                        $when = if ($l.Days -lt 0) { "expired {0} day{1} ago" -f (-$l.Days), $(if (-$l.Days -eq 1) { '' } else { 's' }) }
                                elseif ($l.Days -eq 0) { 'today' }
                                else { "in {0} day{1}" -f $l.Days, $(if ($l.Days -eq 1) { '' } else { 's' }) }
                        Add-Finding 'warn' $AreaName ("Licence {0} ({1}) changes state on {2} ({3})" -f $k['skuPartNumber'], $(if ($l.Sub['isTrial']) { 'trial' } else { $l.Sub['status'] }), $l.Date.ToString('yyyy-MM-dd', $inv), $when) `
                            ("Intune features it unlocks stop working when it lapses: {0}" -f ($plans -join ', '))
                    }
                }
                $rows += New-Row ([string]$k['skuPartNumber']) ("{0} · {1} of {2} used{3} · {4}" -f $k['capabilityStatus'], $k['consumedUnits'], $k['prepaidUnits']['enabled'], $life, ($plans -join ', ')) 'Licences with Intune features'
            }
            if ($rows.Count) { $null = Add-Item -Area $AreaName -Kind 'Licences' -Name 'Licences that include Intune features' -Rows $rows }
        }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- roles and administration ---------------------------------------------------------
    try {
        $AreaName = 'Roles and administration'
        Add-Section $AreaName 'Who can administer Intune and over what. Built-in Intune roles are identical in every tenant, so only their assignments and any custom roles are listed. Restore order: scope tags, custom roles, then role assignments.'
        $tags = Invoke-TenantList -Uri 'beta/deviceManagement/roleScopeTags'
        # keep the names the corpus already read; this read only adds to them
        if (-not $script:ScopeTagNames) { $script:ScopeTagNames = @{} }
        $script:ScopeTagNames['0'] = 'Default'
        if ($tags.Ok) {
            foreach ($t in $tags.Value) { $script:ScopeTagNames[[string]$t['id']] = [string]$t['displayName'] }
            foreach ($t in $tags.Value) {
                $asg = @(ConvertTo-CompactAssignments -Assignments $t['assignments'])
                $null = Add-Item -Area $AreaName -Kind $(if ($t['isBuiltIn']) { 'Scope tag (built-in)' } else { 'Scope tag' }) -Raw $t -Skip @('isBuiltIn') -Assignments $asg `
                    -State $(if ($asg.Count) { 'Auto-tags devices in groups' } else { '' }) -Health 'info' -Backup 'Scope tags' `
                    -Note $(if ($asg.Count) { 'Devices in the assigned groups get this tag automatically.' } else { '' })
            }
        }
        else { Add-NotInUse 'Scope tags' $tags 'DeviceManagementRBAC.Read.All' }
        $tagName = { param($ids) (@(@($ids) | Where-Object { $_ } | ForEach-Object { $(if ($script:ScopeTagNames[[string]$_]) { $script:ScopeTagNames[[string]$_] } else { [string]$_ }) })) -join ', ' }

        $roles = Invoke-TenantRead 'beta/deviceManagement/roleDefinitions' -Paged
        $roleName = @{}
        if ($roles.Ok) {
            foreach ($r in $roles.Value) { $roleName[[string]$r['id']] = [string]$r['displayName'] }
            foreach ($r in @($roles.Value | Where-Object { -not $_['isBuiltIn'] -and -not $_['isBuiltInRoleDefinition'] })) {
                $allowed = @(); $denied = @()
                foreach ($rp in (ConvertTo-RsopList $r['rolePermissions'])) { foreach ($ra0 in (ConvertTo-RsopList $rp['resourceActions'])) { $allowed += @($ra0['allowedResourceActions']); $denied += @($ra0['notAllowedResourceActions']) } }
                $rows = @(New-Row 'Description' $r['description'] 'Role') + @(New-Row 'Scope tags' (& $tagName $r['roleScopeTagIds']) 'Role') +
                    @(New-Row ("Allowed actions ({0})" -f @($allowed | Where-Object { $_ }).Count) ((@($allowed | Where-Object { $_ } | Sort-Object -Unique)) -join "`n") 'Permissions') +
                    @(New-Row 'Not allowed actions' ((@($denied | Where-Object { $_ } | Sort-Object -Unique)) -join "`n") 'Permissions')
                $null = Add-Item -Area $AreaName -Kind 'Custom Intune role' -Raw $r -Rows $rows -Backup 'Intune roles'
            }
        }
        else { Add-NotInUse 'Intune roles' $roles 'DeviceManagementRBAC.Read.All' }

        $ras = Invoke-TenantRead 'beta/deviceManagement/roleAssignments?$expand=roleDefinition($select=id,displayName)' -Paged -DeferRejectedExpand
        if (-not $ras.Ok) { $ras = Invoke-TenantRead 'beta/deviceManagement/roleAssignments' -Paged }
        if ($ras.Ok) {
            $raList = @($ras.Value)
            # list responses can omit roleScopeTagIds / members: read each assignment in full
            if ($raList.Count) {
                $full = Invoke-RsopBatch -Urls @($raList | ForEach-Object { '/deviceManagement/roleAssignments/{0}' -f $_['id'] }) -Activity 'Intune role assignments'
                $raList = @($raList | ForEach-Object { $f = $full['/deviceManagement/roleAssignments/{0}' -f $_['id']]; if ($f) { if (-not $f['roleDefinition']) { $f['roleDefinition'] = $_['roleDefinition'] }; $f } else { $_ } })
                # the role is only a navigation property: if the $expand was refused, rebuild the
                # assignment -> role link from each role's roleAssignments (report + backup need it)
                $noRole = @($raList | Where-Object { -not (Get-Prop (Get-Prop $_ 'roleDefinition') 'displayName') })
                if ($noRole.Count -and $roleName.Count) {
                    $byRole = Invoke-RsopBatch -Urls @($roleName.Keys | ForEach-Object { '/deviceManagement/roleDefinitions/{0}/roleAssignments' -f $_ }) -Activity 'Intune role links'
                    $roleOf = @{}
                    foreach ($rid in $roleName.Keys) {
                        $b = $byRole['/deviceManagement/roleDefinitions/{0}/roleAssignments' -f $rid]
                        if ($b -is [System.Collections.IDictionary]) { foreach ($x in @($b['value'])) { if ($x) { $roleOf[[string]$x['id']] = $rid } } }
                    }
                    foreach ($a in $noRole) {
                        $rid = $roleOf[[string]$a['id']]
                        if ($rid) { $a['roleDefinition'] = [ordered]@{ id = $rid; displayName = $roleName[$rid] } }
                        else { Add-RsopReadProblem ("Could not tell which Intune role the assignment '{0}' grants." -f $a['displayName']) }
                    }
                }
            }
            $ids = @($raList | ForEach-Object { @($_['members']) + @($_['resourceScopes']) + @($_['scopeMembers']) } | Where-Object { $_ })
            Resolve-GroupNames -Ids $ids
            foreach ($a in $raList) {
                $rn = [string](Get-Prop (Get-Prop $a 'roleDefinition') 'displayName')
                if (-not $rn) { $rn = '(role)' }
                $st = [string]$a['scopeType']
                $scopeGroups = @(@($a['resourceScopes']) + @($a['scopeMembers']) | Where-Object { $_ } | Select-Object -Unique)
                $scopeTxt = switch ($st) {
                    'allDevices' { 'All devices' } 'allLicensedUsers' { 'All users' } 'allDevicesAndLicensedUsers' { 'All users and all devices' }
                    default { (@($scopeGroups | ForEach-Object { Get-GroupName $_ })) -join ', ' }
                }
                foreach ($m in @($a['members'])) { Add-GroupRef $m ("{0}: {1}" -f $rn, $a['displayName']) 'Intune role (administrators)' }
                foreach ($g in $scopeGroups) { Add-GroupRef $g ("{0}: {1}" -f $rn, $a['displayName']) 'Intune role (scope)' }
                $rows = @(New-Row 'Role' $rn 'Assignment') + @(New-Row 'Administrators (groups)' ((@(@($a['members']) | ForEach-Object { Get-GroupName $_ })) -join ', ') 'Assignment') +
                    @(New-Row 'Scope (groups)' $scopeTxt 'Assignment') + @(New-Row 'Scope tags' (& $tagName $a['roleScopeTagIds']) 'Assignment') +
                    @(New-Row 'Description' $a['description'] 'Assignment')
                $null = Add-Item -Area $AreaName -Kind 'Intune role assignment' -Raw $a -Name ("{0} - {1}" -f $rn, $a['displayName']) -Rows $rows -Owner $rn -Backup 'Intune role assignments'
            }
        }
        else { Add-NotInUse 'Intune role assignments' $ras 'DeviceManagementRBAC.Read.All' }

        $maa = Invoke-TenantRead 'beta/deviceManagement/operationApprovalPolicies' -Paged
        if ($maa.Ok) {
            Resolve-GroupNames -Ids @($maa.Value | ForEach-Object { @($_['approverGroupIds']) } | Where-Object { $_ })
            foreach ($p in $maa.Value) {
                foreach ($g in @($p['approverGroupIds'])) { Add-GroupRef $g ([string]$p['displayName']) 'Multi admin approval (approvers)' }
                $rows = @(New-Row 'Protects' (ConvertTo-FriendlyName ([string]$p['policyType'])) 'Approval') + @(New-Row 'Platform' $p['policyPlatform'] 'Approval') +
                    @(New-Row 'Approver groups' ((@(@($p['approverGroupIds']) | ForEach-Object { Get-GroupName $_ })) -join ', ') 'Approval') + @(New-Row 'Description' $p['description'] 'Approval')
                $null = Add-Item -Area $AreaName -Kind 'Multi admin approval' -Raw $p -Rows $rows -Backup 'Multi admin approval' -Note 'Recreate access policies last - once they exist, every protected restore step needs a second admin.'
            }
        }
        else { Add-NotInUse 'Multi admin approval' $maa 'DeviceManagementRBAC.Read.All' }

        # Entra roles that reach Intune (the break-glass path when Intune RBAC is empty)
        $rows = @()
        foreach ($er in @(@('3a2c62db-5318-420d-8d74-23affee5d9d5', 'Intune Administrator'), @('62e90394-69f5-4237-9190-012177145e10', 'Global Administrator'),
                @('9f06204d-73c1-4d4c-880a-6edb90606fd8', 'Microsoft Entra Joined Device Local Administrator'))) {
            $x = Invoke-TenantRead ("v1.0/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '{0}'&`$expand=principal(`$select=id,displayName)" -f $er[0]) -Paged
            if (-not $x.Ok) { continue }
            foreach ($ra1 in $x.Value) {
                $pr = $ra1['principal']
                $kind = (([string](Get-Prop $pr '@odata.type')) -replace '#microsoft.graph.', '')
                $rows += New-Row $er[1] ("{0} ({1}){2}" -f (Get-Prop $pr 'displayName'), $kind, $(if ([string]$ra1['directoryScopeId'] -ne '/') { " - scope $($ra1['directoryScopeId'])" } else { '' })) 'Active Entra role assignments'
                if ($kind -eq 'group') { Add-GroupRef ([string]$pr['id']) $er[1] 'Entra role (administrator group)' }
                Save-RsopBackupItem -Area 'Entra roles' -Item $ra1 -Name ("{0} - {1}" -f $er[1], (Get-Prop $pr 'displayName')) -Extra @{ roleDefinitionId = $er[0]; roleName = $er[1] }
            }
        }
        if ($rows.Count) { $null = Add-Item -Area $AreaName -Kind 'Entra roles' -Name 'Entra roles that administer Intune and joined devices' -Rows $rows -Note 'Active assignments only (PIM-eligible holders are not listed).' }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- end-user experience --------------------------------------------------------------
    try {
        $AreaName = 'Company Portal and end-user experience'
        Add-Section $AreaName 'What users see: Company Portal branding, terms and conditions, compliance e-mail templates and categories. Recreated objects get new ids - compliance actions and dynamic group rules that reference them have to be re-pointed.'
        $br = Invoke-TenantList -Uri 'beta/deviceManagement/intuneBrandingProfiles'
        if ($br.Ok) {
            foreach ($p in $br.Value) {
                $asg = @(ConvertTo-CompactAssignments -Assignments $p['assignments'])
                $isDef = [bool]$p['isDefaultProfile']
                $null = Add-Item -Area $AreaName -Kind 'Company Portal branding' -Raw $p -Name ([string]$p['profileName']) -Skip @('profileName', 'isDefaultProfile') -Assignments $asg `
                    -State $(if ($isDef) { 'Default profile' } elseif ($asg.Count) { 'Assigned' } else { 'Not assigned' }) -Health $(if ($isDef -or $asg.Count) { 'ok' } else { 'info' }) `
                    -Note $(if ($isDef) { 'Applies to every user not covered by a group-targeted profile.' } else { '' }) -Backup 'Company Portal branding'
            }
        }
        else { Add-NotInUse 'Company Portal branding' $br 'DeviceManagementServiceConfig.Read.All' }
        $tc = Invoke-TenantList -Uri 'beta/deviceManagement/termsAndConditions'
        if ($tc.Ok) {
            foreach ($p in $tc.Value) {
                $asg = @(ConvertTo-CompactAssignments -Assignments $p['assignments'])
                $null = Add-Item -Area $AreaName -Kind 'Terms and conditions' -Raw $p -Skip @('acceptanceStatuses', 'groupAssignments') -Assignments $asg `
                    -State ("Version {0}" -f $p['version']) -Health 'info' -Backup 'Terms and conditions' -Note 'A recreated version starts again at 1 - every user accepts again.'
            }
        }
        $nt = Invoke-TenantRead 'beta/deviceManagement/notificationMessageTemplates?$expand=localizedNotificationMessages' -Paged
        if ($nt.Ok) {
            foreach ($p in $nt.Value) {
                $rows = @(New-Row 'Branding options' $p['brandingOptions'] 'Template') + @(New-Row 'Default locale' $p['defaultLocale'] 'Template') + @(New-Row 'Scope tags' (& $tagName $p['roleScopeTagIds']) 'Template')
                foreach ($m in (ConvertTo-RsopList $p['localizedNotificationMessages'])) {
                    $cat = ("Message ({0}{1})" -f $m['locale'], $(if ($m['isDefault']) { ', default' } else { '' }))
                    $rows += New-Row 'Subject' $m['subject'] $cat
                    $rows += New-Row 'Message' $m['messageTemplate'] $cat
                }
                $null = Add-Item -Area $AreaName -Kind 'Compliance notification template' -Raw $p -Rows $rows -Backup 'Notification templates'
            }
        }
        $dc = Invoke-TenantRead 'beta/deviceManagement/deviceCategories' -Paged
        if ($dc.Ok) {
            foreach ($p in $dc.Value) { $null = Add-Item -Area $AreaName -Kind 'Device category' -Raw $p -Backup 'Device categories' -Note 'Dynamic group rules match categories by name - recreate with the exact same name.' }
        }
        $cats = Invoke-TenantRead 'beta/deviceAppManagement/mobileAppCategories' -Paged
        if (-not $cats.Ok) { Add-NotInUse 'App categories' $cats 'DeviceManagementApps.Read.All' }
        if ($cats.Ok) {
            $custom = @($cats.Value | Where-Object { (ConvertTo-GraphDateTime $_['lastModifiedDateTime']).Year -gt 2000 -and (ConvertTo-GraphDateTime $_['lastModifiedDateTime']).Year -lt 9000 })
            foreach ($p in $custom) { $null = Add-Item -Area $AreaName -Kind 'App category (custom)' -Raw $p -Backup 'App categories' }
        }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- enrollment: Windows and Entra -----------------------------------------------------
    try {
        $AreaName = 'Enrollment - Windows and Entra'
        Add-Section $AreaName 'How Windows devices reach Intune: the Entra MDM / MAM user scope, device join settings, Autopilot registrations and corporate identifiers.'
        foreach ($mp in @(@('policies/mobileDeviceManagementPolicies', 'Automatic enrollment (MDM user scope)'), @('policies/mobileAppManagementPolicies', 'Windows MAM (MAM user scope)'))) {
            $x = Invoke-TenantRead ("beta/{0}?`$expand=includedGroups(`$select=id,displayName)" -f $mp[0]) -Paged
            if (-not $x.Ok) { Add-NotInUse $mp[1] $x 'Policy.Read.All'; continue }
            foreach ($p in $x.Value) {
                $at = [string]$p['appliesTo']
                $grps = @($p['includedGroups'])
                foreach ($g in $grps) { Add-GroupRef ([string]$g['id']) $mp[1] 'Entra mobility scope' }
                $state = switch ($at) { 'all' { 'All users' } 'selected' { "Some users ({0} group{1})" -f $grps.Count, $(if ($grps.Count -eq 1) { '' } else { 's' }) } 'none' { 'None' } default { $at } }
                $isMdm = $mp[0] -like '*mobileDeviceManagement*'
                $rows = @(New-Row 'Applies to' $state 'Scope') + @(New-Row 'Included groups' ((@($grps | ForEach-Object { $_['displayName'] })) -join ', ') 'Scope') +
                    @(New-Row 'Disable MDM enrollment when adding a work account' $p['isMdmEnrollmentDuringRegistrationDisabled'] 'Scope') +
                    @(New-Row 'Discovery URL' $p['discoveryUrl'] 'URLs') + @(New-Row 'Terms of use URL' $p['termsOfUseUrl'] 'URLs') + @(New-Row 'Compliance URL' $p['complianceUrl'] 'URLs')
                $null = Add-Item -Area $AreaName -Kind $mp[1] -Raw $p -Name ("{0} - {1}" -f $mp[1], $p['displayName']) -Rows $rows -State $state `
                    -Health $(if ($isMdm -and $at -eq 'none' -and [string]$p['id'] -eq '0000000a-0000-0000-c000-000000000000') { 'warn' } else { 'ok' }) -Backup 'Entra mobility scope'
                if ($isMdm -and $at -eq 'none' -and [string]$p['id'] -eq '0000000a-0000-0000-c000-000000000000') {
                    Add-Finding 'warn' $AreaName 'Automatic Intune enrollment (MDM user scope) is set to None' 'Windows automatic enrollment and Autopilot cannot enroll devices into Intune until the scope is All or Some.'
                }
            }
        }
        $drp = Invoke-TenantRead 'beta/policies/deviceRegistrationPolicy'
        if ($drp.Ok) {
            $p = $drp.Value
            $mem = {
                param($m)
                $t = [string](Get-Prop $m '@odata.type')
                if ($t -match 'allDeviceRegistrationMembership') { return 'All' }
                if ($t -match 'noDeviceRegistrationMembership') { return 'None' }
                $gs = @(Get-PropList $m 'groups' | ForEach-Object { [string]$_ }); $us = @(Get-PropList $m 'users')
                Resolve-GroupNames -Ids $gs
                foreach ($g in $gs) { Add-GroupRef $g 'Entra device join / local admin settings' 'Entra device settings' }
                return ("Selected: {0} group(s) {1}; {2} user(s)" -f $gs.Count, ((@($gs | ForEach-Object { Get-GroupName $_ })) -join ', '), $us.Count)
            }
            $join = Get-Prop $p 'azureADJoin'; $reg = Get-Prop $p 'azureADRegistration'; $la = Get-Prop $join 'localAdmins'
            $rows = @(New-Row 'Users may join devices to Microsoft Entra' (& $mem (Get-Prop $join 'allowedToJoin')) 'Join and registration') +
                @(New-Row 'Users may register devices' (& $mem (Get-Prop $reg 'allowedToRegister')) 'Join and registration') +
                @(New-Row 'Maximum devices per user' (Get-Prop $p 'userDeviceQuota') 'Join and registration') +
                @(New-Row 'Require MFA to register or join (legacy setting)' (Get-Prop $p 'multiFactorAuthConfiguration') 'Join and registration') +
                @(New-Row 'Registering user becomes local administrator' (& $mem (Get-Prop $la 'registeringUsers')) 'Local administrators') +
                @(New-Row 'Global administrators are local administrators' (Get-Prop $la 'enableGlobalAdmins') 'Local administrators') +
                @(New-Row 'Microsoft Entra LAPS enabled' (Get-Prop (Get-Prop $p 'localAdminPassword') 'isEnabled') 'Local administrators')
            $null = Add-Item -Area $AreaName -Kind 'Entra device settings' -Raw $p -Name 'Device join and registration settings' -Rows $rows -Backup 'Entra device settings' `
                -Note 'Entra LAPS must be enabled here before Intune LAPS policies can work.'
        }
        else { Add-NotInUse 'Entra device join settings' $drp 'Policy.Read.All' }
        $authz = Invoke-TenantRead 'v1.0/policies/authorizationPolicy?$select=id,defaultUserRolePermissions'
        if ($authz.Ok) {
            $p = Get-Single $authz
            $permission = Get-Prop (Get-Prop $p 'defaultUserRolePermissions') 'allowedToReadBitlockerKeysForOwnedDevice'
            $rows = @(New-Row 'Users may read BitLocker keys of their own devices' $permission 'BitLocker recovery')
            $null = Add-Item -Area $AreaName -Kind 'Entra device settings' -Raw $p -Name 'BitLocker self-service recovery' -Rows $rows -Backup 'Entra device settings'
        }
        else { Add-NotInUse 'BitLocker self-service recovery setting' $authz 'Policy.Read.All' }

        $apd = Invoke-TenantRead 'beta/deviceManagement/windowsAutopilotDeviceIdentities' -Paged
        if ($apd.Ok) {
            $devs = @($apd.Value)
            # device -> profile map from each profile's assignedDevices (the list cannot $expand)
            $profByDev = @{}
            $apProfiles = @($Corpus.policies | Where-Object { $_.Family -eq 'autopilot' })
            if ($devs.Count -and $apProfiles.Count) {
                $got = Invoke-RsopBatch -Urls @($apProfiles | ForEach-Object { '/deviceManagement/windowsAutopilotDeploymentProfiles/{0}/assignedDevices' -f $_.Id }) -Activity 'Autopilot profile devices'
                foreach ($pf in $apProfiles) {
                    $b = $got['/deviceManagement/windowsAutopilotDeploymentProfiles/{0}/assignedDevices' -f $pf.Id]
                    if ($b -isnot [System.Collections.IDictionary]) { continue }
                    foreach ($d in @($b['value'])) { if ($d) { $profByDev[[string]$d['id']] = $pf.Name } }
                }
            }
            if ($script:BackupRoot -and $devs.Count) { Save-RsopBackupItem -Area 'Autopilot devices' -Name 'Autopilot devices' -Item @{ id = 'windowsAutopilotDeviceIdentities'; value = $devs } }
            $rows = [System.Collections.Generic.List[object]]::new()
            $noProfile = 0
            foreach ($d in ($devs | Sort-Object { [string]$_['groupTag'] }, { [string]$_['serialNumber'] })) {
                $pn = $profByDev[[string]$d['id']]
                $ps = [string]$d['deploymentProfileAssignmentStatus']
                if (-not $pn -and $ps -notlike 'assigned*') { $noProfile++ }
                if ($rows.Count -lt 2000) {
                    $bits = @(("{0} {1}" -f $d['manufacturer'], $d['model']).Trim(), $(if ($pn) { "profile '$pn'" } else { "profile: $(ConvertTo-AutopilotStatusLabel $ps)" }), [string]$d['enrollmentState'])
                    if ($d['userPrincipalName']) { $bits += ("user {0}" -f $d['userPrincipalName']) }
                    if ($d['purchaseOrderIdentifier']) { $bits += ("PO {0}" -f $d['purchaseOrderIdentifier']) }
                    [void]$rows.Add([pscustomobject]@{ Setting = [string]$d['serialNumber']; Value = (($bits | Where-Object { $_ }) -join ' · '); Category = $(if ($d['groupTag']) { "Group tag: $($d['groupTag'])" } else { 'No group tag' }) })
                }
            }
            if ($devs.Count -gt 2000) { [void]$rows.Add([pscustomobject]@{ Setting = '...'; Value = ("{0} more devices - see the backup / CSV export" -f ($devs.Count - 2000)); Category = 'More' }) }
            $null = Add-Item -Area $AreaName -Kind 'Windows Autopilot devices' -Name ("Autopilot registrations ({0})" -f $devs.Count) -Rows $rows.ToArray() `
                -State ("{0} device{1}" -f $devs.Count, $(if ($devs.Count -eq 1) { '' } else { 's' })) -Health 'info' `
                -Note $(if ($noProfile) { "$noProfile without an assigned deployment profile." } else { 'Serial, model, group tag, profile and user per registration.' })
            if ($devs.Count) {
                Add-Finding 'info' $AreaName ("Hardware hashes of {0} Autopilot device{1} cannot be read back from Graph" -f $devs.Count, $(if ($devs.Count -eq 1) { '' } else { 's' })) `
                    'Registrations survive the loss of Intune configuration, but a deleted record or a new tenant needs the hashes again (OEM / reseller re-registration or Get-WindowsAutopilotInfo). Keep the serial / group tag list from this report so group-tag dynamic groups and user pre-assignments can be rebuilt.'
            }
            $aps = Invoke-TenantRead 'beta/deviceManagement/windowsAutopilotSettings'
            if ($aps.Ok) {
                $ls = Format-GraphDate $aps.Value['lastSyncDateTime']
                $null = Add-Item -Area $AreaName -Kind 'Windows Autopilot sync' -Name 'Autopilot service sync' -Rows @(@(New-Row 'Sync status' $aps.Value['syncStatus'] 'Sync') + @(New-Row 'Last sync' $ls 'Sync')) `
                    -State ([string]$aps.Value['syncStatus']) -Health $(if ([string]$aps.Value['syncStatus'] -in @('completed', 'inProgress')) { 'ok' } else { 'warn' })
            }
        }
        else { Add-NotInUse 'Windows Autopilot devices' $apd 'DeviceManagementServiceConfig.Read.All' }
        $cdi = Invoke-TenantRead 'beta/deviceManagement/importedDeviceIdentities' -Paged
        if ($cdi.Ok -and @($cdi.Value).Count) {
            $ids = @($cdi.Value)
            if ($script:BackupRoot) { Save-RsopBackupItem -Area 'Corporate device identifiers' -Name 'Corporate device identifiers' -Item @{ id = 'importedDeviceIdentities'; value = $ids } }
            $rows = @($ids | Select-Object -First 2000 | ForEach-Object { [pscustomobject]@{ Setting = [string]$_['importedDeviceIdentifier']; Value = (@($_['platform'], $_['enrollmentState'], $_['description']) | Where-Object { $_ }) -join ' · '; Category = (ConvertTo-FriendlyName ([string]$_['importedDeviceIdentityType'])) } })
            $null = Add-Item -Area $AreaName -Kind 'Corporate device identifiers' -Name ("Corporate identifiers ({0})" -f $ids.Count) -Rows $rows -State ("{0} identifier{1}" -f $ids.Count, $(if ($ids.Count -eq 1) { '' } else { 's' })) -Health 'info' `
                -Note 'Without them, these devices enroll as personal - and restrictions that block personal devices block them.'
        }
        $djc = Invoke-TenantRead 'beta/deviceManagement/domainJoinConnectors' -Paged
        if ($djc.Ok) {
            foreach ($p in $djc.Value) {
                $lc = ConvertTo-GraphDateTime $p['lastConnectionDateTime']
                $stale = ($lc.Year -gt 2000 -and $lc.Year -lt 9000 -and ($now - $lc).TotalDays -gt 30)
                $null = Add-Item -Area $AreaName -Kind 'Intune Connector for Active Directory' -Raw $p -State ([string]$p['state']) -Health $(if ($stale) { 'warn' } else { 'ok' }) -Backup 'Connectors' `
                    -Note 'Hybrid-join Autopilot needs this on-premises connector; reinstall it and restore the OU delegation after a rebuild.'
                if ($stale) { Add-Finding 'warn' $AreaName ("Intune Connector for Active Directory '{0}' last connected {1}" -f $p['displayName'], $lc.ToString('yyyy-MM-dd', $inv)) 'Hybrid Entra join Autopilot deployments fail while the connector is offline.' }
            }
        }
        # Enrollment-time groups (Autopilot device preparation, enrollment time grouping): Graph
        # does not say which policy uses which group, but each such group must be owned by the
        # Intune Provisioning Client - the groups it owns are the complete list.
        $ipc = Invoke-TenantRead ("v1.0/servicePrincipals(appId='{0}')/ownedObjects?`$select=id,displayName,description" -f $script:ProvisioningClientAppId) -Paged
        if ($ipc.Ok) {
            $etg = @($ipc.Value | Where-Object { [string]$_['@odata.type'] -eq '#microsoft.graph.group' })
            foreach ($g in $etg) { Add-GroupRef ([string]$g['id']) 'Intune Provisioning Client (owner)' 'Enrollment-time group' }
            if ($etg.Count) {
                $null = Add-Item -Area $AreaName -Kind 'Enrollment-time groups' -Name ("Groups owned by the Intune Provisioning Client ({0})" -f $etg.Count) `
                    -Rows @($etg | Sort-Object { [string]$_['displayName'] } | ForEach-Object { New-Row ([string]$_['displayName']) ([string]$_['id']) 'Groups' }) `
                    -State ("{0} group{1}" -f $etg.Count, $(if ($etg.Count -eq 1) { '' } else { 's' })) -Health 'info' `
                    -Note ("Autopilot device preparation and enrollment time grouping add devices to these groups as they enroll. Graph does not show which policy uses which group - record that by hand. A recreated group needs the Intune Provisioning Client (app id {0}) as its owner again." -f $script:ProvisioningClientAppId)
            }
        }
        elseif ($ipc.Code -ne 404) { Add-NotInUse 'Enrollment-time groups (Intune Provisioning Client)' $ipc 'Directory.Read.All' }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- enrollment: Apple -----------------------------------------------------------------
    try {
        $AreaName = 'Enrollment - Apple'
        Add-Section $AreaName 'Apple MDM push certificate, Automated Device Enrollment tokens and profiles, user-initiated enrollment profiles and Apps and Books (VPP) tokens. Everything here depends on Apple accounts outside Intune.'
        $apns = Invoke-TenantRead 'beta/deviceManagement/applePushNotificationCertificate'
        $appleOn = $false
        if ($apns.Ok) {
            $c = Get-Single $apns
            $appleOn = $true
            $null = Add-Item -Area $AreaName -Kind 'Apple MDM push certificate' -Raw $c -Name ("APNs certificate - {0}" -f $c['appleIdentifier']) -Skip @('certificate') `
                -Expires $c['expirationDateTime'] -Owner ([string]$c['appleIdentifier']) -WarnDays 45 -Backup 'Apple' `
                -Advice ("Renew it at least a few days before it expires, signed in with the SAME Apple ID ({0}). A certificate from a different Apple ID forces every iOS / iPadOS / macOS device to re-enroll." -f $c['appleIdentifier']) `
                -Note ("Renew yearly with the same Apple ID ({0}). Its private key cannot be exported: a new tenant means a new certificate and re-enrolling every Apple device." -f $c['appleIdentifier'])
        }
        else { Add-NotInUse 'Apple MDM push certificate' $apns 'DeviceManagementServiceConfig.Read.All' }
        $dep = Invoke-TenantRead 'beta/deviceManagement/depOnboardingSettings' -Paged
        if ($dep.Ok) {
            foreach ($t in $dep.Value) {
                $appleOn = $true
                $tn = [string]$t['tokenName']
                $null = Add-Item -Area $AreaName -Kind 'Automated Device Enrollment token' -Raw $t -Name $tn -Expires $t['tokenExpirationDateTime'] -Owner ([string]$t['appleIdentifier']) -WarnDays 45 -Backup 'Apple ADE tokens' `
                    -Advice ("Download a renewed server token from the same MDM server in Apple Business Manager (signed in as {0}) and upload it to this token - do not create a new token." -f $t['appleIdentifier']) `
                    -Note ("{0} devices synced; last sync {1}" -f $t['syncedDeviceCount'], (Format-GraphDate $t['lastSuccessfulSyncDateTime']))
                $pr = Invoke-TenantRead ("beta/deviceManagement/depOnboardingSettings/{0}/enrollmentProfiles" -f $t['id']) -Paged
                $profName = @{}
                foreach ($p in @($pr.Value)) {
                    $profName[[string]$p['id']] = [string]$p['displayName']
                    $plat = switch -Wildcard ([string]$p['@odata.type']) { '*MacOS*' { 'macOS' } '*TvOS*' { 'tvOS' } '*VisionOS*' { 'visionOS' } default { 'iOS / iPadOS' } }
                    foreach ($g in @($p['enrollmentTimeAzureAdGroupIds'])) { Add-GroupRef ([string]$g) ([string]$p['displayName']) 'ADE profile (enrollment-time group)' }
                    $null = Add-Item -Area $AreaName -Kind ("ADE enrollment profile ({0})" -f $plat) -Raw $p -Skip @('managementCertificates') `
                        -State $(if ($p['isDefault']) { "Default for $plat" } else { '' }) -Health $(if ($p['isDefault']) { 'ok' } else { '' }) -Owner $tn -Backup 'Apple ADE profiles' `
                        -Note ("Token '{0}'" -f $tn)
                }
                $dv = Invoke-TenantRead ("beta/deviceManagement/depOnboardingSettings/{0}/importedAppleDeviceIdentities" -f $t['id']) -Paged
                if ($dv.Ok -and @($dv.Value).Count) {
                    $list = @($dv.Value)
                    if ($script:BackupRoot) { Save-RsopBackupItem -Area 'Apple ADE devices' -Name ("ADE devices - {0}" -f $tn) -Item @{ id = [string]$t['id']; value = $list } }
                    $rows = @($list | Select-Object -First 2000 | ForEach-Object {
                            $pid1 = [string]$_['requestedEnrollmentProfileId']
                            [pscustomobject]@{ Setting = [string]$_['serialNumber']; Value = (@($_['platform'], $(if ($pid1) { "profile '$(if ($profName[$pid1]) { $profName[$pid1] } else { $pid1 })'" } else { 'default profile' }), $_['enrollmentState']) | Where-Object { $_ }) -join ' · '; Category = 'Serial numbers' } })
                    $null = Add-Item -Area $AreaName -Kind 'ADE devices' -Name ("ADE devices - {0} ({1})" -f $tn, $list.Count) -Rows $rows -State ("{0} devices" -f $list.Count) -Health 'info' -Owner $tn
                }
            }
        }
        $uie = Invoke-TenantList -Uri 'beta/deviceManagement/appleUserInitiatedEnrollmentProfiles'
        if ($uie.Ok) {
            foreach ($p in $uie.Value) {
                $appleOn = $true
                $null = Add-Item -Area $AreaName -Kind 'Apple enrollment type profile' -Raw $p -Assignments @(ConvertTo-CompactAssignments -Assignments $p['assignments']) `
                    -State ("Priority {0}" -f $p['priority']) -Health 'info' -Backup 'Apple enrollment type profiles'
            }
        }
        $vpp = Invoke-TenantRead 'beta/deviceAppManagement/vppTokens' -Paged
        if (-not $vpp.Ok) { Add-NotInUse 'Apps and Books (VPP) tokens' $vpp 'DeviceManagementApps.Read.All' }
        if ($vpp.Ok) {
            foreach ($t in $vpp.Value) {
                $appleOn = $true
                $stv = [string]$t['state']
                $null = Add-Item -Area $AreaName -Kind 'Apps and Books (VPP) token' -Raw $t -Name ("{0}" -f $(if ($t['displayName']) { $t['displayName'] } else { $t['organizationName'] })) `
                    -Expires $t['expirationDateTime'] -Owner ("{0} ({1})" -f $t['appleId'], $t['locationName']) -WarnDays 45 -Backup 'Apple VPP tokens' `
                    -State $(if ($stv -and $stv -ne 'valid') { ConvertTo-FriendlyName $stv } else { '' }) -Health $(if ($stv -and $stv -ne 'valid') { 'bad' } else { '' }) `
                    -Advice 'Download a renewed content token for the same location in Apple Business Manager and upload it to this token.'
                # (an expired token is already on the checklist through its expiry date)
                if ($stv -and $stv -notin @('valid', 'expired', '')) { Add-Finding 'bad' $AreaName ("VPP token '{0}' is {1}" -f $t['displayName'], (ConvertTo-FriendlyName $stv)) 'Apps and licences from this location stop syncing until the token is fixed.' }
            }
        }
        if ($appleOn) {
            Add-Finding 'info' $AreaName 'Apple Business Manager is outside Intune' 'Record the ABM MDM server names, the Apple IDs that own the APNs certificate and the tokens (and the mailbox / MFA device behind them). ADE, VPP and APNs recovery all depend on them.'
        }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- enrollment: Android and ChromeOS --------------------------------------------------
    try {
        $AreaName = 'Enrollment - Android and ChromeOS'
        Add-Section $AreaName 'The Managed Google Play binding and Android Enterprise enrollment profiles. Enrollment tokens and QR codes are never shown.'
        $mgp = Invoke-TenantRead 'beta/deviceManagement/androidManagedStoreAccountEnterpriseSettings'
        if ($mgp.Ok) {
            $m = Get-Single $mgp
            $bound = ([string]$m['bindStatus'] -eq 'bound')
            foreach ($g in @($m['targetGroupIds'])) { Add-GroupRef ([string]$g) 'Managed Google Play (enrollment scope)' 'Android Enterprise enrollment scope' }
            $null = Add-Item -Area $AreaName -Kind 'Managed Google Play binding' -Raw $m -Name 'Managed Google Play' -Skip @('companyCodes') -State (ConvertTo-FriendlyName ([string]$m['bindStatus'])) `
                -Health $(if ($bound) { 'ok' } else { 'info' }) -Owner ([string]$m['ownerUserPrincipalName']) -Backup 'Android' `
                -Note $(if ($bound) { 'The binding cannot be moved or exported: unbinding creates a new enterprise and every Android Enterprise device has to re-enroll. Keep the Google account that owns it.' } else { 'Android Enterprise is not set up.' })
            if ($bound) { Add-Finding 'info' $AreaName ("Managed Google Play is bound to {0}" -f $m['ownerUserPrincipalName']) 'Keep the credentials of this Google account - rebinding creates a new enterprise and forces every Android Enterprise device to re-enroll. Zero-touch / Knox Mobile Enrollment configurations live in Google / Samsung portals.' }
        }
        $aep = Invoke-TenantRead 'beta/deviceManagement/androidDeviceOwnerEnrollmentProfiles' -Paged
        if ($aep.Ok) {
            foreach ($p in $aep.Value) {
                $null = Add-Item -Area $AreaName -Kind ("Android Enterprise enrollment profile ({0})" -f (ConvertTo-FriendlyName ([string]$p['enrollmentMode']))) -Raw $p `
                    -Expires $p['tokenExpirationDateTime'] -WarnDays 14 -ExpiredHealth 'warn' -Backup 'Android enrollment profiles' `
                    -Note ("{0} device(s) enrolled with it." -f $p['enrolledDeviceCount']) -Advice 'New devices cannot enroll with an expired token - create a new token (zero-touch / Knox configurations that embed it must be updated).'
            }
        }
        $afw = Invoke-TenantRead 'beta/deviceManagement/androidForWorkSettings'
        if ($afw.Ok -and [string](Get-Single $afw)['bindStatus'] -notin @('notBound', '')) {
            $null = Add-Item -Area $AreaName -Kind 'Android for Work binding (legacy)' -Raw (Get-Single $afw) -Name 'Android for Work (legacy)' -State ([string](Get-Single $afw)['bindStatus']) -Owner ([string](Get-Single $afw)['ownerUserPrincipalName']) -Backup 'Android'
        }
        $afwp = Invoke-TenantRead 'beta/deviceManagement/androidForWorkEnrollmentProfiles' -Paged
        if ($afwp.Ok) { foreach ($p in $afwp.Value) { $null = Add-Item -Area $AreaName -Kind 'Android for Work enrollment profile (legacy)' -Raw $p -Expires $p['tokenExpirationDateTime'] -WarnDays 14 -ExpiredHealth 'warn' -Backup 'Android enrollment profiles' } }
        $cros = Invoke-TenantRead 'beta/deviceManagement/chromeOSOnboardingSettings' -Paged
        if ($cros.Ok) {
            foreach ($p in @($cros.Value | Where-Object { [string]$_['onboardingStatus'] -notin @('unknown', 'notOnboarded', 'offboarding', '') })) {
                $null = Add-Item -Area $AreaName -Kind 'ChromeOS connector' -Raw $p -Name 'Google Workspace (ChromeOS) connector' -State (ConvertTo-FriendlyName ([string]$p['onboardingStatus'])) -Owner ([string]$p['ownerUserPrincipalName']) -Backup 'Connectors'
            }
        }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- connectors and integrations -------------------------------------------------------
    try {
        $AreaName = 'Connectors and integrations'
        Add-Section $AreaName 'Security, certificate and partner connectors. Their credentials live on the partner side or on on-premises servers - Graph shows their state and settings only.'
        $mtd = Invoke-TenantRead 'beta/deviceManagement/mobileThreatDefenseConnectors' -Paged
        if ($mtd.Ok) {
            foreach ($p in $mtd.Value) {
                $nm = $script:MtdPartnerNames[[string]$p['id']]
                if (-not $nm) { $nm = $(if ($p['partnerDisplayName']) { [string]$p['partnerDisplayName'] } else { "Mobile Threat Defense connector ($($p['id']))" }) }
                $hb = ConvertTo-GraphDateTime $p['lastHeartbeatDateTime']
                $thr = [int]$p['partnerUnresponsivenessThresholdInDays']; if ($thr -le 0) { $thr = 7 }
                $ps = [string]$p['partnerState']
                $stale = ($ps -eq 'enabled' -and $hb.Year -gt 2000 -and $hb.Year -lt 9000 -and ($now - $hb).TotalDays -gt $thr)
                $health = $(if ($ps -eq 'unresponsive' -or $stale) { 'bad' } elseif ($ps -eq 'enabled') { 'ok' } else { 'info' })
                $null = Add-Item -Area $AreaName -Kind 'Mobile Threat Defense connector' -Raw $p -Name $nm -State (ConvertTo-FriendlyName $ps) -Health $health -Backup 'Connectors' `
                    -Note $(if ($nm -like '*Defender*') { 'The Defender side (Advanced features > Microsoft Intune connection, security settings management scope, onboarding) is configured in the Defender portal, not in Intune.' } else { '' })
                if ($health -eq 'bad') { Add-Finding 'bad' $AreaName ("{0} connector is {1}" -f $nm, $(if ($stale) { "silent since $($hb.ToString('yyyy-MM-dd', $inv))" } else { 'unresponsive' })) 'Compliance policies that require a threat level mark devices noncompliant while the partner is unresponsive.' }
            }
        }
        $dmp = Invoke-TenantRead 'beta/deviceManagement/deviceManagementPartners' -Paged
        if ($dmp.Ok) {
            foreach ($p in @($dmp.Value | Where-Object { $_['isConfigured'] })) {
                foreach ($ga in @($p['groupsRequiringPartnerEnrollment'])) { Add-GroupRef ([string](Get-Prop (Get-Prop $ga 'target') 'groupId')) ([string]$p['displayName']) 'Partner device management (enrollment group)' }
                $hb = ConvertTo-GraphDateTime $p['lastHeartbeatDateTime']
                $pst = [string]$p['partnerState']
                $silent = ($pst -eq 'enabled' -and $hb.Year -gt 2000 -and $hb.Year -lt 9000 -and ($now - $hb).TotalDays -gt 7)
                $null = Add-Item -Area $AreaName -Kind 'Partner device management' -Raw $p -Skip @('groupsRequiringPartnerEnrollment') -State (ConvertTo-FriendlyName $pst) `
                    -Health $(if ($pst -in @('unresponsive', 'terminated', 'rejected') -or $silent) { 'bad' } elseif ($pst -in @('enabled', 'available')) { 'ok' } else { 'warn' }) -Backup 'Connectors' -Note 'Completed from the partner console with an Entra app consent; partner-side credentials are not in Graph.'
                if ($pst -in @('unresponsive', 'terminated', 'rejected') -or $silent) {
                    Add-Finding 'bad' $AreaName ("Partner device management '{0}' is {1}" -f $p['displayName'], $(if ($silent) { "silent since $($hb.ToString('yyyy-MM-dd', $inv))" } else { ConvertTo-FriendlyName $pst })) 'Devices that must enroll through the partner cannot, until the partner connection is re-established from the partner console.'
                }
            }
        }
        $cmp = Invoke-TenantRead 'beta/deviceManagement/complianceManagementPartners' -Paged
        if ($cmp.Ok) {
            foreach ($p in @($cmp.Value | Where-Object { [string]$_['partnerState'] -notin @('unknown', 'notSetUp', '') })) {
                foreach ($k in @('iosEnrollmentAssignments', 'macOsEnrollmentAssignments', 'androidEnrollmentAssignments', 'linuxEnrollmentAssignments')) {
                    foreach ($ga in @($p[$k])) { Add-GroupRef ([string](Get-Prop (Get-Prop $ga 'target') 'groupId')) ([string]$p['displayName']) 'Partner compliance (enrollment group)' }
                }
                $pst = [string]$p['partnerState']
                $bad0 = ($pst -in @('unresponsive', 'terminated', 'rejected'))
                $null = Add-Item -Area $AreaName -Kind 'Partner compliance' -Raw $p -Skip @('iosEnrollmentAssignments', 'macOsEnrollmentAssignments', 'androidEnrollmentAssignments', 'linuxEnrollmentAssignments') `
                    -State (ConvertTo-FriendlyName $pst) -Health $(if ($bad0) { 'bad' } elseif ($pst -eq 'enabled') { 'ok' } else { 'info' }) -Backup 'Connectors'
                if ($bad0) { Add-Finding 'bad' $AreaName ("Partner compliance '{0}' is {1}" -f $p['displayName'], (ConvertTo-FriendlyName $pst)) 'Devices whose compliance comes from this partner become noncompliant, and Conditional Access blocks them.' }
            }
        }
        $ndes = Invoke-TenantRead 'beta/deviceManagement/ndesConnectors' -Paged
        if ($ndes.Ok) {
            foreach ($p in $ndes.Value) {
                $lc = ConvertTo-GraphDateTime $p['lastConnectionDateTime']
                $stale = ($lc.Year -gt 2000 -and $lc.Year -lt 9000 -and ($now - $lc).TotalDays -gt 7)
                $null = Add-Item -Area $AreaName -Kind 'Certificate connector' -Raw $p -Name $(if ($p['displayName']) { [string]$p['displayName'] } else { [string]$p['machineName'] }) `
                    -State ([string]$p['state']) -Health $(if ($stale -or [string]$p['state'] -ne 'active') { 'warn' } else { 'ok' }) -Backup 'Connectors' `
                    -Note 'Reinstall on the server and sign in again after a rebuild; for PFX import keep the encryption key that lives on the connector servers.'
                if ($stale) { Add-Finding 'warn' $AreaName ("Certificate connector '{0}' last connected {1}" -f $p['machineName'], $lc.ToString('yyyy-MM-dd', $inv)) 'SCEP / PKCS certificates are not issued or renewed while the connector is offline.' }
            }
        }
        $pfx = Invoke-TenantRead 'beta/deviceManagement/userPfxCertificates?$select=id,expirationDateTime' -Paged
        if ($pfx.Ok -and @($pfx.Value).Count) {
            $null = Add-Item -Area $AreaName -Kind 'Imported PFX certificates' -Name ("Imported user PFX certificates ({0})" -f @($pfx.Value).Count) -Rows @(New-Row 'Certificates' @($pfx.Value).Count 'PKCS imported') `
                -State ("{0} certificates" -f @($pfx.Value).Count) -Health 'info' -Note 'Back up the PFX-import encryption key held by the certificate connector servers - without it these certificates cannot be recovered.'
        }
        $rh = Invoke-TenantRead 'beta/deviceManagement/remoteAssistanceSettings'
        if ($rh.Ok) { $null = Add-Item -Area $AreaName -Kind 'Remote Help' -Raw (Get-Single $rh) -Name 'Remote Help settings' -State (ConvertTo-FriendlyName ([string](Get-Single $rh)['remoteAssistanceState'])) -Backup 'Connectors' }
        else { Add-NotInUse 'Remote Help settings' $rh 'DeviceManagementConfiguration.Read.All or DeviceManagementServiceConfig.Read.All' }
        $rap = Invoke-TenantRead 'beta/deviceManagement/remoteAssistancePartners' -Paged
        if ($rap.Ok) { foreach ($p in @($rap.Value | Where-Object { [string]$_['onboardingStatus'] -notin @('notOnboarded', '') })) { $null = Add-Item -Area $AreaName -Kind 'Remote assistance partner' -Raw $p -State (ConvertTo-FriendlyName ([string]$p['onboardingStatus'])) -Backup 'Connectors' } }
        $sn = Invoke-TenantRead 'beta/deviceManagement/serviceNowConnections' -Paged
        if ($sn.Ok) { foreach ($p in $sn.Value) { $null = Add-Item -Area $AreaName -Kind 'ServiceNow connection' -Raw $p -Name ([string]$p['instanceUrl']) -State ([string]$p['serviceNowConnectionStatus']) -Backup 'Connectors' } }
        $tun = Invoke-TenantRead 'beta/deviceManagement/microsoftTunnelSites?$expand=microsoftTunnelServers,microsoftTunnelConfiguration' -Paged -DeferRejectedExpand
        if (-not $tun.Ok) { $tun = Invoke-TenantRead 'beta/deviceManagement/microsoftTunnelSites?$expand=microsoftTunnelServers' -Paged -DeferRejectedExpand }
        if (-not $tun.Ok) { $tun = Invoke-TenantRead 'beta/deviceManagement/microsoftTunnelSites' -Paged }
        if ($tun.Ok) {
            foreach ($p in $tun.Value) {
                $srv = @($p['microsoftTunnelServers'])
                $linked = Get-Prop $p 'microsoftTunnelConfiguration'
                $extra = @{}
                if (-not $p.Contains('microsoftTunnelServers')) {
                    $servers = Invoke-TenantRead ("beta/deviceManagement/microsoftTunnelSites/{0}/microsoftTunnelServers" -f $p['id']) -Paged
                    if ($servers.Ok) { $srv = @($servers.Value) }
                    else { $extra['@intuneLens.incomplete'] = 'Server list could not be read' }
                }
                $extra['microsoftTunnelServers'] = ConvertTo-RsopList $srv
                if (-not $linked) {
                    $link = Invoke-TenantRead ("beta/deviceManagement/microsoftTunnelSites/{0}/microsoftTunnelConfiguration?`$select=id,displayName" -f $p['id'])
                    if ($link.Ok) { $linked = Get-Single $link }
                    else {
                        $extra['@intuneLens.incomplete'] = (@($extra['@intuneLens.incomplete'], 'Server configuration link could not be read') | Where-Object { $_ }) -join '; '
                        Add-RsopReadProblem ("Microsoft Tunnel site '{0}': its server configuration link could not be read ({1})." -f $p['displayName'], $link.Code)
                    }
                }
                $extra['linkedConfiguration'] = $linked
                $rows = @(Convert-LegacyProperties -Policy $p -Category 'Site' -Skip @('microsoftTunnelServers', 'microsoftTunnelConfiguration'))
                $rows += New-Row 'Server configuration' $(if ($linked) { "{0} ({1})" -f (Get-Prop $linked 'displayName'), (Get-Prop $linked 'id') } else { 'Could not be read (see warnings)' }) 'Site'
                foreach ($s0 in $srv) { $rows += New-Row ([string]$s0['displayName']) ("{0} · last check-in {1}" -f $s0['tunnelServerHealthStatus'], (Format-GraphDate $s0['lastCheckinDateTime'])) 'Servers' }
                $null = Add-Item -Area $AreaName -Kind 'Microsoft Tunnel site' -Raw $p -Rows $rows -State ("{0} server{1}" -f $srv.Count, $(if ($srv.Count -eq 1) { '' } else { 's' })) -Backup 'Microsoft Tunnel' -BackupExtra $extra `
                    -Note 'The Linux gateway servers and their TLS certificate live outside Intune - keep the PFX and the setup answers.'
            }
        }
        $tcfg = Invoke-TenantRead 'beta/deviceManagement/microsoftTunnelConfigurations' -Paged
        if ($tcfg.Ok) { foreach ($p in $tcfg.Value) { $null = Add-Item -Area $AreaName -Kind 'Microsoft Tunnel server configuration' -Raw $p -Backup 'Microsoft Tunnel' } }
        $thr = Invoke-TenantRead 'beta/deviceManagement/microsoftTunnelHealthThresholds' -Paged
        if ($thr.Ok) {
            $chg = @($thr.Value | Where-Object { $_['healthyThreshold'] -ne $_['defaultHealthyThreshold'] -or $_['unhealthyThreshold'] -ne $_['defaultUnhealthyThreshold'] })
            if ($chg.Count) {
                $null = Add-Item -Area $AreaName -Kind 'Microsoft Tunnel health thresholds' -Name 'Customised Tunnel health thresholds' -Rows @($chg | ForEach-Object { New-Row ([string]$_['id']) ("healthy {0} / unhealthy {1} (defaults {2} / {3})" -f $_['healthyThreshold'], $_['unhealthyThreshold'], $_['defaultHealthyThreshold'], $_['defaultUnhealthyThreshold']) 'Thresholds' })
            }
        }
        $pki = Invoke-TenantRead 'beta/deviceManagement/cloudCertificationAuthority' -Paged
        if ($pki.Ok) {
            foreach ($p in $pki.Value) {
                $fullCa = Invoke-TenantRead ("beta/deviceManagement/cloudCertificationAuthority/{0}" -f $p['id'])
                if ($fullCa.Ok) { $p = Get-Single $fullCa }
                else { $p['@intuneLens.incomplete'] = 'Full CA properties could not be read' }
                $caType = switch ([string]$p['cloudCertificationAuthorityType']) {
                    'rootCertificationAuthority'    { 'Root CA' }
                    'issuingCertificationAuthority' { 'Issuing CA' }
                    default                         { '' }
                }
                $caName = [string]$p['displayName']
                $cn = [string]$p['commonName']
                if (-not $caName) { $caName = $cn }
                elseif ($cn -and $cn -ne $caName) { $caName = "{0} (CN={1})" -f $caName, $cn }
                if ($caType) {
                    if ($caName) { $caName = "{0} [{1}]" -f $caName, $caType }
                    else { $caName = $caType }
                }
                $null = Add-Item -Area $AreaName -Kind 'Cloud PKI certification authority' -Raw $p -Name $caName -Skip @('certificateSigningRequest') -Expires $p['validityEndDateTime'] -WarnDays 90 -Backup 'Cloud PKI' `
                    -State ([string]$p['certificationAuthorityStatus']) -Advice 'CA private keys cannot be exported: plan the replacement CA, trusted-certificate and SCEP profiles before the CA expires.' `
                    -Note 'Private keys stay with Microsoft and cannot be exported: losing the CA means new root / issuing CAs, redeployed trusted-certificate and SCEP profiles and re-issued certificates.'
            }
        }
        else {
            Add-NotInUse 'Cloud PKI' $pki 'DeviceManagementCloudCA.Read.All'
            if ($cloudPkiLicensed) {
                Add-Finding 'warn' $AreaName 'Cloud PKI is licensed but was not captured' 'Record the CA hierarchy, validity, subject, key and hash settings, EKUs and SCEP URLs by hand. The Cloud PKI list API currently documents a write permission; this tool requests read-only permission and does not escalate it.'
            }
        }
        $dcr = Invoke-TenantRead 'beta/deviceManagement/derivedCredentials' -Paged
        if ($dcr.Ok) { foreach ($p in $dcr.Value) { $null = Add-Item -Area $AreaName -Kind 'Derived credential issuer' -Raw $p -Backup 'Connectors' } }
        $epm = Invoke-TenantRead 'beta/deviceManagement/endpointPrivilegeManagementProvisioningStatus'
        if ($epm.Ok) {
            $e = Get-Single $epm
            $null = Add-Item -Area $AreaName -Kind 'Endpoint Privilege Management' -Raw $e -Name 'Endpoint Privilege Management' -State (ConvertTo-FriendlyName ([string]$e['licenseType'])) -Health 'info' `
                -Note 'Informational: EPM policies are in the Policies tab, the certificates their rules use are reusable settings (Policy building blocks).'
        }
        $ecs = Invoke-TenantRead 'beta/deviceAppManagement/enterpriseCodeSigningCertificates?$select=id,subjectName,issuerName,status,expirationDateTime,uploadDateTime' -Paged
        if ($ecs.Ok) { foreach ($p in $ecs.Value) { $null = Add-Item -Area $AreaName -Kind 'Enterprise code-signing certificate' -Raw $p -Name ([string]$p['subjectName']) -Expires $p['expirationDateTime'] -Backup 'Connectors' } }
        $sym = Invoke-TenantRead 'beta/deviceAppManagement/symantecCodeSigningCertificate?$select=id,status,subjectName,issuerName,expirationDateTime,uploadDateTime'
        if ($sym.Ok -and [string](Get-Single $sym)['status'] -eq 'provisioned') { $null = Add-Item -Area $AreaName -Kind 'Windows Phone code-signing certificate (legacy)' -Raw (Get-Single $sym) -Name ([string](Get-Single $sym)['subjectName']) -Expires (Get-Single $sym)['expirationDateTime'] }
        $zeb = Invoke-TenantRead 'beta/deviceManagement/zebraFotaConnector'
        if ($zeb.Ok -and [string](Get-Single $zeb)['state'] -notin @('none', '')) {
            $null = Add-Item -Area $AreaName -Kind 'Zebra FOTA connector' -Raw (Get-Single $zeb) -Name 'Zebra LifeGuard Over-the-Air' -Skip @('enrollmentAuthorizationUrl') -State ([string](Get-Single $zeb)['state']) -Backup 'Connectors'
            $deployments = Invoke-TenantList 'beta/deviceManagement/zebraFotaDeployments' -Navigations @('deploymentAssignments')
            if ($deployments.Ok) {
                foreach ($p in $deployments.Value) {
                    $asgs = @(Get-PropList $p 'deploymentAssignments')
                    $zebraAssignments = @()
                    foreach ($a in $asgs) {
                        $target = Get-Prop $a 'target'
                        if (-not $target) { $target = Get-Prop $a 'assignmentTarget' }
                        Add-GroupRef ([string](Get-Prop $target 'groupId')) ([string]$p['displayName']) 'Zebra FOTA deployment'
                        $zebraAssignments += @{ target = $target }
                    }
                    $null = Add-Item -Area $AreaName -Kind 'Zebra FOTA deployment' -Raw $p -Skip @('deploymentStatus', 'deploymentAssignments') -Assignments @(ConvertTo-CompactAssignments -Assignments $zebraAssignments) -Backup 'Zebra FOTA deployments'
                }
            }
            else { Add-NotInUse 'Zebra FOTA deployments' $deployments 'DeviceManagementConfiguration.Read.All' }
        }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- Windows 365 -----------------------------------------------------------------------
    try {
        $AreaName = 'Windows 365'
        Add-Section $AreaName 'Cloud PC provisioning policies, user settings, Azure network connections and custom images. Cloud PCs themselves are re-provisioned from these policies.'
        $w365 = Invoke-TenantRead 'beta/deviceManagement/virtualEndpoint/provisioningPolicies?$expand=assignments' -Paged
        if ($w365.Ok) {
            foreach ($p in $w365.Value) {
                $null = Add-Item -Area $AreaName -Kind 'Cloud PC provisioning policy' -Raw $p -Assignments @(ConvertTo-CompactAssignments -Assignments $p['assignments']) -Backup 'Windows 365' `
                    -Skip @('onPremisesConnectionId', 'domainJoinConfiguration', 'windowsSettings') -State (ConvertTo-FriendlyName ([string]$p['provisioningType'])) `
                    -Note 'Provisioning type and user experience cannot be changed after creation - recreate them exactly.'
            }
            $us = Invoke-TenantRead 'beta/deviceManagement/virtualEndpoint/userSettings?$expand=assignments' -Paged
            foreach ($p in @($us.Value)) { $null = Add-Item -Area $AreaName -Kind 'Cloud PC user setting' -Raw $p -Assignments @(ConvertTo-CompactAssignments -Assignments $p['assignments']) -Backup 'Windows 365' -Note ("Created {0} - the most recently created user setting wins when several apply." -f (Format-GraphDate $p['createdDateTime'])) }
            $anc = Invoke-TenantRead 'beta/deviceManagement/virtualEndpoint/onPremisesConnections?$select=id,displayName,connectionType,adDomainName,adDomainUsername,organizationalUnit,subscriptionId,subscriptionName,resourceGroupId,virtualNetworkId,subnetId,virtualNetworkLocation,healthCheckStatus,inUse,managedBy,scopeIds' -Paged
            foreach ($p in @($anc.Value)) {
                $hs = [string]$p['healthCheckStatus']
                $null = Add-Item -Area $AreaName -Kind 'Azure network connection' -Raw $p -State (ConvertTo-FriendlyName $hs) -Health $(if ($hs -eq 'passed') { 'ok' } elseif ($hs) { 'warn' } else { '' }) -Backup 'Windows 365' `
                    -Note 'The virtual network, DNS and line of sight to domain controllers live in Azure; the domain join password must be re-entered.'
            }
            $img = Invoke-TenantRead 'beta/deviceManagement/virtualEndpoint/deviceImages' -Paged
            foreach ($p in @($img.Value)) { $null = Add-Item -Area $AreaName -Kind 'Cloud PC custom image' -Raw $p -Expires $p['expirationDate'] -WarnDays 60 -Backup 'Windows 365' -Note 'Keep the source managed image in Azure (sourceImageResourceId) - Graph holds only metadata.' }
            $os = Invoke-TenantRead 'beta/deviceManagement/virtualEndpoint/organizationSettings'
            if ($os.Ok) { $null = Add-Item -Area $AreaName -Kind 'Cloud PC organization settings' -Raw (Get-Single $os) -Name 'Windows 365 organization settings' -Backup 'Windows 365' }
            # published cloud apps, pooled Cloud PCs, Citrix / VMware / HP connectors, alert rules
            foreach ($x in @(@('virtualEndpoint/cloudApps', 'Cloud app (published)', $false), @('virtualEndpoint/cloudPcPools?$expand=assignments', 'Cloud PC pool', $true),
                    @('virtualEndpoint/externalPartners', 'Cloud PC partner connector', $false), @('monitoring/alertRules', 'Cloud PC alert rule', $false))) {
                $r0 = Invoke-TenantRead ("beta/deviceManagement/{0}" -f $x[0]) -Paged
                if (-not $r0.Ok) { if ($r0.Code -eq 403) { Add-NotInUse $x[1] $r0 'CloudPC.Read.All' }; continue }
                foreach ($p in $r0.Value) {
                    $null = Add-Item -Area $AreaName -Kind $x[1] -Raw $p -Backup 'Windows 365' `
                        -Assignments $(if ($x[2]) { @(ConvertTo-CompactAssignments -Assignments $p['assignments']) } else { @() })
                }
            }
        }
        else {
            $sectionNotes[$AreaName] = $(if ($w365.Code -eq 403) { 'Not captured: access to Windows 365 was denied (403). Expected when Windows 365 is not licensed; otherwise grant CloudPC.Read.All and a Cloud PC reader role. Listed under Capture gaps.' }
                else { "Not captured ($($w365.Code)): $($w365.Message) Listed under Capture gaps." })
            Add-NotInUse 'Windows 365 (Cloud PC provisioning policies)' $w365 'CloudPC.Read.All'
        }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- policy building blocks ------------------------------------------------------------
    try {
        $AreaName = 'Policy building blocks'
        Add-Section $AreaName 'Objects that policies reference by id: reusable settings (firewall rules, device control, EPM certificates), imported ADMX files, custom compliance scripts and policy sets. Restore these before the policies that use them.'
        $reu = Invoke-TenantRead 'beta/deviceManagement/reusablePolicySettings?$select=id,displayName,description,settingDefinitionId,settingInstance,referencingConfigurationPolicyCount,version,createdDateTime,lastModifiedDateTime' -Paged
        if ($reu.Ok) {
            $refsBy = @{}
            $withRefs = @($reu.Value | Where-Object { [int]$_['referencingConfigurationPolicyCount'] -gt 0 })
            if ($withRefs.Count) {
                $rb = Invoke-RsopBatch -Urls @($withRefs | ForEach-Object { '/deviceManagement/reusablePolicySettings/{0}/referencingConfigurationPolicies?$select=id,name' -f $_['id'] }) -Activity 'Reusable setting references'
                foreach ($r in $withRefs) {
                    $b = $rb['/deviceManagement/reusablePolicySettings/{0}/referencingConfigurationPolicies?$select=id,name' -f $r['id']]
                    if ($b -is [System.Collections.IDictionary]) { $refsBy[[string]$r['id']] = @(@($b['value']) | Where-Object { $_ } | ForEach-Object { [string]$_['name'] }) }
                }
            }
            foreach ($p in $reu.Value) {
                $lst = [System.Collections.Generic.List[object]]::new()
                Expand-CatalogInstance -Instance $p['settingInstance'] -Defs @{} -Prefix '' -Rows $lst
                $rows = @($lst | ForEach-Object { [pscustomobject]@{ Setting = $_.Setting; Value = $_.Value; Category = 'Values' } })
                $used = @($refsBy[[string]$p['id']] | Where-Object { $_ })
                $rows += New-Row 'Used by' $(if ($used.Count) { $used -join ', ' } else { 'not referenced' }) 'References'
                $rows += New-Row 'Setting type' (Get-DefinitionTail ([string]$p['settingDefinitionId'])) 'References'
                $null = Add-Item -Area $AreaName -Kind 'Reusable setting group' -Raw $p -Rows $rows -State $(if ($used.Count) { "Used by $($used.Count) polic$(if ($used.Count -eq 1) { 'y' } else { 'ies' })" } else { 'Not used' }) `
                    -Health $(if ($used.Count) { 'ok' } else { 'info' }) -Backup 'Reusable settings'
            }
        }
        $admxFiles = Invoke-TenantRead 'beta/deviceManagement/groupPolicyUploadedDefinitionFiles' -Paged
        if ($admxFiles.Ok) {
            $full = @{}
            if ($script:BackupRoot -and @($admxFiles.Value).Count) {
                # GET by id carries the uploaded ADMX / ADML content - the restorable copy
                $full = Invoke-RsopBatch -Urls @($admxFiles.Value | ForEach-Object { '/deviceManagement/groupPolicyUploadedDefinitionFiles/{0}' -f $_['id'] }) -Activity 'Imported ADMX files'
            }
            foreach ($p in $admxFiles.Value) {
                $b = $full['/deviceManagement/groupPolicyUploadedDefinitionFiles/{0}' -f $p['id']]
                $langs = @(@($p['groupPolicyUploadedLanguageFiles']) | ForEach-Object { "{0} ({1})" -f $_['fileName'], $_['languageCode'] })
                $rows = @(Convert-LegacyProperties -Policy $p -Category 'ADMX file' -Skip @('content', 'groupPolicyUploadedLanguageFiles', 'groupPolicyOperations'))
                if ($langs.Count) { $rows += New-Row 'Language files' ($langs -join ', ') 'ADMX file' }
                $st0 = [string]$p['status']
                $null = Add-Item -Area $AreaName -Kind 'Imported ADMX file' -Raw $(if ($b) { $b } else { $p }) -Name ([string]$p['fileName']) -Rows $rows -State (ConvertTo-FriendlyName $st0) `
                    -Health $(if ($st0 -eq 'available') { 'ok' } elseif ($st0) { 'warn' } else { '' }) -Backup 'Imported ADMX files' `
                    -Note 'Re-import the ADMX / ADML before restoring Administrative Templates or Settings Catalog policies that use it.'
            }
        }
        $ccs = Invoke-TenantList -Uri 'beta/deviceManagement/deviceComplianceScripts'
        if ($ccs.Ok) {
            $bodies = @{}
            $need = @($ccs.Value | Where-Object { -not $_['detectionScriptContent'] })
            if ($need.Count) { $bodies = Invoke-RsopBatch -Urls @($need | ForEach-Object { '/deviceManagement/deviceComplianceScripts/{0}' -f $_['id'] }) -Activity 'Custom compliance scripts' }
            $usedBy = @{}
            foreach ($cp in @($Corpus.policies | Where-Object { $_.Family -eq 'compliance' })) {
                # keyed by script id (names repeat; with -SkipScripts the row only has the id)
                foreach ($s0 in @($cp.Settings | Where-Object { $_.Setting -eq 'Custom compliance: discovery script' })) {
                    $sk1 = $(if ($s0.PSObject.Properties['Ref'] -and $s0.Ref) { [string]$s0.Ref } else { [string]$s0.Value })
                    $usedBy[$sk1] = @(@($usedBy[$sk1]) + $cp.Name | Where-Object { $_ })
                }
            }
            foreach ($p in $ccs.Value) {
                $full0 = $p; $b = $bodies['/deviceManagement/deviceComplianceScripts/{0}' -f $p['id']]; if ($b) { $full0 = $b; $full0['assignments'] = $p['assignments'] }
                $rows = @(Convert-LegacyProperties -Policy $full0 -Category 'Script options' -Skip @('detectionScriptContent'))
                $txt = ConvertFrom-Base64Text ([string]$full0['detectionScriptContent'])
                if ($txt) { $rows += New-Row 'Discovery script' $(if ($txt.Length -gt 6000) { $txt.Substring(0, 6000) + "`n...(truncated)" } else { $txt }) 'Script body' }
                $u = @(@($usedBy[[string]$p['id']]) + @($usedBy[[string]$p['displayName']]) | Where-Object { $_ } | Select-Object -Unique)
                $null = Add-Item -Area $AreaName -Kind 'Custom compliance script' -Raw $full0 -Rows $rows -State $(if ($u.Count) { 'Used by ' + ($u -join ', ') } else { 'Not used by a compliance policy' }) `
                    -Health $(if ($u.Count) { 'ok' } else { 'info' }) -Backup 'Custom compliance scripts'
            }
        }
        $ps0 = Invoke-TenantList -Uri 'beta/deviceAppManagement/policySets' -Navigations @('items', 'assignments')
        if (-not $ps0.Ok) { Add-NotInUse 'Policy sets' $ps0 'DeviceManagementApps.Read.All' }
        if ($ps0.Ok) {
            foreach ($p in $ps0.Value) {
                $rows = @((ConvertTo-RsopList $p['items']) | ForEach-Object { New-Row ([string]$_['displayName']) ((([string]$_['@odata.type']) -replace '#microsoft.graph.', '') -replace 'PolicySetItem$', '') 'Items' })
                $rows += New-Row 'Status' $p['status'] 'Policy set'
                $null = Add-Item -Area $AreaName -Kind 'Policy set' -Raw $p -Rows $rows -Assignments @(ConvertTo-CompactAssignments -Assignments $p['assignments']) -Backup 'Policy sets' `
                    -Note 'A policy set pushes its own assignments to every item in it.'
            }
        }
        $lobp = Invoke-TenantList -Uri 'beta/deviceAppManagement/iosLobAppProvisioningConfigurations'
        if (-not $lobp.Ok) { Add-NotInUse 'iOS app provisioning profiles' $lobp 'DeviceManagementApps.Read.All' }
        if ($lobp.Ok) {
            foreach ($p in $lobp.Value) {
                $null = Add-Item -Area $AreaName -Kind 'iOS app provisioning profile' -Raw $p -Skip @('payload') -Assignments @(ConvertTo-CompactAssignments -Assignments $p['assignments']) `
                    -Expires $p['expirationDateTime'] -WarnDays 45 -Backup 'iOS app provisioning profiles' -Advice 'In-house iOS apps signed with it stop launching when it expires - upload the renewed .mobileprovision.'
            }
        }
        $ebk = Invoke-TenantList -Uri 'beta/deviceAppManagement/managedEBooks'
        if (-not $ebk.Ok) { Add-NotInUse 'Managed e-books' $ebk 'DeviceManagementApps.Read.All' }
        if ($ebk.Ok) {
            foreach ($p in $ebk.Value) { $null = Add-Item -Area $AreaName -Kind 'Managed e-book' -Raw $p -Skip @('largeCover') -Assignments @(ConvertTo-CompactAssignments -Assignments $p['assignments']) -Backup 'Managed e-books' }
        }
        $ebc = Invoke-TenantRead 'beta/deviceAppManagement/managedEBookCategories' -Paged
        if ($ebc.Ok) { foreach ($p in $ebc.Value) { $null = Add-Item -Area $AreaName -Kind 'E-book category' -Raw $p -Backup 'Managed e-books' } }
        # eSIM activation code pools (codes are carrier secrets: redacted, re-obtained from the carrier)
        $esim = Invoke-TenantList -Uri 'beta/deviceManagement/embeddedSIMActivationCodePools'
        if ($esim.Ok) {
            foreach ($p in $esim.Value) {
                $null = Add-Item -Area $AreaName -Kind 'eSIM activation code pool' -Raw $p -Skip @('activationCodes') -Assignments @(ConvertTo-CompactAssignments -Assignments $p['assignments']) `
                    -State ("{0} codes" -f $p['activationCodeCount']) -Health 'info' -Backup 'eSIM pools' -Note 'Activation codes come from the carrier and are not kept in this report or backup.'
            }
        }
        # tenant-default app protection (all users no targeted app protection policy covers)
        $dmp = Invoke-TenantList -Uri 'beta/deviceAppManagement/defaultManagedAppProtections' -Navigations @('apps')
        if (-not $dmp.Ok) { Add-NotInUse 'Default app protection' $dmp 'DeviceManagementApps.Read.All' }
        if ($dmp.Ok) {
            foreach ($p in $dmp.Value) {
                $null = Add-Item -Area $AreaName -Kind 'Default app protection' -Raw $p -Skip @('apps', 'deploymentSummary') -Backup 'App protection (default)' `
                    -Note 'Applies to every user that no targeted App Protection policy covers.'
            }
        }
        # Endpoint analytics: custom baselines and device scopes (admin-created; scores are telemetry)
        $uea = Invoke-TenantRead 'beta/deviceManagement/userExperienceAnalyticsBaselines?$select=id,displayName,isBuiltIn,createdDateTime' -Paged
        if ($uea.Ok) { foreach ($p in @($uea.Value | Where-Object { -not $_['isBuiltIn'] })) { $null = Add-Item -Area $AreaName -Kind 'Endpoint analytics baseline' -Raw $p -Backup 'Endpoint analytics' } }
        $ueaS = Invoke-TenantRead 'beta/deviceManagement/userExperienceAnalyticsDeviceScopes' -Paged
        if ($ueaS.Ok) { foreach ($p in @($ueaS.Value | Where-Object { -not $_['isBuiltIn'] })) { $null = Add-Item -Area $AreaName -Kind 'Endpoint analytics device scope' -Raw $p -Name ([string]$p['deviceScopeName']) -Backup 'Endpoint analytics' } }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- Entra ID dependencies -------------------------------------------------------------
    try {
        $AreaName = 'Entra ID dependencies'
        Add-Section $AreaName 'Conditional Access policies that rely on Intune: require a compliant / hybrid-joined device, an approved app or app protection, or filter on device properties.'
        $ca = Invoke-TenantRead 'v1.0/identity/conditionalAccess/policies' -Paged
        if ($ca.Ok) {
            $intuneCtl = @('compliantDevice', 'domainJoinedDevice', 'approvedApplication', 'compliantApplication')
            # policies on the Intune / Intune Enrollment cloud apps gate enrollment itself (MFA,
            # terms of use, location) - a rebuild that misses them breaks enrollment
            $intuneApps = @{ '0000000a-0000-0000-c000-000000000000' = 'Microsoft Intune'; 'd4ebce55-015a-49b5-a083-c84d1797ae8c' = 'Microsoft Intune Enrollment' }
            $appName = { param($id) $(if ($intuneApps.ContainsKey([string]$id)) { $intuneApps[[string]$id] } else { [string]$id }) }
            $locNames = @{}
            $agreementNames = @{}
            foreach ($p in $ca.Value) {
                $gc = Get-Prop $p 'grantControls'
                $ctl = @(Get-PropList $gc 'builtInControls' | ForEach-Object { [string]$_ })
                $cond = Get-Prop $p 'conditions'
                $df = Get-Prop (Get-Prop $cond 'devices') 'deviceFilter'
                $hit = @($ctl | Where-Object { $intuneCtl -contains $_ })
                $caApps = Get-Prop $cond 'applications'
                $appRefs = @(@(Get-PropList $caApps 'includeApplications') + @(Get-PropList $caApps 'excludeApplications') | Where-Object { $intuneApps.ContainsKey([string]$_) })
                if (-not $hit.Count -and -not $df -and -not $appRefs.Count) { continue }
                $users = Get-Prop $cond 'users'
                $inc = @(Get-PropList $users 'includeGroups' | ForEach-Object { [string]$_ }); $excl = @(Get-PropList $users 'excludeGroups' | ForEach-Object { [string]$_ })
                Resolve-GroupNames -Ids @($inc + $excl)
                foreach ($g in $inc) { Add-GroupRef $g ([string]$p['displayName']) 'Conditional Access' 'Include' }
                foreach ($g in $excl) { Add-GroupRef $g ([string]$p['displayName']) 'Conditional Access' 'Exclude' }
                $iu = @(Get-PropList $users 'includeUsers' | ForEach-Object { [string]$_ })
                $apps = $caApps
                $strength = [string](Get-Prop (Get-Prop $gc 'authenticationStrength') 'displayName')
                $rows = @(New-Row 'Grant controls' ((@($ctl | ForEach-Object { ConvertTo-FriendlyName $_ }) + @($(if ($strength) { "authentication strength '$strength'" }))) -join (' ' + (Get-Prop $gc 'operator') + ' ')) 'Policy') +
                    @(New-Row 'Users' $(if ($iu -contains 'All') { 'All users' } else { "{0} user(s), {1} group(s)" -f @($iu | Where-Object { $_ -ne 'None' }).Count, $inc.Count }) 'Assignments') +
                    @(New-Row 'Include groups' ((@($inc | ForEach-Object { Get-GroupName $_ })) -join ', ') 'Assignments') +
                    @(New-Row 'Exclude groups' ((@($excl | ForEach-Object { Get-GroupName $_ })) -join ', ') 'Assignments') +
                    @(New-Row 'Cloud apps' ((@(Get-PropList $apps 'includeApplications' | ForEach-Object { & $appName $_ })) -join ', ') 'Assignments') +
                    @(New-Row 'Excluded cloud apps' ((@(Get-PropList $apps 'excludeApplications' | ForEach-Object { & $appName $_ })) -join ', ') 'Assignments') +
                    @(New-Row 'Platforms' ((@(Get-PropList (Get-Prop $cond 'platforms') 'includePlatforms')) -join ', ') 'Conditions') +
                    @(New-Row 'Device filter' $(if ($df) { "{0}: {1}" -f (Get-Prop $df 'mode'), (Get-Prop $df 'rule') } else { '' }) 'Conditions')
                # locations / terms of use are ids that do not exist in a rebuilt tenant: name them
                $loc = Get-Prop $cond 'locations'
                $locIds = @(@(Get-PropList $loc 'includeLocations') + @(Get-PropList $loc 'excludeLocations') | ForEach-Object { [string]$_ } | Where-Object { $_ -and $_ -notin @('All', 'AllTrusted') -and -not $locNames.ContainsKey($_) })
                foreach ($lid in $locIds) {
                    $lr = Invoke-TenantRead ("v1.0/identity/conditionalAccess/namedLocations/{0}" -f $lid)
                    $locNames[$lid] = $(if ($lr.Ok) { [string]$lr.Value['displayName'] } else { $lid })
                    if ($lr.Ok) { Save-RsopBackupItem -Area 'Conditional Access (Intune-related)' -Item $lr.Value -Name ("Named location - {0}" -f $lr.Value['displayName']) }
                }
                $locName = { param($id) $(switch ([string]$id) { 'All' { 'Any location' } 'AllTrusted' { 'All trusted locations' } default { if ($locNames[[string]$id]) { $locNames[[string]$id] } else { [string]$id } } }) }
                $rows += New-Row 'Locations' ((@(Get-PropList $loc 'includeLocations' | ForEach-Object { & $locName $_ })) -join ', ') 'Conditions'
                $rows += New-Row 'Excluded locations' ((@(Get-PropList $loc 'excludeLocations' | ForEach-Object { & $locName $_ })) -join ', ') 'Conditions'
                $rows += New-Row 'Client apps' ((@(Get-PropList $cond 'clientAppTypes')) -join ', ') 'Conditions'
                $rows += New-Row 'Sign-in risk' ((@(Get-PropList $cond 'signInRiskLevels')) -join ', ') 'Conditions'
                $agreementIds = @(Get-PropList $gc 'termsOfUse' | ForEach-Object { [string]$_ } | Where-Object { $_ })
                foreach ($aid in $agreementIds) {
                    if ($agreementNames.ContainsKey($aid)) { continue }
                    $agreement = Invoke-TenantRead ("v1.0/identityGovernance/termsOfUse/agreements/{0}?`$expand=files" -f $aid)
                    if ($agreement.Ok) {
                        $ar = Get-Single $agreement
                        $agreementNames[$aid] = $(if ($ar['displayName']) { [string]$ar['displayName'] } else { $aid })
                        $arows = @(Convert-LegacyProperties -Policy $ar -Category 'Agreement' -Skip @('files'))
                        foreach ($af in @(Get-PropList $ar 'files')) { $arows += New-Row ([string](Get-Prop $af 'fileName')) ("{0}{1}" -f (Get-Prop $af 'language'), $(if (Get-Prop $af 'isDefault') { ' (default)' } else { '' })) 'Agreement files' }
                        $null = Add-Item -Area $AreaName -Kind 'Terms of use agreement' -Raw $ar -Rows $arows -Backup 'Conditional Access (Intune-related)'
                    }
                    else {
                        $agreementNames[$aid] = "$aid (not captured)"
                        Add-RsopReadProblem ("Terms of use agreement '{0}' was not captured ({1})." -f $aid, $agreement.Code)
                        Add-Finding 'warn' $AreaName ("Terms of use agreement {0} was not captured" -f $aid) 'Record its name, acceptance and expiry settings and original files by hand. Agreement.Read.All supports delegated access only and the signed-in user needs a supported Entra role.'
                    }
                }
                $rows += New-Row 'Terms of use' ((@($agreementIds | ForEach-Object { $agreementNames[$_] })) -join ', ') 'Policy'
                $sc = Get-Prop $p 'sessionControls'
                $scOn = @(foreach ($k in @('applicationEnforcedRestrictions', 'cloudAppSecurity', 'signInFrequency', 'persistentBrowser', 'continuousAccessEvaluation', 'disableResilienceDefaults')) {
                        $v = Get-Prop $sc $k; if ($v -and ((Get-Prop $v 'isEnabled') -ne $false)) { ConvertTo-FriendlyName $k } })
                $rows += New-Row 'Session controls' ($scOn -join ', ') 'Policy'
                $stt = [string]$p['state']
                $null = Add-Item -Area $AreaName -Kind 'Conditional Access policy' -Raw $p -Rows $rows -State $(switch ($stt) { 'enabled' { 'On' } 'disabled' { 'Off' } 'enabledForReportingButNotEnforced' { 'Report-only' } default { $stt } }) `
                    -Health $(if ($stt -eq 'enabled') { 'ok' } else { 'info' }) -Backup 'Conditional Access (Intune-related)'
            }
        }
        else { Add-NotInUse 'Conditional Access policies' $ca 'Policy.Read.All' }

        # Entra company branding: Autopilot OOBE shows it, and 'hide change account options'
        # in an Autopilot profile only works with branding configured
        $br0 = Invoke-TenantRead ("v1.0/organization/{0}/branding" -f $tenantId)
        $hidesAccountChange = @($Corpus.policies | Where-Object { $_.Family -eq 'autopilot' } | ForEach-Object { $_.Settings } |
                Where-Object { [string]$_.Value -match '"(escapeLinkHidden|hideEscapeLink)"\s*:\s*true' }).Count -gt 0
        if ($br0.Ok) {
            $locs = Invoke-TenantRead ("v1.0/organization/{0}/branding/localizations" -f $tenantId) -Paged
            $rows = @(Convert-LegacyProperties -Policy (Get-Single $br0) -Category 'Default branding' -Skip @('cdnList', 'backgroundImage', 'bannerLogo', 'squareLogo', 'squareLogoDark', 'favicon', 'headerLogo'))
            foreach ($l in @($locs.Value)) {
                if ($l['id'] -and $l['id'] -ne '0') { $rows += New-Row ("Localized ({0})" -f $l['id']) ((@($l['signInPageText'], $l['usernameHintText']) | Where-Object { $_ }) -join ' · ') 'Localizations' }
            }
            $null = Add-Item -Area $AreaName -Kind 'Entra company branding' -Name 'Company branding (sign-in / Autopilot OOBE)' -Rows $rows -State 'Configured' -Health 'ok' `
                -Raw (Get-Single $br0) -Backup 'Entra company branding' -BackupExtra @{ localizations = (ConvertTo-RsopList $locs.Value) } `
                -Note 'Logos and background images are separate downloads - keep the original image files.'
        }
        elseif ($br0.Code -eq 404) {
            $null = Add-Item -Area $AreaName -Kind 'Entra company branding' -Name 'Company branding (sign-in / Autopilot OOBE)' -Rows @() -State 'Not configured' -Health $(if ($hidesAccountChange) { 'warn' } else { 'info' })
            if ($hidesAccountChange) { Add-Finding 'warn' $AreaName 'An Autopilot profile hides the change-account options, but Entra company branding is not configured' 'Microsoft documents that this option needs company branding in Microsoft Entra ID.' }
        }
        else { Add-NotInUse 'Entra company branding' $br0 'Organization.Read.All' }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # ---- enrolled devices ------------------------------------------------------------------
    try {
        $AreaName = 'Enrolled devices'
        Add-Section $AreaName 'The managed-device inventory: what has to re-enroll after a disaster, and per-device facts admins set by hand (ownership, category, primary user). The full list is in the backup.'
        # counted page by page: only a backup keeps the per-device list (a large tenant's full
        # inventory would otherwise sit in memory just to be counted)
        $dims = @(@('operatingSystem', 'Operating system'), @('managedDeviceOwnerType', 'Ownership'), @('joinType', 'Join type'), @('deviceEnrollmentType', 'Enrollment type'),
            @('enrollmentProfileName', 'Enrollment profile'), @('deviceCategoryDisplayName', 'Device category'), @('complianceState', 'Compliance'), @('managementAgent', 'Management agent'))
        # raw values are counted per page; each distinct value is worded once at the end
        $tally = @{}; foreach ($dim in $dims) { $tally[$dim[0]] = [System.Collections.Generic.Dictionary[string, int]]::new([System.StringComparer]::Ordinal) }
        $kept = [System.Collections.Generic.List[object]]::new()
        $cnt = @{ Devices = 0; Stale = 0 }
        $countPage = {
            param($PageItems)
            foreach ($d in $PageItems) {
                if ($d -isnot [System.Collections.IDictionary]) { continue }
                $cnt.Devices++
                foreach ($dim in $dims) {
                    $v = [string]$d[$dim[0]]
                    $t0 = $tally[$dim[0]]
                    if ($t0.ContainsKey($v)) { $t0[$v]++ } else { $t0[$v] = 1 }
                }
                $d0 = ConvertTo-GraphDateTime $d['lastSyncDateTime']
                if ($d0.Year -gt 2000 -and $d0.Year -lt 9000 -and ($now - $d0).TotalDays -gt 90) { $cnt.Stale++ }
                if ($script:BackupRoot) { [void]$kept.Add($d) }
            }
        }
        $mdSelect = $(if ($script:BackupRoot) { 'id,deviceName,serialNumber,operatingSystem,osVersion,userPrincipalName,managedDeviceOwnerType,deviceCategoryDisplayName,joinType,enrollmentProfileName,deviceEnrollmentType,complianceState,lastSyncDateTime,model,manufacturer,azureADDeviceId,autopilotEnrolled,managementAgent' }
            else { 'id,operatingSystem,managedDeviceOwnerType,deviceCategoryDisplayName,joinType,enrollmentProfileName,deviceEnrollmentType,complianceState,lastSyncDateTime,managementAgent' })
        $md = Invoke-TenantRead ('beta/deviceManagement/managedDevices?$select={0}&$top=999' -f $mdSelect) -Paged -OnPage $countPage
        if ($md.Ok) {
            $devCount = $cnt.Devices
            $partial = $md.ErrorCode -eq 'IncompleteRead'
            if ($script:BackupRoot -and $kept.Count) {
                $deviceBackup = @{ id = 'managedDevices'; value = $kept.ToArray() }
                if ($partial) { $deviceBackup['@intuneLens.collectionIncomplete'] = $md.Uri }
                Save-RsopBackupItem -Area 'Enrolled devices' -Name 'Managed devices' -Item $deviceBackup
            }
            $rows = [System.Collections.Generic.List[object]]::new()
            foreach ($dim in $dims) {
                $byLabel = @{}
                foreach ($raw in $tally[$dim[0]].Keys) {
                    $label = $(if ($raw) { ConvertTo-DeviceLabel $raw } else { '(none)' })
                    $byLabel[$label] = [int]$byLabel[$label] + $tally[$dim[0]][$raw]
                }
                # most first; ties in name order (the same on every run)
                foreach ($k in @($byLabel.Keys | Sort-Object @{ Expression = { $byLabel[$_] }; Descending = $true }, @{ Expression = { $_ } })) {
                    [void]$rows.Add([pscustomobject]@{ Setting = $k; Value = [string]$byLabel[$k]; Category = $dim[1] })
                }
            }
            if ($cnt.Stale) { [void]$rows.Add([pscustomobject]@{ Setting = 'Not synced for 90+ days'; Value = [string]$cnt.Stale; Category = 'Health' }) }
            $deviceName = $(if ($partial) { "Managed devices ($devCount captured, partial)" } else { "Managed devices ($devCount)" })
            $deviceState = "{0} device{1}{2}" -f $devCount, $(if ($devCount -eq 1) { '' } else { 's' }), $(if ($partial) { ' captured (partial inventory)' } else { '' })
            $note = 'Counts per operating system, ownership, join / enrollment type, category and compliance; the backup has the per-device list (name, serial, user, ownership, category).'
            if ($partial) { $note = 'Only captured pages are counted; these are not complete tenant totals. Retry with -Refresh. ' + $note }
            $null = Add-Item -Area $AreaName -Kind 'Managed devices' -Name $deviceName -Rows $rows.ToArray() -State $deviceState -Health $(if ($partial) { 'warn' } else { 'info' }) -Note $note
        }
        else { Add-NotInUse 'Managed devices' $md 'DeviceManagementManagedDevices.Read.All' }
    } catch { Add-Finding 'warn' 'Tenant setup' ("Section '{0}' is incomplete - reading it stopped with: {1}" -f $AreaName, (Format-RsopError $_)) 'Re-run with -Refresh; the rest of the tenant setup view is complete.' }

    # capture gaps of reads no section named: list them too, so no unread area passes silently
    foreach ($gap in @($script:CaptureGaps)) {
        if ($reportedGaps.Contains([string]$gap.Uri)) { continue }
        Add-NotInUse ("Graph: {0}" -f (([string]$gap.Uri -replace '^(beta|v1\.0)/', '') -replace '\?.*$', '')) $gap ''
    }
    if ($notInUse.Count) {
        $null = Add-Item -Area 'Connectors and integrations' -Kind 'Status' -Name 'Capture gaps and unavailable features' -Rows $notInUse.ToArray() -State ("{0} feature{1}" -f $notInUse.Count, $(if ($notInUse.Count -eq 1) { '' } else { 's' })) -Health 'warn' `
            -Note 'Expected for features this tenant does not use or license; a 403 can also mean the token lacks the permission named.'
    }

    # ---- groups, filters, assignments ------------------------------------------------------
    $usage = @{}
    $addUse = {
        param([string]$Gid, [string]$Name, [string]$Kind, [string]$Mode, [string]$Id = '')
        if (-not $Gid) { return }
        if (-not $usage.ContainsKey($Gid)) { $usage[$Gid] = [System.Collections.Generic.List[object]]::new() }
        [void]$usage[$Gid].Add([pscustomobject]@{ Name = $Name; Kind = $Kind; Mode = $Mode; Id = $Id })
    }
    foreach ($p in @($Corpus.policies)) {
        foreach ($a in @($p.Assignments)) { if ($a.GroupId) { & $addUse ([string]$a.GroupId) $p.Name $p.FamilyLabel $(if ([string]$a.Type -like '*exclusion*') { 'Exclude' } else { 'Include' }) $p.Id } }
        foreach ($g in @($p.ExtraGroupRefs)) { & $addUse ([string]$g) $p.Name 'Compliance notification (CC)' 'Include' $p.Id }
    }
    foreach ($ap in @($Corpus.apps)) {
        foreach ($a in @($ap.Assignments)) {
            if (-not $a.GroupId) { continue }
            $il = $script:IntentLabels[[string]$a.Intent]
            & $addUse ([string]$a.GroupId) $ap.Name ("App ({0})" -f $(if ($il) { $il } else { 'assignment' })) $(if ([string]$a.Type -like '*exclusion*') { 'Exclude' } else { 'Include' }) $ap.Id
        }
    }
    foreach ($sec in $sections.Keys) {
        foreach ($it in $sections[$sec]) {
            foreach ($a in @($it.Asg)) { if ($a.GroupId) { & $addUse ([string]$a.GroupId) $it.Name $it.Kind $(if ([string]$a.Type -like '*exclusion*') { 'Exclude' } else { 'Include' }) $it.Id } }
        }
    }
    foreach ($r in $refs) { & $addUse $r.GroupId $r.Name $r.Kind $r.Mode }
    Resolve-GroupNames -Ids @($usage.Keys)
    foreach ($sec in $sections.Keys) {
        foreach ($it in $sections[$sec]) {
            if (@($it.Asg).Count) {
                $it.Assignment = ConvertTo-AssignmentSummary -Assignments $it.Asg
                $it.AssignmentDetail = @(ConvertTo-AssignmentDetail -Assignments $it.Asg)
            }
            elseif ($it.AsgUnreadable) {
                $it.Assignment = 'Assignments could not be read (see warnings)'
                if ($it.State -eq 'Not assigned') { $it.State = 'Unknown'; $it.Health = 'warn' }
            }
        }
    }
    # Members of Assigned (static) groups are the only record of who / what was in a pilot,
    # ring or exclusion group; owners matter too (Autopilot device preparation needs the
    # 'Intune Provisioning Client' as owner of its device group). Batched. A backup keeps every
    # member; otherwise only the count and the nested groups are read (an assigned group can
    # hold hundreds of thousands of users).
    $memberInfo = @{}
    $memberCounts = @{}
    $advanced = @{ ConsistencyLevel = 'eventual' }
    $visitedGroups = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $frontier = @($usage.Keys)
    $maxNestedDepth = 20
    for ($depth = 0; $frontier.Count -and $depth -le $maxNestedDepth; $depth++) {
        Resolve-GroupNames -Ids $frontier
        $memberUrls = @{}
        $countUrls = @{}
        $nestedUrls = @{}
        foreach ($gid in $frontier) {
            if (-not $visitedGroups.Add($gid) -or -not $script:GroupInfoCache.ContainsKey($gid)) { continue }
            if (-not $script:GroupInfoCache[$gid].Dynamic) {
                if ($script:BackupRoot) { $memberUrls[('/groups/{0}/members?$select=id,displayName,userPrincipalName,deviceId&$top=999' -f $gid)] = @($gid, 'members') }
                else {
                    $countUrls[('/groups/{0}/members?$count=true&$select=id&$top=1' -f $gid)] = $gid
                    $nestedUrls[('/groups/{0}/members/microsoft.graph.group?$count=true&$select=id,displayName&$top=999' -f $gid)] = @($gid, 'members')
                }
            }
            $memberUrls[('/groups/{0}/owners?$select=id,displayName,userPrincipalName,appId' -f $gid)] = @($gid, 'owners')
        }
        $next = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        if ($countUrls.Count) {
            $cb = Invoke-RsopBatch -Urls @($countUrls.Keys) -Activity 'Group member counts' -Headers $advanced -FirstPageOnly
            foreach ($u in $countUrls.Keys) {
                $b = $cb[$u]
                $c = -1
                if ($b -is [System.Collections.IDictionary] -and $null -ne $b['@odata.count'] -and [int]::TryParse([string]$b['@odata.count'], [ref]$c)) { $memberCounts[$countUrls[$u]] = $c }
                else { Add-RsopReadProblem ("Could not count the members of group '{0}' - shown without a count." -f $script:GroupInfoCache[$countUrls[$u]].Name) }
            }
        }
        $mb = @{}
        if ($nestedUrls.Count) {
            $got = Invoke-RsopBatch -Urls @($nestedUrls.Keys) -Activity 'Nested groups' -Headers $advanced
            foreach ($u in $nestedUrls.Keys) { $mb[$u] = $got[$u] }
        }
        if ($memberUrls.Count) {
            $got = Invoke-RsopBatch -Urls @($memberUrls.Keys) -Activity 'Group members and owners'
            foreach ($u in $memberUrls.Keys) { $mb[$u] = $got[$u] }
        }
        foreach ($u in $nestedUrls.Keys) { $memberUrls[$u] = $nestedUrls[$u] }
        if ($memberUrls.Count) {
            foreach ($u in $memberUrls.Keys) {
                $b = $mb[$u]
                $gid0, $kind0 = $memberUrls[$u]
                if ($b -isnot [System.Collections.IDictionary]) {
                    $what = $(if ($nestedUrls.ContainsKey($u)) { 'nested groups' } else { $kind0 })
                    Add-RsopReadProblem ("Could not read the {0} of group '{1}' - not in the report or backup." -f $what, $script:GroupInfoCache[$gid0].Name)
                    continue
                }
                # a cast read (members/microsoft.graph.group) may leave out @odata.type
                $castType = $(if ($nestedUrls.ContainsKey($u)) { 'group' } else { '' })
                if (-not $memberInfo.ContainsKey($gid0)) { $memberInfo[$gid0] = @{} }
                $memberInfo[$gid0][$kind0] = ConvertTo-RsopList (@($b['value']) | Where-Object { $_ } | ForEach-Object {
                        $ty = (([string]$_['@odata.type']) -replace '#microsoft.graph.', '')
                        [ordered]@{ type = $(if ($ty) { $ty } else { $castType }); id = [string]$_['id']; displayName = [string]$_['displayName']
                            userPrincipalName = [string]$_['userPrincipalName']; deviceId = [string]$_['deviceId']; appId = [string]$_['appId'] } })
                if ($b['@intuneLens.truncated']) { $memberInfo[$gid0]["$kind0.truncated"] = $true }
                if ($kind0 -eq 'members') {
                    foreach ($nested in @($memberInfo[$gid0]['members'] | Where-Object { $_['type'] -eq 'group' -and $_['id'] })) {
                        $nid = [string]$nested['id']
                        & $addUse $nid $script:GroupInfoCache[$gid0].Name 'Nested group' 'Member' $gid0
                        if (-not $visitedGroups.Contains($nid)) { [void]$next.Add($nid) }
                    }
                }
            }
        }
        $frontier = @($next | ForEach-Object { $_ })
    }
    if ($frontier.Count) { Add-RsopReadProblem ("Nested group capture stopped at depth {0}; record these remaining group definitions and members separately: {1}" -f $maxNestedDepth, ($frontier -join ', ')) }
    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($gid in $usage.Keys) {
        $gi = $script:GroupInfoCache[$gid]
        $missing = $script:GroupMissing.Contains($gid)
        $mi0 = $memberInfo[$gid]
        if ($script:BackupRoot -and $gi) {
            Save-RsopBackupItem -Area 'Groups used by Intune' -Name $gi.Name -Item ([ordered]@{
                    id = $gid; displayName = $gi.Name; description = $gi.Desc; dynamic = $gi.Dynamic; membershipRule = $gi.Rule; membershipRuleProcessingState = $gi.RuleState
                    securityEnabled = $gi.Security; mailEnabled = $gi.MailEnabled; onPremisesSyncEnabled = $gi.Synced; isAssignableToRole = $gi.RoleAssignable
                    # null = not read (dynamic: the rule is the record) - [] = read, and empty
                    members = $(if ($mi0 -and $mi0.ContainsKey('members')) { , (ConvertTo-RsopList $mi0['members']) } else { $null })
                    membersComplete = $(if ($mi0 -and $mi0.ContainsKey('members')) { -not $mi0['members.truncated'] } elseif ($gi.Dynamic) { 'dynamic group - members come from membershipRule' } else { 'not readable' })
                    owners = $(if ($mi0 -and $mi0.ContainsKey('owners')) { , (ConvertTo-RsopList $mi0['owners']) } else { $null })
                    usedBy = @($usage[$gid] | ForEach-Object { "{0} ({1}, {2})" -f $_.Name, $_.Kind, $_.Mode })
                })
        }
        $membership = ''
        if ($gi) {
            $membership = $(if ($gi.Dynamic) { $(if ($gi.Rule -match '^\W*device\.') { 'Dynamic (devices)' } else { 'Dynamic (users)' }) } else { 'Assigned' })
            if ($gi.Unified) { $membership = "Microsoft 365 group - $membership" }
            elseif (-not $gi.Security) { $membership = "Distribution - $membership" }
        }
        $used = @($usage[$gid] | Sort-Object Kind, Name, Mode, Id -Unique)
        [void]$groups.Add([pscustomobject]@{
            Id = $gid; Name = $(if ($gi) { $gi.Name } elseif ($missing) { "(deleted group) $gid" } else { Get-GroupName $gid })
            Membership = $(if ($missing) { 'Not found in the directory' } else { $membership })
            Rule = $(if ($gi) { $gi.Rule } else { '' }); RuleState = $(if ($gi) { $gi.RuleState } else { '' })
            Synced = $(if ($gi) { $gi.Synced } else { $false }); RoleAssignable = $(if ($gi) { $gi.RoleAssignable } else { $false })
            Desc = $(if ($gi) { $gi.Desc } else { '' }); Created = $(if ($gi) { $gi.Created } else { '' })
            MemberCount = $(if ($memberCounts.ContainsKey($gid)) { $memberCounts[$gid] } elseif ($script:BackupRoot -and $mi0 -and $mi0.ContainsKey('members')) { $(if ($mi0['members.truncated']) { "{0}+ (incomplete read)" -f @($mi0['members']).Count } else { @($mi0['members']).Count }) } else { '' })
            Owners = @($(if ($mi0 -and $mi0['owners']) { @($mi0['owners']) | ForEach-Object { $(if ($_.userPrincipalName) { $_.userPrincipalName } else { $_.displayName }) } }))
            Missing = $missing; UsedBy = $used
        })
        # groups Intune fills at enrollment are empty by design until devices enroll
        $fillsAtEnrollment = @($used | Where-Object { $_.Kind -in @('Enrollment-time group', 'ADE profile (enrollment-time group)') }).Count -gt 0 -or
            @($(if ($mi0) { $mi0['owners'] }) | Where-Object { $_ -and $_['appId'] -eq $script:ProvisioningClientAppId }).Count -gt 0
        $isEmpty = $(if ($memberCounts.ContainsKey($gid)) { $memberCounts[$gid] -eq 0 } else { $script:BackupRoot -and $mi0 -and $mi0.ContainsKey('members') -and @($mi0['members']).Count -eq 0 })
        if ($gi -and -not $gi.Dynamic -and -not $fillsAtEnrollment -and $isEmpty) {
            Add-Finding 'info' 'Groups' ("Assigned group '{0}' has no members" -f $gi.Name) ("Its assignments reach nobody: {0}" -f ((@($usage[$gid] | ForEach-Object { $_.Name } | Select-Object -Unique)) -join ', '))
        }
    }
    $missingGroups = @($groups | Where-Object { $_.Missing })
    if ($missingGroups.Count) {
        $detail = ((@($missingGroups | ForEach-Object { "{0} - used by {1}" -f $_.Id, ((@($_.UsedBy | ForEach-Object { $_.Name } | Select-Object -Unique)) -join ', ') })) -join "`n") +
            "`nRestore the group from the Entra recycle bin (30 days, keeps the id) or re-point the assignments."
        Add-Finding 'bad' 'Groups' ("{0} deleted group{1} still referenced by assignments or settings" -f $missingGroups.Count, $(if ($missingGroups.Count -eq 1) { ' is' } else { 's are' })) $detail
    }
    $paused = @($groups | Where-Object { $_.RuleState -eq 'Paused' })
    if ($paused.Count) { Add-Finding 'warn' 'Groups' ("Dynamic membership is paused on {0} group(s)" -f $paused.Count) ((@($paused | ForEach-Object { $_.Name })) -join ', ') }

    $fuse = @{}
    foreach ($p in @(@($Corpus.policies) + @($Corpus.apps))) {
        foreach ($a in @($p.Assignments)) {
            if ($a.FilterId -and $a.FilterType -and $a.FilterType -ne 'none') {
                if (-not $fuse.ContainsKey([string]$a.FilterId)) { $fuse[[string]$a.FilterId] = [System.Collections.Generic.List[object]]::new() }
                [void]$fuse[[string]$a.FilterId].Add([pscustomobject]@{ Name = $p.Name; Kind = $(if ($p.FamilyLabel) { $p.FamilyLabel } else { 'App' }); Mode = (ConvertTo-FriendlyName ([string]$a.FilterType)); Id = [string]$p.Id })
            }
        }
    }
    $filters = @(@($Corpus.filters) | ForEach-Object {
            [pscustomobject]@{
                Id = $_.Id; Name = $_.Name; Platform = $_.Platform; Rule = $_.Rule; Desc = [string]$_.Desc
                ManagementType = [string]$_.ManagementType; Modified = [string]$_.Modified
                UsedBy = @($(if ($fuse.ContainsKey([string]$_.Id)) { $fuse[[string]$_.Id] | Sort-Object Name, Kind, Mode, Id -Unique } else { @() }))
            } })

    # ---- recovery checklist: what Graph cannot hand back -----------------------------------
    $pkgApps = @($Corpus.apps | Where-Object { @($_.Info | Where-Object { $_.Label -like 'Package file*' }).Count })
    if ($pkgApps.Count) {
        $detail = ((@($pkgApps | Select-Object -First 25 | ForEach-Object { "{0} - {1}" -f $_.Name, (@($_.Info | Where-Object { $_.Label -like 'Package file*' })[0].Value) })) -join "`n") +
            $(if ($pkgApps.Count -gt 25) { "`n... and $($pkgApps.Count - 25) more" } else { '' })
        Add-Finding 'info' 'Apps' ("Keep the installer packages of {0} app{1} - Graph cannot download app content" -f $pkgApps.Count, $(if ($pkgApps.Count -eq 1) { '' } else { 's' })) $detail
    }
    if ($script:ContainsDecryptedSecrets) {
        $dec = @($script:DecryptedOmaSettings)
        Add-Finding 'warn' 'Security' ("Custom OMA-URI values are shown decrypted{0}" -f $(if ($dec.Count) { " ({0})" -f $dec.Count } else { '' })) `
            ("Intune encrypts every custom OMA-URI string value; this report and any backup show them in plain text{0}. If one of them is a password, key or token, store the report and backup like a password vault export." -f $(if ($dec.Count) { ":`n" + ($dec -join "`n") + "`n" } else { '' }))
    }
    Add-Finding 'info' 'Not in Graph' 'Record configuration outside this Graph export by hand' `
        'This export does not capture: device enrollment managers; Apple Configurator profiles; Google zero-touch / Samsung Knox configurations; the policy-to-group mappings for Autopilot device preparation / enrollment-time grouping; Office app cloud policies (config.office.com); Windows Autopatch groups and release settings; Intune diagnostic settings in Azure Monitor; Defender portal settings for security settings management. Record these settings and their supporting Azure / vendor resources separately. The enrollment-time groups themselves are listed under Enrollment - Windows and Entra.'
    Add-Finding 'info' 'Restore order' 'Suggested rebuild order' ("1. Tenant switches, consents, Apple / Google / Windows connectors and tokens`n2. Scope tags, custom roles, role assignments`n3. Entra groups and assignment filters (assignments reference both by id)`n4. Building blocks: reusable settings, imported ADMX, compliance scripts, notification templates`n5. Policies, apps and app configurations, then their assignments`n6. Enrollment restrictions, ESP and Autopilot profiles`n7. Multi admin approval policies last")

    $script:TenantPrefetch = @{}
    Complete-RsopProgress -Id 3
    $sevRank = @{ bad = 0; warn = 1; info = 2 }
    $result = [pscustomobject]@{
        Generated = (Get-Date).ToString('o')
        Sections  = @(foreach ($k in $sections.Keys) {
                [pscustomobject]@{
                    Area  = $k
                    Note  = [string]$sectionNotes[$k]
                    Items = @($sections[$k] | ForEach-Object { $o = [ordered]@{}; foreach ($kk in $_.Keys) { if ($kk -notin @('Asg', 'AsgUnreadable')) { $o[$kk] = $_[$kk] } }; [pscustomobject]$o })
                }
            })
        Groups    = @($groups | Sort-Object @{ e = { -not $_.Missing } }, Name)
        Filters   = @($filters | Sort-Object Name)
        # the same order on every run: most severe first, then by area and title
        Findings  = @($findings | Sort-Object @{ e = { $r = $sevRank[[string]$_.Severity]; $(if ($null -eq $r) { 9 } else { $r }) } }, Area, Title, Detail)
        ScopeTags = [pscustomobject]$script:ScopeTagNames
    }
    $Corpus.tenantConfig = $result
    $Corpus.captureGaps = $script:CaptureGaps.ToArray()
    $Corpus.warnings = @(@($Corpus.warnings) + @($script:ReadProblems) | Where-Object { $_ } | Select-Object -Unique)
    Save-CorpusCache -Corpus $Corpus
    $nItems = (@($result.Sections | ForEach-Object { @($_.Items).Count }) | Measure-Object -Sum).Sum
    Write-Good ("Tenant setup: {0} items, {1} groups, {2} filters, {3} checklist entries" -f $nItems, $groups.Count, @($filters).Count, $findings.Count)
    return $result
}

#endregion

#region ---------- device + directory resolution --------------------------------------------

$script:DeviceIndex = $null
# every managed-device field the evaluation, filters and report read - one list for all lookups
$script:ManagedDeviceSelect = 'id,deviceName,serialNumber,azureADDeviceId,userId,userPrincipalName,operatingSystem,osVersion,model,manufacturer,lastSyncDateTime,ownerType,enrollmentProfileName,deviceCategoryDisplayName,joinType,skuFamily,skuNumber,jailBroken,complianceState,managementAgent,enrolledDateTime,deviceEnrollmentType,deviceType,autopilotEnrolled,isEncrypted,managedDeviceOwnerType'

function Get-DeviceIndex {
    # Bulk index of Windows managed devices (used as a fallback and for group/filter modes).
    if ($null -ne $script:DeviceIndex) { return $script:DeviceIndex }
    Write-Info "Building managed-device index (one-time per run)..."
    $sel = $script:ManagedDeviceSelect
    $all = Get-RsopPaged -Uri ("beta/deviceManagement/managedDevices?`$select={0}&`$top=1000" -f $sel) -Activity 'managedDevices index'
    $script:DeviceIndex = @($all)
    Write-Info ("Indexed {0} managed devices" -f @($all).Count)
    return $script:DeviceIndex
}

function Find-ManagedDevices {
    param(
        [ValidateSet('serialNumber', 'deviceName', 'azureADDeviceId')]
        [string]$By,
        [string]$Value
    )
    $sel = $script:ManagedDeviceSelect
    # as typed, then upper-case (serials and names are usually stored that way); only a refused
    # filter falls back to indexing every managed device - a value that simply isn't there doesn't
    try {
        foreach ($v in @($Value, $Value.ToUpperInvariant()) | Select-Object -Unique) {
            $filter = "{0} eq '{1}'" -f $By, ($v -replace "'", "''")
            $uri = "beta/deviceManagement/managedDevices?`$filter={0}&`$select={1}" -f [uri]::EscapeDataString($filter), $sel
            $hits = @(Get-RsopPaged -Uri $uri)
            if ($hits.Count -gt 0) { return $hits }
        }
        if ($null -eq $script:DeviceIndex) { return @() }
    } catch {
        Write-Info ("Server-side filter on {0} not accepted; falling back to full index scan." -f $By)
    }
    $idx = Get-DeviceIndex
    return @($idx | Where-Object { [string](Get-Prop $_ $By) -ieq $Value })
}

function Select-BestEnrollment {
    # Serial/name can match several enrollment records; prefer the most recently synced.
    param($Candidates, [string]$Label)
    $list = @($Candidates | Sort-Object { $d = ConvertTo-GraphDateTime (Get-Prop $_ 'lastSyncDateTime'); if ($d -eq [datetime]::MaxValue) { [datetime]::MinValue } else { $d } } -Descending)
    if ($list.Count -gt 1) {
        Write-Warn2 ("'{0}' matched {1} enrollment records; using most recently synced ({2}). Others are likely stale." -f $Label, $list.Count, (Get-Prop $list[0] 'deviceName'))
    }
    return $list[0]
}

$script:MemberGroupCache = @{}   # 'users/<id>' -> transitive group ids, read once per run (a primary user often owns many devices)

function Get-EntraGroupIds {
    # Transitive group membership for a directory object (device or user). getMemberGroups
    # refuses objects in more than 11,000 groups; those are read from transitiveMemberOf.
    param([string]$DirectoryObjectId, [string]$Kind)
    if (-not $DirectoryObjectId) { return @() }
    $key = "$Kind/$DirectoryObjectId"
    if ($script:MemberGroupCache.ContainsKey($key)) { return $script:MemberGroupCache[$key] }
    try {
        try {
            $resp = Invoke-Rsop -Method POST -Uri ("v1.0/{0}/{1}/getMemberGroups" -f $Kind, $DirectoryObjectId) -Body @{ securityEnabledOnly = $false }
            $ids = [string[]]@($resp['value'] | ForEach-Object { [string]$_ })
        } catch {
            if ((Get-RsopServiceError -ErrorRecord $_).Code -ne 400) { throw }
            $ids = [string[]]@(Get-RsopPaged -Uri ("v1.0/{0}/{1}/transitiveMemberOf/microsoft.graph.group?`$select=id&`$top=999" -f $Kind, $DirectoryObjectId) | ForEach-Object { [string]$_['id'] })
        }
        $script:MemberGroupCache[$key] = $ids
        return $ids
    } catch {
        $message = "Could not read group membership for {0} {1}: {2}" -f $Kind, $DirectoryObjectId, (Format-RsopError $_)
        Add-RunLog -Level error -Message $message
        throw $message
    }
}

$script:GroupNameCache = @{}
$script:GroupInfoCache = @{}   # id -> group definition (type, dynamic rule, sync) for the recovery view
$script:GroupMissing = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)

function Resolve-GroupNames {
    # Names (and definitions) for group ids via directoryObjects/getByIds (read-only query).
    # An id the directory no longer knows is recorded as missing - an assignment to a
    # deleted group.
    param([string[]]$Ids)
    # resolved = defined or known-missing; ids from a failed call are retried on the next call
    # (callers pass every assignment's group id - thousands, mostly repeats: de-dupe in O(n))
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $todo = @(foreach ($id in @($Ids)) {
            if ($id -and -not $script:GroupInfoCache.ContainsKey($id) -and -not $script:GroupMissing.Contains($id) -and $seen.Add($id)) { $id }
        })
    for ($i = 0; $i -lt $todo.Count; $i += 900) {
        $chunk = @($todo[$i..([math]::Min($i + 899, $todo.Count - 1))])
        try {
            $resp = Invoke-Rsop -Method POST -Uri 'v1.0/directoryObjects/getByIds' -Body @{ ids = $chunk; types = @('group') }
            $found = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($o in @($resp['value'])) {
                $gid = [string]$o['id']
                [void]$found.Add($gid)
                $script:GroupNameCache[$gid] = [string]$o['displayName']
                $types = @(Get-PropList $o 'groupTypes' | ForEach-Object { [string]$_ })
                $script:GroupInfoCache[$gid] = [pscustomobject]@{
                    Id          = $gid
                    Name        = [string]$o['displayName']
                    Desc        = [string]$o['description']
                    Dynamic     = ($types -contains 'DynamicMembership')
                    Unified     = ($types -contains 'Unified')
                    Rule        = [string]$o['membershipRule']
                    RuleState   = [string]$o['membershipRuleProcessingState']
                    Security    = [bool]$o['securityEnabled']
                    MailEnabled = [bool]$o['mailEnabled']
                    Synced      = [bool]$o['onPremisesSyncEnabled']
                    RoleAssignable = [bool]$o['isAssignableToRole']
                    Created     = (Format-GraphDate $o['createdDateTime'])
                }
            }
            foreach ($gid in $chunk) { if (-not $found.Contains($gid)) { [void]$script:GroupMissing.Add($gid) } }
        } catch {
            # NOT 'missing' (that would claim deleted groups) - unresolved, retried next call
            Add-RsopReadProblem ("Could not resolve {0} group id(s) through directoryObjects/getByIds: {1}" -f $chunk.Count, (Format-RsopError $_))
        }
    }
    foreach ($id in @($Ids)) {
        if ($id -and $script:GroupMissing.Contains($id)) { $script:GroupNameCache[$id] = "$id (deleted group?)" }
    }
}

function Get-GroupName { param([string]$Id) if ($Id -and $script:GroupNameCache.ContainsKey($Id)) { return $script:GroupNameCache[$Id] } return $Id }

function Get-DeviceContext {
    # Everything needed to evaluate assignments for one managed device.
    param($ManagedDevice)

    $md = $ManagedDevice
    $azId = [string](Get-Prop $md 'azureADDeviceId')
    $dirId = $null
    $deviceGroupsResolved = $true
    if ($azId -and $azId -ne '00000000-0000-0000-0000-000000000000') {
        try {
            $resp = Invoke-Rsop -Uri ("v1.0/devices?`$filter=deviceId eq '{0}'&`$select=id" -f $azId)
            $vals = @($resp['value'])
            if ($vals.Count -gt 0) { $dirId = [string]$vals[0]['id'] }
        } catch {
            $deviceGroupsResolved = $false
            Add-RunLog -Level error -Message ("Could not resolve the Entra device object for '{0}': {1}" -f (Get-Prop $md 'deviceName'), (Format-RsopError $_))
        }
    }
    $deviceGroups = @()
    if ($dirId) {
        try { $deviceGroups = Get-EntraGroupIds -DirectoryObjectId $dirId -Kind 'devices' }
        catch { $deviceGroupsResolved = $false }
    }
    else {
        $deviceGroupsResolved = $false
        Add-RunLog -Level error -Message ("No Entra device object found for '{0}' - device-group targeting cannot be evaluated." -f (Get-Prop $md 'deviceName'))
    }

    $userId = [string](Get-Prop $md 'userId')
    $userGroups = @()
    $userGroupsResolved = $true
    if ($userId -and $userId -ne '00000000-0000-0000-0000-000000000000') {
        try { $userGroups = Get-EntraGroupIds -DirectoryObjectId $userId -Kind 'users' }
        catch { $userGroupsResolved = $false }
    }

    $dg = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $deviceGroups) { [void]$dg.Add($g) }
    $ug = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($g in $userGroups) { [void]$ug.Add($g) }

    return [pscustomobject]@{
        ManagedDevice   = $md
        DirectoryId     = $dirId
        DeviceGroupIds  = $dg
        UserGroupIds    = $ug
        DeviceGroupsResolved = $deviceGroupsResolved
        UserGroupsResolved   = $userGroupsResolved
        HasPrimaryUser  = [bool]($userId -and $userId -ne '00000000-0000-0000-0000-000000000000')
    }
}

#endregion

#region ---------- assignment filter evaluation ----------------------------------------------

$script:FilterEvalCache = @{}
$script:FilterById = @{}
$script:FilterEvalVariant = 0   # remembers which request shape this tenant accepts

function Invoke-FilterEvaluate {
    # Calls /deviceManagement/evaluateAssignmentFilter trying several request shapes,
    # because the endpoint is picky and its response is a Stream with varying envelopes.
    # Returns normalized rows; throws only if every variant fails.
    param($FilterObj, [int]$Top = 100, [int]$Skip = 0, [string]$Search = '')

    $mk = {
        param([bool]$HashPrefix, [bool]$IncludeEmpty)
        $data = [ordered]@{}
        if ($HashPrefix) { $data['@odata.type'] = '#microsoft.graph.assignmentFilterEvaluateRequest' }
        else             { $data['@odata.type'] = 'microsoft.graph.assignmentFilterEvaluateRequest' }
        $data['platform'] = $FilterObj.Platform
        $data['rule']     = $FilterObj.Rule
        $data['top']      = $Top
        $data['skip']     = $Skip
        if ($IncludeEmpty -or $Search) { $data['search'] = $Search }
        if ($IncludeEmpty) { $data['orderBy'] = @() }
        return @{ data = $data }
    }
    # The endpoint answers with a Stream (octet-stream + Content-Disposition) on real
    # tenants, which the SDK refuses to return inline - so temp-file variants go first.
    # variant 1: '#'-prefixed type, omit empty fields, response via temp file
    # variant 2: portal-style body (no '#', always send search/orderBy), temp file
    # variant 3: '#'-prefixed type, parsed inline (works where the answer is plain JSON)
    $variants = @(
        @{ N = 1; Body = (& $mk $true $false);  Stream = $true  },
        @{ N = 2; Body = (& $mk $false $true);  Stream = $true  },
        @{ N = 3; Body = (& $mk $true $false);  Stream = $false }
    )
    if ($script:FilterEvalVariant -gt 0) {
        $variants = @($variants | Sort-Object { $_.N -ne $script:FilterEvalVariant })
    }

    $lastErr = $null
    foreach ($v in $variants) {
        try {
            if ($v.Stream) {
                $resp = Invoke-RsopStream -Uri 'beta/deviceManagement/evaluateAssignmentFilter' -Body $v.Body
            } else {
                $json = $v.Body | ConvertTo-Json -Depth 8
                $resp = Invoke-MgGraphRequest -Method POST -Uri 'beta/deviceManagement/evaluateAssignmentFilter' -Body $json -ContentType 'application/json' -OutputType HashTable
            }
            $rows = ConvertFrom-ReportGrid -Response $resp
            $script:FilterEvalVariant = $v.N
            return @($rows)
        } catch {
            if (Test-RsopRetryable -ErrorRecord $_) { throw }   # still throttled after the retries: another shape won't help
            $lastErr = (Format-RsopError $_)
            Add-SessionLog 'info' ("evaluateAssignmentFilter variant {0} failed for '{1}': {2}" -f $v.N, $FilterObj.Name, $lastErr)
        }
    }
    throw ("all evaluateAssignmentFilter request variants failed; last error: {0}" -f $lastErr)
}

# ---- client-side rule evaluation (fallback when the service call fails) --------------------

function ConvertTo-FilterTokens {
    param([string]$Rule)
    $tokens = [System.Collections.Generic.List[object]]::new()
    $i = 0; $n = $Rule.Length
    while ($i -lt $n) {
        $c = $Rule[$i]
        if ([char]::IsWhiteSpace($c)) { $i++; continue }
        if ($c -eq '"') {
            $sb = New-Object System.Text.StringBuilder
            $i++
            while ($i -lt $n -and $Rule[$i] -ne '"') {
                if ($Rule[$i] -eq '\' -and $i + 1 -lt $n) { [void]$sb.Append($Rule[$i + 1]); $i += 2 }
                else { [void]$sb.Append($Rule[$i]); $i++ }
            }
            if ($i -ge $n) { throw 'unterminated string' }
            $i++
            [void]$tokens.Add(@{ T = 'str'; V = $sb.ToString() })
            continue
        }
        if ('()[],'.Contains($c)) { [void]$tokens.Add(@{ T = [string]$c; V = [string]$c }); $i++; continue }
        $j = $i
        while ($j -lt $n -and -not [char]::IsWhiteSpace($Rule[$j]) -and -not '()[],"'.Contains($Rule[$j])) { $j++ }
        $w = $Rule.Substring($i, $j - $i); $i = $j
        $wl = $w.ToLowerInvariant()
        # Rule syntax allows every operator with or without the dash ('-eq' | 'eq'),
        # including the boolean ones ('-and' | 'and').
        $opNames = @('eq', 'ne', 'in', 'notin', 'startswith', 'notstartswith',
                     'endswith', 'notendswith', 'contains', 'notcontains', 'gt', 'ge', 'lt', 'le')
        $bare = $wl.TrimStart('-')
        if ($bare -in @('and', 'or', 'not')) { [void]$tokens.Add(@{ T = 'kw'; V = $bare }) }
        elseif ($bare -in $opNames) { [void]$tokens.Add(@{ T = 'op'; V = ('-' + $bare) }) }
        elseif ($wl.StartsWith('-')) { [void]$tokens.Add(@{ T = 'op'; V = $wl }) }
        else { [void]$tokens.Add(@{ T = 'id'; V = $w }) }
    }
    return , $tokens.ToArray()
}

# Windows SKU number -> Intune filter operatingSystemSKU value, per
# learn.microsoft.com/intune/fundamentals/filters/ref-device-properties
$script:WinSkuNames = @{
    4 = 'Enterprise'; 27 = 'EnterpriseN'; 48 = 'Professional'; 49 = 'BusinessN'
    72 = 'EnterpriseEval'; 84 = 'EnterpriseNEval'; 98 = 'CoreN'; 99 = 'CoreCountrySpecific'
    100 = 'CoreSingleLanguage'; 101 = 'Core'; 111 = 'Core'; 119 = 'PPIPro'
    121 = 'Education'; 122 = 'EducationN'; 123 = 'IoTUAP'; 125 = 'EnterpriseS'
    126 = 'EnterpriseSN'; 129 = 'EnterpriseSEval'; 131 = 'IoTUAPCommercial'; 136 = 'Holographic'
    138 = 'ProfessionalSingleLanguage'; 161 = 'ProfessionalWorkstation'; 162 = 'ProfessionalN'
    164 = 'ProfessionalEducation'; 165 = 'ProfessionalEducationN'; 171 = 'EnterpriseG'
    172 = 'EnterpriseGN'; 175 = 'ServerRdsh'; 188 = 'IoTEnterprise'
    202 = 'CloudEditionN'; 203 = 'CloudEdition'
}

function Get-FilterDeviceValue {
    # Maps a filter rule property (device.xxx) onto managedDevice fields.
    # Returns $null (not '') when the device data cannot answer the question.
    param([string]$PropRef, $Md)
    $p = ($PropRef -replace '^(?i)device\.', '').ToLowerInvariant()
    switch ($p) {
        'devicename'             { return [string](Get-Prop $Md 'deviceName') }
        'manufacturer'           { return [string](Get-Prop $Md 'manufacturer') }
        'model'                  { return [string](Get-Prop $Md 'model') }
        'osversion'              { return [string](Get-Prop $Md 'osVersion') }
        'operatingsystemversion' { return [string](Get-Prop $Md 'osVersion') }
        'operatingsystemsku'     {
            # The rule compares against SKU *names* (Enterprise, Professional, ...) which
            # correspond to the numeric skuNumber; skuFamily is only a fallback.
            $n = Get-Prop $Md 'skuNumber'
            $ni = 0
            if ($null -ne $n -and [int]::TryParse([string]$n, [ref]$ni) -and $script:WinSkuNames.ContainsKey($ni)) {
                return [string]$script:WinSkuNames[$ni]
            }
            $fam = [string](Get-Prop $Md 'skuFamily')
            if ($fam) { return $fam }
            return $null
        }
        'enrollmentprofilename'  { return [string](Get-Prop $Md 'enrollmentProfileName') }
        'devicecategory'         { return [string](Get-Prop $Md 'deviceCategoryDisplayName') }
        'deviceownership'        {
            $o = [string](Get-Prop $Md 'ownerType')
            if ($o -ieq 'company') { return 'Corporate' }
            if ($o -ieq 'personal') { return 'Personal' }
            return $o
        }
        'devicetrusttype'        {
            # joinType 'azureADJoined' vs rule literal 'Azure AD joined' - Compare-FilterValue
            # normalizes whitespace on both sides for this property.
            return [string](Get-Prop $Md 'joinType')
        }
        'isrooted'               {
            $j = [string](Get-Prop $Md 'jailBroken')
            if ($j) { return $j }
            return $null
        }
        default                  { return $null }
    }
}

function Compare-FilterValue {
    # Single comparison; returns $true/$false, or $null when it cannot be decided.
    # $Prop = normalized rule property name; $RightIsBare = value was an unquoted token
    # (needed to give -eq $null / -eq Null the documented "is empty" semantics).
    param($Left, [string]$Op, $Right, [string]$Prop = '', [bool]$RightIsBare = $false)
    # $null = property unknown to the local evaluator -> undecidable; '' = known-empty -> comparable
    if ($null -eq $Left) { return $null }
    $l = ([string]$Left).Trim().ToLowerInvariant()

    if ($RightIsBare -and ([string]$Right) -match '^\$?null$') {
        switch ($Op) {
            '-eq' { return ($l -eq '') }
            '-ne' { return ($l -ne '') }
            default { return $null }
        }
    }

    # deviceTrustType inventory values have no spaces ('azureADJoined') while rule
    # literals do ('Azure AD joined') - compare that property whitespace-insensitively.
    $norm = { param($x) (([string]$x) -replace '\s', '').ToLowerInvariant() }
    $wsInsensitive = ($Prop -eq 'devicetrusttype')

    switch ($Op) {
        '-eq'            {
            if ($wsInsensitive) { return ((& $norm $Left) -eq (& $norm $Right)) }
            return $l -eq ([string]$Right).Trim().ToLowerInvariant()
        }
        '-ne'            { return -not (Compare-FilterValue -Left $Left -Op '-eq' -Right $Right -Prop $Prop) }
        '-startswith'    { return $l.StartsWith(([string]$Right).ToLowerInvariant()) }
        '-notstartswith' { return -not $l.StartsWith(([string]$Right).ToLowerInvariant()) }
        '-endswith'      { return $l.EndsWith(([string]$Right).ToLowerInvariant()) }
        '-notendswith'   { return -not $l.EndsWith(([string]$Right).ToLowerInvariant()) }
        '-contains'      { return $l.Contains(([string]$Right).ToLowerInvariant()) }
        '-notcontains'   { return -not $l.Contains(([string]$Right).ToLowerInvariant()) }
        '-in'            {
            foreach ($r in @($Right)) {
                if ($wsInsensitive) { if ((& $norm $Left) -eq (& $norm $r)) { return $true } }
                elseif ($l -eq ([string]$r).Trim().ToLowerInvariant()) { return $true }
            }
            return $false
        }
        '-notin'         { return -not (Compare-FilterValue -Left $Left -Op '-in' -Right $Right -Prop $Prop) }
        { $_ -in @('-gt', '-ge', '-lt', '-le') } {
            $lv = $null; $rv = $null
            if ([version]::TryParse([string]$Left, [ref]$lv) -and [version]::TryParse([string]$Right, [ref]$rv)) {
                switch ($Op) { '-gt' { return $lv -gt $rv } '-ge' { return $lv -ge $rv } '-lt' { return $lv -lt $rv } '-le' { return $lv -le $rv } }
            }
            return $null
        }
        default          { return $null }
    }
}

function Test-FilterRuleLocal {
    # Parses and evaluates an Intune filter rule against a managedDevice, entirely locally.
    # Returns $true / $false / $null (couldn't parse or property unavailable).
    param([string]$Rule, $Md)
    try {
        $toks = ConvertTo-FilterTokens -Rule $Rule
        $state = @{ i = 0; t = $toks }

        $peek = { if ($state.i -lt $state.t.Count) { $state.t[$state.i] } else { $null } }
        $take = { $tk = & $peek; $state.i++; $tk }

        # three-valued logic combinators ('fOr' would collide with the 'for' keyword)
        function Merge-TriAnd($a, $b) { if ($a -eq $false -or $b -eq $false) { return $false }; if ($null -eq $a -or $null -eq $b) { return $null }; return $true }
        function Merge-TriOr($a, $b)  { if ($a -eq $true -or $b -eq $true) { return $true };  if ($null -eq $a -or $null -eq $b) { return $null }; return $false }

        $parsePrimary = $null; $parseUnary = $null; $parseAnd = $null; $parseOr = $null

        $parsePrimary = {
            $tk = & $peek
            if ($null -eq $tk) { throw 'unexpected end' }
            if ($tk.T -eq '(') {
                [void](& $take)
                $v = & $parseOr
                $tk2 = & $take
                if ($null -eq $tk2 -or $tk2.T -ne ')') { throw 'expected )' }
                return $v
            }
            if ($tk.T -ne 'id') { throw "expected property, got '$($tk.V)'" }
            [void](& $take)
            $propRef = $tk.V
            $opTok = & $take
            if ($null -eq $opTok -or $opTok.T -ne 'op') { throw 'expected operator' }
            $valTok = & $peek
            $right = $null
            $rightIsBare = $false
            if ($null -ne $valTok -and $valTok.T -eq '[') {
                [void](& $take)
                $list = @()
                while ($true) {
                    $t2 = & $take
                    if ($null -eq $t2) { throw 'unterminated list' }
                    if ($t2.T -eq ']') { break }
                    if ($t2.T -eq ',') { continue }
                    $list += [string]$t2.V
                }
                $right = $list
            } else {
                $t2 = & $take
                if ($null -eq $t2) { throw 'expected value' }
                $right = [string]$t2.V
                $rightIsBare = ($t2.T -eq 'id')
            }
            $prop = ($propRef -replace '^(?i)(device|app)\.', '').ToLowerInvariant()
            $left = Get-FilterDeviceValue -PropRef $propRef -Md $Md
            return (Compare-FilterValue -Left $left -Op $opTok.V -Right $right -Prop $prop -RightIsBare $rightIsBare)
        }
        $parseUnary = {
            $tk = & $peek
            if ($null -ne $tk -and $tk.T -eq 'kw' -and $tk.V -eq 'not') {
                [void](& $take)
                $v = & $parseUnary
                if ($null -eq $v) { return $null }
                return (-not $v)
            }
            return (& $parsePrimary)
        }
        $parseAnd = {
            $v = & $parseUnary
            while ($true) {
                $tk = & $peek
                if ($null -ne $tk -and $tk.T -eq 'kw' -and $tk.V -eq 'and') { [void](& $take); $r = & $parseUnary; $v = Merge-TriAnd $v $r }
                else { break }
            }
            return $v
        }
        $parseOr = {
            $v = & $parseAnd
            while ($true) {
                $tk = & $peek
                if ($null -ne $tk -and $tk.T -eq 'kw' -and $tk.V -eq 'or') { [void](& $take); $r = & $parseAnd; $v = Merge-TriOr $v $r }
                else { break }
            }
            return $v
        }

        $result = & $parseOr
        if ($state.i -lt $state.t.Count) { throw 'trailing tokens' }
        return $result
    } catch {
        return $null
    }
}

$script:FilterMatchSetCache = @{}
$script:DeviceReportShape = 0   # the getConfigurationPoliciesReportForDevice request shape this tenant accepts

function Get-FilterRowIdentity {
    # An id, when supplied, is authoritative; a display name never overrides it.
    param($Row)
    $id = ''; $name = ''
    foreach ($p in @($Row.PSObject.Properties)) {
        if ($p.Name -match '^(deviceid|intunedeviceid)$' -and $p.Value) { $id = [string]$p.Value }
        elseif ($p.Name -match 'devicename' -and $p.Value) { $name = [string]$p.Value }
    }
    return @{ Id = $id; Name = $name }
}

function Test-UniqueManagedDeviceName {
    param([string]$Name, [string]$Id)
    $matched = @(Get-DeviceIndex | Where-Object { [string](Get-Prop $_ 'deviceName') -ieq $Name })
    return ($matched.Count -eq 1 -and [string](Get-Prop $matched[0] 'id') -ieq $Id)
}

function Test-FilterDevicePlatform {
    # A filter's platform is part of its scope. Unknown Android subtypes need service evidence.
    param($FilterObj, $ManagedDevice)
    $platform = ([string]$FilterObj.Platform).ToLowerInvariant()
    $devicePlatform = Get-DevicePlatform -Md $ManagedDevice
    if ($devicePlatform -eq 'other') {
        $sku = 0
        if ([int]::TryParse([string](Get-Prop $ManagedDevice 'skuNumber'), [ref]$sku) -and $script:WinSkuNames.ContainsKey($sku)) { $devicePlatform = 'windows' }
    }
    if ($platform -match 'mobileapplicationmanagement') { return $null }
    $expected = switch -Regex ($platform) {
        '^windows' { 'windows'; break }
        '^macos' { 'macos'; break }
        '^ios' { 'ios'; break }
        '^android' { 'android'; break }
        default { '' }
    }
    if (-not $expected -or $devicePlatform -eq 'other') { return $null }
    if ($expected -ne $devicePlatform) { return $false }
    if ($expected -ne 'android') { return $true }
    $type = [string](Get-Prop $ManagedDevice 'deviceType')
    $enrollment = [string](Get-Prop $ManagedDevice 'deviceEnrollmentType')
    $agent = [string](Get-Prop $ManagedDevice 'managementAgent')
    $aosp = $enrollment -match '^androidAOSP' -or $agent -eq 'intuneAosp'
    $enterprise = $enrollment -match '^androidEnterprise' -or $type -in @('androidForWork', 'androidEnterprise') -or $agent -eq 'googleCloudDevicePolicyController'
    $workProfile = $enrollment -eq 'androidEnterpriseCorporateWorkProfile' -or $type -eq 'androidForWork'
    switch ($platform) {
        'androidaosp' { if ($aosp) { return $true }; if ($enterprise -or $type -eq 'android') { return $false }; return $null }
        'androidforwork' { if ($enterprise) { return $true }; if ($aosp -or $type -eq 'android') { return $false }; return $null }
        'androidworkprofile' { if ($workProfile) { return $true }; if ($aosp -or $enrollment -in @('androidEnterpriseDedicatedDevice', 'androidEnterpriseFullyManaged') -or $type -eq 'android') { return $false }; return $null }
        'android' { if ($aosp -or $enterprise) { return $false }; if ($type -eq 'android') { return $true }; return $null }
        default { return $null }
    }
}

function Get-FilterMatchSet {
    # Fully evaluates a filter server-side (paged) into id/name lookup sets, once per
    # filter per run. Complete=$false means the result was capped, so a device being
    # absent from the set proves nothing.
    param($FilterObj, [int]$Cap = 10000)
    $fid = [string]$FilterObj.Id
    if ($script:FilterMatchSetCache.ContainsKey($fid)) { return $script:FilterMatchSetCache[$fid] }

    $set = $null
    try {
        $ids = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $names = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $skip = 0; $count = 0; $complete = $false
        while ($true) {
            $batch = @(Invoke-FilterEvaluate -FilterObj $FilterObj -Top 100 -Skip $skip)
            foreach ($r in $batch) {
                $count++
                $identity = Get-FilterRowIdentity -Row $r
                if ($identity.Id) { [void]$ids.Add($identity.Id) }
                elseif ($identity.Name) { [void]$names.Add($identity.Name) }
            }
            if ($batch.Count -lt 100) { $complete = $true; break }
            if ($count -ge $Cap) { break }
            $skip += 100
        }
        $set = @{ Ids = $ids; Names = $names; Complete = $complete }
        if (-not $complete) {
            Add-RunLog -Level warn -Message ("Filter '{0}' matches more than {1} devices; absence from the evaluation set is treated as unknown, not as non-match." -f $FilterObj.Name, $Cap)
        }
    } catch {
        Add-RunLog -Level info -Message ("Full server-side evaluation of filter '{0}' failed: {1}" -f $FilterObj.Name, (Format-RsopError $_))
        $set = $null
    }
    $script:FilterMatchSetCache[$fid] = $set
    return $set
}

function Test-DeviceMatchesFilter {
    # Layered: (1) local rule evaluation against live inventory (the server-side report
    # lags enrollment and pages at 100 rows, so a device missing from it proves nothing),
    # (2) server-side evaluateAssignmentFilter scoped by device-name search for positive
    # evidence, (3) full paged server evaluation - absence only counts as non-match when
    # that set is complete. Cached per (filter, device).
    param([string]$FilterId, $ManagedDevice)

    $mdId = [string](Get-Prop $ManagedDevice 'id')
    $mdName = [string](Get-Prop $ManagedDevice 'deviceName')
    $cacheKey = "$FilterId|$mdId"
    if ($script:FilterEvalCache.ContainsKey($cacheKey)) { return $script:FilterEvalCache[$cacheKey] }

    $flt = $null
    if ($script:FilterById.ContainsKey($FilterId)) { $flt = $script:FilterById[$FilterId] }
    if ($null -eq $flt) {
        Add-RunLog -Level warn -Message ("Assignment referenced unknown filter id {0}" -f $FilterId)
        $script:FilterEvalCache[$cacheKey] = 'error'; return 'error'
    }

    $result = 'error'

    # Managed-app filters (app.* properties) are evaluated inside the app at launch - no
    # device inventory can answer them, and evaluateAssignmentFilter doesn't serve them.
    if ([string]$flt.Platform -match 'MobileApplicationManagement') {
        Add-RunLog -Level info -Message ("Filter '{0}' is a managed-app filter (evaluated in the app at runtime); applicability left as unknown." -f $flt.Name)
        $script:FilterEvalCache[$cacheKey] = 'error'
        return 'error'
    }

    $platformMatch = Test-FilterDevicePlatform -FilterObj $flt -ManagedDevice $ManagedDevice
    if ($platformMatch -is [bool] -and -not $platformMatch) {
        $script:FilterEvalCache[$cacheKey] = $false
        return $false
    }
    $local = $(if ($platformMatch -eq $true) { Test-FilterRuleLocal -Rule $flt.Rule -Md $ManagedDevice } else { $null })
    if ($local -is [bool]) {
        Add-SessionLog 'info' ("Filter '{0}' evaluated locally for '{1}': {2}" -f $flt.Name, $mdName, $local)
        $script:FilterEvalCache[$cacheKey] = $local
        return $local
    }
    Add-SessionLog 'info' ("Filter '{0}' rule not locally decidable for '{1}'; asking the service. Rule: {2}" -f $flt.Name, $mdName, $flt.Rule)

    if ($mdName) {
        try {
            $rows = Invoke-FilterEvaluate -FilterObj $flt -Search $mdName
            foreach ($r in @($rows)) {
                $identity = Get-FilterRowIdentity -Row $r
                if ($identity.Id) {
                    if ($identity.Id -ieq $mdId) { $result = $true }
                }
                elseif ($identity.Name -ieq $mdName -and (Test-UniqueManagedDeviceName -Name $mdName -Id $mdId)) { $result = $true }
                if ($result -eq $true) { break }
            }
        } catch {
            Add-RunLog -Level info -Message ("Search-scoped evaluation of filter '{0}' failed ({1})." -f $flt.Name, (Format-RsopError $_))
        }
    }

    if ($result -isnot [bool]) {
        $set = Get-FilterMatchSet -FilterObj $flt
        if ($null -ne $set) {
            if ($mdId -and $set.Ids.Contains($mdId)) { $result = $true }
            elseif ($mdName -and $set.Names.Contains($mdName)) {
                $result = $(if (Test-UniqueManagedDeviceName -Name $mdName -Id $mdId) { $true } else { 'error' })
            }
            elseif ($set.Complete) { $result = $false }
            else { $result = 'error' }
        }
    }

    if ($result -isnot [bool]) {
        Add-RunLog -Level error -Message ("Filter '{0}' could not be conclusively evaluated for '{1}'. Rule: {2}" -f $flt.Name, $mdName, $flt.Rule)
    }
    $script:FilterEvalCache[$cacheKey] = $result
    return $result
}

function Get-FilterMatchedDevices {
    # Full evaluation of a filter -> managed devices (used for -AssignmentFilter mode).
    # Falls back to local rule evaluation across the device index when the service call fails.
    param($FilterObj, [int]$Cap = 0)
    $rows = [System.Collections.Generic.List[object]]::new()
    $skip = 0
    $truncated = $false
    try {
        while ($true) {
            $batch = @(Invoke-FilterEvaluate -FilterObj $FilterObj -Top 100 -Skip $skip)
            foreach ($b in $batch) { [void]$rows.Add($b) }
            if ($batch.Count -lt 100) { break }
            if ($Cap -gt 0 -and $rows.Count -ge $Cap) { $truncated = $true; break }
            $skip += 100
        }
    } catch {
        Write-Warn2 ("Server-side evaluation of filter '{0}' failed ({1}); evaluating the rule locally across the device index." -f $FilterObj.Name, (Format-RsopError $_))
        $idx = Get-DeviceIndex
        $matched = [System.Collections.Generic.List[object]]::new()
        $undecided = 0
        foreach ($d in $idx) {
            $platformMatch = Test-FilterDevicePlatform -FilterObj $FilterObj -ManagedDevice $d
            if ($platformMatch -isnot [bool]) { $undecided++; continue }
            if (-not $platformMatch) { continue }
            $v = Test-FilterRuleLocal -Rule $FilterObj.Rule -Md $d
            if ($v -is [bool]) { if ($v) { [void]$matched.Add($d) } }
            else { $undecided++ }
        }
        if ($undecided -gt 0) {
            Write-Warn2 ("Filter rule could not be evaluated locally for {0} devices; they are not included." -f $undecided)
        }
        if ($Cap -gt 0 -and $matched.Count -gt $Cap) {
            Write-Warn2 ("Filter results capped at {0} devices." -f $Cap)
            return @($matched.ToArray() | Select-Object -First $Cap)
        }
        return $matched.ToArray()
    }
    if ($truncated) {
        while ($rows.Count -gt $Cap) { $rows.RemoveAt($rows.Count - 1) }
        Write-Warn2 ("Filter results capped at {0} devices." -f $Cap)
    }

    # Map preview rows back to managed devices (by id column when present, else by name).
    $idx = Get-DeviceIndex
    $byId = @{}; $byName = @{}
    foreach ($d in $idx) {
        $byId[[string](Get-Prop $d 'id')] = $d
        $name = ([string](Get-Prop $d 'deviceName')).ToLowerInvariant()
        if ($byName.ContainsKey($name)) { $byName[$name] = $null } else { $byName[$name] = $d }
    }
    $out = [System.Collections.Generic.List[object]]::new()
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($r in $rows) {
        $md = $null
        $identity = Get-FilterRowIdentity -Row $r
        if ($identity.Id) { if ($byId.ContainsKey($identity.Id)) { $md = $byId[$identity.Id] } }
        elseif ($identity.Name -and $byName.ContainsKey($identity.Name.ToLowerInvariant())) { $md = $byName[$identity.Name.ToLowerInvariant()] }
        if ($null -ne $md) {
            $mid = [string](Get-Prop $md 'id')
            if ($seen.Add($mid)) { [void]$out.Add($md) }
        }
    }
    return $out.ToArray()
}

#endregion

#region ---------- applicability engine ------------------------------------------------------

# Applicability is evaluated in two phases, mirroring Intune:
#   1. Get-ReachingPaths: which INCLUDE assignments reach the device by group membership
#      (device groups, the primary user's groups, All devices / All users), after same-kind
#      group exclusions. User-group exclusions do not undo device-targeted includes and vice
#      versa (Intune doesn't evaluate user-to-device relationships).
#   2. Resolve-FilterPrecedence: assignment filters across every reaching path, using Intune's
#      filter-mode precedence: an Exclude-mode filter wins over 'no filter', which wins over
#      an Include-mode filter; filters in the same mode are ORed
#      (learn.microsoft.com/intune/fundamentals/filters/troubleshoot).
# Apps add a step in between: the winning intent is resolved from phase 1 first and only
# the winning intent's filters are evaluated (Resolve-AppIntent).
# Every assignment gets a hit marker (Hit/Note) that the report shows next to it:
#   applies | excluded (include cancelled by a group exclusion) | excluding (exclusion that
#   matches this device) | filteredout | notevaluated | overridden | ignored | unknown | ''

function New-HitArray {
    param([int]$Count)
    $h = New-Object object[] $Count
    for ($i = 0; $i -lt $Count; $i++) { $h[$i] = [pscustomobject]@{ Hit = ''; Note = '' } }
    return , $h
}

function Get-FilterDisplayName {
    param([string]$FilterId)
    if ($FilterId -and $script:FilterById.ContainsKey($FilterId)) { return $script:FilterById[$FilterId].Name }
    return $FilterId
}

function Get-ReachingPaths {
    param($Assignments, $Ctx, [ValidateSet('both', 'user', 'device')][string]$TargetKinds = 'both', [string]$PathTag = '')
    $asg = @($Assignments)
    $hits = New-HitArray -Count $asg.Count
    $paths = [System.Collections.Generic.List[object]]::new()
    $excludeReasons = New-Object System.Collections.Generic.List[string]
    $unknownNotes = New-Object System.Collections.Generic.List[string]
    $deviceExcl = New-Object System.Collections.Generic.List[string]
    $userExcl = New-Object System.Collections.Generic.List[string]
    $uncertainPaths = [System.Collections.Generic.List[object]]::new()
    $uncertainExclusions = [System.Collections.Generic.List[object]]::new()
    $unresolvedKinds = @()
    if ($TargetKinds -ne 'user' -and -not $Ctx.DeviceGroupsResolved) { $unresolvedKinds += 'device' }
    if ($TargetKinds -ne 'device' -and $Ctx.HasPrimaryUser -and -not $Ctx.UserGroupsResolved) { $unresolvedKinds += 'user' }
    $membershipUnknown = (-not $Ctx.DeviceGroupsResolved) -or ($Ctx.HasPrimaryUser -and -not $Ctx.UserGroupsResolved)
    $hasGroupExclusions = $false

    for ($i = 0; $i -lt $asg.Count; $i++) {
        $a = $asg[$i]
        if ([string]$a.Type -notlike '*exclusionGroupAssignmentTarget*') { continue }
        $hasGroupExclusions = $true
        if (-not $a.GroupId) { continue }
        $gn = Get-GroupName $a.GroupId
        if ($unresolvedKinds.Count) {
            [void]$uncertainExclusions.Add([pscustomobject]@{ Index = $i; Kinds = $unresolvedKinds })
        }
        $notes = @()
        if ($Ctx.DeviceGroupIds.Contains($a.GroupId)) { [void]$deviceExcl.Add($gn); $notes += 'the device is a member' }
        if ($Ctx.UserGroupIds.Contains($a.GroupId)) { [void]$userExcl.Add($gn); $notes += 'the primary user is a member' }
        if ($notes.Count) { $hits[$i] = [pscustomobject]@{ Hit = 'excluding'; Note = ("Excludes this device - {0}" -f ($notes -join ' and ')) } }
        elseif ($unresolvedKinds.Count) { $hits[$i] = [pscustomobject]@{ Hit = 'unknown'; Note = 'Group membership could not be resolved' } }
    }

    $hadDeviceInclude = $false; $hadUserInclude = $false; $pathExcluded = $false
    for ($i = 0; $i -lt $asg.Count; $i++) {
        $a = $asg[$i]
        $type = [string]$a.Type
        if ($type -like '*exclusionGroupAssignmentTarget*') { continue }
        $base = $null; $kind = ''; $reaches = @()
        switch -Wildcard ($type) {
            '*configurationManagerCollectionAssignmentTarget*' {
                # tenant-attached ConfigMgr collection: membership lives in Configuration Manager
                if ($TargetKinds -eq 'user') { $hits[$i] = [pscustomobject]@{ Hit = 'ignored'; Note = 'Configuration Manager collection targets devices only' }; break }
                [void]$unknownNotes.Add(("Targets Configuration Manager collection {0} - collection membership is not readable from Graph." -f $a.CollectionId))
                $hits[$i] = [pscustomobject]@{ Hit = 'unknown'; Note = 'Configuration Manager collection - membership not readable' }
                if ($TargetKinds -ne 'user') { [void]$uncertainPaths.Add([pscustomobject]@{ Index = $i; Kind = 'device'; GroupReach = $false }) }
                break
            }
            '*allDevicesAssignmentTarget*' { $base = 'All devices'; $kind = 'device'; break }
            '*allLicensedUsersAssignmentTarget*' {
                if ($Ctx.HasPrimaryUser) { $base = 'All users (via primary user)'; $kind = 'user' }
                else { $hits[$i] = [pscustomobject]@{ Hit = ''; Note = 'Device has no primary user' } }
                break
            }
            '*GroupAssignmentTarget*' {
                if ($a.GroupId) {
                    foreach ($unresolvedKind in $unresolvedKinds) {
                        [void]$uncertainPaths.Add([pscustomobject]@{ Index = $i; Kind = $unresolvedKind; GroupReach = $true })
                    }
                    # A group can contain both the device and its primary user. Keep each
                    # reach independently so a same-kind exclusion or user-only policy
                    # does not discard the other confirmed membership.
                    if ($Ctx.DeviceGroupIds.Contains($a.GroupId)) { $reaches += [pscustomobject]@{ Base = ("Device group '{0}'" -f (Get-GroupName $a.GroupId)); Kind = 'device' } }
                    if ($Ctx.UserGroupIds.Contains($a.GroupId)) { $reaches += [pscustomobject]@{ Base = ("User group '{0}' (via primary user)" -f (Get-GroupName $a.GroupId)); Kind = 'user' } }
                    if (-not $reaches.Count -and $unresolvedKinds.Count) {
                        [void]$unknownNotes.Add(("Could not determine membership of group '{0}' because directory membership resolution failed." -f (Get-GroupName $a.GroupId)))
                        $hits[$i] = [pscustomobject]@{ Hit = 'unknown'; Note = 'Group membership could not be resolved' }
                    }
                }
                break
            }
        }
        if ($null -ne $base) { $reaches = @([pscustomobject]@{ Base = $base; Kind = $kind }) }
        if (-not $reaches.Count) { continue }
        $eligible = @($reaches | Where-Object { $TargetKinds -eq 'both' -or $_.Kind -eq $TargetKinds })
        if (-not $eligible.Count -and $TargetKinds -eq 'user') {
            $hits[$i] = [pscustomobject]@{ Hit = 'ignored'; Note = 'This policy type is evaluated for users only - device targeting is ignored' }
            continue
        }
        if (-not $eligible.Count -and $TargetKinds -eq 'device') {
            $hits[$i] = [pscustomobject]@{ Hit = 'ignored'; Note = 'This policy type is evaluated for devices only - user targeting is ignored' }
            continue
        }
        foreach ($reach in $eligible) {
            $base = $reach.Base; $kind = $reach.Kind
            if ($kind -eq 'device') { $hadDeviceInclude = $true } else { $hadUserInclude = $true }

            # same-kind exclusion beats the include (and its filter) for this path
            if ($kind -eq 'device' -and $deviceExcl.Count -gt 0) {
                $pathExcluded = $true
                $why = ("{0} - excluded via device group '{1}'" -f $base, (@($deviceExcl) -join "', '"))
                [void]$excludeReasons.Add($why)
                $hits[$i] = [pscustomobject]@{ Hit = 'excluded'; Note = ("Cancelled by the exclusion of '{0}'" -f (@($deviceExcl) -join "', '")) }
                continue
            }
            if ($kind -eq 'user' -and $userExcl.Count -gt 0) {
                $pathExcluded = $true
                $why = ("{0} - excluded via user group '{1}' (via primary user)" -f $base, (@($userExcl) -join "', '"))
                [void]$excludeReasons.Add($why)
                $hits[$i] = [pscustomobject]@{ Hit = 'excluded'; Note = ("Cancelled by the exclusion of '{0}'" -f (@($userExcl) -join "', '")) }
                continue
            }
            [void]$paths.Add([pscustomobject]@{
                Index = $i; Base = $base; Kind = $kind; Tag = $PathTag
                FilterId = [string]$a.FilterId; FilterType = [string]$a.FilterType; Hits = $hits
            })
            $hits[$i] = [pscustomobject]@{ Hit = 'unknown'; Note = ("Assignment reach confirmed via {0}; final applicability not yet resolved" -f $base) }
        }
    }

    $mixNotes = @()
    if ($userExcl.Count -gt 0 -and $hadDeviceInclude) {
        $mixNotes += ("note: user-group exclusion '{0}' does not affect device-targeted assignments (Intune doesn't evaluate user-to-device relationships)" -f (@($userExcl) -join "', '"))
    }
    if ($deviceExcl.Count -gt 0 -and $hadUserInclude) {
        $mixNotes += ("note: device-group exclusion '{0}' does not affect user-targeted assignments (Intune doesn't evaluate user-to-device relationships)" -f (@($deviceExcl) -join "', '"))
    }
    return [pscustomobject]@{
        Paths = $paths.ToArray(); Hits = $hits; ExcludeReasons = $excludeReasons.ToArray(); UnknownNotes = $unknownNotes.ToArray()
        UncertainPaths = $uncertainPaths.ToArray(); UncertainExclusions = $uncertainExclusions.ToArray()
        HasRelevantUncertainty = ($uncertainPaths.Count -gt 0 -or $uncertainExclusions.Count -gt 0)
        MixNotes = $mixNotes; DeviceExcl = $deviceExcl.ToArray(); UserExcl = $userExcl.ToArray()
        PathExcluded = $pathExcluded; MembershipUnknown = $membershipUnknown; HasGroupExclusions = $hasGroupExclusions
    }
}

function Resolve-FilterPrecedence {
    # Returns Status = Applies | FilteredOut | Unknown | None (no reaching path) with Reasons
    # and the target kinds (device/user) of the paths that made it apply.
    param($Paths, $Ctx)
    $all = @($Paths)
    if ($all.Count -eq 0) { return [pscustomobject]@{ Status = 'None'; Reasons = @(); Kinds = @() } }
    $md = $Ctx.ManagedDevice
    $hasF = { param($p) $p.FilterId -and $p.FilterType -and $p.FilterType -ne 'none' }
    $exc = @($all | Where-Object { (& $hasF $_) -and $_.FilterType -ieq 'exclude' })
    $none = @($all | Where-Object { -not (& $hasF $_) })
    $inc = @($all | Where-Object { (& $hasF $_) -and $_.FilterType -ieq 'include' })
    $tag = { param($p) if ($p.Tag) { "[$($p.Tag)] " } else { '' } }
    $setHit = { param($p, $h, $n) $p.Hits[$p.Index] = [pscustomobject]@{ Hit = $h; Note = $n } }

    if ($exc.Count -gt 0) {
        $matched = @(); $unknown = @(); $clear = @()
        foreach ($p in $exc) {
            $fn = Get-FilterDisplayName $p.FilterId
            $m = Test-DeviceMatchesFilter -FilterId $p.FilterId -ManagedDevice $md
            if ($m -isnot [bool]) { $unknown += $p; & $setHit $p 'unknown' ("Exclude filter '{0}' could not be evaluated" -f $fn) }
            elseif ($m) { $matched += $p; & $setHit $p 'filteredout' ("Exclude filter '{0}' matched: device excluded" -f $fn) }
            else { $clear += $p; & $setHit $p 'applies' ("Exclude filter '{0}' not matched" -f $fn) }
        }
        foreach ($p in @($none + $inc)) { & $setHit $p 'notevaluated' 'Not evaluated - an Exclude-mode filter on another assignment takes precedence' }
        if ($matched.Count -gt 0) {
            return [pscustomobject]@{ Status = 'FilteredOut'; Kinds = @(); Reasons = @($matched | ForEach-Object {
                        "{0}{1}, exclude filter '{2}' matched: excluded (an exclude filter takes precedence over every other assignment)" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
        }
        if ($unknown.Count -gt 0) {
            return [pscustomobject]@{ Status = 'Unknown'; Kinds = @(); Reasons = @($unknown | ForEach-Object {
                        "{0}{1}, exclude filter '{2}' could not be evaluated: applicability unknown" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
        }
        return [pscustomobject]@{ Status = 'Applies'; Kinds = @($clear | ForEach-Object { $_.Kind } | Select-Object -Unique); Reasons = @($clear | ForEach-Object {
                    "{0}{1}, exclude filter '{2}' not matched" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
    }
    if ($none.Count -gt 0) {
        foreach ($p in $none) { & $setHit $p 'applies' 'Targets this device (no filter)' }
        foreach ($p in $inc) { & $setHit $p 'notevaluated' 'Not evaluated - an assignment without a filter already applies' }
        return [pscustomobject]@{ Status = 'Applies'; Kinds = @($none | ForEach-Object { $_.Kind } | Select-Object -Unique); Reasons = @($none | ForEach-Object { "{0}{1}" -f (& $tag $_), $_.Base }) }
    }
    $ok = @(); $unknown = @(); $miss = @()
    foreach ($p in $inc) {
        $fn = Get-FilterDisplayName $p.FilterId
        $m = Test-DeviceMatchesFilter -FilterId $p.FilterId -ManagedDevice $md
        if ($m -isnot [bool]) { $unknown += $p; & $setHit $p 'unknown' ("Filter '{0}' could not be evaluated" -f $fn) }
        elseif ($m) { $ok += $p; & $setHit $p 'applies' ("Filter '{0}' matched" -f $fn) }
        else { $miss += $p; & $setHit $p 'filteredout' ("Filter '{0}' not matched" -f $fn) }
    }
    if ($ok.Count -gt 0) {
        $r = @($ok | ForEach-Object { "{0}{1}, filter '{2}' matched" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) })
        $r += @($miss | ForEach-Object { "(other path filtered out: {0}{1}, filter '{2}' not matched)" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) })
        return [pscustomobject]@{ Status = 'Applies'; Kinds = @($ok | ForEach-Object { $_.Kind } | Select-Object -Unique); Reasons = $r }
    }
    if ($unknown.Count -gt 0) {
        return [pscustomobject]@{ Status = 'Unknown'; Kinds = @(); Reasons = @($unknown | ForEach-Object {
                    "{0}{1}, filter '{2}' could not be evaluated: applicability unknown" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
    }
    return [pscustomobject]@{ Status = 'FilteredOut'; Kinds = @(); Reasons = @($miss | ForEach-Object {
                "{0}{1}, filter '{2}' not matched" -f (& $tag $_), $_.Base, (Get-FilterDisplayName $_.FilterId) }) }
}

function Test-ReachingUncertaintyChangesResult {
    # Safe monotonic cases need no missing-membership combinations: lower filter modes
    # cannot undo a confirmed include, and further paths cannot undo an Exclude match.
    param($Reach, $Assignments, $FilterResult)
    if (-not $Reach.HasRelevantUncertainty) { return $false }
    $knownKinds = @($Reach.Paths | ForEach-Object { $_.Kind } | Select-Object -Unique)
    foreach ($exclusion in $Reach.UncertainExclusions) {
        if (@($exclusion.Kinds | Where-Object { $knownKinds -contains $_ }).Count) { return $true }
    }
    if ($FilterResult.Status -eq 'Applies') {
        foreach ($path in $Reach.UncertainPaths) {
            $assignment = $Assignments[$path.Index]
            if ($assignment.FilterId -and $assignment.FilterType -ieq 'exclude') { return $true }
        }
        return $false
    }
    if ($FilterResult.Status -eq 'FilteredOut' -and @($Reach.Paths | Where-Object { $_.FilterId -and $_.FilterType -ieq 'exclude' }).Count) { return $false }
    return $true
}

function Get-PolicyApplicability {
    # Evaluates one policy's assignments against one device context.
    # Returns Status: Applies | Excluded | FilteredOut | Unknown | NotTargeted, Reasons,
    # Hits (aligned with $Policy.Assignments) and Kinds (target kinds that made it apply).
    param($Policy, $Ctx, [string]$TargetKinds = 'both')
    if (-not $TargetKinds) { $TargetKinds = 'both' }
    $r = Get-ReachingPaths -Assignments $Policy.Assignments -Ctx $Ctx -TargetKinds $TargetKinds
    $candidateKinds = @(@($r.Paths) + @($r.UncertainPaths) | ForEach-Object { $_.Kind } | Select-Object -Unique)
    $candidateGroupReach = @($r.UncertainPaths | Where-Object { $_.GroupReach }).Count -gt 0
    $knownGroupReach = $false
    for ($i = 0; $i -lt @($Policy.Assignments).Count; $i++) {
        if ($Policy.Assignments[$i].Type -eq 'groupAssignmentTarget' -and @($r.Paths | Where-Object { $_.Index -eq $i }).Count) { $candidateGroupReach = $true; $knownGroupReach = $true }
    }

    $f = Resolve-FilterPrecedence -Paths $r.Paths -Ctx $Ctx
    $uncertaintyChangesResult = Test-ReachingUncertaintyChangesResult -Reach $r -Assignments $Policy.Assignments -FilterResult $f
    # Even a redundant include can change device/user precedence for ESP or turn an
    # Autopilot fallback into a specific-group candidate.
    if ($f.Status -eq 'Applies' -and $Policy.PriorityClass -eq 'esp' -and $f.Kinds -notcontains 'device' -and @($r.UncertainPaths | Where-Object Kind -eq 'device').Count) { $uncertaintyChangesResult = $true }
    if ($f.Status -eq 'Applies' -and $Policy.PriorityClass -eq 'autopilot' -and -not $knownGroupReach -and @($r.UncertainPaths | Where-Object { $_.GroupReach }).Count) { $uncertaintyChangesResult = $true }

    if ($Policy.AssignmentsUnreadable -or $uncertaintyChangesResult) {
        $unresolved = @()
        if ($TargetKinds -ne 'user' -and -not $Ctx.DeviceGroupsResolved) { $unresolved += 'device' }
        if ($TargetKinds -ne 'device' -and $Ctx.HasPrimaryUser -and -not $Ctx.UserGroupsResolved) { $unresolved += 'primary user' }
        $reasons = @($r.UnknownNotes)
        if ($Policy.AssignmentsUnreadable) {
            $reasons += 'Assignments could not be fully read; applicability is unknown (see warnings).'
            $candidateKinds = $(if ($TargetKinds -eq 'both') { @('device', 'user') } else { @($TargetKinds) })
            $candidateGroupReach = $true
        }
        elseif ($unresolved.Count) { $reasons += ("Could not resolve {0} group membership; applicability is unknown." -f ($unresolved -join ' and ')) }
        foreach ($path in $r.Paths) {
            if ($r.Hits[$path.Index].Hit -eq 'applies') { $r.Hits[$path.Index] = [pscustomobject]@{ Hit = 'unknown'; Note = ("Assignment reach confirmed via {0}; overall applicability is unknown" -f $path.Base) } }
        }
        return [pscustomobject]@{
            Status  = 'Unknown'; Hits = $r.Hits; Kinds = @()
            Reasons = $reasons; CandidateKinds = $candidateKinds; CandidateGroupReach = $candidateGroupReach
        }
    }

    switch ($f.Status) {
        'Applies' {
            $all = @($f.Reasons)
            if ($r.ExcludeReasons.Count -gt 0) { $all += @($r.ExcludeReasons | ForEach-Object { "(other path excluded: $_)" }) }
            $all += $r.MixNotes
            return [pscustomobject]@{ Status = 'Applies'; Reasons = $all; Hits = $r.Hits; Kinds = $f.Kinds; CandidateKinds = $candidateKinds; CandidateGroupReach = $candidateGroupReach }
        }
        'Unknown' {
            return [pscustomobject]@{ Status = 'Unknown'; Reasons = (@($f.Reasons) + @($r.UnknownNotes) + @($r.ExcludeReasons) + $r.MixNotes); Hits = $r.Hits; Kinds = @(); CandidateKinds = $candidateKinds; CandidateGroupReach = $candidateGroupReach }
        }
    }
    # A confirmed Exclude-mode match cannot be undone by additional include paths.
    if ($f.Status -eq 'FilteredOut' -and $r.HasRelevantUncertainty -and -not $uncertaintyChangesResult) {
        return [pscustomobject]@{ Status = 'FilteredOut'; Reasons = (@($f.Reasons) + @($r.UnknownNotes) + $r.MixNotes); Hits = $r.Hits; Kinds = @() }
    }
    # nothing applies: an undecided membership could still make it apply, so Unknown
    # outranks Excluded / FilteredOut
    if ($r.UnknownNotes.Count -gt 0) {
        return [pscustomobject]@{ Status = 'Unknown'; Reasons = (@($r.UnknownNotes) + @($r.ExcludeReasons) + @($f.Reasons) + $r.MixNotes); Hits = $r.Hits; Kinds = @() }
    }
    if ($r.PathExcluded) {
        return [pscustomobject]@{ Status = 'Excluded'; Reasons = (@($r.ExcludeReasons) + @($f.Reasons | ForEach-Object { "(other path filtered out: $_)" }) + $r.MixNotes); Hits = $r.Hits; Kinds = @() }
    }
    if ($f.Status -eq 'FilteredOut') {
        return [pscustomobject]@{ Status = 'FilteredOut'; Reasons = (@($f.Reasons) + $r.MixNotes); Hits = $r.Hits; Kinds = @() }
    }
    if ($r.DeviceExcl.Count -gt 0 -or $r.UserExcl.Count -gt 0) {
        $names = @(@($r.DeviceExcl) + @($r.UserExcl) | Select-Object -Unique)
        return [pscustomobject]@{ Status = 'Excluded'; Reasons = @(("Member of excluded group '{0}' (no include path targets this device)" -f ($names -join "', '"))); Hits = $r.Hits; Kinds = @() }
    }
    return [pscustomobject]@{ Status = 'NotTargeted'; Reasons = @(); Hits = $r.Hits; Kinds = @() }
}

$script:IntentLabels = @{
    required = 'Required'; available = 'Available'; uninstall = 'Uninstall'
    availableWithoutEnrollment = 'Available (no enrollment)'; requiredAndAvailable = 'Required + Available'
}

function Resolve-AppIntent {
    # Intune's documented resolution when one device/user is reached by several intents
    # (learn.microsoft.com/intune/app-management/deployment/assign-groups#how-conflicts-
    # between-app-intents-are-resolved). $Reach: intent -> kinds ('user'/'device') reaching it.
    # Returns @{ Key; Win (intents whose filters are evaluated); Note } or $null.
    param([hashtable]$Reach)
    $has = { param([string]$i, [string]$k) $Reach.ContainsKey($i) -and (-not $k -or @($Reach[$i]) -contains $k) }
    $R = & $has 'required' ''; $A = & $has 'available' ''; $U = & $has 'uninstall' ''; $W = & $has 'availableWithoutEnrollment' ''
    if ($R) {
        if ($A) {
            $n = 'Required and Available both reach this device: Intune merges them into "Required and Available" (the filters of both are evaluated).'
            if ($U) { $n += ' Uninstall also reaches it but Required always wins over Uninstall.' }
            return @{ Key = 'requiredAndAvailable'; Win = @('required', 'available'); Note = $n }
        }
        if ($W -and (& $has 'required' 'device')) {
            return @{ Key = 'requiredAndAvailable'; Win = @('required', 'availableWithoutEnrollment'); Note = 'Device Required + user Available without enrollment resolve to "Required and Available without enrollment".' }
        }
        $n = ''
        if ($U) { $n = 'Required and Uninstall both reach this device - Required wins (Intune: Required always beats Uninstall, for user and device targeting alike).' }
        elseif ($W) { $n = 'Required beats Available without enrollment.' }
        return @{ Key = 'required'; Win = @('required'); Note = $n }
    }
    if ($U) {
        if ($A -and (& $has 'available' 'user') -and -not (& $has 'available' 'device') -and (& $has 'uninstall' 'device') -and -not (& $has 'uninstall' 'user')) {
            return @{ Key = 'available'; Win = @('available'); Note = 'User Available + device Uninstall resolve to Available: the app shows in Company Portal; a copy previously installed as Required is uninstalled, but an install from Company Portal is honoured.' }
        }
        if ($A) { return @{ Key = 'uninstall'; Win = @('uninstall'); Note = 'Available and Uninstall both reach this device - Uninstall wins (same target type).' } }
        if ($W) { return @{ Key = 'uninstall'; Win = @('uninstall'); Note = 'Uninstall and Available without enrollment: the uninstall is honoured unless the user installs the app from Company Portal.' } }
        return @{ Key = 'uninstall'; Win = @('uninstall'); Note = '' }
    }
    if ($A) { return @{ Key = 'available'; Win = @('available'); Note = $(if ($W) { 'Available beats Available without enrollment.' } else { '' }) } }
    if ($W) { return @{ Key = 'availableWithoutEnrollment'; Win = @('availableWithoutEnrollment'); Note = '' } }
    return $null
}

function Get-AppApplicability {
    # One app against one device: per-intent reach -> intent resolution -> filters of the
    # winning intent(s). Returns the per-intent breakdown the Apps tab renders.
    param($App, $Ctx)
    $asg = @($App.Assignments)
    if ($App.AssignmentsUnreadable) {
        $unknownIntents = Get-AppIntentSkeleton -App $App
        foreach ($i in $unknownIntents) { $i.Status = 'Unknown'; $i.Via = @('Assignments could not be fully read') }
        return [pscustomobject]@{ Status = 'Unknown'; EffectiveIntent = ''; Resolution = 'Assignments could not be fully read; the effective app intent is unknown (see warnings).'; IntentConflict = $false; Kinds = @(); Intents = $unknownIntents }
    }
    $intents = @($asg | ForEach-Object { if ($_.Intent) { [string]$_.Intent } else { 'unknown' } } | Select-Object -Unique)
    $order = @('required', 'available', 'uninstall', 'availableWithoutEnrollment')
    $intents = @($order | Where-Object { $intents -contains $_ }) + @($intents | Where-Object { $order -notcontains $_ })

    $per = [ordered]@{}
    $reach = @{}
    $anyUnknownMembership = $false
    $uncertainIntents = @()
    foreach ($it in $intents) {
        $sub = @($asg | Where-Object { ([string]$_.Intent -eq $it) -or (-not $_.Intent -and $it -eq 'unknown') })
        $rp = Get-ReachingPaths -Assignments $sub -Ctx $Ctx -PathTag $script:IntentLabels[$it]
        if ($rp.HasRelevantUncertainty -or $it -eq 'unknown') { $anyUnknownMembership = $true; $uncertainIntents += $it }
        $per[$it] = [pscustomobject]@{ Intent = $it; Sub = $sub; R = $rp; Status = 'NotTargeted'; Via = @() }
        if ($rp.Paths.Count -gt 0 -and $it -ne 'unknown') { $reach[$it] = @($rp.Paths | ForEach-Object { $_.Kind } | Select-Object -Unique) }
    }

    $res = Resolve-AppIntent -Reach $reach
    # Prove safe redundant winning paths and losing Uninstall paths independently;
    # all other uncertainty stays conservative without membership combinations.
    $stableMembership = [bool]$res
    foreach ($it in $uncertainIntents) {
        if ($it -eq 'unknown') { $stableMembership = $false; break }
        if ($res -and $res.Win -contains $it) {
            $rp = $per[$it].R
            $knownFilter = Resolve-FilterPrecedence -Paths $rp.Paths -Ctx $Ctx
            if (Test-ReachingUncertaintyChangesResult -Reach $rp -Assignments $per[$it].Sub -FilterResult $knownFilter) { $stableMembership = $false; break }
            $possibleReach = $reach.Clone()
            $possibleReach[$it] = @(@($rp.Paths) + @($rp.UncertainPaths) | ForEach-Object { $_.Kind } | Select-Object -Unique)
            $possibleIntent = Resolve-AppIntent -Reach $possibleReach
            if (-not $possibleIntent -or $possibleIntent.Key -ne $res.Key -or (($possibleIntent.Win | Sort-Object) -join ',') -ne (($res.Win | Sort-Object) -join ',')) { $stableMembership = $false; break }
        }
        elseif (-not ($reach.ContainsKey('required') -and $it -eq 'uninstall')) { $stableMembership = $false; break }
    }
    if ($anyUnknownMembership -and -not $stableMembership) {
        foreach ($i in $per.Values) {
            if ($i.R.Paths.Count -or $i.R.HasRelevantUncertainty -or $i.Intent -eq 'unknown') {
                $i.Status = 'Unknown'
                $i.Via = @($i.R.UnknownNotes) + @($i.R.Paths | ForEach-Object { $_.Base })
                foreach ($path in $i.R.Paths) {
                    if ($i.R.Hits[$path.Index].Hit -eq 'applies') { $i.R.Hits[$path.Index] = [pscustomobject]@{ Hit = 'unknown'; Note = ("Assignment reach confirmed via {0}; effective app intent is unknown" -f $path.Base) } }
                }
            }
            elseif ($i.R.PathExcluded) { $i.Status = 'Excluded'; $i.Via = @($i.R.ExcludeReasons) }
        }
        return [pscustomobject]@{ Status = 'Unknown'; EffectiveIntent = ''; Resolution = 'Targeting could not be fully resolved; the effective app intent and applicability are unknown.'; IntentConflict = $false; Kinds = @(); Intents = @($per.Values) }
    }
    $status = 'NotTargeted'; $effKey = ''; $resolution = @(); $conflict = $false; $kinds = @()
    if ($res) {
        $winPaths = @()
        foreach ($w in $res.Win) { if ($per.Contains($w)) { $winPaths += @($per[$w].R.Paths) } }
        $f = Resolve-FilterPrecedence -Paths $winPaths -Ctx $Ctx
        $effKey = $res.Key
        $winLabel = $script:IntentLabels[$res.Key]
        foreach ($w in $res.Win) {
            if (-not $per.Contains($w)) { continue }
            # the merged / winning intent(s) share one filter outcome
            $per[$w].Status = $(switch ($f.Status) { 'Applies' { 'Applies' } 'FilteredOut' { 'FilteredOut' } default { 'Unknown' } })
            $pfx = '[' + $script:IntentLabels[$w] + ']'
            $per[$w].Via = @($f.Reasons | Where-Object { ([string]$_).Contains($pfx) } | ForEach-Object { ([string]$_).Replace($pfx + ' ', '') })
        }
        foreach ($k in $reach.Keys) {
            if ($res.Win -contains $k) { continue }
            $conflict = $true
            $per[$k].Status = 'Overridden'
            $per[$k].Via = @($per[$k].R.Paths | ForEach-Object { $_.Base })
            foreach ($p in $per[$k].R.Paths) { $p.Hits[$p.Index] = [pscustomobject]@{ Hit = 'overridden'; Note = ("Reaches the device but loses to {0} (intent conflict rules)" -f $winLabel) } }
        }
        if ($res.Key -eq 'requiredAndAvailable' -and $reach.Count -eq 2) { $conflict = $false }
        switch ($f.Status) {
            'Applies' {
                $status = 'Applies'; $kinds = $f.Kinds
                $resolution += ("{0} - {1}" -f $winLabel, (($f.Reasons | Where-Object { $_ -notlike '(other path*' } | ForEach-Object { $_ -replace '^\[[^\]]+\]\s*', '' }) -join '; '))
            }
            'FilteredOut' {
                $status = 'FilteredOut'
                $resolution += ("{0} wins the intent resolution, but its assignment filter excludes the device - the app is not delivered. ({1})" -f $winLabel, (($f.Reasons | ForEach-Object { $_ -replace '^\[[^\]]+\]\s*', '' }) -join '; '))
                if ($conflict) { $resolution += 'Intune resolves the intent BEFORE evaluating filters, so the losing intent is not applied either.' }
            }
            default {
                $status = 'Unknown'
                $resolution += ("{0} wins the intent resolution, but its filter could not be evaluated. ({1})" -f $winLabel, (($f.Reasons | ForEach-Object { $_ -replace '^\[[^\]]+\]\s*', '' }) -join '; '))
            }
        }
        if ($res.Note) { $resolution += $res.Note }
        foreach ($k in $reach.Keys) { if ($res.Win -notcontains $k) { $resolution += ("{0} via {1} is overridden." -f $script:IntentLabels[$k], (@($per[$k].R.Paths | ForEach-Object { $_.Base }) -join ', ')) } }
    }
    # intents that never reached the device: excluded / unknown / not targeted
    $anyExcluded = $false
    foreach ($k in @($per.Keys)) {
        $e = $per[$k]
        if ($reach.ContainsKey($k)) { continue }
        if ($e.R.PathExcluded) { $e.Status = 'Excluded'; $e.Via = @($e.R.ExcludeReasons); $anyExcluded = $true }
        elseif ($e.R.UnknownNotes.Count -or ($e.R.HasGroupExclusions -and $e.R.MembershipUnknown)) { $e.Status = 'Unknown'; $e.Via = @($e.R.UnknownNotes) }
        elseif ($e.R.DeviceExcl.Count -or $e.R.UserExcl.Count) {
            $e.Status = 'Excluded'; $anyExcluded = $true
            $e.Via = @(("Member of excluded group '{0}'" -f (@(@($e.R.DeviceExcl) + @($e.R.UserExcl) | Select-Object -Unique) -join "', '")))
        }
        $e.Via = @($e.Via) + @($e.R.MixNotes)
    }
    if (-not $res) {
        if ($anyUnknownMembership) { $status = 'Unknown'; $resolution += 'Group membership could not be fully resolved; whether the app targets this device is unknown.' }
        elseif ($anyExcluded) { $status = 'Excluded'; $resolution += (@($per.Values | Where-Object { $_.Status -eq 'Excluded' } | ForEach-Object { "{0}: {1}" -f $script:IntentLabels[$_.Intent], ($_.Via -join '; ') }) -join ' | ') }
    }
    return [pscustomobject]@{
        Status = $status; EffectiveIntent = $effKey; Resolution = ($resolution -join ' '); IntentConflict = $conflict; Kinds = $kinds
        Intents = @($per.Values)
    }
}

#endregion

#region ---------- reported status (device truth) --------------------------------------------

function Get-ReportedPolicyStatus {
    # What the device actually reported, via the same endpoint the portal's per-device
    # Configuration blade uses. Returns @{ policyIdLower = @{Status=..; Name=..} }
    param([string]$IntuneDeviceId)
    $map = @{}
    # Best-effort mapping of the report's numeric PolicyStatus (raw value is kept alongside).
    $statusMap = @{
        0 = 'Unknown'; 1 = 'Not applicable'; 2 = 'Succeeded'; 3 = 'Remediated';
        4 = 'Not compliant'; 5 = 'Error'; 6 = 'Conflict'; 7 = 'Not assigned'
    }
    # The service rejects a bare IntuneDeviceId filter with 400 on some tenants; the
    # portal always scopes the report to the supported policy base types, so mirror
    # its request shape first and fall back to simpler bodies from there.
    $baseTypeClause = "((PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceConfiguration') " +
        "or (PolicyBaseTypeName eq 'DeviceManagementConfigurationPolicy') " +
        "or (PolicyBaseTypeName eq 'DeviceConfigurationAdmxPolicy') " +
        "or (PolicyBaseTypeName eq 'Microsoft.Management.Services.Api.DeviceManagementIntent'))"
    try {
        $rows = [System.Collections.Generic.List[object]]::new()
        $skip = 0
        while ($true) {
            $portalBody = @{
                select  = @('IntuneDeviceId', 'PolicyBaseTypeName', 'PolicyId', 'PolicyStatus', 'UPN', 'UserId', 'PolicyName', 'UnifiedPolicyType')
                filter  = ("{0} and (IntuneDeviceId eq '{1}')" -f $baseTypeClause, $IntuneDeviceId)
                skip    = $skip
                top     = 50
                orderBy = @('PolicyName')
            }
            $simpleBody = @{
                select = @('PolicyId', 'PolicyName', 'PolicyStatus', 'UPN', 'PolicyBaseTypeName')
                filter = "(IntuneDeviceId eq '$IntuneDeviceId')"
                skip   = $skip
                top    = 50
            }
            $reportUri = 'beta/deviceManagement/reports/getConfigurationPoliciesReportForDevice'
            # report responses are a Stream, read via a temp file (Invoke-RsopStream). Shapes in
            # order: portal-shaped, simple filter, portal-shaped parsed inline; the first one the
            # tenant accepts is used for every later page and device.
            $shapes = @(
                @{ N = 1; Run = { Invoke-RsopStream -Uri $reportUri -Body $portalBody } },
                @{ N = 2; Run = { Invoke-RsopStream -Uri $reportUri -Body $simpleBody } },
                @{ N = 3; Run = { Invoke-Rsop -Method POST -Uri $reportUri -Body $portalBody } }
            )
            if ($script:DeviceReportShape -gt 0) { $shapes = @($shapes | Sort-Object { $_.N -ne $script:DeviceReportShape }) }
            $resp = $null; $answered = $false
            foreach ($shape in $shapes) {
                try { $resp = & $shape.Run; $answered = $true; $script:DeviceReportShape = $shape.N; break }
                catch {
                    if ((Test-RsopRetryable -ErrorRecord $_) -or $shape.N -eq $shapes[-1].N) { throw }
                    Add-SessionLog 'info' ("device report shape {0} refused: {1}" -f $shape.N, (Format-RsopError $_))
                }
            }
            if (-not $answered) { break }
            $batch = @(ConvertFrom-ReportGrid -Response $resp)
            foreach ($row in $batch) { $rows.Add($row) }
            if ($batch.Count -lt 50) { break }
            if ($skip -ge 9950) {
                Add-RunLog -Level warn -Message 'Device-reported policy results exceeded 10,000 rows and were truncated.'
                break
            }
            $skip += 50
        }
        foreach ($r in @($rows)) {
            $polId = [string](Get-Prop $r 'PolicyId')
            if (-not $polId) { continue }
            $statusRaw = Get-Prop $r 'PolicyStatus'
            $statusTxt = "$statusRaw"
            $si = 0
            if ([int]::TryParse("$statusRaw", [ref]$si) -and $statusMap.ContainsKey($si)) {
                $statusTxt = ("{0} ({1})" -f $statusMap[$si], $si)
            }
            $key = $polId.ToLower()
            if (-not $map.ContainsKey($key)) {
                $map[$key] = [pscustomobject]@{
                    Status = $statusTxt
                    Name   = [string](Get-Prop $r 'PolicyName')
                    Upn    = [string](Get-Prop $r 'UPN')
                }
            }
        }
    } catch {
        Add-RunLog -Level warn -Message ("Reported-status lookup failed for device {0}: {1}" -f $IntuneDeviceId, (Format-RsopError $_))
    }
    return $map
}

$script:ComplianceStatusNames = @{
    0 = 'Unknown'; 1 = 'Not applicable'; 2 = 'Compliant'; 3 = 'Remediated'; 4 = 'Not compliant'; 5 = 'Error'; 6 = 'Conflict'; 7 = 'Not assigned'
}

function Get-ReportedComplianceStatus {
    # Per-policy compliance state the device reported. Primary: the reporting pipeline the
    # portal uses (getDevicePoliciesComplianceReport); fallback: deviceCompliancePolicyStates.
    # Returns @{ policyIdLower = 'Compliant' ... }
    param([string]$IntuneDeviceId)
    $map = @{}
    $fmt = {
        param($raw, $loc)
        if ($loc) { return [string]$loc }
        $n = 0
        if ([int]::TryParse("$raw", [ref]$n) -and $script:ComplianceStatusNames.ContainsKey($n)) { return $script:ComplianceStatusNames[$n] }
        return (ConvertTo-FriendlyName "$raw")
    }
    try {
        $skip = 0
        while ($true) {
            $body = @{ select = @('PolicyId', 'PolicyName', 'PolicyStatus', 'LastContact'); filter = "(DeviceId eq '$IntuneDeviceId')"; skip = $skip; top = 50 }
            $rows = @(ConvertFrom-ReportGrid -Response (Invoke-RsopStream -Uri 'beta/deviceManagement/reports/getDevicePoliciesComplianceReport' -Body $body))
            foreach ($r in $rows) {
                $pid0 = [string](Get-Prop $r 'PolicyId')
                if ($pid0) { $map[$pid0.ToLower()] = (& $fmt (Get-Prop $r 'PolicyStatus') (Get-Prop $r 'PolicyStatus_loc')) }
            }
            if ($rows.Count -lt 50) { break }
            if ($skip -ge 950) { Add-RunLog -Level warn -Message ("Device-reported compliance for {0} exceeded 1,000 rows and was truncated." -f $IntuneDeviceId); break }
            $skip += 50
        }
    } catch {
        Add-RunLog -Level info -Message ("Compliance report for device failed ({0}); trying deviceCompliancePolicyStates." -f (Format-RsopError $_))
    }
    if ($map.Count -eq 0) {
        try {
            foreach ($s in (Get-RsopPaged -Uri ("beta/deviceManagement/managedDevices/{0}/deviceCompliancePolicyStates" -f $IntuneDeviceId))) {
                $sid = [string]$s['id']
                $m = [regex]::Match($sid, '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')
                if ($m.Success) { $map[$m.Value.ToLower()] = (& $fmt $s['state'] $null) }
                if ($s['displayName']) { $map['name:' + ([string]$s['displayName']).ToLower()] = (& $fmt $s['state'] $null) }
            }
        } catch { Add-RunLog -Level info -Message ("deviceCompliancePolicyStates unavailable: {0}" -f (Format-RsopError $_)) }
    }
    return $map
}

function Get-ReportedRemediationStatus {
    # Remediation (device health script) results for one device. @{ policyIdLower = 'text' }
    param([string]$IntuneDeviceId)
    $map = @{}
    try {
        foreach ($s in (Get-RsopPaged -Uri ("beta/deviceManagement/managedDevices/{0}/deviceHealthScriptStates" -f $IntuneDeviceId))) {
            $pid0 = [string]$s['policyId']
            if (-not $pid0) { continue }
            $when = Format-GraphDate $s['lastStateUpdateDateTime']
            if ($when.Length -ge 16) { $when = $when.Substring(0, 16) -replace 'T', ' ' }
            $txt = ("detection: {0} · remediation: {1}{2}" -f $s['detectionState'], $s['remediationState'], $(if ($when) { " ($when)" } else { '' }))
            $out = [string]$s['preRemediationDetectionScriptOutput']
            if ($out) { if ($out.Length -gt 160) { $out = $out.Substring(0, 160) + '...' }; $txt += " · output: $out" }
            $map[$pid0.ToLower()] = $txt
        }
    } catch { Add-RunLog -Level info -Message ("Remediation states unavailable for device {0}: {1}" -f $IntuneDeviceId, (Format-RsopError $_)) }
    return $map
}

$script:ReportedIntentMap = @{
    requiredInstall = 'required'; requiredUninstall = 'uninstall'; available = 'available'; requiredAndAvailableInstall = 'requiredAndAvailable'
    availableInstallWithoutEnrollment = 'availableWithoutEnrollment'; exclude = 'excluded'; notAvailable = 'notAvailable'
}

function Get-ReportedAppStates {
    # Intune's own resolved intent + install state for every app on this device
    # (users/{primaryUser}/mobileAppIntentAndStates - the data behind the device's Managed
    # Apps blade). Returns @{ appIdLower = @{ Intent; InstallState; Name; Version } }
    param([string]$UserId, [string]$IntuneDeviceId)
    $map = @{}
    if (-not $UserId -or $UserId -eq '00000000-0000-0000-0000-000000000000') { return $map }
    $entry = $null
    try {
        foreach ($e in (Get-RsopPaged -Uri ("beta/users/{0}/mobileAppIntentAndStates" -f $UserId))) {
            if ([string]$e['managedDeviceIdentifier'] -ieq $IntuneDeviceId -or [string]$e['id'] -ieq $IntuneDeviceId) { $entry = $e; break }
        }
    } catch {
        try { $entry = Invoke-Rsop -Uri ("beta/users/{0}/mobileAppIntentAndStates/{1}" -f $UserId, $IntuneDeviceId) } catch {
            Add-RunLog -Level info -Message ("Device app states unavailable: {0}" -f (Format-RsopError $_))
        }
    }
    if ($null -eq $entry) { return $map }
    foreach ($a in (ConvertTo-RsopList $entry['mobileAppList'])) {
        $aid = [string]$a['applicationId']
        if (-not $aid) { continue }
        $map[$aid.ToLower()] = [pscustomobject]@{
            Intent       = [string]$a['mobileAppIntent']
            InstallState = [string]$a['installState']
            Name         = [string]$a['displayName']
            Version      = [string]$a['displayVersion']
        }
    }
    return $map
}

function ConvertTo-AutopilotStatusLabel {
    # deploymentProfileAssignmentStatus -> words (the service enum really is spelled 'Unkown')
    param([string]$Status)
    switch ($Status) {
        'assignedUnkownSyncState' { return 'assigned, sync state unknown' }
        'assignedInSync'          { return 'assigned, in sync' }
        'assignedOutOfSync'       { return 'assigned, out of sync' }
        'notAssigned'             { return 'not assigned' }
        default                   { return $Status }
    }
}

function Get-AutopilotRecord {
    # The device's Windows Autopilot registration and the profile the service actually
    # assigned (authoritative over the predicted one).
    param([string]$SerialNumber)
    if (-not $SerialNumber) { return $null }
    $esc = $SerialNumber -replace "'", "''"
    $rec = $null
    try {
        $filter = "contains(serialNumber,'{0}')" -f $esc
        $hits = @(Get-RsopPaged -Uri ("beta/deviceManagement/windowsAutopilotDeviceIdentities?`$filter={0}" -f [uri]::EscapeDataString($filter)))
        $rec = @($hits | Where-Object { [string]$_['serialNumber'] -ieq $SerialNumber })[0]
    } catch {
        Add-RunLog -Level info -Message ("Autopilot record lookup failed: {0}" -f (Format-RsopError $_))
        return $null
    }
    if ($null -eq $rec) { return $null }
    $prof = $null; $intended = $null; $readable = $false
    # the profile navigations only come back through $expand on a GET by id - the direct
    # /{id}/deploymentProfile path answers 400 'No OData route' in production tenants
    try {
        $full = Invoke-Rsop -Uri ("beta/deviceManagement/windowsAutopilotDeviceIdentities/{0}?`$expand=deploymentProfile,intendedDeploymentProfile" -f $rec['id'])
        $prof = Get-Prop $full 'deploymentProfile'; $intended = Get-Prop $full 'intendedDeploymentProfile'; $readable = $true
    } catch {
        try { $prof = Invoke-Rsop -Uri ("beta/deviceManagement/windowsAutopilotDeviceIdentities/{0}/deploymentProfile?`$select=id,displayName" -f $rec['id']); $readable = $true } catch { }
        try { $intended = Invoke-Rsop -Uri ("beta/deviceManagement/windowsAutopilotDeviceIdentities/{0}/intendedDeploymentProfile?`$select=id,displayName" -f $rec['id']) } catch { }
    }
    $when = Format-GraphDate $rec['deploymentProfileAssignedDateTime']
    if ($when.Length -ge 10) { $when = $when.Substring(0, 10) }
    return [pscustomobject]@{
        GroupTag       = [string]$rec['groupTag']
        Status         = (ConvertTo-AutopilotStatusLabel ([string]$rec['deploymentProfileAssignmentStatus']))
        AssignedDate   = $when
        ProfileId      = [string](Get-Prop $prof 'id')
        ProfileName    = [string](Get-Prop $prof 'displayName')
        IntendedId     = [string](Get-Prop $intended 'id')
        IntendedName   = [string](Get-Prop $intended 'displayName')
        EnrollmentState = [string]$rec['enrollmentState']
        ProfileReadable = $readable
    }
}

#endregion

#region ---------- per-device orchestration --------------------------------------------------

function Get-DevicePlatform {
    param($Md)
    $os = [string](Get-Prop $Md 'operatingSystem')
    if ($os -match 'Windows') { return 'windows' }
    if ($os -match 'macOS|Mac OS') { return 'macos' }
    if ($os -match 'iOS|iPadOS') { return 'ios' }
    if ($os -match 'Android') { return 'android' }
    if ($os -match 'Linux') { return 'linux' }
    return 'other'
}

$script:DeviceLabels = @{
    azureADJoined = 'Microsoft Entra joined'; hybridAzureADJoined = 'Microsoft Entra hybrid joined'; azureADRegistered = 'Microsoft Entra registered'
    windowsAzureADJoin = 'Microsoft Entra join'; windowsAzureADJoinUsingDeviceAuth = 'Microsoft Entra join (device authentication)'
    windowsAutoEnrollment = 'Windows automatic enrollment'; windowsCoManagement = 'Co-management'; windowsBulkUserless = 'Bulk enrollment (userless)'
    windowsBulkAzureDomainJoin = 'Bulk Microsoft Entra join'; deviceEnrollmentManager = 'Device enrollment manager'; userEnrollment = 'User enrollment'
    appleBulkWithUser = 'Apple ADE with user affinity'; appleBulkWithoutUser = 'Apple ADE without user affinity'; appleUserEnrollment = 'Apple User Enrollment'
    androidEnterpriseDedicatedDevice = 'Android Enterprise dedicated'; androidEnterpriseFullyManaged = 'Android Enterprise fully managed'
    androidEnterpriseCorporateWorkProfile = 'Android Enterprise corporate work profile'
    mdm = 'MDM'; easMdm = 'EAS + MDM'; configurationManagerClientMdm = 'Configuration Manager + MDM (co-managed)'
    configurationManagerClient = 'Configuration Manager'; intuneClient = 'Intune PC agent'; msSense = 'Microsoft Defender for Endpoint'
    company = 'Corporate'; personal = 'Personal'; noncompliant = 'Not compliant'; inGracePeriod = 'In grace period'; configManager = 'Configuration Manager'
}

function ConvertTo-DeviceLabel {
    # Graph enum value -> the wording the Intune admin center uses.
    param([string]$Value)
    if (-not $Value) { return '' }
    if ($script:DeviceLabels.ContainsKey($Value)) { return $script:DeviceLabels[$Value] }
    return (ConvertTo-FriendlyName $Value)
}

function Get-FilterPhrase {
    # How an assignment filter reads in the report and the CSV: 'filter' for the Include mode
    # (Intune's default), 'exclude filter' for the Exclude mode.
    param([string]$Mode)
    if ($Mode -ieq 'exclude') { return 'exclude filter' }
    return 'filter'
}

function Get-AssignmentFilterName {
    param($Assignment)
    if (-not ($Assignment.FilterId -and $Assignment.FilterType -and $Assignment.FilterType -ne 'none')) { return $null }
    $fn = $Assignment.FilterId
    if ($script:FilterById.ContainsKey($Assignment.FilterId)) { $fn = $script:FilterById[$Assignment.FilterId].Name }
    return $fn
}

function ConvertTo-AssignmentSummary {
    # Human-readable summary of a policy's assignments (group names + filters).
    param($Assignments)
    $inc = @(); $exc = @()
    foreach ($a in @($Assignments)) {
        $fnote = ''
        $fn = Get-AssignmentFilterName -Assignment $a
        if ($fn) { $fnote = (" ({0}: {1})" -f (Get-FilterPhrase $a.FilterType), $fn) }
        # break per case: '*groupAssignmentTarget*' also matches the (case-insensitive)
        # exclusion type, and a switch without break runs every matching case
        switch -Wildcard ([string]$a.Type) {
            '*exclusionGroupAssignmentTarget*'   { $exc += ((Get-GroupName $a.GroupId)); break }
            '*configurationManagerCollectionAssignmentTarget*' { $inc += ("ConfigMgr collection {0}{1}" -f $a.CollectionId, $fnote); break }
            '*allDevicesAssignmentTarget*'       { $inc += ("All devices" + $fnote); break }
            '*allLicensedUsersAssignmentTarget*' { $inc += ("All users" + $fnote); break }
            '*groupAssignmentTarget*'            { $inc += ((Get-GroupName $a.GroupId) + $fnote); break }
        }
    }
    $parts = @()
    if ($inc.Count -gt 0) { $parts += ("Include: " + ($inc -join '; ')) }
    if ($exc.Count -gt 0) { $parts += ("Exclude: " + ($exc -join '; ')) }
    if ($parts.Count -eq 0) { return 'Not assigned' }
    return ($parts -join '  |  ')
}

function ConvertTo-AssignmentDetail {
    # Structured include/exclude breakdown of assignments - what the report's detail panes
    # render (target, filter + mode, delivery options, and the per-device hit marker).
    param($Assignments, $Hits)
    $asg = @($Assignments)
    $hl = @($Hits)
    $out = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $asg.Count; $i++) {
        $a = $asg[$i]
        $mode = 'Include'; $target = $null
        switch -Wildcard ([string]$a.Type) {
            '*exclusionGroupAssignmentTarget*'   { $mode = 'Exclude'; $target = ("Group: " + (Get-GroupName $a.GroupId)); break }
            '*configurationManagerCollectionAssignmentTarget*' { $target = ("ConfigMgr collection: {0}" -f $a.CollectionId); break }
            '*allDevicesAssignmentTarget*'       { $target = 'All devices'; break }
            '*allLicensedUsersAssignmentTarget*' { $target = 'All users'; break }
            '*groupAssignmentTarget*'            { $target = ("Group: " + (Get-GroupName $a.GroupId)); break }
            default                              { $target = [string]$a.Type }
        }
        if (-not $target) { continue }
        $fn = Get-AssignmentFilterName -Assignment $a
        $h = $(if ($i -lt $hl.Count) { $hl[$i] } else { $null })
        [void]$out.Add([pscustomobject]@{
            Mode       = $mode
            Target     = $target
            GroupId    = [string]$a.GroupId
            Filter     = [string]$fn
            FilterMode = $(if ($fn) { [string]$a.FilterType } else { '' })
            Intent     = [string]$a.Intent
            Options    = [string]$a.Options
            Hit        = $(if ($h) { [string]$h.Hit } else { '' })
            HitNote    = $(if ($h) { [string]$h.Note } else { '' })
        })
    }
    # plain array (no unary comma): every call site wraps this in @(), which would
    # otherwise double-wrap the returned array into a single element
    return $out.ToArray()
}

function ConvertTo-ScopeTagText {
    # Scope tag ids -> names. No tag means the built-in 'Default' tag (Intune puts every object
    # without a custom tag in Default; some list responses just leave the array empty).
    param($Ids)
    $names = @(@($Ids) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object {
            $(if ($script:ScopeTagNames[[string]$_]) { $script:ScopeTagNames[[string]$_] } elseif ([string]$_ -eq '0') { 'Default' } else { [string]$_ }) })
    if (-not $names.Count) { return 'Default' }
    return ($names -join ', ')
}

function New-PolicyEntry {
    # The per-scope policy row the report renders (Policies tab, inspector, matrix).
    param($Policy, [string]$Status, [string]$Via, $Hits)
    return [pscustomobject]@{
        PolicyId         = $Policy.Id
        Name             = $Policy.Name
        Family           = $Policy.Family
        FamilyLabel      = $Policy.FamilyLabel
        Platform         = [string]$Policy.Platform
        Intent           = ''
        Status           = $Status
        Via              = $Via
        Reported         = ''
        SettingCount     = @($Policy.Settings | Where-Object { $null -ne $_ }).Count
        Modified         = [string]$Policy.Modified
        Created          = $(if ($Policy.Created) { ([string](Format-GraphDate $Policy.Created)) -replace '^(\d{4}-\d{2}-\d{2}).*$', '$1' } else { '' })
        Detail           = [string]$Policy.Detail
        Desc             = [string]$Policy.Desc
        Priority         = [string]$Policy.Priority
        ScopeTags        = (ConvertTo-ScopeTagText -Ids $Policy.ScopeTags)
        TargetApps       = @(@($Policy.TargetApps) | Where-Object { $_ })
        Assignment       = (ConvertTo-AssignmentSummary -Assignments $Policy.Assignments)
        AssignmentDetail = @(ConvertTo-AssignmentDetail -Assignments $Policy.Assignments -Hits $Hits)
    }
}

function New-SettingRow {
    param($Setting, $Policy, [string]$PolicyName, [string]$Via, [string]$Status)
    $o = [ordered]@{
        Key         = $Setting.Key
        Setting     = $Setting.Setting
        Value       = $Setting.Value
        Category    = [string]$Setting.Category
        Info        = $Setting.Info
        InfoUrl     = $Setting.InfoUrl
        PolicyId    = $Policy.Id
        PolicyName  = $PolicyName
        FamilyLabel = $Policy.FamilyLabel
        Via         = $Via
        ConflictKeys = @($(if ($Setting.ConflictKeys) { $Setting.ConflictKeys } else { $Setting.Key }) | Where-Object { $null -ne $_ })
    }
    if ($Status) { $o['Status'] = $Status } else { $o['Conflict'] = '' }
    return [pscustomobject]$o
}

function Test-UnmanagedOnly {
    # MAM policies scoped to unmanaged devices never apply on an MDM-enrolled device.
    param($Policy)
    if ($Policy.UnmanagedOnly) { return $true }
    $lv = @(([string]$Policy.ManagementLevels) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    return ($lv.Count -gt 0 -and @($lv | Where-Object { $_ -ne 'unmanaged' }).Count -eq 0)
}

function Get-EnrollmentEvaluationContext {
    # Enrollment restrictions act at enrollment time. These inventory fields identify
    # known exceptions; current assignments do not reconstruct the historical decision.
    param($ManagedDevice)
    $type = [string](Get-Prop $ManagedDevice 'deviceEnrollmentType')
    $agent = [string](Get-Prop $ManagedDevice 'managementAgent')
    $join = [string](Get-Prop $ManagedDevice 'joinType')
    $enrollmentWindows = ([string](Get-Prop $ManagedDevice 'operatingSystem')) -match 'Windows'
    $nonUserDriven = $type -in @('windowsBulkUserless', 'windowsBulkAzureDomainJoin', 'windowsAzureADJoinUsingDeviceAuth',
        'windowsCoManagement', 'windowsAutoEnrollment', 'appleBulkWithoutUser', 'androidEnterpriseDedicatedDevice')
    $limitException = ''
    if ($enrollmentWindows) {
        if ((Get-Prop $ManagedDevice 'autopilotEnrolled') -eq $true) { $limitException = 'Windows Autopilot enrollment' }
        elseif ($type -in @('deviceEnrollmentManager', 'windowsBulkUserless', 'windowsBulkAzureDomainJoin')) { $limitException = 'device enrollment manager or bulk enrollment' }
        elseif ($type -eq 'windowsCoManagement' -or $agent -match 'configurationManager') { $limitException = 'co-management enrollment' }
        elseif ($type -eq 'windowsAutoEnrollment') { $limitException = 'Windows automatic enrollment (including Group Policy)' }
        elseif ($type -in @('windowsAzureADJoin', 'windowsAzureADJoinUsingDeviceAuth') -or $join -eq 'azureADJoined') { $limitException = 'Microsoft Entra joined Windows enrollment' }
    }
    return [pscustomobject]@{ NonUserDriven = $nonUserDriven; LimitException = $limitException }
}

function Get-RsopPriorityRank {
    # Internal ranking also represents an Unknown candidate's best possible precedence.
    param($Evaluated, [string]$Class)
    $p = $Evaluated.P
    if ($Class -eq 'autopilot') {
        $fallback = [bool]$Evaluated.DefaultForDevice
        if ($Evaluated.Entry.Status -eq 'Unknown' -and $Evaluated.CandidateGroupReach) { $fallback = $false }
        return ,@([long]$(if ($fallback) { 1 } else { 0 }), [long]0, (ConvertTo-GraphDateTime $p.Created).Ticks)
    }
    $kinds = @($Evaluated.Kinds)
    if ($Evaluated.Entry.Status -eq 'Unknown') {
        $kinds = @($Evaluated.CandidateKinds)
        if (-not $kinds.Count) { $kinds = $(if ($p.TargetKinds -in @('user', 'device')) { @($p.TargetKinds) } else { @('device', 'user') }) }
    }
    $priority = [int]::MaxValue
    $parsed = 0
    if ([int]::TryParse([string]$p.Priority, [ref]$parsed)) { $priority = $parsed }
    return ,@([long]$(if ($p.IsDefault) { 1 } else { 0 }), [long]$(if ($Class -eq 'esp' -and $kinds -notcontains 'device') { 1 } else { 0 }), [long]$priority)
}

function Compare-RsopPriorityRank {
    param($Left, $Right)
    for ($i = 0; $i -lt 3; $i++) {
        if ($Left[$i] -lt $Right[$i]) { return -1 }
        if ($Left[$i] -gt $Right[$i]) { return 1 }
    }
    return 0
}

function Resolve-PriorityWinners {
    # Intune applies exactly one Enrollment Status Page / enrollment restriction / device
    # limit / co-management configuration, and one Autopilot profile, per device. Pick the
    # winner per class and mark the rest Superseded:
    #  - enrollment configurations: lowest priority number wins, default last; for ESP a
    #    device-targeted profile beats any user-targeted one
    #    (learn.microsoft.com/intune/device-enrollment/windows/setup-status-page#prioritize-profiles)
    #  - Autopilot: the oldest created profile wins
    #    (learn.microsoft.com/autopilot/profiles#windows-autopilot-profile-priority)
    param($Evaluated, [string]$DevPlatform)
    $groups = @{}
    foreach ($ev in $Evaluated) {
        $cls = [string]$ev.P.PriorityClass
        if (-not $cls -or $cls -like 'notification:*') { continue }
        if ($ev.Entry.Status -notin @('Applies', 'Unknown')) { continue }
        if ($cls -eq 'restriction:*') { $cls = "restriction:$DevPlatform" }   # the tenant default covers every platform
        if (-not $groups.ContainsKey($cls)) { $groups[$cls] = [System.Collections.Generic.List[object]]::new() }
        [void]$groups[$cls].Add($ev)
    }
    foreach ($cls in @($groups.Keys)) {
        $list = $groups[$cls].ToArray()
        $ranked = @(foreach ($ev in $list) { [pscustomobject]@{ E = $ev; Rank = (Get-RsopPriorityRank -Evaluated $ev -Class $cls) } })
        $known = @($ranked | Where-Object { $_.E.Entry.Status -eq 'Applies' } | Sort-Object @{ e = { $_.Rank[0] } }, @{ e = { $_.Rank[1] } }, @{ e = { $_.Rank[2] } })
        if (-not $known.Count) { continue }
        $sorted = @($known | ForEach-Object { $_.E })
        if ($cls -eq 'autopilot') {
            $why = 'a specific group assignment beats All devices fallback, then the oldest created profile wins'
        }
        else {
            $why = $(if ($cls -eq 'esp') { 'device-targeted profiles beat user-targeted ones, then the lowest priority number wins' } else { 'the lowest priority number wins' })
        }
        $win = $sorted[0]
        $contenders = @($ranked | Where-Object { $_.E.Entry.Status -eq 'Unknown' -and (Compare-RsopPriorityRank -Left $_.Rank -Right $known[0].Rank) -le 0 })
        if ($contenders.Count) {
            $win.Entry.Status = 'Unknown'
            $win.Entry.Via = ("Effective configuration is unknown: '{0}' could take precedence ({1}) | {2}" -f (($contenders | ForEach-Object { $_.E.P.Name }) -join "', '"), $why, $win.Entry.Via)
        }
        $winDesc = $(if ($cls -eq 'autopilot') { "created $((ConvertTo-GraphDateTime $win.P.Created).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture))" } elseif ($win.P.IsDefault) { 'default' } else { "priority $($win.P.Priority)" })
        if ($sorted.Count -gt 1 -and -not $contenders.Count) {
            $win.Entry.Via = ("Effective - wins over {0} other configuration(s) ({1}) | {2}" -f ($sorted.Count - 1), $why, $win.Entry.Via)
        }
        foreach ($ev in @($sorted | Select-Object -Skip 1)) {
            $ev.Entry.Status = 'Superseded'
            $ev.Entry.Via = ("Superseded by {0}'{1}' ({2}; {3}) | {4}" -f $(if ($contenders.Count) { 'at least ' } else { '' }), $win.P.Name, $winDesc, $why, $ev.Entry.Via)
        }
    }
}

function New-AppEntry {
    # One app row for the Apps tab: per-intent targets with hit markers + resolution.
    param($App, $Result, $Reported, $ConfigPolicies)
    $intents = @()
    foreach ($i in @($Result.Intents | Where-Object { $null -ne $_ })) {
        $intents += [pscustomobject]@{
            Intent  = $i.Intent
            Label   = $(if ($script:IntentLabels[$i.Intent]) { $script:IntentLabels[$i.Intent] } else { ConvertTo-FriendlyName $i.Intent })
            Status  = $i.Status
            Via     = (@($i.Via) -join ' | ')
            Targets = @(ConvertTo-AssignmentDetail -Assignments $i.Sub -Hits $(if ($i.R) { $i.R.Hits } else { $null }))
        }
    }
    $eff = [string]$Result.EffectiveIntent
    $label = switch ($Result.Status) {
        'Applies'     { $script:IntentLabels[$eff] }
        'FilteredOut' { 'Filtered out' }
        'Excluded'    { 'Excluded' }
        'Unknown'     { 'Unknown' }
        'Assigned'    { 'Assigned' }
        default       { [string]$Result.Status }
    }
    $rep = $null
    if ($Reported) {
        $rk = $script:ReportedIntentMap[[string]$Reported.Intent]
        $pred = $(if ($Result.Status -eq 'Applies') { $eff } else { 'none' })
        $mismatch = $false
        if ($rk -and $Result.Status -ne 'Unknown') {
            if ($pred -eq 'none') { $mismatch = ($rk -notin @('excluded', 'notAvailable')) }
            else { $mismatch = ($rk -ne $pred) -and -not ($pred -eq 'requiredAndAvailable' -and $rk -eq 'required') }
        }
        $rep = [pscustomobject]@{
            Intent       = $(if ($rk -and $script:IntentLabels[$rk]) { $script:IntentLabels[$rk] } elseif ($rk) { ConvertTo-FriendlyName $rk } else { [string]$Reported.Intent })
            InstallState = (ConvertTo-FriendlyName ([string]$Reported.InstallState))
            Version      = [string]$Reported.Version
            Mismatch     = $mismatch
        }
    }
    return [pscustomobject]@{
        AppId          = $App.Id
        Name           = $App.Name
        Type           = $App.Type
        Platform       = $App.Platform
        Publisher      = $App.Publisher
        Version        = $App.Version
        Desc           = $App.Desc
        Modified       = $App.Modified
        Created        = $(if ($App.Created) { Format-GraphDate $App.Created } else { '' })
        ScopeTags      = (ConvertTo-ScopeTagText -Ids $App.ScopeTags)
        Status         = $Result.Status
        EffectiveIntent = $eff
        EffectiveLabel = $label
        Resolution     = [string]$Result.Resolution
        IntentConflict = [bool]$Result.IntentConflict
        Intents        = $intents
        Reported       = $rep
        Info           = @($App.Info | Where-Object { $null -ne $_ })
        Relationships  = @($App.Relationships | Where-Object { $null -ne $_ })
        ConfigPolicies = @($ConfigPolicies | Where-Object { $null -ne $_ })
    }
}

function Get-AppConfigIndex {
    # appId -> app configuration / protection policies that target it
    param($Corpus, [hashtable]$StatusById)
    $idx = @{}
    foreach ($p in @($Corpus.policies)) {
        foreach ($t in @($p.TargetApps)) {
            if (-not $t -or -not $t.AppId) { continue }
            if (-not $idx.ContainsKey($t.AppId)) { $idx[$t.AppId] = [System.Collections.Generic.List[object]]::new() }
            $st = $(if ($StatusById -and $StatusById.ContainsKey($p.Id)) { $StatusById[$p.Id] } elseif ($StatusById) { 'NotTargeted' } else { $(if (@($p.Assignments).Count) { 'Assigned' } else { 'NotAssigned' }) })
            [void]$idx[$t.AppId].Add([pscustomobject]@{ PolicyId = $p.Id; Name = $p.Name; FamilyLabel = $p.FamilyLabel; Status = $st })
        }
    }
    return $idx
}

function Get-AppIntentSkeleton {
    # Intents for scopes without device math (inventory / group): targets grouped by intent.
    param($App, [scriptblock]$HitFor)
    $asg = @($App.Assignments)
    $order = @('required', 'available', 'uninstall', 'availableWithoutEnrollment')
    $present = @($asg | ForEach-Object { [string]$_.Intent } | Where-Object { $_ } | Select-Object -Unique)
    $present = @($order | Where-Object { $present -contains $_ }) + @($present | Where-Object { $order -notcontains $_ })
    $out = @()
    foreach ($it in $present) {
        $sub = @($asg | Where-Object { [string]$_.Intent -eq $it })
        $hits = $null
        if ($HitFor) { $hits = @($sub | ForEach-Object { & $HitFor $_ }) }
        $out += [pscustomobject]@{ Intent = $it; Sub = $sub; R = $(if ($hits) { [pscustomobject]@{ Hits = $hits } } else { $null }); Status = 'Assigned'; Via = @() }
    }
    return , $out
}

function Resolve-DeviceRsop {
    param($ManagedDevice, $Corpus)

    $md = $ManagedDevice
    $mdName = [string](Get-Prop $md 'deviceName')
    $mdId = [string](Get-Prop $md 'id')
    Write-Step ("Resolving device: {0}  (serial: {1})" -f $mdName, (Get-Prop $md 'serialNumber'))

    $ctx = Get-DeviceContext -ManagedDevice $md
    Write-Info ("Entra groups - device: {0}, primary user: {1}" -f $ctx.DeviceGroupIds.Count, $ctx.UserGroupIds.Count)

    # Resolve display names for every group referenced by any assignment - membership
    # reasons, exclusions AND the per-policy assignment breakdown all need names, not GUIDs.
    # The group list and the assigned policies are worked out once per corpus, not per device.
    if (-not [object]::ReferenceEquals($script:EvalCorpus, $Corpus)) {
        $mentioned = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($p in @(@($Corpus.policies) + @($Corpus.apps))) {
            foreach ($a in @($p.Assignments)) {
                if ($a.GroupId) { [void]$mentioned.Add([string]$a.GroupId) }
            }
        }
        $script:EvalGroupIds = [string[]]@($mentioned)
        $script:EvalPolicies = @($Corpus.policies | Where-Object { @($_.Assignments).Count -gt 0 -or $_.AssignmentsUnreadable })
        $script:EvalCorpus = $Corpus
    }
    Resolve-GroupNames -Ids $script:EvalGroupIds

    $devPlatform = Get-DevicePlatform -Md $md
    $enrollmentContext = Get-EnrollmentEvaluationContext -ManagedDevice $md

    $evaluated = [System.Collections.Generic.List[object]]::new()
    $evalPolicies = $script:EvalPolicies
    $n = 0
    foreach ($p in $evalPolicies) {
        $n++
        Write-RsopProgress -Id 5 -Activity ("Evaluating policies for {0}" -f $mdName) -Status ("{0}/{1}  {2}" -f $n, $evalPolicies.Count, $p.Name) -Percent ([int](100 * $n / [math]::Max(1, $evalPolicies.Count)))

        if ($devPlatform -ne 'other' -and $p.Platform -ne 'other' -and $p.Platform -ne $devPlatform) { continue }

        # MAM is user-targeted; Autopilot profiles / restrictions carry their own kind
        $tk = [string]$p.TargetKinds
        if (-not $tk) { $tk = $(if ($p.Family -in @('mam', 'appconfig-mam')) { 'user' } else { 'both' }) }
        if ($p.PriorityClass -like 'restriction:*' -and $p.IsDefault -and $enrollmentContext.NonUserDriven) { $tk = 'both' }
        $app = Get-PolicyApplicability -Policy $p -Ctx $ctx -TargetKinds $tk
        if ($app.Status -eq 'NotTargeted') { continue }

        $status = $app.Status
        $via = (@($app.Reasons) -join ' | ')
        if ($p.Family -in @('mam', 'appconfig-mam') -and $status -in @('Applies', 'Unknown') -and (Test-UnmanagedOnly -Policy $p)) {
            $status = 'NotApplicable'
            $via = ("Targets unmanaged devices only ({0}) - not applied to an MDM-enrolled device | {1}" -f $(if ($p.ManagementLevels) { $p.ManagementLevels } else { 'MAM for unmanaged devices' }), $via)
        }
        if ($p.Family -eq 'enrollment') {
            if ($status -in @('Applies', 'Unknown') -and $p.PriorityClass -eq 'limit' -and $enrollmentContext.LimitException) {
                $status = 'NotApplicable'
                $via = ("Intune device-limit restrictions do not apply to {0} | {1}" -f $enrollmentContext.LimitException, $via)
            }
            elseif ($status -in @('Applies', 'Unknown') -and $p.PriorityClass -like 'restriction:*' -and -not $p.IsDefault -and $enrollmentContext.NonUserDriven) {
                $status = 'NotApplicable'
                $via = "A non-user-driven enrollment uses the default platform restriction | $via"
            }
            $via = "Enrollment snapshot: current configuration and assignments; original enrollment enforcement is not verified | $via"
        }
        $entry = New-PolicyEntry -Policy $p -Status $status -Via $via -Hits $app.Hits
        $defaultForDevice = [bool]$p.IsDefault
        if ($p.Family -eq 'autopilot') {
            $specific = $false
            for ($aIndex = 0; $aIndex -lt @($p.Assignments).Count; $aIndex++) {
                if ($p.Assignments[$aIndex].Type -eq 'groupAssignmentTarget' -and $app.Hits[$aIndex].Hit -eq 'applies') { $specific = $true; break }
            }
            $defaultForDevice = -not $specific
        }
        [void]$evaluated.Add([pscustomobject]@{ P = $p; Entry = $entry; Kinds = @($app.Kinds); CandidateKinds = @($app.CandidateKinds); CandidateGroupReach = [bool]$app.CandidateGroupReach; DefaultForDevice = $defaultForDevice })
    }
    Complete-RsopProgress -Id 5

    Resolve-PriorityWinners -Evaluated $evaluated -DevPlatform $devPlatform

    $policyResults = [System.Collections.Generic.List[object]]::new()
    $settingRows = [System.Collections.Generic.List[object]]::new()
    $shadowRows = [System.Collections.Generic.List[object]]::new()   # settings of targeted-but-not-applying policies (report "near misses")
    $definitePolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($ev in $evaluated) {
        $p = $ev.P; $entry = $ev.Entry
        [void]$policyResults.Add($entry)
        if ($entry.Status -eq 'Applies') { [void]$definitePolicyIds.Add([string]$p.Id) }
        if ($entry.Status -eq 'Applies' -or $entry.Status -eq 'Unknown') {
            $tag = $(if ($entry.Status -eq 'Unknown') { ' [applicability unknown]' } else { '' })
            foreach ($s in @($p.Settings)) { [void]$settingRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName ($p.Name + $tag) -Via $entry.Via)) }
        }
        elseif ($shadowRows.Count -lt 4000) {
            foreach ($s in @($p.Settings)) { [void]$shadowRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName $p.Name -Via $entry.Via -Status $entry.Status)) }
        }
    }
    if ($shadowRows.Count -ge 4000) {
        Add-RunLog -Level info -Message ("{0}: settings of excluded/filtered policies capped at 4000 rows for report size" -f $mdName)
    }

    # Cross-check with what the device actually reported.
    if (-not $SkipReportedStatus) {
        $reported = Get-ReportedPolicyStatus -IntuneDeviceId $mdId
        $known = New-Object 'System.Collections.Generic.HashSet[string]'
        $reportFamilies = @('catalog', 'legacy', 'admx', 'intent')
        foreach ($pr in $policyResults) {
            $k = ([string]$pr.PolicyId).ToLower()
            [void]$known.Add($k)
            if ($reported.ContainsKey($k)) { $pr.Reported = $reported[$k].Status }
            elseif ($pr.Status -eq 'Applies' -and $pr.Family -in $reportFamilies) { $pr.Reported = 'not in device report' }
        }
        foreach ($k in $reported.Keys) {
            if (-not $known.Contains($k)) {
                $r = $reported[$k]
                [void]$policyResults.Add([pscustomobject]@{
                    PolicyId    = $k
                    Name        = $r.Name
                    Family      = 'reported'
                    FamilyLabel = 'Reported by device (not predicted - verify targeting)'
                    Platform    = ''
                    Intent      = ''
                    Status      = 'ReportedOnly'
                    Via         = 'Device check-in report'
                    Reported    = $r.Status
                    SettingCount = 0
                    Modified    = ''
                    Detail      = ''
                    Desc        = ''
                    Priority    = ''
                    TargetApps  = @()
                    Assignment  = ''
                    AssignmentDetail = @()
                })
            }
        }
        if (-not $SkipCompliance) {
            $comp = Get-ReportedComplianceStatus -IntuneDeviceId $mdId
            foreach ($pr in @($policyResults | Where-Object { $_.Family -eq 'compliance' })) {
                $k = ([string]$pr.PolicyId).ToLower()
                if ($comp.ContainsKey($k)) { $pr.Reported = $comp[$k] }
                elseif ($comp.ContainsKey('name:' + ([string]$pr.Name).ToLower())) { $pr.Reported = $comp['name:' + ([string]$pr.Name).ToLower()] }
            }
        }
        if (-not $SkipScripts -and @($policyResults | Where-Object { $_.Family -eq 'remediation' }).Count) {
            $rem = Get-ReportedRemediationStatus -IntuneDeviceId $mdId
            foreach ($pr in @($policyResults | Where-Object { $_.Family -eq 'remediation' })) {
                $k = ([string]$pr.PolicyId).ToLower()
                if ($rem.ContainsKey($k)) { $pr.Reported = $rem[$k] }
            }
        }
    }

    # Autopilot: the service's assigned profile is authoritative over the prediction.
    $apText = ''
    if (-not $SkipEnrollment -and $devPlatform -eq 'windows') {
        $apr = Get-AutopilotRecord -SerialNumber ([string](Get-Prop $md 'serialNumber'))
        if ($apr) {
            $bits = @()
            if ($apr.ProfileName) { $bits += ("profile '{0}'" -f $apr.ProfileName) } elseif ($apr.ProfileReadable) { $bits += 'no profile assigned' } else { $bits += 'profile not readable' }
            if ($apr.Status) { $bits += $apr.Status }
            if ($apr.AssignedDate) { $bits += ("assigned {0}" -f $apr.AssignedDate) }
            if ($apr.GroupTag) { $bits += ("group tag '{0}'" -f $apr.GroupTag) }
            if ($apr.IntendedName -and $apr.IntendedId -ne $apr.ProfileId) { $bits += ("intended '{0}' (pending)" -f $apr.IntendedName) }
            $apText = $bits -join ' · '
            foreach ($pr in @($policyResults | Where-Object { $_.Family -eq 'autopilot' })) {
                if ($apr.ProfileId -and [string]$pr.PolicyId -ieq $apr.ProfileId) { $pr.Reported = ("assigned per Autopilot record ({0})" -f $apr.Status) }
                elseif ($apr.IntendedId -and [string]$pr.PolicyId -ieq $apr.IntendedId) { $pr.Reported = 'intended per Autopilot record (pending)' }
                elseif (-not $apr.ProfileId -and -not $apr.IntendedId) {
                    # no profile on the record (or not readable): never claim a mismatch
                    $pr.Reported = $(if ($apr.ProfileReadable) { ("Autopilot record has no profile ({0})" -f $apr.Status) } else { 'Autopilot record profile not readable' })
                }
                else { $pr.Reported = 'not the profile on the Autopilot record' }
            }
        }
        else { $apText = 'not registered in Windows Autopilot (or record not readable)' }
    }

    # Conflict detection: same setting key from >1 applicable policy.
    $byKey = @{}
    foreach ($row in $settingRows) {
        if (-not $definitePolicyIds.Contains([string]$row.PolicyId)) { continue }
        foreach ($k in @($row.ConflictKeys)) {
            if (-not $k) { continue }
            if (-not $byKey.ContainsKey($k)) { $byKey[$k] = [System.Collections.Generic.List[object]]::new() }
            [void]$byKey[$k].Add($row)
        }
    }
    $conflicts = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $byKey.Keys) {
        $rows = $byKey[$k]
        $policies = @($rows | Select-Object -ExpandProperty PolicyId -Unique)
        if ($policies.Count -lt 2) { continue }
        $values = @($rows | Select-Object -ExpandProperty Value -Unique)
        $flag = if ($values.Count -gt 1) { 'CONFLICT' } else { 'Duplicate' }
        foreach ($r in $rows) {
            # An app-scoped row can participate in several comparisons. A duplicate
            # on one app must not erase a conflict already found on another app.
            if ($flag -eq 'CONFLICT' -or $r.Conflict -ne 'CONFLICT') { $r.Conflict = $flag }
        }
        if ($flag -eq 'CONFLICT') {
            $targetApp = ''
            if ($k -match '^(appcfg|mamcfg|mam):([^:]+):' -and $Matches[2] -ne 'policy') { $targetApp = $Matches[2] }
            [void]$conflicts.Add([pscustomobject]@{
                Key     = $k
                Kind    = 'setting'
                Setting = $rows[0].Setting + $(if ($targetApp) { " (app: $targetApp)" } else { '' })
                TargetApp = $targetApp
                Sources = @($rows | ForEach-Object { [pscustomobject]@{ Policy = $_.PolicyName; PolicyId = $_.PolicyId; Value = $_.Value } })
            })
        }
    }

    # Applications: one entry per app, intent resolved for this device.
    $appResults = [System.Collections.Generic.List[object]]::new()
    if (@($Corpus.apps).Count -gt 0) {
        $appStates = @{}
        if (-not $SkipReportedStatus) { $appStates = Get-ReportedAppStates -UserId ([string](Get-Prop $md 'userId')) -IntuneDeviceId $mdId }
        $statusById = @{}
        foreach ($pr in $policyResults) { $statusById[[string]$pr.PolicyId] = $pr.Status }
        $cfgIdx = Get-AppConfigIndex -Corpus $Corpus -StatusById $statusById
        $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        $nA = 0
        $appList = @($Corpus.apps)
        foreach ($a in $appList) {
            $nA++
            if (@($a.Assignments).Count -eq 0 -and -not $a.AssignmentsUnreadable) { continue }
            if ($devPlatform -ne 'other' -and $a.Platform -ne 'other' -and $a.Platform -ne $devPlatform) { continue }
            Write-RsopProgress -Id 5 -Activity ("Resolving apps for {0}" -f $mdName) -Status ("{0}/{1}  {2}" -f $nA, $appList.Count, $a.Name) -Percent ([int](100 * $nA / [math]::Max(1, $appList.Count)))
            $r = Get-AppApplicability -App $a -Ctx $ctx
            $touched = ($r.Status -ne 'NotTargeted') -or @($r.Intents | Where-Object { $_.Status -ne 'NotTargeted' }).Count -gt 0
            $rep = $appStates[([string]$a.Id).ToLower()]
            if (-not $touched -and -not $rep) { continue }
            [void]$seen.Add([string]$a.Id)
            [void]$appResults.Add((New-AppEntry -App $a -Result $r -Reported $rep -ConfigPolicies $(if ($cfgIdx.ContainsKey($a.Id)) { $cfgIdx[$a.Id].ToArray() } else { @() })))
        }
        Complete-RsopProgress -Id 5
        # apps Intune reports an active intent for, that no assignment in the snapshot predicts
        foreach ($k in $appStates.Keys) {
            if ($seen.Contains($k)) { continue }
            $s = $appStates[$k]
            $rk = $script:ReportedIntentMap[[string]$s.Intent]
            if (-not $rk -or $rk -in @('excluded', 'notAvailable')) { continue }
            $knownApp = @($appList | Where-Object { ([string]$_.Id) -ieq $k })[0]
            $stub = [pscustomobject]@{
                Id = $k; Name = $(if ($knownApp) { $knownApp.Name } else { $s.Name }); Type = $(if ($knownApp) { $knownApp.Type } else { '' })
                Platform = $(if ($knownApp) { $knownApp.Platform } else { '' }); Publisher = $(if ($knownApp) { $knownApp.Publisher } else { '' })
                Version = $(if ($knownApp) { $knownApp.Version } else { $s.Version }); Desc = ''; Modified = $(if ($knownApp) { $knownApp.Modified } else { '' })
                Info = $(if ($knownApp) { @($knownApp.Info) } else { @() }); Relationships = $(if ($knownApp) { @($knownApp.Relationships) } else { @() })
            }
            $res = [pscustomobject]@{
                Status = 'ReportedOnly'; EffectiveIntent = $rk; IntentConflict = $false; Intents = @()
                Resolution = 'Intune reports this intent for the device, but no assignment in this snapshot predicts it - check nested / recently changed groups or a dependency / supersedence relationship.'
            }
            $entry = New-AppEntry -App $stub -Result $res -Reported $s -ConfigPolicies @()
            $entry.EffectiveLabel = $script:IntentLabels[$rk]
            [void]$appResults.Add($entry)
        }
        # Supersedence with 'replace': installing a Required superseding app uninstalls the
        # superseded app first - even when that app isn't assigned to the device at all.
        $byAppId = @{}
        foreach ($ae in $appResults.ToArray()) { $byAppId[([string]$ae.AppId).ToLower()] = $ae }
        foreach ($sup in @($appResults | Where-Object { $_.Status -eq 'Applies' -and $_.EffectiveIntent -in @('required', 'requiredAndAvailable') })) {
            foreach ($rel in @($sup.Relationships | Where-Object { $_ -and $_.Relation -eq 'Supersedes' -and $_.Type -eq 'replace' })) {
                $why = ("Replaced on this device: '{0}' supersedes it with 'replace' and is Required here, so Intune uninstalls this app before installing it." -f $sup.Name)
                $old = $byAppId[([string]$rel.TargetId).ToLower()]
                if ($old) {
                    $old.Resolution = (("{0} {1}" -f $old.Resolution, $why)).Trim()
                    $old | Add-Member -NotePropertyName ReplacedBy -NotePropertyValue $sup.Name -Force
                    continue
                }
                $knownOld = @($appList | Where-Object { ([string]$_.Id) -ieq [string]$rel.TargetId })[0]
                $stub = [pscustomobject]@{
                    Id = [string]$rel.TargetId; Name = $(if ($knownOld) { $knownOld.Name } else { [string]$rel.TargetName }); Type = $(if ($knownOld) { $knownOld.Type } else { '' })
                    Platform = $(if ($knownOld) { $knownOld.Platform } else { $sup.Platform }); Publisher = $(if ($knownOld) { $knownOld.Publisher } else { '' })
                    Version = $(if ($knownOld) { $knownOld.Version } else { [string]$rel.TargetVersion }); Desc = ''; Modified = $(if ($knownOld) { $knownOld.Modified } else { '' })
                    Info = $(if ($knownOld) { @($knownOld.Info) } else { @() })
                    Relationships = @([pscustomobject]@{ Relation = 'Superseded by'; Type = 'replace'; TargetId = $sup.AppId; TargetName = $sup.Name; TargetVersion = $sup.Version; Note = 'installing the superseding app uninstalls this one' })
                }
                $res = [pscustomobject]@{ Status = 'Applies'; EffectiveIntent = 'uninstall'; IntentConflict = $false; Intents = @(); Resolution = $why }
                $entry = New-AppEntry -App $stub -Result $res -Reported $appStates[([string]$rel.TargetId).ToLower()] -ConfigPolicies @()
                $entry.EffectiveLabel = 'Uninstall (superseded)'
                $entry | Add-Member -NotePropertyName ReplacedBy -NotePropertyValue $sup.Name -Force
                [void]$appResults.Add($entry)
                $byAppId[([string]$rel.TargetId).ToLower()] = $entry
            }
        }
        foreach ($ae in $appResults) {
            if (-not $ae.IntentConflict) { continue }
            [void]$conflicts.Add([pscustomobject]@{
                Key     = ("app:{0}" -f $ae.AppId)
                Kind    = 'app'
                Setting = ("App assignment intent: {0}" -f $ae.Name)
                Sources = @($ae.Intents | Where-Object { $_.Status -in @('Applies', 'Overridden', 'FilteredOut', 'Unknown') } | ForEach-Object {
                        [pscustomobject]@{
                            Policy   = ("{0} via {1}" -f $_.Label, $(if ($_.Via) { $_.Via } else { 'assignment' }))
                            PolicyId = ("app:{0}" -f $ae.AppId)
                            Value    = $(if ($_.Status -eq 'Overridden') { "$($_.Label) (overridden)" } else { "$($_.Label) (wins: $($ae.EffectiveLabel))" })
                        } })
            })
        }
    }

    $applied = @($policyResults | Where-Object { $_.Status -eq 'Applies' })
    $appsOn = @($appResults | Where-Object { $_.Status -eq 'Applies' })
    Write-Good ("{0}: {1} policies apply, {2} settings, {3} conflicts, {4} excluded/filtered, {5} apps targeted" -f `
        $mdName, $applied.Count, $settingRows.Count, $conflicts.Count, `
        @($policyResults | Where-Object { $_.Status -in @('Excluded', 'FilteredOut') }).Count, $appsOn.Count)

    $own = [string](Get-Prop $md 'managedDeviceOwnerType'); if (-not $own) { $own = [string](Get-Prop $md 'ownerType') }
    $enr = Format-GraphDate (Get-Prop $md 'enrolledDateTime'); if ($enr.Length -ge 10) { $enr = $enr.Substring(0, 10) }
    $enc = Get-Prop $md 'isEncrypted'
    return [pscustomobject]@{
        Device = [pscustomobject]@{
            Scope           = 'device'
            DeviceName      = $mdName
            SerialNumber    = [string](Get-Prop $md 'serialNumber')
            IntuneDeviceId  = $mdId
            EntraDeviceId   = [string](Get-Prop $md 'azureADDeviceId')
            PrimaryUser     = [string](Get-Prop $md 'userPrincipalName')
            OS              = ("{0} {1}" -f (Get-Prop $md 'operatingSystem'), (Get-Prop $md 'osVersion')).Trim()
            Model           = ("{0} {1}" -f (Get-Prop $md 'manufacturer'), (Get-Prop $md 'model')).Trim()
            LastSync        = Format-GraphDate (Get-Prop $md 'lastSyncDateTime')
            Compliance      = (ConvertTo-DeviceLabel ([string](Get-Prop $md 'complianceState')))
            JoinType        = (ConvertTo-DeviceLabel ([string](Get-Prop $md 'joinType')))
            Ownership       = (ConvertTo-DeviceLabel $own)
            Enrolled        = $enr
            EnrollmentType  = (ConvertTo-DeviceLabel ([string](Get-Prop $md 'deviceEnrollmentType')))
            EnrollmentProfile = [string](Get-Prop $md 'enrollmentProfileName')
            ManagementAgent = (ConvertTo-DeviceLabel ([string](Get-Prop $md 'managementAgent')))
            Encrypted       = $(if ($null -eq $enc) { '' } elseif ($enc) { 'Yes' } else { 'No' })
            Autopilot       = $apText
            DeviceGroups    = @($ctx.DeviceGroupIds | ForEach-Object { Get-GroupName $_ } | Sort-Object)
            UserGroups      = @($ctx.UserGroupIds | ForEach-Object { Get-GroupName $_ } | Sort-Object)
        }
        Policies  = @($policyResults | Sort-Object @{e = { $_.Status -ne 'Applies' } }, FamilyLabel, Name)
        Settings  = @($settingRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Conflicts = @($conflicts | Sort-Object Setting)
        Shadow    = @($shadowRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Apps      = @($appResults | Sort-Object Name)
    }
}

function Get-GroupAssignedRsop {
    # -GroupAssignedOnly: which policies and apps directly reference this group (no device math).
    param($GroupObj, $Corpus)

    $gid = [string]$GroupObj.id
    $gname = [string]$GroupObj.displayName
    $policyResults = [System.Collections.Generic.List[object]]::new()
    $settingRows = [System.Collections.Generic.List[object]]::new()
    $hitFor = {
        param($a)
        if ([string]$a.GroupId -ne $gid) { return [pscustomobject]@{ Hit = ''; Note = '' } }
        if ($a.Type -like '*exclusion*') { return [pscustomobject]@{ Hit = 'excluding'; Note = 'This group is excluded' } }
        return [pscustomobject]@{ Hit = 'applies'; Note = 'Assigned to this group' }
    }.GetNewClosure()

    foreach ($p in @($Corpus.policies)) {
        foreach ($a in @($p.Assignments)) {
            if ([string]$a.GroupId -ne $gid) { continue }
            $isExcl = ($a.Type -like '*exclusion*')
            $fnote = ''
            $fn = Get-AssignmentFilterName -Assignment $a
            if ($fn) { $fnote = (", {0} '{1}'" -f (Get-FilterPhrase $a.FilterType), $fn) }
            $status = if ($isExcl) { 'Excluded' } else { 'Applies' }
            $via = $(if ($isExcl) { "Group '$gname' is EXCLUDED$fnote" } else { "Assigned to group '$gname'$fnote" })
            [void]$policyResults.Add((New-PolicyEntry -Policy $p -Status $status -Via $via -Hits @(@($p.Assignments) | ForEach-Object { & $hitFor $_ })))
            if (-not $isExcl) {
                foreach ($s in @($p.Settings)) { [void]$settingRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName $p.Name -Via $via)) }
            }
            break
        }
    }

    $appResults = [System.Collections.Generic.List[object]]::new()
    $cfgIdx = Get-AppConfigIndex -Corpus $Corpus
    foreach ($a in @($Corpus.apps)) {
        $mine = @(@($a.Assignments) | Where-Object { [string]$_.GroupId -eq $gid })
        if ($mine.Count -eq 0) { continue }
        $inc = @($mine | Where-Object { $_.Type -notlike '*exclusion*' })
        $ints = @($inc | ForEach-Object { $script:IntentLabels[[string]$_.Intent] } | Select-Object -Unique)
        $res = [pscustomobject]@{
            Status = $(if ($inc.Count) { 'Assigned' } else { 'Excluded' }); EffectiveIntent = $(if ($inc.Count -eq 1) { [string]$inc[0].Intent } else { '' })
            IntentConflict = $false; Intents = (Get-AppIntentSkeleton -App $a -HitFor $hitFor)
            Resolution = $(if ($inc.Count) { "Group '$gname' is assigned as: " + ($ints -join ', ') } else { "Group '$gname' is excluded" })
        }
        $e = New-AppEntry -App $a -Result $res -Reported $null -ConfigPolicies $(if ($cfgIdx.ContainsKey($a.Id)) { $cfgIdx[$a.Id].ToArray() } else { @() })
        if ($inc.Count) { $e.EffectiveLabel = ($ints -join ' + ') }
        [void]$appResults.Add($e)
    }

    return [pscustomobject]@{
        Device = [pscustomobject]@{
            Scope = 'group'
            DeviceName = "GROUP: $gname"; SerialNumber = ''; IntuneDeviceId = ''; EntraDeviceId = $gid
            PrimaryUser = ''; OS = '(policies and apps directly assigned to this group)'; Model = ''; LastSync = ''
            DeviceGroups = @(); UserGroups = @()
        }
        Policies  = @($policyResults | Sort-Object Status, FamilyLabel, Name)
        Settings  = @($settingRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Conflicts = @()
        Shadow    = @()
        Apps      = @($appResults | Sort-Object Name)
    }
}

function Test-InventoryScope {
    # -All scoping for one set of assignments: does it reach the scope group (directly, via a
    # parent group, or All devices / All users) and/or carry the scope filter?
    # Returns $null when out of scope, else @{ InScope; Reason; Hits }.
    param($Assignments, $ScopeGroup, $ScopeFilter)
    $asg = @($Assignments)
    $inc = New-Object System.Collections.Generic.List[string]
    $exc = New-Object System.Collections.Generic.List[string]
    $fhits = New-Object System.Collections.Generic.List[string]
    $filterOnInclude = $false
    $hits = New-HitArray -Count $asg.Count
    for ($i = 0; $i -lt $asg.Count; $i++) {
        $a = $asg[$i]
        $isExcl = ([string]$a.Type -like '*exclusionGroupAssignmentTarget*')
        $target = ''
        switch -Wildcard ([string]$a.Type) {
            '*allDevicesAssignmentTarget*'       { $target = 'All devices'; break }
            '*allLicensedUsersAssignmentTarget*' { $target = 'All users'; break }
            '*GroupAssignmentTarget*'            { if ($a.GroupId) { $target = ("group '{0}'" -f (Get-GroupName $a.GroupId)) }; break }
        }
        $fnote = ''
        $fn = Get-AssignmentFilterName -Assignment $a
        if ($fn) { $fnote = (" ({0}: {1})" -f (Get-FilterPhrase $a.FilterType), $fn) }
        $ipfx = $(if ($a.Intent) { "$($script:IntentLabels[[string]$a.Intent]): " } else { '' })

        if ($null -ne $ScopeFilter -and [string]$a.FilterId -ieq [string]$ScopeFilter.Id) {
            [void]$fhits.Add(("{0}uses {1} '{2}' on {3}" -f $ipfx, (Get-FilterPhrase $a.FilterType), $ScopeFilter.Name, $(if ($target) { $target } else { '(unknown target)' })))
            if (-not $isExcl) { $filterOnInclude = $true; $hits[$i] = [pscustomobject]@{ Hit = 'applies'; Note = 'Carries the scope filter' } }
        }
        if ($null -ne $ScopeGroup) {
            if ($a.GroupId) {
                $how = ''
                if ([string]$a.GroupId -ieq [string]$ScopeGroup.Id) { $how = ("group '{0}'" -f $ScopeGroup.Name) }
                elseif ($ScopeGroup.Parents.ContainsKey([string]$a.GroupId)) { $how = ("parent group '{0}'" -f $ScopeGroup.Parents[[string]$a.GroupId]) }
                if ($how) {
                    if ($isExcl) { [void]$exc.Add(("{0}EXCLUDED via {1}" -f $ipfx, $how)); $hits[$i] = [pscustomobject]@{ Hit = 'excluding'; Note = "Excludes the scope ($how)" } }
                    else { [void]$inc.Add(("{0}assigned to {1}{2}" -f $ipfx, $how, $fnote)); $hits[$i] = [pscustomobject]@{ Hit = 'applies'; Note = "Reaches the scope ($how)" } }
                }
            }
            elseif (-not $isExcl -and ($target -eq 'All devices' -or $target -eq 'All users')) {
                [void]$inc.Add(("{0}{1} (tenant-wide){2}" -f $ipfx, $target, $fnote))
                $hits[$i] = [pscustomobject]@{ Hit = 'applies'; Note = 'Tenant-wide assignment reaches the scope' }
            }
        }
    }
    $groupOk = ($null -eq $ScopeGroup) -or ($inc.Count -gt 0 -or $exc.Count -gt 0)
    $filterOk = ($null -eq $ScopeFilter) -or ($fhits.Count -gt 0)
    if (-not ($groupOk -and $filterOk)) { return $null }
    $inScope = $true
    if ($null -ne $ScopeGroup) { $inScope = ($inc.Count -gt 0) }
    elseif ($null -ne $ScopeFilter) { $inScope = $filterOnInclude }
    return [pscustomobject]@{ InScope = $inScope; Reason = ((@($inc) + @($exc) + @($fhits)) -join '; '); Hits = $hits }
}

function Get-TenantInventoryRsop {
    # -All: every policy (and assigned app) in the tenant with its settings and an assignment
    # summary. No device math and no conflict detection (policies target different devices).
    # -ScopeGroup / -ScopeFilter narrow the inventory to what reaches the group (directly, via
    # a parent group, or All devices / All users) and/or carries the filter, each with the
    # reason spelled out. Policies that only EXCLUDE the scope stay visible as Excluded.
    param($Corpus, $ScopeGroup, $ScopeFilter)

    # resolve every group name referenced anywhere, once
    $allGids = New-Object System.Collections.Generic.List[string]
    foreach ($p in @(@($Corpus.policies) + @($Corpus.apps))) {
        foreach ($a in @($p.Assignments)) { if ($a.GroupId) { [void]$allGids.Add([string]$a.GroupId) } }
    }
    Resolve-GroupNames -Ids $allGids.ToArray()

    $scoped = ($null -ne $ScopeGroup -or $null -ne $ScopeFilter)
    $policyResults = [System.Collections.Generic.List[object]]::new()
    $settingRows = [System.Collections.Generic.List[object]]::new()
    $shadowRows = [System.Collections.Generic.List[object]]::new()

    foreach ($p in @($Corpus.policies)) {
        $summary = ConvertTo-AssignmentSummary -Assignments $p.Assignments
        $assigned = ($summary -ne 'Not assigned')
        $status = $(if ($assigned) { 'Assigned' } else { 'NotAssigned' })
        if ($p.AssignmentsUnreadable) {
            $status = 'Unknown'
            $summary = $(if ($assigned) { "$summary | Assignments could not be fully read (see warnings)" } else { 'Assignments could not be read (see warnings)' })
        }
        $via = $summary
        $hits = $null
        if ($scoped) {
            $sc = Test-InventoryScope -Assignments $p.Assignments -ScopeGroup $ScopeGroup -ScopeFilter $ScopeFilter
            if ($null -eq $sc) {
                if (-not $p.AssignmentsUnreadable) { continue }   # confirmed out of scope
                $via = "Scope membership is unknown because assignments could not be fully read | $summary"
            }
            else {
                $status = $(if ($p.AssignmentsUnreadable) { 'Unknown' } elseif ($sc.InScope) { 'Assigned' } else { 'Excluded' })
                $via = ("Scope: {0}  |  {1}" -f $sc.Reason, $summary)
                $hits = $sc.Hits
            }
        }
        [void]$policyResults.Add((New-PolicyEntry -Policy $p -Status $status -Via $via -Hits $hits))

        if ($status -eq 'Excluded') {
            # scope-excluded: keep the settings inspectable via Investigate's rule-out list
            foreach ($s in @($p.Settings)) { [void]$shadowRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName $p.Name -Via $via -Status 'Excluded')) }
            continue
        }
        $tag = $(if ($status -eq 'NotAssigned') { ' [not assigned]' } elseif ($status -eq 'Unknown') { ' [applicability unknown]' } else { '' })
        foreach ($s in @($p.Settings)) { [void]$settingRows.Add((New-SettingRow -Setting $s -Policy $p -PolicyName ($p.Name + $tag) -Via $via)) }
    }

    $appResults = [System.Collections.Generic.List[object]]::new()
    $cfgIdx = Get-AppConfigIndex -Corpus $Corpus
    foreach ($a in @($Corpus.apps)) {
        if (@($a.Assignments).Count -eq 0) {
            # unassigned apps belong in the inventory (they still have to be rebuilt after a
            # disaster), but never in a group / filter scope
            if ($scoped -and -not $a.AssignmentsUnreadable) { continue }
            $unk = [bool]$a.AssignmentsUnreadable
            $res = [pscustomobject]@{ Status = $(if ($unk) { 'Unknown' } else { 'NotAssigned' }); EffectiveIntent = ''; IntentConflict = $false; Intents = @()
                Resolution = $(if ($unk) { 'Assignments could not be read (see warnings)' } else { 'Not assigned to any group' }) }
            $e = New-AppEntry -App $a -Result $res -Reported $null -ConfigPolicies $(if ($cfgIdx.ContainsKey($a.Id)) { $cfgIdx[$a.Id].ToArray() } else { @() })
            $e.EffectiveLabel = $(if ($unk) { 'Assignments not readable' } else { 'Not assigned' })
            [void]$appResults.Add($e)
            continue
        }
        $status = $(if ($a.AssignmentsUnreadable) { 'Unknown' } else { 'Assigned' })
        $reason = $(if ($a.AssignmentsUnreadable) { 'Assignments could not be fully read (see warnings)' } else { '' }); $hits = $null
        if ($scoped) {
            $sc = Test-InventoryScope -Assignments $a.Assignments -ScopeGroup $ScopeGroup -ScopeFilter $ScopeFilter
            if ($null -eq $sc) {
                if (-not $a.AssignmentsUnreadable) { continue }
                $reason = 'Scope membership is unknown because assignments could not be fully read (see warnings)'
            }
            else {
                $status = $(if ($a.AssignmentsUnreadable) { 'Unknown' } elseif ($sc.InScope) { 'Assigned' } else { 'Excluded' })
                $reason = ("Scope: {0}{1}" -f $sc.Reason, $(if ($a.AssignmentsUnreadable) { ' | Assignments could not be fully read (see warnings)' } else { '' }))
                $hits = $sc.Hits
            }
        }
        $hitList = @($hits)
        $asgList = @($a.Assignments)
        $hitFor = $(if ($hits) { { param($x) $ix = [array]::IndexOf($asgList, $x); if ($ix -ge 0) { $hitList[$ix] } else { [pscustomobject]@{ Hit = ''; Note = '' } } }.GetNewClosure() } else { $null })
        $res = [pscustomobject]@{
            Status = $status; EffectiveIntent = ''; IntentConflict = $false
            Intents = (Get-AppIntentSkeleton -App $a -HitFor $hitFor); Resolution = $reason
        }
        $e = New-AppEntry -App $a -Result $res -Reported $null -ConfigPolicies $(if ($cfgIdx.ContainsKey($a.Id)) { $cfgIdx[$a.Id].ToArray() } else { @() })
        # scoped: name only the intents whose targets reach the scope; unscoped: every intent
        $labelIntents = @($res.Intents)
        if ($scoped -and $hits) {
            $labelIntents = @($res.Intents | Where-Object { @($_.R.Hits | Where-Object { $_.Hit -eq 'applies' }).Count -gt 0 })
        }
        $e.EffectiveLabel = ((@($labelIntents | ForEach-Object { $script:IntentLabels[$_.Intent] })) -join ' / ')
        if ($status -eq 'Unknown') { $e.EffectiveLabel = 'Unknown' }
        if (-not $e.EffectiveLabel -and $status -eq 'Excluded') { $e.EffectiveLabel = 'Excluded' }
        [void]$appResults.Add($e)
    }

    # Counts come straight off the List/array .Count (pwsh 7.6 throws on @($genericList).Count).
    $totalPolicies = @($Corpus.policies).Count
    $assignedCount = @($policyResults | Where-Object { $_.Status -eq 'Assigned' }).Count
    $unassignedCount = @($policyResults | Where-Object { $_.Status -eq 'NotAssigned' }).Count
    $unknownCount = @($policyResults | Where-Object { $_.Status -eq 'Unknown' }).Count
    $name = 'TENANT-WIDE INVENTORY'
    $appsAssigned = @($appResults | Where-Object { $_.Status -eq 'Assigned' }).Count
    $appsUnassigned = @($appResults | Where-Object { $_.Status -eq 'NotAssigned' }).Count
    $appsUnknown = @($appResults | Where-Object { $_.Status -eq 'Unknown' }).Count
    $osLine = ("{0} policies ({1} assigned, {2} unassigned, {3} unknown) · {4} apps ({5} assigned, {6} unassigned, {7} unknown)" -f $totalPolicies, $assignedCount, $unassignedCount, $unknownCount, $appResults.Count, $appsAssigned, $appsUnassigned, $appsUnknown)
    if ($scoped) {
        $bits = @()
        if ($null -ne $ScopeGroup) { $bits += ("group '{0}'" -f $ScopeGroup.Name) }
        if ($null -ne $ScopeFilter) { $bits += ("filter '{0}'" -f $ScopeFilter.Name) }
        $inScopeCount = $policyResults.Count
        $excCount = @($policyResults | Where-Object { $_.Status -eq 'Excluded' }).Count
        $appsExcluded = @($appResults | Where-Object { $_.Status -eq 'Excluded' }).Count
        $name = 'TENANT INVENTORY (scoped)'
        $osLine = ("scope {0}: {1} of {2} policy candidates ({3} assigned, {4} exclude it, {5} unknown) · {6} app candidates ({7} assigned, {8} exclude it, {9} unknown)" -f `
            ($bits -join ' + '), $inScopeCount, $totalPolicies, $assignedCount, $excCount, $unknownCount, $appResults.Count, $appsAssigned, $appsExcluded, $appsUnknown)
    }
    return [pscustomobject]@{
        Device = [pscustomobject]@{
            Scope = 'tenant'
            DeviceName = $name; SerialNumber = ''; IntuneDeviceId = ''; EntraDeviceId = ''
            PrimaryUser = ''
            OS = $osLine
            Model = ''; LastSync = ''; DeviceGroups = @(); UserGroups = @()
        }
        Policies  = @($policyResults | Sort-Object Status, FamilyLabel, Name)
        Settings  = @($settingRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Conflicts = @()
        Shadow    = @($shadowRows | Sort-Object FamilyLabel, PolicyName, Setting)
        Apps      = @($appResults | Sort-Object Name)
    }
}

#endregion

#region ---------- output: console / csv / json / html ---------------------------------------

function Show-ConsoleSummary {
    # What a run found, on the console. Long lists (a tenant's policies, its conflicts) stay in
    # the report; -Brief (runs over many devices) prints each device's counts only.
    param($Result, [switch]$Brief)
    $listMax = 25
    $d = $Result.Device
    $isDevice = ($d.Scope -eq 'device' -or -not $d.Scope)
    Write-RsopConsole ""
    if ($isDevice) {
        Write-RsopConsole ("DEVICE  {0}" -f $d.DeviceName) -ForegroundColor White
        Write-RsopConsole ("        serial {0} | {1} | {2} | user {3}" -f $d.SerialNumber, $d.OS, $d.Model, $d.PrimaryUser) -ForegroundColor DarkGray
    }
    else {
        Write-RsopConsole ("{0}" -f $d.DeviceName) -ForegroundColor White
        Write-RsopConsole ("        {0}" -f $d.OS) -ForegroundColor DarkGray
    }
    $applied  = @($Result.Policies | Where-Object { $_.Status -in @('Applies', 'Assigned') })
    $excluded = @($Result.Policies | Where-Object { $_.Status -in @('Excluded', 'FilteredOut', 'NotAssigned') })
    $unknown  = @($Result.Policies | Where-Object { $_.Status -in @('Unknown', 'ReportedOnly') })
    Write-RsopConsole ("        {0} policies {1} | {2} settings | {3} conflicts | {4} excluded/filtered/unassigned | {5} unknown/reported-only" -f `
        $applied.Count, $(if ($isDevice) { 'apply' } else { 'assigned' }), @($Result.Settings).Count, @($Result.Conflicts).Count, $excluded.Count, $unknown.Count) -ForegroundColor White
    if ($Brief) { return }

    if ($applied.Count -gt $listMax -and -not $isDevice) {
        Write-RsopConsole ("   {0} policies - listed in the report (Reports > All policies)." -f $applied.Count) -ForegroundColor DarkGray
    }
    elseif ($applied.Count -gt 0) {
        $tbl = $applied | Select-Object @{n = 'Policy'; e = { $_.Name } },
            @{n = 'Type'; e = { $_.FamilyLabel } },
            @{n = 'Settings'; e = { $_.SettingCount } },
            @{n = 'Reported'; e = { $_.Reported } },
            @{n = 'Applies via'; e = { $_.Via } } |
            Format-Table -AutoSize -Wrap | Out-String -Width 300
        Write-RsopConsole $tbl
    }
    # unassigned policies are clean-up candidates, not problems: one line (the report lists them)
    $notAssigned = @($excluded | Where-Object { $_.Status -eq 'NotAssigned' })
    if ($notAssigned.Count) {
        Write-RsopConsole ("   {0} polic{1} not assigned to any group - the report's 'Not assigned' status filter lists them." -f $notAssigned.Count, $(if ($notAssigned.Count -eq 1) { 'y is' } else { 'ies are' })) -ForegroundColor DarkGray
    }
    foreach ($x in @($excluded | Where-Object { $_.Status -ne 'NotAssigned' })) {
        Write-RsopConsole ("   {0}: {1}  <- {2}" -f $(if ($x.Status -eq 'FilteredOut') { 'FILTERED OUT' } else { 'EXCLUDED' }), $x.Name, $x.Via) -ForegroundColor Yellow
    }
    foreach ($x in $unknown) {
        Write-RsopConsole ("   {0}: {1}  <- {2}" -f $x.Status.ToUpper(), $x.Name, $x.Via) -ForegroundColor Magenta
    }
    if (@($Result.Conflicts).Count -gt $listMax) {
        Write-RsopConsole ("   CONFLICTS: {0} - listed in the report (Reports > Conflicts)." -f @($Result.Conflicts).Count) -ForegroundColor Red
    }
    elseif (@($Result.Conflicts).Count -gt 0) {
        Write-RsopConsole ("   CONFLICTS ({0}):" -f @($Result.Conflicts).Count) -ForegroundColor Red
        foreach ($c in $Result.Conflicts) {
            Write-RsopConsole ("     - {0}" -f $c.Setting) -ForegroundColor Red
            foreach ($s in $c.Sources) { Write-RsopConsole ("         {0}  =>  {1}" -f $s.Policy, $s.Value) -ForegroundColor DarkYellow }
        }
    }
    $apps = @($Result.Apps)
    if ($apps.Count -gt 0) {
        $on = @($apps | Where-Object { $_.Status -eq 'Applies' })
        $cnt = { param($k) @($on | Where-Object { $_.EffectiveIntent -eq $k -or ($k -in @('required', 'available') -and $_.EffectiveIntent -eq 'requiredAndAvailable') }).Count }
        if ($d.Scope -eq 'device') {
            Write-RsopConsole ("   APPS: {0} targeted - {1} required, {2} available, {3} uninstall; {4} intent conflict(s); {5} excluded/filtered" -f `
                $on.Count, (& $cnt 'required'), (& $cnt 'available'), (& $cnt 'uninstall'), @($apps | Where-Object { $_.IntentConflict }).Count,
                @($apps | Where-Object { $_.Status -in @('Excluded', 'FilteredOut') }).Count) -ForegroundColor White
            foreach ($a in @($on | Where-Object { $_.EffectiveIntent -eq 'uninstall' })) {
                Write-RsopConsole ("   UNINSTALL: {0}  <- {1}" -f $a.Name, $a.Resolution) -ForegroundColor Yellow
            }
            foreach ($a in @($apps | Where-Object { $_.IntentConflict })) {
                Write-RsopConsole ("   APP INTENT CONFLICT: {0} -> {1}  ({2})" -f $a.Name, $a.EffectiveLabel, $a.Resolution) -ForegroundColor Magenta
            }
            foreach ($a in @($apps | Where-Object { $_.Reported -and $_.Reported.Mismatch })) {
                if ($a.Status -eq 'ReportedOnly') {
                    Write-RsopConsole ("   ASSIGNMENT NOT FOUND IN SNAPSHOT: {0} - Intune reports {1} ({2})" -f $a.Name, $a.Reported.Intent, $a.Reported.InstallState) -ForegroundColor Magenta
                }
                else {
                    Write-RsopConsole ("   DEVICE REPORTS DIFFERENT INTENT: {0} - predicted {1}, Intune reports {2} ({3})" -f $a.Name, $a.EffectiveLabel, $a.Reported.Intent, $a.Reported.InstallState) -ForegroundColor Magenta
                }
            }
        }
        else {
            Write-RsopConsole ("   APPS: {0} in this view" -f $apps.Count) -ForegroundColor White
        }
    }
    if ($Result.PSObject.Properties['Tenant'] -and $Result.Tenant) {
        $t = $Result.Tenant
        $n = (@($t.Sections | ForEach-Object { @($_.Items).Count }) | Measure-Object -Sum).Sum
        Write-RsopConsole ("   TENANT SETUP: {0} items, {1} groups, {2} assignment filters" -f $n, @($t.Groups).Count, @($t.Filters).Count) -ForegroundColor White
        foreach ($f in @($t.Findings | Where-Object { $_.Severity -in @('bad', 'warn') } | Sort-Object { if ($_.Severity -eq 'bad') { 0 } else { 1 } })) {
            Write-RsopConsole ("   {0}: {1}" -f $(if ($f.Severity -eq 'bad') { 'ACT NOW' } else { 'CHECK' }), $f.Title) -ForegroundColor $(if ($f.Severity -eq 'bad') { 'Red' } else { 'Yellow' })
        }
    }
}

function Protect-RsopCsvRow {
    # Only a complete negative number is exempt from formula-prefix neutralisation.
    param([Parameter(ValueFromPipeline = $true)]$Row)
    process {
        foreach ($pp in $Row.PSObject.Properties) {
            $v = $pp.Value
            if ($v -is [string] -and $v -match '^[=+@\-\t\r\n]' -and $v -notmatch '^-(?:\d+(?:\.\d+)?|\.\d+)$') { $pp.Value = "'" + $v }
        }
        $Row
    }
}

function Get-CsvRows {
    param($Results)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @($Results)) {
        $reportedByPolicy = @{}
        $intentByPolicy = @{}
        $platformByPolicy = @{}
        $statusByPolicy = @{}
        foreach ($p in @($r.Policies)) {
            $reportedByPolicy[[string]$p.PolicyId] = [string]$p.Reported
            $intentByPolicy[[string]$p.PolicyId] = [string]$p.Intent
            $platformByPolicy[[string]$p.PolicyId] = [string]$p.Platform
            $statusByPolicy[[string]$p.PolicyId] = [string]$p.Status
        }
        foreach ($s in @($r.Settings)) {
            $rep = ''
            if ($reportedByPolicy.ContainsKey([string]$s.PolicyId)) { $rep = $reportedByPolicy[[string]$s.PolicyId] }
            $int = ''
            if ($intentByPolicy.ContainsKey([string]$s.PolicyId)) { $int = $intentByPolicy[[string]$s.PolicyId] }
            $plat = ''
            if ($platformByPolicy.ContainsKey([string]$s.PolicyId)) { $plat = $platformByPolicy[[string]$s.PolicyId] }
            $stat = ''
            if ($statusByPolicy.ContainsKey([string]$s.PolicyId)) { $stat = $statusByPolicy[[string]$s.PolicyId] }
            elseif ($s.PSObject.Properties['Status'] -and $s.Status) { $stat = [string]$s.Status }
            [void]$rows.Add([pscustomobject]@{
                DeviceName       = $r.Device.DeviceName
                SerialNumber     = $r.Device.SerialNumber
                PolicyType       = $s.FamilyLabel
                Platform         = $plat
                PolicyName       = $s.PolicyName
                Category         = [string]$s.Category
                Setting          = $s.Setting
                Value            = $s.Value
                Conflict         = $s.Conflict
                PolicyStatus     = $stat
                AssignmentIntent = $int
                AppliesVia       = [string]$s.Via
                PolicyReported   = $rep
                PolicyId         = $s.PolicyId
                SettingKey       = $s.Key
            })
        }
        # one row per app: the resolved intent, plus each intent's targets
        foreach ($a in @($r.Apps)) {
            $targets = @($a.Intents | ForEach-Object {
                    $t = @($_.Targets | ForEach-Object { "{0} {1}{2}" -f $_.Mode, $_.Target, $(if ($_.Filter) { " ({0}: {1})" -f (Get-FilterPhrase $_.FilterMode), $_.Filter } else { '' }) })
                    "{0}: {1}" -f $_.Label, ($t -join '; ')
                })
            [void]$rows.Add([pscustomobject]@{
                DeviceName       = $r.Device.DeviceName
                SerialNumber     = $r.Device.SerialNumber
                PolicyType       = ("App - {0}" -f $a.Type)
                Platform         = [string]$a.Platform
                PolicyName       = $a.Name
                Category         = 'App assignment'
                Setting          = 'Resolved assignment intent'
                Value            = $a.EffectiveLabel
                Conflict         = $(if ($a.IntentConflict) { 'INTENT CONFLICT' } else { '' })
                PolicyStatus     = [string]$a.Status
                AssignmentIntent = $a.EffectiveLabel
                AppliesVia       = ((@($a.Resolution) + $targets) -join ' | ')
                PolicyReported   = $(if ($a.Reported) { "{0} / {1}" -f $a.Reported.Intent, $a.Reported.InstallState } else { '' })
                PolicyId         = $a.AppId
                SettingKey       = ("app:{0}" -f $a.AppId)
            })
        }
        # tenant setup (whole-tenant inventory): one row per item property, plus groups / filters
        if ($r.PSObject.Properties['Tenant'] -and $r.Tenant) {
            $add = {
                param($type, $name, $cat, $setting, $value, $via, $state, $id, $platform, $status)
                [void]$rows.Add([pscustomobject]@{
                    DeviceName       = $r.Device.DeviceName
                    SerialNumber     = ''
                    PolicyType       = $type
                    Platform         = $(if ($null -ne $platform) { [string]$platform } else { '' })
                    PolicyName       = $name
                    Category         = $cat
                    Setting          = $setting
                    Value            = $value
                    Conflict         = ''
                    PolicyStatus     = $(if ($null -ne $status) { [string]$status } else { '' })
                    AssignmentIntent = ''
                    AppliesVia       = $via
                    PolicyReported   = $state
                    PolicyId         = $id
                    SettingKey       = ''
                })
            }
            foreach ($sec in @($r.Tenant.Sections)) {
                foreach ($it in @($sec.Items)) {
                    $type = "Tenant setup - {0}" -f $sec.Area
                    $plat = [string]$it.Platform
                    $stat = [string]$it.Status
                    $its = @($it.Rows | Where-Object { $null -ne $_ })
                    if (-not $its.Count) { & $add $type $it.Name $it.Kind '' '' $it.Assignment $it.State $it.Id $plat $stat }
                    foreach ($row in $its) { & $add $type $it.Name $(if ($row.Category) { $row.Category } else { $it.Kind }) $row.Setting $row.Value $it.Assignment $it.State $it.Id $plat $stat }
                }
            }
            foreach ($g in @($r.Tenant.Groups)) {
                & $add 'Tenant setup - Groups used by Intune' $g.Name $g.Membership 'Membership rule' $g.Rule ((@($g.UsedBy | ForEach-Object { "{0} ({1}, {2})" -f $_.Name, $_.Kind, $_.Mode })) -join '; ') $(if ($g.Missing) { 'Deleted' } else { $g.RuleState }) $g.Id '' ''
            }
            foreach ($f in @($r.Tenant.Filters)) {
                & $add 'Tenant setup - Assignment filters' $f.Name $f.Platform 'Rule' $f.Rule ((@($f.UsedBy | ForEach-Object { $_.Name })) -join '; ') $f.ManagementType $f.Id $f.Platform ''
            }
            foreach ($f in @($r.Tenant.Findings)) {
                & $add 'Tenant setup - Recovery checklist' $f.Title $f.Area $f.Severity $f.Detail '' '' '' '' ''
            }
        }
    }
    return $rows.ToArray()
}

$script:HtmlTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#f6f7f9;--card:#ffffff;--ink:#1a1f2b;--muted:#68707f;--line:#e3e6ea;--accent:#2458d6;
--chip:#eef1f5;--red:#c62f2f;--redbg:#fdecec;--amber:#9a6700;--amberbg:#fff3d6;--green:#1a7f37;--greenbg:#e9f7ee;}
@media (prefers-color-scheme: dark){:root{--bg:#12141a;--card:#1b1e27;--ink:#e8eaf0;--muted:#9aa2b1;--line:#2a2f3b;
--accent:#7aa2ff;--chip:#252a36;--red:#ff7b7b;--redbg:#3a2020;--amber:#e3b341;--amberbg:#3a3120;--green:#57d38c;--greenbg:#1d3327;}}
*{box-sizing:border-box}
body{margin:0;font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--ink);padding:24px}
h1{font-size:20px;margin:0 0 4px}
.sub{color:var(--muted);margin-bottom:18px;font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}
select,input[type=text]{background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:8px 10px;font-size:14px;min-width:200px}
input[type=text]{flex:1;min-width:240px}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0 0}
.stat{background:var(--chip);border-radius:8px;padding:8px 14px;font-size:13px}
.stat b{font-size:16px;display:block}
.tabs{display:flex;gap:4px;margin:16px 0 0;border-bottom:1px solid var(--line)}
.tab{padding:8px 16px;cursor:pointer;border:none;background:none;color:var(--muted);font-size:14px;border-bottom:2px solid transparent}
.tab.active{color:var(--accent);border-bottom-color:var(--accent);font-weight:600}
.tblwrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:13px}
th{position:sticky;top:0;background:var(--card);text-align:left;padding:8px 10px;border-bottom:2px solid var(--line);color:var(--muted);font-weight:600;white-space:nowrap}
td{padding:6px 10px;border-bottom:1px solid var(--line);vertical-align:top;word-break:break-word}
tr:hover td{background:var(--chip)}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;white-space:nowrap}
.b-conflict{background:var(--redbg);color:var(--red)}
.b-dup{background:var(--chip);color:var(--muted)}
.b-applies{background:var(--greenbg);color:var(--green)}
.b-excluded{background:var(--redbg);color:var(--red)}
.b-other{background:var(--amberbg);color:var(--amber)}
.small{color:var(--muted);font-size:12px}
.btn{background:var(--accent);color:#fff;border:none;border-radius:8px;padding:8px 14px;font-size:13px;cursor:pointer}
label.chk{display:flex;align-items:center;gap:6px;color:var(--muted);font-size:13px;white-space:nowrap}
.conf-card{border:1px solid var(--line);border-left:4px solid var(--red);border-radius:8px;padding:10px 14px;margin-bottom:10px}
.conf-card h3{margin:0 0 6px;font-size:14px}
.conf-src{display:flex;justify-content:space-between;gap:16px;padding:3px 0;font-size:13px;border-top:1px dashed var(--line)}
.groups{font-size:12px;color:var(--muted);margin-top:6px}
mark{background:var(--amberbg);color:inherit;border-radius:3px}
</style>
</head>
<body>
<h1>🔍 Intune Lens</h1>
<div class="sub">Query: __QUERY__ &middot; Generated by __ACCOUNT__ on __GENERATED__ &middot; v__VERSION__</div>

<div class="card">
  <div class="row">
    <select id="devSel"></select>
    <input type="text" id="q" placeholder="Search settings, values, policies...">
    <select id="famSel"><option value="">All policy types</option></select>
    <label class="chk"><input type="checkbox" id="confOnly"> conflicts only</label>
    <button class="btn" id="csvBtn">Download CSV</button>
  </div>
  <div class="stats" id="stats"></div>
  <div class="groups" id="groups"></div>
  <div class="tabs">
    <button class="tab active" data-tab="settings">Settings</button>
    <button class="tab" data-tab="policies">Policies</button>
    <button class="tab" data-tab="apps">Apps</button>
    <button class="tab" data-tab="conflicts">Conflicts</button>
  </div>
</div>

<div class="card" id="pane-settings">
  <div class="tblwrap"><table id="tblSettings">
    <thead><tr><th>Setting</th><th>Value</th><th>Policy</th><th>Type</th><th></th></tr></thead>
    <tbody></tbody>
  </table></div>
  <div class="small" id="rowCount"></div>
</div>

<div class="card" id="pane-policies" style="display:none">
  <div class="tblwrap"><table id="tblPolicies">
    <thead><tr><th>Status</th><th>Policy</th><th>Type</th><th>#Settings</th><th>Device reported</th><th>Applies via</th></tr></thead>
    <tbody></tbody>
  </table></div>
</div>

<div class="card" id="pane-apps" style="display:none">
  <div class="tblwrap"><table id="tblApps">
    <thead><tr><th>App</th><th>Type</th><th>Resolved intent</th><th>Assignments by intent</th><th>Why</th></tr></thead>
    <tbody></tbody>
  </table></div>
</div>

<div class="card" id="pane-conflicts" style="display:none"><div id="confList"></div></div>

<script>
const DATA = __DATA__;
let cur = 0;

const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

function init(){
  const sel = document.getElementById("devSel");
  DATA.devices.forEach((d,i)=>{
    const o=document.createElement("option");
    o.value=i; o.textContent=d.Device.DeviceName + (d.Device.SerialNumber? " ("+d.Device.SerialNumber+")":"");
    sel.appendChild(o);
  });
  sel.onchange = ()=>{cur=parseInt(sel.value); buildFamilies(); render();};
  document.getElementById("q").oninput = render;
  document.getElementById("famSel").onchange = render;
  document.getElementById("confOnly").onchange = render;
  document.getElementById("csvBtn").onclick = downloadCsv;
  document.querySelectorAll(".tab").forEach(t=>{
    t.onclick=()=>{
      document.querySelectorAll(".tab").forEach(x=>x.classList.remove("active"));
      t.classList.add("active");
      ["settings","policies","apps","conflicts"].forEach(p=>{
        document.getElementById("pane-"+p).style.display = (t.dataset.tab===p) ? "" : "none";
      });
    };
  });
  buildFamilies(); render();
}

function buildFamilies(){
  const d = DATA.devices[cur];
  const fams = [...new Set(d.Settings.map(s=>s.FamilyLabel))].sort();
  const sel = document.getElementById("famSel");
  sel.innerHTML = '<option value="">All policy types</option>';
  fams.forEach(f=>{const o=document.createElement("option");o.value=f;o.textContent=f;sel.appendChild(o);});
}

function render(){
  const d = DATA.devices[cur];
  const q = document.getElementById("q").value.toLowerCase();
  const fam = document.getElementById("famSel").value;
  const confOnly = document.getElementById("confOnly").checked;

  const applied = d.Policies.filter(p=>p.Status==="Applies").length;
  const excl = d.Policies.filter(p=>p.Status==="Excluded"||p.Status==="FilteredOut").length;
  document.getElementById("stats").innerHTML =
    '<div class="stat"><b>'+applied+'</b>policies apply</div>'+
    '<div class="stat"><b>'+d.Settings.length+'</b>settings</div>'+
    '<div class="stat"><b>'+d.Conflicts.length+'</b>conflicts</div>'+
    '<div class="stat"><b>'+excl+'</b>excluded / filtered out</div>';

  const g = d.Device;
  document.getElementById("groups").innerHTML =
    (g.OS? esc(g.OS)+" &middot; " : "") + (g.PrimaryUser? "user "+esc(g.PrimaryUser)+" &middot; ":"") +
    (g.DeviceGroups && g.DeviceGroups.length ? "device groups: "+esc(g.DeviceGroups.join(", ")) : "") +
    (g.UserGroups && g.UserGroups.length ? " &middot; user groups: "+esc(g.UserGroups.join(", ")) : "");

  // settings table
  const tb = document.querySelector("#tblSettings tbody");
  const frag = document.createDocumentFragment();
  let shown = 0;
  d.Settings.forEach(s=>{
    if (fam && s.FamilyLabel!==fam) return;
    if (confOnly && s.Conflict!=="CONFLICT") return;
    if (q){
      const hay = (s.Setting+" "+s.Value+" "+s.PolicyName+" "+s.FamilyLabel).toLowerCase();
      if (!hay.includes(q)) return;
    }
    shown++;
    const tr = document.createElement("tr");
    let badge = "";
    if (s.Conflict==="CONFLICT") badge = '<span class="badge b-conflict">CONFLICT</span>';
    else if (s.Conflict==="Duplicate") badge = '<span class="badge b-dup">dup</span>';
    tr.innerHTML = "<td>"+esc(s.Setting)+"</td><td>"+esc(s.Value)+"</td><td>"+esc(s.PolicyName)+
      "</td><td class='small'>"+esc(s.FamilyLabel)+"</td><td>"+badge+"</td>";
    frag.appendChild(tr);
  });
  tb.innerHTML=""; tb.appendChild(frag);
  document.getElementById("rowCount").textContent = shown+" of "+d.Settings.length+" settings shown";

  // policies table (same search + type filter as the settings table)
  const pb = document.querySelector("#tblPolicies tbody");
  const pf = document.createDocumentFragment();
  d.Policies.forEach(p=>{
    if (fam && p.FamilyLabel!==fam) return;
    if (q){
      const hay = (p.Name+" "+p.FamilyLabel+" "+(p.Intent||"")+" "+p.Via).toLowerCase();
      if (!hay.includes(q)) return;
    }
    const tr=document.createElement("tr");
    let cls="b-other";
    if(p.Status==="Applies"||p.Status==="Assigned")cls="b-applies"; else if(p.Status==="Excluded"||p.Status==="FilteredOut")cls="b-excluded";
    tr.innerHTML="<td><span class='badge "+cls+"'>"+esc(p.Status)+"</span></td><td>"+esc(p.Name)+(p.Intent?" <span class='small'>("+esc(p.Intent)+")</span>":"")+"</td><td class='small'>"+
      esc(p.FamilyLabel)+"</td><td>"+esc(p.SettingCount)+"</td><td class='small'>"+esc(p.Reported||"")+"</td><td class='small'>"+esc(p.Via)+"</td>";
    pf.appendChild(tr);
  });
  pb.innerHTML=""; pb.appendChild(pf);

  // apps (one row per app, resolved intent)
  const ab = document.querySelector("#tblApps tbody");
  ab.innerHTML = (d.Apps||[]).filter(a=>!q||(a.Name+" "+a.Type+" "+a.EffectiveLabel+" "+(a.Resolution||"")).toLowerCase().includes(q)).map(a=>
    "<tr><td>"+esc(a.Name)+"</td><td class='small'>"+esc(a.Type)+"</td><td><b>"+esc(a.EffectiveLabel)+"</b>"+(a.IntentConflict?" <span class='badge b-conflict'>intent conflict</span>":"")+
    "</td><td class='small'>"+(a.Intents||[]).map(i=>esc(i.Label)+": "+esc((i.Targets||[]).map(t=>t.Mode+" "+t.Target).join(", "))).join("<br>")+"</td><td class='small'>"+esc(a.Resolution||"")+"</td></tr>").join("");

  // conflicts
  const cl = document.getElementById("confList");
  if(!d.Conflicts.length){ cl.innerHTML = '<div class="small">No conflicting values among applicable policies. Note: conflicts are matched per setting key; the same OS setting delivered via different policy families (e.g. ADMX vs Settings Catalog) cannot always be correlated.</div>'; }
  else {
    cl.innerHTML = d.Conflicts.map(c=>
      '<div class="conf-card"><h3>'+esc(c.Setting)+'</h3>'+
      c.Sources.map(s=>'<div class="conf-src"><span>'+esc(s.Policy)+'</span><b>'+esc(s.Value)+'</b></div>').join("")+
      '</div>').join("");
  }
}

function downloadCsv(){
  const d = DATA.devices[cur];
  const q = v => { let s=String(v==null?"":v); if (/^[=+@\-\t\r\n]/.test(s) && !/^-(?:\d+(?:\.\d+)?|\.\d+)$/.test(s)) s="'"+s; return '"'+s.replace(/"/g,'""')+'"'; };
  let csv = "DeviceName,SerialNumber,PolicyType,Platform,PolicyName,Category,Setting,Value,Conflict,PolicyStatus,DeviceReported,AppliesVia\r\n";
  d.Settings.forEach(s=>{
    const p = (d.Policies||[]).find(x=>x.PolicyId===s.PolicyId);
    csv += [q(d.Device.DeviceName),q(d.Device.SerialNumber),q(s.FamilyLabel),q(p&&p.Platform),q(s.PolicyName),q(s.Category),q(s.Setting),q(s.Value),q(s.Conflict),q(p&&p.Status),q(p&&p.Reported),q(s.Via)].join(",")+"\r\n";
  });
  const a=document.createElement("a");
  a.href=URL.createObjectURL(new Blob([csv],{type:"text/csv"}));
  a.download=DATA.exportNames.devices[cur]+"-settings.csv";
  a.click();
}

init();
</script>
</body>
</html>
'@

function Export-HtmlReport {
    param($Results, [string]$Path, [string]$QueryLabel, [string]$Tenant, [string]$Account, [datetime]$CaptureTime = (Get-Date))

    # Accept only a template with the expected schema marker and required placeholders.
    # An incompatible adjacent file must not silently generate a broken rich report.
    $templatePath = $script:HtmlTemplatePath
    if (-not $templatePath) { $templatePath = Join-Path $PSScriptRoot 'report-template.html' }
    $html = $script:HtmlTemplate
    if (Test-Path -LiteralPath $templatePath) {
        $candidate = Get-Content -Raw -LiteralPath $templatePath
        $schemaMarker = '<meta name="intune-lens-template-schema" content="{0}">' -f $script:TemplateSchema
        if ($candidate.Contains($schemaMarker) -and $candidate.Contains('__DATA__') -and $candidate.Contains('__TITLE__')) {
            $html = $candidate
        }
        else {
            Add-RunLog -Level warn -Message ("report-template.html is incompatible with template schema {0}; using the basic built-in layout." -f $script:TemplateSchema)
        }
    }
    else {
        Add-RunLog -Level warn -Message 'report-template.html not found next to the script; using the basic built-in layout.'
    }

    $payload = [pscustomobject]@{
        query        = $QueryLabel
        generated    = $captureTime.ToString('yyyy-MM-dd HH:mm')
        utcOffset    = $captureTime.ToString('zzz')
        exportNames  = @{
            report = Get-RsopExportBaseName -Label $QueryLabel -Results $Results -Tenant $Tenant -Timestamp $captureTime
            devices = @($Results | ForEach-Object { Get-RsopExportBaseName -Label $QueryLabel -Results @($_) -Tenant $Tenant -Timestamp $captureTime })
        }
        tenant       = $Tenant
        tenantName   = [string]$script:TenantName
        tenantDomain = [string]$script:TenantDomain
        account      = $Account
        version   = $script:Version
        warnings  = $script:RunLog.ToArray()
        devices   = @($Results)
    }
    # Tenant text lands inside a <script> block: EscapeHtml writes < > & ' as JSON \u escapes,
    # so no name or description ('</script>', '<!--<script>') can end or derail the block.
    $json = $payload | ConvertTo-Json -Depth 100 -Compress -EscapeHandling EscapeHtml

    # Reserve data with a nonce before inserting any operator or tenant text. Each metadata
    # token is replaced in one pass, so inserted labels cannot be interpreted as placeholders.
    $dataToken = '__INTUNE_DATA_' + [guid]::NewGuid().ToString('N') + '__'
    $html = $html.Replace('__DATA__', $dataToken)
    $titleText = "Intune Lens - $QueryLabel"
    if ($script:TenantName) { $titleText += " - $($script:TenantName)" }   # tells reports of several tenants apart
    $safeTitle = [System.Net.WebUtility]::HtmlEncode($titleText)
    $tokens = @{
        '__TITLE__' = $safeTitle
        '__QUERY__' = [System.Net.WebUtility]::HtmlEncode($QueryLabel)
        '__GENERATED__' = (Get-Date).ToString('yyyy-MM-dd HH:mm')
        '__ACCOUNT__' = [System.Net.WebUtility]::HtmlEncode($(if ($Account) { $Account } else { 'unknown account' }))
        '__VERSION__' = $script:Version
    }
    $html = [regex]::Replace($html, '__TITLE__|__QUERY__|__GENERATED__|__ACCOUNT__|__VERSION__', { param($m) $tokens[$m.Value] })
    $html = $html.Replace($dataToken, $json)
    Set-Content -LiteralPath $Path -Value $html -Encoding UTF8
    Set-RsopPrivateFile $Path
    Write-Good ("HTML report: {0}" -f (Resolve-Path -LiteralPath $Path))
}

#endregion

#region ---------- main -----------------------------------------------------------------------

function Resolve-GroupIdentity {
    # Group picker object / object id / display name -> @{ id; displayName } (or $null).
    param($Value)
    if ($Value -is [System.Collections.IDictionary] -or ($Value.PSObject -and (Get-Prop $Value 'id'))) {
        return [pscustomobject]@{ id = [string](Get-Prop $Value 'id'); displayName = [string](Get-Prop $Value 'displayName') }
    }
    $guid = [guid]::Empty
    if ([guid]::TryParse([string]$Value, [ref]$guid)) {
        $g = Invoke-Rsop -Uri ("v1.0/groups/{0}?`$select=id,displayName" -f $Value)
        return [pscustomobject]@{ id = [string](Get-Prop $g 'id'); displayName = [string](Get-Prop $g 'displayName') }
    }
    $esc = [string]$Value -replace "'", "''"
    $filter = "displayName eq '{0}'" -f $esc
    $vals = @(Get-RsopPaged -Uri ("v1.0/groups?`$filter={0}&`$select=id,displayName" -f [uri]::EscapeDataString($filter)))
    if ($vals.Count -gt 1) {
        $candidates = @($vals | ForEach-Object { "{0} ({1})" -f $_['displayName'], $_['id'] }) -join '; '
        throw "Multiple groups are named '$Value'. Re-run with the required object id. Matches: $candidates"
    }
    if ($vals.Count -eq 0) { return $null }
    return [pscustomobject]@{ id = [string]$vals[0]['id']; displayName = [string]$vals[0]['displayName'] }
}

function Resolve-AssignmentFilterIdentity {
    # An explicit id wins over a display name; duplicated names cannot pick a safe target.
    param($Corpus, [string]$Value, [string]$Label = 'Assignment filter')
    foreach ($f in @($Corpus.filters)) { if ($f.Id -ieq $Value) { return $f } }
    $matches = @($Corpus.filters | Where-Object { $_.Name -ieq $Value })
    if ($matches.Count -gt 1) {
        $candidates = @($matches | ForEach-Object { "{0} ({1}, {2})" -f $_.Name, $_.Id, $_.Platform }) -join '; '
        throw "Multiple assignment filters are named '$Value'. Re-run with the required filter id. Matches: $candidates"
    }
    if ($matches.Count -eq 1) { return $matches[0] }
    $names = @($Corpus.filters | ForEach-Object { $_.Name }) -join "', '"
    throw "$Label '$Value' not found. Available: '$names'"
}

function Resolve-DeviceRsopInRun {
    # One device of a multi-device run: a failure is logged and the run moves on to the next.
    param($ManagedDevice, $Corpus, $Results)
    try { [void]$Results.Add((Resolve-DeviceRsop -ManagedDevice $ManagedDevice -Corpus $Corpus)) }
    catch { Add-RunLog -Level error -Message ("Device '{0}' could not be evaluated and is left out: {1}" -f (Get-Prop $ManagedDevice 'deviceName'), (Format-RsopError $_)) }
}

function Resolve-QueryResults {
    # Shared by CLI flags and the interactive menu. Returns @{ Label; Results }.
    param([string]$Mode, $Corpus, $Value, [bool]$AssignedOnly = $false)

    $results = [System.Collections.Generic.List[object]]::new()
    $label = ''
    Reset-RsopQueryCaches   # live state is re-read once per query, then shared by its devices

    switch ($Mode) {
        'serial' {
            $label = "Serial: " + (@($Value) -join ', ')
            foreach ($sn in @($Value)) {
                $hits = Find-ManagedDevices -By serialNumber -Value $sn.Trim()
                if (@($hits).Count -eq 0) { Write-Warn2 ("No managed device found with serial '{0}'" -f $sn); continue }
                $md = Select-BestEnrollment -Candidates $hits -Label $sn
                if (@($Value).Count -gt 1) { Resolve-DeviceRsopInRun -ManagedDevice $md -Corpus $Corpus -Results $results }
                else { [void]$results.Add((Resolve-DeviceRsop -ManagedDevice $md -Corpus $Corpus)) }
            }
        }
        'name' {
            $label = "Device: " + (@($Value) -join ', ')
            foreach ($dn in @($Value)) {
                $hits = Find-ManagedDevices -By deviceName -Value $dn.Trim()
                if (@($hits).Count -eq 0) { Write-Warn2 ("No managed device found named '{0}'" -f $dn); continue }
                $md = Select-BestEnrollment -Candidates $hits -Label $dn
                if (@($Value).Count -gt 1) { Resolve-DeviceRsopInRun -ManagedDevice $md -Corpus $Corpus -Results $results }
                else { [void]$results.Add((Resolve-DeviceRsop -ManagedDevice $md -Corpus $Corpus)) }
            }
        }
        'group' {
            $gobj = Resolve-GroupIdentity -Value $Value
            if ($null -eq $gobj) { throw "Group '$Value' not found." }
            $label = "Group: " + $gobj.displayName

            if ($AssignedOnly) {
                Write-Step ("Listing policies directly assigned to group '{0}'" -f $gobj.displayName)
                Resolve-GroupNames -Ids @($gobj.id)
                [void]$results.Add((Get-GroupAssignedRsop -GroupObj $gobj -Corpus $Corpus))
            }
            else {
                Write-Step ("Resolving device members of '{0}' (transitive)" -f $gobj.displayName)
                $members = Get-RsopPaged -Uri ("v1.0/groups/{0}/transitiveMembers/microsoft.graph.device?`$select=id,deviceId,displayName&`$top=999" -f $gobj.id)
                Write-Info ("{0} device objects in group (user members are not expanded to their devices)" -f @($members).Count)
                $targets = [System.Collections.Generic.List[object]]::new()
                $byAzId = $null
                $memberIds = @(@($members) | ForEach-Object { [string](Get-Prop $_ 'deviceId') } | Where-Object { $_ })
                if ($null -eq $script:DeviceIndex -and $memberIds.Count -le 5000) {
                    # a small group: look its members up (batched) instead of indexing every
                    # managed device in the tenant; any refused lookup falls back to the index
                    $lookupUrl = { param($id) '/deviceManagement/managedDevices?$filter=' + [uri]::EscapeDataString("azureADDeviceId eq '$id'") + '&$select=' + $script:ManagedDeviceSelect }
                    $got = Invoke-RsopBatch -Urls @($memberIds | ForEach-Object { & $lookupUrl $_ }) -Activity 'Managed devices in the group'
                    $byAzId = @{}
                    foreach ($id in $memberIds) {
                        $b = $got[(& $lookupUrl $id)]
                        if ($b -isnot [System.Collections.IDictionary]) { $byAzId = $null; break }
                        $hits = @(@($b['value']) | Where-Object { $_ })
                        if ($hits.Count) { $byAzId[$id] = Select-BestEnrollment -Candidates $hits -Label $id }
                    }
                }
                if ($null -eq $byAzId) {
                    # a re-enrolled device has several records: keep the most recently synced one
                    $synced = { $d0 = ConvertTo-GraphDateTime (Get-Prop $args[0] 'lastSyncDateTime'); if ($d0 -eq [datetime]::MaxValue) { [datetime]::MinValue } else { $d0 } }
                    $byAzId = @{}
                    foreach ($d in (Get-DeviceIndex)) {
                        $k = [string](Get-Prop $d 'azureADDeviceId')
                        if (-not $byAzId.ContainsKey($k) -or (& $synced $d) -gt (& $synced $byAzId[$k])) { $byAzId[$k] = $d }
                    }
                }
                foreach ($m in @($members)) {
                    $devId = [string](Get-Prop $m 'deviceId')
                    if ($devId -and $byAzId.ContainsKey($devId)) { [void]$targets.Add($byAzId[$devId]) }
                }
                Write-Info ("{0} of them are Intune-managed" -f $targets.Count)
                if ($MaxDevices -gt 0 -and $targets.Count -gt $MaxDevices) {
                    Write-Warn2 ("Group has {0} managed devices; evaluating the first {1} (use -MaxDevices 0 for all)." -f $targets.Count, $MaxDevices)
                }
                $take = if ($MaxDevices -gt 0) { [math]::Min($MaxDevices, $targets.Count) } else { $targets.Count }
                for ($i = 0; $i -lt $take; $i++) {
                    Write-RsopProgress -Id 4 -Activity ("Devices in '{0}'" -f $gobj.displayName) -Status ("{0}/{1}" -f ($i + 1), $take) -Percent ([int](100 * $i / [math]::Max(1, $take))) -Force
                    Resolve-DeviceRsopInRun -ManagedDevice $targets[$i] -Corpus $Corpus -Results $results
                }
                Complete-RsopProgress -Id 4
            }
        }
        'filter' {
            $flt = Resolve-AssignmentFilterIdentity -Corpus $Corpus -Value ([string]$Value)
            $label = "Filter: " + $flt.Name
            Write-Step ("Evaluating assignment filter '{0}' server-side" -f $flt.Name)
            $targets = @(Get-FilterMatchedDevices -FilterObj $flt -Cap $MaxDevices)
            Write-Info ("{0} devices match the filter" -f $targets.Count)
            if ($MaxDevices -gt 0 -and $targets.Count -gt $MaxDevices) {
                Write-Warn2 ("Evaluating the first {0} (use -MaxDevices 0 for all)." -f $MaxDevices)
            }
            $take = if ($MaxDevices -gt 0) { [math]::Min($MaxDevices, $targets.Count) } else { $targets.Count }
            for ($i = 0; $i -lt $take; $i++) {
                Write-RsopProgress -Id 4 -Activity ("Devices matching '{0}'" -f $flt.Name) -Status ("{0}/{1}" -f ($i + 1), $take) -Percent ([int](100 * $i / [math]::Max(1, $take))) -Force
                Resolve-DeviceRsopInRun -ManagedDevice $targets[$i] -Corpus $Corpus -Results $results
            }
            Complete-RsopProgress -Id 4
        }
        'all' {
            $label = 'Tenant-wide inventory'
            $sgObj = $null; $sfObj = $null
            $gRef = $null; $fRef = $null
            if ($null -ne $Value) { $gRef = Get-Prop $Value 'Group'; $fRef = Get-Prop $Value 'Filter' }
            if ($gRef) {
                $g = Resolve-GroupIdentity -Value $gRef
                if ($null -eq $g) { throw "Scope group '$gRef' not found." }
                # policies assigned to a group the scope group is nested in reach its members too
                $parents = @{}
                try {
                    foreach ($pg in (Get-RsopPaged -Uri ("v1.0/groups/{0}/transitiveMemberOf/microsoft.graph.group?`$select=id,displayName&`$top=999" -f $g.id))) {
                        $parents[[string](Get-Prop $pg 'id')] = [string](Get-Prop $pg 'displayName')
                    }
                    if ($parents.Count -gt 0) { Write-Info ("Scope group is nested in {0} parent group(s); assignments to those count as in scope." -f $parents.Count) }
                } catch {
                    Add-RunLog -Level warn -Message ("Could not resolve parent groups of '{0}' ({1}); scope matches direct assignments only." -f $g.displayName, (Format-RsopError $_))
                }
                $sgObj = [pscustomobject]@{ Id = $g.id; Name = $g.displayName; Parents = $parents }
                $label += (" - group '{0}'" -f $g.displayName)
            }
            if ($fRef) {
                $sfObj = Resolve-AssignmentFilterIdentity -Corpus $Corpus -Value ([string]$fRef) -Label 'Scope filter'
                $label += (" - filter '{0}'" -f $sfObj.Name)
            }
            Write-Step $(if ($sgObj -or $sfObj) { "Building scoped tenant inventory" } else { "Building tenant-wide settings inventory" })
            # the whole-tenant view also carries the recovery picture: roles, tokens,
            # connectors, enrollment, groups and filters Intune depends on
            $tc = $null
            if ($script:WantTenantConfig -and -not ($sgObj -or $sfObj)) {
                # never let the recovery view take the inventory down with it
                try { $tc = Get-TenantConfiguration -Corpus $Corpus }
                catch { Add-RunLog -Level warn -Message ("Tenant setup view incomplete - it stopped with: {0}" -f (Format-RsopError $_)); $tc = $null }
            }
            $inv = Get-TenantInventoryRsop -Corpus $Corpus -ScopeGroup $sgObj -ScopeFilter $sfObj
            if ($tc) { $inv | Add-Member -NotePropertyName Tenant -NotePropertyValue $tc -Force }
            [void]$results.Add($inv)
        }
    }

    return [pscustomobject]@{ Label = $label; Results = $results.ToArray() }
}

function Export-RsopResults {
    param($Results, [string]$Label, [string]$Tenant, [string]$Account, [string]$HtmlPath, [string]$CsvPath, [string]$JsonPath, [datetime]$CaptureTime = (Get-Date))
    $brief = @($Results).Count -gt 5
    foreach ($r in @($Results)) { Show-ConsoleSummary -Result $r -Brief:$brief }
    if ($HtmlPath) { Export-HtmlReport -Results @($Results) -Path $HtmlPath -QueryLabel $Label -Tenant $Tenant -Account $Account -CaptureTime $CaptureTime }
    if ($CsvPath) {
        Get-CsvRows -Results @($Results) | Protect-RsopCsvRow | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding utf8BOM
        Set-RsopPrivateFile $CsvPath
        Write-Good ("CSV export: {0}" -f (Resolve-Path -LiteralPath $CsvPath))
    }
    if ($JsonPath) {
        [pscustomobject]@{ query = $Label; generated = (Get-Date).ToString('o'); devices = @($Results) } |
            ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $JsonPath -Encoding UTF8
        Set-RsopPrivateFile $JsonPath
        Write-Good ("JSON export: {0}" -f (Resolve-Path -LiteralPath $JsonPath))
    }
    Add-RsopRunQuery -Label $Label -Results $Results -Outputs @($HtmlPath, $CsvPath, $JsonPath)
}

function Reset-RunLog {
    param($Corpus)
    $script:RunLog.Clear()
    # corpus warnings, plus reads that failed afterwards (tenant setup) - they still apply
    foreach ($w in @(@($Corpus.warnings) + @($script:ReadProblems) | Select-Object -Unique)) {
        [void]$script:RunLog.Add([pscustomobject]@{ Time = ''; Level = 'warn'; Message = [string]$w })
    }
}

function Open-File {
    param([string]$Path)
    try {
        if ($env:OS -eq 'Windows_NT') { Start-Process -FilePath $Path }
        elseif ($IsMacOS) { & open $Path }
        else { & xdg-open $Path 2>$null }
    } catch { Write-Warn2 "Could not auto-open $Path" }
}

#endregion

#region ---------- interactive menu -----------------------------------------------------------

function Select-EntraGroup {
    # Search-as-you-type group picker.
    while ($true) {
        $q = Read-Host "  Group name starts with (blank = cancel)"
        if (-not $q) { return $null }
        $guid = [guid]::Empty
        if ([guid]::TryParse($q, [ref]$guid)) {
            try { $g = Invoke-Rsop -Uri ("v1.0/groups/{0}?`$select=id,displayName" -f $q); return $g } catch { Write-Warn2 "Not found."; continue }
        }
        $esc = $q -replace "'", "''"
        $filter = "startswith(displayName,'{0}')" -f $esc
        $resp = Invoke-Rsop -Uri ("v1.0/groups?`$filter={0}&`$select=id,displayName&`$top=20" -f [uri]::EscapeDataString($filter))
        $vals = @($resp['value'])
        if ($vals.Count -eq 0) { Write-Warn2 "No groups match."; continue }
        for ($i = 0; $i -lt $vals.Count; $i++) { Write-RsopConsole ("   [{0}] {1}" -f ($i + 1), $vals[$i]['displayName']) }
        $pick = Read-Host "  Pick number (blank = search again)"
        $pi = 0
        if ([int]::TryParse($pick, [ref]$pi) -and $pi -ge 1 -and $pi -le $vals.Count) { return $vals[$pi - 1] }
    }
}

function Select-CorpusFilter {
    param($Corpus)
    $flts = @($Corpus.filters)
    if ($flts.Count -eq 0) { Write-Warn2 "Tenant has no assignment filters."; return $null }
    for ($i = 0; $i -lt $flts.Count; $i++) {
        Write-RsopConsole ("   [{0}] {1}  ({2})" -f ($i + 1), $flts[$i].Name, $flts[$i].Platform)
    }
    $pick = Read-Host "  Pick number (blank = cancel)"
    $pi = 0
    if ([int]::TryParse($pick, [ref]$pi) -and $pi -ge 1 -and $pi -le $flts.Count) { return $flts[$pi - 1].Id }
    return $null
}

function Invoke-InteractiveMenu {
    param($Corpus, [string]$TenantKey, $GraphCtx)

    $menuLabels = @{
        '1' = 'device(s) by serial number'; '2' = 'device(s) by name'; '3' = 'all devices in an Entra group'
        '4' = 'policies and apps assigned to a group'; '5' = 'devices matching an assignment filter'
        '6' = 'tenant-wide inventory'; '7' = 'backup'; 'R' = 'refresh policy cache'; 'Q' = 'quit'
    }
    while ($true) {
        # the log is current whenever the menu waits: closing the window here loses nothing
        $script:RunOutcome = 'Waiting at the guided menu (closing the window there ends the run)'
        Save-RsopRunLogFile
        Complete-RsopProgress
        $assigned = @($Corpus.policies | Where-Object { @($_.Assignments).Count -gt 0 }).Count
        Write-RsopConsole ""
        Write-RsopConsole ("  🔍 Intune Lens v{0}" -f $script:Version) -ForegroundColor White
        Write-RsopConsole ("  Tenant {0}  |  signed in as {1}" -f $TenantKey, $GraphCtx.Account) -ForegroundColor DarkGray
        Write-RsopConsole ("  Policy corpus: {0} policies ({1} assigned), {2} apps, {3} filters, pulled {4}" -f `
            @($Corpus.policies).Count, $assigned, @($Corpus.apps).Count, @($Corpus.filters).Count, ([datetime]$Corpus.generated).ToString('HH:mm')) -ForegroundColor DarkGray
        Write-RsopConsole ""
        Write-RsopConsole "  What do you want to look up?" -ForegroundColor Cyan
        Write-RsopConsole "   [1] Device(s) by serial number"
        Write-RsopConsole "   [2] Device(s) by name"
        Write-RsopConsole "   [3] All devices in an Entra group"
        Write-RsopConsole "   [4] Policies and apps assigned directly to a group  (fast, no device math)"
        Write-RsopConsole "   [5] Devices matching an assignment filter"
        Write-RsopConsole "   [6] Tenant-wide inventory + tenant setup  (every policy, app and setting, roles, tokens,"
        Write-RsopConsole "       connectors, groups, recovery checklist; optional group/filter scope)"
        Write-RsopConsole "   [7] Back up everything as raw JSON to a folder  (for disaster recovery)"
        Write-RsopConsole "   [R] Refresh policy cache      [Q] Quit"
        $choice = (Read-Host "  Choice").Trim().ToUpper()
        if (-not $menuLabels.ContainsKey($choice)) { continue }
        Add-SessionLog 'info' ("Menu: [{0}] {1}" -f $choice, $menuLabels[$choice])
        $script:RunOutcome = 'In progress (a window closed mid-run leaves it at this)'

        if ($choice -eq 'Q') { break }
        if ($choice -eq 'R') {
            $script:Refresh = $true
            $Corpus = Get-PolicyCorpus -TenantKey $TenantKey
            $script:Refresh = $false
            $script:FilterById = @{}
            foreach ($f in @($Corpus.filters)) { $script:FilterById[[string]$f.Id] = $f }
            continue
        }

        $mode = $null; $value = $null; $assignedOnly = $false
        switch ($choice) {
            '1' {
                $s = Read-Host "  Serial number(s), comma-separated"
                if ($s) { $mode = 'serial'; $value = @($s -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            }
            '2' {
                $s = Read-Host "  Device name(s), comma-separated"
                if ($s) { $mode = 'name'; $value = @($s -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) }
            }
            '3' { $g = Select-EntraGroup; if ($g) { $mode = 'group'; $value = $g } }
            '4' { $g = Select-EntraGroup; if ($g) { $mode = 'group'; $value = $g; $assignedOnly = $true } }
            '5' { $f = Select-CorpusFilter -Corpus $Corpus; if ($f) { $mode = 'filter'; $value = $f } }
            '6' {
                $mode = 'all'
                Write-RsopConsole "  Optional scope - answers 'what policies apply to this group / filter?'" -ForegroundColor DarkGray
                $sg = (Read-Host "  Scope by group name or id (blank = whole tenant)").Trim()
                $sf = (Read-Host "  Scope by assignment filter name or id (blank = none)").Trim()
                if ($sg -or $sf) { $value = [pscustomobject]@{ Group = $sg; Filter = $sf } }
            }
            '7' {
                $destPrompt = (Read-Host "  Backup folder [default: .\backups, C to cancel]").Trim()
                if ($destPrompt -match '^(?i:c|cancel)$') { continue }
                $dest = if ($destPrompt) { $destPrompt } else { '.\backups' }
                try {
                    $script:BackupRoot = New-RsopBackupDirectory -ParentPath $dest -TenantKey $TenantKey
                    $script:BackupFiles.Clear(); $script:BackupProblems.Clear()
                    # raw objects are only seen while pulling: re-read everything from Graph
                    $script:Refresh = $true
                    $Corpus = Get-PolicyCorpus -TenantKey $TenantKey
                    $script:Refresh = $false
                    $script:FilterById = @{}
                    foreach ($f in @($Corpus.filters)) { $script:FilterById[[string]$f.Id] = $f }
                    # -SkipTenantConfig: its scopes were not requested, so do not read it (403s would look like 'not licensed')
                    try { if ($script:WantTenantConfig) { $null = Get-TenantConfiguration -Corpus $Corpus } }
                    catch { [void]$script:BackupProblems.Add("Tenant setup part of the backup incomplete: $(Format-RsopError $_)") }
                    Complete-RsopBackup -Corpus $Corpus -TenantKey $TenantKey -Account ([string]$GraphCtx.Account)
                }
                catch { Write-Warn2 ("Backup failed: {0}" -f (Format-RsopError $_)) }
                finally { $script:BackupRoot = $null; $script:Refresh = $false }
                continue
            }
            default { continue }
        }
        if (-not $mode) { continue }

        Reset-RunLog -Corpus $Corpus
        $q = $null
        try { $q = Resolve-QueryResults -Mode $mode -Corpus $Corpus -Value $value -AssignedOnly $assignedOnly }
        catch { Write-Warn2 (Format-RsopError $_) -Level 'error'; continue }
        if (-not $q -or @($q.Results).Count -eq 0) { Write-Warn2 "Nothing resolved."; continue }

        $captureTime = Get-Date
        $baseName = Get-RsopExportBaseName -Label $q.Label -Results $q.Results -Tenant $TenantKey -Timestamp $captureTime
        $htmlPath = New-RsopOutputFile -Path (Join-Path (Get-Location) ($baseName + '.html'))
        Export-RsopResults -Results $q.Results -Label $q.Label -Tenant $TenantKey -Account $GraphCtx.Account -HtmlPath $htmlPath -CaptureTime $captureTime
        # the report is on disk: closing the window at the questions below loses nothing
        $script:RunOutcome = 'Report written; waiting at the questions after it (closing the window there ends the run)'
        Save-RsopRunLogFile
        Complete-RsopProgress

        $open = (Read-Host "  Open the HTML report now? [Y/n]").Trim().ToUpper()
        if ($open -ne 'N') { Open-File -Path $htmlPath }
        # y = a CSV next to the report with the same name; anything else but n / blank is a file name
        $csvAns = (Read-Host "  Also write a CSV? [y/N or a file name]").Trim()
        $csvPath = $null
        if ($csvAns -match '^(?i:y|yes)$') { $csvPath = New-RsopOutputFile -Path ([IO.Path]::ChangeExtension($htmlPath, '.csv')) }
        elseif ($csvAns -and $csvAns -notmatch '^(?i:n|no)$') { $csvPath = $(if ([IO.Path]::GetExtension($csvAns)) { $csvAns } else { "$csvAns.csv" }) }
        if ($csvPath) {
            try {
                Get-CsvRows -Results $q.Results | Protect-RsopCsvRow | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8BOM
                Set-RsopPrivateFile $csvPath
                Write-Good ("CSV export: {0}" -f (Resolve-Path -LiteralPath $csvPath))
            }
            catch { Write-Warn2 ("CSV export to '{0}' failed: {1}" -f $csvPath, (Format-RsopError $_)) }
        }
    }
}

#endregion

#region ---------- main -----------------------------------------------------------------------

# the run log records the exact command, then everything the run prints
$script:CommandText = (@([IO.Path]::GetFileName([string]$PSCommandPath)) + @($PSBoundParameters.GetEnumerator() | ForEach-Object {
            if ($_.Value -is [switch]) { if ($_.Value) { '-' + $_.Key } }
            else { '-{0} {1}' -f $_.Key, ((@($_.Value) | ForEach-Object { "'$_'" }) -join ',') }
        })) -join ' '
Initialize-RsopRunLogFile -Folder $LogPath
$runCompleted = $false
try {
    $ctx = Connect-RsopGraph
    $tenantKey = [string]$ctx.TenantId
    # the organisation's name and default domain head the report (any signed-in user can read them)
    try {
        $org = @((Invoke-Rsop -Uri 'v1.0/organization?$select=displayName,verifiedDomains')['value'])[0]
        $script:TenantName = [string]$org['displayName']
        $script:TenantDomain = [string]@((ConvertTo-RsopList $org['verifiedDomains']) | Where-Object { $_['isDefault'] } | ForEach-Object { $_['name'] })[0]
    } catch { Add-RunLog -Level info -Message ("Organization name not readable: {0}" -f (Format-RsopError $_)) }
    $orgLabel = (@($script:TenantName, $(if ($script:TenantDomain) { "($($script:TenantDomain))" })) | Where-Object { $_ }) -join ' '
    $script:LogTenant = '{0}{1}, signed in as {2}' -f $(if ($orgLabel) { "$orgLabel - " } else { '' }), $tenantKey, $ctx.Account

    if ($BackupPath) {
        $script:BackupRoot = New-RsopBackupDirectory -ParentPath $BackupPath -TenantKey $tenantKey
        $Refresh = $true   # raw objects are only seen while pulling from Graph, never from the cache
        Write-Step ("Backup: raw JSON of every object goes to {0}" -f $script:BackupRoot)
    }

    $corpus = Get-PolicyCorpus -TenantKey $tenantKey

    # Index filters for quick lookup during evaluation.
    $script:FilterById = @{}
    foreach ($f in @($corpus.filters)) { $script:FilterById[[string]$f.Id] = $f }

    if ($BackupPath) {
        # -SkipTenantConfig: its scopes were not requested, so do not read it (403s would look like 'not licensed')
        if ($script:WantTenantConfig) {
            try { $null = Get-TenantConfiguration -Corpus $corpus }
            catch {
                $msg = "Tenant setup part of the backup incomplete - it stopped with: $(Format-RsopError $_)"
                [void]$script:BackupProblems.Add($msg); Write-Warn2 $msg
            }
        }
        Complete-RsopBackup -Corpus $corpus -TenantKey $tenantKey -Account ([string]$ctx.Account)
        # the backup is complete: later corpus pulls (menu [R]) must not write into it
        $script:BackupRoot = $null
        $Refresh = $false
    }

    if ($PSCmdlet.ParameterSetName -eq 'Interactive') {
        Invoke-InteractiveMenu -Corpus $corpus -TenantKey $tenantKey -GraphCtx $ctx
        Write-RsopConsole ""
        Write-RsopConsole "Bye." -ForegroundColor Cyan
        $runCompleted = $true
        return
    }

    Reset-RunLog -Corpus $corpus

    $mode = $null; $value = $null; $assignedOnly = $false
    switch ($PSCmdlet.ParameterSetName) {
        'BySerial'     { $mode = 'serial'; $value = $SerialNumber }
        'ByDeviceName' { $mode = 'name'; $value = $DeviceName }
        'ByGroup'      { $mode = 'group'; $value = $Group; $assignedOnly = [bool]$GroupAssignedOnly }
        'ByFilter'     { $mode = 'filter'; $value = $AssignmentFilter }
        'All'          {
            $mode = 'all'
            if ($ScopeGroup -or $ScopeFilter) { $value = [pscustomobject]@{ Group = $ScopeGroup; Filter = $ScopeFilter } }
        }
    }

    $q = Resolve-QueryResults -Mode $mode -Corpus $corpus -Value $value -AssignedOnly $assignedOnly
    if (-not $q -or @($q.Results).Count -eq 0) {
        Write-Warn2 "Nothing resolved - no report generated."
        $runCompleted = $true
        return
    }

    $captureTime = Get-Date
    if (-not $ExportHtml -and -not $NoHtml) {
        $baseName = Get-RsopExportBaseName -Label $q.Label -Results $q.Results -Tenant $tenantKey -Timestamp $captureTime
        $ExportHtml = New-RsopOutputFile -Path (Join-Path (Get-Location) ($baseName + '.html'))
    }

    Export-RsopResults -Results $q.Results -Label $q.Label -Tenant $tenantKey -Account $ctx.Account -HtmlPath $ExportHtml -CsvPath $ExportCsv -JsonPath $ExportJson -CaptureTime $captureTime

    $elapsed = (Get-Date) - $script:StartTime
    Write-RsopConsole ""
    Write-RsopConsole ("Done in {0:n0}s." -f $elapsed.TotalSeconds) -ForegroundColor Cyan

    if ($PassThru) { @($q.Results) }
    $runCompleted = $true
}
catch {
    $script:RunFailure = $_
    Add-SessionLog 'error' ('Run stopped: ' + (Format-RsopError $_))
    throw
}
finally {
    Complete-RsopProgress
    $script:RunOutcome = $(if ($script:RunFailure) { 'Failed: ' + (Format-RsopError $script:RunFailure) } elseif ($runCompleted) { 'Completed' } else { 'Stopped before completion' })
    Save-RsopRunLogFile
    if ($script:RunLogFile) { Write-RsopConsole ("Run log: {0}" -f $script:RunLogFile) -ForegroundColor DarkGray }
}

#endregion
