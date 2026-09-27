<#
.SYNOPSIS
    Reports on the authentication methods registered in a Microsoft 365 / Entra ID tenant, with a passkey type
    breakdown and phishing-resistant readiness, and exports raw CSV data plus a presentation-ready HTML report.

.DESCRIPTION
    Signs in to Microsoft Graph with an interactive (delegated) login and collects:
      - Users in scope (enabled member accounts by default)
      - The Entra ID user registration details report (every registered method per user)
      - Live authentication method details for every user who has a phishing-resistant method registered
        (for every user with -FullMethodScan, or automatically when the registration report is unavailable)
      - The authentication methods policy (targeting and passkey profiles) and the Conditional Access policies
        that require a phishing-resistant authentication strength

    Passkeys are classified from the Graph passkeyType (device-bound or synced), the authenticator AAGUID and the
    attestation result, so hardware security keys, Microsoft Authenticator, Windows Hello and synced passkeys
    (iCloud Keychain, Google Password Manager, password managers) are reported separately. Method names are
    normalised to plain-English labels, and methods with no registered users are left out of the report.

    The script only reads data. It requests read-only permissions, sends no changes to the tenant and keeps the
    sign-in token in memory for the current PowerShell session instead of the persistent token cache.

    Each run writes to a new folder in -OutputPath, named after the report title and the date and time of the run
    (for example "Authentication methods - 2026-09-27 1343"). A second run in the same minute gets " (2)" added.
      Authentication methods - report.html             Self-contained HTML report: a one-screen overview, then every
                                                       detail section on the same page, with tabs that jump to each one
      Authentication methods - users.csv               One row per user with phishing-resistant status and a summary
      Authentication methods - registered methods.csv  Raw data: one row per user per registered method or credential

.PARAMETER OutputPath
    Folder to create each run's output folder in. Created if it doesn't exist. Defaults to the current folder.

.PARAMETER TenantId
    Tenant ID or verified domain to sign in to. Useful for admins with access to several tenants.

.PARAMETER ClientId
    Application (client) ID of your own app registration to sign in with, instead of the shared Microsoft Graph
    Command Line Tools app. The app needs the delegated permissions listed under NOTES and http://localhost as a
    mobile and desktop redirect URI. Requires -TenantId.

.PARAMETER IncludeGuests
    Include guest (B2B) accounts. By default only member accounts are reported.

.PARAMETER UsersOnly
    Report enabled member accounts, excluding direct active or eligible Entra ID directory-role assignees and
    active members of groups assigned those roles. Used by the companion standard-user script.

.PARAMETER IncludeDisabledUsers
    Include disabled accounts. By default only enabled (active) accounts are reported.

.PARAMETER LicensedUsersOnly
    Only report on users with at least one licence assigned (excludes most service and resource accounts).

.PARAMETER ActiveWithinDays
    Only report on users who signed in within this many days. 0 (the default) turns the filter off.
    Requires Microsoft Entra ID P1 or P2.

.PARAMETER FullMethodScan
    Read live authentication methods for every user instead of only users with a phishing-resistant method.
    Slower on large tenants, but independent of the registration report's refresh cycle.

.PARAMETER ThrottleLimit
    Number of Graph batch requests (20 users each) to run in parallel when reading live method details.
    Defaults to 4. Use 1 to read sequentially, or a lower value if Graph throttling slows the run down.

.PARAMETER MaxUsersInHtml
    Maximum rows in each user list in the HTML report. The CSV files always contain every user. Use 0 to leave
    individual users out of the HTML report, for example before sharing it more widely.

.PARAMETER ReportTitle
    Title shown at the top of the HTML report. It also names the output folder and files.

.PARAMETER UseDeviceCode
    Sign in with the device code flow instead of a browser window (for example over a remote session).

.PARAMETER NoOpen
    Don't open the HTML report when the script finishes.

.PARAMETER ForceModuleInstall
    Install the Microsoft.Graph.Authentication module without prompting if it's missing.

.EXAMPLE
    .\get-authentication-methods-report.ps1
    Signs in interactively and reports on all enabled member accounts, writing the files to a new folder in the
    current folder.

.EXAMPLE
    .\get-authentication-methods-report.ps1 -OutputPath 'C:\Reports' -LicensedUsersOnly -ActiveWithinDays 90
    Reports on licensed users who signed in during the last 90 days.

.EXAMPLE
    .\get-authentication-methods-report.ps1 -TenantId contoso.onmicrosoft.com -FullMethodScan -MaxUsersInHtml 0
    Reads live method details for every user and leaves individual users out of the HTML report.

.NOTES
    Title        : Authentication Methods and Phishing-Resistant MFA Report
    Tags         : Security,Monitoring
    Platform     : Windows (Windows PowerShell 5.1 or PowerShell 7+)
    Permissions  : User.Read.All, AuditLog.Read.All, UserAuthenticationMethod.Read.All, Policy.Read.All,
                   GroupMember.Read.All (delegated); RoleManagement.Read.Directory for -UsersOnly
    Author       : AI Generated (Claude Code)
    Version      : 1.4
    Changelog    : 1.4 - One adoption chart and a standard-user report mode with role-based account exclusion.
                   1.3 - Light-only HTML with a clearer title, vivid method colors, concise definitions and footer.
                   1.2 - One scrolling page with tabs that jump to each section; dates and times in Irish time;
                         shorter default title; even spacing below the header; a new output folder for each run,
                         with plain-English folder and file names
                   1.1 - Tabbed report with a one-screen overview; parallel live reads, streamed CSV output and
                         lower memory use for large tenants; -ActiveWithinDays page size fix; CSV formula
                         protection; session-only sign-in token; -ClientId and -ThrottleLimit parameters
                   1.0 - Initial release
    Last update  : 2026-09-27

    - Requires the Microsoft.Graph.Authentication module.
    - The signed-in account needs a directory role that can read reports, authentication methods and policies.
      Global Reader is the least-privileged built-in role that covers every section of the report.
    - Uses the Microsoft Graph beta endpoint: passkey type (device-bound or synced) and last-used dates are
      only exposed there.
    - The registration details report needs Microsoft Entra ID P1 or P2. Without it, every user's methods are
      read live instead (slower on large tenants).
    - Certificate-based authentication can't be detected per user through Graph, so it's reported at policy
      level only.
    - The standard output files list users, admin roles and sign-in methods, so store and share them accordingly. Phone
      numbers and email addresses registered as methods are never exported.
    - The companion standard-user report needs RoleManagement.Read.Directory and GroupMember.Read.All. It excludes
      direct active or eligible Entra ID role assignees and active members of groups assigned those roles. It stops
      if role or role-group membership data can't be read.
    - Dates and times in the HTML report and the output folder name are in Irish time (Dublin), wherever the
      script runs. The CSV files keep UTC, as their column names say.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, HelpMessage = "Folder for the CSV and HTML output files")]
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Get-Location).Path,

    [Parameter(Mandatory = $false, HelpMessage = "Tenant ID or verified domain to sign in to")]
    [string]$TenantId,

    [Parameter(Mandatory = $false, HelpMessage = "Application (client) ID of your own app registration")]
    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [Parameter(Mandatory = $false, HelpMessage = "Include guest (B2B) accounts")]
    [switch]$IncludeGuests,

    [Parameter(Mandatory = $false, HelpMessage = "Report enabled member users without Entra ID directory roles")]
    [switch]$UsersOnly,

    [Parameter(Mandatory = $false, HelpMessage = "Include disabled accounts")]
    [switch]$IncludeDisabledUsers,

    [Parameter(Mandatory = $false, HelpMessage = "Only report on users with at least one licence assigned")]
    [switch]$LicensedUsersOnly,

    [Parameter(Mandatory = $false, HelpMessage = "Only report on users who signed in within this many days (0 = no filter)")]
    [ValidateRange(0, 3650)]
    [int]$ActiveWithinDays = 0,

    [Parameter(Mandatory = $false, HelpMessage = "Read live authentication methods for every user")]
    [switch]$FullMethodScan,

    [Parameter(Mandatory = $false, HelpMessage = "Graph batch requests to run in parallel (1 = sequential)")]
    [ValidateRange(1, 8)]
    [int]$ThrottleLimit = 4,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum rows in each user list in the HTML report (0 = no user names)")]
    [ValidateRange(0, 1000000)]
    [int]$MaxUsersInHtml = 5000,

    [Parameter(Mandatory = $false, HelpMessage = "Title shown at the top of the HTML report")]
    [ValidateNotNullOrEmpty()]
    [string]$ReportTitle = 'Authentication methods',

    [Parameter(Mandatory = $false, HelpMessage = "Sign in with the device code flow instead of a browser window")]
    [switch]$UseDeviceCode,

    [Parameter(Mandatory = $false, HelpMessage = "Don't open the HTML report when finished")]
    [switch]$NoOpen,

    [Parameter(Mandatory = $false, HelpMessage = "Install missing modules without prompting")]
    [switch]$ForceModuleInstall
)

if ($ClientId -and -not $TenantId) {
    Write-Error '-ClientId needs -TenantId, because an app registration signs in to a specific tenant.'
    exit 1
}
if ($UsersOnly -and ($IncludeGuests -or $IncludeDisabledUsers)) {
    Write-Error '-UsersOnly reports enabled member accounts only; remove -IncludeGuests and -IncludeDisabledUsers.'
    exit 1
}

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

function Initialize-RequiredModule {
    param(
        [string[]]$ModuleNames,
        [bool]$ForceInstall = $false
    )

    foreach ($moduleName in $ModuleNames) {
        if (-not (Get-Module -ListAvailable -Name $moduleName)) {
            if (-not $ForceInstall) {
                $response = Read-Host "Module '$moduleName' is required. Install it for the current user now? (Y/N)"
                if ($response -notmatch '^[Yy]') {
                    throw "Module '$moduleName' is required but installation was declined."
                }
            }
            Write-Information "Installing module '$moduleName'..." -InformationAction Continue
            Install-Module -Name $moduleName -Scope CurrentUser -Force -Repository PSGallery -ErrorAction Stop
        }
        # Re-importing a loaded Graph module can clash with its already-loaded assemblies, so only import when needed
        if (-not (Get-Module -Name $moduleName)) {
            Import-Module -Name $moduleName -ErrorAction Stop
        }
    }
}

try {
    Initialize-RequiredModule -ModuleNames @('Microsoft.Graph.Authentication') -ForceInstall $ForceModuleInstall.IsPresent
}
catch {
    Write-Error "Module initialisation failed: $($_.Exception.Message)"
    exit 1
}

try {
    if (-not (Test-Path -LiteralPath $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    $OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
}
catch {
    Write-Error "Output folder '$OutputPath' can't be used: $($_.Exception.Message)"
    exit 1
}

# ============================================================================
# AUTHENTICATION
# ============================================================================

$RequiredScopes = @(
    'User.Read.All',
    'AuditLog.Read.All',
    'UserAuthenticationMethod.Read.All',
    'Policy.Read.All',
    'GroupMember.Read.All'
)
if ($UsersOnly) { $RequiredScopes += 'RoleManagement.Read.Directory' }

try {
    Write-Information "Connecting to Microsoft Graph..." -InformationAction Continue
    $connectCommand = Get-Command -Name Connect-MgGraph
    $connectParams = @{ Scopes = $RequiredScopes; ErrorAction = 'Stop' }
    if ($TenantId) { $connectParams.TenantId = $TenantId }
    if ($ClientId) { $connectParams.ClientId = $ClientId }
    if ($UseDeviceCode) { $connectParams.UseDeviceCode = $true }
    # -NoWelcome only exists in Microsoft.Graph.Authentication v2+
    if ($connectCommand.Parameters.ContainsKey('NoWelcome')) { $connectParams.NoWelcome = $true }
    # Keep the token in memory for this PowerShell session instead of the persistent token cache
    if ($connectCommand.Parameters.ContainsKey('ContextScope')) { $connectParams.ContextScope = 'Process' }
    Connect-MgGraph @connectParams

    $context = Get-MgContext
    if (-not $context) { throw 'No Microsoft Graph context was created.' }
    $missingScopes = @($RequiredScopes | Where-Object { $context.Scopes -notcontains $_ })
    if ($missingScopes.Count -gt 0) {
        if ($UsersOnly -and @($missingScopes | Where-Object { $_ -in @('RoleManagement.Read.Directory', 'GroupMember.Read.All') }).Count -gt 0) {
            throw 'The standard-user report needs RoleManagement.Read.Directory and GroupMember.Read.All permissions to exclude admin accounts.'
        }
        Write-Warning "These permissions weren't granted, so related sections may be incomplete: $($missingScopes -join ', ')"
    }
    Write-Information "Connected to tenant $($context.TenantId) as $($context.Account)" -InformationAction Continue
}
catch {
    Write-Error "Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    exit 1
}

# ============================================================================
# REFERENCE DATA
# ============================================================================

# Relative URIs resolve against the Graph endpoint of the cloud the session signed in to
$GraphBase = 'beta'
$ReportWarnings = [System.Collections.Generic.List[string]]::new()
$ObservedAaguidNames = @{}
$RegistrationEntryCache = @{}
# Characters that make spreadsheet apps treat a cell as a formula
$CsvFormulaStart = "=+-@`t`r"

# Registration report values that mean "has a phishing-resistant credential", used to decide who gets a live lookup
$PhishingResistantRegistrationValues = [System.Collections.Generic.HashSet[string]]::new([string[]]@(
        'passKeyDeviceBound', 'passKeyDeviceBoundAuthenticator', 'passKeyDeviceBoundWindowsHello', 'passKeySynced',
        'fido2SecurityKey', 'fido2', 'windowsHelloForBusiness', 'macOsSecureEnclaveKey'
    ), [StringComparer]::OrdinalIgnoreCase)
$PhishingResistantStrengthId = '00000000-0000-0000-0000-000000000004'
$PhishingResistantModes = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')
$ZeroAaguid = '00000000-0000-0000-0000-000000000000'

# Fallback when an AAGUID isn't in the catalogue below: FIDO-certified hardware vendors and product names
$HardwareModelPattern = '(?i)yubi|feitian|epass|biopass|allinpass|token2|thales|safenet|etoken|idprime|titan|crescendo|\bhid\b|nitrokey|solokey|\bsolo\b|verimark|kensington|identiv|utrust|trustkey|atkey|authentrend|swissbit|ishield|idem key|gotrust|digipass|onespan|hyperfido|hypersecu|vincss|fido2key|excelsecu|esecu|ensurity|thinc|crayonic|deepnet|safekey|offpad|hideez|cryptnox|ledger|neowave|winkeo|ewbm|goldkey|onlykey|arculus|secora|idemia|id-one|cardos|keyxentic|security key|smart ?card'

# Strength groups. Rank orders the "strongest method" ladder (1 = strongest).
$GroupCatalog = @{
    PhishingResistant = [pscustomobject]@{ Key = 'PhishingResistant'; Name = 'Phishing-resistant';                   Ladder = 'Phishing-resistant';          Rank = 1; Css = 'pr' }
    Passwordless      = [pscustomobject]@{ Key = 'Passwordless';      Name = 'Passwordless (not phishing-resistant)'; Ladder = 'Passwordless phone sign-in'; Rank = 2; Css = 'pwl' }
    AppMfa            = [pscustomobject]@{ Key = 'AppMfa';            Name = 'App or token MFA';                     Ladder = 'App or token MFA';            Rank = 3; Css = 'app' }
    PhoneMfa          = [pscustomobject]@{ Key = 'PhoneMfa';          Name = 'SMS or voice MFA';                     Ladder = 'SMS or voice only';           Rank = 4; Css = 'phone' }
    RecoveryOnly      = [pscustomobject]@{ Key = 'RecoveryOnly';      Name = 'Password reset only (not MFA)';        Ladder = 'No MFA (reset methods only)'; Rank = 5; Css = 'rec' }
    Other             = [pscustomobject]@{ Key = 'Other';             Name = 'Temporary and other';                  Ladder = $null;                         Rank = 5; Css = 'other' }
    None              = [pscustomobject]@{ Key = 'None';              Name = 'No methods registered';                Ladder = 'No methods registered';       Rank = 6; Css = 'none' }
}
$LadderOrder = @('PhishingResistant', 'Passwordless', 'AppMfa', 'PhoneMfa', 'RecoveryOnly', 'None')
$GroupOrder = @('PhishingResistant', 'Passwordless', 'AppMfa', 'PhoneMfa', 'RecoveryOnly', 'Other')

# Normalised method names. Graph values from both the registration report and live method objects map onto these keys.
$methodDefinitions = @(
    #  Key                         Normalised name                                         Short name                    Group
    @('PasskeySecurityKey',       'Passkey - hardware security key',                      'Security key',               'PhishingResistant'),
    @('PasskeyAuthenticator',     'Passkey - Microsoft Authenticator',                    'Authenticator passkey',      'PhishingResistant'),
    @('PasskeyWindowsHello',      'Passkey - Windows Hello',                              'Windows Hello passkey',      'PhishingResistant'),
    @('PasskeySynced',            'Passkey - synced',                                     'Synced passkey',             'PhishingResistant'),
    @('PasskeyOther',             'Passkey - other device-bound or unidentified',         'Other passkey',              'PhishingResistant'),
    @('PasskeyDeviceBound',       'Passkey - device-bound (not classified)',              'Device-bound passkey',       'PhishingResistant'),
    @('WindowsHelloForBusiness',  'Windows Hello for Business',                           'Windows Hello for Business', 'PhishingResistant'),
    @('PlatformCredential',       'Platform SSO - macOS Secure Enclave key',              'Platform SSO',               'PhishingResistant'),
    @('AuthenticatorPhoneSignIn', 'Microsoft Authenticator - passwordless phone sign-in', 'Phone sign-in',              'Passwordless'),
    @('AuthenticatorPush',        'Microsoft Authenticator - push notification',          'Authenticator push',         'AppMfa'),
    @('SoftwareOath',             'Authenticator app - verification code (TOTP)',         'Authenticator code',         'AppMfa'),
    @('HardwareOath',             'Hardware OATH token',                                  'Hardware token',             'AppMfa'),
    @('ExternalMfa',              'External MFA provider',                                'External MFA',               'AppMfa'),
    @('MobilePhone',              'Mobile phone - SMS or voice call',                     'Mobile phone',               'PhoneMfa'),
    @('AlternateMobilePhone',     'Alternate mobile phone - voice call',                  'Alternate phone',            'PhoneMfa'),
    @('OfficePhone',              'Office phone - voice call',                            'Office phone',               'PhoneMfa'),
    @('Email',                    'Email - password reset only',                          'Email',                      'RecoveryOnly'),
    @('SecurityQuestions',        'Security questions - password reset only',             'Security questions',         'RecoveryOnly'),
    @('TemporaryAccessPass',      'Temporary Access Pass',                                'Temporary Access Pass',      'Other'),
    @('QrCodePin',                'QR code with PIN',                                     'QR code',                    'Other'),
    @('AppPassword',              'App password (legacy)',                                'App password',               'Other'),
    @('ResourceAccountKey',       'Resource account key (Teams Rooms)',                   'Resource account key',       'Other')
)
$MethodCatalog = @{}
$methodOrder = 0
foreach ($definition in $methodDefinitions) {
    $methodOrder++
    $MethodCatalog[$definition[0]] = [pscustomobject]@{
        Key       = $definition[0]
        Name      = $definition[1]
        Short     = $definition[2]
        Group     = $definition[3]
        Rank      = $GroupCatalog[$definition[3]].Rank
        Order     = $methodOrder
        IsPasskey = $definition[0].StartsWith('Passkey')
        CsvFields = $null
    }
}

# Registration report values (methodsRegistered) and the normalised method each one maps to
$RegistrationMethodMap = @{
    mobilePhone                        = 'MobilePhone'
    sms                                = 'MobilePhone'
    alternateMobilePhone               = 'AlternateMobilePhone'
    officePhone                        = 'OfficePhone'
    email                              = 'Email'
    securityQuestion                   = 'SecurityQuestions'
    microsoftAuthenticatorPush         = 'AuthenticatorPush'
    microsoftAuthenticatorPasswordless = 'AuthenticatorPhoneSignIn'
    softwareOneTimePasscode            = 'SoftwareOath'
    hardwareOneTimePasscode            = 'HardwareOath'
    windowsHelloForBusiness            = 'WindowsHelloForBusiness'
    macOsSecureEnclaveKey              = 'PlatformCredential'
    passKeyDeviceBound                 = 'PasskeyDeviceBound'
    passKeyDeviceBoundAuthenticator    = 'PasskeyAuthenticator'
    passKeyDeviceBoundWindowsHello     = 'PasskeyWindowsHello'
    passKeySynced                      = 'PasskeySynced'
    fido2SecurityKey                   = 'PasskeySecurityKey'
    fido2                              = 'PasskeyDeviceBound'
    temporaryAccessPass                = 'TemporaryAccessPass'
    externalAuthMethod                 = 'ExternalMfa'
    qrCode                             = 'QrCodePin'
    qrCodePin                          = 'QrCodePin'
    appPassword                        = 'AppPassword'
}

# Default and system-preferred MFA method values from the registration report, for the user CSV
$PreferredMethodNames = @{
    push                               = 'Authenticator push'
    microsoftAuthenticatorPush         = 'Authenticator push'
    microsoftAuthenticatorPasswordless = 'Phone sign-in'
    oath                               = 'Authenticator code'
    softwareOath                       = 'Authenticator code'
    softwareOneTimePasscode            = 'Authenticator code'
    hardwareOath                       = 'Hardware token'
    hardwareOneTimePasscode            = 'Hardware token'
    sms                                = 'SMS'
    mobilePhone                        = 'Mobile phone'
    voiceMobile                        = 'Voice call - mobile'
    alternateMobilePhone               = 'Alternate phone'
    voiceAlternateMobile               = 'Voice call - alternate phone'
    officePhone                        = 'Office phone'
    voiceOffice                        = 'Voice call - office phone'
    email                              = 'Email'
    fido2                              = 'Passkey'
    passKeyDeviceBound                 = 'Passkey'
    windowsHelloForBusiness            = 'Windows Hello for Business'
    x509CertificateMultiFactor         = 'Certificate'
    x509CertificateSingleFactor        = 'Certificate'
    temporaryAccessPass                = 'Temporary Access Pass'
    none                               = ''
}

# Authentication method policy IDs and the normalised methods each one governs (for "registered users" counts)
$ConfigMethodKeys = @{
    Fido2                  = @('PasskeySecurityKey', 'PasskeyAuthenticator', 'PasskeyWindowsHello', 'PasskeySynced', 'PasskeyOther', 'PasskeyDeviceBound')
    MicrosoftAuthenticator = @('AuthenticatorPush', 'AuthenticatorPhoneSignIn')
    Sms                    = @('MobilePhone')
    Voice                  = @('MobilePhone', 'AlternateMobilePhone', 'OfficePhone')
    Email                  = @('Email')
    TemporaryAccessPass    = @('TemporaryAccessPass')
    SoftwareOath           = @('SoftwareOath')
    HardwareOath           = @('HardwareOath')
    QRCodePin              = @('QrCodePin')
}
$KeyToConfigIds = @{}
foreach ($configId in $ConfigMethodKeys.Keys) {
    foreach ($methodKey in $ConfigMethodKeys[$configId]) {
        if (-not $KeyToConfigIds.ContainsKey($methodKey)) { $KeyToConfigIds[$methodKey] = @() }
        $KeyToConfigIds[$methodKey] += $configId
    }
}

# Known passkey authenticators by AAGUID: aaguid|kind|form factor|name
# Sources: Microsoft Learn (Authenticator and Windows Hello AAGUIDs), FIDO Alliance MDS3 (platform/app
# authenticators) and the community passkey-authenticator-aaguids list (passkey providers).
# Hardware security keys aren't listed: FIDO-attested keys are identified by their attestation and model instead.
$AaguidData = @'
90a3ccdf-635c-4729-a248-9b709135078f|MicrosoftAuthenticator|Authenticator app|Microsoft Authenticator (iOS)
de1e552d-db1d-4423-a619-566b625cdc84|MicrosoftAuthenticator|Authenticator app|Microsoft Authenticator (Android)
08987058-cadc-4b81-b6e1-30de50dcbe96|WindowsHello|Windows Hello|Windows Hello (TPM)
9ddd1817-af5a-4672-a2b9-3e3dd95000a9|WindowsHello|Windows Hello|Windows Hello (VBS)
6028b017-b1d4-4c02-b4b3-afcdafc96bb2|WindowsHello|Windows Hello|Windows Hello (software key)
fbfc3007-154e-4ecc-8c0b-6e020557d7bd|Provider|Platform keychain|Apple iCloud Keychain / Passwords
dd4ec289-e01d-41c9-bb89-70fa845d4bf2|Provider|Platform keychain|Apple iCloud Keychain (managed)
ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4|Provider|Platform keychain|Google Password Manager
d3452668-01fd-4c12-926c-83a4204853aa|Provider|Platform keychain|Microsoft Password Manager (Edge)
53414d53-554e-4700-0000-000000000000|Provider|Platform keychain|Samsung Pass
adce0002-35bc-c60a-648b-0b25f1f05503|Provider|Browser|Chrome on Mac
771b48fd-d3d4-4f74-9232-fc157ab0507a|Provider|Browser|Edge on Mac
b5397666-4885-aa6b-cebf-e52262a439a2|Provider|Browser|Chromium browser
bada5566-a7aa-401f-bd96-45619a55120d|Provider|Password manager|1Password
d548826e-79b4-db40-a3d8-11116f7e8349|Provider|Password manager|Bitwarden
531126d6-e717-415c-9320-3d9aa6981239|Provider|Password manager|Dashlane
0ea242b4-43c4-4a1b-8b17-dd6d0b6baec6|Provider|Password manager|Keeper
b84e4048-15dc-4dd0-8640-f4f60813c8af|Provider|Password manager|NordPass
b78a0a55-6ef8-d246-a042-ba0f6d55050c|Provider|Password manager|LastPass
50726f74-6f6e-5061-7373-50726f746f6e|Provider|Password manager|Proton Pass
f3809540-7f14-49c1-a8b3-8f813b225541|Provider|Password manager|Enpass
b35a26b2-8f6e-4697-ab1d-d44db4da28c6|Provider|Password manager|Zoho Vault
de503f9c-21a4-4f76-b4b7-558eb55c6f89|Provider|Password manager|Devolutions
fdb141b2-5d84-443e-8a35-4698c205a502|Provider|Password manager|KeePassXC
eaecdef2-1c31-5634-8639-f1cbd9c00a08|Provider|Password manager|KeePassDX
9addb28c-b46f-4402-808f-019651441ff3|Provider|Password manager|KeePass passkey provider
a10c6dd9-465e-4226-8198-c7c44b91c555|Provider|Password manager|Kaspersky Password Manager
22248c4c-7a12-46e2-9a41-44291b373a4d|Provider|Password manager|LogMeOnce
d350af52-0351-4ba2-acd3-dfeeadc3f764|Provider|Password manager|pwSafe
891494da-2c90-4d31-a9cd-4eab0aed1309|Provider|Password manager|Sesame
d49b2120-b865-4191-8cea-be84a52b0485|Provider|Password manager|Heimlane Vault
d9be9d39-e6a6-4c28-a581-32b044d986e4|Provider|Password manager|Sticky Password
70617373-7761-6c6c-6669-646f32303236|Provider|Password manager|Passwall
fa37f553-f9b6-4adb-ac53-8bbb57ebdf0d|Provider|Password manager|Norton Password Manager
a4a2d88e-9796-4356-9164-e2a5a8bd019c|Provider|Password manager|Avast Password Manager
e7db2bd3-f2fe-4d71-ad78-7e7aa166cfd1|Provider|Password manager|Avira Password Manager
6bb49926-160a-4306-a100-4eb39ba6ac45|Provider|Password manager|AVG Password Manager
45e3057e-b2f9-48ed-912f-9b901e153b16|Provider|Password manager|Uniqkey
53e7a7a5-e75f-4d3d-9483-12fc779cdf23|Provider|Password manager|Password Depot
477b05cd-7f78-4fe7-b629-27247f296138|Provider|Password manager|WALLIX Vault
65c97700-f5ef-4d5c-8a42-f30e45ac94b7|Provider|Password manager|Royal Vault
a11a5faa-9f32-4b8c-8c5d-2f7d13e8c942|Provider|Password manager|AliasVault
bfc748bb-3429-4faa-b9f9-7cfa9f3b76d0|Provider|Password manager|iPasswords
e8b7f4a2-c3d5-e6f7-890a-b1c2d3e4f567|Provider|Password manager|Sherlocked
cc45f64e-52a2-451b-831a-4edd8022a202|Provider|Password manager|ToothPic
b93fd961-f2e6-462f-b122-82002247de78|Platform|Platform or app authenticator|Android device
6f706c75-7366-6964-6f2d-70732d303031|Platform|Platform or app authenticator|OPPO device
970c8d9c-19d2-46af-aa32-3f448db49e35|Platform|Platform or app authenticator|WinMagic FIDO Eazy (TPM)
f56f58b3-d711-4afc-ba7d-6ac05f88cb19|Platform|Platform or app authenticator|WinMagic FIDO Eazy (phone)
31c3f7ff-bf15-4327-83ec-9336abcbcd34|Platform|Platform or app authenticator|WinMagic FIDO Eazy (software)
95e4d58c-056e-4a65-866d-f5a69659e880|Platform|Platform or app authenticator|TruU Windows Authenticator
ba86dc56-635f-4141-aef6-00227b1b9af6|Platform|Platform or app authenticator|TruU Windows Authenticator
bb878d7b-cf54-4784-b390-357030497043|Platform|Platform or app authenticator|TruU FIDO2 Authenticator
6dae43be-af9c-417b-8b9f-1b611168ec60|Platform|Platform or app authenticator|Dapple Authenticator
2588ae83-5a3b-4536-b8de-5e540200d191|Platform|Platform or app authenticator|Dapple Authenticator
8791f7dc-418b-4510-bbf5-3baf30715324|Platform|Platform or app authenticator|Virtual FIDO2 authenticator (Linux)
8681a073-5f50-4d52-bce4-e21658d207b3|Platform|Platform or app authenticator|RSA Authenticator (iOS)
59f85fe7-faa5-4c92-9f52-697b9d4d5473|Platform|Platform or app authenticator|RSA Authenticator (Android)
6e8d1eae-8d40-4c25-bcf8-4633959afc71|Platform|Platform or app authenticator|Veridium (iOS)
5ea308b2-7ac7-48b9-ac09-7e2da9015f8c|Platform|Platform or app authenticator|Veridium (Android)
1e906e14-77af-46bc-ae9f-fe6ef18257e4|Platform|Platform or app authenticator|VeridiumID Passkey (iOS)
8d4378b0-725d-4432-b3c2-01fcdaf46286|Platform|Platform or app authenticator|VeridiumID Passkey (Android)
1105e4ed-af1d-02ff-ffff-ffffffffffff|Platform|Platform or app authenticator|Egomet (Android)
5ca1ab1e-1337-fa57-f1d0-a117e71ca702|Platform|Platform or app authenticator|Allthenticator (iOS)
5ca1ab1e-fa57-1337-f1d0-a117371ca702|Platform|Platform or app authenticator|Allthenticator (Android)
66a0ccb3-bd6a-191f-ee06-e375c50b9846|Platform|Platform or app authenticator|Thales mobile app (iOS)
8836336a-f590-0921-301d-46427531eee6|Platform|Platform or app authenticator|Thales mobile app (Android)
cd69adb5-3c7a-deb9-3177-6800ea6cb72a|Platform|Platform or app authenticator|Thales mobile app (Android)
17290f1e-c212-34d0-1423-365d729f09d9|Platform|Platform or app authenticator|Thales mobile app (iOS)
'@
$AaguidCatalog = @{}
foreach ($line in ($AaguidData -split "`r?`n")) {
    if (-not $line.Trim()) { continue }
    $parts = $line.Split('|')
    $AaguidCatalog[$parts[0].Trim().ToLowerInvariant()] = [pscustomobject]@{ Kind = $parts[1]; FormFactor = $parts[2]; Name = $parts[3] }
}
$FormFactorOrder = @('Hardware security key', 'Authenticator app', 'Windows Hello', 'Platform keychain', 'Password manager', 'Browser', 'Platform or app authenticator', 'Unidentified')

# CSV columns, in order (used for the header when a file has no rows)
$DetailCsvColumns = @('UserPrincipalName', 'DisplayName', 'UserId', 'AccountEnabled', 'UserType', 'Department', 'IsAdmin', 'Method', 'MethodCategory', 'PhishingResistant', 'MfaCapable', 'Active', 'PasskeyType', 'PasskeyHeldBy', 'HardwareOrSoftware', 'Authenticator', 'AAGUID', 'Attestation', 'CredentialName', 'Detail', 'CreatedUtc', 'LastUsedUtc', 'Source', 'GraphValue')
$UserCsvColumns = @('UserPrincipalName', 'DisplayName', 'UserId', 'AccountEnabled', 'UserType', 'Department', 'IsAdmin', 'StrongestMethod', 'PhishingResistant', 'PasswordlessCapable', 'MfaCapable', 'PhishingResistantMethods', 'Passkeys', 'HardwareSecurityKeys', 'AuthenticatorPasskeys', 'WindowsHelloPasskeys', 'SyncedPasskeys', 'OtherPasskeys', 'WindowsHelloForBusiness', 'PlatformSso', 'RegisteredMethods', 'DefaultMfaMethod', 'SystemPreferredMethods', 'PasskeyPolicy', 'CertificateAuthEnabled', 'FirstPhishingResistantUtc', 'LastPhishingResistantUseUtc', 'LastSignInUtc', 'DataSource')

# ============================================================================
# HELPER FUNCTIONS - GRAPH
# ============================================================================

function Write-Step {
    param([string]$Message)
    Write-Information ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Message) -InformationAction Continue
}

function Add-ReportWarning {
    param([string]$Message)
    Write-Warning $Message
    $ReportWarnings.Add($Message)
}

function Get-HttpStatusFromError {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $response = $ErrorRecord.Exception.Response
    if ($response -and $response.StatusCode) { return [int]$response.StatusCode }
    $text = "$($ErrorRecord.Exception.Message) $($ErrorRecord.ErrorDetails.Message)"
    if ($text -match 'HTTP/\d(?:\.\d)?\s+(\d{3})') { return [int]$Matches[1] }
    if ($text -match '\b(BadRequest|Unauthorized|Forbidden|NotFound|TooManyRequests|InternalServerError|BadGateway|ServiceUnavailable|GatewayTimeout)\b') {
        $codes = @{ BadRequest = 400; Unauthorized = 401; Forbidden = 403; NotFound = 404; TooManyRequests = 429; InternalServerError = 500; BadGateway = 502; ServiceUnavailable = 503; GatewayTimeout = 504 }
        return $codes[$Matches[1]]
    }
    return $null
}

function Get-ErrorSummary {
    param([System.Management.Automation.ErrorRecord]$ErrorRecord)

    $status = Get-HttpStatusFromError -ErrorRecord $ErrorRecord
    $text = "$($ErrorRecord.ErrorDetails.Message) $($ErrorRecord.Exception.Message)"
    $parts = @()
    if ($status) { $parts += "HTTP $status" }
    if ($text -match '"code"\s*:\s*"([^"]+)"') { $parts += $Matches[1] }
    if ($parts.Count -eq 0) { $parts += (($ErrorRecord.Exception.Message -split "`r?`n")[0]) }
    return ($parts -join ' ')
}

function Invoke-GraphRequestWithRetry {
    # GET only: the report never changes anything in the tenant
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers,
        [int]$MaxRetries = 5
    )

    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $params = @{ Uri = $Uri; Method = 'GET'; ErrorAction = 'Stop' }
            if ($Headers) { $params.Headers = $Headers }
            return Invoke-MgGraphRequest @params
        }
        catch {
            $status = Get-HttpStatusFromError -ErrorRecord $_
            if ($attempt -le $MaxRetries -and ($status -eq 429 -or $status -eq 502 -or $status -eq 503 -or $status -eq 504)) {
                $delay = [Math]::Min(60, 5 * [Math]::Pow(2, $attempt - 1))
                Write-Verbose "Graph returned HTTP $status; retrying in $delay seconds (attempt $attempt of $MaxRetries)."
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

function Get-GraphPage {
    # Streams a Graph collection one page (an array of items) at a time, so large collections are processed
    # as they arrive instead of being held in memory first
    param(
        [Parameter(Mandatory)][string]$Uri,
        [string]$Activity
    )

    $count = 0
    while ($Uri) {
        $response = Invoke-GraphRequestWithRetry -Uri $Uri
        $items = @($response.value)
        $count += $items.Count
        # The comma keeps the page together as one pipeline object
        , $items
        $Uri = $response.'@odata.nextLink'
        if ($Activity -and $Uri) { Write-Progress -Activity $Activity -Status "$(Format-Count $count) retrieved" }
    }
    if ($Activity) { Write-Progress -Activity $Activity -Completed }
}

function Get-MgGraphAllPage {
    param([Parameter(Mandatory)][string]$Uri)

    $results = [System.Collections.Generic.List[object]]::new()
    Get-GraphPage -Uri $Uri | ForEach-Object { foreach ($item in $_) { if ($null -ne $item) { $results.Add($item) } } }
    return $results
}

function Get-RoleExcludedUserIds {
    # Active and PIM-eligible Entra directory roles can belong to a user or a role-assignable group.
    # A failed read must stop the users-only report, or an admin could enter its CSV and totals.
    param([object[]]$Users)

    $candidateIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($user in $Users) { [void]$candidateIds.Add([string]$user.id) }
    $excluded = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $groupIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $unresolvedIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $sources = @(
        @{ Uri = 'v1.0/roleManagement/directory/roleAssignments?$expand=principal'; Activity = 'Reading active Entra roles' },
        @{ Uri = 'v1.0/roleManagement/directory/roleEligibilityScheduleInstances?$expand=principal'; Activity = 'Reading eligible Entra roles' }
    )
    foreach ($source in $sources) {
        try {
            Get-GraphPage -Uri $source.Uri -Activity $source.Activity | ForEach-Object {
                foreach ($assignment in $_) {
                    if ($null -eq $assignment) { continue }
                    $principalId = [string]$assignment.principalId
                    $parsedId = [guid]::Empty
                    if (-not [guid]::TryParse($principalId, [ref]$parsedId)) { throw "Role assignment has an invalid principal ID: '$principalId'." }
                    if ($candidateIds.Contains($principalId)) { [void]$excluded.Add($principalId); continue }
                    $type = [string]$assignment.principal.'@odata.type'
                    if ($type -eq '#microsoft.graph.group') { [void]$groupIds.Add($principalId) }
                    elseif ($type -notin @('#microsoft.graph.user', '#microsoft.graph.servicePrincipal', '#microsoft.graph.device')) {
                        [void]$unresolvedIds.Add($principalId)
                    }
                }
            }
        }
        catch { throw "Admin role assignments couldn't be read ($($source.Activity): $(Get-ErrorSummary -ErrorRecord $_))." }
    }

    # Some assignments do not expand a principal (for example, deleted objects). Resolve unknown IDs as groups.
    foreach ($principalId in $unresolvedIds) {
        if ($groupIds.Contains($principalId)) { continue }
        try {
            $group = Invoke-GraphRequestWithRetry -Uri "v1.0/groups/$($principalId)?`$select=id"
            if ($group.id) { [void]$groupIds.Add($principalId) }
        }
        catch {
            if ((Get-HttpStatusFromError -ErrorRecord $_) -ne 404) {
                throw "Admin role principal $principalId couldn't be classified ($(Get-ErrorSummary -ErrorRecord $_))."
            }
        }
    }

    foreach ($groupId in $groupIds) {
        try {
            Get-GraphPage -Uri "v1.0/groups/$groupId/transitiveMembers?`$select=id&`$top=999" -Activity 'Reading admin role groups' | ForEach-Object {
                foreach ($member in $_) {
                    if ($null -ne $member -and $candidateIds.Contains([string]$member.id)) { [void]$excluded.Add([string]$member.id) }
                }
            }
        }
        catch { throw "Members of admin role group $groupId couldn't be read ($(Get-ErrorSummary -ErrorRecord $_))." }
    }

    return , $excluded
}

# Reads /authentication/methods for up to 20 users in one Graph JSON batch, retrying throttled requests and
# honouring Retry-After. It runs in this session or in a parallel runspace, so it only uses Graph SDK cmdlets.
$LiveBatchWorker = {
    param([string[]]$UserIds, [string]$BatchUri, [int]$MaxRetries = 6)

    if ($BatchUri -notmatch '(^|/)\$batch$') { throw "Unexpected batch URI '$BatchUri'." }
    $results = @{}
    $requests = @{}
    for ($i = 0; $i -lt $UserIds.Count; $i++) {
        $requests[[string]$i] = @{ id = [string]$i; method = 'GET'; url = "/users/$($UserIds[$i])/authentication/methods" }
    }
    $pending = @($requests.Values)
    $attempt = 0
    while ($pending.Count -gt 0) {
        $attempt++
        $body = ConvertTo-Json -InputObject @{ requests = $pending } -Depth 4 -Compress
        try {
            $response = Invoke-MgGraphRequest -Method POST -Uri $BatchUri -Body $body -ContentType 'application/json' -ErrorAction Stop
        }
        catch {
            $text = "$($_.Exception.Message) $($_.ErrorDetails.Message)"
            if ($attempt -le $MaxRetries -and $text -match '\b(429|500|502|503|504)\b|TooManyRequests|ServiceUnavailable|BadGateway|GatewayTimeout|timed out|Timeout') {
                Start-Sleep -Seconds ([int][Math]::Min(60, 5 * [Math]::Pow(2, $attempt - 1)))
                continue
            }
            foreach ($request in $pending) { $results[$UserIds[[int]$request.id]] = @{ Status = 0; Error = $text } }
            break
        }

        $retry = [System.Collections.Generic.List[object]]::new()
        $retryAfter = 0
        foreach ($item in @($response.responses)) {
            if ($null -eq $item) { continue }
            $index = [int]$item.id
            $status = [int]$item.status
            if (($status -eq 429 -or $status -ge 500) -and $attempt -le $MaxRetries) {
                $retry.Add($requests[[string]$item.id])
                $headerValue = $null
                if ($item.headers) {
                    $headerValue = $item.headers['Retry-After']
                    if (-not $headerValue) { $headerValue = $item.headers['retry-after'] }
                }
                $seconds = 0
                if ($headerValue -and [int]::TryParse([string]$headerValue, [ref]$seconds)) { $retryAfter = [Math]::Max($retryAfter, $seconds) }
                continue
            }
            if ($status -ne 200) {
                $results[$UserIds[$index]] = @{ Status = $status }
                continue
            }
            $methods = [System.Collections.Generic.List[object]]::new()
            foreach ($method in @($item.body.value)) { if ($null -ne $method) { $methods.Add($method) } }
            try {
                $nextLink = $item.body.'@odata.nextLink'
                while ($nextLink) {
                    $page = Invoke-MgGraphRequest -Method GET -Uri $nextLink -ErrorAction Stop
                    foreach ($method in @($page.value)) { if ($null -ne $method) { $methods.Add($method) } }
                    $nextLink = $page.'@odata.nextLink'
                }
                $results[$UserIds[$index]] = @{ Status = 200; Methods = $methods }
            }
            catch {
                $results[$UserIds[$index]] = @{ Status = 0; Error = $_.Exception.Message }
            }
        }
        $pending = $retry.ToArray()
        if ($pending.Count -gt 0) { Start-Sleep -Seconds ([int][Math]::Min(60, [Math]::Max($retryAfter, 2 * $attempt))) }
    }
    return $results
}

function Complete-LiveBatch {
    # Converts one batch's Graph responses into method entries and updates progress
    param($State, $BatchResults, [string[]]$BatchIds)

    foreach ($userId in $BatchIds) {
        $result = $null
        if ($BatchResults) { $result = $BatchResults[$userId] }
        if ($result -and $result.Status -eq 200) {
            $entries = [System.Collections.Generic.List[object]]::new()
            foreach ($method in $result.Methods) {
                $entry = Convert-LiveMethod -Method $method
                if ($entry) { $entries.Add($entry) }
            }
            $State.Entries[$userId] = $entries
        }
        else {
            $State.Failed++
            $status = if ($result) { $result.Status } else { 'no response' }
            Write-Verbose "Live methods unavailable for $userId (status $status)."
        }
    }
    $State.Done += $BatchIds.Count
    if ($State.ProgressTimer.ElapsedMilliseconds -ge 400 -or $State.Done -ge $State.Total) {
        $remaining = [int](($State.Timer.Elapsed.TotalSeconds / $State.Done) * ($State.Total - $State.Done))
        Write-Progress -Activity 'Reading authentication methods' -Status "$(Format-Count $State.Done) of $(Format-Count $State.Total) users" -PercentComplete ([int](100 * $State.Done / $State.Total)) -SecondsRemaining $remaining
        $State.ProgressTimer.Restart()
    }
}

function Invoke-LiveMethodScan {
    # Reads live methods in batches of 20 users, running up to $ThrottleLimit batches in parallel runspaces
    param([string[]]$UserIds, [int]$ThrottleLimit)

    $state = [pscustomobject]@{
        Entries       = @{}
        Failed        = 0
        Done          = 0
        Total         = $UserIds.Count
        Parallel      = $false
        Timer         = [System.Diagnostics.Stopwatch]::StartNew()
        ProgressTimer = [System.Diagnostics.Stopwatch]::StartNew()
    }
    $batches = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $UserIds.Count; $i += 20) {
        $batches.Add([string[]]@($UserIds[$i..([Math]::Min($i + 19, $UserIds.Count - 1))]))
    }
    $batchUri = "$GraphBase/`$batch"

    $pool = $null
    if ($ThrottleLimit -gt 1 -and $batches.Count -gt 1) {
        try {
            $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
            $graphModule = Get-Module -Name Microsoft.Graph.Authentication | Select-Object -First 1
            if ($graphModule) {
                # Load exactly the module version this session already uses
                $manifest = Join-Path -Path $graphModule.ModuleBase -ChildPath "$($graphModule.Name).psd1"
                if (-not (Test-Path -LiteralPath $manifest)) { $manifest = $graphModule.Name }
                $sessionState.ImportPSModule([string[]]@($manifest))
            }
            # Each runspace parses the worker once, rather than once per batch
            $sessionState.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Invoke-LiveBatch', $LiveBatchWorker.ToString()))
            $pool = [runspacefactory]::CreateRunspacePool(1, $ThrottleLimit, $sessionState, $Host)
            $pool.Open()
            # The runspaces have to share this session's Graph sign-in; if they don't, read sequentially instead
            $probe = [powershell]::Create()
            try {
                $probe.RunspacePool = $pool
                $shared = $probe.AddScript('[bool](Get-MgContext)').Invoke()
            }
            finally { $probe.Dispose() }
            if (-not ($shared.Count -gt 0 -and [bool]$shared[0])) { throw 'parallel runspaces could not use the Microsoft Graph sign-in' }
            $state.Parallel = $true
        }
        catch {
            Write-Verbose "Reading live methods sequentially: $($_.Exception.Message)"
            if ($pool) { $pool.Dispose() }
            $pool = $null
        }
    }

    try {
        if ($pool) {
            $queue = [System.Collections.Generic.Queue[object]]::new()
            $next = 0
            try {
                while ($next -lt $batches.Count -or $queue.Count -gt 0) {
                    while ($next -lt $batches.Count -and $queue.Count -lt (2 * $ThrottleLimit)) {
                        $worker = [powershell]::Create()
                        $worker.RunspacePool = $pool
                        [void]$worker.AddCommand('Invoke-LiveBatch').AddParameter('UserIds', $batches[$next]).AddParameter('BatchUri', $batchUri)
                        $queue.Enqueue([pscustomobject]@{ PowerShell = $worker; Handle = $worker.BeginInvoke(); Ids = $batches[$next] })
                        $next++
                    }
                    $job = $queue.Dequeue()
                    $batchResults = $null
                    try {
                        $output = $job.PowerShell.EndInvoke($job.Handle)
                        if ($output.Count -gt 0) { $batchResults = $output[0].psobject.BaseObject }
                    }
                    catch { Write-Verbose "A batch of live method reads failed: $($_.Exception.Message)" }
                    finally { $job.PowerShell.Dispose() }
                    Complete-LiveBatch -State $state -BatchResults $batchResults -BatchIds $job.Ids
                }
            }
            finally {
                foreach ($job in $queue) {
                    try { $job.PowerShell.Stop() } catch { Write-Verbose "Couldn't stop a batch: $($_.Exception.Message)" }
                    $job.PowerShell.Dispose()
                }
                $pool.Dispose()
            }
        }
        else {
            foreach ($batch in $batches) {
                $batchResults = $null
                try { $batchResults = & $LiveBatchWorker -UserIds $batch -BatchUri $batchUri }
                catch { Write-Verbose "A batch of live method reads failed: $($_.Exception.Message)" }
                Complete-LiveBatch -State $state -BatchResults $batchResults -BatchIds $batch
            }
        }
    }
    finally {
        Write-Progress -Activity 'Reading authentication methods' -Completed
    }
    return $state
}

function Get-GroupDisplayName {
    param([string]$GroupId)

    if (-not $script:GroupNameCache) { $script:GroupNameCache = @{} }
    if (-not $script:GroupNameCache.ContainsKey($GroupId)) {
        $name = $null
        try {
            $name = [string](Invoke-GraphRequestWithRetry -Uri "$GraphBase/groups/$($GroupId)?`$select=id,displayName").displayName
        }
        catch {
            Write-Verbose "Group $GroupId couldn't be resolved: $($_.Exception.Message)"
        }
        if (-not $name) { $name = "Group $GroupId" }
        $script:GroupNameCache[$GroupId] = $name
    }
    return $script:GroupNameCache[$GroupId]
}

function Get-GroupMemberSet {
    param([string]$GroupId)

    if (-not $script:GroupMemberCache) { $script:GroupMemberCache = @{} }
    if (-not $script:GroupMemberCache.ContainsKey($GroupId)) {
        $set = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        try {
            Get-GraphPage -Uri "$GraphBase/groups/$GroupId/transitiveMembers?`$select=id&`$top=999" | ForEach-Object {
                foreach ($member in $_) { if ($null -ne $member) { [void]$set.Add([string]$member.id) } }
            }
        }
        catch {
            Add-ReportWarning "Members of policy target group '$(Get-GroupDisplayName -GroupId $GroupId)' couldn't be read ($(Get-ErrorSummary -ErrorRecord $_)), so its users are treated as not targeted."
        }
        $script:GroupMemberCache[$GroupId] = $set
    }
    # The comma stops PowerShell unrolling the set into its members
    return , $script:GroupMemberCache[$GroupId]
}

function Get-PolicyScope {
    # Works out which in-scope users an authentication method policy is enabled for (and, for passkeys,
    # which passkey types their passkey profiles allow)
    param(
        $Config,
        [object[]]$Users,
        [switch]$PasskeyProfiles
    )

    $enabled = @{}
    if (-not $Config -or [string]$Config.state -ne 'enabled') { return $enabled }

    $profilesById = @{}
    foreach ($passkeyProfile in @($Config.passkeyProfiles | Where-Object { $_ })) { $profilesById[[string]$passkeyProfile.id] = $passkeyProfile }
    $includes = @($Config.includeTargets | Where-Object { $_ })
    $excludes = @($Config.excludeTargets | Where-Object { $_ })

    $memberSets = @{}
    foreach ($target in ($includes + $excludes)) {
        $groupId = [string]$target.id
        if ($groupId -and $groupId -ne 'all_users' -and -not $memberSets.ContainsKey($groupId)) {
            $memberSets[$groupId] = Get-GroupMemberSet -GroupId $groupId
        }
    }

    # Passkey types each include target allows, worked out once per target rather than once per user
    $targetTypes = @(foreach ($target in $includes) {
            $types = [System.Collections.Generic.List[string]]::new()
            if ($PasskeyProfiles) {
                $allowed = @($target.allowedPasskeyProfiles | Where-Object { $_ })
                if ($allowed.Count -gt 0 -and $profilesById.Count -gt 0) {
                    foreach ($profileId in $allowed) {
                        $passkeyProfile = $profilesById[[string]$profileId]
                        if (-not $passkeyProfile) { continue }
                        foreach ($type in ((@($passkeyProfile.passkeyTypes) -join ',') -split ',')) {
                            if ($type.Trim() -and -not $types.Contains($type.Trim())) { $types.Add($type.Trim()) }
                        }
                    }
                }
                else {
                    # Tenants not yet migrated to passkey profiles only allow device-bound passkeys
                    $types.Add('deviceBound')
                }
            }
            , $types.ToArray()
        })

    foreach ($user in $Users) {
        $userId = [string]$user.id
        $excluded = $false
        foreach ($target in $excludes) {
            if ([string]$target.id -eq 'all_users' -or $memberSets[[string]$target.id].Contains($userId)) { $excluded = $true; break }
        }
        if ($excluded) { continue }

        $matched = $null
        $combined = $null
        for ($i = 0; $i -lt $includes.Count; $i++) {
            $targetId = [string]$includes[$i].id
            if ($targetId -ne 'all_users' -and -not $memberSets[$targetId].Contains($userId)) { continue }
            if ($null -eq $matched) { $matched = $targetTypes[$i]; continue }
            # In more than one target: allow the union of their passkey types
            if ($null -eq $combined) { $combined = [System.Collections.Generic.HashSet[string]]::new([string[]]$matched, [StringComparer]::OrdinalIgnoreCase) }
            foreach ($type in $targetTypes[$i]) { [void]$combined.Add($type) }
        }
        if ($null -ne $combined) { $enabled[$userId] = @($combined) }
        elseif ($null -ne $matched) { $enabled[$userId] = $matched }
    }
    return $enabled
}

function Test-PhishingResistantStrength {
    param($Strength)

    if ([string]$Strength.id -eq $PhishingResistantStrengthId) { return $true }
    $combinations = @($Strength.allowedCombinations | Where-Object { $_ })
    if ($combinations.Count -eq 0) { return $false }
    foreach ($combination in $combinations) {
        foreach ($mode in ([string]$combination -split ',')) {
            if ($PhishingResistantModes -notcontains $mode.Trim()) { return $false }
        }
    }
    return $true
}

# ============================================================================
# HELPER FUNCTIONS - CLASSIFICATION
# ============================================================================

function ConvertTo-UtcDateTime {
    param($Value)

    if ($null -eq $Value) { return $null }
    $result = $null
    if ($Value -is [DateTime]) {
        $result = if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [DateTime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }
    }
    elseif ($Value -is [DateTimeOffset]) {
        $result = $Value.UtcDateTime
    }
    else {
        $text = [string]$Value
        if ([string]::IsNullOrWhiteSpace($text)) { return $null }
        $parsed = [DateTimeOffset]::MinValue
        if ([DateTimeOffset]::TryParse($text, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) {
            $result = $parsed.UtcDateTime
        }
    }
    # Graph uses 0001-01-01 as a "never" placeholder on some properties
    if ($result -and $result.Year -lt 2000) { return $null }
    return $result
}

function Get-LatestDate {
    param([object[]]$Values)

    $latest = $null
    foreach ($value in $Values) {
        $date = ConvertTo-UtcDateTime $value
        if ($date -and (-not $latest -or $date -gt $latest)) { $latest = $date }
    }
    return $latest
}

function Get-MethodDefinition {
    # Returns the catalogue entry for a method key, adding one for method types Graph introduces later
    param([string]$Key)

    $definition = $MethodCatalog[$Key]
    if ($definition) { return $definition }
    $raw = $Key -replace '^Other:', ''
    $definition = [pscustomobject]@{ Key = $Key; Name = "Other - $raw"; Short = $raw; Group = 'Other'; Rank = $GroupCatalog['Other'].Rank; Order = 999; IsPasskey = $false; CsvFields = $null }
    $definition.CsvFields = Get-MethodCsvFields -Definition $definition
    $MethodCatalog[$Key] = $definition
    return $definition
}

function Get-MethodCsvFields {
    # The Method, MethodCategory, PhishingResistant and MfaCapable columns of the detail CSV
    param($Definition)
    return '{0},{1},"{2}","{3}"' -f (Format-CsvField $Definition.Name), (Format-CsvField $GroupCatalog[$Definition.Group].Name), ($Definition.Rank -eq 1), ($Definition.Rank -le 4)
}

function New-MethodProfile {
    # Everything that depends only on which methods a user has registered, worked out once per distinct set
    param([string[]]$Keys)

    $definitions = @(@(foreach ($key in $Keys) { Get-MethodDefinition -Key $key }) | Sort-Object -Property Order, Key)
    $rank = 6
    foreach ($definition in $definitions) { if ($definition.Rank -lt $rank) { $rank = $definition.Rank } }
    $ladderKey = $LadderOrder[$rank - 1]
    $prShortNames = @($definitions | Where-Object { $_.Rank -eq 1 } | ForEach-Object { $_.Short }) -join ', '
    $shortNames = @($definitions | ForEach-Object { $_.Short }) -join ', '
    $names = @($definitions | ForEach-Object { $_.Name }) -join '; '
    $configs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($definition in $definitions) { foreach ($configId in $KeyToConfigIds[$definition.Key]) { [void]$configs.Add($configId) } }

    return [pscustomobject]@{
        Keys             = $Keys
        Groups           = @($definitions | ForEach-Object { $_.Group } | Select-Object -Unique)
        Configs          = @($configs)
        Rank             = $rank
        LadderKey        = $ladderKey
        PrShortNames     = $prShortNames
        ShortNames       = if ($shortNames) { $shortNames } else { 'None' }
        PasskeyTypeCount = @($definitions | Where-Object { $_.IsPasskey }).Count
        Users            = 0
        # StrongestMethod, PhishingResistant, PasswordlessCapable, MfaCapable and PhishingResistantMethods columns
        CsvStrength      = '{0},"{1}","{2}","{3}",{4}' -f (Format-CsvField $GroupCatalog[$ladderKey].Ladder), ($rank -eq 1), ($rank -le 2), ($rank -le 4), (Format-CsvField $prShortNames)
        # WindowsHelloForBusiness, PlatformSso and RegisteredMethods columns
        CsvMethods       = '"{0}","{1}",{2}' -f ($Keys -contains 'WindowsHelloForBusiness'), ($Keys -contains 'PlatformCredential'), (Format-CsvField $names)
    }
}

function Format-PreferredMethods {
    param($Values)

    $names = foreach ($value in @($Values)) {
        $text = [string]$value
        if (-not $text) { continue }
        if ($PreferredMethodNames.ContainsKey($text)) { $text = $PreferredMethodNames[$text] }
        if ($text) { $text }
    }
    return (@($names) -join '; ')
}

function Get-PasskeyClassification {
    # Storage (device-bound/synced) comes from Graph's passkeyType when present. The form factor comes from the
    # AAGUID catalogue, then from FIDO attestation or a known hardware vendor name, otherwise it's unidentified.
    param([Parameter(Mandatory)]$Method)

    $aaguid = ([string]$Method.aaGuid).Trim().ToLowerInvariant()
    $model = ([string]$Method.model).Trim()
    $attested = ([string]$Method.attestationLevel) -eq 'attested'
    $known = if ($aaguid) { $AaguidCatalog[$aaguid] } else { $null }

    if ($known) {
        $kind = $known.Kind; $formFactor = $known.FormFactor; $provider = $known.Name
    }
    elseif ($aaguid -and $aaguid -ne $ZeroAaguid -and ($attested -or $model -match $HardwareModelPattern)) {
        $kind = 'Hardware'; $formFactor = 'Hardware security key'
        $provider = if ($model) { $model } else { "Security key ($aaguid)" }
    }
    else {
        $kind = 'Unknown'; $formFactor = 'Unidentified'
        $provider = if ($model) { $model } elseif (-not $aaguid -or $aaguid -eq $ZeroAaguid) { 'Unidentified provider (no AAGUID)' } else { "Unidentified ($aaguid)" }
    }

    $storage = switch ([string]$Method.passkeyType) {
        'synced'      { 'Synced' }
        'deviceBound' { 'Device-bound' }
        default {
            if ($kind -eq 'Provider') { 'Synced' } elseif ($kind -eq 'Unknown') { 'Unknown' } else { 'Device-bound' }
        }
    }

    $methodKey = 'PasskeyOther'
    if ($storage -eq 'Synced') { $methodKey = 'PasskeySynced' }
    elseif ($kind -eq 'Hardware') { $methodKey = 'PasskeySecurityKey' }
    elseif ($kind -eq 'MicrosoftAuthenticator') { $methodKey = 'PasskeyAuthenticator' }
    elseif ($kind -eq 'WindowsHello') { $methodKey = 'PasskeyWindowsHello' }

    $hardwareOrSoftware = 'Software'
    if ($kind -eq 'Hardware') { $hardwareOrSoftware = 'Hardware' } elseif ($kind -eq 'Unknown') { $hardwareOrSoftware = 'Unknown' }

    $attestation = ''
    if ($attested) { $attestation = 'Attested' } elseif ($Method.attestationLevel) { $attestation = 'Not attested' }

    return [pscustomobject]@{
        MethodKey          = $methodKey
        Storage            = $storage
        Kind               = $kind
        FormFactor         = $formFactor
        HardwareOrSoftware = $hardwareOrSoftware
        Provider           = $provider
        Aaguid             = $aaguid
        Model              = $model
        Attestation        = $attestation
    }
}

function Convert-LiveMethod {
    param([Parameter(Mandatory)]$Method)

    $type = ([string]$Method['@odata.type']) -replace '^#?microsoft\.graph\.', ''
    $entry = [pscustomobject]@{
        MethodKey      = $null
        CredentialName = [string]$Method.displayName
        Detail         = ''
        Created        = ConvertTo-UtcDateTime $Method.createdDateTime
        LastUsed       = ConvertTo-UtcDateTime $Method.lastUsedDateTime
        Counts         = $true
        RawType        = $type
        Passkey        = $null
        Source         = 'Live'
    }

    switch ($type) {
        'passwordAuthenticationMethod' { return $null }
        'fido2AuthenticationMethod' {
            $passkey = Get-PasskeyClassification -Method $Method
            $entry.MethodKey = $passkey.MethodKey
            $entry.Passkey = $passkey
            $entry.Detail = "$($passkey.Storage); $($passkey.FormFactor)"
        }
        'windowsHelloForBusinessAuthenticationMethod' {
            $entry.MethodKey = 'WindowsHelloForBusiness'
            if ($Method.keyStrength) { $entry.Detail = "Key strength: $($Method.keyStrength)" }
        }
        'platformCredentialAuthenticationMethod' {
            $entry.MethodKey = 'PlatformCredential'
            $notes = @()
            if ($Method.platform) { $notes += "Platform: $($Method.platform)" }
            if ($Method.keyStrength) { $notes += "Key strength: $($Method.keyStrength)" }
            $entry.Detail = $notes -join '; '
        }
        'microsoftAuthenticatorAuthenticationMethod' {
            $entry.MethodKey = 'AuthenticatorPush'
            $notes = @()
            if ([string]$Method.clientAppName -eq 'outlookMobile') { $notes += 'App: Outlook mobile' }
            if ($Method.phoneAppVersion) { $notes += "App version: $($Method.phoneAppVersion)" }
            $entry.Detail = $notes -join '; '
        }
        'passwordlessMicrosoftAuthenticatorAuthenticationMethod' { $entry.MethodKey = 'AuthenticatorPhoneSignIn' }
        'softwareOathAuthenticationMethod' { $entry.MethodKey = 'SoftwareOath' }
        'hardwareOathAuthenticationMethod' { $entry.MethodKey = 'HardwareOath' }
        'phoneAuthenticationMethod' {
            $entry.MethodKey = switch ([string]$Method.phoneType) {
                'alternateMobile' { 'AlternateMobilePhone' }
                'office'          { 'OfficePhone' }
                default           { 'MobilePhone' }
            }
            $entry.CredentialName = ''
            if ([string]$Method.smsSignInState -eq 'ready') { $entry.Detail = 'SMS sign-in enabled' }
        }
        'emailAuthenticationMethod' {
            $entry.MethodKey = 'Email'
            $entry.CredentialName = ''
        }
        'temporaryAccessPassAuthenticationMethod' {
            # Expired or used passes linger until deleted, so only a usable pass counts as registered
            $entry.MethodKey = 'TemporaryAccessPass'
            $entry.Counts = ($Method.isUsable -eq $true)
            $entry.Detail = if ($entry.Counts) { 'Usable' } else { "Not usable ($($Method.methodUsabilityReason))" }
        }
        'externalAuthenticationMethod' { $entry.MethodKey = 'ExternalMfa' }
        'qrCodePinAuthenticationMethod' { $entry.MethodKey = 'QrCodePin' }
        'resourceAccountKeyAuthenticationMethod' { $entry.MethodKey = 'ResourceAccountKey' }
        default { $entry.MethodKey = "Other:$type" }
    }
    return $entry
}

function Get-RegistrationEntry {
    # Registration report values carry no per-user detail, so every user with the same value shares one entry
    param([string]$Value)

    $entry = $RegistrationEntryCache[$Value]
    if ($entry) { return $entry }
    $key = $RegistrationMethodMap[$Value]
    if (-not $key) { $key = "Other:$Value" }
    $entry = [pscustomobject]@{
        MethodKey      = $key
        CredentialName = ''
        Detail         = ''
        Created        = $null
        LastUsed       = $null
        Counts         = $true
        RawType        = $Value
        Passkey        = $null
        Source         = 'Registration report'
        # Active to GraphValue columns of the detail CSV
        CsvTail        = '"True",' + ('"",' * 10) + '"Registration report",' + (Format-CsvField $Value)
    }
    $RegistrationEntryCache[$Value] = $entry
    return $entry
}

function Format-PasskeyTypes {
    param([object[]]$Types)

    $names = @(foreach ($type in @($Types)) {
            switch ([string]$type) {
                'deviceBound' { 'device-bound' }
                'synced'      { 'synced' }
                default       { if ($type) { [string]$type } }
            }
        })
    if ($names.Count -eq 0) { return 'device-bound' }
    return (@($names | Sort-Object -Unique) -join ' and ')
}

# ============================================================================
# HELPER FUNCTIONS - POLICY DESCRIPTIONS
# ============================================================================

function Get-MethodConfigName {
    param($Config)

    if ([string]$Config['@odata.type'] -match 'externalAuthenticationMethodConfiguration') { return "External MFA - $($Config.displayName)" }
    switch ([string]$Config.id) {
        'Fido2'                  { return 'Passkey (FIDO2)' }
        'MicrosoftAuthenticator' { return 'Microsoft Authenticator' }
        'Sms'                    { return 'SMS' }
        'Voice'                  { return 'Voice call' }
        'Email'                  { return 'Email one-time passcode' }
        'TemporaryAccessPass'    { return 'Temporary Access Pass' }
        'SoftwareOath'           { return 'Third-party software OATH tokens' }
        'HardwareOath'           { return 'Hardware OATH tokens' }
        'X509Certificate'        { return 'Certificate-based authentication' }
        'QRCodePin'              { return 'QR code' }
    }
    return [string]$Config.id
}

function Get-TargetName {
    param([string]$TargetId)
    if ($TargetId -eq 'all_users') { return 'All users' }
    return (Get-GroupDisplayName -GroupId $TargetId)
}

function Get-PolicyTargetSummary {
    param($Config)

    $include = @(foreach ($target in @($Config.includeTargets | Where-Object { $_ })) { Get-TargetName -TargetId ([string]$target.id) })
    $exclude = @(foreach ($target in @($Config.excludeTargets | Where-Object { $_ })) { Get-TargetName -TargetId ([string]$target.id) })
    $text = if ($include.Count) { $include -join ', ' } else { 'No users targeted' }
    if ($exclude.Count) { $text += " (excluding $($exclude -join ', '))" }
    return $text
}

function Get-AaguidListText {
    param([object[]]$Aaguids)

    # Falls back to the model name Graph reported for a passkey with the same AAGUID in this tenant
    $names = @(foreach ($aaguid in @($Aaguids | Where-Object { $_ })) {
            $key = ([string]$aaguid).ToLowerInvariant()
            $known = $AaguidCatalog[$key]
            if ($known) { $known.Name } elseif ($ObservedAaguidNames[$key]) { $ObservedAaguidNames[$key] } else { [string]$aaguid }
        })
    $names = @($names | Select-Object -Unique)
    if ($names.Count -gt 4) { return (($names[0..3] -join ', ') + " and $($names.Count - 4) more") }
    return ($names -join ', ')
}

function Get-MethodConfigSettings {
    param($Config)

    $notes = [System.Collections.Generic.List[string]]::new()
    $targets = @($Config.includeTargets | Where-Object { $_ })
    switch ([string]$Config.id) {
        'Fido2' {
            $notes.Add("Self-service set-up $(if ($Config.isSelfServiceRegistrationAllowed) { 'on' } else { 'off' })")
            $profiles = @($Config.passkeyProfiles | Where-Object { $_ })
            if ($profiles.Count -gt 0) {
                $notes.Add("$($profiles.Count) passkey profile$(if ($profiles.Count -ne 1) { 's' }) (see below)")
            }
            else {
                $notes.Add("Attestation $(if ($Config.isAttestationEnforced) { 'enforced' } else { 'not enforced' })")
                $restrictions = $Config.keyRestrictions
                if ($restrictions -and $restrictions.isEnforced) {
                    $notes.Add("$(if ([string]$restrictions.enforcementType -eq 'allow') { 'Only allows' } else { 'Blocks' }): $(Get-AaguidListText -Aaguids $restrictions.aaGuids)")
                }
            }
        }
        'MicrosoftAuthenticator' {
            $modeNames = @{ any = 'push and phone sign-in'; push = 'push only'; deviceBasedPush = 'phone sign-in only' }
            $modes = @($targets | ForEach-Object { [string]$_.authenticationMode } | Where-Object { $_ } | Select-Object -Unique)
            if ($modes.Count) { $notes.Add('Mode: ' + (@($modes | ForEach-Object { if ($modeNames[$_]) { $modeNames[$_] } else { $_ } }) -join ', ')) }
            if ($Config.isSoftwareOathEnabled) { $notes.Add('Verification codes allowed') }
        }
        'Sms' {
            if (@($targets | Where-Object { $_.isUsableForSignIn }).Count) { $notes.Add('Usable for SMS sign-in') }
        }
        'Voice' {
            if ($Config.isOfficePhoneAllowed) { $notes.Add('Office phone allowed') }
        }
        'TemporaryAccessPass' {
            if ($Config.defaultLifetimeInMinutes) { $notes.Add("Default lifetime $($Config.defaultLifetimeInMinutes) minutes") }
            if ($Config.isUsableOnce) { $notes.Add('One-time use') }
        }
        'X509Certificate' {
            $mode = [string]$Config.authenticationModeConfiguration.x509CertificateAuthenticationDefaultMode
            if ($mode) { $notes.Add("Default strength: $(if ($mode -match 'Multi') { 'multifactor (phishing-resistant)' } else { 'single-factor' })") }
        }
    }
    return ($notes -join '; ')
}

function Get-CaAssignmentSummary {
    param($Users)

    $include = [System.Collections.Generic.List[string]]::new()
    $exclude = [System.Collections.Generic.List[string]]::new()
    $includeUsers = @($Users.includeUsers | Where-Object { $_ })
    if ($includeUsers -contains 'All') { $include.Add('All users') }
    elseif ($includeUsers -contains 'None') { $include.Add('No users') }
    else {
        if ($includeUsers -contains 'GuestsOrExternalUsers') { $include.Add('Guests and external users') }
        $count = @($includeUsers | Where-Object { $_ -ne 'GuestsOrExternalUsers' }).Count
        if ($count) { $include.Add("$count user$(if ($count -ne 1) { 's' })") }
    }
    if ($Users.includeGuestsOrExternalUsers) { $include.Add('Guests and external users') }
    foreach ($groupId in @($Users.includeGroups | Where-Object { $_ })) { $include.Add((Get-GroupDisplayName -GroupId $groupId)) }
    $count = @($Users.includeRoles | Where-Object { $_ }).Count
    if ($count) { $include.Add("$count directory role$(if ($count -ne 1) { 's' })") }

    $count = @($Users.excludeUsers | Where-Object { $_ -and $_ -ne 'GuestsOrExternalUsers' }).Count
    if ($count) { $exclude.Add("$count user$(if ($count -ne 1) { 's' })") }
    if ((@($Users.excludeUsers) -contains 'GuestsOrExternalUsers') -or $Users.excludeGuestsOrExternalUsers) { $exclude.Add('guests and external users') }
    foreach ($groupId in @($Users.excludeGroups | Where-Object { $_ })) { $exclude.Add((Get-GroupDisplayName -GroupId $groupId)) }
    $count = @($Users.excludeRoles | Where-Object { $_ }).Count
    if ($count) { $exclude.Add("$count directory role$(if ($count -ne 1) { 's' })") }

    $text = if ($include.Count) { @($include | Select-Object -Unique) -join ', ' } else { 'No users' }
    if ($exclude.Count) { $text += " (excluding $(@($exclude | Select-Object -Unique) -join ', '))" }
    return $text
}

function Get-CaResourceSummary {
    param($Applications)

    $parts = [System.Collections.Generic.List[string]]::new()
    $apps = @($Applications.includeApplications | Where-Object { $_ })
    if ($apps -contains 'All') { $parts.Add('All resources') }
    else {
        if ($apps -contains 'Office365') { $parts.Add('Office 365') }
        if ($apps -contains 'MicrosoftAdminPortals') { $parts.Add('Microsoft admin portals') }
        $count = @($apps | Where-Object { $_ -notin @('Office365', 'MicrosoftAdminPortals', 'None') }).Count
        if ($count) { $parts.Add("$count app$(if ($count -ne 1) { 's' })") }
    }
    foreach ($action in @($Applications.includeUserActions | Where-Object { $_ })) {
        switch ([string]$action) {
            'urn:user:registersecurityinfo' { $parts.Add('Register security information') }
            'urn:user:registerdevice'       { $parts.Add('Register or join devices') }
            default                         { $parts.Add([string]$action) }
        }
    }
    $count = @($Applications.includeAuthenticationContextClassReferences | Where-Object { $_ }).Count
    if ($count) { $parts.Add("$count authentication context$(if ($count -ne 1) { 's' })") }
    if ($parts.Count -eq 0) { return 'Not set' }
    return ($parts -join ', ')
}

# ============================================================================
# HELPER FUNCTIONS - OUTPUT FILES
# ============================================================================

function ConvertTo-FileName {
    # The report title as a folder or file name: characters Windows doesn't allow become spaces
    param([string]$Text)
    $invalid = [System.IO.Path]::GetInvalidFileNameChars()
    $chars = foreach ($char in $Text.ToCharArray()) { if ($invalid -contains $char) { ' ' } else { $char } }
    $name = ((-join $chars) -replace '\s+', ' ').Trim([char[]]' .')
    if ($name.Length -gt 60) { $name = $name.Substring(0, 60).Trim([char[]]' .') }
    if (-not $name) { $name = 'Sign-in security' }
    return $name
}

function New-RunFolder {
    # Every run gets its own folder; a second run in the same minute gets " (2)" added, as Windows does for copies
    param([string]$Parent, [string]$Name)
    $path = Join-Path -Path $Parent -ChildPath $Name
    $copy = 1
    while (Test-Path -LiteralPath $path) {
        $copy++
        $path = Join-Path -Path $Parent -ChildPath "$Name ($copy)"
    }
    return [System.IO.Directory]::CreateDirectory($path).FullName
}

function Format-CsvField {
    # Quotes a value for CSV. Spreadsheet apps run a cell that starts with =, +, - or @ as a formula, so a
    # leading apostrophe keeps those values as text.
    param([string]$Value)
    if ($Value.Length -gt 0 -and $CsvFormulaStart.IndexOf($Value[0]) -ge 0) { $Value = "'" + $Value }
    return '"' + $Value.Replace('"', '""') + '"'
}

function New-CsvWriter {
    # Rows are written as each user is analysed, so large tenants never hold every row in memory.
    # UTF-8 with a byte order mark, so Excel detects the encoding.
    param([string]$Path, [string[]]$Columns)
    $writer = [System.IO.StreamWriter]::new($Path, $false, [System.Text.UTF8Encoding]::new($true))
    $writer.WriteLine((@($Columns | ForEach-Object { '"' + $_ + '"' }) -join ','))
    return $writer
}

# ============================================================================
# HELPER FUNCTIONS - REPORT FORMATTING
# ============================================================================

$StatusIcons = @{ good = 'i-check'; warn = 'i-alert'; bad = 'i-cross'; info = 'i-info'; off = 'i-minus' }

function ConvertTo-HtmlText {
    # Encodes text for HTML; spaced hyphens in normalised names are set as en dashes
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode([string]$Value).Replace(' - ', ' &ndash; ')
}

function Format-Count {
    param($Value)
    if ($null -eq $Value) { return '0' }
    return ([double]$Value).ToString('N0', [Globalization.CultureInfo]::CurrentCulture)
}

function Format-Percent {
    param([double]$Part, [double]$Whole)
    if ($Whole -le 0) { return '0%' }
    $percent = 100 * $Part / $Whole
    if ($percent -gt 0 -and $percent -lt 1) { return '<1%' }
    if ($percent -gt 99 -and $percent -lt 100) { return '>99%' }
    return ('{0}%' -f [Math]::Round($percent, 0, [MidpointRounding]::AwayFromZero))
}

function Format-Number {
    # Culture-invariant numbers for CSS, SVG and JSON
    param([double]$Value, [string]$Format = '0.##')
    return $Value.ToString($Format, [Globalization.CultureInfo]::InvariantCulture)
}

# Report dates and times are shown in Irish time (Dublin) wherever the script runs: the Windows time zone ID first,
# then the IANA ID for PowerShell 7 on other platforms
$ReportTimeZone = [TimeZoneInfo]::Local
foreach ($zoneId in 'GMT Standard Time', 'Europe/Dublin') {
    try { $ReportTimeZone = [TimeZoneInfo]::FindSystemTimeZoneById($zoneId); break }
    catch { Write-Verbose "Time zone '$zoneId' isn't available." }
}

function ConvertTo-ReportTime {
    # Dates without a time zone are UTC, like every date read from Graph
    param([datetime]$Date)
    if ($Date.Kind -eq [DateTimeKind]::Unspecified) { $Date = [DateTime]::SpecifyKind($Date, [DateTimeKind]::Utc) }
    return [TimeZoneInfo]::ConvertTime($Date, $ReportTimeZone)
}

function Format-ReportDate {
    param($Date, [switch]$WithTime)
    if ($null -eq $Date) { return '' }
    $format = if ($WithTime) { 'd MMM yyyy, HH:mm' } else { 'd MMM yyyy' }
    return (ConvertTo-ReportTime $Date).ToString($format, [Globalization.CultureInfo]::InvariantCulture)
}

function Get-Plural {
    param([double]$Count, [string]$Singular, [string]$Plural)
    if ($Count -eq 1) { return $Singular }
    if ($Plural) { return $Plural }
    return "${Singular}s"
}

function Get-CspHash {
    param([string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return "'sha256-$([Convert]::ToBase64String($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text))))'" }
    finally { $sha.Dispose() }
}

function New-PanelStartHtml {
    # Opens one section of the single-page report; the tabs and card links jump to it by id
    param([string]$Id, [string]$Title)
    return "<section class='panel' id='$Id' aria-labelledby='h-$Id'><h2 class='panel-title' id='h-$Id' tabindex='-1'>$(ConvertTo-HtmlText $Title)</h2>"
}

function New-CardHeadHtml {
    param([string]$Title, [string]$Sub, [string]$Tab, [string]$LinkText)
    $subHtml = if ($Sub) { "<span class='sub'>$(ConvertTo-HtmlText $Sub)</span>" } else { '' }
    $linkHtml = if ($Tab) { "<a class='more' href='#$Tab'>$(ConvertTo-HtmlText $LinkText)<svg aria-hidden='true'><use href='#i-arrow'/></svg></a>" } else { '' }
    return "<div class='card-head'><div><h3>$(ConvertTo-HtmlText $Title)</h3>$subHtml</div>$linkHtml</div>"
}

function New-KpiHtml {
    param([string]$Label, [string]$Value, [string]$Note, [string]$Status)
    $icon = if ($Status) { "<svg aria-hidden='true'><use href='#$($StatusIcons[$Status])'/></svg>" } else { '' }
    $noteHtml = if ($Note) { "<div class='note'>$(ConvertTo-HtmlText $Note)</div>" } else { '' }
    return "<div class='kpi $Status'><div class='label'>$icon$(ConvertTo-HtmlText $Label)</div><div class='value'>$(ConvertTo-HtmlText $Value)</div>$noteHtml</div>"
}

function New-CalloutHtml {
    # $Html must already be encoded
    param([ValidateSet('good', 'warn', 'bad', 'info')][string]$Kind, [string]$Html)
    $icon = @{ good = 'i-check'; warn = 'i-alert'; bad = 'i-cross'; info = 'i-info' }[$Kind]
    return "<div class='callout $Kind'><svg aria-hidden='true'><use href='#$icon'/></svg><div>$Html</div></div>"
}

function New-StatusHtml {
    param([ValidateSet('good', 'warn', 'bad', 'off')][string]$Kind, [string]$Text)
    return "<span class='status $Kind'><svg aria-hidden='true'><use href='#$($StatusIcons[$Kind])'/></svg>$(ConvertTo-HtmlText $Text)</span>"
}

function New-CheckHtml {
    param([string]$Status, [string]$Title, [string]$Value, [string]$Tab)
    $statusText = @{ good = 'OK'; warn = 'Needs attention'; bad = 'Action needed'; info = 'For information'; off = 'Not available' }[$Status]
    return "<li class='$Status'><a href='#$Tab'><svg aria-hidden='true'><use href='#$($StatusIcons[$Status])'/></svg><span><span class='sr-only'>$($statusText): </span>$(ConvertTo-HtmlText $Title)</span><span class='val'>$(ConvertTo-HtmlText $Value)</span></a></li>"
}

function New-ChipHtml {
    param([string]$Text, [string]$Css)
    return "<span class='chip'><i class='sw t-$Css'></i>$(ConvertTo-HtmlText $Text)</span>"
}

function New-BarHtml {
    param([double]$Value, [double]$Max, [string]$Css, [string]$TipLabel, [string]$TipValue)
    # Bars sit beside the same numbers, so they're hidden from screen readers
    $width = if ($Max -gt 0) { [Math]::Max(0.6, 100 * $Value / $Max) } else { 0 }
    return "<div class='bar' aria-hidden='true'><i class='t-$Css' style='width:$(Format-Number $width)%' data-tip='$(ConvertTo-HtmlText $TipLabel)' data-tip-value='$(ConvertTo-HtmlText $TipValue)'></i></div>"
}

function New-MeterHtml {
    param([double]$Part, [double]$Whole, [string]$Label, [switch]$Small)
    $width = if ($Whole -gt 0) { 100 * $Part / $Whole } else { 0 }
    $class = if ($Small) { 'meter sm' } else { 'meter' }
    return "<div class='$class' role='img' aria-label='$(ConvertTo-HtmlText "$Label $(Format-Percent $Part $Whole)")'><span style='width:$(Format-Number $width)%'></span></div>"
}

function New-LadderRowHtml {
    param([string]$Label, [hashtable]$Counts, [int]$Total)

    $segments = foreach ($tier in $LadderOrder) {
        $count = [int]$Counts[$tier]
        if ($count -le 0) { continue }
        $group = $GroupCatalog[$tier]
        $share = Format-Percent $count $Total
        $inner = if ((100.0 * $count / $Total) -ge 10) { "<span>$(ConvertTo-HtmlText $share)</span>" } else { '' }
        $tip = '{0} {1} ({2})' -f (Format-Count $count), (Get-Plural $count 'user'), $share
        "<div class='seg t-$($group.Css)' style='flex-grow:$count' tabindex='0' data-tip='$(ConvertTo-HtmlText $group.Ladder)' data-tip-value='$(ConvertTo-HtmlText $tip)'>$inner</div>"
    }
    return "<div class='ladder-row'><div class='ladder-label'>$(ConvertTo-HtmlText $Label)<span>$(Format-Count $Total) $(Get-Plural $Total 'user')</span></div><div class='stack' role='img' aria-label='$(ConvertTo-HtmlText "$Label by strongest registered method")'>$($segments -join '')</div></div>"
}

function New-LadderLegendHtml {
    param([hashtable]$Counts, [int]$Total)

    $items = foreach ($tier in $LadderOrder) {
        $count = [int]$Counts[$tier]
        if ($count -le 0) { continue }
        $group = $GroupCatalog[$tier]
        "<li><i class='sw t-$($group.Css)'></i><span class='name'>$(ConvertTo-HtmlText $group.Ladder)</span><span class='val'>$(Format-Count $count)</span><span class='pct'>$(ConvertTo-HtmlText (Format-Percent $count $Total))</span></li>"
    }
    return "<ul class='legend'>$($items -join '')</ul>"
}

function New-StorageSegmentsHtml {
    # Device-bound, synced and unknown-type passkeys as segments of one bar
    param([int]$DeviceBound, [int]$Synced, [int]$Unknown, [string]$Label)

    $total = $DeviceBound + $Synced + $Unknown
    $parts = @(@('db', 'Device-bound', $DeviceBound), @('sync', 'Synced', $Synced), @('unk', 'Type unknown', $Unknown))
    $segments = foreach ($part in $parts) {
        if ($part[2] -le 0) { continue }
        $tipLabel = if ($Label) { "$Label - $($part[1])" } else { $part[1] }
        $tipValue = '{0} {1} ({2})' -f (Format-Count $part[2]), (Get-Plural $part[2] 'passkey'), (Format-Percent $part[2] $total)
        "<i class='t-$($part[0])' style='flex-grow:$($part[2])' data-tip='$(ConvertTo-HtmlText $tipLabel)' data-tip-value='$(ConvertTo-HtmlText $tipValue)'></i>"
    }
    return ($segments -join '')
}

function New-StorageLegendHtml {
    param([int]$DeviceBound, [int]$Synced, [int]$Unknown, [switch]$Counts)

    $total = $DeviceBound + $Synced + $Unknown
    $parts = @(@('db', 'Device-bound', $DeviceBound), @('sync', 'Synced', $Synced), @('unk', 'Unknown', $Unknown))
    $items = foreach ($part in $parts) {
        if ($part[2] -le 0 -and ($part[0] -eq 'unk' -or $Counts)) { continue }
        $value = ''
        if ($Counts) {
            $value = " <b>$(Format-Count $part[2])</b>"
            # A share is noise for the (usually tiny) unknown group
            if ($part[0] -ne 'unk') { $value += " $(ConvertTo-HtmlText (Format-Percent $part[2] $total))" }
        }
        "<span><i class='sw t-$($part[0])'></i>$($part[1])$value</span>"
    }
    return "<div class='split-legend'>$($items -join '')</div>"
}

function New-BarListHtml {
    # Compact labelled bars for the overview. Rows need Name, Value and Css; values show as counts or percentages.
    param([object[]]$Rows, [int]$Total, [switch]$Percent)

    $max = 0
    foreach ($row in $Rows) { if ($row.Value -gt $max) { $max = $row.Value } }
    $items = foreach ($row in $Rows) {
        $width = if ($max -gt 0) { [Math]::Max(1.5, 100 * $row.Value / $max) } else { 0 }
        $valueText = if ($Percent) { Format-Percent $row.Value $Total } else { Format-Count $row.Value }
        $tip = '{0} {1} ({2})' -f (Format-Count $row.Value), (Get-Plural $row.Value 'user'), (Format-Percent $row.Value $Total)
        "<li><span class='name' title='$(ConvertTo-HtmlText $row.Name)'>$(ConvertTo-HtmlText $row.Name)</span><span class='bar' aria-hidden='true'><i class='t-$($row.Css)' style='width:$(Format-Number $width)%' data-tip='$(ConvertTo-HtmlText $row.Name)' data-tip-value='$(ConvertTo-HtmlText $tip)'></i></span><span class='val'>$(ConvertTo-HtmlText $valueText)</span></li>"
    }
    return "<ul class='bar-list'>$($items -join '')</ul>"
}

function New-FormFactorListHtml {
    # Passkeys by what holds them, each bar split by storage type; long tails fold into "Other"
    param([object[]]$Rows, [int]$Max = 5)

    $sorted = @($Rows | Sort-Object -Property @{ Expression = 'Total'; Descending = $true }, Name)
    if ($sorted.Count -gt $Max) {
        $rest = @($sorted[($Max - 1)..($sorted.Count - 1)])
        $other = [pscustomobject]@{ Name = "Other ($($rest.Count) types)"; DeviceBound = 0; Synced = 0; Unknown = 0; Total = 0 }
        foreach ($row in $rest) { $other.DeviceBound += $row.DeviceBound; $other.Synced += $row.Synced; $other.Unknown += $row.Unknown; $other.Total += $row.Total }
        $sorted = @($sorted[0..($Max - 2)]) + $other
    }
    $maxTotal = 0
    foreach ($row in $sorted) { if ($row.Total -gt $maxTotal) { $maxTotal = $row.Total } }
    $items = foreach ($row in $sorted) {
        $width = if ($maxTotal -gt 0) { [Math]::Max(1.5, 100 * $row.Total / $maxTotal) } else { 0 }
        "<li><span class='name' title='$(ConvertTo-HtmlText $row.Name)'>$(ConvertTo-HtmlText $row.Name)</span><span class='bar' aria-hidden='true'><span class='split sm' style='width:$(Format-Number $width)%'>$(New-StorageSegmentsHtml -DeviceBound $row.DeviceBound -Synced $row.Synced -Unknown $row.Unknown -Label $row.Name)</span></span><span class='val'>$(Format-Count $row.Total)</span></li>"
    }
    return "<ul class='bar-list'>$($items -join '')</ul>"
}

function New-MethodBarTableHtml {
    param([object[]]$Rows, [int]$Total, [string]$Css)

    $max = ($Rows | Measure-Object -Property Users -Maximum).Maximum
    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add("<div class='x-scroll'><table class='bars'><thead><tr><th>Method</th><th class='bar-col' aria-hidden='true'></th><th class='num'>Users</th><th class='num'>Share</th></tr></thead><tbody>")
    foreach ($row in $Rows) {
        $share = Format-Percent $row.Users $Total
        $rowCss = if ($Css) { $Css } else { $GroupCatalog[$row.Group].Css }
        $tip = '{0} {1} ({2})' -f (Format-Count $row.Users), (Get-Plural $row.Users 'user'), $share
        $out.Add("<tr><td>$(ConvertTo-HtmlText $row.Name)</td><td class='bar-col'>$(New-BarHtml -Value $row.Users -Max $max -Css $rowCss -TipLabel $row.Name -TipValue $tip)</td><td class='num'>$(Format-Count $row.Users)</td><td class='num'>$(ConvertTo-HtmlText $share)</td></tr>")
    }
    $out.Add('</tbody></table></div>')
    return ($out -join '')
}

function Get-AxisScale {
    param([double]$Max, [int]$Ticks = 4)
    if ($Max -le 0) { $Max = 1 }
    $raw = $Max / $Ticks
    $base = [Math]::Pow(10, [Math]::Floor([Math]::Log10($raw)))
    $fraction = $raw / $base
    $nice = if ($fraction -le 1) { 1 } elseif ($fraction -le 2) { 2 } elseif ($fraction -le 5) { 5 } else { 10 }
    $step = [Math]::Max(1, $nice * $base)
    return @{ Step = $step; Max = $step * [Math]::Ceiling($Max / $step) }
}

function New-TrendChartHtml {
    # Area chart of cumulative phishing-resistant users. -Compact drops the data table and thins the axis labels.
    param([object[]]$Series, [int]$Width = 560, [int]$Height = 240, [switch]$Compact)

    $left = 44; $right = 22; $top = 20; $bottom = 28
    $plotWidth = $Width - $left - $right
    $plotHeight = $Height - $top - $bottom
    $count = $Series.Count
    $maxValue = 0
    foreach ($item in $Series) { if ($item.Cumulative -gt $maxValue) { $maxValue = $item.Cumulative } }
    $scale = Get-AxisScale -Max $maxValue -Ticks $(if ($Compact) { 3 } else { 4 })
    $inv = [Globalization.CultureInfo]::InvariantCulture

    $points = @(for ($i = 0; $i -lt $count; $i++) {
            $x = $left + $(if ($count -gt 1) { $plotWidth * $i / ($count - 1) } else { $plotWidth / 2 })
            $y = $top + $plotHeight - ($plotHeight * $Series[$i].Cumulative / $scale.Max)
            [pscustomobject]@{ X = $x; Y = $y; Item = $Series[$i] }
        })

    $svg = [System.Collections.Generic.List[string]]::new()
    $hoverData = @(foreach ($point in $points) {
            [pscustomobject]@{
                x = [Math]::Round($point.X, 1)
                y = [Math]::Round($point.Y, 1)
                c = Format-Count $point.Item.Cumulative
                m = $point.Item.Month.ToString('MMMM yyyy', $inv)
                n = Format-Count $point.Item.New
            }
        })
    $json = ConvertTo-Json -InputObject $hoverData -Compress
    $first = $Series[0]; $last = $Series[$count - 1]
    $aria = "Users with a phishing-resistant method grew from $(Format-Count $first.Cumulative) in $($first.Month.ToString('MMMM yyyy', $inv)) to $(Format-Count $last.Cumulative) in $($last.Month.ToString('MMMM yyyy', $inv))"
    $svg.Add("<svg class='trend' viewBox='0 0 $Width $Height' role='img' aria-label='$(ConvertTo-HtmlText $aria)' data-points='$(ConvertTo-HtmlText $json)'>")

    for ($value = 0; $value -le $scale.Max; $value += $scale.Step) {
        $gy = Format-Number ($top + $plotHeight - ($plotHeight * $value / $scale.Max)) '0.#'
        $class = if ($value -eq 0) { 'axis' } else { 'grid' }
        $svg.Add("<line class='$class' x1='$left' x2='$($Width - $right)' y1='$gy' y2='$gy'/>")
        $svg.Add("<text class='tick' x='$($left - 8)' y='$gy' dy='4' text-anchor='end'>$(Format-Count $value)</text>")
    }

    $every = [Math]::Max(1, [Math]::Ceiling($count / $(if ($Compact) { 4 } else { 6 })))
    for ($i = 0; $i -lt $count; $i++) {
        if ((($count - 1 - $i) % $every) -ne 0) { continue }
        $svg.Add("<text class='tick' x='$(Format-Number $points[$i].X '0.#')' y='$($Height - 8)' text-anchor='middle'>$($points[$i].Item.Month.ToString('MMM yy', $inv))</text>")
    }

    $path = [System.Text.StringBuilder]::new()
    for ($i = 0; $i -lt $count; $i++) {
        [void]$path.Append($(if ($i -eq 0) { 'M' } else { ' L' })).Append((Format-Number $points[$i].X '0.#')).Append(',').Append((Format-Number $points[$i].Y '0.#'))
    }
    $baseline = Format-Number ($top + $plotHeight) '0.#'
    $area = "$($path.ToString()) L$(Format-Number $points[$count - 1].X '0.#'),$baseline L$(Format-Number $points[0].X '0.#'),$baseline Z"
    $svg.Add("<path class='area' d='$area'/>")
    $svg.Add("<path class='line' d='$($path.ToString())'/>")

    $end = $points[$count - 1]
    $svg.Add("<circle class='end' cx='$(Format-Number $end.X '0.#')' cy='$(Format-Number $end.Y '0.#')' r='4'/>")
    $svg.Add("<text class='end-label' x='$(Format-Number $end.X '0.#')' y='$(Format-Number ($end.Y - 12) '0.#')' text-anchor='end'>$(Format-Count $end.Item.Cumulative)</text>")
    $svg.Add("<line class='cross' x1='0' x2='0' y1='$top' y2='$($top + $plotHeight)'/>")
    $svg.Add("<circle class='hover-dot' cx='0' cy='0' r='5'/>")
    $svg.Add("<rect class='hit' x='$left' y='$top' width='$plotWidth' height='$plotHeight'/>")
    $svg.Add('</svg>')

    if (-not $Compact) {
        $rows = @(for ($i = $count - 1; $i -ge 0; $i--) {
                "<tr><td>$($Series[$i].Month.ToString('MMMM yyyy', $inv))</td><td class='num'>$(Format-Count $Series[$i].New)</td><td class='num'>$(Format-Count $Series[$i].Cumulative)</td></tr>"
            })
        $svg.Add("<details class='data-view'><summary>View data</summary><div class='table-wrap short'><table><thead><tr><th>Month</th><th class='num'>First registered</th><th class='num'>Cumulative</th></tr></thead><tbody>$($rows -join '')</tbody></table></div></details>")
    }
    return ($svg -join '')
}

# ============================================================================
# REPORT TEMPLATE
# ============================================================================

$ReportCssLight = '--page:#f8f9fd;--surface:#fff;--surface-2:#f1f5fa;--ink:#142238;--ink-2:#4b5d73;--muted:#66788d;--grid:#dce5ef;--baseline:#aebfd0;--border:rgba(36,71,108,.13);--accent:#0078d4;--link:#005a9e;--track:#dceef4;--meter:#65b69d;--trend:#4b9c86;--t-pr:#72bea4;--t-pwl:#81add4;--t-app:#91c4dc;--t-phone:#d9b587;--t-rec:#d7a398;--t-none:#d3a1b4;--t-other:#8794a2;--on-pr:#142238;--on-pwl:#142238;--on-app:#142238;--on-phone:#142238;--on-rec:#142238;--on-none:#142238;--pk-db:#a18bc8;--pk-sync:#7bbcaf;--pk-unk:#8794a2;--good:#187a37;--warn:#945400;--bad:#a61935;--good-mark:#4d9b75;--warn-mark:#b7894f;--bad-mark:#bd7182;--good-bg:rgba(114,190,164,.12);--warn-bg:rgba(217,181,135,.14);--bad-bg:rgba(211,161,180,.14);--info-bg:rgba(0,170,255,.09);--shadow:0 2px 9px rgba(22,53,83,.05);'

$ReportCss = @'
*,*::before,*::after{box-sizing:border-box}
:root{color-scheme:light;/*LIGHT*/}
:root{--gap:16px;--nav-h:42px}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--page);color:var(--ink);font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;-webkit-font-smoothing:antialiased}
a{color:var(--link)}
.wrap{max-width:1440px;margin:0 auto;padding:0 24px}
.sr-only,#h-overview{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.topbar{background:var(--surface);border-top:3px solid var(--accent);border-bottom:1px solid var(--border)}
.topbar .wrap{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:12px;padding-bottom:12px}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.brand-mark{width:40px;height:40px;flex:none;color:#fff;background:linear-gradient(135deg,#005ab8,#00aaff);border-radius:11px;padding:8px;box-shadow:0 3px 10px rgba(0,105,190,.2)}
h1{font-size:19px;line-height:1.25;font-weight:700;letter-spacing:-.015em;margin:0}
.meta{display:flex;flex-wrap:wrap;gap:0 14px;color:var(--ink-2);font-size:12.5px;margin-top:1px}
.meta b{color:var(--ink);font-weight:600}
.actions{display:flex;gap:8px;flex:none}
.btn{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--border);background:var(--surface);color:var(--ink-2);border-radius:8px;padding:6px 10px;font:inherit;font-size:13px;cursor:pointer}
.btn:hover{color:var(--ink);background:var(--surface-2)}
.btn svg{width:16px;height:16px}
.btn:focus-visible,.more:focus-visible,.checks a:focus-visible,.seg:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.tabs{position:sticky;top:0;z-index:20;background:var(--surface);border-bottom:1px solid var(--border)}
.tabs .wrap{display:flex;gap:2px;overflow-x:auto;scrollbar-width:none}
.tabs .wrap::-webkit-scrollbar{display:none}
.tab{display:block;border-bottom:2px solid transparent;font-size:13.5px;line-height:20px;font-weight:550;color:var(--ink-2);text-decoration:none;padding:10px 12px 9px;white-space:nowrap}
.tab:hover{color:var(--ink)}
.tab[aria-current="true"]{color:var(--ink);border-bottom-color:var(--accent)}
.tab:focus-visible{outline:2px solid var(--accent);outline-offset:-4px;border-radius:6px}
main.wrap{padding-top:var(--gap);padding-bottom:40px}
.panel{scroll-margin-top:calc(var(--nav-h) + var(--gap))}
.panel + .panel{margin-top:44px}
.panel-title{font-size:19px;line-height:1.25;font-weight:650;margin:0 0 12px}
.panel-title:focus{outline:none}
.vstack > * + *{margin-top:var(--gap)}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:16px 18px;box-shadow:var(--shadow);min-width:0}
.card-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin:0 0 12px}
.card-head h3{font-size:14.5px;line-height:1.3;font-weight:620;margin:0}
.card-head .sub{display:block;color:var(--ink-2);font-size:12.5px;margin-top:2px}
.more{display:inline-flex;align-items:center;gap:1px;font-size:12.5px;font-weight:550;color:var(--link);text-decoration:none;white-space:nowrap;border-radius:4px;margin-top:1px}
.more:hover{text-decoration:underline}
.more svg{width:14px;height:14px}
.grid{display:grid;gap:var(--gap)}
.grid-2{grid-template-columns:repeat(2,minmax(0,1fr))}
.overview{display:grid;grid-template-columns:repeat(12,minmax(0,1fr));gap:var(--gap)}
.ov-top{grid-column:1/-1;display:grid;grid-template-columns:minmax(0,1.7fr) repeat(4,minmax(0,1fr));gap:inherit}
.ov-wide{grid-column:1/-1}.ov-third{grid-column:span 4}
.hero{display:flex;flex-direction:column;justify-content:space-between;gap:8px;background:linear-gradient(135deg,#f1faf7 0%,var(--surface) 76%);border-top:3px solid var(--t-pr)}
.hero-head{display:flex;align-items:center;justify-content:space-between;gap:4px 10px;flex-wrap:wrap}
.hero-label{font-size:12.5px;font-weight:600;color:var(--ink-2)}
.hero-row{display:flex;align-items:flex-end;gap:16px}
.hero-figure{font-size:46px;line-height:.95;font-weight:700;letter-spacing:-.03em}
.hero-side{flex:1;min-width:0;padding-bottom:2px}
.hero-count{font-size:13px;color:var(--ink-2);margin-top:6px}
.hero-count b{color:var(--ink);font-weight:650}
.delta{display:inline-flex;align-items:center;gap:4px;font-size:12.5px;font-weight:600;color:var(--good)}
.delta svg{width:14px;height:14px;flex:none}
.delta.flat{color:var(--ink-2);font-weight:500}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}
.kpi{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:14px 16px;box-shadow:var(--shadow);min-width:0}
.card .kpi{background:var(--page);box-shadow:none;border-radius:10px}
.kpi .label{display:flex;align-items:center;gap:6px;font-size:12.5px;font-weight:550;color:var(--ink-2)}
.kpi .label svg{width:15px;height:15px;flex:none}
.kpi.good .label svg{color:var(--good-mark)}.kpi.warn .label svg{color:var(--warn-mark)}.kpi.bad .label svg{color:var(--bad-mark)}
.kpi .value{font-size:26px;line-height:1.15;font-weight:650;letter-spacing:-.015em;margin-top:6px;white-space:nowrap}
.kpi .note{font-size:12.5px;color:var(--ink-2);margin-top:2px}
.meter{height:10px;background:var(--track);border-radius:5px;overflow:hidden}
.meter span{display:block;height:100%;background:var(--meter);border-radius:0 4px 4px 0}
.meter.sm{height:8px;min-width:90px;flex:1}
.meter-cell{display:flex;align-items:center;gap:10px}
.meter-cell b{font-weight:600;min-width:3.2em;text-align:right;font-variant-numeric:tabular-nums}
.ladder-row{display:grid;grid-template-columns:96px minmax(0,1fr);gap:12px;align-items:center;margin:0 0 10px}
.ladder-label{font-weight:600;font-size:12.5px;line-height:1.3}
.ladder-label span{display:block;font-weight:400;color:var(--ink-2);font-size:11.5px}
.stack{display:flex;gap:2px;height:28px;border-radius:4px;overflow:hidden}
.seg{flex:1 1 0;min-width:4px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:600;cursor:default;white-space:nowrap;overflow:hidden}
.seg:hover,.bar i:hover,.split i:hover{filter:brightness(1.04) saturate(1.02)}
.legend{list-style:none;margin:14px 0 0;padding:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:6px 22px;font-size:12.5px}
.legend li{display:flex;align-items:center;gap:8px;min-width:0}
.legend .name{flex:1;min-width:0;color:var(--ink-2)}
.legend .val{font-weight:600;font-variant-numeric:tabular-nums}
.legend .pct{color:var(--ink-2);font-variant-numeric:tabular-nums;min-width:2.9em;text-align:right}
@media (min-width:1101px) and (max-width:1359px){.legend{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (min-width:1360px){.legend{grid-template-columns:repeat(3,max-content);justify-content:space-between}.legend .name{white-space:nowrap}}
.t-pr{background:var(--t-pr)}.seg.t-pr{color:var(--on-pr)}
.t-pwl{background:var(--t-pwl)}.seg.t-pwl{color:var(--on-pwl)}
.t-app{background:var(--t-app)}.seg.t-app{color:var(--on-app)}
.t-phone{background:var(--t-phone)}.seg.t-phone{color:var(--on-phone)}
.t-rec{background:var(--t-rec)}.seg.t-rec{color:var(--on-rec)}
.t-none{background:var(--t-none)}.seg.t-none{color:var(--on-none)}
.t-other{background:var(--t-other)}
.t-db{background:var(--pk-db)}.t-sync{background:var(--pk-sync)}.t-unk{background:var(--pk-unk)}
.sw{display:inline-block;width:10px;height:10px;border-radius:3px;flex:none;vertical-align:-1px;margin-right:8px}
.legend .sw,.split-legend .sw{margin-right:0}
.split{display:flex;gap:2px;height:12px;border-radius:4px;overflow:hidden}
.split i{flex:1 1 0;min-width:3px;cursor:default}
.split.sm{height:10px}
.split-legend{display:flex;flex-wrap:wrap;gap:4px 14px;margin:8px 0 0;font-size:12.5px;color:var(--ink-2)}
.split-legend span{display:inline-flex;align-items:center;gap:6px}
.split-legend b{color:var(--ink);font-weight:600;font-variant-numeric:tabular-nums}
.pk-summary{margin:0 0 14px}
.bar-list{list-style:none;margin:0;padding:0;display:grid;gap:7px}
.bar-list li{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr) 4.2em;align-items:center;gap:10px;font-size:12.5px;min-height:20px}
.bar-list .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.bar-list .val{text-align:right;font-weight:600;font-variant-numeric:tabular-nums;white-space:nowrap}
.bar-list .bar{min-width:0;display:flex}
.bar-list .bar > i{display:block}
.checks{list-style:none;margin:0;padding:0}
.checks li + li{border-top:1px solid var(--grid)}
.checks a{display:grid;grid-template-columns:18px minmax(0,1fr) auto;align-items:center;gap:10px;padding:7px 6px;margin:0 -6px;border-radius:6px;color:inherit;text-decoration:none;font-size:13px}
.checks a:hover{background:var(--surface-2)}
.checks svg{width:18px;height:18px}
.checks .good svg{color:var(--good-mark)}.checks .warn svg{color:var(--warn-mark)}.checks .bad svg{color:var(--bad-mark)}.checks .info svg{color:var(--accent)}.checks .off svg{color:var(--muted)}
.checks .val{font-weight:600;font-variant-numeric:tabular-nums;white-space:nowrap;text-align:right}
.callout{display:flex;gap:10px;align-items:flex-start;border-radius:10px;padding:12px 14px;font-size:13px;border:1px solid var(--border);background:var(--info-bg)}
.callout svg{width:18px;height:18px;flex:none;margin-top:1px;color:var(--accent)}
.callout.good{background:var(--good-bg)}.callout.good svg{color:var(--good-mark)}
.callout.warn{background:var(--warn-bg)}.callout.warn svg{color:var(--warn-mark)}
.callout.bad{background:var(--bad-bg)}.callout.bad svg{color:var(--bad-mark)}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--grid);vertical-align:middle}
thead th{font-size:12px;font-weight:600;color:var(--ink-2);white-space:nowrap}
tbody tr:last-child td,tbody tr:last-child th{border-bottom:0}
.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.nowrap{white-space:nowrap}
.x-scroll{overflow-x:auto}
.table-wrap{overflow:auto;border:1px solid var(--border);border-radius:10px;background:var(--surface)}
.table-wrap.scroll{max-height:560px}
.table-wrap.short{max-height:320px}
.sub-line{display:block;margin-top:2px}
.table-wrap thead th{position:sticky;top:0;background:var(--surface-2);z-index:1}
.table-wrap tbody tr:hover{background:var(--surface-2)}
.group-row th{background:var(--surface-2);font-size:12px;font-weight:600;color:var(--ink);padding-top:9px;padding-bottom:9px}
.group-row th span{font-weight:400;color:var(--ink-2)}
table.bars td{padding-top:7px;padding-bottom:7px}
.bar-col{width:38%}
.bar-col.narrow{width:18%}
.bar{height:10px;min-width:60px}
.bar i{display:block;height:100%;border-radius:0 4px 4px 0;cursor:default}
.chip{display:inline-flex;align-items:center;padding:2px 9px 2px 8px;border:1px solid var(--border);border-radius:999px;font-size:12px;white-space:nowrap;background:var(--surface)}
.chip .sw{width:8px;height:8px;border-radius:50%;margin-right:6px}
.status{display:inline-flex;align-items:center;gap:5px;font-weight:600;font-size:12.5px;white-space:nowrap}
.status svg{width:14px;height:14px}
.status.good{color:var(--good)}.status.warn{color:var(--warn)}.status.bad{color:var(--bad)}.status.off{color:var(--ink-2)}
.muted{color:var(--ink-2)}
.mono{font-family:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;font-size:11.5px;color:var(--ink-2)}
.empty{color:var(--ink-2);margin:6px 0 0}
.toolbar{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap;margin:0 0 12px}
.toolbar .count{color:var(--ink-2);font-size:13px}
.search{border:1px solid var(--border);background:var(--surface);color:var(--ink);border-radius:8px;padding:7px 11px;font:inherit;font-size:13px;min-width:280px}
.search:focus{outline:2px solid var(--accent);outline-offset:1px}
th button.sort{all:unset;cursor:pointer;display:inline-flex;align-items:center;gap:4px}
th button.sort::after{content:"";width:0;height:0;border:4px solid transparent;border-top-color:var(--muted);margin-top:4px;opacity:.5}
th[aria-sort="ascending"] button.sort::after{border-top-color:transparent;border-bottom-color:var(--ink-2);margin-top:-4px;opacity:1}
th[aria-sort="descending"] button.sort::after{border-top-color:var(--ink-2);opacity:1}
th button.sort:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:3px}
details.data-view{margin-top:10px;font-size:13px}
details.data-view summary{cursor:pointer;color:var(--link)}
details.data-view .table-wrap{margin-top:8px}
svg.trend{width:100%;height:auto;display:block;overflow:visible}
svg.trend .grid{stroke:var(--grid);stroke-width:1}
svg.trend .axis{stroke:var(--baseline);stroke-width:1}
svg.trend .tick{fill:var(--muted);font-size:11.5px}
svg.trend .line{fill:none;stroke:var(--trend);stroke-width:2;stroke-linejoin:round;stroke-linecap:round}
svg.trend .area{fill:var(--t-pr);opacity:.1}
svg.trend .end{fill:var(--trend);stroke:var(--surface);stroke-width:2}
svg.trend .end-label{fill:var(--ink);font-size:12px;font-weight:600}
svg.trend .cross{stroke:var(--baseline);stroke-width:1;opacity:0}
svg.trend .hover-dot{fill:var(--trend);stroke:var(--surface);stroke-width:2;opacity:0}
svg.trend .hit{fill:transparent;cursor:crosshair}
dl.defs{display:grid;grid-template-columns:minmax(160px,220px) minmax(0,1fr);gap:10px 24px;margin:0}
dl.defs dt{font-weight:600}
dl.defs dd{margin:0;color:var(--ink-2)}
.foot{color:var(--ink-2);font-size:12px;margin:16px 0 0}
#tip{position:fixed;z-index:50;pointer-events:none;background:var(--ink);color:var(--surface);padding:8px 11px;border-radius:8px;font-size:12px;line-height:1.35;box-shadow:0 8px 24px rgba(0,0,0,.2);opacity:0;transform:translateY(3px);transition:opacity .12s,transform .12s;max-width:280px;left:0;top:0}
#tip.show{opacity:1;transform:none}
#tip strong{display:block;font-size:14px;font-weight:650}
#tip span{opacity:.8}
@media (min-width:1101px) and (max-height:800px){
:root{--gap:12px;--nav-h:38px}
.topbar .wrap{padding-top:8px;padding-bottom:8px}
.tab{padding-top:8px;padding-bottom:7px}
.overview .card,.overview .kpi{padding:12px 16px}
.card-head{margin-bottom:10px}
.hero-figure{font-size:42px}
.kpi .value{font-size:24px;margin-top:4px}
.ladder-row{margin-bottom:8px}
.stack{height:26px}
.legend{margin-top:10px;gap:4px 22px}
.split-legend,.kpi .label{font-size:12px}
.bar-list{gap:5px}
.checks a{padding-top:5px;padding-bottom:5px}
}
@media (min-width:1101px) and (max-height:700px){
.topbar .wrap{padding-top:6px;padding-bottom:6px}
.overview .card-head .sub{display:none}
.overview .card,.overview .kpi{padding:10px 14px}
.hero-figure{font-size:38px}
.kpi .value{font-size:22px}
.legend{margin-top:8px}
.checks a{padding-top:4px;padding-bottom:4px}
}
@media (max-width:1100px){
.overview{grid-template-columns:repeat(6,minmax(0,1fr))}
.ov-top{grid-template-columns:repeat(2,minmax(0,1fr))}
.ov-top .hero{grid-column:1/-1}
.ov-wide{grid-column:span 6}
.ov-third{grid-column:span 3}
.ov-third:last-child{grid-column:span 6}
}
@media (max-width:860px){.grid-2{grid-template-columns:minmax(0,1fr)}dl.defs{grid-template-columns:minmax(0,1fr)}dl.defs dd{margin-bottom:8px}.bar-col{width:30%}}
@media (max-width:640px){
.wrap{padding:0 16px}
.topbar .wrap{flex-wrap:wrap}
.overview{grid-template-columns:minmax(0,1fr)}
.overview > *{grid-column:auto!important}
.hero-figure{font-size:40px}
.ladder-row{grid-template-columns:minmax(0,1fr);gap:6px}
.search{min-width:0;width:100%}
.card{padding:14px}
}
@page{margin:12mm}
@page overview{size:landscape}
@media print{
:root{--page:#fff;--surface:#fff}
body{font-size:12px}
.tabs,.actions,.search,.data-view,.more,#tip{display:none!important}
.panel{break-before:page;margin:0!important}
.panel:first-of-type{break-before:auto}
.topbar,#overview{page:overview}
.overview{zoom:.85;grid-template-columns:repeat(12,minmax(0,1fr))}
.ov-top{grid-template-columns:minmax(0,1.7fr) repeat(4,minmax(0,1fr))}
.ov-top .hero{grid-column:auto}
.ov-wide{grid-column:1/-1}.ov-third,.ov-third:last-child{grid-column:span 4}
.legend{grid-template-columns:repeat(2,minmax(0,1fr))}
.card,.kpi,.ladder-row,.checks li,tr{break-inside:avoid}
.card,.kpi{box-shadow:none}
.topbar{border-bottom:0}
.table-wrap,.table-wrap.scroll,.table-wrap.short,.x-scroll{max-height:none;overflow:visible}
.table-wrap thead th{position:static}
}
'@
$ReportCss = $ReportCss.Replace('/*LIGHT*/', $ReportCssLight).Replace("`r`n", "`n")

$ReportIcons = @'
<svg xmlns="http://www.w3.org/2000/svg" style="display:none">
<symbol id="i-credential" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2.5 4.5 5.5v5.7c0 4.6 3 8.5 7.5 10.3 4.5-1.8 7.5-5.7 7.5-10.3V5.5L12 2.5Z"/><circle cx="12" cy="10.5" r="2.1"/><path d="M12 12.6V16"/></symbol>
<symbol id="i-check" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m8 12.5 2.8 2.8L16.5 9.5"/></symbol>
<symbol id="i-alert" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.5 2.5 20h19L12 3.5z"/><path d="M12 10v4.5"/><path d="M12 17.5h.01"/></symbol>
<symbol id="i-cross" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/></symbol>
<symbol id="i-minus" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><circle cx="12" cy="12" r="9"/><path d="M8 12h8"/></symbol>
<symbol id="i-info" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 11v5.5"/><path d="M12 7.5h.01"/></symbol>
<symbol id="i-print" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M7 9V3.5h10V9"/><rect x="3" y="9" width="18" height="8" rx="2"/><path d="M7 14h10v6.5H7z"/></symbol>
<symbol id="i-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m9.5 6 6 6-6 6"/></symbol>
<symbol id="i-up" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5.5 11.5 12 5l6.5 6.5"/></symbol>
</svg>
'@
$ReportIcons = $ReportIcons.Replace("`r`n", "`n")

$ReportFaviconSvg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="8" fill="#0078d4"/><path d="M16 5 7 8.5v6.6c0 5.4 3.6 9.9 9 12 5.4-2.1 9-6.6 9-12V8.5L16 5Z" fill="none" stroke="#fff" stroke-width="2.2" stroke-linejoin="round"/><circle cx="16" cy="15" r="2.4" fill="none" stroke="#fff" stroke-width="2.2"/><path d="M16 17.4V21" fill="none" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/></svg>'
$ReportFavicon = '<link rel="icon" href="data:image/svg+xml,' + [uri]::EscapeDataString($ReportFaviconSvg) + '">'

$ReportScript = @'
(function(){
var root=document.documentElement,tip=document.getElementById('tip');
function hideTip(){if(tip){tip.classList.remove('show');}}
var nav=document.querySelector('.tabs'),strip=nav?nav.querySelector('.wrap'):null;
var links=nav?Array.prototype.slice.call(nav.querySelectorAll('a.tab')):[];
var panels=links.map(function(a){return document.getElementById(a.getAttribute('href').slice(1));});
var current=0,held=false,holdTimer=0,queued=false;
var smooth=!(window.matchMedia&&window.matchMedia('(prefers-reduced-motion: reduce)').matches);
function mark(i){
if(i===current||!links[i]){return;}
current=i;
links.forEach(function(a,j){if(j===i){a.setAttribute('aria-current','true');}else{a.removeAttribute('aria-current');}});
var r=links[i].getBoundingClientRect(),s=strip.getBoundingClientRect();
if(r.left<s.left){strip.scrollLeft-=s.left-r.left+16;}else if(r.right>s.right){strip.scrollLeft+=r.right-s.right+16;}
}
function spy(){
queued=false;
if(held||!panels.length){return;}
var top=nav.getBoundingClientRect().bottom,line=top+(window.innerHeight-top)/4,i=0;
panels.forEach(function(p,j){if(p&&p.getBoundingClientRect().top<=line){i=j;}});
if(window.innerHeight+window.pageYOffset>=root.scrollHeight-2){i=panels.length-1;}
mark(i);
}
function queue(){if(!queued){queued=true;requestAnimationFrame(spy);}}
function hold(){
clearTimeout(holdTimer);
holdTimer=setTimeout(function(){
held=false;
var p=panels[current],r=p?p.getBoundingClientRect():null;
if(r&&(r.bottom<nav.getBoundingClientRect().bottom||r.top>window.innerHeight)){queue();}
},150);
}
function jump(i){
var panel=panels[i],heading=panel.querySelector('.panel-title'),behavior=smooth?'smooth':'auto';
mark(i);held=true;hold();hideTip();
if(i===0){window.scrollTo({top:0,behavior:behavior});}else{panel.scrollIntoView({behavior:behavior,block:'start'});}
if(heading){heading.focus({preventScroll:true});}
}
Array.prototype.forEach.call(document.querySelectorAll('a[href^="#"]'),function(a){
var target=document.getElementById(a.getAttribute('href').slice(1)),i=target?panels.indexOf(target):-1;
if(i<0){return;}
a.addEventListener('click',function(e){if(e.ctrlKey||e.metaKey||e.shiftKey||e.altKey){return;}e.preventDefault();jump(i);});
});
window.addEventListener('scroll',function(){hideTip();if(held){hold();}else{queue();}},{passive:true});
window.addEventListener('resize',queue);
queue();
var printButton=document.getElementById('printReport');
if(printButton){printButton.addEventListener('click',function(){window.print();});}
function fillTip(value,label){tip.textContent='';var s=document.createElement('strong');s.textContent=value;tip.appendChild(s);if(label){var l=document.createElement('span');l.textContent=label;tip.appendChild(l);}}
function placeTip(x,y){var r=tip.getBoundingClientRect();var left=Math.max(8,Math.min(x+14,window.innerWidth-r.width-8));var top=y-r.height-12;if(top<8){top=y+18;}tip.style.left=left+'px';tip.style.top=top+'px';}
Array.prototype.forEach.call(document.querySelectorAll('[data-tip]'),function(el){
el.addEventListener('pointerenter',function(e){fillTip(el.getAttribute('data-tip-value'),el.getAttribute('data-tip'));tip.classList.add('show');placeTip(e.clientX,e.clientY);});
el.addEventListener('pointermove',function(e){placeTip(e.clientX,e.clientY);});
el.addEventListener('pointerleave',hideTip);
el.addEventListener('focus',function(){var r=el.getBoundingClientRect();fillTip(el.getAttribute('data-tip-value'),el.getAttribute('data-tip'));tip.classList.add('show');placeTip(r.left+r.width/2,r.top);});
el.addEventListener('blur',hideTip);
});
Array.prototype.forEach.call(document.querySelectorAll('svg.trend'),function(svg){
var points=JSON.parse(svg.getAttribute('data-points')||'[]');if(!points.length){return;}
var cross=svg.querySelector('.cross'),dot=svg.querySelector('.hover-dot'),hit=svg.querySelector('.hit');
hit.addEventListener('pointermove',function(e){
var pt=svg.createSVGPoint();pt.x=e.clientX;pt.y=e.clientY;var loc=pt.matrixTransform(svg.getScreenCTM().inverse());
var best=0,distance=Infinity;for(var i=0;i<points.length;i++){var d=Math.abs(points[i].x-loc.x);if(d<distance){distance=d;best=i;}}
var p=points[best];cross.setAttribute('x1',p.x);cross.setAttribute('x2',p.x);cross.style.opacity=1;dot.setAttribute('cx',p.x);dot.setAttribute('cy',p.y);dot.style.opacity=1;
fillTip(p.c+' users',p.m+' \u00b7 '+p.n+' first registered');tip.classList.add('show');placeTip(e.clientX,e.clientY);
});
hit.addEventListener('pointerleave',function(){cross.style.opacity=0;dot.style.opacity=0;hideTip();});
});
Array.prototype.forEach.call(document.querySelectorAll('input[data-filter]'),function(input){
var id=input.getAttribute('data-filter'),table=document.getElementById(id),counter=document.getElementById(id+'-count');
if(!table){return;}var rows=Array.prototype.slice.call(table.tBodies[0].rows);
input.addEventListener('input',function(){var q=input.value.trim().toLowerCase(),shown=0;
rows.forEach(function(r){var hit=!q||r.textContent.toLowerCase().indexOf(q)>-1;r.hidden=!hit;if(hit){shown++;}});
if(counter){counter.textContent=shown.toLocaleString();}});
});
Array.prototype.forEach.call(document.querySelectorAll('table.sortable'),function(table){
var heads=table.tHead.rows[0].cells;
Array.prototype.forEach.call(heads,function(th,index){
if(!th.hasAttribute('data-sort')){return;}
var button=document.createElement('button');button.type='button';button.className='sort';
while(th.firstChild){button.appendChild(th.firstChild);}th.appendChild(button);
button.addEventListener('click',function(){
var numeric=th.getAttribute('data-sort')==='num',dir=th.getAttribute('aria-sort')==='ascending'?-1:1;
Array.prototype.forEach.call(heads,function(h){h.removeAttribute('aria-sort');});
th.setAttribute('aria-sort',dir===1?'ascending':'descending');
var body=table.tBodies[0],rows=Array.prototype.slice.call(body.rows);
rows.sort(function(a,b){
var ca=a.cells[index],cb=b.cells[index];
var va=ca?(ca.getAttribute('data-v')||ca.textContent.trim()):'',vb=cb?(cb.getAttribute('data-v')||cb.textContent.trim()):'';
if(numeric){return((parseFloat(va)||0)-(parseFloat(vb)||0))*dir;}
return va.localeCompare(vb,undefined,{numeric:true,sensitivity:'base'})*dir;});
rows.forEach(function(r){body.appendChild(r);});
});
});
});
})();
'@
$ReportScript = $ReportScript.Replace("`r`n", "`n")

function New-ReportHtml {
    param([hashtable]$Model)

    $inv = [Globalization.CultureInfo]::InvariantCulture
    $total = $Model.TotalUsers
    $ladder = $Model.LadderCounts
    $prCount = [int]$ladder['PhishingResistant']
    $mfaCount = $prCount + [int]$ladder['Passwordless'] + [int]$ladder['AppMfa'] + [int]$ladder['PhoneMfa']
    $passwordlessCount = $prCount + [int]$ladder['Passwordless']
    $noMfaCount = [int]$ladder['RecoveryOnly'] + [int]$ladder['None']
    $phoneOnlyCount = [int]$ladder['PhoneMfa']
    $pk = $Model.PasskeyStats
    $methodStats = @($Model.MethodStats)
    $trend = @($Model.Trend)
    $formFactors = @($Model.PasskeyFormFactors)
    $providers = @($Model.PasskeyProviders)
    $departments = @($Model.Departments)
    $caRows = @($Model.CaRows)
    $showUsers = [bool]$Model.ShowUsers
    $usersOnly = [bool]$Model.UsersOnly
    $userTab = if ($showUsers) { 'users' } else { 'phishing-resistant' }

    $panels = [ordered]@{}
    $panels['overview'] = 'Overview'
    $panels['phishing-resistant'] = 'Phishing-resistant'
    $panels['passkeys'] = 'Passkeys'
    $panels['methods'] = 'All methods'
    $panels['policy'] = 'Policy'
    if ($showUsers) { $panels['users'] = 'Users' }
    $panels['about'] = 'About'

    $html = [System.Collections.Generic.List[string]]::new()

    # ----- Document head -----
    # The Content Security Policy only lets this report's own script run and blocks every network request
    $csp = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src $(Get-CspHash -Text $ReportScript); base-uri 'none'; form-action 'none'"
    $html.Add('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">')
    $html.Add("<meta http-equiv=""Content-Security-Policy"" content=""$csp"">")
    $html.Add('<meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light">')
    $html.Add($ReportFavicon)
    $html.Add("<title>$(ConvertTo-HtmlText "$($Model.TenantName) - $($Model.ReportTitle)")</title>")
    $html.Add("<style>$ReportCss</style></head><body>")
    $html.Add($ReportIcons)

    # ----- Top bar and section tabs -----
    $metaParts = [System.Collections.Generic.List[string]]::new()
    $metaParts.Add("<b>$(ConvertTo-HtmlText $Model.TenantName)</b>")
    if ($Model.TenantDomain) { $metaParts.Add((ConvertTo-HtmlText $Model.TenantDomain)) }
    $html.Add("<header class='topbar'><div class='wrap'><div class='brand'><svg class='brand-mark' aria-hidden='true'><use href='#i-credential'/></svg><div><h1>$(ConvertTo-HtmlText $Model.ReportTitle)</h1><div class='meta'>$(@($metaParts | ForEach-Object { "<span>$_</span>" }) -join '')</div></div></div>")
    $html.Add("<div class='actions'><button type='button' class='btn' id='printReport'><svg aria-hidden='true'><use href='#i-print'/></svg>Print</button></div></div></header>")
    # Every section is on one page; the tabs stay at the top and jump to them
    $html.Add("<nav class='tabs' aria-label='Report sections'><div class='wrap'>")
    foreach ($panelId in $panels.Keys) {
        $currentAttr = if ($panelId -eq 'overview') { " aria-current='true'" } else { '' }
        $html.Add("<a class='tab' href='#$panelId'$currentAttr>$($panels[$panelId])</a>")
    }
    $html.Add("</div></nav><main class='wrap'>")

    # ----- Overview: fits on one screen -----
    $html.Add("$(New-PanelStartHtml -Id 'overview' -Title 'Overview')<div class='overview'>")
    $deltaHtml = if ($null -eq $Model.NewPr30) { '' }
    elseif ($Model.NewPr30 -gt 0) { "<span class='delta'><svg aria-hidden='true'><use href='#i-up'/></svg>$(Format-Count $Model.NewPr30) new in 30 days</span>" }
    else { "<span class='delta flat'>None new in 30 days</span>" }
    $html.Add("<div class='ov-top'><div class='card hero'><div class='hero-head'><span class='hero-label'>Phishing-resistant users</span>$deltaHtml</div><div class='hero-row'><div class='hero-figure'>$(ConvertTo-HtmlText (Format-Percent $prCount $total))</div><div class='hero-side'>$(New-MeterHtml -Part $prCount -Whole $total -Label 'Phishing-resistant users')<div class='hero-count'><b>$(Format-Count $prCount)</b> of $(Format-Count $total) $(Get-Plural $total 'user')</div></div></div></div>")
    $html.Add((New-KpiHtml -Label 'MFA capable' -Value (Format-Percent $mfaCount $total) -Note "$(Format-Count $mfaCount) $(Get-Plural $mfaCount 'user')"))
    $html.Add((New-KpiHtml -Label 'Passkeys' -Value (Format-Count $pk.Total) -Note "Held by $(Format-Count $Model.PasskeyUserCount) $(Get-Plural $Model.PasskeyUserCount 'user')"))
    $html.Add((New-KpiHtml -Status $(if ($noMfaCount -gt 0) { 'bad' } else { 'good' }) -Label 'No MFA method' -Value (Format-Count $noMfaCount) -Note "$(Format-Percent $noMfaCount $total) of users"))
    if (-not $usersOnly -and $Model.AdminTotal -gt 0) {
        $adminGap = $Model.AdminTotal - $Model.AdminPrCount
        $adminNote = if ($adminGap -gt 0) { "$(Format-Count $adminGap) still to do" } else { 'All admins covered' }
        $html.Add((New-KpiHtml -Status $(if ($adminGap -gt 0) { 'bad' } else { 'good' }) -Label 'Admins phishing-resistant' -Value "$(Format-Count $Model.AdminPrCount) of $(Format-Count $Model.AdminTotal)" -Note $adminNote))
    }
    else {
        $html.Add((New-KpiHtml -Label 'Passwordless capable' -Value (Format-Percent $passwordlessCount $total) -Note "$(Format-Count $passwordlessCount) $(Get-Plural $passwordlessCount 'user')"))
    }
    $html.Add('</div>')

    $html.Add("<div class='card ov-wide'>$(New-CardHeadHtml -Title 'Strongest sign-in method' -Sub 'Each user is counted once, under the strongest method they have registered.' -Tab 'methods' -LinkText 'All methods')")
    $html.Add((New-LadderRowHtml -Label 'All users' -Counts $ladder -Total $total))
    if (-not $usersOnly -and $Model.AdminTotal -gt 0) { $html.Add((New-LadderRowHtml -Label 'Admins' -Counts $Model.AdminLadderCounts -Total $Model.AdminTotal)) }
    $html.Add((New-LadderLegendHtml -Counts $ladder -Total $total))
    $html.Add('</div>')

    $html.Add("<div class='card ov-third'>$(New-CardHeadHtml -Title 'Passkeys by type' -Tab 'passkeys' -LinkText 'Details')")
    if ($pk.Total -eq 0) { $html.Add("<p class='empty'>No passkeys are registered yet.</p>") }
    else {
        $html.Add("<div class='pk-summary'><div class='split' role='img' aria-label='$(ConvertTo-HtmlText "Passkeys: $($pk.DeviceBound) device-bound, $($pk.Synced) synced, $($pk.UnknownStorage) of unknown type")'>$(New-StorageSegmentsHtml -DeviceBound $pk.DeviceBound -Synced $pk.Synced -Unknown $pk.UnknownStorage)</div>$(New-StorageLegendHtml -DeviceBound $pk.DeviceBound -Synced $pk.Synced -Unknown $pk.UnknownStorage -Counts)</div>")
        $html.Add((New-FormFactorListHtml -Rows $formFactors -Max 5))
    }
    $html.Add('</div>')

    $html.Add("<div class='card ov-third'>$(New-CardHeadHtml -Title 'Methods in use' -Sub 'Share of users with each method registered' -Tab 'methods' -LinkText 'All methods')")
    if ($methodStats.Count -eq 0) { $html.Add("<p class='empty'>No authentication methods are registered.</p>") }
    else {
        $topMethods = @($methodStats | Sort-Object -Property @{ Expression = 'Users'; Descending = $true }, Order | Select-Object -First 6 | ForEach-Object {
                [pscustomobject]@{ Name = $_.Short; Value = $_.Users; Css = $GroupCatalog[$_.Group].Css }
            })
        $html.Add((New-BarListHtml -Rows $topMethods -Total $total -Percent))
    }
    $html.Add('</div>')

    $checks = [System.Collections.Generic.List[string]]::new()
    if (-not $Model.PolicyAvailable) {
        $checks.Add((New-CheckHtml -Status 'off' -Title 'Passkey policy' -Value "Couldn't be read" -Tab 'policy'))
    }
    elseif (-not $Model.Fido2Enabled) {
        $checks.Add((New-CheckHtml -Status 'bad' -Title 'Passkey policy' -Value 'Turned off' -Tab 'policy'))
    }
    else {
        $enabled = $Model.PasskeyEnabledCount
        $status = if ($enabled -ge $total) { 'good' } elseif ($enabled -gt 0) { 'warn' } else { 'bad' }
        $value = if ($enabled -ge $total) { 'All users' }
        elseif ($enabled -ge 0.95 * $total) { "All but $(Format-Count ($total - $enabled)) $(Get-Plural ($total - $enabled) 'user')" }
        else { "$(Format-Percent $enabled $total) of users" }
        $checks.Add((New-CheckHtml -Status $status -Title 'Passkey policy' -Value $value -Tab 'policy'))
        if ($Model.SyncedAllowedCount -gt 0) {
            $checks.Add((New-CheckHtml -Status 'info' -Title 'Synced passkeys allowed' -Value "$(Format-Count $Model.SyncedAllowedCount) $(Get-Plural $Model.SyncedAllowedCount 'user')" -Tab 'policy'))
        }
        else {
            $checks.Add((New-CheckHtml -Status 'good' -Title 'Passkeys allowed' -Value 'Device-bound only' -Tab 'policy'))
        }
        $notRegistered = $enabled - $Model.PasskeyEnabledRegistered
        $checks.Add((New-CheckHtml -Status $(if ($notRegistered -gt 0) { 'warn' } else { 'good' }) -Title 'Enabled, no passkey yet' -Value "$(Format-Count $notRegistered) $(Get-Plural $notRegistered 'user')" -Tab $userTab))
    }
    if (-not $usersOnly) {
        if (-not $Model.CaAvailable) {
            $checks.Add((New-CheckHtml -Status 'off' -Title 'Conditional Access' -Value "Couldn't be read" -Tab 'policy'))
        }
        else {
            $caOn = @($caRows | Where-Object { $_.State -eq 'enabled' }).Count
            $caReportOnly = @($caRows | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' }).Count
            if ($caOn -gt 0) {
                $value = if ($caReportOnly -gt 0) { "$caOn on, $caReportOnly report-only" } else { "$caOn $(Get-Plural $caOn 'policy' 'policies') on" }
                $checks.Add((New-CheckHtml -Status 'good' -Title 'Conditional Access' -Value $value -Tab 'policy'))
            }
            elseif ($caReportOnly -gt 0) { $checks.Add((New-CheckHtml -Status 'warn' -Title 'Conditional Access' -Value 'Report-only' -Tab 'policy')) }
            else { $checks.Add((New-CheckHtml -Status 'bad' -Title 'Conditional Access' -Value 'Not enforced' -Tab 'policy')) }
        }
    }
    $checks.Add((New-CheckHtml -Status $(if ($phoneOnlyCount -gt 0) { 'warn' } else { 'good' }) -Title 'SMS or voice as strongest method' -Value "$(Format-Count $phoneOnlyCount) $(Get-Plural $phoneOnlyCount 'user')" -Tab $userTab))
    $html.Add("<div class='card ov-third'>$(New-CardHeadHtml -Title 'Readiness checks' -Tab 'policy' -LinkText 'Policy')<ul class='checks'>$($checks -join '')</ul></div>")
    $html.Add('</div></section>')

    # ----- Phishing-resistant -----
    $prMethods = @($methodStats | Where-Object { $_.Group -eq 'PhishingResistant' })
    $html.Add("$(New-PanelStartHtml -Id 'phishing-resistant' -Title 'Phishing-resistant')<div class='vstack'>")
    $html.Add("<div class='grid grid-2'><div class='card'>$(New-CardHeadHtml -Title 'Phishing-resistant methods' -Sub 'Users registered for each method. One user can hold several.')")
    if ($prMethods.Count) { $html.Add((New-MethodBarTableHtml -Rows $prMethods -Total $total -Css 'pr')) }
    else { $html.Add("<p class='empty'>No phishing-resistant methods are registered yet.</p>") }
    $html.Add("</div><div class='card'>$(New-CardHeadHtml -Title 'Adoption over time' -Sub 'Users with a phishing-resistant method, by month first registered')")
    if ($trend.Count -ge 2) {
        $html.Add((New-TrendChartHtml -Series $trend))
        if ($Model.TrendUndated -gt 0) { $html.Add("<p class='empty'>$(Format-Count $Model.TrendUndated) phishing-resistant $(Get-Plural $Model.TrendUndated 'user') without registration dates $(Get-Plural $Model.TrendUndated 'isn''t' 'aren''t') shown.</p>") }
    }
    elseif ($trend.Count -eq 1) { $html.Add("<p class='empty'>All $(Format-Count $trend[0].Cumulative) phishing-resistant $(Get-Plural $trend[0].Cumulative 'registration was' 'registrations were') made in $($trend[0].Month.ToString('MMMM yyyy', $inv)).</p>") }
    else { $html.Add("<p class='empty'>No dated phishing-resistant registrations yet.</p>") }
    $html.Add('</div></div>')

    $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'Enabled by policy' -Sub 'Who the authentication methods policy allows to register phishing-resistant methods')")
    if (-not $Model.PolicyAvailable) {
        $html.Add((New-CalloutHtml -Kind 'info' -Html 'The authentication methods policy couldn''t be read, so policy scope isn''t shown.'))
    }
    else {
        $html.Add("<div class='kpis'>")
        if ($Model.Fido2Enabled) {
            $html.Add((New-KpiHtml -Label 'Enabled for passkeys' -Value (Format-Count $Model.PasskeyEnabledCount) -Note "$(Format-Percent $Model.PasskeyEnabledCount $total) of users"))
            $html.Add((New-KpiHtml -Label 'Enabled and registered' -Value (Format-Count $Model.PasskeyEnabledRegistered) -Note "$(Format-Percent $Model.PasskeyEnabledRegistered $Model.PasskeyEnabledCount) of enabled users"))
            $html.Add((New-KpiHtml -Label 'Synced passkeys allowed' -Value (Format-Count $Model.SyncedAllowedCount) -Note "Device-bound allowed for $(Format-Count $Model.DeviceBoundAllowedCount)"))
        }
        else {
            $html.Add((New-KpiHtml -Label 'Enabled for passkeys' -Value 'Off' -Note 'Passkey (FIDO2) policy is turned off'))
        }
        if ($Model.CbaEnabled) { $html.Add((New-KpiHtml -Label 'Certificate-based authentication' -Value (Format-Count $Model.CbaEnabledCount) -Note 'Users enabled')) }
        else { $html.Add((New-KpiHtml -Label 'Certificate-based authentication' -Value 'Off' -Note 'Not enabled in the policy')) }
        $html.Add('</div>')
    }
    $html.Add('</div>')

    if ($showUsers -and -not $usersOnly -and $Model.AdminTotal -gt 0) {
        $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'Admin accounts' -Sub 'Accounts with an Entra ID admin role, weakest first')<div class='table-wrap short'><table class='sortable'><thead><tr><th data-sort='text'>Name</th><th data-sort='text'>User principal name</th><th data-sort='num'>Strongest method</th><th>Phishing-resistant methods</th><th data-sort='num' class='num'>Passkeys</th></tr></thead><tbody>")
        foreach ($admin in @($Model.Admins)) {
            $group = $GroupCatalog[$admin.LadderKey]
            $html.Add("<tr><td>$(ConvertTo-HtmlText $admin.DisplayName)</td><td>$(ConvertTo-HtmlText $admin.UserPrincipalName)</td><td data-v='$($group.Rank)'>$(New-ChipHtml -Text $group.Ladder -Css $group.Css)</td><td>$(ConvertTo-HtmlText $admin.PrMethods)</td><td class='num'>$($admin.PasskeyCount)</td></tr>")
        }
        $html.Add('</tbody></table></div></div>')
    }

    if ($departments.Count -gt 1) {
        $shown = @($departments | Select-Object -First 25)
        $shownNote = if ($departments.Count -gt $shown.Count) { "The $($shown.Count) largest of $(Format-Count $departments.Count) departments" } else { 'Largest first' }
        $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'By department' -Sub $shownNote)<div class='table-wrap'><table class='sortable'><thead><tr><th data-sort='text'>Department</th><th data-sort='num' class='num'>Users</th><th data-sort='num'>Phishing-resistant</th><th data-sort='num'>MFA capable</th><th data-sort='num' class='num'>No MFA</th></tr></thead><tbody>")
        foreach ($department in $shown) {
            $prShare = if ($department.Users) { $department.Pr / $department.Users } else { 0 }
            $mfaShare = if ($department.Users) { $department.Mfa / $department.Users } else { 0 }
            $prMeter = New-MeterHtml -Part $department.Pr -Whole $department.Users -Label 'Phishing-resistant' -Small
            $mfaMeter = New-MeterHtml -Part $department.Mfa -Whole $department.Users -Label 'MFA capable' -Small
            $html.Add("<tr><td>$(ConvertTo-HtmlText $department.Name)</td><td class='num'>$(Format-Count $department.Users)</td><td data-v='$(Format-Number $prShare '0.####')'><div class='meter-cell'>$prMeter<b>$(ConvertTo-HtmlText (Format-Percent $department.Pr $department.Users))</b></div></td><td data-v='$(Format-Number $mfaShare '0.####')'><div class='meter-cell'>$mfaMeter<b>$(ConvertTo-HtmlText (Format-Percent $department.Mfa $department.Users))</b></div></td><td class='num'>$(Format-Count $department.NoMfa)</td></tr>")
        }
        $html.Add('</tbody></table></div></div>')
    }
    $html.Add('</div></section>')

    # ----- Passkeys -----
    $html.Add("$(New-PanelStartHtml -Id 'passkeys' -Title 'Passkeys')<div class='vstack'>")
    if ($pk.Total -eq 0) {
        $html.Add("<div class='card'><p class='empty'>No passkeys are registered yet.</p></div>")
    }
    else {
        $html.Add("<div class='kpis'>")
        $html.Add((New-KpiHtml -Label 'Passkeys registered' -Value (Format-Count $pk.Total) -Note "Held by $(Format-Count $Model.PasskeyUserCount) $(Get-Plural $Model.PasskeyUserCount 'user')"))
        $html.Add((New-KpiHtml -Label 'Device-bound' -Value (Format-Count $pk.DeviceBound) -Note "$(Format-Percent $pk.DeviceBound $pk.Total) - key stays on one device"))
        $html.Add((New-KpiHtml -Label 'Synced' -Value (Format-Count $pk.Synced) -Note "$(Format-Percent $pk.Synced $pk.Total) - key backed up to a provider"))
        $html.Add((New-KpiHtml -Label 'Hardware security keys' -Value (Format-Count $pk.Hardware) -Note "$(Format-Percent $pk.Hardware $pk.Total) - physical FIDO2 keys"))
        if ($pk.WithUsage -gt 0) { $html.Add((New-KpiHtml -Label 'Used in the last 30 days' -Value (Format-Count $pk.UsedRecently) -Note "$(Format-Percent $pk.UsedRecently $pk.Total) of passkeys")) }
        else { $html.Add((New-KpiHtml -Label 'Used in the last 30 days' -Value 'Not reported' -Note 'Graph returned no last-used dates')) }
        $html.Add('</div>')

        $hasUnknownStorage = $pk.UnknownStorage -gt 0
        $unknownHead = if ($hasUnknownStorage) { "<th class='num'>Type unknown</th>" } else { '' }
        $maxFormFactor = 0
        foreach ($row in $formFactors) { if ($row.Total -gt $maxFormFactor) { $maxFormFactor = $row.Total } }
        $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'By type' -Sub 'What holds the key, and whether it stays on one device or syncs')$(New-StorageLegendHtml -DeviceBound $pk.DeviceBound -Synced $pk.Synced -Unknown $pk.UnknownStorage)<div class='table-wrap' style='margin-top:12px'><table><thead><tr><th>Held by</th><th>Hardware or software</th><th class='bar-col narrow' aria-hidden='true'></th><th class='num'>Device-bound</th><th class='num'>Synced</th>$unknownHead<th class='num'>Total</th><th class='num'>Users</th><th class='num'>Attested</th><th class='num'>Used in 30 days</th></tr></thead><tbody>")
        foreach ($row in $formFactors) {
            $width = if ($maxFormFactor -gt 0) { [Math]::Max(1.5, 100 * $row.Total / $maxFormFactor) } else { 0 }
            $unknownCell = if ($hasUnknownStorage) { "<td class='num'>$(Format-Count $row.Unknown)</td>" } else { '' }
            $usedCell = if ($pk.WithUsage -gt 0) { Format-Count $row.Recent } else { '&ndash;' }
            $html.Add("<tr><td>$(ConvertTo-HtmlText $row.Name)</td><td>$(ConvertTo-HtmlText $row.Kind)</td><td class='bar-col narrow'><div class='split sm' aria-hidden='true' style='width:$(Format-Number $width)%'>$(New-StorageSegmentsHtml -DeviceBound $row.DeviceBound -Synced $row.Synced -Unknown $row.Unknown -Label $row.Name)</div></td><td class='num'>$(Format-Count $row.DeviceBound)</td><td class='num'>$(Format-Count $row.Synced)</td>$unknownCell<td class='num'><b>$(Format-Count $row.Total)</b></td><td class='num'>$(Format-Count $row.Users)</td><td class='num'>$(Format-Count $row.Attested)</td><td class='num'>$usedCell</td></tr>")
        }
        $html.Add('</tbody></table></div></div>')

        $maxCredentials = 0
        foreach ($provider in $providers) { if ($provider.Credentials -gt $maxCredentials) { $maxCredentials = $provider.Credentials } }
        $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'By authenticator' -Sub 'Identified from each passkey''s AAGUID, attestation and model')<div class='table-wrap'><table class='sortable'><thead><tr><th data-sort='text'>Authenticator</th><th data-sort='text'>Held by</th><th data-sort='text'>Storage</th><th class='bar-col narrow' aria-hidden='true'></th><th data-sort='num' class='num'>Passkeys</th><th data-sort='num' class='num'>Users</th><th data-sort='num' class='num'>Attested</th><th data-sort='text'>Last used</th></tr></thead><tbody>")
        foreach ($provider in $providers) {
            $tip = '{0} {1}, {2} {3}' -f (Format-Count $provider.Credentials), (Get-Plural $provider.Credentials 'passkey'), (Format-Count $provider.Users), (Get-Plural $provider.Users 'user')
            $lastUsedIso = if ($provider.LastUsed) { $provider.LastUsed.ToString('s', $inv) } else { '' }
            $aaguidLine = if ($provider.Aaguid) { "<span class='mono sub-line'>$(ConvertTo-HtmlText $provider.Aaguid)</span>" } else { '' }
            $storageCss = switch ($provider.Storage) { 'Device-bound' { 'db' } 'Synced' { 'sync' } default { 'unk' } }
            $html.Add("<tr><td>$(ConvertTo-HtmlText $provider.Provider)$aaguidLine</td><td>$(ConvertTo-HtmlText $provider.FormFactor)</td><td class='nowrap'>$(ConvertTo-HtmlText $provider.Storage)</td><td class='bar-col narrow'>$(New-BarHtml -Value $provider.Credentials -Max $maxCredentials -Css $storageCss -TipLabel $provider.Provider -TipValue $tip)</td><td class='num'>$(Format-Count $provider.Credentials)</td><td class='num'>$(Format-Count $provider.Users)</td><td class='num'>$(Format-Count $provider.Attested)</td><td class='nowrap' data-v='$lastUsedIso'>$(Format-ReportDate $provider.LastUsed)</td></tr>")
        }
        $html.Add('</tbody></table></div></div>')
    }
    $html.Add('</div></section>')

    # ----- All methods -----
    $html.Add("$(New-PanelStartHtml -Id 'methods' -Title 'All methods')<div class='card'>$(New-CardHeadHtml -Title 'Authentication methods' -Sub 'Users registered for each method, grouped by strength')")
    if ($methodStats.Count -eq 0) { $html.Add("<p class='empty'>No authentication methods are registered.</p>") }
    else {
        $maxUsers = 0
        foreach ($row in $methodStats) { if ($row.Users -gt $maxUsers) { $maxUsers = $row.Users } }
        $html.Add("<div class='x-scroll'><table class='bars'><thead><tr><th>Method</th><th class='bar-col' aria-hidden='true'></th><th class='num'>Users</th><th class='num'>Share</th></tr></thead><tbody>")
        foreach ($groupKey in $GroupOrder) {
            $rows = @($methodStats | Where-Object { $_.Group -eq $groupKey })
            if ($rows.Count -eq 0) { continue }
            $group = $GroupCatalog[$groupKey]
            $groupUsers = [int]$Model.GroupUserCounts[$groupKey]
            $html.Add("<tr class='group-row'><th colspan='4'><i class='sw t-$($group.Css)'></i>$(ConvertTo-HtmlText $group.Name) <span>&middot; $(Format-Count $groupUsers) $(Get-Plural $groupUsers 'user')</span></th></tr>")
            foreach ($row in $rows) {
                $share = Format-Percent $row.Users $total
                $tip = '{0} {1} ({2})' -f (Format-Count $row.Users), (Get-Plural $row.Users 'user'), $share
                $html.Add("<tr><td>$(ConvertTo-HtmlText $row.Name)</td><td class='bar-col'>$(New-BarHtml -Value $row.Users -Max $maxUsers -Css $group.Css -TipLabel $row.Name -TipValue $tip)</td><td class='num'>$(Format-Count $row.Users)</td><td class='num'>$(ConvertTo-HtmlText $share)</td></tr>")
            }
        }
        $html.Add('</tbody></table></div>')
    }
    $html.Add('</div></section>')

    # ----- Policy -----
    $html.Add("$(New-PanelStartHtml -Id 'policy' -Title 'Policy')<div class='vstack'>")
    if (-not $Model.PolicyAvailable) {
        $html.Add("<div class='card'>$(New-CalloutHtml -Kind 'info' -Html 'The authentication methods policy couldn''t be read with the signed-in account.')</div>")
    }
    else {
        $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'Authentication methods policy' -Sub 'Methods that are turned on, and who for')<div class='table-wrap'><table><thead><tr><th>Method</th><th>Enabled for</th><th>Settings</th><th class='num'>Registered users</th></tr></thead><tbody>")
        foreach ($row in @($Model.MethodPolicyRows)) {
            $registered = if ($null -eq $row.Registered) { "<span class='muted'>Not visible</span>" } else { Format-Count $row.Registered }
            $html.Add("<tr><td>$(ConvertTo-HtmlText $row.Name)</td><td>$(ConvertTo-HtmlText $row.Targets)</td><td>$(ConvertTo-HtmlText $row.Settings)</td><td class='num'>$registered</td></tr>")
        }
        if (@($Model.MethodPolicyRows).Count -eq 0) { $html.Add("<tr><td colspan='4' class='muted'>No methods are turned on.</td></tr>") }
        $html.Add("</tbody></table></div><p class='empty'>Windows Hello for Business and macOS Platform SSO are configured through device management (Intune or Group Policy), not this policy.</p></div>")

        if (@($Model.PasskeyProfileRows).Count -gt 0) {
            $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'Passkey profiles' -Sub 'Which passkey types each group can register')<div class='table-wrap'><table><thead><tr><th>Profile</th><th>Passkey types</th><th>Attestation</th><th>Key restrictions</th><th>Assigned to</th></tr></thead><tbody>")
            foreach ($row in @($Model.PasskeyProfileRows)) {
                $html.Add("<tr><td>$(ConvertTo-HtmlText $row.Name)</td><td>$(ConvertTo-HtmlText $row.Types)</td><td>$(ConvertTo-HtmlText $row.Attestation)</td><td>$(ConvertTo-HtmlText $row.KeyRestrictions)</td><td>$(ConvertTo-HtmlText $row.AssignedTo)</td></tr>")
            }
            $html.Add('</tbody></table></div></div>')
        }
    }

    if (-not $usersOnly) {
        $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'Conditional Access' -Sub 'Policies that require a phishing-resistant authentication strength')")
        if (-not $Model.CaAvailable) {
            $html.Add((New-CalloutHtml -Kind 'info' -Html 'Conditional Access policies couldn''t be read with the signed-in account.'))
        }
        elseif ($caRows.Count -eq 0) {
            $html.Add((New-CalloutHtml -Kind 'warn' -Html 'No Conditional Access policy requires a phishing-resistant authentication strength yet.'))
        }
        else {
            $html.Add("<div class='table-wrap'><table><thead><tr><th>Policy</th><th>State</th><th>Authentication strength</th><th>Applies to</th><th>Target resources</th></tr></thead><tbody>")
            foreach ($row in $caRows) {
                $state = switch ($row.State) {
                    'enabled'                           { New-StatusHtml -Kind 'good' -Text 'On' }
                    'enabledForReportingButNotEnforced' { New-StatusHtml -Kind 'warn' -Text 'Report-only' }
                    default                             { New-StatusHtml -Kind 'off' -Text 'Off' }
                }
                $html.Add("<tr><td>$(ConvertTo-HtmlText $row.Name)</td><td>$state</td><td>$(ConvertTo-HtmlText $row.Strength)</td><td>$(ConvertTo-HtmlText $row.AppliesTo)</td><td>$(ConvertTo-HtmlText $row.Resources)</td></tr>")
            }
            $html.Add('</tbody></table></div>')
        }
        $html.Add('</div>')
    }
    $html.Add('</div></section>')

    # ----- Users -----
    if ($showUsers) {
        $prUsers = @($Model.PrUsers)
        $otherUsers = @($Model.OtherUsers)
        $otherTotal = $total - $prCount
        $html.Add("$(New-PanelStartHtml -Id 'users' -Title 'Users')<div class='vstack'>")
        $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'Phishing-resistant users' -Sub 'Users with at least one phishing-resistant method. Every user is in the CSV files.')")
        if ($prCount -eq 0) { $html.Add("<p class='empty'>No users have a phishing-resistant method yet.</p>") }
        else {
            $limitNote = if ($prUsers.Count -lt $prCount) { " (first $(Format-Count $prUsers.Count) shown)" } else { '' }
            $html.Add("<div class='toolbar'><input class='search' type='search' placeholder='Filter by name, department or method' aria-label='Filter phishing-resistant users' data-filter='pr-users'><span class='count'><span id='pr-users-count'>$(Format-Count $prUsers.Count)</span> of $(Format-Count $prCount) $(Get-Plural $prCount 'user')$limitNote</span></div>")
            $adminHead = if ($usersOnly) { '' } else { "<th data-sort='text'>Admin</th>" }
            $html.Add("<div class='table-wrap scroll'><table class='sortable' id='pr-users'><thead><tr><th data-sort='text'>Name</th><th data-sort='text'>User principal name</th><th data-sort='text'>Department</th>$adminHead<th data-sort='text'>Phishing-resistant methods</th><th data-sort='num' class='num'>Passkeys</th><th data-sort='text'>First registered</th><th data-sort='text'>Last used</th></tr></thead><tbody>")
            foreach ($user in $prUsers) {
                $firstIso = if ($user.FirstPr) { $user.FirstPr.ToString('s', $inv) } else { '' }
                $lastIso = if ($user.LastPrUse) { $user.LastPrUse.ToString('s', $inv) } else { '' }
                $adminCell = if ($usersOnly) { '' } else { "<td>$(ConvertTo-HtmlText $user.AdminText)</td>" }
                $html.Add("<tr><td>$(ConvertTo-HtmlText $user.DisplayName)</td><td>$(ConvertTo-HtmlText $user.UserPrincipalName)</td><td>$(ConvertTo-HtmlText $user.Department)</td>$adminCell<td>$(ConvertTo-HtmlText $user.PrMethods)</td><td class='num'>$($user.PasskeyCount)</td><td class='nowrap' data-v='$firstIso'>$(Format-ReportDate $user.FirstPr)</td><td class='nowrap' data-v='$lastIso'>$(Format-ReportDate $user.LastPrUse)</td></tr>")
            }
            $html.Add('</tbody></table></div>')
        }
        $html.Add('</div>')

        $otherSub = if ($usersOnly) { 'Weakest methods first' } else { 'Weakest first, with admins first in each group' }
        $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'Not yet phishing-resistant' -Sub $otherSub)")
        if ($otherTotal -eq 0) { $html.Add("<p class='empty'>Every user in scope is phishing-resistant.</p>") }
        else {
            $limitNote = if ($otherUsers.Count -lt $otherTotal) { " (first $(Format-Count $otherUsers.Count) shown)" } else { '' }
            $html.Add("<div class='toolbar'><input class='search' type='search' placeholder='Filter by name, department or method' aria-label='Filter users who are not yet phishing-resistant' data-filter='other-users'><span class='count'><span id='other-users-count'>$(Format-Count $otherUsers.Count)</span> of $(Format-Count $otherTotal) $(Get-Plural $otherTotal 'user')$limitNote</span></div>")
            $adminHead = if ($usersOnly) { '' } else { "<th data-sort='text'>Admin</th>" }
            $html.Add("<div class='table-wrap scroll'><table class='sortable' id='other-users'><thead><tr><th data-sort='text'>Name</th><th data-sort='text'>User principal name</th><th data-sort='text'>Department</th>$adminHead<th data-sort='num'>Strongest method</th><th data-sort='text'>Registered methods</th><th data-sort='text'>Passkey policy</th></tr></thead><tbody>")
            foreach ($user in $otherUsers) {
                $group = $GroupCatalog[$user.LadderKey]
                $adminCell = if ($usersOnly) { '' } else { "<td>$(ConvertTo-HtmlText $user.AdminText)</td>" }
                $html.Add("<tr><td>$(ConvertTo-HtmlText $user.DisplayName)</td><td>$(ConvertTo-HtmlText $user.UserPrincipalName)</td><td>$(ConvertTo-HtmlText $user.Department)</td>$adminCell<td data-v='$($group.Rank)'>$(New-ChipHtml -Text $group.Ladder -Css $group.Css)</td><td>$(ConvertTo-HtmlText $user.Methods)</td><td class='nowrap'>$(ConvertTo-HtmlText $user.PasskeyPolicy)</td></tr>")
            }
            $html.Add('</tbody></table></div>')
        }
        $html.Add('</div></div></section>')
    }

    # ----- About -----
    $html.Add("$(New-PanelStartHtml -Id 'about' -Title 'About this report')<div class='vstack'>")
    if ($usersOnly) { $html.Add("<div class='callout info'><svg aria-hidden='true'><use href='#i-info'/></svg><span>Includes enabled members without active or eligible direct directory roles or active membership in a role-assigned group.</span></div>") }
    $html.Add("<div class='card'>$(New-CardHeadHtml -Title 'Definitions')<dl class='defs'>")
    $definitions = @(
        @('Phishing-resistant', 'Passkeys, Windows Hello for Business and macOS Platform SSO use credentials tied to the sign-in site, blocking fake-site replay.'),
        @('Passwordless phone sign-in', 'Microsoft Authenticator signs in without a password, but approval prompts can still be phished.'),
        @('App or token MFA', 'A second sign-in step using an authenticator app, verification code, hardware token or external MFA provider.'),
        @('SMS or voice only', 'MFA relies on a text message or phone call. Both can be phished.'),
        @('No MFA', 'No MFA method is registered; the account may have password-reset methods or none.'),
        @('Device-bound passkey', 'A passkey stored on one device or physical security key; it does not sync across devices.'),
        @('Synced passkey', 'A passkey backed up by a provider and available across the user''s devices.'),
        @('Hardware or software', 'Hardware is a physical security key; software is an app, operating system or password manager.'),
        @('Passkey classification', 'Graph reports whether a passkey syncs. An authenticator ID, attestation and model name help identify its type.')
    )
    foreach ($definition in $definitions) { $html.Add("<dt>$(ConvertTo-HtmlText $definition[0])</dt><dd>$(ConvertTo-HtmlText $definition[1])</dd>") }
    $html.Add('</dl></div>')

    foreach ($warning in @($Model.Warnings)) {
        $html.Add("<div class='callout warn'><svg aria-hidden='true'><use href='#i-alert'/></svg><span>$(ConvertTo-HtmlText $warning)</span></div>")
    }
    $html.Add("</div><p class='foot'>Generated by $(ConvertTo-HtmlText $Model.Account) on $(ConvertTo-HtmlText $Model.GeneratedText)</p></section>")

    $html.Add("</main><div id='tip' role='tooltip'></div><script>$ReportScript</script></body></html>")
    return ($html -join "`n")
}

# ============================================================================
# MAIN SCRIPT LOGIC
# ============================================================================

try {
    # One run time, in Irish time, names the output folder and dates the report
    $runStarted = Get-Date
    $timestamp = (ConvertTo-ReportTime $runStarted).ToString('yyyy-MM-dd HHmm', [Globalization.CultureInfo]::InvariantCulture)

    # ----- Tenant -----
    Write-Step 'Reading tenant details...'
    $tenantName = $null
    $tenantDomain = $null
    try {
        $organization = @((Invoke-GraphRequestWithRetry -Uri "$GraphBase/organization?`$select=id,displayName,verifiedDomains").value)[0]
        $tenantName = [string]$organization.displayName
        $tenantDomain = [string](@($organization.verifiedDomains | Where-Object { $_.isInitial }) | Select-Object -First 1).name
    }
    catch {
        Write-Verbose "Organisation details unavailable: $($_.Exception.Message)"
    }
    if (-not $tenantName) { $tenantName = "Tenant $($context.TenantId)" }

    # ----- Users -----
    Write-Step 'Retrieving users...'
    $userSelect = 'id,displayName,userPrincipalName,accountEnabled,userType,department'
    if ($LicensedUsersOnly) { $userSelect += ',assignedLicenses' }
    # Graph filters out disabled accounts, so they're never downloaded
    $userFilter = if ($IncludeDisabledUsers) { '' } else { '&$filter=' + [uri]::EscapeDataString('accountEnabled eq true') }
    $signInCutoff = if ($ActiveWithinDays -gt 0) { (Get-Date).ToUniversalTime().AddDays(-$ActiveWithinDays) } else { $null }
    $userList = [System.Collections.Generic.List[object]]::new()
    foreach ($withSignIn in @($true, $false)) {
        if ($withSignIn -and -not $signInCutoff) { continue }
        # Graph caps pages at 500 users when sign-in activity is included
        $uri = if ($withSignIn) { "$GraphBase/users?`$select=$userSelect,signInActivity&`$top=500$userFilter" } else { "$GraphBase/users?`$select=$userSelect&`$top=999$userFilter" }
        $userList.Clear()
        try {
            Get-GraphPage -Uri $uri -Activity 'Retrieving users' | ForEach-Object {
                foreach ($user in $_) {
                    if ($null -eq $user) { continue }
                    $userType = if ($user.userType) { [string]$user.userType } else { 'Member' }
                    if ($UsersOnly) {
                        if ([string]$user.userType -ne 'Member' -or $user.accountEnabled -ne $true) { continue }
                    }
                    else {
                        if (-not $IncludeGuests -and $userType -eq 'Guest') { continue }
                        if (-not $IncludeDisabledUsers -and $user.accountEnabled -ne $true) { continue }
                    }
                    if ($LicensedUsersOnly -and -not $user.assignedLicenses) { continue }
                    if ($withSignIn) {
                        $activity = $user.signInActivity
                        $lastSignIn = Get-LatestDate -Values @($activity.lastSignInDateTime, $activity.lastNonInteractiveSignInDateTime, $activity.lastSuccessfulSignInDateTime)
                        if (-not $lastSignIn -or $lastSignIn -lt $signInCutoff) { continue }
                    }
                    $userList.Add($user)
                }
            }
            break
        }
        catch {
            if (-not $withSignIn) { throw }
            Add-ReportWarning "Sign-in activity isn't available ($(Get-ErrorSummary -ErrorRecord $_)). It needs Microsoft Entra ID P1 or P2, so the -ActiveWithinDays filter wasn't applied."
            $signInCutoff = $null
        }
    }
    if ($userList.Count -eq 0) { throw 'No users matched the selected scope.' }

    # Sort once by display name, so every list and CSV file comes out in name order
    $users = $userList.ToArray()
    $sortKeys = [string[]]::new($users.Length)
    for ($i = 0; $i -lt $users.Length; $i++) { $sortKeys[$i] = [string]$users[$i].displayName }
    [Array]::Sort($sortKeys, $users, [StringComparer]::CurrentCultureIgnoreCase)
    if ($UsersOnly) {
        Write-Step 'Excluding users with active or eligible Entra ID directory roles...'
        $excludedByRole = Get-RoleExcludedUserIds -Users $users
        $roleCount = $excludedByRole.Count
        $users = @($users | Where-Object { -not $excludedByRole.Contains([string]$_.id) })
        Write-Step "Excluded $(Format-Count $roleCount) $(Get-Plural $roleCount 'admin account') from the standard-user report."
        if ($users.Count -eq 0) { throw 'No standard users remain after excluding admin accounts.' }
    }
    $inScope = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($user in $users) { [void]$inScope.Add([string]$user.id) }
    Write-Step "$(Format-Count $users.Length) users in scope."


    # ----- Registration report -----
    Write-Step 'Retrieving the authentication methods registration report...'
    $registrationById = @{}
    $registrationAvailable = $false
    $registrationUpdated = $null
    $lastUpdatedRaw = $null
    try {
        Get-GraphPage -Uri "$GraphBase/reports/authenticationMethods/userRegistrationDetails" -Activity 'Retrieving the registration report' | ForEach-Object {
            foreach ($record in $_) {
                if ($null -eq $record) { continue }
                $id = [string]$record.id
                if (-not $inScope.Contains($id)) { continue }
                # Keep only the fields the report uses
                $registrationById[$id] = @{
                    Methods          = $record.methodsRegistered
                    IsAdmin          = $record.isAdmin
                    DefaultMethod    = $record.defaultMfaMethod
                    PreferredMethods = $record.systemPreferredAuthenticationMethods
                }
                # Every record carries the report's refresh time, so only parse it when it changes
                $raw = $record.lastUpdatedDateTime
                if ($null -ne $raw -and "$raw" -ne "$lastUpdatedRaw") {
                    $lastUpdatedRaw = $raw
                    $updated = ConvertTo-UtcDateTime $raw
                    if ($updated -and (-not $registrationUpdated -or $updated -gt $registrationUpdated)) { $registrationUpdated = $updated }
                }
            }
        }
        $registrationAvailable = $true
    }
    catch {
        $registrationById = @{}
        Add-ReportWarning "The registration details report couldn't be read ($(Get-ErrorSummary -ErrorRecord $_)). It needs Microsoft Entra ID P1 or P2 and a Reports Reader, Security Reader or Global Reader role, so every user's methods were read live instead."
    }
    if ($UsersOnly -and $registrationAvailable) {
        $reportedAdmins = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($id in @($registrationById.Keys)) {
            if ($registrationById[$id].IsAdmin -eq $true) { [void]$reportedAdmins.Add([string]$id); [void]$registrationById.Remove($id) }
        }
        if ($reportedAdmins.Count -gt 0) {
            $users = @($users | Where-Object { -not $reportedAdmins.Contains([string]$_.id) })
            Write-Step "Excluded $(Format-Count $reportedAdmins.Count) additional $(Get-Plural $reportedAdmins.Count 'admin account') identified in the registration report."
            if ($users.Count -eq 0) { throw 'No standard users remain after excluding admin accounts.' }
        }
    }

    # ----- Live method details -----
    $fullScan = $FullMethodScan.IsPresent -or -not $registrationAvailable
    $scanIds = [System.Collections.Generic.List[string]]::new()
    foreach ($user in $users) {
        $id = [string]$user.id
        $registration = $registrationById[$id]
        # Users missing from the report (for example, very new accounts) are read live
        if ($fullScan -or -not $registration) { $scanIds.Add($id); continue }
        foreach ($value in $registration.Methods) {
            if ($PhishingResistantRegistrationValues.Contains([string]$value)) { $scanIds.Add($id); break }
        }
    }

    $liveById = @{}
    if ($scanIds.Count -gt 0) {
        $scanReason = if ($FullMethodScan) { 'every user' } elseif ($fullScan) { 'every user, as the registration report is unavailable' } else { 'users with phishing-resistant methods' }
        Write-Step "Reading live authentication methods for $(Format-Count $scanIds.Count) $(Get-Plural $scanIds.Count 'user') ($scanReason)..."
        $scan = Invoke-LiveMethodScan -UserIds $scanIds.ToArray() -ThrottleLimit $ThrottleLimit
        $liveById = $scan.Entries
        Write-Verbose "Live read mode: $(if ($scan.Parallel) { "parallel ($ThrottleLimit batches)" } else { 'sequential' }), $([Math]::Round($scan.Timer.Elapsed.TotalSeconds, 1)) seconds."
        if ($scan.Failed -gt 0) {
            $failureNote = if ($UsersOnly) { 'Check the signed-in account permissions.' } else { 'This can happen when an Authentication Administrator reads admin accounts.' }
            Add-ReportWarning "Live method details couldn't be read for $(Format-Count $scan.Failed) $(Get-Plural $scan.Failed 'user'). $failureNote Registration report data was used where available."
        }
    }

    # ----- Policies -----
    Write-Step 'Reading the authentication methods policy...'
    $policy = $null
    $fido2Config = $null
    $methodConfigs = @()
    try {
        $policy = Invoke-GraphRequestWithRetry -Uri "$GraphBase/policies/authenticationMethodsPolicy"
        $methodConfigs = @($policy.authenticationMethodConfigurations | Where-Object { $_ })
        try {
            $fido2Config = Invoke-GraphRequestWithRetry -Uri "$GraphBase/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/Fido2"
        }
        catch {
            $fido2Config = $methodConfigs | Where-Object { [string]$_.id -eq 'Fido2' } | Select-Object -First 1
        }
    }
    catch {
        Add-ReportWarning "The authentication methods policy couldn't be read ($(Get-ErrorSummary -ErrorRecord $_))."
    }
    $policyAvailable = $null -ne $policy
    $x509Config = $methodConfigs | Where-Object { [string]$_.id -eq 'X509Certificate' } | Select-Object -First 1

    $passkeyScope = @{}
    $cbaScope = @{}
    if ($policyAvailable) {
        Write-Step 'Resolving policy target groups...'
        $passkeyScope = Get-PolicyScope -Config $fido2Config -Users $users -PasskeyProfiles
        $cbaScope = Get-PolicyScope -Config $x509Config -Users $users
    }

    $caRows = @()
    $caAvailable = $false
    if (-not $UsersOnly) {
        Write-Step 'Reading Conditional Access policies...'
        try {
            $caPolicies = @(Get-MgGraphAllPage -Uri "$GraphBase/identity/conditionalAccess/policies")
            $caAvailable = $true
            $caCandidates = @(foreach ($caPolicy in $caPolicies) {
                    $strength = $caPolicy.grantControls.authenticationStrength
                    if (-not $strength -or -not (Test-PhishingResistantStrength -Strength $strength)) { continue }
                    [pscustomobject]@{
                        Name      = [string]$caPolicy.displayName
                        State     = [string]$caPolicy.state
                        Strength  = [string]$strength.displayName
                        AppliesTo = Get-CaAssignmentSummary -Users $caPolicy.conditions.users
                        Resources = Get-CaResourceSummary -Applications $caPolicy.conditions.applications
                        Order     = switch ([string]$caPolicy.state) { 'enabled' { 0 } 'enabledForReportingButNotEnforced' { 1 } default { 2 } }
                    }
                })
            $caRows = @($caCandidates | Sort-Object -Property Order, Name)
        }
        catch {
            Add-ReportWarning "Conditional Access policies couldn't be read ($(Get-ErrorSummary -ErrorRecord $_))."
        }
    }

    # ----- Analysis and CSV export -----
    Write-Step 'Analysing authentication methods and writing the CSV files...'
    # For example "Sign-in security - 2026-09-27 1343\Sign-in security - report.html"
    $fileBase = ConvertTo-FileName -Text $ReportTitle
    $runFolder = New-RunFolder -Parent $OutputPath -Name "$fileBase - $timestamp"
    $htmlPath = Join-Path -Path $runFolder -ChildPath "$fileBase - report.html"
    $usersPath = Join-Path -Path $runFolder -ChildPath "$fileBase - users.csv"
    $detailPath = Join-Path -Path $runFolder -ChildPath "$fileBase - registered methods.csv"
    $inv = [Globalization.CultureInfo]::InvariantCulture

    foreach ($definition in @($MethodCatalog.Values)) { $definition.CsvFields = Get-MethodCsvFields -Definition $definition }
    # Users with the same set of methods share one profile (strength, names, CSV fields), and lookups that only
    # depend on a handful of distinct values are cached, which keeps large tenants fast
    $methodProfiles = @{}
    $preferredCache = @{}
    $passkeyPolicyCache = @{}
    $passkeyPolicyUnknown = [pscustomobject]@{ Text = 'Unknown'; Csv = '"Unknown"'; Synced = $false; DeviceBound = $false }
    $passkeyPolicyOff = [pscustomobject]@{ Text = 'Not enabled'; Csv = '"Not enabled"'; Synced = $false; DeviceBound = $false }

    $ladderCounts = @{}
    $adminLadderCounts = @{}
    foreach ($tier in $LadderOrder) { $ladderCounts[$tier] = 0; $adminLadderCounts[$tier] = 0 }
    $adminTotal = 0
    $firstPrDates = [System.Collections.Generic.List[datetime]]::new()
    $undatedPrUsers = 0
    $departmentStats = @{}
    $passkeyUserCount = 0
    $passkeyEnabledRegistered = 0
    $syncedAllowed = 0
    $deviceBoundAllowed = 0
    $recentCutoff = (Get-Date).ToUniversalTime().AddDays(-30)
    $passkeyStats = [pscustomobject]@{ Total = 0; DeviceBound = 0; Synced = 0; UnknownStorage = 0; Hardware = 0; Software = 0; UnknownKind = 0; WithUsage = 0; UsedRecently = 0 }
    $formFactorStats = @{}
    $providerStats = @{}
    $showUsers = $MaxUsersInHtml -gt 0
    $prViews = [System.Collections.Generic.List[object]]::new()
    $adminViews = [System.Collections.Generic.List[object]]::new()
    # Users who aren't phishing-resistant are listed weakest first, admins first; one capped list per rank and role
    $otherViewBuckets = @{}
    $progressTimer = [System.Diagnostics.Stopwatch]::StartNew()
    $processed = 0

    $detailColumns = if ($UsersOnly) { @($DetailCsvColumns | Where-Object { $_ -ne 'IsAdmin' }) } else { $DetailCsvColumns }
    $userColumns = if ($UsersOnly) { @($UserCsvColumns | Where-Object { $_ -ne 'IsAdmin' }) } else { $UserCsvColumns }
    $detailWriter = New-CsvWriter -Path $detailPath -Columns $detailColumns
    $usersWriter = $null
    try {
        $usersWriter = New-CsvWriter -Path $usersPath -Columns $userColumns
        foreach ($user in $users) {
            $processed++
            if ($progressTimer.ElapsedMilliseconds -ge 500) {
                Write-Progress -Activity 'Analysing users' -Status "$(Format-Count $processed) of $(Format-Count $users.Length)" -PercentComplete ([int](100 * $processed / $users.Length))
                $progressTimer.Restart()
            }
            $id = [string]$user.id
            $registration = $registrationById[$id]
            $liveEntries = $liveById[$id]

            $entries = [System.Collections.Generic.List[object]]::new()
            if ($null -ne $liveEntries) {
                $entries.AddRange($liveEntries)
                # Security questions and phone sign-in aren't exposed as live method objects, so take them from the report
                if ($registration) {
                    foreach ($value in $registration.Methods) {
                        if ($value -eq 'securityQuestion' -or $value -eq 'microsoftAuthenticatorPasswordless') { $entries.Add((Get-RegistrationEntry -Value $value)) }
                    }
                }
            }
            elseif ($registration) {
                foreach ($value in $registration.Methods) {
                    if (-not $value) { continue }
                    $entry = $RegistrationEntryCache[$value]
                    if (-not $entry) { $entry = Get-RegistrationEntry -Value $value }
                    $entries.Add($entry)
                }
            }

            # Strongest method and method names, shared by every user with the same set of methods
            $keys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $entries) { if ($entry.Counts) { [void]$keys.Add($entry.MethodKey) } }
            $keyArray = [string[]]::new($keys.Count)
            $keys.CopyTo($keyArray)
            [Array]::Sort($keyArray, [StringComparer]::OrdinalIgnoreCase)
            $profileKey = $keyArray -join '|'
            $methodProfile = $methodProfiles[$profileKey]
            if (-not $methodProfile) {
                $methodProfile = New-MethodProfile -Keys $keyArray
                $methodProfiles[$profileKey] = $methodProfile
            }
            $methodProfile.Users++
            $bestRank = $methodProfile.Rank
            $ladderKey = $methodProfile.LadderKey
            $ladderCounts[$ladderKey]++

            # Phishing-resistant dates and passkey detail
            $firstPr = $null
            $lastPrUse = $null
            $userPasskeys = 0
            $hardwareKeys = 0; $authenticatorPasskeys = 0; $helloPasskeys = 0; $syncedPasskeys = 0; $otherPasskeys = 0
            foreach ($entry in $entries) {
                if (-not $entry.Counts -or $MethodCatalog[$entry.MethodKey].Rank -ne 1) { continue }
                if ($entry.Created -and (-not $firstPr -or $entry.Created -lt $firstPr)) { $firstPr = $entry.Created }
                if ($entry.LastUsed -and (-not $lastPrUse -or $entry.LastUsed -gt $lastPrUse)) { $lastPrUse = $entry.LastUsed }
                $passkey = $entry.Passkey
                if (-not $passkey) { continue }

                $userPasskeys++
                switch ($entry.MethodKey) {
                    'PasskeySecurityKey'   { $hardwareKeys++ }
                    'PasskeyAuthenticator' { $authenticatorPasskeys++ }
                    'PasskeyWindowsHello'  { $helloPasskeys++ }
                    'PasskeySynced'        { $syncedPasskeys++ }
                    default                { $otherPasskeys++ }
                }
                $passkeyStats.Total++
                switch ($passkey.Storage) { 'Device-bound' { $passkeyStats.DeviceBound++ } 'Synced' { $passkeyStats.Synced++ } default { $passkeyStats.UnknownStorage++ } }
                switch ($passkey.HardwareOrSoftware) { 'Hardware' { $passkeyStats.Hardware++ } 'Software' { $passkeyStats.Software++ } default { $passkeyStats.UnknownKind++ } }
                $usedRecently = $false
                if ($entry.LastUsed) {
                    $passkeyStats.WithUsage++
                    if ($entry.LastUsed -ge $recentCutoff) { $passkeyStats.UsedRecently++; $usedRecently = $true }
                }

                $formFactor = $formFactorStats[$passkey.FormFactor]
                if (-not $formFactor) {
                    $formFactor = [pscustomobject]@{ DeviceBound = 0; Synced = 0; Unknown = 0; Total = 0; UserIds = [System.Collections.Generic.HashSet[string]]::new(); Attested = 0; Recent = 0 }
                    $formFactorStats[$passkey.FormFactor] = $formFactor
                }
                $formFactor.Total++
                switch ($passkey.Storage) { 'Device-bound' { $formFactor.DeviceBound++ } 'Synced' { $formFactor.Synced++ } default { $formFactor.Unknown++ } }
                [void]$formFactor.UserIds.Add($id)
                if ($passkey.Attestation -eq 'Attested') { $formFactor.Attested++ }
                if ($usedRecently) { $formFactor.Recent++ }

                $providerKey = "$($passkey.Provider)|$($passkey.FormFactor)|$($passkey.Storage)"
                $provider = $providerStats[$providerKey]
                if (-not $provider) {
                    $provider = [pscustomobject]@{ Provider = $passkey.Provider; FormFactor = $passkey.FormFactor; Storage = $passkey.Storage; Aaguid = $passkey.Aaguid; Credentials = 0; UserIds = [System.Collections.Generic.HashSet[string]]::new(); Attested = 0; LastUsed = $null }
                    $providerStats[$providerKey] = $provider
                }
                $provider.Credentials++
                [void]$provider.UserIds.Add($id)
                if ($passkey.Attestation -eq 'Attested') { $provider.Attested++ }
                if ($entry.LastUsed -and (-not $provider.LastUsed -or $entry.LastUsed -gt $provider.LastUsed)) { $provider.LastUsed = $entry.LastUsed }
                if ($passkey.Aaguid -and $passkey.Model -and -not $ObservedAaguidNames.ContainsKey($passkey.Aaguid)) { $ObservedAaguidNames[$passkey.Aaguid] = $passkey.Model }
            }
            if ($ladderKey -eq 'PhishingResistant') {
                if ($firstPr) { $firstPrDates.Add($firstPr) } else { $undatedPrUsers++ }
            }
            if ($userPasskeys -gt 0 -or $methodProfile.PasskeyTypeCount -gt 0) { $passkeyUserCount++ }
            # Registration-report-only users have no credential detail, so count one passkey per passkey type
            $passkeyCount = if ($userPasskeys -gt 0) { $userPasskeys } else { $methodProfile.PasskeyTypeCount }

            # Admin role (registration report only)
            $isAdmin = $null
            if ($registration -and $null -ne $registration.IsAdmin) { $isAdmin = [bool]$registration.IsAdmin }
            if ($isAdmin) { $adminTotal++; $adminLadderCounts[$ladderKey]++ }
            $adminText = if ($null -eq $isAdmin) { '' } elseif ($isAdmin) { 'Yes' } else { 'No' }

            # Department
            $department = if ($user.department) { ([string]$user.department).Trim() } else { '' }
            $departmentKey = if ($department) { $department } else { '(No department)' }
            $departmentRow = $departmentStats[$departmentKey]
            if (-not $departmentRow) {
                $departmentRow = [pscustomobject]@{ Name = $departmentKey; Users = 0; Pr = 0; Mfa = 0; NoMfa = 0 }
                $departmentStats[$departmentKey] = $departmentRow
            }
            $departmentRow.Users++
            if ($bestRank -eq 1) { $departmentRow.Pr++ }
            if ($bestRank -le 4) { $departmentRow.Mfa++ } else { $departmentRow.NoMfa++ }

            # Passkey policy scope
            $passkeyPolicy = $passkeyPolicyUnknown
            if ($policyAvailable) {
                $passkeyPolicy = $passkeyPolicyOff
                if ($passkeyScope.ContainsKey($id)) {
                    $allowedTypes = $passkeyScope[$id]
                    $typesKey = $allowedTypes -join ','
                    $passkeyPolicy = $passkeyPolicyCache[$typesKey]
                    if (-not $passkeyPolicy) {
                        $policyText = "Enabled ($(Format-PasskeyTypes -Types $allowedTypes))"
                        $passkeyPolicy = [pscustomobject]@{ Text = $policyText; Csv = Format-CsvField $policyText; Synced = $allowedTypes -contains 'synced'; DeviceBound = $allowedTypes -contains 'deviceBound' }
                        $passkeyPolicyCache[$typesKey] = $passkeyPolicy
                    }
                    if ($passkeyPolicy.Synced) { $syncedAllowed++ }
                    if ($passkeyPolicy.DeviceBound) { $deviceBoundAllowed++ }
                    if ($methodProfile.PasskeyTypeCount -gt 0) { $passkeyEnabledRegistered++ }
                }
            }

            # CSV rows: one line per method or credential in the detail file, one line per user in the user file
            $upn = [string]$user.userPrincipalName
            $displayName = [string]$user.displayName
            $userType = if ($user.userType) { [string]$user.userType } else { 'Member' }
            $userCsv = if ($UsersOnly) {
                '{0},{1},"{2}","{3}",{4},{5}' -f (Format-CsvField $upn), (Format-CsvField $displayName), $id, [bool]$user.accountEnabled, (Format-CsvField $userType), (Format-CsvField $department)
            }
            else {
                '{0},{1},"{2}","{3}",{4},{5},"{6}"' -f (Format-CsvField $upn), (Format-CsvField $displayName), $id, [bool]$user.accountEnabled, (Format-CsvField $userType), (Format-CsvField $department), $adminText
            }
            foreach ($entry in $entries) {
                $definition = $MethodCatalog[$entry.MethodKey]
                if (-not $definition) { $definition = Get-MethodDefinition -Key $entry.MethodKey }
                $tail = $entry.CsvTail
                if ($entry.Source -eq 'Live') {
                    $passkey = $entry.Passkey
                    $passkeyCsv = if ($passkey) { '"{0}","{1}","{2}",{3},{4},"{5}"' -f $passkey.Storage, $passkey.FormFactor, $passkey.HardwareOrSoftware, (Format-CsvField $passkey.Provider), (Format-CsvField $passkey.Aaguid), $passkey.Attestation } else { '"","","","","",""' }
                    $created = if ($entry.Created) { $entry.Created.ToString('yyyy-MM-dd HH:mm:ss', $inv) } else { '' }
                    $lastUsed = if ($entry.LastUsed) { $entry.LastUsed.ToString('yyyy-MM-dd HH:mm:ss', $inv) } else { '' }
                    $tail = '"{0}",{1},{2},{3},"{4}","{5}","Live",{6}' -f $entry.Counts, $passkeyCsv, (Format-CsvField $entry.CredentialName), (Format-CsvField $entry.Detail), $created, $lastUsed, (Format-CsvField $entry.RawType)
                }
                $detailWriter.WriteLine($userCsv + ',' + $definition.CsvFields + ',' + $tail)
            }

            $preferredCsv = '"",""'
            if ($registration) {
                $preferredKey = "$($registration.DefaultMethod)|$(@($registration.PreferredMethods) -join ',')"
                $preferredCsv = $preferredCache[$preferredKey]
                if (-not $preferredCsv) {
                    $preferredCsv = (Format-CsvField (Format-PreferredMethods -Values $registration.DefaultMethod)) + ',' + (Format-CsvField (Format-PreferredMethods -Values $registration.PreferredMethods))
                    $preferredCache[$preferredKey] = $preferredCsv
                }
            }
            $cbaText = if (-not $policyAvailable) { '' } elseif ($cbaScope.ContainsKey($id)) { 'True' } else { 'False' }
            $firstText = if ($firstPr) { $firstPr.ToString('yyyy-MM-dd HH:mm:ss', $inv) } else { '' }
            $lastText = if ($lastPrUse) { $lastPrUse.ToString('yyyy-MM-dd HH:mm:ss', $inv) } else { '' }
            $signInText = ''
            if ($signInCutoff) {
                $lastSignIn = Get-LatestDate -Values @($user.signInActivity.lastSignInDateTime, $user.signInActivity.lastNonInteractiveSignInDateTime)
                if ($lastSignIn) { $signInText = $lastSignIn.ToString('yyyy-MM-dd HH:mm:ss', $inv) }
            }
            $dataSource = if ($null -ne $liveEntries -and $registration) { 'Live and registration report' } elseif ($null -ne $liveEntries) { 'Live' } elseif ($registration) { 'Registration report' } else { 'None' }
            $usersWriter.WriteLine(('{0},{1},"{2}","{3}","{4}","{5}","{6}","{7}",{8},{9},{10},"{11}","{12}","{13}","{14}","{15}"' -f $userCsv, $methodProfile.CsvStrength, $passkeyCount, $hardwareKeys, $authenticatorPasskeys, $helloPasskeys, $syncedPasskeys, $otherPasskeys, $methodProfile.CsvMethods, $preferredCsv, $passkeyPolicy.Csv, $cbaText, $firstText, $lastText, $signInText, $dataSource))

            # User lists for the HTML report, capped at -MaxUsersInHtml each
            if ($showUsers) {
                $bucket = $null
                if ($bestRank -eq 1) {
                    if ($prViews.Count -lt $MaxUsersInHtml) { $bucket = $prViews }
                }
                else {
                    $bucketKey = '{0}|{1}' -f $bestRank, [int][bool]$isAdmin
                    $bucket = $otherViewBuckets[$bucketKey]
                    if ($null -eq $bucket) {
                        $bucket = [System.Collections.Generic.List[object]]::new()
                        $otherViewBuckets[$bucketKey] = $bucket
                    }
                    if ($bucket.Count -ge $MaxUsersInHtml) { $bucket = $null }
                }
                if ($null -ne $bucket -or $isAdmin) {
                    $view = [pscustomobject]@{
                        DisplayName       = $displayName
                        UserPrincipalName = $upn
                        Department        = $department
                        AdminText         = if ($isAdmin) { 'Yes' } else { '' }
                        LadderKey         = $ladderKey
                        Rank              = $bestRank
                        PrMethods         = $methodProfile.PrShortNames
                        Methods           = $methodProfile.ShortNames
                        PasskeyCount      = $passkeyCount
                        FirstPr           = $firstPr
                        LastPrUse         = $lastPrUse
                        PasskeyPolicy     = $passkeyPolicy.Text
                    }
                    if ($null -ne $bucket) { $bucket.Add($view) }
                    if ($isAdmin) { $adminViews.Add($view) }
                }
            }
        }
    }
    finally {
        Write-Progress -Activity 'Analysing users' -Completed
        $detailWriter.Dispose()
        if ($usersWriter) { $usersWriter.Dispose() }
    }

    # Per-method, per-group and per-policy user counts, from the shared method profiles
    $methodUserCounts = @{}
    $groupUserCounts = @{}
    $configUserCounts = @{}
    foreach ($methodProfile in $methodProfiles.Values) {
        foreach ($key in $methodProfile.Keys) { $methodUserCounts[$key] = $methodProfile.Users + [int]$methodUserCounts[$key] }
        foreach ($groupKey in $methodProfile.Groups) { $groupUserCounts[$groupKey] = $methodProfile.Users + [int]$groupUserCounts[$groupKey] }
        foreach ($configId in $methodProfile.Configs) { $configUserCounts[$configId] = $methodProfile.Users + [int]$configUserCounts[$configId] }
    }

    # ----- Aggregates -----
    $methodStats = @(@(foreach ($key in $methodUserCounts.Keys) {
                $definition = $MethodCatalog[$key]
                [pscustomobject]@{ Key = $key; Name = $definition.Name; Short = $definition.Short; Group = $definition.Group; Rank = $definition.Rank; Order = $definition.Order; Users = [int]$methodUserCounts[$key] }
            }) | Sort-Object -Property Rank, @{ Expression = 'Users'; Descending = $true }, Order)

    # Cumulative phishing-resistant users by month of first registration (last 24 months)
    $firstPrDates.Sort()
    $now = (Get-Date).ToUniversalTime()
    $newPr30 = 0
    foreach ($date in $firstPrDates) { if ($date -ge $now.AddDays(-30)) { $newPr30++ } }
    $trend = [System.Collections.Generic.List[object]]::new()
    if ($firstPrDates.Count -gt 0) {
        # Months run in Irish time, like every date in the report; each month's start is compared in UTC
        $today = ConvertTo-ReportTime $now
        $firstMonth = ConvertTo-ReportTime $firstPrDates[0]
        $endMonth = [datetime]::new($today.Year, $today.Month, 1)
        $startMonth = [datetime]::new($firstMonth.Year, $firstMonth.Month, 1)
        if ($startMonth -lt $endMonth.AddMonths(-23)) { $startMonth = $endMonth.AddMonths(-23) }
        if ($startMonth -gt $endMonth) { $startMonth = $endMonth }
        $index = 0
        $cumulative = 0
        $month = $startMonth
        while ($month -le $endMonth) {
            $nextMonth = $month.AddMonths(1)
            $monthStartUtc = [TimeZoneInfo]::ConvertTimeToUtc($month, $ReportTimeZone)
            $nextMonthUtc = [TimeZoneInfo]::ConvertTimeToUtc($nextMonth, $ReportTimeZone)
            $newCount = 0
            while ($index -lt $firstPrDates.Count -and $firstPrDates[$index] -lt $nextMonthUtc) {
                if ($firstPrDates[$index] -ge $monthStartUtc) { $newCount++ }
                $cumulative++
                $index++
            }
            $trend.Add([pscustomobject]@{ Month = $month; Cumulative = $cumulative; New = $newCount })
            $month = $nextMonth
        }
    }

    $formFactorRows = @(foreach ($name in $FormFactorOrder) {
            $stat = $formFactorStats[$name]
            if (-not $stat) { continue }
            $kind = if ($name -eq 'Hardware security key') { 'Hardware' } elseif ($name -eq 'Unidentified') { 'Unknown' } else { 'Software' }
            [pscustomobject]@{ Name = $name; Kind = $kind; DeviceBound = $stat.DeviceBound; Synced = $stat.Synced; Unknown = $stat.Unknown; Total = $stat.Total; Users = $stat.UserIds.Count; Attested = $stat.Attested; Recent = $stat.Recent }
        })
    $providerRows = @(@(foreach ($provider in $providerStats.Values) {
                [pscustomobject]@{ Provider = $provider.Provider; FormFactor = $provider.FormFactor; Storage = $provider.Storage; Aaguid = $provider.Aaguid; Credentials = $provider.Credentials; Users = $provider.UserIds.Count; Attested = $provider.Attested; LastUsed = $provider.LastUsed }
            }) | Sort-Object -Property @{ Expression = 'Credentials'; Descending = $true }, Provider, FormFactor, Storage)

    $methodPolicyRows = @()
    $passkeyProfileRows = @()
    if ($policyAvailable) {
        $methodPolicyRows = @(foreach ($config in $methodConfigs) {
                $odataType = [string]$config['@odata.type']
                if ($odataType -and $odataType -notmatch 'AuthenticationMethodConfiguration$') { continue }
                if ([string]$config.state -ne 'enabled') { continue }
                $source = if ([string]$config.id -eq 'Fido2' -and $fido2Config) { $fido2Config } else { $config }
                $registered = $null
                if ($odataType -match 'externalAuthenticationMethodConfiguration') { $registered = [int]$methodUserCounts['ExternalMfa'] }
                elseif ($ConfigMethodKeys.ContainsKey([string]$config.id)) { $registered = [int]$configUserCounts[[string]$config.id] }
                [pscustomobject]@{
                    Id         = [string]$config.id
                    Name       = Get-MethodConfigName -Config $source
                    Targets    = Get-PolicyTargetSummary -Config $source
                    Settings   = Get-MethodConfigSettings -Config $source
                    Registered = $registered
                }
            })
        if ($fido2Config) {
            $passkeyProfileRows = @(foreach ($passkeyProfile in @($fido2Config.passkeyProfiles | Where-Object { $_ })) {
                    $types = @(((@($passkeyProfile.passkeyTypes) -join ',') -split ',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                    $typesText = Format-PasskeyTypes -Types $types
                    $typesText = $typesText.Substring(0, 1).ToUpperInvariant() + $typesText.Substring(1)
                    $restrictions = $passkeyProfile.keyRestrictions
                    $restrictionText = 'None'
                    if ($restrictions -and $restrictions.isEnforced) {
                        $restrictionText = "$(if ([string]$restrictions.enforcementType -eq 'allow') { 'Only allows' } else { 'Blocks' }): $(Get-AaguidListText -Aaguids $restrictions.aaGuids)"
                    }
                    $assigned = @(foreach ($target in @($fido2Config.includeTargets | Where-Object { $_ })) {
                            if (@($target.allowedPasskeyProfiles) -contains [string]$passkeyProfile.id) { Get-TargetName -TargetId ([string]$target.id) }
                        })
                    [pscustomobject]@{
                        Name            = [string]$passkeyProfile.name
                        Types           = if ($types.Count) { $typesText } else { 'Not set' }
                        Attestation     = if ([string]$passkeyProfile.attestationEnforcement -and [string]$passkeyProfile.attestationEnforcement -ne 'disabled') { 'Enforced' } else { 'Not enforced' }
                        KeyRestrictions = $restrictionText
                        AssignedTo      = if ($assigned.Count) { $assigned -join ', ' } else { 'Not assigned' }
                    }
                })
        }
    }

    $otherViews = [System.Collections.Generic.List[object]]::new()
    foreach ($rank in 6..2) {
        foreach ($adminFlag in 1, 0) {
            $bucket = $otherViewBuckets["$rank|$adminFlag"]
            if ($null -eq $bucket) { continue }
            foreach ($view in $bucket) {
                if ($otherViews.Count -ge $MaxUsersInHtml) { break }
                $otherViews.Add($view)
            }
        }
    }
    $adminViewsSorted = @($adminViews | Sort-Object -Property @{ Expression = 'Rank'; Descending = $true }, DisplayName)
    $departments = @($departmentStats.Values | Sort-Object -Property @{ Expression = 'Users'; Descending = $true }, Name)

    # ----- HTML report -----
    Write-Step 'Building the HTML report...'

    $model = @{
        ReportTitle              = $ReportTitle
        TenantName               = $tenantName
        TenantDomain             = $tenantDomain
        Account                  = [string]$context.Account
        GeneratedText            = (ConvertTo-ReportTime $runStarted).ToString('d MMM yyyy HH:mm', [Globalization.CultureInfo]::InvariantCulture)
        TotalUsers               = $users.Length
        LadderCounts             = $ladderCounts
        AdminLadderCounts        = $adminLadderCounts
        AdminTotal               = $adminTotal
        AdminPrCount             = [int]$adminLadderCounts['PhishingResistant']
        Admins                   = $adminViewsSorted
        MethodStats              = $methodStats
        GroupUserCounts          = $groupUserCounts
        PasskeyStats             = $passkeyStats
        PasskeyFormFactors       = $formFactorRows
        PasskeyProviders         = $providerRows
        PasskeyUserCount         = $passkeyUserCount
        Trend                    = $trend.ToArray()
        TrendUndated             = $undatedPrUsers
        NewPr30                  = if ($firstPrDates.Count -gt 0) { $newPr30 } else { $null }
        Departments              = $departments
        PolicyAvailable          = $policyAvailable
        Fido2Enabled             = ($fido2Config -and [string]$fido2Config.state -eq 'enabled')
        PasskeyEnabledCount      = $passkeyScope.Count
        PasskeyEnabledRegistered = $passkeyEnabledRegistered
        SyncedAllowedCount       = $syncedAllowed
        DeviceBoundAllowedCount  = $deviceBoundAllowed
        CbaEnabled               = ($x509Config -and [string]$x509Config.state -eq 'enabled')
        CbaEnabledCount          = $cbaScope.Count
        MethodPolicyRows         = $methodPolicyRows
        PasskeyProfileRows       = $passkeyProfileRows
        CaAvailable              = $caAvailable
        CaRows                   = $caRows
        ShowUsers                = $showUsers
        UsersOnly                = [bool]$UsersOnly
        PrUsers                  = $prViews.ToArray()
        OtherUsers               = $otherViews.ToArray()
        Warnings                 = $ReportWarnings.ToArray()
    }
    $reportHtml = New-ReportHtml -Model $model
    [System.IO.File]::WriteAllText($htmlPath, $reportHtml, (New-Object System.Text.UTF8Encoding($false)))

    # ----- Summary -----
    $total = $users.Length
    $prTotal = [int]$ladderCounts['PhishingResistant']
    Write-Information '' -InformationAction Continue
    Write-Information "$ReportTitle report complete" -InformationAction Continue
    Write-Information ("  Users in scope              : {0}" -f (Format-Count $total)) -InformationAction Continue
    Write-Information ("  Phishing-resistant          : {0} ({1})" -f (Format-Count $prTotal), (Format-Percent $prTotal $total)) -InformationAction Continue
    Write-Information ("  No MFA method               : {0}" -f (Format-Count ([int]$ladderCounts['RecoveryOnly'] + [int]$ladderCounts['None']))) -InformationAction Continue
    Write-Information ("  Passkeys                    : {0} (device-bound {1}, synced {2}, hardware keys {3})" -f (Format-Count $passkeyStats.Total), (Format-Count $passkeyStats.DeviceBound), (Format-Count $passkeyStats.Synced), (Format-Count $passkeyStats.Hardware)) -InformationAction Continue
    Write-Information "  Output folder               : $runFolder" -InformationAction Continue
    Write-Information "  HTML report                 : $([System.IO.Path]::GetFileName($htmlPath))" -InformationAction Continue
    Write-Information "  Users (CSV)                 : $([System.IO.Path]::GetFileName($usersPath))" -InformationAction Continue
    Write-Information "  Registered methods (CSV)    : $([System.IO.Path]::GetFileName($detailPath))" -InformationAction Continue
    Write-Information '  These files list users and their sign-in methods, so store and share them with care.' -InformationAction Continue

    if (-not $NoOpen) {
        try { Invoke-Item -LiteralPath $htmlPath } catch { Write-Verbose "Couldn't open the report: $($_.Exception.Message)" }
    }
}
catch {
    Write-Error "Script failed: $($_.Exception.Message)"
    exit 1
}
finally {
    try {
        $null = Disconnect-MgGraph -ErrorAction SilentlyContinue
        Write-Information 'Disconnected from Microsoft Graph' -InformationAction Continue
    }
    catch {
        # Ignore disconnect errors
    }
}
