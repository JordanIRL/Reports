#requires -Version 7.0
#requires -PSEdition Core

<#
.SYNOPSIS
    Generates the Intune Reports Excel workbook without VBA or a companion EXE.

.DESCRIPTION
    Uses Windows Web Account Manager (WAM) through the official Microsoft Graph
    PowerShell authentication module, reads Microsoft Intune data from Microsoft
    Graph, and writes a macro-free .xlsx workbook through desktop Excel. The
    Graph authentication context is limited to this PowerShell process.

.PARAMETER OutputPath
    Destination .xlsx path. The parent directory is created when necessary.

.PARAMETER Tenant
    Microsoft Entra tenant ID or tenant domain. Defaults to "organizations".

.PARAMETER Open
    Opens the saved workbook after generation.

.PARAMETER Force
    Replaces an existing output file.

.EXAMPLE
    pwsh -File .\Generate-IntuneExcelReport.ps1

.NOTES
    Requirements: Windows, PowerShell 7, desktop Microsoft Excel, and the
    Microsoft.Graph.Authentication module from PowerShell Gallery (auto-installed
    for the current user if missing).

    Delegated permissions (all read-only):
      DeviceManagementManagedDevices.Read.All
      DeviceManagementConfiguration.Read.All
      DeviceManagementApps.Read.All
      DeviceManagementServiceConfig.Read.All
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string] $OutputPath = (Join-Path -Path (Get-Location).Path -ChildPath ("IntuneReports-{0:yyyyMMdd-HHmmss}.xlsx" -f (Get-Date))),

    [Parameter()]
    [ValidatePattern('^(organizations|common|consumers|[0-9a-fA-F-]{36}|[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,})$')]
    [string] $Tenant = 'organizations',

    [Parameter()]
    [switch] $Open,

    [Parameter()]
    [switch] $Force
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:AppVersion = '1.0.2'
$script:GraphBase = 'https://graph.microsoft.com/beta'
$script:GraphRoot = 'https://graph.microsoft.com'
$script:Scopes = @(
    'DeviceManagementManagedDevices.Read.All'
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementApps.Read.All'
    'DeviceManagementServiceConfig.Read.All'
)
$script:Tenant = $Tenant
$script:GraphConnected = $false
$script:UserLabel = 'unknown'
$script:AuthMethod = 'unknown'
$script:MaximumDataRows = 1048573

function Write-ReportStatus {
    param([Parameter(Mandatory)][string] $Message)
    Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Message)
}

function Get-ObjectValue {
    param(
        [AllowNull()][object] $InputObject,
        [Parameter(Mandatory)][string] $Name,
        [AllowNull()][object] $Default = $null
    )
    if ($null -eq $InputObject) { return $Default }
    if ($InputObject -is [Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -ieq $Name) {
                $dictionaryValue = $InputObject[$key]
                if ($null -eq $dictionaryValue) { return $Default }
                return $dictionaryValue
            }
        }
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) { return $Default }
    return $property.Value
}

function Test-ObjectProperty {
    param(
        [AllowNull()][object] $InputObject,
        [Parameter(Mandatory)][string] $Name
    )
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [Collections.IDictionary]) {
        foreach ($key in $InputObject.Keys) {
            if ([string]$key -ieq $Name) { return $true }
        }
        return $false
    }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Get-ObjectString {
    param([AllowNull()][object] $InputObject, [Parameter(Mandatory)][string] $Name)
    $value = Get-ObjectValue -InputObject $InputObject -Name $Name
    if ($null -eq $value) { return '' }
    return [string]$value
}

function Get-ObjectNumber {
    param([AllowNull()][object] $InputObject, [Parameter(Mandatory)][string] $Name)
    $value = Get-ObjectValue -InputObject $InputObject -Name $Name
    if ($null -eq $value) { return 0.0 }
    $number = 0.0
    if ([double]::TryParse([string]$value, [Globalization.NumberStyles]::Any,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) {
        return $number
    }
    return 0.0
}

function ConvertFrom-GraphDate {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim()
    if ([string]::IsNullOrWhiteSpace($text) -or $text.StartsWith('0001-', [StringComparison]::Ordinal)) {
        return $null
    }
    try {
        return [DateTimeOffset]::Parse(
            $text,
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal
        ).UtcDateTime
    }
    catch {
        return $text
    }
}

function ConvertTo-CleanReportCell {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        # Intune report actions do not expose column types consistently. Only
        # parse unambiguous Graph ISO date-times; labels such as "May 2024" or
        # version text such as "2024-01" must remain text.
        if ($Value -match '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$') {
            return ConvertFrom-GraphDate -Value $Value
        }
        return $Value
    }
    if ($Value -is [Collections.IDictionary] -or
        ($Value -is [Collections.IEnumerable] -and $Value -isnot [string])) {
        return $null
    }
    return $Value
}

function Protect-ExcelText {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -isnot [string]) { return $Value }
    # Prefixing every string keeps identifiers, dates, scientific notation, and
    # formula-like text as literal text. Excel does not display the apostrophe.
    return "'$Value"
}

function ConvertTo-NormalizedName {
    param([AllowNull()][string] $Value)
    if ([string]::IsNullOrWhiteSpace($Value)) { return '' }
    return [regex]::Replace($Value.ToLowerInvariant(), '[^a-z0-9]', '')
}

function ConvertTo-PrettyHeader {
    param([Parameter(Mandatory)][string] $Value)
    $text = $Value.Replace('_', ' ')
    if ($text.Contains(' ') -or $text.Length -lt 4) { return $text }
    $text = [regex]::Replace($text, '([a-z0-9])([A-Z])', '$1 $2')
    $text = [regex]::Replace($text, '([A-Z])([A-Z][a-z])', '$1 $2')
    return $text
}

function ConvertTo-ComplianceLabel {
    param([AllowNull()][string] $Value)
    switch ($Value.Trim().ToLowerInvariant()) {
        'compliant'     { 'Compliant' }
        'noncompliant'  { 'Noncompliant' }
        'ingraceperiod' { 'In grace period' }
        'error'         { 'Error' }
        'conflict'      { 'Conflict' }
        'configmanager' { 'Config Manager' }
        'unknown'       { 'Unknown' }
        default         { $Value }
    }
}

function ConvertTo-OwnerLabel {
    param([AllowNull()][string] $Value)
    switch ($Value.Trim().ToLowerInvariant()) {
        'company'  { 'Corporate' }
        'personal' { 'Personal' }
        default    { $Value }
    }
}

function ConvertTo-EnrollmentLabel {
    param([AllowNull()][string] $Value)
    switch ($Value.Trim().ToLowerInvariant()) {
        'unknown'                               { 'Unknown' }
        'userenrollment'                        { 'User enrollment' }
        'deviceenrollmentmanager'               { 'Device Enrollment Manager' }
        'applebulkwithuser'                     { 'Apple Automated Device Enrollment (with user affinity)' }
        'applebulkwithoutuser'                  { 'Apple Automated Device Enrollment (without user affinity)' }
        'windowsazureadjoin'                    { 'Microsoft Entra joined' }
        'windowsbulkuserless'                   { 'Windows bulk enrollment (userless)' }
        'windowsautoenrollment'                 { 'Windows automatic enrollment' }
        'windowsbulkazuredomainjoin'            { 'Microsoft Entra joined (bulk)' }
        'windowscomanagement'                   { 'Windows co-management' }
        'windowsazureadjoinusingdeviceauth'     { 'Microsoft Entra joined (device authentication)' }
        'appleuserenrollment'                   { 'Apple User Enrollment' }
        'appleuserenrollmentwithserviceaccount' { 'Apple User Enrollment (service account)' }
        default                                 { $Value }
    }
}

function ConvertTo-PlatformLabel {
    param([AllowNull()][string] $ODataType)
    $type = $ODataType.ToLowerInvariant().Replace('#microsoft.graph.', '')
    if ($type -match 'windows10|windows81|windowsphone') { return 'Windows' }
    if ($type -match 'macos') { return 'macOS' }
    if ($type -match 'ioscompliance' -or $type.StartsWith('ios')) { return 'iOS/iPadOS' }
    if ($type -match 'aosp') { return 'Android (AOSP)' }
    if ($type -match 'androiddeviceowner') { return 'Android Enterprise (corporate)' }
    if ($type -match 'androidworkprofile|androidforwork') { return 'Android Enterprise (work profile)' }
    if ($type -match 'android') { return 'Android' }
    if ($type -match 'linux') { return 'Linux' }
    if ($type -match 'default') { return 'Built-in' }
    return $ODataType.Replace('#microsoft.graph.', '')
}

function Convert-BytesToGiB {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) { return $null }
    $number = 0.0
    if (-not [double]::TryParse([string]$Value, [Globalization.NumberStyles]::Any,
            [Globalization.CultureInfo]::InvariantCulture, [ref]$number)) { return $null }
    if ($number -lt 0) { return $null }
    return [math]::Round($number / 1073741824.0, 1)
}

function Get-DeviceUserEmail {
    param([Parameter(Mandatory)][object] $Device)
    $email = (Get-ObjectString $Device 'emailAddress').Trim()
    if ([string]::IsNullOrWhiteSpace($email)) {
        $email = (Get-ObjectString $Device 'userPrincipalName').Trim()
    }
    return $email
}

function Get-WholeDaysSince {
    param([AllowNull()][object] $DateValue)
    if ($DateValue -isnot [datetime]) { return $null }
    return [math]::Floor(([datetime]::UtcNow - ([datetime]$DateValue).ToUniversalTime()).TotalDays)
}

function Get-DeviceModelLabel {
    param([AllowNull()][string] $Manufacturer, [AllowNull()][string] $Model)
    if (-not [string]::IsNullOrWhiteSpace($Model)) { return $Model.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($Manufacturer)) { return $Manufacturer.Trim() }
    return '(unknown)'
}

function Get-DashboardOsLabel {
    param([AllowNull()][string] $OperatingSystem, [AllowNull()][string] $EnrollmentType)
    $osKey = $OperatingSystem.Trim().ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($osKey)) { return '(unknown)' }
    if (-not $osKey.StartsWith('android')) { return $OperatingSystem }
    switch ($EnrollmentType.Trim().ToLowerInvariant()) {
        'androidenterprisecorporateworkprofile' { 'Android COPE' }
        'androidenterprisefullymanaged'         { 'Android Fully managed' }
        'androidenterprisededicateddevice'      { 'Android Dedicated' }
        default                                 { 'Android (other)' }
    }
}

function Test-TrustedGraphUri {
    param([Parameter(Mandatory)][string] $Uri)
    $parsed = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed)) { return $false }
    return $parsed.Scheme -eq 'https' -and
        $parsed.Host.Equals('graph.microsoft.com', [StringComparison]::OrdinalIgnoreCase) -and
        ($parsed.IsDefaultPort -or $parsed.Port -eq 443)
}

function Get-GraphAuthenticationModule {
    param([Parameter(Mandatory)][version] $MinimumVersion)
    return Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' |
        Where-Object Version -GE $MinimumVersion |
        Sort-Object Version -Descending |
        Select-Object -First 1
}

function Assert-GraphAuthenticationModule {
    $minimumVersion = [version]'2.35.1'
    $module = Get-GraphAuthenticationModule -MinimumVersion $minimumVersion

    # When the module is completely absent, install it from the PowerShell Gallery
    # for the current user so the script is zero-setup. An outdated build is left
    # untouched (updating shared modules can affect other tooling); the caller is
    # asked to update it instead, below.
    if ($null -eq $module -and
        $null -eq (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
        Write-ReportStatus 'Microsoft.Graph.Authentication is not installed; installing it from the PowerShell Gallery for the current user...'
        try {
            if ($null -eq (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
                Install-PackageProvider -Name NuGet -Scope CurrentUser -Force -ErrorAction Stop | Out-Null
            }
            Install-Module -Name 'Microsoft.Graph.Authentication' -Scope CurrentUser `
                -MinimumVersion $minimumVersion -Repository PSGallery -Force -AllowClobber -ErrorAction Stop
            $module = Get-GraphAuthenticationModule -MinimumVersion $minimumVersion
        }
        catch {
            throw @"
Microsoft.Graph.Authentication $minimumVersion or newer is required for WAM sign-in, and automatic installation failed ($($_.Exception.Message)). Install the official Microsoft module manually, then run this script again:

  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery
"@
        }
    }

    if ($null -eq $module) {
        throw @"
Microsoft.Graph.Authentication $minimumVersion or newer is required for WAM sign-in. Install or update the official Microsoft module, then run this script again:

  Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Repository PSGallery
"@
    }

    Import-Module $module.Path -ErrorAction Stop
    foreach ($commandName in @('Connect-MgGraph','Disconnect-MgGraph','Get-MgContext','Invoke-MgGraphRequest')) {
        if ($null -eq (Get-Command $commandName -ErrorAction SilentlyContinue)) {
            throw "The installed Microsoft.Graph.Authentication module does not provide $commandName. Update the module and try again."
        }
    }

    $requestCommand = Get-Command 'Invoke-MgGraphRequest' -ErrorAction Stop
    foreach ($parameterName in @('SkipHttpErrorCheck','StatusCodeVariable','ResponseHeadersVariable','OutputType')) {
        if (-not $requestCommand.Parameters.ContainsKey($parameterName)) {
            throw "The installed Microsoft.Graph.Authentication module is too old: Invoke-MgGraphRequest lacks -$parameterName. Update the module and try again."
        }
    }
}

function Test-ConsoleWindowAvailable {
    # The WAM broker anchors its account picker to a parent window handle, which the
    # Microsoft Graph SDK derives from GetConsoleWindow(). ConPTY-based hosts (Windows
    # Terminal, the VS Code integrated terminal, and other embedded terminals) expose
    # no console window, so GetConsoleWindow() returns 0 and WAM fails with
    # "A window handle must be configured." Detect that up front so we can choose a
    # sign-in method that does not require a window handle.
    try {
        if (-not ('IntuneReport.NativeWindow' -as [type])) {
            Add-Type -Namespace 'IntuneReport' -Name 'NativeWindow' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll")]
public static extern System.IntPtr GetConsoleWindow();
'@ -ErrorAction Stop | Out-Null
        }
        return [IntuneReport.NativeWindow]::GetConsoleWindow() -ne [IntPtr]::Zero
    }
    catch {
        return $false
    }
}

function Connect-IntuneGraph {
    if (-not [Environment]::UserInteractive) {
        throw 'Interactive sign-in requires an active interactive Windows user session.'
    }
    Assert-GraphAuthenticationModule

    # Prefer the native Windows account picker (WAM) when this host can anchor it, and
    # fall back to device-code sign-in (which needs no window handle) otherwise. The
    # interactive-browser flow is intentionally omitted: on this SDK version it still
    # routes through the WAM broker and fails identically when there is no console
    # window handle, so device code is the reliable fallback for embedded terminals.
    $methods = [Collections.Generic.List[hashtable]]::new()
    if (Test-ConsoleWindowAvailable) {
        $methods.Add(@{ Name = 'WAM'; DeviceCode = $false; Timeout = 120
            Status = 'Opening the Windows account picker (WAM)...' })
    }
    else {
        Write-ReportStatus 'This terminal exposes no console window handle, so WAM cannot open its account picker here; using device-code sign-in instead.'
    }
    $methods.Add(@{ Name = 'device code'; DeviceCode = $true; Timeout = 900
        Status = 'Starting device-code sign-in - open the URL shown below and enter the code to continue...' })

    $connected = $false
    $lastError = $null
    foreach ($method in $methods) {
        # No ClientId is supplied, so Connect-MgGraph uses its built-in Microsoft Graph
        # Command Line Tools application, which is already registered with the redirect
        # URIs that both WAM and device-code sign-in require.
        $connectParams = @{
            TenantId      = $script:Tenant
            Scopes        = $script:Scopes
            ContextScope  = 'Process'
            Environment   = 'Global'
            ClientTimeout = $method.Timeout
            NoWelcome     = $true
            ErrorAction   = 'Stop'
        }
        if ($method.DeviceCode) { $connectParams['UseDeviceCode'] = $true }

        Write-ReportStatus $method.Status
        try {
            # Merge the Information stream (6) into the pipeline and re-emit it via
            # Write-Host. The device-code prompt is written on the Information stream,
            # which PowerShell suppresses by default; without this the code stays hidden
            # and the sign-in times out with no visible instructions.
            Microsoft.Graph.Authentication\Connect-MgGraph @connectParams 6>&1 | ForEach-Object {
                $line = if ($_ -is [Management.Automation.InformationRecord]) { [string]$_.MessageData } else { [string]$_ }
                if (-not [string]::IsNullOrWhiteSpace($line)) { Write-Host $line }
            }
            $script:GraphConnected = $true
            $script:AuthMethod = $method.Name
            $connected = $true
            break
        }
        catch {
            $lastError = $_
            $script:GraphConnected = $false
            try { Microsoft.Graph.Authentication\Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
            if ($method -ne $methods[$methods.Count - 1]) {
                Write-ReportStatus ("{0} sign-in did not complete ({1}); trying the next method..." -f $method.Name, $_.Exception.Message)
            }
        }
    }

    if (-not $connected) {
        $detail = if ($null -ne $lastError) { $lastError.Exception.Message } else { 'no interactive sign-in method was available.' }
        throw "Interactive Microsoft Graph sign-in failed. $detail"
    }

    $context = Microsoft.Graph.Authentication\Get-MgContext -ErrorAction Stop
    if ($null -eq $context -or [string]::IsNullOrWhiteSpace([string]$context.Account)) {
        throw 'Sign-in completed without an authenticated Microsoft Graph user context.'
    }
    if ([string]$context.AuthType -ne 'Delegated') {
        throw "Expected delegated authentication, but Microsoft Graph returned '$($context.AuthType)'."
    }

    $grantedScopes = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($scope in @($context.Scopes)) { [void]$grantedScopes.Add([string]$scope) }
    $missingScopes = @($script:Scopes | Where-Object { -not $grantedScopes.Contains($_) })
    if ($missingScopes.Count -gt 0) {
        throw "The signed-in context is missing required delegated permission(s): $($missingScopes -join ', ')."
    }

    $script:UserLabel = [string]$context.Account
    Write-ReportStatus ("Signed in as {0} via {1}." -f $script:UserLabel, $script:AuthMethod)
    return $context
}

function Get-GraphHeaderValue {
    param([AllowNull()][object] $Headers, [Parameter(Mandatory)][string] $Name)
    if ($null -eq $Headers) { return '' }
    try {
        if ($Headers -is [Collections.IDictionary]) {
            foreach ($key in $Headers.Keys) {
                if ([string]$key -ieq $Name) {
                    return [string](@($Headers[$key]) | Select-Object -First 1)
                }
            }
        }
        $values = $null
        if ($Headers.PSObject.Methods['TryGetValues'] -and $Headers.TryGetValues($Name, [ref]$values)) {
            return [string](@($values) | Select-Object -First 1)
        }
        $property = $Headers.PSObject.Properties[$Name]
        if ($null -ne $property) { return [string](@($property.Value) | Select-Object -First 1) }
    }
    catch { }
    return ''
}

function Get-RetryDelaySeconds {
    param([Parameter(Mandatory)][object] $Response, [Parameter(Mandatory)][int] $Attempt)
    $retryAfter = Get-GraphHeaderValue -Headers $Response.Headers -Name 'Retry-After'
    $seconds = 0
    if ([int]::TryParse($retryAfter, [ref]$seconds) -and $seconds -ge 0) {
        return [double]$seconds
    }
    $retryDate = [DateTimeOffset]::MinValue
    if ([DateTimeOffset]::TryParse($retryAfter, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$retryDate)) {
        return [math]::Max(0.0, [math]::Ceiling(($retryDate.UtcDateTime - [datetime]::UtcNow).TotalSeconds))
    }
    $retryMs = Get-GraphHeaderValue -Headers $Response.Headers -Name 'x-ms-retry-after-ms'
    $milliseconds = 0
    if ([int]::TryParse($retryMs, [ref]$milliseconds) -and $milliseconds -ge 0) {
        return $milliseconds / 1000.0
    }
    return [math]::Min(32.0, [math]::Pow(2, $Attempt - 1) + (Get-Random -Minimum 0 -Maximum 750) / 1000.0)
}

function New-GraphException {
    param(
        [Parameter(Mandatory)][int] $StatusCode,
        [AllowNull()][object] $Payload,
        [Parameter(Mandatory)][string] $Uri
    )
    $code = ''
    $message = ''
    $errorObject = Get-ObjectValue $Payload 'error'
    if ($null -ne $errorObject) {
        $code = Get-ObjectString $errorObject 'code'
        $message = Get-ObjectString $errorObject 'message'
    }
    if ([string]::IsNullOrWhiteSpace($message)) { $message = 'Microsoft Graph request failed.' }
    $exception = [InvalidOperationException]::new("Graph HTTP $StatusCode ($code): $message")
    $exception.Data['StatusCode'] = $StatusCode
    $exception.Data['GraphErrorCode'] = $code
    $exception.Data['GraphUri'] = $Uri
    return $exception
}

function Test-GraphTransportError {
    param([Parameter(Mandatory)][Management.Automation.ErrorRecord] $ErrorRecord)
    if ($ErrorRecord.CategoryInfo.Category -in @(
            [Management.Automation.ErrorCategory]::ConnectionError,
            [Management.Automation.ErrorCategory]::ResourceUnavailable,
            [Management.Automation.ErrorCategory]::OperationTimeout
        )) { return $true }
    $exception = $ErrorRecord.Exception
    while ($null -ne $exception) {
        if ($exception -is [Net.Http.HttpRequestException] -or
            $exception -is [Net.WebException] -or
            $exception -is [TimeoutException] -or
            $exception -is [Threading.Tasks.TaskCanceledException]) { return $true }
        $exception = $exception.InnerException
    }
    return $false
}

function Invoke-IntuneGraphRequest {
    param(
        [Parameter(Mandatory)][ValidateSet('GET', 'POST')][string] $Method,
        [Parameter(Mandatory)][string] $Uri,
        [AllowNull()][object] $Body = $null,
        [switch] $StreamJsonResponse
    )
    if (-not (Test-TrustedGraphUri -Uri $Uri)) {
        throw "Refusing to send an authenticated Graph request to an untrusted URL: $Uri"
    }

    for ($attempt = 1; $attempt -le 7; $attempt++) {
        try {
            $invoke = @{
                Uri                     = $Uri
                Method                  = $Method
                Headers                 = @{ Accept = 'application/json' }
                SkipHttpErrorCheck      = $true
                StatusCodeVariable      = 'graphStatusCode'
                ResponseHeadersVariable = 'graphResponseHeaders'
                OutputType              = 'Json'
                ErrorAction             = 'Stop'
            }
            if ($null -ne $Body) {
                $invoke.ContentType = 'application/json'
                $invoke.Body = if ($Body -is [string]) { $Body } else { $Body | ConvertTo-Json -Depth 30 -Compress }
            }
            $graphStatusCode = $null
            $graphResponseHeaders = $null
            $rawContent = $null
            $streamContentType = ''
            if ($StreamJsonResponse) {
                $httpResponse = $null
                try {
                    $invoke.OutputType = 'HttpResponseMessage'
                    $httpResponse = Microsoft.Graph.Authentication\Invoke-MgGraphRequest @invoke
                    if ($httpResponse -isnot [Net.Http.HttpResponseMessage]) {
                        throw 'Microsoft Graph returned no HTTP response message.'
                    }
                    if ($null -eq $graphStatusCode) { $graphStatusCode = [int]$httpResponse.StatusCode }
                    if ($null -eq $graphResponseHeaders) { $graphResponseHeaders = $httpResponse.Headers }
                    if ($null -ne $httpResponse.Content) {
                        if ($null -ne $httpResponse.Content.Headers.ContentType) {
                            $streamContentType = [string]$httpResponse.Content.Headers.ContentType.MediaType
                        }
                        $rawContent = $httpResponse.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                    }
                }
                finally {
                    if ($null -ne $httpResponse) { $httpResponse.Dispose() }
                }
            }
            else {
                $rawContent = Microsoft.Graph.Authentication\Invoke-MgGraphRequest @invoke
            }
            if ($null -eq $graphStatusCode) {
                throw 'Microsoft Graph returned no HTTP status code.'
            }
            $status = [int]$graphStatusCode
            $payload = $null
            if (-not [string]::IsNullOrWhiteSpace([string]$rawContent)) {
                try {
                    $payload = [string]$rawContent | ConvertFrom-Json -Depth 100
                }
                catch {
                    if ($status -ge 200 -and $status -lt 300) {
                        if ($StreamJsonResponse) {
                            $contentLabel = if ([string]::IsNullOrWhiteSpace($streamContentType)) {
                                'streamed'
                            } else { $streamContentType }
                            $exception = [IO.InvalidDataException]::new(
                                "Microsoft Graph returned an invalid $contentLabel report response."
                            )
                            $exception.Data['ReportFormat'] = $true
                            $exception.Data['GraphUri'] = $Uri
                            throw $exception
                        }
                        throw
                    }
                }
            }
            if ($status -ge 200 -and $status -lt 300) {
                if ($StreamJsonResponse -and $null -eq $payload) {
                    $exception = [IO.InvalidDataException]::new('Microsoft Graph returned an empty streamed report response.')
                    $exception.Data['ReportFormat'] = $true
                    $exception.Data['GraphUri'] = $Uri
                    throw $exception
                }
                return $payload
            }

            if ($status -in @(408, 429, 500, 502, 503, 504) -and $attempt -lt 7) {
                $delay = Get-RetryDelaySeconds -Response ([pscustomobject]@{ Headers = $graphResponseHeaders }) -Attempt $attempt
                Write-ReportStatus "Graph returned HTTP $status; retrying in $([math]::Round($delay, 1)) seconds."
                Start-Sleep -Milliseconds ([int]($delay * 1000))
                continue
            }
            throw (New-GraphException -StatusCode $status -Payload $payload -Uri $Uri)
        }
        catch {
            if ($_.Exception.Data.Contains('StatusCode')) { throw }
            if (-not (Test-GraphTransportError $_)) { throw }
            if ($attempt -ge 7) { throw }
            $delay = [math]::Min(32.0, [math]::Pow(2, $attempt - 1) + (Get-Random -Minimum 0 -Maximum 750) / 1000.0)
            Write-ReportStatus "Graph transport error; retrying in $([math]::Round($delay, 1)) seconds."
            Start-Sleep -Milliseconds ([int]($delay * 1000))
        }
    }
    throw 'Microsoft Graph retry limit was reached.'
}

function Test-QueryFallbackAllowed {
    param([Parameter(Mandatory)][Management.Automation.ErrorRecord] $ErrorRecord)
    $status = [int]$ErrorRecord.Exception.Data['StatusCode']
    $code = [string]$ErrorRecord.Exception.Data['GraphErrorCode']
    if ($status -in @(405, 501)) { return $true }
    if ($status -eq 404) {
        return [string]::IsNullOrWhiteSpace($code) -or $code -match '(?i)not.?found|resource.?not.?found'
    }
    if ($status -ne 400) { return $false }
    return $code -match '^(?i:BadRequest|Request_BadRequest|InvalidRequest|Invalid_Request|ErrorInvalidRequest|UnsupportedQuery|Request_UnsupportedQuery|NotSupported|Not_Supported|InvalidFilterClause|InvalidSelectClause)$'
}

function Invoke-GraphPaged {
    param([Parameter(Mandatory)][string] $Uri, [Parameter(Mandatory)][string] $StatusLabel)
    $items = [Collections.Generic.List[object]]::new()
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $next = $Uri
    while (-not [string]::IsNullOrWhiteSpace($next)) {
        if (-not $seen.Add($next)) { throw "Graph pagination cycle detected for $StatusLabel." }
        Write-ReportStatus "$StatusLabel ($($items.Count) rows received)"
        $response = Invoke-IntuneGraphRequest -Method GET -Uri $next
        $value = Get-ObjectValue $response 'value'
        if ($null -ne $value) {
            foreach ($item in @($value)) { $items.Add($item) }
        }
        $next = Get-ObjectString $response '@odata.nextLink'
        if (-not [string]::IsNullOrWhiteSpace($next) -and -not (Test-TrustedGraphUri $next)) {
            throw "Graph returned an untrusted pagination URL: $next"
        }
    }
    return $items.ToArray()
}

function ConvertTo-BatchRelativeUri {
    param([Parameter(Mandatory)][string] $Uri)
    if (-not (Test-TrustedGraphUri $Uri)) { throw "Untrusted Graph batch URL: $Uri" }
    $parsed = [uri]$Uri
    return $parsed.PathAndQuery
}

function Invoke-GraphBatchGet {
    param(
        [Parameter(Mandatory)][Collections.IDictionary] $Requests,
        [switch] $ContinueOnError,
        [string] $StatusLabel = 'Fetching Graph details'
    )
    $results = [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    $keys = @($Requests.Keys)
    for ($offset = 0; $offset -lt $keys.Count; $offset += 20) {
        $last = [math]::Min($offset + 19, $keys.Count - 1)
        $chunkKeys = @($keys[$offset..$last])
        Write-ReportStatus "$StatusLabel ($([math]::Min($last + 1, $keys.Count)) of $($keys.Count))"
        $batchRequests = foreach ($key in $chunkKeys) {
            [ordered]@{ id = [string]$key; method = 'GET'; url = ConvertTo-BatchRelativeUri -Uri ([string]$Requests[$key]) }
        }
        $batch = Invoke-IntuneGraphRequest -Method POST -Uri "$($script:GraphBase)/`$batch" -Body @{ requests = @($batchRequests) }
        $byId = @{}
        foreach ($subresponse in @(Get-ObjectValue $batch 'responses')) {
            $byId[[string](Get-ObjectValue $subresponse 'id')] = $subresponse
        }
        foreach ($key in $chunkKeys) {
            $sub = $byId[[string]$key]
            $status = if ($null -eq $sub) { 0 } else { [int](Get-ObjectNumber $sub 'status') }
            if ($status -ge 200 -and $status -lt 300) {
                $results[[string]$key] = Get-ObjectValue $sub 'body'
                continue
            }
            try {
                $results[[string]$key] = Invoke-IntuneGraphRequest -Method GET -Uri ([string]$Requests[$key])
            }
            catch {
                if (-not $ContinueOnError) { throw }
            }
        }
    }
    return $results
}

function New-ReportData {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Headers,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Rows
    )
    if ($Rows.Count -gt $script:MaximumDataRows) {
        throw "A report returned $($Rows.Count) rows, exceeding Excel's available data rows."
    }
    return [pscustomobject]@{ Headers = $Headers; Rows = $Rows }
}

function Get-DeviceReportRow {
    param([Parameter(Mandatory)][object] $Device, [switch] $DuplicateLayout)
    $enrolled = ConvertFrom-GraphDate (Get-ObjectValue $Device 'enrolledDateTime')
    $lastSync = ConvertFrom-GraphDate (Get-ObjectValue $Device 'lastSyncDateTime')
    $email = Get-DeviceUserEmail $Device
    $base = @(
        Get-ObjectString $Device 'deviceName'
        Get-ObjectString $Device 'serialNumber'
        $email
        Get-ObjectString $Device 'operatingSystem'
        $enrolled
        $lastSync
    )
    if ($DuplicateLayout) {
        return @(
            $base
            Get-ObjectString $Device 'osVersion'
            ConvertTo-ComplianceLabel (Get-ObjectString $Device 'complianceState')
            Get-ObjectString $Device 'userDisplayName'
            Get-ObjectString $Device 'managedDeviceName'
            ConvertTo-OwnerLabel (Get-ObjectString $Device 'managedDeviceOwnerType')
            ConvertTo-EnrollmentLabel (Get-ObjectString $Device 'deviceEnrollmentType')
            Get-WholeDaysSince $lastSync
            Get-ObjectString $Device 'manufacturer'
            Get-ObjectString $Device 'model'
        )
    }
    $encryptedValue = Get-ObjectValue $Device 'isEncrypted'
    $encrypted = if ($encryptedValue -is [bool]) { if ($encryptedValue) { 'Yes' } else { 'No' } } else { '' }
    return @(
        $base
        ConvertTo-ComplianceLabel (Get-ObjectString $Device 'complianceState')
        Get-ObjectString $Device 'osVersion'
        Get-ObjectString $Device 'userDisplayName'
        Get-ObjectString $Device 'managedDeviceName'
        ConvertTo-OwnerLabel (Get-ObjectString $Device 'managedDeviceOwnerType')
        ConvertTo-EnrollmentLabel (Get-ObjectString $Device 'deviceEnrollmentType')
        Get-WholeDaysSince $lastSync
        Get-ObjectString $Device 'manufacturer'
        Get-ObjectString $Device 'model'
        $encrypted
        Convert-BytesToGiB (Get-ObjectValue $Device 'totalStorageSpaceInBytes')
        Convert-BytesToGiB (Get-ObjectValue $Device 'freeStorageSpaceInBytes')
        Get-ObjectString $Device 'deviceCategoryDisplayName'
    )
}

function Get-DevicesData {
    $select = @(
        'deviceName','managedDeviceName','userPrincipalName','userDisplayName','emailAddress',
        'operatingSystem','osVersion','complianceState','managementAgent','managedDeviceOwnerType',
        'deviceEnrollmentType','enrolledDateTime','lastSyncDateTime','manufacturer','model',
        'serialNumber','isEncrypted','totalStorageSpaceInBytes','freeStorageSpaceInBytes',
        'deviceCategoryDisplayName','jailBroken','azureADDeviceId','id'
    ) -join ','
    $baseUri = "$($script:GraphBase)/deviceManagement/managedDevices?`$top=1000"
    try {
        $devices = @(Invoke-GraphPaged -Uri "$baseUri&`$select=$select" -StatusLabel 'Fetching devices')
    }
    catch {
        if (-not (Test-QueryFallbackAllowed $_)) { throw }
        $devices = @(Invoke-GraphPaged -Uri $baseUri -StatusLabel 'Fetching devices (compatibility query)')
    }

    $deviceRows = [Collections.Generic.List[object]]::new()
    foreach ($device in $devices) { $deviceRows.Add([object](Get-DeviceReportRow -Device $device)) }
    $deviceReport = New-ReportData -Headers @(
        'Device Name','Serial Number','User Email','OS','Enrolled','Last Check-in','Compliance',
        'OS Version','User Name','Managed Device Name','Ownership','Enrollment Type',
        'Days Since Check-in','Manufacturer','Model','Encrypted','Storage Total (GB)',
        'Storage Free (GB)','Category'
    ) -Rows $deviceRows.ToArray()

    $serialCounts = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($device in $devices) {
        $serial = (Get-ObjectString $device 'serialNumber').Trim()
        if ([string]::IsNullOrWhiteSpace($serial)) { continue }
        if ($serialCounts.ContainsKey($serial)) { $serialCounts[$serial]++ } else { $serialCounts[$serial] = 1 }
    }
    $duplicateRows = [Collections.Generic.List[object]]::new()
    foreach ($device in $devices) {
        $serial = (Get-ObjectString $device 'serialNumber').Trim()
        if (-not [string]::IsNullOrWhiteSpace($serial) -and $serialCounts[$serial] -gt 1) {
            $duplicateRows.Add([object](Get-DeviceReportRow -Device $device -DuplicateLayout))
        }
    }
    $sortedDuplicates = @($duplicateRows.ToArray() | Sort-Object { [string]$_[1] })
    $duplicateReport = New-ReportData -Headers @(
        'Device Name','Serial Number','User Email','OS','Enrolled','Last Check-in','OS Version',
        'Compliance','User Name','Managed Device Name','Ownership','Enrollment Type',
        'Days Since Check-in','Manufacturer','Model'
    ) -Rows $sortedDuplicates

    return [pscustomobject]@{
        RawDevices = $devices
        Devices     = $deviceReport
        Duplicates  = $duplicateReport
    }
}

function Resolve-ComplianceOverview {
    param(
        [AllowNull()][object] $Response,
        [Parameter(Mandatory)][string] $PolicyId
    )
    if ($null -eq $Response) {
        throw "Compliance policy $PolicyId returned an empty status overview."
    }

    $overview = $Response
    if (-not (Test-ObjectProperty $overview 'successCount') -and
        (Test-ObjectProperty $overview 'value')) {
        $value = Get-ObjectValue $overview 'value'
        if ($null -eq $value) {
            throw "Compliance policy $PolicyId returned an empty status overview value."
        }
        if ($value -is [Collections.IEnumerable] -and
            $value -isnot [string] -and
            $value -isnot [Collections.IDictionary]) {
            $items = @($value)
            if ($items.Count -ne 1) {
                throw "Compliance policy $PolicyId returned $($items.Count) status overview values; expected exactly one."
            }
            $overview = $items[0]
        }
        else {
            $overview = $value
        }
    }

    foreach ($field in @('successCount','failedCount','errorCount','pendingCount','notApplicableCount')) {
        if (-not (Test-ObjectProperty $overview $field) -or
            $null -eq (Get-ObjectValue $overview $field)) {
            throw "Compliance policy $PolicyId omitted $field."
        }
    }
    return $overview
}

function Get-ComplianceData {
    $uri = "$($script:GraphBase)/deviceManagement/deviceCompliancePolicies?`$top=1000&`$select=id,displayName,createdDateTime,lastModifiedDateTime"
    $policies = @(Invoke-GraphPaged -Uri $uri -StatusLabel 'Fetching compliance policies')
    $requests = [ordered]@{}
    foreach ($policy in $policies) {
        $id = (Get-ObjectString $policy 'id').Trim()
        if ([string]::IsNullOrWhiteSpace($id)) { throw 'A compliance policy was returned without an ID.' }
        if ($requests.Contains($id)) { throw "Graph returned duplicate compliance policy ID $id." }
        $requests[$id] = "$($script:GraphBase)/deviceManagement/deviceCompliancePolicies/$id/deviceStatusOverview"
    }
    $overviews = if ($requests.Count -gt 0) {
        Invoke-GraphBatchGet -Requests $requests -StatusLabel 'Fetching compliance policy status'
    } else {
        [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($policy in $policies) {
        $id = (Get-ObjectString $policy 'id').Trim()
        if (-not $overviews.ContainsKey($id)) { throw "No status overview was returned for compliance policy $id." }
        $overview = Resolve-ComplianceOverview -Response $overviews[$id] -PolicyId $id
        $rows.Add([object]@(
            Get-ObjectString $policy 'displayName'
            ConvertTo-PlatformLabel (Get-ObjectString $policy '@odata.type')
            Get-ObjectNumber $overview 'successCount'
            Get-ObjectNumber $overview 'failedCount'
            Get-ObjectNumber $overview 'errorCount'
            Get-ObjectNumber $overview 'conflictCount'
            Get-ObjectNumber $overview 'pendingCount'
            Get-ObjectNumber $overview 'notApplicableCount'
            ConvertFrom-GraphDate (Get-ObjectValue $overview 'lastUpdateDateTime')
            ConvertFrom-GraphDate (Get-ObjectValue $policy 'createdDateTime')
            ConvertFrom-GraphDate (Get-ObjectValue $policy 'lastModifiedDateTime')
        ))
    }
    $sorted = @($rows.ToArray() | Sort-Object { [double]$_[3] } -Descending)
    return New-ReportData -Headers @(
        'Policy','Platform','Compliant','Noncompliant','Error','Conflict','Pending',
        'Not Applicable','Status Updated','Created','Last Modified'
    ) -Rows $sorted
}

function ConvertTo-ReportTable {
    param([Parameter(Mandatory)][object] $Response, [Parameter(Mandatory)][string] $ActionName)
    $schema = Get-ObjectValue $Response 'Schema'
    $values = Get-ObjectValue $Response 'Values'
    if ($null -eq $schema -or $null -eq $values) {
        $exception = [IO.InvalidDataException]::new("$ActionName returned an unexpected report format.")
        $exception.Data['ReportFormat'] = $true
        throw $exception
    }
    $headers = @(
        foreach ($definition in @($schema)) { Get-ObjectString $definition 'Column' }
    )
    return [pscustomobject]@{ Headers = [string[]]$headers; Values = @($values) }
}

function Invoke-IntuneReportAction {
    param(
        [Parameter(Mandatory)][string] $ActionName,
        [string] $Filter = '',
        [AllowNull()][string[]] $Select = $null
    )
    $allRows = [Collections.Generic.List[object]]::new()
    $headers = $null
    $pageSize = 500
    $skip = 0
    $total = -1
    $firstPage = $true
    # while($true)+break (not do/while): the page-size fallback below uses `continue`,
    # which in a do/while would jump to the condition and read $received before it is
    # ever set (a StrictMode error). Here `continue` correctly re-runs the request.
    while ($true) {
        $body = [ordered]@{ top = $pageSize; skip = $skip; filter = $Filter }
        if ($null -ne $Select -and $Select.Count -gt 0) { $body.select = @($Select) }
        try {
            $response = Invoke-IntuneGraphRequest -Method POST -Uri "$($script:GraphBase)/deviceManagement/reports/$ActionName" -Body $body -StreamJsonResponse
        }
        catch {
            if ($firstPage -and $pageSize -eq 500 -and (Test-QueryFallbackAllowed $_)) {
                $pageSize = 50
                continue
            }
            throw
        }
        $table = ConvertTo-ReportTable -Response $response -ActionName $ActionName
        if ($null -eq $headers) { $headers = $table.Headers }
        foreach ($row in @($table.Values)) { $allRows.Add([object]$row) }
        $totalValue = Get-ObjectValue $response 'TotalRowCount'
        if ($null -ne $totalValue) { $total = [int64]$totalValue }
        if ($total -gt $script:MaximumDataRows -or $allRows.Count -gt $script:MaximumDataRows) {
            throw "$ActionName exceeds Excel's row limit."
        }
        $received = $table.Values.Count
        $skip += $received
        $firstPage = $false
        Write-ReportStatus "Report $ActionName ($($allRows.Count) rows received)"
        if (-not ($received -gt 0 -and (($total -ge 0 -and $allRows.Count -lt $total) -or ($total -lt 0 -and $received -ge $pageSize)))) {
            break
        }
    }

    if ($null -eq $headers -or $headers.Count -eq 0) {
        $exception = [IO.InvalidDataException]::new("$ActionName returned no schema.")
        $exception.Data['ReportFormat'] = $true
        throw $exception
    }
    $cleanRows = [Collections.Generic.List[object]]::new()
    foreach ($row in $allRows) {
        $values = @($row)
        $clean = for ($index = 0; $index -lt $headers.Count; $index++) {
            if ($index -lt $values.Count) { ConvertTo-CleanReportCell $values[$index] } else { $null }
        }
        $cleanRows.Add([object]@($clean))
    }
    return New-ReportData -Headers $headers -Rows $cleanRows.ToArray()
}

function Select-ReportColumns {
    param([Parameter(Mandatory)][object] $Report, [Parameter(Mandatory)][string[]] $Columns)
    $positions = foreach ($column in $Columns) {
        $match = -1
        for ($index = 0; $index -lt $Report.Headers.Count; $index++) {
            if ([string]$Report.Headers[$index] -ieq $column) { $match = $index; break }
        }
        if ($match -lt 0) { throw "The report did not return the requested column '$column'." }
        $match
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($row in $Report.Rows) {
        $projected = foreach ($position in $positions) { $row[$position] }
        $rows.Add([object]@($projected))
    }
    return New-ReportData -Headers $Columns -Rows $rows.ToArray()
}

function Test-TrustedReportExportUri {
    # Completed Intune export jobs are delivered as short-lived, SAS-signed Azure
    # Blob storage URLs. Confirm the download target is HTTPS Azure Blob storage
    # before fetching it so a malformed or spoofed response cannot redirect the
    # download elsewhere.
    param([AllowNull()][string] $Uri)
    if ([string]::IsNullOrWhiteSpace($Uri)) { return $false }
    $parsed = $null
    if (-not [uri]::TryCreate($Uri, [UriKind]::Absolute, [ref]$parsed)) { return $false }
    if ($parsed.Scheme -ne 'https') { return $false }
    if (-not ($parsed.IsDefaultPort -or $parsed.Port -eq 443)) { return $false }
    return $parsed.Host.EndsWith('.blob.core.windows.net', [StringComparison]::OrdinalIgnoreCase)
}

function ConvertFrom-ReportExportCsv {
    param([Parameter(Mandatory)][AllowEmptyString()][string] $CsvText)
    if ([string]::IsNullOrWhiteSpace($CsvText)) {
        return New-ReportData -Headers ([string[]]@()) -Rows @()
    }
    $objects = @($CsvText | ConvertFrom-Csv)
    $headers = [string[]]@()
    if ($objects.Count -gt 0) {
        $headers = [string[]]@($objects[0].PSObject.Properties.Name)
    }
    else {
        # No data rows were returned. Recover the column names from the header line
        # so callers that look up columns by position still receive a valid, empty
        # table instead of failing on a missing schema.
        $firstLine = @($CsvText -split "\r?\n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) |
            Select-Object -First 1
        if (-not [string]::IsNullOrWhiteSpace($firstLine)) {
            $probe = @(($firstLine + "`n_") | ConvertFrom-Csv)
            if ($probe.Count -gt 0) { $headers = [string[]]@($probe[0].PSObject.Properties.Name) }
        }
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($object in $objects) {
        $values = foreach ($header in $headers) { ConvertTo-CleanReportCell $object.$header }
        $rows.Add([object]@($values))
    }
    return New-ReportData -Headers $headers -Rows $rows.ToArray()
}

function ConvertFrom-ReportExportArchive {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][string] $ReportName
    )
    $bytes = [IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -eq 0) {
        $exception = [IO.InvalidDataException]::new("The $ReportName export download was empty.")
        $exception.Data['ReportFormat'] = $true
        throw $exception
    }
    # Export jobs return a .zip containing a single CSV even when csv format is
    # requested. Detect the ZIP local-file-header magic (PK\x03\x04); otherwise
    # treat the payload as raw CSV text.
    $isZip = $bytes.Length -ge 4 -and $bytes[0] -eq 0x50 -and $bytes[1] -eq 0x4B -and
        $bytes[2] -eq 0x03 -and $bytes[3] -eq 0x04
    if (-not $isZip) {
        return ConvertFrom-ReportExportCsv -CsvText ([Text.Encoding]::UTF8.GetString($bytes))
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop | Out-Null
    $archive = [IO.Compression.ZipFile]::OpenRead($Path)
    try {
        $entry = $archive.Entries | Where-Object { $_.FullName -match '(?i)\.csv$' } | Select-Object -First 1
        if ($null -eq $entry) {
            $exception = [IO.InvalidDataException]::new("The $ReportName export archive did not contain a CSV file.")
            $exception.Data['ReportFormat'] = $true
            throw $exception
        }
        $reader = [IO.StreamReader]::new($entry.Open())
        try { $csvText = $reader.ReadToEnd() }
        finally { $reader.Dispose() }
    }
    finally { $archive.Dispose() }
    return ConvertFrom-ReportExportCsv -CsvText $csvText
}

function Invoke-IntuneReportExportJob {
    param(
        [Parameter(Mandatory)][string] $ReportName,
        [AllowNull()][string[]] $Select = $null,
        [string] $Filter = '',
        [int] $TimeoutSeconds = 180,
        [int] $PollSeconds = 3
    )
    # Some Intune reports (for example the Windows feature-update policy status
    # summary) are not exposed as synchronous report actions; they are only
    # available through the asynchronous export-jobs pipeline. Create a job, poll
    # until it completes, then download the CSV it produced from Azure storage.
    $createBody = [ordered]@{ reportName = $ReportName; format = 'csv' }
    if ($null -ne $Select -and $Select.Count -gt 0) { $createBody.select = @($Select) }
    if (-not [string]::IsNullOrWhiteSpace($Filter)) { $createBody.filter = $Filter }

    $job = Invoke-IntuneGraphRequest -Method POST `
        -Uri "$($script:GraphBase)/deviceManagement/reports/exportJobs" -Body $createBody
    $jobId = Get-ObjectString $job 'id'
    if ([string]::IsNullOrWhiteSpace($jobId)) {
        throw "The $ReportName export job did not return a job identifier."
    }

    # The job id becomes an OData key; escape single quotes by doubling them.
    $escapedId = $jobId.Replace("'", "''")
    $statusUri = "$($script:GraphBase)/deviceManagement/reports/exportJobs('$escapedId')"
    $status = Get-ObjectString $job 'status'
    $poll = $job
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    while ($status -ne 'completed' -and $status -ne 'failed') {
        if ($stopwatch.Elapsed.TotalSeconds -ge $TimeoutSeconds) {
            throw "The $ReportName export job did not finish within $TimeoutSeconds seconds (last status '$status')."
        }
        Start-Sleep -Seconds $PollSeconds
        $poll = Invoke-IntuneGraphRequest -Method GET -Uri $statusUri
        $status = Get-ObjectString $poll 'status'
    }
    if ($status -ne 'completed') {
        throw "Microsoft Graph reported the $ReportName export job as '$status'."
    }

    $downloadUri = Get-ObjectString $poll 'url'
    if (-not (Test-TrustedReportExportUri -Uri $downloadUri)) {
        throw "The $ReportName export job returned a missing or untrusted download URL."
    }

    $tempFile = Join-Path ([IO.Path]::GetTempPath()) ('intune-export-{0}.tmp' -f ([guid]::NewGuid().ToString('N')))
    try {
        # The download URL is a self-authenticating SAS blob URL. Deliberately issue
        # an unauthenticated request so the Graph bearer token is never sent to
        # storage. Silence the progress stream so large downloads do not stall.
        $previousProgress = $ProgressPreference
        $ProgressPreference = 'SilentlyContinue'
        try {
            Invoke-WebRequest -Uri $downloadUri -OutFile $tempFile -ErrorAction Stop | Out-Null
        }
        finally { $ProgressPreference = $previousProgress }
        return ConvertFrom-ReportExportArchive -Path $tempFile -ReportName $ReportName
    }
    finally {
        if (Test-Path -LiteralPath $tempFile -PathType Leaf) {
            try { Remove-Item -LiteralPath $tempFile -Force -ErrorAction Stop } catch { }
        }
    }
}

function Get-AppsFallbackData {
    $filteredUri = "$($script:GraphBase)/deviceAppManagement/mobileApps?`$top=1000&`$filter=isAssigned%20eq%20true&`$select=id,displayName,publisher"
    try {
        $apps = @(Invoke-GraphPaged -Uri $filteredUri -StatusLabel 'Fetching assigned apps')
    }
    catch {
        if (-not (Test-QueryFallbackAllowed $_)) { throw }
        $apps = @(Invoke-GraphPaged -Uri "$($script:GraphBase)/deviceAppManagement/mobileApps?`$top=1000&`$select=id,displayName,publisher" -StatusLabel 'Fetching apps')
    }
    $requests = [ordered]@{}
    foreach ($app in $apps) {
        $id = (Get-ObjectString $app 'id').Trim()
        if ([string]::IsNullOrWhiteSpace($id)) { throw 'A mobile app was returned without an ID.' }
        if ($requests.Contains($id)) { throw "Graph returned duplicate mobile app ID $id." }
        $requests[$id] = "$($script:GraphBase)/deviceAppManagement/mobileApps/$id/installSummary"
    }
    $summaries = if ($requests.Count -gt 0) {
        Invoke-GraphBatchGet -Requests $requests -StatusLabel 'Fetching app install summaries'
    } else {
        [Collections.Generic.Dictionary[string, object]]::new([StringComparer]::OrdinalIgnoreCase)
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($app in $apps) {
        $id = (Get-ObjectString $app 'id').Trim()
        if (-not $summaries.ContainsKey($id)) { throw "No install summary was returned for app $id." }
        $summary = Get-SingletonGraphObject $summaries[$id]
        if ($null -eq $summary) { throw "App $id returned an empty install summary." }
        foreach ($field in @(
                'installedDeviceCount','failedDeviceCount','pendingInstallDeviceCount',
                'notInstalledDeviceCount','notApplicableDeviceCount','installedUserCount','failedUserCount'
            )) {
            if (-not (Test-ObjectProperty $summary $field) -or
                $null -eq (Get-ObjectValue $summary $field)) {
                throw "App $id omitted $field from its install summary."
            }
        }
        $rows.Add([object]@(
            Get-ObjectString $app 'displayName'
            Get-ObjectString $app 'publisher'
            Get-ObjectNumber $summary 'installedDeviceCount'
            Get-ObjectNumber $summary 'failedDeviceCount'
            Get-ObjectNumber $summary 'pendingInstallDeviceCount'
            Get-ObjectNumber $summary 'notInstalledDeviceCount'
            Get-ObjectNumber $summary 'notApplicableDeviceCount'
            Get-ObjectNumber $summary 'installedUserCount'
            Get-ObjectNumber $summary 'failedUserCount'
        ))
    }
    return New-ReportData -Headers @(
        'DisplayName','Publisher','InstalledDeviceCount','FailedDeviceCount',
        'PendingInstallDeviceCount','NotInstalledDeviceCount','NotApplicableDeviceCount',
        'InstalledUserCount','FailedUserCount'
    ) -Rows $rows.ToArray()
}

function Get-AppsData {
    $columns = @(
        'DisplayName','Publisher','InstalledDeviceCount','FailedDeviceCount',
        'PendingInstallDeviceCount','NotInstalledDeviceCount','NotApplicableDeviceCount',
        'InstalledUserCount','FailedUserCount'
    )
    $report = $null
    try {
        $report = Invoke-IntuneReportAction -ActionName 'getAppsInstallSummaryReport' -Select $columns
    }
    catch {
        $formatFailure = $_.Exception.Data.Contains('ReportFormat')
        if (-not $formatFailure -and -not (Test-QueryFallbackAllowed $_)) { throw }
        try {
            $report = Select-ReportColumns -Report (Invoke-IntuneReportAction -ActionName 'getAppsInstallSummaryReport') -Columns $columns
        }
        catch {
            $formatFailure = $_.Exception.Data.Contains('ReportFormat') -or $_.Exception -is [IO.InvalidDataException]
            if (-not $formatFailure -and -not (Test-QueryFallbackAllowed $_)) { throw }
            $report = Get-AppsFallbackData
        }
    }
    $failedIndex = [array]::IndexOf([string[]]$report.Headers, 'FailedDeviceCount')
    $sorted = if ($failedIndex -ge 0) {
        @($report.Rows | Sort-Object { [double]$_[$failedIndex] } -Descending)
    } else { @($report.Rows) }
    return New-ReportData -Headers ([string[]]$report.Headers) -Rows $sorted
}

function Test-ManagedDeviceDeletion {
    param(
        [AllowNull()][string] $OperationType,
        [AllowNull()][string] $Category,
        [AllowNull()][string] $ActivityType,
        [AllowNull()][string] $DisplayName
    )
    $operation = ([string]$OperationType).ToLowerInvariant()
    $activity = ("$ActivityType $DisplayName").ToLowerInvariant()
    if ($operation -ne 'delete' -and -not $activity.Contains('delete')) { return $false }
    return $activity.Contains('manageddevice') -or ([string]$Category).Equals('device', [StringComparison]::OrdinalIgnoreCase)
}

function Get-DeletedResourceName {
    param([Parameter(Mandatory)][object] $AuditEvent)
    $firstName = ''
    foreach ($resource in @(Get-ObjectValue $AuditEvent 'resources')) {
        $name = Get-ObjectString $resource 'displayName'
        if ([string]::IsNullOrWhiteSpace($firstName)) { $firstName = $name }
        $type = ((Get-ObjectString $resource 'type') + (Get-ObjectString $resource 'auditResourceType')).ToLowerInvariant()
        if ($type.Contains('manageddevice')) { return $name }
    }
    return $firstName
}

function Get-DeletedDevicesData {
    $cutoff = [datetime]::UtcNow.AddDays(-14).ToString('yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture)
    # Restrict the query server-side: device removals are recorded with
    # activityOperationType 'Delete', and only the fields below are consumed. This
    # avoids transferring every audit event in the window on busy tenants. If the
    # tenant rejects the richer query, fall back to the unfiltered date-only form.
    $select = 'activityDateTime,activityOperationType,category,activityType,displayName,activity,activityResult,actor,resources'
    $baseFilter = "activityDateTime gt $cutoff"
    $deleteFilter = [uri]::EscapeDataString("$baseFilter and activityOperationType eq 'Delete'")
    $auditUri = "$($script:GraphBase)/deviceManagement/auditEvents"
    try {
        $events = @(Invoke-GraphPaged -Uri "$auditUri`?`$filter=$deleteFilter&`$select=$select" -StatusLabel 'Fetching deleted-device audit events')
    }
    catch {
        if (-not (Test-QueryFallbackAllowed $_)) { throw }
        $dateFilter = [uri]::EscapeDataString($baseFilter)
        $events = @(Invoke-GraphPaged -Uri "$auditUri`?`$filter=$dateFilter" -StatusLabel 'Fetching deleted-device audit events (compatibility query)')
    }
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($auditEvent in $events) {
        if (-not (Test-ManagedDeviceDeletion `
                -OperationType (Get-ObjectString $auditEvent 'activityOperationType') `
                -Category (Get-ObjectString $auditEvent 'category') `
                -ActivityType (Get-ObjectString $auditEvent 'activityType') `
                -DisplayName (Get-ObjectString $auditEvent 'displayName'))) { continue }
        $actor = Get-ObjectValue $auditEvent 'actor'
        $deletedBy = Get-ObjectString $actor 'userPrincipalName'
        if ([string]::IsNullOrWhiteSpace($deletedBy)) { $deletedBy = Get-ObjectString $actor 'applicationDisplayName' }
        if ([string]::IsNullOrWhiteSpace($deletedBy)) { $deletedBy = Get-ObjectString $actor 'servicePrincipalName' }
        $actorType = Get-ObjectString $actor 'auditActorType'
        if ([string]::IsNullOrWhiteSpace($actorType)) { $actorType = Get-ObjectString $actor 'type' }
        $activity = Get-ObjectString $auditEvent 'activityType'
        if ([string]::IsNullOrWhiteSpace($activity)) { $activity = Get-ObjectString $auditEvent 'displayName' }
        if ([string]::IsNullOrWhiteSpace($activity)) { $activity = Get-ObjectString $auditEvent 'activity' }
        $rows.Add([object]@(
            ConvertFrom-GraphDate (Get-ObjectValue $auditEvent 'activityDateTime')
            Get-DeletedResourceName $auditEvent
            $deletedBy
            $actorType
            $activity
            Get-ObjectString $auditEvent 'activityResult'
        ))
    }
    $sorted = @($rows.ToArray() | Sort-Object { if ($_[0] -is [datetime]) { $_[0] } else { [datetime]::MinValue } } -Descending)
    return New-ReportData -Headers @('Deleted','Device Name','Deleted By','Actor Type','Activity','Result') -Rows $sorted
}

function Get-ExpiryStatus {
    param([AllowNull()][object] $Expires)
    if ($Expires -isnot [datetime]) { return '' }
    $days = [math]::Floor((([datetime]$Expires).Date - [datetime]::UtcNow.Date).TotalDays)
    if ($days -lt 0) { return 'Expired' }
    if ($days -le 30) { return 'Expiring soon' }
    return 'Healthy'
}

function Add-ConnectorRow {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]] $Rows,
        [Parameter(Mandatory)][string] $Name,
        [AllowNull()][string] $Identifier,
        [Parameter(Mandatory)][string] $Status,
        [AllowNull()][string] $Detail,
        [AllowNull()][object] $Expires,
        [AllowNull()][object] $LastSync
    )
    $days = if ($Expires -is [datetime]) {
        [math]::Floor((([datetime]$Expires).Date - [datetime]::UtcNow.Date).TotalDays)
    } else { $null }
    $Rows.Add([object]@($Name, $Identifier, $Status, $Detail, $Expires, $days, $LastSync))
}

function Add-ConnectorUnavailable {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][Collections.Generic.List[object]] $Rows,
        [Parameter(Mandatory)][string] $Name,
        [Parameter(Mandatory)][Management.Automation.ErrorRecord] $ErrorRecord
    )
    $detail = [regex]::Replace(([string]$ErrorRecord.Exception.Message).Trim(), '\s+', ' ')
    if ([string]::IsNullOrWhiteSpace($detail)) { $detail = 'Graph endpoint returned no usable response.' }
    $detail = "Graph request failed: $detail"
    if ($detail.Length -gt 300) { $detail = $detail.Substring(0, 297) + '...' }
    Add-ConnectorRow -Rows $Rows -Name $Name -Identifier '' -Status 'Unavailable' -Detail $detail -Expires $null -LastSync $null
}

function Get-SingletonGraphObject {
    param([AllowNull()][object] $Response)
    if ($null -eq $Response) { return $null }
    $value = Get-ObjectValue $Response 'value'
    if ($null -ne $value -and $value -isnot [array]) { return $value }
    return $Response
}

function Get-ConnectorsData {
    $rows = [Collections.Generic.List[object]]::new()

    try {
        Write-ReportStatus 'Fetching Apple MDM push certificate'
        $item = Get-SingletonGraphObject (Invoke-IntuneGraphRequest -Method GET -Uri "$($script:GraphBase)/deviceManagement/applePushNotificationCertificate")
        if ($null -eq $item) { throw 'The endpoint returned no object.' }
        $expires = ConvertFrom-GraphDate (Get-ObjectValue $item 'expirationDateTime')
        $status = Get-ExpiryStatus $expires
        if ([string]::IsNullOrWhiteSpace($status)) { $status = 'Unknown' }
        Add-ConnectorRow -Rows $rows -Name 'Apple MDM push certificate' `
            -Identifier (Get-ObjectString $item 'appleIdentifier') -Status $status `
            -Detail (Get-ObjectString $item 'certificateUploadStatus') -Expires $expires `
            -LastSync (ConvertFrom-GraphDate (Get-ObjectValue $item 'lastModifiedDateTime'))
    } catch { Add-ConnectorUnavailable -Rows $rows -Name 'Apple MDM push certificate' -ErrorRecord $_ }

    try {
        $tokens = @(Invoke-GraphPaged -Uri "$($script:GraphBase)/deviceAppManagement/vppTokens" -StatusLabel 'Fetching Apple VPP tokens')
        foreach ($token in $tokens) {
            $expires = ConvertFrom-GraphDate (Get-ObjectValue $token 'expirationDateTime')
            $state = (Get-ObjectString $token 'state').ToLowerInvariant()
            $status = Get-ExpiryStatus $expires
            if ($state -eq 'expired') { $status = 'Expired' }
            elseif ($state -in @('invalid','assignedtoexternalmdm','duplicatelocationid')) { $status = 'Needs attention' }
            elseif ([string]::IsNullOrWhiteSpace($status)) { $status = 'Unknown' }
            $identifier = Get-ObjectString $token 'organizationName'
            if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = Get-ObjectString $token 'appleId' }
            Add-ConnectorRow -Rows $rows -Name 'Apple VPP token' -Identifier $identifier -Status $status `
                -Detail ("state: " + (Get-ObjectString $token 'state')) -Expires $expires `
                -LastSync (ConvertFrom-GraphDate (Get-ObjectValue $token 'lastSyncDateTime'))
        }
    } catch { Add-ConnectorUnavailable -Rows $rows -Name 'Apple VPP token' -ErrorRecord $_ }

    try {
        $tokens = @(Invoke-GraphPaged -Uri "$($script:GraphBase)/deviceManagement/depOnboardingSettings" -StatusLabel 'Fetching Apple ADE tokens')
        foreach ($token in $tokens) {
            $expires = ConvertFrom-GraphDate (Get-ObjectValue $token 'tokenExpirationDateTime')
            $status = Get-ExpiryStatus $expires
            if ([string]::IsNullOrWhiteSpace($status)) { $status = 'Unknown' }
            $name = 'Apple ADE token'
            $tokenName = Get-ObjectString $token 'tokenName'
            if (-not [string]::IsNullOrWhiteSpace($tokenName)) { $name += " ($tokenName)" }
            Add-ConnectorRow -Rows $rows -Name $name -Identifier (Get-ObjectString $token 'appleIdentifier') -Status $status `
                -Detail ("type: " + (Get-ObjectString $token 'tokenType')) -Expires $expires `
                -LastSync (ConvertFrom-GraphDate (Get-ObjectValue $token 'lastSuccessfulSyncDateTime'))
        }
    } catch { Add-ConnectorUnavailable -Rows $rows -Name 'Apple ADE token' -ErrorRecord $_ }

    try {
        $connectors = @(Invoke-GraphPaged -Uri "$($script:GraphBase)/deviceManagement/exchangeConnectors" -StatusLabel 'Fetching Exchange connectors')
        foreach ($connector in $connectors) {
            $state = Get-ObjectString $connector 'status'
            $status = if ($state.Equals('connected', [StringComparison]::OrdinalIgnoreCase)) { 'Healthy' } else { 'Needs attention' }
            $identifier = Get-ObjectString $connector 'serverName'
            if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = Get-ObjectString $connector 'connectorServerName' }
            Add-ConnectorRow -Rows $rows -Name 'Exchange connector' -Identifier $identifier -Status $status -Detail $state `
                -Expires $null -LastSync (ConvertFrom-GraphDate (Get-ObjectValue $connector 'lastSyncDateTime'))
        }
    } catch { Add-ConnectorUnavailable -Rows $rows -Name 'Exchange connector' -ErrorRecord $_ }

    try {
        $connectors = @(Invoke-GraphPaged -Uri "$($script:GraphBase)/deviceManagement/ndesConnectors" -StatusLabel 'Fetching NDES connectors')
        foreach ($connector in $connectors) {
            $state = Get-ObjectString $connector 'state'
            $status = if ($state.Equals('active', [StringComparison]::OrdinalIgnoreCase)) { 'Healthy' } else { 'Needs attention' }
            $identifier = Get-ObjectString $connector 'displayName'
            if ([string]::IsNullOrWhiteSpace($identifier)) { $identifier = Get-ObjectString $connector 'machineName' }
            Add-ConnectorRow -Rows $rows -Name 'NDES connector' -Identifier $identifier -Status $status `
                -Detail ("state: $state") -Expires $null `
                -LastSync (ConvertFrom-GraphDate (Get-ObjectValue $connector 'lastConnectionDateTime'))
        }
    } catch { Add-ConnectorUnavailable -Rows $rows -Name 'NDES connector' -ErrorRecord $_ }

    try {
        Write-ReportStatus 'Fetching Managed Google Play status'
        $item = Get-SingletonGraphObject (Invoke-IntuneGraphRequest -Method GET -Uri "$($script:GraphBase)/deviceManagement/androidManagedStoreAccountEnterpriseSettings")
        if ($null -eq $item) { throw 'The endpoint returned no object.' }
        $bind = (Get-ObjectString $item 'bindStatus').ToLowerInvariant()
        $sync = (Get-ObjectString $item 'lastAppSyncStatus').ToLowerInvariant()
        $owner = Get-ObjectString $item 'ownerUserPrincipalName'
        if (-not ([string]::IsNullOrWhiteSpace($bind) -and [string]::IsNullOrWhiteSpace($owner))) {
            $status = if ($bind -eq 'notbound') { 'Not configured' }
                elseif ($bind -in @('bound','boundandvalidated') -and $sync -in @('','success')) { 'Healthy' }
                else { 'Needs attention' }
            Add-ConnectorRow -Rows $rows -Name 'Managed Google Play' -Identifier $owner -Status $status `
                -Detail ("bind: " + (Get-ObjectString $item 'bindStatus')) -Expires $null `
                -LastSync (ConvertFrom-GraphDate (Get-ObjectValue $item 'lastAppSyncDateTime'))
        }
    } catch { Add-ConnectorUnavailable -Rows $rows -Name 'Managed Google Play' -ErrorRecord $_ }

    $sorted = @($rows.ToArray() | Sort-Object {
        if ($null -eq $_[5]) { [double]::PositiveInfinity } else { [double]$_[5] }
    })
    return New-ReportData -Headers @(
        'Connector / Token','Identifier','Status','Detail','Expires','Days Until Expiry','Last Sync'
    ) -Rows $sorted
}

function Find-HeaderIndex {
    param([Parameter(Mandatory)][string[]] $Headers, [Parameter(Mandatory)][string] $Wanted)
    $wantedKey = ConvertTo-NormalizedName $Wanted
    for ($index = 0; $index -lt $Headers.Count; $index++) {
        if ((ConvertTo-NormalizedName $Headers[$index]) -eq $wantedKey) { return $index }
    }
    return -1
}

function Get-AutopatchSummary {
    try {
        $report = Invoke-IntuneReportExportJob -ReportName 'FeatureUpdatePolicyStatusSummary'
        $nameIndex = Find-HeaderIndex $report.Headers 'PolicyName'
        $versionIndex = Find-HeaderIndex $report.Headers 'FeatureUpdateVersion'
        $successIndex = Find-HeaderIndex $report.Headers 'CountDevicesSuccessStatus'
        $progressIndex = Find-HeaderIndex $report.Headers 'CountDevicesInProgressStatus'
        $errorIndex = Find-HeaderIndex $report.Headers 'CountDevicesErrorStatus'
        if ($nameIndex -lt 0 -or $successIndex -lt 0 -or $progressIndex -lt 0 -or $errorIndex -lt 0) {
            throw 'The feature-update report schema changed.'
        }
        $rows = [Collections.Generic.List[object]]::new()
        foreach ($row in $report.Rows) {
            $inProgress = [double]$row[$progressIndex]
            if ($inProgress -le 0) { continue }
            $success = [double]$row[$successIndex]
            $failed = [double]$row[$errorIndex]
            $total = $success + $inProgress + $failed
            if ($total -le 0) { continue }
            $label = ([string]$row[$nameIndex]).Trim()
            $version = if ($versionIndex -ge 0) { ([string]$row[$versionIndex]).Trim() } else { '' }
            if (-not [string]::IsNullOrWhiteSpace($version) -and -not $label.Contains($version, [StringComparison]::OrdinalIgnoreCase)) {
                $label += " ($version)"
            }
            if ([string]::IsNullOrWhiteSpace($label)) { $label = 'Unnamed ring' }
            $rows.Add([object]@($label, ($success / $total)))
        }
        return [pscustomobject]@{ Available = $true; Rows = $rows.ToArray() }
    }
    catch {
        Write-Warning "Windows Autopatch progress is unavailable: $($_.Exception.Message)"
        return [pscustomobject]@{ Available = $false; Rows = @() }
    }
}

function ConvertTo-NormalizedAppleModel {
    param([AllowNull()][string] $Value)
    $text = ([string]$Value).Trim().ToLowerInvariant()
    if ($text.StartsWith('apple ')) { $text = $text.Substring(6) }
    return [regex]::Replace($text, '[^a-z0-9]', '')
}

function Compare-DottedVersion {
    param([AllowNull()][string] $Left, [AllowNull()][string] $Right)
    $leftParts = ([string]$Left).Split('.')
    $rightParts = ([string]$Right).Split('.')
    for ($index = 0; $index -lt 6; $index++) {
        $leftValue = if ($index -lt $leftParts.Count) { [double]([regex]::Match($leftParts[$index], '^\d+(?:\.\d+)?').Value) } else { 0 }
        $rightValue = if ($index -lt $rightParts.Count) { [double]([regex]::Match($rightParts[$index], '^\d+(?:\.\d+)?').Value) } else { 0 }
        if ($leftValue -gt $rightValue) { return 1 }
        if ($leftValue -lt $rightValue) { return -1 }
    }
    return 0
}

function Test-IsIosDevice {
    param([AllowNull()][string] $OperatingSystem)
    return ([string]$OperatingSystem).Trim().ToLowerInvariant() -in @('ios','ipados')
}

function Get-EmbeddedIosProductName {
    param([Parameter(Mandatory)][object] $Device)
    $hardware = Get-ObjectValue $Device 'hardwareInformation'
    return (Get-ObjectString $hardware 'productName').Trim()
}

function Get-IosUpdateSummary {
    param([Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Devices)
    $iosDevices = @($Devices | Where-Object { Test-IsIosDevice (Get-ObjectString $_ 'operatingSystem') })
    if ($iosDevices.Count -eq 0) {
        return [pscustomobject]@{ Available = $true; Current = 0; Eligible = 0 }
    }
    try {
        Write-ReportStatus 'Fetching available iOS updates'
        $response = Invoke-IntuneGraphRequest -Method GET -Uri "$($script:GraphBase)/deviceManagement/deviceConfigurations/microsoft.graph.getIosAvailableUpdateVersions()"
        $updates = @(Get-ObjectValue $response 'value')
        $latestByModel = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        $now = [datetime]::UtcNow
        foreach ($update in $updates) {
            $version = (Get-ObjectString $update 'productVersion').Trim()
            if ([string]::IsNullOrWhiteSpace($version)) { continue }
            $posted = ConvertFrom-GraphDate (Get-ObjectValue $update 'postingDateTime')
            $expires = ConvertFrom-GraphDate (Get-ObjectValue $update 'expirationDateTime')
            if ($posted -is [datetime] -and $posted -gt $now) { continue }
            if ($expires -is [datetime] -and $expires -lt $now) { continue }
            foreach ($supportedDevice in @(Get-ObjectValue $update 'supportedDevices')) {
                $key = ConvertTo-NormalizedAppleModel ([string]$supportedDevice)
                if ([string]::IsNullOrWhiteSpace($key)) { continue }
                if (-not $latestByModel.ContainsKey($key) -or (Compare-DottedVersion $version $latestByModel[$key]) -gt 0) {
                    $latestByModel[$key] = $version
                }
            }
        }
        if ($latestByModel.Count -eq 0) { throw 'The iOS update feed contained no active model mappings.' }

        $hardwareById = [Collections.Generic.Dictionary[string, string]]::new([StringComparer]::OrdinalIgnoreCase)
        $requests = [ordered]@{}
        foreach ($device in $iosDevices) {
            $modelKey = ConvertTo-NormalizedAppleModel (Get-ObjectString $device 'model')
            if (-not [string]::IsNullOrWhiteSpace($modelKey) -and $latestByModel.ContainsKey($modelKey)) { continue }
            $embedded = Get-EmbeddedIosProductName $device
            if (-not [string]::IsNullOrWhiteSpace($embedded)) { continue }
            $id = (Get-ObjectString $device 'id').Trim()
            if (-not [string]::IsNullOrWhiteSpace($id) -and -not $requests.Contains($id)) {
                $requests[$id] = "$($script:GraphBase)/deviceManagement/managedDevices/$id?`$select=hardwareInformation"
            }
        }
        if ($requests.Count -gt 0) {
            $details = Invoke-GraphBatchGet -Requests $requests -StatusLabel 'Fetching iOS hardware details' -ContinueOnError
            foreach ($id in $requests.Keys) {
                if (-not $details.ContainsKey([string]$id)) { continue }
                $hardware = Get-ObjectValue $details[[string]$id] 'hardwareInformation'
                $hardwareById[[string]$id] = (Get-ObjectString $hardware 'productName').Trim()
            }
        }

        $current = 0
        $eligible = 0
        foreach ($device in $iosDevices) {
            $availableVersion = ''
            $modelKey = ConvertTo-NormalizedAppleModel (Get-ObjectString $device 'model')
            if (-not [string]::IsNullOrWhiteSpace($modelKey) -and $latestByModel.ContainsKey($modelKey)) {
                $availableVersion = $latestByModel[$modelKey]
            }
            if ([string]::IsNullOrWhiteSpace($availableVersion)) {
                $productName = Get-EmbeddedIosProductName $device
                if ([string]::IsNullOrWhiteSpace($productName)) {
                    $id = (Get-ObjectString $device 'id').Trim()
                    if ($hardwareById.ContainsKey($id)) { $productName = $hardwareById[$id] }
                }
                $productKey = ConvertTo-NormalizedAppleModel $productName
                if (-not [string]::IsNullOrWhiteSpace($productKey) -and $latestByModel.ContainsKey($productKey)) {
                    $availableVersion = $latestByModel[$productKey]
                }
            }
            $installedVersion = (Get-ObjectString $device 'osVersion').Trim()
            if ([string]::IsNullOrWhiteSpace($availableVersion) -or [string]::IsNullOrWhiteSpace($installedVersion)) { continue }
            $eligible++
            if ((Compare-DottedVersion $installedVersion $availableVersion) -ge 0) { $current++ }
        }
        if ($eligible -ne $iosDevices.Count) {
            return [pscustomobject]@{ Available = $false; Current = 0; Eligible = 0 }
        }
        return [pscustomobject]@{ Available = $true; Current = $current; Eligible = $eligible }
    }
    catch {
        Write-Warning "iOS update coverage is unavailable: $($_.Exception.Message)"
        return [pscustomobject]@{ Available = $false; Current = 0; Eligible = 0 }
    }
}

function ConvertTo-OleColor {
    param([Parameter(Mandatory)][int] $Red, [Parameter(Mandatory)][int] $Green, [Parameter(Mandatory)][int] $Blue)
    return $Red + (256 * $Green) + (65536 * $Blue)
}

function ConvertTo-ExcelMatrix {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Rows,
        [Parameter(Mandatory)][int] $ColumnCount
    )
    $matrix = [object[,]]::new($Rows.Count, $ColumnCount)
    for ($rowIndex = 0; $rowIndex -lt $Rows.Count; $rowIndex++) {
        $row = @($Rows[$rowIndex])
        for ($columnIndex = 0; $columnIndex -lt $ColumnCount; $columnIndex++) {
            $value = if ($columnIndex -lt $row.Count) { $row[$columnIndex] } else { $null }
            if ($value -is [datetime]) {
                $matrix[$rowIndex, $columnIndex] = ([datetime]$value).ToOADate()
            }
            elseif ($value -is [DateTimeOffset]) {
                $matrix[$rowIndex, $columnIndex] = ([DateTimeOffset]$value).UtcDateTime.ToOADate()
            }
            else {
                $matrix[$rowIndex, $columnIndex] = Protect-ExcelText $value
            }
        }
    }
    return ,$matrix
}

function Add-ExcelCellRule {
    param(
        [Parameter(Mandatory)][object] $Range,
        [Parameter(Mandatory)][int] $Operator,
        [Parameter(Mandatory)][string] $Formula,
        [Parameter(Mandatory)][int] $FontColor,
        [Parameter(Mandatory)][int] $FillColor,
        [switch] $StopIfTrue
    )
    $condition = $Range.FormatConditions.Add(1, $Operator, $Formula)
    $condition.Font.Color = $FontColor
    $condition.Interior.Color = $FillColor
    if ($StopIfTrue) { $condition.StopIfTrue = $true }
}

function Add-ExcelTextRule {
    param(
        [Parameter(Mandatory)][object] $Range,
        [Parameter(Mandatory)][string] $Text,
        [Parameter(Mandatory)][int] $FontColor,
        [Parameter(Mandatory)][int] $FillColor
    )
    Add-ExcelCellRule -Range $Range -Operator 3 -Formula ('="' + $Text.Replace('"', '""') + '"') `
        -FontColor $FontColor -FillColor $FillColor
}

function Set-CommonColumnFormatting {
    param([Parameter(Mandatory)][object] $Table)
    if ($null -eq $Table.DataBodyRange) { return }
    $redFont = ConvertTo-OleColor 176 35 35
    $redFill = ConvertTo-OleColor 252 233 231
    $amberFont = ConvertTo-OleColor 158 95 0
    $amberFill = ConvertTo-OleColor 255 243 214
    $greenFont = ConvertTo-OleColor 28 108 54
    $greenFill = ConvertTo-OleColor 226 242 230
    $greyFont = ConvertTo-OleColor 91 100 113
    $greyFill = ConvertTo-OleColor 235 238 242
    for ($index = 1; $index -le $Table.ListColumns.Count; $index++) {
        $column = $Table.ListColumns.Item($index)
        $name = ConvertTo-NormalizedName ([string]$column.Name)
        $range = $column.DataBodyRange
        if ($null -eq $range) { continue }

        if ($name -match 'count|days|year') {
            $range.NumberFormat = '#,##0'
        }
        elseif ($name -match 'date|time|enrolled|checkin|deleted|expires|sync|created|modified|updated') {
            $range.NumberFormat = 'dd-mm-yyyy'
        }
        elseif ($name.Contains('gb')) { $range.NumberFormat = '#,##0.0' }

        try {
            if ($name.Contains('dayssince')) {
                Add-ExcelCellRule $range 7 '90' $redFont $redFill -StopIfTrue
                Add-ExcelCellRule $range 7 '30' $amberFont $amberFill
            }
            elseif ($name.Contains('untilexpiry')) {
                Add-ExcelCellRule $range 6 '0' $redFont $redFill -StopIfTrue
                Add-ExcelCellRule $range 8 '30' $amberFont $amberFill
            }
            elseif ($name.Contains('pending')) {
                Add-ExcelCellRule $range 5 '0' $amberFont $amberFill
            }
            elseif ($name.Contains('notinstalled') -or $name.Contains('notapplicable')) {
                # These inventory states are neutral rather than failures or
                # successes, despite containing the word "installed".
            }
            elseif ($name -match 'failed|error|conflict|noncompliant') {
                Add-ExcelCellRule $range 5 '0' $redFont $redFill
            }
            elseif ($name -match 'success|compliant|installed') {
                $bar = $range.FormatConditions.AddDatabar()
                $bar.BarColor.Color = ConvertTo-OleColor 0 114 198
            }

            if ($name -in @('compliance','compliancestate')) {
                Add-ExcelTextRule $range 'Compliant' $greenFont $greenFill
                Add-ExcelTextRule $range 'Noncompliant' $redFont $redFill
                Add-ExcelTextRule $range 'In grace period' $amberFont $amberFill
                Add-ExcelTextRule $range 'Error' $redFont $redFill
                Add-ExcelTextRule $range 'Conflict' $redFont $redFill
            }
            elseif ($name -eq 'encrypted') {
                Add-ExcelTextRule $range 'No' $redFont $redFill
            }
            elseif ($name -eq 'status') {
                Add-ExcelTextRule $range 'Healthy' $greenFont $greenFill
                Add-ExcelTextRule $range 'Expiring soon' $amberFont $amberFill
                Add-ExcelTextRule $range 'Expired' $redFont $redFill
                Add-ExcelTextRule $range 'Needs attention' $redFont $redFill
                Add-ExcelTextRule $range 'Unavailable' $greyFont $greyFill
            }
        }
        catch {
            Write-Verbose "Conditional formatting could not be applied to '$($column.Name)': $($_.Exception.Message)"
        }
    }
}

function Set-WorksheetView {
    param([Parameter(Mandatory)][object] $Excel, [Parameter(Mandatory)][object] $Worksheet)
    $Worksheet.Activate() | Out-Null
    $Excel.ActiveWindow.FreezePanes = $false
    $Excel.ActiveWindow.SplitColumn = 0
    $Excel.ActiveWindow.SplitRow = 3
    $Excel.ActiveWindow.FreezePanes = $true
    $Excel.ActiveWindow.DisplayGridlines = $false
    $Worksheet.Range('A1').Select() | Out-Null
}

function Write-DataSheet {
    param(
        [Parameter(Mandatory)][object] $Excel,
        [Parameter(Mandatory)][object] $Workbook,
        [Parameter(Mandatory)][string] $SheetName,
        [Parameter(Mandatory)][string] $TableName,
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][object] $Report,
        [Parameter(Mandatory)][int] $TabColor,
        [AllowNull()][string] $Subtitle = $null
    )
    $worksheet = $Workbook.Worksheets.Add([Type]::Missing, $Workbook.Worksheets.Item($Workbook.Worksheets.Count))
    $worksheet.Name = $SheetName
    $worksheet.Cells.Font.Name = 'Segoe UI'
    $worksheet.Cells.Font.Size = 10

    $rawHeaders = @($Report.Headers)
    $headers = @(
        for ($headerIndex = 0; $headerIndex -lt $rawHeaders.Count; $headerIndex++) {
            $rawHeader = [string]$rawHeaders[$headerIndex]
            if ([string]::IsNullOrWhiteSpace($rawHeader)) {
                # A live report schema can occasionally return a blank column name.
                # Excel tables reject blank (and duplicate) headers, so substitute a
                # stable placeholder rather than aborting the whole workbook.
                "Column $($headerIndex + 1)"
            }
            else {
                ConvertTo-PrettyHeader $rawHeader
            }
        }
    )
    $rowCount = @($Report.Rows).Count
    $columnCount = $headers.Count
    if ($columnCount -le 0) { throw "$SheetName has no columns." }

    $headerMatrix = [object[,]]::new(1, $columnCount)
    for ($columnIndex = 0; $columnIndex -lt $columnCount; $columnIndex++) {
        $headerMatrix[0, $columnIndex] = Protect-ExcelText $headers[$columnIndex]
    }
    $worksheet.Range($worksheet.Cells.Item(3, 1), $worksheet.Cells.Item(3, $columnCount)).Value2 = $headerMatrix
    if ($rowCount -gt 0) {
        $dataMatrix = ConvertTo-ExcelMatrix -Rows @($Report.Rows) -ColumnCount $columnCount
        $worksheet.Range($worksheet.Cells.Item(4, 1), $worksheet.Cells.Item(3 + $rowCount, $columnCount)).Value2 = $dataMatrix
    }

    $lastTableRow = if ($rowCount -gt 0) { 3 + $rowCount } else { 4 }
    $tableRange = $worksheet.Range($worksheet.Cells.Item(3, 1), $worksheet.Cells.Item($lastTableRow, $columnCount))
    $table = $worksheet.ListObjects.Add(1, $tableRange, $null, 1)
    $table.Name = $TableName
    try { $table.TableStyle = 'TableStyleMedium2' } catch { }

    $navy = ConvertTo-OleColor 31 45 65
    $white = ConvertTo-OleColor 255 255 255
    $muted = ConvertTo-OleColor 120 128 138
    $wide = [math]::Max(6, $columnCount)
    $worksheet.Rows.Item(1).RowHeight = 30
    $worksheet.Rows.Item(2).RowHeight = 15
    $worksheet.Range($worksheet.Cells.Item(1, 1), $worksheet.Cells.Item(1, $wide)).Interior.Color = $navy
    $worksheet.Cells.Item(1, 1).Value2 = Protect-ExcelText $Title
    $worksheet.Cells.Item(1, 1).Font.Color = $white
    $worksheet.Cells.Item(1, 1).Font.Bold = $true
    $worksheet.Cells.Item(1, 1).Font.Size = 13
    $worksheet.Cells.Item(1, 1).IndentLevel = 1
    $worksheet.Cells.Item(1, 1).VerticalAlignment = -4108
    if ([string]::IsNullOrWhiteSpace($Subtitle)) {
        $noun = if ($rowCount -eq 1) { 'row' } else { 'rows' }
        $Subtitle = ('{0:N0} {1}  |  generated {2:dd-MM-yyyy}' -f $rowCount, $noun, (Get-Date))
    }
    $worksheet.Cells.Item(2, 1).Value2 = Protect-ExcelText $Subtitle
    $worksheet.Cells.Item(2, 1).Font.Size = 8.5
    $worksheet.Cells.Item(2, 1).Font.Color = $muted
    $worksheet.Cells.Item(2, 1).IndentLevel = 1
    $worksheet.Cells.Item(2, 1).VerticalAlignment = -4108

    $header = $table.HeaderRowRange
    $header.Interior.Color = $navy
    $header.Font.Color = $white
    $header.Font.Bold = $true
    $header.HorizontalAlignment = -4108
    $header.VerticalAlignment = -4108
    $header.RowHeight = 18
    if ($null -ne $table.DataBodyRange) {
        $table.DataBodyRange.HorizontalAlignment = -4108
    }
    $table.Range.Columns.AutoFit() | Out-Null
    for ($column = 1; $column -le $columnCount; $column++) {
        if ($worksheet.Columns.Item($column).ColumnWidth -gt 48) { $worksheet.Columns.Item($column).ColumnWidth = 48 }
        if ($worksheet.Columns.Item($column).ColumnWidth -lt 9) { $worksheet.Columns.Item($column).ColumnWidth = 9 }
    }
    Set-CommonColumnFormatting -Table $table
    $worksheet.Tab.Color = $TabColor
    Set-WorksheetView -Excel $Excel -Worksheet $worksheet
    return [pscustomobject]@{ Worksheet = $worksheet; Table = $table }
}

function Format-Percentage {
    param(
        [Parameter(Mandatory)][double] $Part,
        [Parameter(Mandatory)][double] $Total
    )
    if ($Total -le 0) { return 'n/a' }
    return ('{0:0.0}%' -f (($Part / $Total) * 100.0))
}

function ConvertTo-DashboardNumber {
    param([AllowNull()][object] $Value)
    if ($null -eq $Value) { return 0.0 }
    $number = 0.0
    if ([double]::TryParse(
            [string]$Value,
            [Globalization.NumberStyles]::Any,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$number)) {
        return $number
    }
    return 0.0
}

function Find-DashboardHeaderIndex {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]] $Headers,
        [Parameter(Mandatory)][string[]] $Candidates
    )
    foreach ($candidate in $Candidates) {
        $wanted = ConvertTo-NormalizedName $candidate
        for ($index = 0; $index -lt $Headers.Count; $index++) {
            if ((ConvertTo-NormalizedName $Headers[$index]) -eq $wanted) { return $index }
        }
    }
    foreach ($candidate in $Candidates) {
        $wanted = ConvertTo-NormalizedName $candidate
        for ($index = 0; $index -lt $Headers.Count; $index++) {
            if ((ConvertTo-NormalizedName $Headers[$index]).Contains($wanted, [StringComparison]::OrdinalIgnoreCase)) {
                return $index
            }
        }
    }
    return -1
}

function Get-TopCountRows {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Pairs,
        [Parameter(Mandatory)][ValidateRange(1, 1000)][int] $Maximum
    )
    $rows = @(
        foreach ($pair in $Pairs) {
            if ($null -eq $pair) { continue }
            if ($pair -is [array]) {
                if ($pair.Count -lt 2) { continue }
                $label = [string]$pair[0]
                $value = ConvertTo-DashboardNumber $pair[1]
            }
            else {
                $label = [string](Get-ObjectValue $pair 'Label' '')
                $value = ConvertTo-DashboardNumber (Get-ObjectValue $pair 'Value' 0)
            }
            if ([string]::IsNullOrWhiteSpace($label)) { $label = '(unknown)' }
            [pscustomobject]@{ Label = $label; Value = $value }
        }
    )
    if ($rows.Count -eq 0) { return @() }
    return @(
        $rows |
            Sort-Object -Property @{ Expression = { [double]$_.Value }; Descending = $true },
                @{ Expression = { [string]$_.Label }; Descending = $false } |
            Select-Object -First $Maximum
    )
}

function Add-KpiCard {
    param(
        [Parameter(Mandatory)][object] $Worksheet,
        [Parameter(Mandatory)][int] $TopRow,
        [Parameter(Mandatory)][int] $StartColumn,
        [Parameter(Mandatory)][string] $ValueText,
        [Parameter(Mandatory)][string] $LabelText,
        [Parameter(Mandatory)][int] $AccentColor
    )
    $white = ConvertTo-OleColor 255 255 255
    $valueColor = ConvertTo-OleColor 33 43 54
    $labelColor = ConvertTo-OleColor 122 130 140
    $borderColor = ConvertTo-OleColor 218 224 232
    $box = $Worksheet.Range(
        $Worksheet.Cells.Item($TopRow, $StartColumn),
        $Worksheet.Cells.Item($TopRow + 3, $StartColumn + 2)
    )
    $box.Interior.Color = $white
    $box.Borders.LineStyle = -4142

    $bar = $Worksheet.Range(
        $Worksheet.Cells.Item($TopRow, $StartColumn),
        $Worksheet.Cells.Item($TopRow, $StartColumn + 2)
    )
    $null = $bar.Merge()
    $bar.Interior.Color = $AccentColor

    $valueRange = $Worksheet.Range(
        $Worksheet.Cells.Item($TopRow + 1, $StartColumn),
        $Worksheet.Cells.Item($TopRow + 1, $StartColumn + 2)
    )
    $null = $valueRange.Merge()
    $valueRange.Value2 = Protect-ExcelText $ValueText
    $valueRange.Font.Size = 20
    $valueRange.Font.Bold = $true
    $valueRange.Font.Color = $valueColor
    $valueRange.HorizontalAlignment = -4108
    $valueRange.VerticalAlignment = -4107

    $labelRange = $Worksheet.Range(
        $Worksheet.Cells.Item($TopRow + 2, $StartColumn),
        $Worksheet.Cells.Item($TopRow + 2, $StartColumn + 2)
    )
    $null = $labelRange.Merge()
    $labelRange.Value2 = Protect-ExcelText $LabelText.ToUpperInvariant()
    $labelRange.Font.Size = 7.5
    $labelRange.Font.Color = $labelColor
    $labelRange.HorizontalAlignment = -4108
    $labelRange.VerticalAlignment = -4108

    $footer = $Worksheet.Range(
        $Worksheet.Cells.Item($TopRow + 3, $StartColumn),
        $Worksheet.Cells.Item($TopRow + 3, $StartColumn + 2)
    )
    $null = $footer.Merge()
    try { $null = $box.BorderAround(1, 2, [Type]::Missing, $borderColor) }
    catch { Write-Verbose "The border for KPI '$LabelText' could not be applied: $($_.Exception.Message)" }
}

function Write-ChartPairs {
    param(
        [Parameter(Mandatory)][object] $Worksheet,
        [Parameter(Mandatory)][int] $StartColumn,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Pairs
    )
    if ($Pairs.Count -le 0) { throw 'A chart source cannot be empty.' }
    for ($index = 0; $index -lt $Pairs.Count; $index++) {
        $label = [string](Get-ObjectValue $Pairs[$index] 'Label' '')
        if ($label.Length -gt 34) { $label = $label.Substring(0, 32) + '...' }
        # Scalar writes are intentional here. Excel's COM binder can treat a
        # multi-dimensional Object array as a scalar on hidden chart sources.
        $Worksheet.Cells.Item(2 + $index, $StartColumn).Value2 = Protect-ExcelText $label
        # The Value2 setter can retain a string-only late-bound call site after
        # the adjacent label write in PowerShell 7. Value preserves the Double.
        $Worksheet.Cells.Item(2 + $index, $StartColumn + 1).Value = [double](
            ConvertTo-DashboardNumber (Get-ObjectValue $Pairs[$index] 'Value' 0)
        )
    }
    $sourceRange = $Worksheet.Range(
        $Worksheet.Cells.Item(2, $StartColumn),
        $Worksheet.Cells.Item(1 + $Pairs.Count, $StartColumn + 1)
    )
    return [pscustomobject]@{ Range = $sourceRange; Count = $Pairs.Count }
}

function Set-DashboardSingleSeries {
    param(
        [Parameter(Mandatory)][object] $Chart,
        [Parameter(Mandatory)][object] $SourceRange,
        [Parameter(Mandatory)][string] $SeriesName
    )
    $seriesCollection = $Chart.SeriesCollection()
    while ([int]$seriesCollection.Count -gt 0) {
        $null = $seriesCollection.Item(1).Delete()
    }
    $series = $seriesCollection.NewSeries()
    $series.Name = $SeriesName
    $series.XValues = $SourceRange.Columns.Item(1)
    $series.Values = $SourceRange.Columns.Item(2)
    return [pscustomobject]@{ Series = $series }
}

function Set-DashboardChartShell {
    param(
        [Parameter(Mandatory)][object] $Shape,
        [Parameter(Mandatory)][string] $Title
    )
    $chart = $Shape.Chart
    try {
        $chart.PlotVisibleOnly = $false
        $chart.HasTitle = $true
        $chart.ChartTitle.Text = $Title
        $chart.ChartTitle.IncludeInLayout = $true
        $chart.ChartArea.Format.Fill.ForeColor.RGB = ConvertTo-OleColor 255 255 255
        $chart.ChartArea.Format.Line.ForeColor.RGB = ConvertTo-OleColor 218 224 232
        $chart.ChartArea.Format.Line.Weight = 1
        $chart.ChartArea.Font.Name = 'Segoe UI'
        $chart.ChartArea.Font.Size = 9
        $chart.ChartArea.Font.Color = ConvertTo-OleColor 80 90 102
        $chart.ChartTitle.Font.Size = 11
        $chart.ChartTitle.Font.Bold = $true
        $chart.ChartTitle.Font.Color = ConvertTo-OleColor 31 45 65
        $chart.PlotArea.Format.Fill.Visible = 0
    }
    catch {
        Write-Verbose "Some formatting for chart '$Title' could not be applied: $($_.Exception.Message)"
    }
}

function Add-DoughnutChart {
    param(
        [Parameter(Mandatory)][object] $Worksheet,
        [Parameter(Mandatory)][object] $SourceRange,
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][double] $Left,
        [Parameter(Mandatory)][double] $Top,
        [Parameter(Mandatory)][double] $Width,
        [Parameter(Mandatory)][double] $Height,
        [Parameter(Mandatory)][int[]] $Colors
    )
    $shape = $Worksheet.Shapes.AddChart2(-1, -4120, $Left, $Top, $Width, $Height)
    $binding = Set-DashboardSingleSeries -Chart $shape.Chart -SourceRange $SourceRange -SeriesName 'Devices'
    Set-DashboardChartShell -Shape $shape -Title $Title
    try {
        $chart = $shape.Chart
        $chart.HasLegend = $true
        $chart.Legend.Position = -4107
        $chart.Legend.Font.Size = 9
        $chart.ChartGroups().Item(1).DoughnutHoleSize = 62
        $series = $binding.Series
        for ($index = 0; $index -lt $Colors.Count; $index++) {
            $series.Points().Item($index + 1).Format.Fill.ForeColor.RGB = $Colors[$index]
        }
        $null = $series.ApplyDataLabels()
        $labels = $series.DataLabels()
        $labels.ShowValue = $false
        $labels.ShowPercentage = $true
        $labels.NumberFormat = '0%'
        $labels.Font.Size = 9
        $labels.Font.Bold = $true
        $labels.Font.Color = ConvertTo-OleColor 255 255 255
    }
    catch {
        Write-Verbose "Some doughnut-chart formatting for '$Title' could not be applied: $($_.Exception.Message)"
    }
}

function Add-BarChart {
    param(
        [Parameter(Mandatory)][object] $Worksheet,
        [Parameter(Mandatory)][object] $SourceRange,
        [Parameter(Mandatory)][string] $Title,
        [Parameter(Mandatory)][double] $Left,
        [Parameter(Mandatory)][double] $Top,
        [Parameter(Mandatory)][double] $Width,
        [Parameter(Mandatory)][double] $Height,
        [Parameter(Mandatory)][int] $BarColor,
        [switch] $Percentage
    )
    $shape = $Worksheet.Shapes.AddChart2(-1, 57, $Left, $Top, $Width, $Height)
    $seriesName = if ($Percentage) { 'Percent complete' } else { 'Devices' }
    $binding = Set-DashboardSingleSeries -Chart $shape.Chart -SourceRange $SourceRange -SeriesName $seriesName
    Set-DashboardChartShell -Shape $shape -Title $Title
    try {
        $chart = $shape.Chart
        $series = $binding.Series
        $chart.HasLegend = $false
        $series.Format.Fill.ForeColor.RGB = $BarColor
        $categoryAxis = $chart.Axes(1, 1)
        $categoryAxis.ReversePlotOrder = $true
        $categoryAxis.MajorTickMark = -4142
        $categoryAxis.TickLabels.Font.Size = if ($Percentage) { 8 } else { 9 }
        $chart.ChartGroups().Item(1).GapWidth = 55
        $valueAxis = $chart.Axes(2, 1)
        if ($Percentage) {
            $valueAxis.MinimumScale = 0
            $valueAxis.MaximumScale = 1
            $valueAxis.TickLabels.NumberFormat = '0%'
            $valueAxis.MajorGridlines.Format.Line.ForeColor.RGB = ConvertTo-OleColor 230 234 239
        }
        else {
            $categoryAxis.Format.Line.ForeColor.RGB = ConvertTo-OleColor 203 210 219
            try { $null = $valueAxis.MajorGridlines.Delete() } catch { }
            $null = $valueAxis.Delete()
            if ($Width -gt 600) {
                $chart.PlotArea.InsideLeft = 245
                $chart.PlotArea.InsideTop = 42
                $chart.PlotArea.InsideHeight = $Height - 70
                $chart.PlotArea.InsideWidth = $Width - 275
            }
        }
        $null = $series.ApplyDataLabels()
        $labels = $series.DataLabels()
        $labels.Font.Size = 9
        if ($Percentage) {
            $labels.Font.Bold = $true
            $labels.Font.Color = ConvertTo-OleColor 46 83 70
            $labels.NumberFormat = '0%'
        }
        else {
            $labels.Font.Color = ConvertTo-OleColor 96 104 114
            $labels.NumberFormat = '#,##0'
        }
    }
    catch {
        Write-Verbose "Some bar-chart formatting for '$Title' could not be applied: $($_.Exception.Message)"
    }
}

function Add-ChartNote {
    param(
        [Parameter(Mandatory)][object] $Worksheet,
        [Parameter(Mandatory)][double] $Left,
        [Parameter(Mandatory)][double] $Top,
        [Parameter(Mandatory)][double] $Width,
        [Parameter(Mandatory)][double] $Height,
        [Parameter(Mandatory)][string] $Message
    )
    $shape = $Worksheet.Shapes.AddShape(1, $Left, $Top, $Width, $Height)
    try {
        $shape.Fill.ForeColor.RGB = ConvertTo-OleColor 255 255 255
        $shape.Line.ForeColor.RGB = ConvertTo-OleColor 218 224 232
        $shape.Line.Weight = 1
        $shape.TextFrame2.TextRange.Text = $Message
        $shape.TextFrame2.VerticalAnchor = 3
        $shape.TextFrame2.TextRange.ParagraphFormat.Alignment = 2
        $shape.TextFrame2.TextRange.Font.Name = 'Segoe UI'
        $shape.TextFrame2.TextRange.Font.Size = 9
        $shape.TextFrame2.TextRange.Font.Italic = -1
        $shape.TextFrame2.TextRange.Font.Fill.ForeColor.RGB = ConvertTo-OleColor 120 128 138
    }
    catch {
        Write-Verbose "Some empty-state formatting could not be applied: $($_.Exception.Message)"
    }
}

function Build-DashboardSheet {
    param(
        [Parameter(Mandatory)][object] $Excel,
        [Parameter(Mandatory)][object] $Workbook,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]] $Devices,
        [AllowNull()][object] $AppsReport = $null,
        [AllowNull()][object] $DeletedReport = $null,
        [AllowNull()][object] $ConnectorsReport = $null,
        [AllowNull()][object] $IosUpdateSummary = $null,
        [AllowNull()][object] $AutopatchSummary = $null,
        [AllowNull()][string] $UserLabel = 'unknown'
    )
    $worksheet = $null
    try { $worksheet = $Workbook.Worksheets.Item('Dashboard') } catch { }
    if ($null -eq $worksheet) {
        $worksheet = $Workbook.Worksheets.Add($Workbook.Worksheets.Item(1), [Type]::Missing)
        $worksheet.Name = 'Dashboard'
    }
    elseif ([int]$worksheet.Index -ne 1) {
        $null = $worksheet.Move($Workbook.Worksheets.Item(1), [Type]::Missing)
        $worksheet = $Workbook.Worksheets.Item('Dashboard')
    }

    for ($shapeIndex = [int]$worksheet.Shapes.Count; $shapeIndex -ge 1; $shapeIndex--) {
        $null = $worksheet.Shapes.Item($shapeIndex).Delete()
    }
    $null = $worksheet.Cells.UnMerge()
    $null = $worksheet.Cells.Clear()

    $total = @($Devices).Count
    $compliant = 0
    $noncompliant = 0
    $inGrace = 0
    $errorOrConflict = 0
    $otherCompliance = 0
    $stale = 0
    $osCounts = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
    $modelCounts = [Collections.Generic.Dictionary[string, int]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($device in @($Devices)) {
        switch ((Get-ObjectString $device 'complianceState').Trim().ToLowerInvariant()) {
            'compliant'     { $compliant++; break }
            'noncompliant'  { $noncompliant++; break }
            'ingraceperiod' { $inGrace++; break }
            'error'         { $errorOrConflict++; break }
            'conflict'      { $errorOrConflict++; break }
            default         { $otherCompliance++ }
        }
        $lastSync = ConvertFrom-GraphDate (Get-ObjectValue $device 'lastSyncDateTime')
        if ($lastSync -isnot [datetime] -or $lastSync -lt [datetime]::UtcNow.AddDays(-30)) { $stale++ }

        $osLabel = Get-DashboardOsLabel `
            -OperatingSystem (Get-ObjectString $device 'operatingSystem') `
            -EnrollmentType (Get-ObjectString $device 'deviceEnrollmentType')
        if ($osCounts.ContainsKey($osLabel)) { $osCounts[$osLabel]++ } else { $osCounts[$osLabel] = 1 }
        $modelLabel = Get-DeviceModelLabel `
            -Manufacturer (Get-ObjectString $device 'manufacturer') `
            -Model (Get-ObjectString $device 'model')
        if ($modelCounts.ContainsKey($modelLabel)) { $modelCounts[$modelLabel]++ } else { $modelCounts[$modelLabel] = 1 }
    }

    $appPairs = [Collections.Generic.List[object]]::new()
    $appsWithFailures = 0
    $appsAvailable = $false
    if ($null -ne $AppsReport) {
        $appHeaders = [string[]]@(Get-ObjectValue $AppsReport 'Headers' @())
        $failedIndex = Find-DashboardHeaderIndex -Headers $appHeaders -Candidates @('FailedDeviceCount','Failed Device Count','Failed Device','Failed')
        $nameIndex = Find-DashboardHeaderIndex -Headers $appHeaders -Candidates @('DisplayName','Application','AppName','App','Name')
        if ($failedIndex -ge 0) {
            $appsAvailable = $true
            if ($nameIndex -lt 0) { $nameIndex = 0 }
            foreach ($row in @(Get-ObjectValue $AppsReport 'Rows' @())) {
                $values = @($row)
                if ($failedIndex -ge $values.Count) { continue }
                $failed = ConvertTo-DashboardNumber $values[$failedIndex]
                if ($failed -le 0) { continue }
                $appsWithFailures++
                $name = if ($nameIndex -lt $values.Count) { ([string]$values[$nameIndex]).Trim() } else { '' }
                if ([string]::IsNullOrWhiteSpace($name)) { $name = '(unnamed app)' }
                $appPairs.Add([pscustomobject]@{ Label = $name; Value = $failed })
            }
        }
    }

    $deletedCount = 0
    $deletedAvailable = $null -ne $DeletedReport
    if ($deletedAvailable) {
        foreach ($row in @(Get-ObjectValue $DeletedReport 'Rows' @())) {
            $values = @($row)
            if ($values.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace([string]$values[0])) { $deletedCount++ }
        }
    }

    $connectorsExpiring = 0
    $connectorsAvailable = $false
    if ($null -ne $ConnectorsReport) {
        $connectorHeaders = [string[]]@(Get-ObjectValue $ConnectorsReport 'Headers' @())
        $statusIndex = Find-DashboardHeaderIndex -Headers $connectorHeaders -Candidates @('Status')
        if ($statusIndex -ge 0) {
            $connectorsAvailable = $true
            foreach ($row in @(Get-ObjectValue $ConnectorsReport 'Rows' @())) {
                $values = @($row)
                if ($statusIndex -ge $values.Count) { continue }
                $status = ([string]$values[$statusIndex]).Trim()
                if ($status.Equals('Unavailable', [StringComparison]::OrdinalIgnoreCase)) {
                    $connectorsAvailable = $false
                }
                elseif ($status.Equals('Expiring soon', [StringComparison]::OrdinalIgnoreCase)) {
                    $connectorsExpiring++
                }
            }
        }
    }

    $iosAvailable = $null -ne $IosUpdateSummary -and [bool](Get-ObjectValue $IosUpdateSummary 'Available' $false)
    $iosCurrent = if ($iosAvailable) { ConvertTo-DashboardNumber (Get-ObjectValue $IosUpdateSummary 'Current' 0) } else { 0 }
    $iosEligible = if ($iosAvailable) { ConvertTo-DashboardNumber (Get-ObjectValue $IosUpdateSummary 'Eligible' 0) } else { 0 }
    $autopatchAvailable = $null -ne $AutopatchSummary -and [bool](Get-ObjectValue $AutopatchSummary 'Available' $false)
    $autopatchPairs = @(
        if ($autopatchAvailable) {
            foreach ($row in @(Get-ObjectValue $AutopatchSummary 'Rows' @())) {
                $values = @($row)
                if ($values.Count -ge 2) {
                    [pscustomobject]@{
                        Label = if ([string]::IsNullOrWhiteSpace([string]$values[0])) { 'Unnamed ring' } else { [string]$values[0] }
                        Value = ConvertTo-DashboardNumber $values[1]
                    }
                }
            }
        }
    )

    $canvas = ConvertTo-OleColor 246 248 251
    $navy = ConvertTo-OleColor 31 45 65
    $white = ConvertTo-OleColor 255 255 255
    $bylineColor = ConvertTo-OleColor 173 184 202
    $worksheet.Cells.Font.Name = 'Segoe UI'
    $worksheet.Cells.Font.Size = 10
    $worksheet.Cells.Interior.Color = $canvas
    $worksheet.Range($worksheet.Columns.Item(2), $worksheet.Columns.Item(28)).ColumnWidth = 10
    $worksheet.Columns.Item(1).ColumnWidth = 2.5
    $worksheet.Columns.Item(17).ColumnWidth = 2.5
    foreach ($column in @(5, 9, 13)) { $worksheet.Columns.Item($column).ColumnWidth = 3.5 }

    $worksheet.Rows.Item(1).RowHeight = 42
    $worksheet.Rows.Item(2).RowHeight = 10
    $worksheet.Range($worksheet.Cells.Item(1, 1), $worksheet.Cells.Item(1, 17)).Interior.Color = $navy
    $worksheet.Cells.Item(1, 2).Value2 = Protect-ExcelText 'Microsoft Intune - Report Dashboard'
    $worksheet.Cells.Item(1, 2).Font.Size = 15
    $worksheet.Cells.Item(1, 2).Font.Bold = $true
    $worksheet.Cells.Item(1, 2).Font.Color = $white
    $worksheet.Cells.Item(1, 2).VerticalAlignment = -4108
    $displayUser = ([string]$UserLabel).Trim()
    $atPosition = $displayUser.IndexOf('@', [StringComparison]::Ordinal)
    if ($atPosition -gt 0) { $displayUser = $displayUser.Substring(0, $atPosition) }
    if ([string]::IsNullOrWhiteSpace($displayUser)) { $displayUser = 'unknown' }
    $worksheet.Cells.Item(1, 16).Value2 = Protect-ExcelText ('Generated by {0} on {1:dd-MM-yyyy}.' -f $displayUser, (Get-Date))
    $worksheet.Cells.Item(1, 16).Font.Size = 8.5
    $worksheet.Cells.Item(1, 16).Font.Color = $bylineColor
    $worksheet.Cells.Item(1, 16).HorizontalAlignment = -4152
    $worksheet.Cells.Item(1, 16).VerticalAlignment = -4108

    $worksheet.Rows.Item(3).RowHeight = 4
    $worksheet.Rows.Item(4).RowHeight = 30
    $worksheet.Rows.Item(5).RowHeight = 14
    $worksheet.Rows.Item(6).RowHeight = 6
    $worksheet.Rows.Item(7).RowHeight = 6
    $worksheet.Rows.Item(8).RowHeight = 4
    $worksheet.Rows.Item(9).RowHeight = 30
    $worksheet.Rows.Item(10).RowHeight = 14
    $worksheet.Rows.Item(11).RowHeight = 6
    $worksheet.Rows.Item(12).RowHeight = 12

    Add-KpiCard $worksheet 3 2 ('{0:N0}' -f $total) 'Managed devices' (ConvertTo-OleColor 31 78 120)
    Add-KpiCard $worksheet 3 6 (Format-Percentage $compliant $total) 'Compliant' (ConvertTo-OleColor 56 142 60)
    Add-KpiCard $worksheet 3 10 ('{0:N0}' -f $noncompliant) 'Noncompliant' (ConvertTo-OleColor 198 40 40)
    Add-KpiCard $worksheet 3 14 ('{0:N0}' -f $stale) 'Stale (30+ days)' (ConvertTo-OleColor 211 120 0)
    $iosText = if ($iosAvailable) { Format-Percentage $iosCurrent $iosEligible } else { 'n/a' }
    Add-KpiCard $worksheet 8 2 $iosText 'iOS Updates' (ConvertTo-OleColor 0 137 137)
    $appsText = if ($appsAvailable) { '{0:N0}' -f $appsWithFailures } else { 'n/a' }
    Add-KpiCard $worksheet 8 6 $appsText 'Apps w/ failed installs' (ConvertTo-OleColor 226 100 20)
    $deletedText = if ($deletedAvailable) { '{0:N0}' -f $deletedCount } else { 'n/a' }
    Add-KpiCard $worksheet 8 10 $deletedText 'Deleted (14 days)' (ConvertTo-OleColor 124 92 168)
    $connectorsText = if ($connectorsAvailable) { '{0:N0}' -f $connectorsExpiring } else { 'n/a' }
    Add-KpiCard $worksheet 8 14 $connectorsText 'Connectors expiring soon' (ConvertTo-OleColor 150 62 100)

    $null = $worksheet.Range($worksheet.Cells.Item(1, 29), $worksheet.Cells.Item(100, 44)).ClearContents()
    $chartRow = 13
    $left = [double]$worksheet.Cells.Item($chartRow, 2).Left
    $right = [double]$worksheet.Cells.Item($chartRow, 17).Left
    $gutter = 14.0
    $verticalGutter = 14.0
    $chartHeight = 232.0
    $modelHeight = 340.0
    $chartWidth = ($right - $left - $gutter) / 2.0
    $rightChartLeft = $left + $chartWidth + $gutter
    $topA = [double]$worksheet.Cells.Item($chartRow, 2).Top
    $topB = $topA + $chartHeight + $verticalGutter
    $topC = $topB + $chartHeight + $verticalGutter
    $topD = $topC + $modelHeight + $verticalGutter
    $fullWidth = $right - $left
    $appHeight = 206.0

    $compliancePairs = [Collections.Generic.List[object]]::new()
    $complianceColors = [Collections.Generic.List[int]]::new()
    foreach ($item in @(
            @('Compliant', $compliant, (ConvertTo-OleColor 87 166 96)),
            @('Noncompliant', $noncompliant, (ConvertTo-OleColor 212 74 66)),
            @('In grace period', $inGrace, (ConvertTo-OleColor 240 178 50)),
            @('Error / Conflict', $errorOrConflict, (ConvertTo-OleColor 150 62 152)),
            @('Other / Unknown', $otherCompliance, (ConvertTo-OleColor 158 165 173)))) {
        if ([double]$item[1] -le 0) { continue }
        $compliancePairs.Add([pscustomobject]@{ Label = [string]$item[0]; Value = [double]$item[1] })
        $complianceColors.Add([int]$item[2])
    }
    if ($compliancePairs.Count -gt 0) {
        $source = Write-ChartPairs $worksheet 30 $compliancePairs.ToArray()
        Add-DoughnutChart $worksheet $source.Range 'Device compliance' $left $topA $chartWidth $chartHeight $complianceColors.ToArray()
    }
    else {
        Add-ChartNote $worksheet $left $topA $chartWidth $chartHeight 'No device compliance data.'
    }

    if ($autopatchAvailable -and $autopatchPairs.Count -gt 0) {
        $source = Write-ChartPairs $worksheet 33 $autopatchPairs
        Add-BarChart $worksheet $source.Range 'Active Autopatch rings - percent complete' `
            $rightChartLeft $topA $chartWidth $chartHeight (ConvertTo-OleColor 46 125 90) -Percentage
    }
    elseif ($autopatchAvailable) {
        Add-ChartNote $worksheet $rightChartLeft $topA $chartWidth $chartHeight `
            'No feature-update rings are currently in progress.'
    }
    else {
        Add-ChartNote $worksheet $rightChartLeft $topA $chartWidth $chartHeight `
            'Windows Autopatch progress data unavailable.'
    }

    $osPairs = @(
        foreach ($entry in $osCounts.GetEnumerator()) {
            [pscustomobject]@{ Label = [string]$entry.Key; Value = [double]$entry.Value }
        }
    )
    $topOs = @(Get-TopCountRows -Pairs $osPairs -Maximum 8)
    if ($topOs.Count -gt 0) {
        $source = Write-ChartPairs $worksheet 36 $topOs
        Add-BarChart $worksheet $source.Range 'Devices by OS' $left $topB $fullWidth $chartHeight `
            (ConvertTo-OleColor 70 130 180)
    }
    else {
        Add-ChartNote $worksheet $left $topB $fullWidth $chartHeight 'No device data.'
    }

    $modelPairs = @(
        foreach ($entry in $modelCounts.GetEnumerator()) {
            [pscustomobject]@{ Label = [string]$entry.Key; Value = [double]$entry.Value }
        }
    )
    $topModels = @(Get-TopCountRows -Pairs $modelPairs -Maximum 20)
    if ($topModels.Count -gt 0) {
        $source = Write-ChartPairs $worksheet 39 $topModels
        Add-BarChart $worksheet $source.Range 'Devices by model' $left $topC $fullWidth $modelHeight `
            (ConvertTo-OleColor 96 110 168)
    }
    else {
        Add-ChartNote $worksheet $left $topC $fullWidth $modelHeight 'No device model data.'
    }

    $topApps = @(Get-TopCountRows -Pairs $appPairs.ToArray() -Maximum 12)
    if ($appsAvailable -and $topApps.Count -gt 0) {
        $source = Write-ChartPairs $worksheet 42 $topApps
        Add-BarChart $worksheet $source.Range 'Top apps by failed installs' $left $topD $fullWidth $appHeight `
            (ConvertTo-OleColor 212 105 40)
    }
    else {
        Add-ChartNote $worksheet $left $topD $fullWidth $appHeight 'No failed app installs reported.'
    }

    $worksheet.Range($worksheet.Columns.Item(29), $worksheet.Columns.Item(44)).EntireColumn.Hidden = $true
    $worksheet.Tab.Color = $navy
    $Workbook.Activate() | Out-Null
    $worksheet.Activate() | Out-Null
    $Excel.ActiveWindow.DisplayGridlines = $false
    $Excel.ActiveWindow.FreezePanes = $false
    $worksheet.Range('A1').Select() | Out-Null
    return $worksheet
}

function Resolve-ReportOutputPath {
    param(
        [Parameter(Mandatory)][string] $Path,
        [Parameter(Mandatory)][bool] $AllowOverwrite
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { throw 'OutputPath cannot be empty.' }
    try { $fullPath = [IO.Path]::GetFullPath($Path) }
    catch { throw "OutputPath is invalid: $($_.Exception.Message)" }
    if (-not [IO.Path]::GetExtension($fullPath).Equals('.xlsx', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'OutputPath must end in .xlsx. This generator creates a macro-free Excel workbook.'
    }
    if (Test-Path -LiteralPath $fullPath -PathType Container) {
        throw "OutputPath points to a directory: $fullPath"
    }
    if ((Test-Path -LiteralPath $fullPath -PathType Leaf) -and -not $AllowOverwrite) {
        throw "The output file already exists. Use -Force to replace it: $fullPath"
    }
    return $fullPath
}

function Assert-ReportRuntime {
    if (-not $IsWindows) { throw 'This generator requires Windows because it uses WAM and desktop Excel.' }
    if (-not [Environment]::UserInteractive) {
        throw 'This generator requires an interactive Windows desktop session for WAM and Excel.'
    }
    if ($null -eq [type]::GetTypeFromProgID('Excel.Application')) {
        throw 'Desktop Microsoft Excel is not installed or its COM registration is unavailable.'
    }
}

function Remove-ComReference {
    param([AllowNull()][object] $InputObject)
    if ($null -eq $InputObject) { return }
    try {
        if ([Runtime.InteropServices.Marshal]::IsComObject($InputObject)) {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($InputObject)
        }
    }
    catch { }
}

function Invoke-IntuneExcelReport {
    Assert-ReportRuntime
    $fullOutputPath = Resolve-ReportOutputPath -Path $OutputPath -AllowOverwrite ([bool]$Force)
    $outputDirectory = [IO.Path]::GetDirectoryName($fullOutputPath)
    if ([string]::IsNullOrWhiteSpace($outputDirectory)) {
        throw 'Unable to determine the output directory.'
    }

    $excel = $null
    $workbook = $null
    $temporaryOutputPath = Join-Path -Path $outputDirectory -ChildPath (
        '.{0}.{1}.{2}.tmp.xlsx' -f [IO.Path]::GetFileNameWithoutExtension($fullOutputPath), $PID, ([guid]::NewGuid().ToString('N'))
    )

    try {
        Connect-IntuneGraph | Out-Null

        Write-ReportStatus 'Collecting managed-device inventory...'
        $deviceBundle = Get-DevicesData
        Write-ReportStatus 'Collecting deleted-device audit events...'
        $deleted = Get-DeletedDevicesData
        Write-ReportStatus 'Collecting compliance policy status...'
        $compliance = Get-ComplianceData
        Write-ReportStatus 'Collecting application install status...'
        $apps = Get-AppsData
        Write-ReportStatus 'Collecting connector and token status...'
        $connectors = Get-ConnectorsData
        Write-ReportStatus 'Collecting dashboard enrichments...'
        $iosSummary = Get-IosUpdateSummary -Devices @($deviceBundle.RawDevices)
        $autopatch = Get-AutopatchSummary

        if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
            [void](New-Item -ItemType Directory -Path $outputDirectory -Force)
        }

        Write-ReportStatus 'Building the Excel workbook...'
        try {
            $excel = New-Object -ComObject Excel.Application
            $excel.Visible = $false
            $excel.DisplayAlerts = $false
            $excel.ScreenUpdating = $false
            $excel.EnableEvents = $false
            $workbook = $excel.Workbooks.Add()

            while ([int]$workbook.Worksheets.Count -gt 1) {
                $workbook.Worksheets.Item($workbook.Worksheets.Count).Delete()
            }
            $dashboard = $workbook.Worksheets.Item(1)
            $dashboard.Name = 'Dashboard'
            Remove-ComReference $dashboard
            $dashboard = $null

            Write-DataSheet -Excel $excel -Workbook $workbook -SheetName 'Devices' `
                -TableName 'ManagedDevices' -Title 'Managed Devices' -Report $deviceBundle.Devices `
                -TabColor (ConvertTo-OleColor 0 114 198) | Out-Null
            Write-DataSheet -Excel $excel -Workbook $workbook -SheetName 'Duplicates' `
                -TableName 'DuplicateDevices' -Title 'Duplicate Devices' -Report $deviceBundle.Duplicates `
                -TabColor (ConvertTo-OleColor 198 40 40) | Out-Null
            Write-DataSheet -Excel $excel -Workbook $workbook -SheetName 'Deleted Devices' `
                -TableName 'DeletedDevices' -Title 'Deleted Devices (last 14 days)' -Report $deleted `
                -TabColor (ConvertTo-OleColor 124 92 168) | Out-Null
            Write-DataSheet -Excel $excel -Workbook $workbook -SheetName 'Compliance' `
                -TableName 'CompliancePolicies' -Title 'Compliance Policies' -Report $compliance `
                -TabColor (ConvertTo-OleColor 56 142 60) | Out-Null
            Write-DataSheet -Excel $excel -Workbook $workbook -SheetName 'Apps' `
                -TableName 'ApplicationStatus' -Title 'Application Install Status' -Report $apps `
                -TabColor (ConvertTo-OleColor 226 100 20) | Out-Null
            Write-DataSheet -Excel $excel -Workbook $workbook -SheetName 'Connectors & Tokens' `
                -TableName 'ConnectorsAndTokens' -Title 'Connectors & Tokens' -Report $connectors `
                -TabColor (ConvertTo-OleColor 0 137 137) | Out-Null

            Build-DashboardSheet -Excel $excel -Workbook $workbook -Devices @($deviceBundle.RawDevices) `
                -AppsReport $apps -DeletedReport $deleted -ConnectorsReport $connectors `
                -IosUpdateSummary $iosSummary -AutopatchSummary $autopatch `
                -UserLabel $script:UserLabel | Out-Null

            $workbook.Worksheets.Item('Dashboard').Activate() | Out-Null
            $workbook.SaveAs($temporaryOutputPath, 51)
        }
        finally {
            if ($null -ne $workbook) {
                try { $workbook.Close($false) | Out-Null } catch { }
                Remove-ComReference $workbook
                $workbook = $null
            }
            if ($null -ne $excel) {
                try { $excel.Quit() | Out-Null } catch { }
                Remove-ComReference $excel
                $excel = $null
            }
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
            [GC]::Collect()
            [GC]::WaitForPendingFinalizers()
        }

        if (-not (Test-Path -LiteralPath $temporaryOutputPath -PathType Leaf)) {
            throw 'Excel closed without creating the workbook file.'
        }
        [IO.File]::Move($temporaryOutputPath, $fullOutputPath, [bool]$Force)
        Write-ReportStatus "Saved $fullOutputPath"
    }
    finally {
        if ($null -ne $workbook) {
            try { $workbook.Close($false) | Out-Null } catch { }
            Remove-ComReference $workbook
        }
        if ($null -ne $excel) {
            try { $excel.Quit() | Out-Null } catch { }
            Remove-ComReference $excel
        }
        if (Test-Path -LiteralPath $temporaryOutputPath -PathType Leaf) {
            try { Remove-Item -LiteralPath $temporaryOutputPath -Force -ErrorAction Stop } catch { }
        }
        if ($script:GraphConnected) {
            try {
                Microsoft.Graph.Authentication\Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
            }
            catch { }
            $script:GraphConnected = $false
        }
    }

    if ($Open) { Start-Process -FilePath $fullOutputPath | Out-Null }
    return Get-Item -LiteralPath $fullOutputPath
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-IntuneExcelReport
}