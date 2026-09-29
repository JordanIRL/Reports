# Delegated, WAM-brokered connections. Everything requested here is read-only.

$script:MtrGraphScopes = @(
    'User.Read.All'
    'Group.Read.All'
    'Directory.Read.All'
    'OnPremDirectorySynchronization.Read.All'
    'Policy.Read.All'
    'Policy.Read.DeviceConfiguration'
    'AuditLog.Read.All'
    'UserAuthenticationMethod.Read.All'
    'Device.Read.All'
    'RoleManagement.Read.Directory'
    'Place.Read.All'
    'DeviceManagementManagedDevices.Read.All'
    'DeviceManagementConfiguration.Read.All'
    'DeviceManagementServiceConfig.Read.All'
    'TeamworkDevice.Read.All'
)

# Only these Exchange Online cmdlets are loaded into the session (Get-EXO* REST cmdlets are always present).
$script:MtrExoCommands = @(
    'Get-Mailbox'
    'Get-Recipient'
    'Get-CalendarProcessing'
    'Get-Place'
    'Get-DistributionGroup'
    'Get-DistributionGroupMember'
    'Get-MailboxRegionalConfiguration'
    'Get-MailboxCalendarConfiguration'
    'Get-OrganizationConfig'
    'Get-CASMailbox'
)

$script:MtrServiceModules = @{
    Graph    = 'Microsoft.Graph.Authentication'
    Exchange = 'ExchangeOnlineManagement'
    Teams    = 'MicrosoftTeams'
}

function Test-MtrPrerequisite {
    param(
        [Parameter(Mandatory)][string[]]$Services,
        [Parameter(Mandatory)]$Baseline
    )
    $problems = [System.Collections.Generic.List[string]]::new()
    if ($PSVersionTable.PSVersion -lt [version]'7.4') {
        $problems.Add("PowerShell 7.4 or later is required (running $($PSVersionTable.PSVersion)).")
    }
    if (-not $IsWindows) {
        $problems.Add('Windows is required: sign-in uses the Web Account Manager (WAM) broker.')
    }
    foreach ($service in $Services) {
        $name = $script:MtrServiceModules[$service]
        $minimum = [version]$Baseline.Versions.MinModuleVersions[$name]
        $installed = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1
        if (-not $installed) {
            $problems.Add("Module '$name' is not installed. Install it with: Install-Module $name -Scope CurrentUser")
        }
        elseif ($installed.Version -lt $minimum) {
            $problems.Add("Module '$name' $($installed.Version) is older than the required $minimum (WAM support). Update with: Update-Module $name")
        }
    }
    if ($problems.Count) {
        throw ("Prerequisites not met:`n - " + ($problems -join "`n - "))
    }
}

function Connect-MtrGraph {
    param([string]$TenantId, [string]$ClientId)
    $params = @{ Scopes = $script:MtrGraphScopes; NoWelcome = $true; ErrorAction = 'Stop' }
    if ($TenantId) { $params.TenantId = $TenantId }
    if ($ClientId) { $params.ClientId = $ClientId }
    Connect-MgGraph @params
    $mg = Get-MgContext
    if (-not $mg) { throw 'Connect-MgGraph did not return a context.' }

    $granted = Get-MtrArray $mg.Scopes
    $missing = @($script:MtrGraphScopes | Where-Object { $_ -notin $granted })
    if ($missing.Count) {
        Write-Warning ("These Graph scopes were not granted; related checks will show as not assessed: " + ($missing -join ', '))
    }
    $writeScopes = @($granted | Where-Object { $_ -notmatch '\.Read(\.|$)|^(openid|profile|offline_access|email)$' })
    if ($writeScopes.Count) {
        Write-Warning ("The token also carries non-read scopes previously consented to this app: " + ($writeScopes -join ', ') +
            ". The tool only issues GET requests, but for a guaranteed read-only token use -ClientId with a dedicated read-only app registration (see README).")
    }
    $mg
}

function Connect-MtrExchange {
    param([string]$UserPrincipalName)
    Import-Module ExchangeOnlineManagement -ErrorAction Stop
    $params = @{ ShowBanner = $false; CommandName = $script:MtrExoCommands; ErrorAction = 'Stop' }
    $connectCommand = Get-Command Connect-ExchangeOnline
    if ($connectCommand.Parameters.ContainsKey('SkipLoadingCmdletHelp')) { $params.SkipLoadingCmdletHelp = $true }
    if ($UserPrincipalName) {
        try { Connect-ExchangeOnline @params -UserPrincipalName $UserPrincipalName; return }
        catch { Write-Verbose "Exchange sign-in with the account hint failed ($($_.Exception.Message)); retrying with the account picker." }
    }
    Connect-ExchangeOnline @params
}

function Connect-MtrTeams {
    param([string]$TenantId, [string]$AccountId)
    Import-Module MicrosoftTeams -ErrorAction Stop
    $params = @{ ErrorAction = 'Stop' }
    if ($TenantId) { $params.TenantId = $TenantId }
    if ($AccountId) {
        try { $null = Connect-MicrosoftTeams @params -AccountId $AccountId; return }
        catch { Write-Verbose "Teams sign-in with the account hint failed ($($_.Exception.Message)); retrying with the account picker." }
    }
    $null = Connect-MicrosoftTeams @params
}

function Connect-MtrService {
    <#
    .SYNOPSIS
        Connects Microsoft Graph in this process. Exchange Online and Teams run in a separate pwsh process
        per call by default, because their MSAL/WAM libraries clash with Microsoft.Graph.Authentication when
        loaded into the same session (seen as "Object reference not set..." from Connect-ExchangeOnline and
        "Only some brokers (WAM) can log in the current OS account" from Connect-MicrosoftTeams).
        The child process runs in the same Windows session, so WAM sign-in still works.
        With -InProcessExchangeAndTeams they are connected here instead, falling back to a separate
        process if the connection fails.
    #>
    param(
        [Parameter(Mandatory)][string[]]$Services,
        [string]$TenantId,
        [string]$ClientId,
        [switch]$InProcessExchangeAndTeams,
        [Parameter(Mandatory)][string]$SourceRoot
    )

    $session = [pscustomobject]@{
        Graph      = 'Unavailable'
        Exchange   = 'Unavailable'
        Teams      = 'Unavailable'
        TenantId   = $TenantId
        Upn        = $null
        SourceRoot = $SourceRoot
        Errors     = @{}
    }

    Write-Information 'Connecting to Microsoft Graph (WAM)...' -InformationAction Continue
    $mg = Connect-MtrGraph -TenantId $TenantId -ClientId $ClientId
    $session.Graph = 'InProcess'
    $session.Upn = $mg.Account
    if (-not $session.TenantId) { $session.TenantId = $mg.TenantId }

    foreach ($service in @('Exchange', 'Teams')) {
        if ($service -notin $Services) { continue }
        if (-not $InProcessExchangeAndTeams) { $session.$service = 'Isolated'; continue }
        Write-Information "Connecting to $service (WAM)..." -InformationAction Continue
        try {
            if ($service -eq 'Exchange') { Connect-MtrExchange -UserPrincipalName $session.Upn }
            else { Connect-MtrTeams -TenantId $session.TenantId -AccountId $session.Upn }
            $session.$service = 'InProcess'
        }
        catch {
            Write-Warning "$service could not connect in this PowerShell session ($($_.Exception.Message)); its data will be collected in a separate PowerShell process."
            $session.Errors[$service] = "In-process connection failed: $($_.Exception.Message)"
            $session.$service = 'Isolated'
        }
    }
    $session
}

function Invoke-MtrServiceCall {
    <#
    .SYNOPSIS
        Runs an Exchange/Teams collector function in-process, or in a child pwsh process when isolated.
        Errors raised in the child are carried back and re-thrown here, so they reach the Coverage report.
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('Exchange', 'Teams')][string]$Service,
        [Parameter(Mandatory)][string]$FunctionName,
        [hashtable]$Arguments = @{},
        [Parameter(Mandatory)]$Session
    )

    switch ($Session.$Service) {
        'InProcess' { return & $FunctionName @Arguments }
        'Isolated' {
            $argsPath = [System.IO.Path]::GetTempFileName()
            $outPath = [System.IO.Path]::GetTempFileName()
            try {
                Set-Content -Path $argsPath -Value (ConvertTo-Json -InputObject $Arguments -Depth 10) -Encoding utf8
                $pwsh = (Get-Process -Id $PID).Path
                $script = Join-Path $Session.SourceRoot 'Core/Invoke-MtrIsolatedCall.ps1'
                Write-Information "    $Service runs in a separate PowerShell process; sign in if prompted." -InformationAction Continue
                # A native command's output inside a function becomes part of its return value, so the child's
                # console output (warnings, module banners) is shown to the user instead of being returned as data.
                & $pwsh -NoProfile -File $script -Service $Service -FunctionName $FunctionName -ArgumentsPath $argsPath `
                    -OutputPath $outPath -TenantId $Session.TenantId -UserPrincipalName $Session.Upn 2>&1 |
                    ForEach-Object { Write-Information "      [$Service] $_" -InformationAction Continue }
                $exitCode = $LASTEXITCODE
                $raw = Get-Content -LiteralPath $outPath -Raw -ErrorAction SilentlyContinue
                $parsed = if ([string]::IsNullOrWhiteSpace($raw)) { $null } else { ConvertFrom-Json -InputObject $raw -Depth 64 }
                $childError = if ($parsed -is [System.Management.Automation.PSCustomObject] -and $parsed.PSObject.Properties['MtrIsolatedError']) { $parsed.MtrIsolatedError } else { $null }
                if ($childError -or $exitCode -ne 0) {
                    throw "$Service (separate PowerShell process) failed in ${FunctionName}: $(if ($childError) { $childError } else { "exit code $exitCode" })"
                }
                if ($null -ne $parsed) { return $parsed }
                return
            }
            finally {
                Remove-Item -LiteralPath $argsPath, $outPath -ErrorAction SilentlyContinue
            }
        }
        default { throw "$Service is not connected$(if ($Session.Errors[$Service]) { ': ' + $Session.Errors[$Service] })." }
    }
}

function Disconnect-MtrService {
    param($Session)
    if (-not $Session) { return }
    if ($Session.Exchange -eq 'InProcess') { try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop | Out-Null } catch { Write-Verbose $_ } }
    if ($Session.Teams -eq 'InProcess') { try { Disconnect-MicrosoftTeams -ErrorAction Stop | Out-Null } catch { Write-Verbose $_ } }
    if ($Session.Graph -eq 'InProcess') {
        # The Graph module can warn that it failed to clear its persisted MSAL cache; the sign-out still happens,
        # so that warning is only shown with -Verbose.
        try { Disconnect-MgGraph -ErrorAction Stop -WarningAction SilentlyContinue -WarningVariable graphWarnings | Out-Null } catch { Write-Verbose $_ }
        foreach ($w in (Get-MtrArray $graphWarnings)) { Write-Verbose "Disconnect-MgGraph: $w" }
    }
}
