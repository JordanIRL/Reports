#requires -Version 7.2
<#
.SYNOPSIS
Offline tests for the AD / Connect preflight; no tenant, AD or service reads.
.DESCRIPTION
Extracts selected production functions from their PowerShell AST, then exercises
them with fixture values and command mocks. It does not override platform variables
or bypass the production Windows requirement. The macOS/Linux report path can be
executed safely; on Windows that whole-script check is skipped to avoid live reads.
These tests cannot validate actual Windows AD/ADSync module compatibility, AD access,
the installed Connect product name, or tenant/device health.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/Test-RoomADAndConnect.ps1'
$commonPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts/ReadOnlyCheck.Common.ps1'
$script:ChecksPassed = 0

function Assert-Offline {
    param([string]$Name, [bool]$Condition)
    if (-not $Condition) { throw "Offline test failed: $Name" }
    $script:ChecksPassed++
    Write-Host "[OK] $Name" -ForegroundColor Green
}

function Get-SourceAst {
    param([string]$Path)
    $tokens = $null; $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    Assert-Offline "Syntax: $(Split-Path -Leaf $Path)" ($errors.Count -eq 0)
    $ast
}

$adAst = Get-SourceAst -Path $scriptPath
$commonAst = Get-SourceAst -Path $commonPath
foreach ($functionSpec in @(
    @{ Ast = $commonAst; Names = @('Get-DataValue', 'Test-DataProperty', 'New-CheckResult', 'Get-SafeErrorText') },
    @{ Ast = $adAst; Names = @('ConvertTo-LdapLiteral', 'Get-ADIdentifierValues', 'Get-ConnectVersionChecks', 'Get-SchedulerSettingCheck', 'Add-LocalCheck', 'Import-LocalReadModule') }
)) {
    foreach ($functionName in $functionSpec.Names) {
        $nodes = @($functionSpec.Ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
        }, $true))
        if ($nodes.Count -ne 1) { throw "Expected one production definition of $functionName." }
        . ([scriptblock]::Create($nodes[0].Extent.Text))
    }
}

function Get-VersionStatus {
    param([AllowNull()][AllowEmptyString()][string]$Version, [string]$Name, [datetime]$Date = [datetime]'2026-10-06')
    $rows = @(Get-ConnectVersionChecks -VersionText $Version -Today $Date)
    $matches = @($rows | Where-Object Name -eq $Name)
    if ($matches.Count -ne 1) { throw "Expected one $Name row for '$Version'." }
    $matches[0].Status
}

Assert-Offline 'Latest known Connect version is supported within snapshot window' ((Get-VersionStatus '2.6.92.0' 'Known support status') -eq 'Pass')
Assert-Offline 'Latest known version meets User SOA feature minimum' ((Get-VersionStatus '2.6.92.0' 'User SOA feature minimum') -eq 'Pass')
Assert-Offline 'Retired feature-minimum build is not a supported baseline' ((Get-VersionStatus '2.5.76.0' 'Known support status') -eq 'Action')
Assert-Offline 'Retired build can meet feature minimum without support passing' ((Get-VersionStatus '2.5.76.0' 'User SOA feature minimum') -eq 'Pass')
Assert-Offline 'Older build below User SOA minimum requires action' ((Get-VersionStatus '2.4.131.0' 'User SOA feature minimum') -eq 'Action')
Assert-Offline 'Older retired build requires action' ((Get-VersionStatus '2.4.131.0' 'Known support status') -eq 'Action')
Assert-Offline '2.5.79 remains supported before published retirement' ((Get-VersionStatus '2.5.79.0' 'Known support status' ([datetime]'2026-10-22')) -eq 'Pass')
Assert-Offline '2.5.79 requires action on its retirement date' ((Get-VersionStatus '2.5.79.0' 'Known support status' ([datetime]'2026-10-23')) -eq 'Action')
Assert-Offline 'Supported older build still requests security release review' ((Get-VersionStatus '2.5.190.0' 'Latest security release') -eq 'Review')
Assert-Offline 'Unknown newer build is reviewed rather than guessed supported' ((Get-VersionStatus '2.7.0.0' 'Known support status') -eq 'Review')
Assert-Offline 'Stale release snapshot does not pass known support' ((Get-VersionStatus '2.6.92.0' 'Known support status' ([datetime]'2026-11-06')) -eq 'Review')
Assert-Offline 'Future-dated snapshot does not pass known support' ((Get-VersionStatus '2.6.92.0' 'Known support status' ([datetime]'2026-10-05')) -eq 'Review')
foreach ($badVersion in @('', 'latest', '2.6.invalid')) {
    $badRows = @(Get-ConnectVersionChecks -VersionText $badVersion -Today ([datetime]'2026-10-06'))
    Assert-Offline "Missing / malformed version '$badVersion' is Unknown with no Pass" ($badRows.Count -eq 1 -and $badRows[0].Status -eq 'Unknown')
}

Assert-Offline 'Ordinary room UPN remains literal' ((ConvertTo-LdapLiteral 'mtr@meetingrooms.ie') -eq 'mtr@meetingrooms.ie')
Assert-Offline 'LDAP backslash is escaped once' ((ConvertTo-LdapLiteral 'room\test') -eq 'room\5ctest')
Assert-Offline 'LDAP stars and parentheses cannot alter exact UPN filter' ((ConvertTo-LdapLiteral 'room*)(userPrincipalName=*)') -eq 'room\2a\29\28userPrincipalName=\2a\29')
Assert-Offline 'LDAP NUL is escaped' ((ConvertTo-LdapLiteral ("room$([char]0)@example.ie")) -eq 'room\00@example.ie')
Assert-Offline 'Already escape-looking input remains a literal string' ((ConvertTo-LdapLiteral 'room\28') -eq 'room\5c28')

$setting = @{ Name = 'SyncCycleEnabled'; Expected = $true; Label = 'Scheduled synchronization'; BadStatus = 'Action'; BadDetail = 'Fixture disabled.' }
Assert-Offline 'Boolean enabled scheduler observation passes' ((Get-SchedulerSettingCheck @{ SyncCycleEnabled = $true } $setting).Status -eq 'Pass')
Assert-Offline 'Boolean disabled scheduler observation requires action' ((Get-SchedulerSettingCheck @{ SyncCycleEnabled = $false } $setting).Status -eq 'Action')
Assert-Offline 'Missing scheduler property is Unknown' ((Get-SchedulerSettingCheck @{} $setting).Status -eq 'Unknown')
Assert-Offline 'Null scheduler property is Unknown' ((Get-SchedulerSettingCheck @{ SyncCycleEnabled = $null } $setting).Status -eq 'Unknown')
Assert-Offline 'String True cannot masquerade as Boolean success' ((Get-SchedulerSettingCheck @{ SyncCycleEnabled = 'True' } $setting).Status -eq 'Unknown')
Assert-Offline 'Null scheduler object is Unknown' ((Get-SchedulerSettingCheck $null $setting).Status -eq 'Unknown')
Assert-Offline 'Unreadable member property is distinguishable from empty members' (-not (Test-DataProperty @{} 'member') -and (Test-DataProperty @{ member = @() } 'member'))

$fixtureRoom = @{ memberOf = @('CN=RoomListA,DC=example,DC=ie', 'CN=LicenceGroupB,DC=example,DC=ie') }
$directGroups = @(Get-ADIdentifierValues -Values (Get-DataValue $fixtureRoom 'memberOf'))
Assert-Offline 'Preserved multi-group property enumerates two exact AD identities' ($directGroups.Count -eq 2 -and $directGroups[0] -eq $fixtureRoom.memberOf[0] -and $directGroups[1] -eq $fixtureRoom.memberOf[1])
$roomDn = 'CN=RoomA,DC=example,DC=ie'
$fixtureGroup = @{ member = @('CN=RoomB,DC=example,DC=ie', $roomDn, 'CN=RoomC,DC=example,DC=ie') }
$groupMembers = @(Get-ADIdentifierValues -Values (Get-DataValue $fixtureGroup 'member'))
Assert-Offline 'Preserved multi-member property enumerates full membership count' ($groupMembers.Count -eq 3)
Assert-Offline 'Room is correctly found among several direct group members' ($groupMembers -contains $roomDn)
Assert-Offline 'An absent room is not falsely marked a direct member' (-not ($groupMembers -contains 'CN=Absent,DC=example,DC=ie'))
$fixtureAddresses = @{ proxyAddresses = @('SMTP:rooms@example.ie', 'smtp:roomlist@example.ie') }
$addresses = @(Get-ADIdentifierValues -Values (Get-DataValue $fixtureAddresses 'proxyAddresses'))
Assert-Offline 'Preserved proxy address array stays a flat complete snapshot' ($addresses.Count -eq 2 -and $addresses[1] -eq 'smtp:roomlist@example.ie')
Assert-Offline 'Empty identifiers remain empty and do not become a nested array' (@(Get-ADIdentifierValues -Values (Get-DataValue @{ member = @() } 'member')).Count -eq 0)

# Local mocks shadow module cmdlets for the extracted import helper only.
$script:MockModuleMode = 'Absent'; $script:ModuleLookups = 0; $script:ModuleImports = 0
function Get-Module {
    [CmdletBinding()]
    param([string]$Name, [switch]$ListAvailable)
    $script:ModuleLookups++
    if ($script:MockModuleMode -ne 'Absent') { [pscustomobject]@{ Name = $Name } }
}
function Import-Module {
    [CmdletBinding()]
    param([string]$Name, [switch]$UseWindowsPowerShell)
    $script:ModuleImports++
    if ($script:MockModuleMode -eq 'Failure') { throw 'Fixture import failed; access_token=secretfixture' }
    if ($script:MockModuleMode -eq 'Compatibility' -and -not $UseWindowsPowerShell) { throw 'Fixture native import is incompatible.' }
}
$results = [System.Collections.Generic.List[object]]::new()
$available = Import-LocalReadModule -Name 'ADSync'
Assert-Offline 'Absent installed module returns false and Action without installing' (-not $available -and $results.Count -eq 1 -and $results[0].Status -eq 'Action' -and $script:ModuleImports -eq 0)
$script:MockModuleMode = 'Failure'; $results.Clear(); $script:ModuleImports = 0
$available = Import-LocalReadModule -Name 'ADSync'
Assert-Offline 'Failed native / compatibility imports return false and Unknown' (-not $available -and $results.Count -eq 1 -and $results[0].Status -eq 'Unknown' -and $script:ModuleImports -eq 2)
Assert-Offline 'Caught module error redacts token-like material' ($results[0].Detail -notmatch 'secretfixture')
$script:MockModuleMode = 'Compatibility'; $results.Clear(); $script:ModuleImports = 0
$available = Import-LocalReadModule -Name 'ADSync'
Assert-Offline 'Compatibility import succeeds after one failed native attempt' ($available -and $results.Count -eq 1 -and $results[0].Status -eq 'Pass' -and $script:ModuleImports -eq 2)
Remove-Item Function:Get-Module, Function:Import-Module

$mutationCommands = @($adAst.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -and
    $node.GetCommandName() -match '^(Set|Add|Remove|Disable|Enable|Start|Stop|Update|New|Clear|Reset)-(AD|ADSync|Mg|Distribution|Mailbox|Service)'
}, $true))
Assert-Offline 'Production script contains no AD / sync / Graph / service mutation command' ($mutationCommands.Count -eq 0)

if (-not $IsWindows) {
    # The real production platform check remains intact. Every potential external
    # read is guarded with a throwing fixture; none should be reached.
    $script:UnexpectedReads = 0
    foreach ($commandName in @('Get-Module', 'Import-Module', 'Get-Service', 'Get-ItemProperty', 'Get-ADSyncScheduler', 'Get-ADUser', 'Get-ADGroup')) {
        Set-Item -Path "Function:$commandName" -Value {
            $script:UnexpectedReads++
            throw 'Unexpected external read in non-Windows offline report.'
        }
    }
    try {
        $platformRows = @(& $scriptPath -RoomUpn 'mtr@meetingrooms.ie' -Ascii -PassThru)
        Assert-Offline 'Real non-Windows run returns one Unknown prerequisite check' ($platformRows.Count -eq 1 -and $platformRows[0].Status -eq 'Unknown' -and $platformRows[0].Name -eq 'Windows Connect server')
        Assert-Offline 'Real non-Windows report performs no module / AD / service reads' ($script:UnexpectedReads -eq 0)
    }
    finally {
        foreach ($commandName in @('Get-Module', 'Import-Module', 'Get-Service', 'Get-ItemProperty', 'Get-ADSyncScheduler', 'Get-ADUser', 'Get-ADGroup')) {
            Remove-Item -Path "Function:$commandName" -ErrorAction SilentlyContinue
        }
    }
}
else {
    Write-Host '[REVIEW] Whole-script non-Windows report test skipped on Windows to avoid live reads.' -ForegroundColor Yellow
}
Write-Host "`nAD / Connect offline tests passed: $script:ChecksPassed. No tenant or AD calls executed." -ForegroundColor Cyan
Write-Host 'Limit: actual Windows ActiveDirectory / ADSync compatibility and environment evidence are unverified.'
