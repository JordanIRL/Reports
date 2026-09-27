<#
.SYNOPSIS
    Creates an authentication methods report for standard users.

.DESCRIPTION
    Reports enabled Microsoft Entra member accounts. It excludes direct active or eligible
    directory role assignees, active members of groups assigned those roles, and guests
    before authentication methods are read, counted or exported.
    The HTML report and two CSV files are saved in a timestamped folder. Keep this script beside
    get-authentication-methods-report.ps1, which supplies the shared report engine.

.EXAMPLE
    .\get-standard-user-authentication-methods-report.ps1 -OutputPath 'C:\Reports'

.EXAMPLE
    .\get-standard-user-authentication-methods-report.ps1 -OutputPath 'C:\Reports' -FullMethodScan -NoOpen

.NOTES
    Requires delegated RoleManagement.Read.Directory and GroupMember.Read.All in addition to
    the shared report permissions. The report stops if it cannot verify role assignments or
    role-group membership.
#>
#Requires -Version 5.1

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$OutputPath = (Get-Location).Path,

    [string]$TenantId,

    [ValidatePattern('^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')]
    [string]$ClientId,

    [switch]$LicensedUsersOnly,

    [ValidateRange(0, 3650)]
    [int]$ActiveWithinDays = 0,

    [switch]$FullMethodScan,

    [ValidateRange(1, 8)]
    [int]$ThrottleLimit = 4,

    [ValidateRange(0, 1000000)]
    [int]$MaxUsersInHtml = 5000,

    [ValidateNotNullOrEmpty()]
    [string]$ReportTitle = 'Standard user authentication',

    [switch]$UseDeviceCode,
    [switch]$NoOpen,
    [switch]$ForceModuleInstall
)

$engine = Join-Path $PSScriptRoot 'get-authentication-methods-report.ps1'
if (-not (Test-Path -LiteralPath $engine -PathType Leaf)) {
    throw "The shared report script is missing: $engine"
}

$forward = @{}
foreach ($name in $PSBoundParameters.Keys) { $forward[$name] = $PSBoundParameters[$name] }
$forward.UsersOnly = $true
if (-not $forward.ContainsKey('ReportTitle')) { $forward.ReportTitle = $ReportTitle }

& $engine @forward
if (-not $?) { throw 'The standard-user report did not complete.' }
