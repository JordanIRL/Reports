<#
    Child-process runner for Exchange Online and Teams collection. Their modules cannot share a session
    with Microsoft.Graph.Authentication (MSAL/WAM clash), so each call connects one service with WAM in a
    fresh pwsh process, runs one read-only collector function, writes its result as JSON, and disconnects.
    Failures are written to the output file as { "MtrIsolatedError": "..." } so the parent can report them.
    Not intended to be run directly.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('Exchange', 'Teams')][string]$Service,
    [Parameter(Mandatory)][ValidatePattern('^Get-Mtr\w+$')][string]$FunctionName,
    [Parameter(Mandatory)][string]$ArgumentsPath,
    [Parameter(Mandatory)][string]$OutputPath,
    [string]$TenantId,
    [string]$UserPrincipalName
)

$ErrorActionPreference = 'Stop'
$sourceRoot = Split-Path -Path $PSScriptRoot -Parent
foreach ($file in Get-ChildItem -Path $sourceRoot -Recurse -Filter '*.ps1' | Where-Object Name -ne 'Invoke-MtrIsolatedCall.ps1' | Sort-Object FullName) {
    . $file.FullName
}

$exitCode = 1
try {
    $arguments = Get-Content -LiteralPath $ArgumentsPath -Raw | ConvertFrom-Json -AsHashtable
    if (-not $arguments) { $arguments = @{} }

    if ($Service -eq 'Exchange') { Connect-MtrExchange -UserPrincipalName $UserPrincipalName }
    else { Connect-MtrTeams -TenantId $TenantId -AccountId $UserPrincipalName }

    $result = & $FunctionName @arguments
    Set-Content -LiteralPath $OutputPath -Value (ConvertTo-Json -InputObject $result -Depth 30 -WarningAction SilentlyContinue) -Encoding utf8
    $exitCode = 0
}
catch {
    $message = "$($_.Exception.Message)"
    if ($_.InvocationInfo -and $_.InvocationInfo.ScriptLineNumber) { $message += " (at $(Split-Path $_.InvocationInfo.ScriptName -Leaf):$($_.InvocationInfo.ScriptLineNumber))" }
    Write-Warning "$Service collection failed: $message"
    Set-Content -LiteralPath $OutputPath -Value (ConvertTo-Json -InputObject @{ MtrIsolatedError = $message } -Depth 3) -Encoding utf8
}
finally {
    if ($Service -eq 'Exchange') { try { Disconnect-ExchangeOnline -Confirm:$false -ErrorAction Stop | Out-Null } catch { Write-Verbose $_ } }
    else { try { Disconnect-MicrosoftTeams -ErrorAction Stop | Out-Null } catch { Write-Verbose $_ } }
}
exit $exitCode
