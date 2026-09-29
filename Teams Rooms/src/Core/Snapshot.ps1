# The collected data ("context") and its JSON snapshot. Checks only ever read from the context,
# so a saved snapshot can be re-checked offline with -FromSnapshot.

$script:MtrSnapshotSchema = 1
# Never persist anything that looks like an enrollment token or secret, even if an API returns it.
$script:MtrSensitivePropertyPattern = '^(tokenValue|qrCodeContent|qrCodeImage|wifiPassword|preSharedKey|password|scriptContent|detectionScriptContent|remediationScriptContent)$'

function New-MtrContext {
    param([hashtable]$Parameters)
    [pscustomobject]@{
        Meta      = [pscustomobject]@{
            SchemaVersion = $script:MtrSnapshotSchema
            ToolVersion   = $script:MtrToolVersion
            CollectedAt   = [datetime]::UtcNow
            TenantId      = $null
            TenantName    = $null
            RunBy         = $null
            Sections      = @()
            Parameters    = $Parameters
        }
        Coverage  = [System.Collections.Generic.List[object]]::new()
        Tenant    = $null
        Licensing = $null
        Identity  = $null
        ConditionalAccess = $null
        Groups    = $null
        Exchange  = $null
        Places    = $null
        Teams     = $null
        Intune    = $null
        Seeds     = $null
    }
}

function Remove-MtrSensitiveData {
    # Recursively strips sensitive property names from PSCustomObjects/hashtables/arrays in place.
    param($InputObject, [int]$Depth = 0)
    if ($null -eq $InputObject -or $Depth -gt 40) { return }
    if ($InputObject -is [string] -or $InputObject -is [datetime] -or $InputObject.GetType().IsPrimitive) { return }
    if ($InputObject -is [System.Collections.IDictionary]) {
        foreach ($key in (Get-MtrArray $InputObject.Keys)) {
            if ([string]$key -match $script:MtrSensitivePropertyPattern) { $InputObject.Remove($key); continue }
            Remove-MtrSensitiveData -InputObject $InputObject[$key] -Depth ($Depth + 1)
        }
        return
    }
    if ($InputObject -is [System.Collections.IEnumerable]) {
        foreach ($item in $InputObject) { Remove-MtrSensitiveData -InputObject $item -Depth ($Depth + 1) }
        return
    }
    if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
        foreach ($prop in (Get-MtrArray $InputObject.PSObject.Properties)) {
            if ($prop.MemberType -ne 'NoteProperty') { continue }
            if ($prop.Name -match $script:MtrSensitivePropertyPattern) { $InputObject.PSObject.Properties.Remove($prop.Name); continue }
            Remove-MtrSensitiveData -InputObject $prop.Value -Depth ($Depth + 1)
        }
    }
}

function Export-MtrSnapshot {
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Path)
    Remove-MtrSensitiveData -InputObject $Context
    $json = $Context | ConvertTo-Json -Depth 30 -WarningAction SilentlyContinue
    Set-Content -Path $Path -Value $json -Encoding utf8
}

function Import-MtrSnapshot {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Snapshot not found: $Path" }
    $ctx = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 64
    if (-not $ctx.Meta -or $ctx.Meta.SchemaVersion -ne $script:MtrSnapshotSchema) {
        throw "Snapshot schema mismatch (expected $script:MtrSnapshotSchema). Re-collect with this version of the tool."
    }
    $coverage = [System.Collections.Generic.List[object]]::new()
    foreach ($c in (Get-MtrArray $ctx.Coverage)) { if ($c) { $coverage.Add($c) } }
    $ctx.Coverage = $coverage
    $ctx
}
