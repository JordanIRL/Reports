# Finding model, coverage tracking and small shared helpers.

$script:MtrSeverityRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Info = 4; Pass = 5 }
$script:MtrFixLocations = @(
    'On-prem AD', 'On-prem Exchange', 'Exchange Online', 'Entra ID', 'Intune', 'Teams Admin Center',
    'Teams PowerShell', 'Pro Management Portal', 'Microsoft Places', 'Device', 'None'
)

function New-MtrFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$CheckId,
        [Parameter(Mandatory)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info', 'Pass')][string]$Severity,
        [Parameter(Mandatory)][string]$Category,
        [Parameter(Mandatory)][string]$Title,
        [string]$Target = 'Tenant',
        [string]$Detail,
        [string]$Impact,
        [string]$Recommendation,
        [ValidateScript({ $_ -in $script:MtrFixLocations })][string]$FixLocation = 'None',
        [string[]]$AffectedObjects = @(),
        [string[]]$RemediationCommand = @(),
        [string[]]$VerifyCommand = @(),
        [string]$Reference
    )

    [pscustomobject]@{
        PSTypeName         = 'MtrFinding'
        CheckId            = $CheckId
        Severity           = $Severity
        SeverityRank       = $script:MtrSeverityRank[$Severity]
        Category           = $Category
        Title              = $Title
        Target             = $Target
        Detail             = $Detail
        Impact             = $Impact
        Recommendation     = $Recommendation
        FixLocation        = $FixLocation
        AffectedObjects    = @($AffectedObjects | Where-Object { $_ })
        RemediationCommand = @($RemediationCommand | Where-Object { $_ })
        VerifyCommand      = @($VerifyCommand | Where-Object { $_ })
        Reference          = $Reference
    }
}

function Step-MtrSeverity {
    # Lowers a severity by one level, used for report-only CA policies.
    param([Parameter(Mandatory)][string]$Severity)
    switch ($Severity) {
        'Critical' { 'High' }
        'High' { 'Medium' }
        'Medium' { 'Low' }
        default { $Severity }
    }
}

function Add-MtrCoverage {
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)][ValidateSet('OK', 'Partial', 'Skipped', 'Failed')][string]$Status,
        [string]$Detail
    )
    $Context.Coverage.Add([pscustomobject]@{ Section = $Section; Item = $Item; Status = $Status; Detail = $Detail })
}

function Invoke-MtrCollectorStep {
    <#
    .SYNOPSIS
        Runs one collection step, records coverage, and never lets a single failure stop the audit.
    #>
    param(
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Item,
        [Parameter(Mandatory)][scriptblock]$ScriptBlock
    )
    Write-Information "  - $Section / $Item" -InformationAction Continue
    try {
        $result = & $ScriptBlock
        Add-MtrCoverage -Context $Context -Section $Section -Item $Item -Status OK
        if ($null -eq $result) { return }
        return $result
    }
    catch {
        if ($_.Exception -is [System.UnauthorizedAccessException]) {
            # Raised by collectors when some (not all) objects could not be read.
            Write-Warning "$Section / $Item partially collected: $($_.Exception.Message)"
            Add-MtrCoverage -Context $Context -Section $Section -Item $Item -Status Partial -Detail $_.Exception.Message
            return
        }
        $failure = $_
        $info = Get-MtrGraphErrorInfo -ErrorRecord $failure
        $reason = switch ($info.Status) {
            403 { "Insufficient permission (403): $($info.Message)" }
            401 { "Not authorized (401): $($info.Message)" }
            404 { "Not found or API unavailable (404): $($info.Message)" }
            410 { "API retired (410): $($info.Message)" }
            default { if ($info.Message) { $info.Message } else { $failure.Exception.Message } }
        }
        if (-not $reason) { $reason = $failure.Exception.GetType().FullName }
        $where = $failure.InvocationInfo.PositionMessage -split "`n" | Select-Object -First 1
        if ($where -and $info.Status -notin 401, 403, 404, 410) { $reason = "$reason [$($where.Trim())]" }
        Write-Warning "$Section / $Item failed: $reason"
        Add-MtrCoverage -Context $Context -Section $Section -Item $Item -Status Failed -Detail $reason
        return
    }
}

function Add-MtrBatchCoverage {
    # Records a Partial coverage entry when some requests in a Graph batch failed, so partial data is never
    # mistaken for a clean result. -IgnoreStatus lists statuses that mean "nothing there" for this lookup.
    param([Parameter(Mandatory)]$Context, [Parameter(Mandatory)][string]$Section, [Parameter(Mandatory)][string]$Item, [hashtable]$Responses, [int[]]$IgnoreStatus = @())
    if (-not $Responses) { return }
    $failed = @($Responses.Values | Where-Object { $_ -and $_.Status -ge 400 -and $_.Status -notin $IgnoreStatus })
    if (-not $failed.Count) { return }
    $byStatus = ($failed | Group-Object Status | ForEach-Object { "$($_.Count) x HTTP $($_.Name)" }) -join ', '
    $sample = Format-MtrErrorText ($failed | Select-Object -First 1).Error
    Add-MtrCoverage -Context $Context -Section $Section -Item $Item -Status Partial -Detail "$($failed.Count) of $($Responses.Count) lookups failed ($byStatus). Example: $sample"
}

function Format-MtrErrorText {
    # One-line, bounded error text for the Coverage section. Intune nests a JSON document inside the Graph
    # error message; only its Message field (without the internal service URL) is kept.
    param([string]$Text, [int]$MaxLength = 300)
    if (-not $Text) { return $Text }
    if ($Text -match '(?s)^(?<code>[^:{]*):\s*\{.*?"Message"\s*:\s*"(?<msg>(?:[^"\\]|\\.)*)"') {
        $Text = '{0}: {1}' -f $Matches.code.Trim(), ($Matches.msg -replace '\s+-\s+Url:.*$', '')
    }
    $Text = ($Text -replace '\s+', ' ').Trim()
    if ($Text.Length -gt $MaxLength) { $Text = $Text.Substring(0, $MaxLength) + '...' }
    $Text
}

function ConvertTo-MtrDateTime {
    # Null-safe conversion of Graph/EXO date values (string, DateTime or DateTimeOffset) to UTC DateTime.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        if ($Value.Year -le 1601) { return $null }
        return $Value.ToUniversalTime()
    }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    $text = [string]$Value
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    $parsed = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetimeoffset]::TryParse($text, [cultureinfo]::InvariantCulture, $styles, [ref]$parsed)) {
        if ($parsed.Year -le 1601) { return $null }
        return $parsed.UtcDateTime
    }
    return $null
}

function ConvertTo-MtrVersion {
    # Parses '10.0.26100.8655', '1449/1.0.96.2026129709' or '14' into [version]; $null when unparseable.
    param($Value)
    if ($null -eq $Value) { return $null }
    $text = ([string]$Value).Trim()
    if ($text -match '/') { $text = $text.Split('/')[-1] }
    if ($text -match '^\d+$') { $text = "$text.0" }
    $match = [regex]::Match($text, '^\d+(\.\d+){1,3}')
    if (-not $match.Success) { return $null }
    $parsed = $null
    if ([version]::TryParse($match.Value, [ref]$parsed)) { return $parsed }
    return $null
}

function Get-MtrPropertyValue {
    # Safe property read for objects that may be PSCustomObject, hashtable or $null.
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject[$Name] }
    $prop = $InputObject.PSObject.Properties[$Name]
    if ($prop) { return $prop.Value }
    return $null
}

function Get-MtrArray {
    # Like @() but drops nulls. In PowerShell @($null).Count is 1, which breaks emptiness tests and loops
    # over properties that Graph/EXO/JSON leave as null.
    param($Value)
    , [object[]]@($Value | Where-Object { $null -ne $_ })
}

function Get-MtrCount {
    param($Value)
    @($Value | Where-Object { $null -ne $_ }).Count
}

function Get-MtrMapEntry {
    # Enumerates key/value pairs of a hashtable (live collection) or PSCustomObject (loaded from a snapshot).
    param($Map)
    if ($null -eq $Map) { return }
    if ($Map -is [System.Collections.IDictionary]) {
        foreach ($key in $Map.Keys) { [pscustomobject]@{ Key = [string]$key; Value = $Map[$key] } }
        return
    }
    foreach ($prop in $Map.PSObject.Properties) {
        if ($prop.MemberType -eq 'NoteProperty') { [pscustomobject]@{ Key = $prop.Name; Value = $prop.Value } }
    }
}

function Format-MtrList {
    # Compact, bounded list for finding details.
    param([string[]]$Items, [int]$Max = 15)
    $items = @($Items | Where-Object { $_ } | Sort-Object -Unique)
    if ($items.Count -le $Max) { return ($items -join ', ') }
    return ('{0} (+{1} more)' -f (($items | Select-Object -First $Max) -join ', '), ($items.Count - $Max))
}

function ConvertTo-MtrPsLiteral {
    # Single-quoted PowerShell literal for generated remediation text.
    param([AllowNull()][string]$Value)
    if ($null -eq $Value) { return "''" }
    return "'" + $Value.Replace("'", "''") + "'"
}
