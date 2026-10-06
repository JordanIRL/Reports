#requires -Version 7.2
# Shared display/data helpers. Graph requests in this file use GET only.
Set-StrictMode -Version Latest

function Get-DataValue {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return ,($InputObject[$Name]) }
        return $null
    }
    $p = $InputObject.PSObject.Properties[$Name]
    if ($null -ne $p) { return ,($p.Value) }
    return $null
}

function Test-DataProperty {
    param([AllowNull()][object]$InputObject, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $InputObject) { return $false }
    if ($InputObject -is [System.Collections.IDictionary]) { return $InputObject.Contains($Name) }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function New-CheckResult {
    param(
        [Parameter(Mandatory)][string]$Section,
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][ValidateSet('Pass','Action','Review','Unknown')][string]$Status,
        [Parameter(Mandatory)][string]$Detail,
        [AllowNull()][object]$Evidence
    )
    [pscustomobject][ordered]@{
        Section = $Section; Name = $Name; Status = $Status; Detail = $Detail
        ObservedAtUtc = [datetime]::UtcNow.ToString('o'); Evidence = $Evidence
    }
}

function Write-CheckReport {
    param(
        [Parameter(Mandatory)][string]$Title,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Results,
        [switch]$Ascii,
        [switch]$PassThru
    )
    Write-Host "`n$Title" -ForegroundColor Cyan
    Write-Host ('-' * [Math]::Min(100, [Math]::Max(32, $Title.Length)))
    $lastSection = ''
    foreach ($r in $Results) {
        if ($r.Section -ne $lastSection) {
            Write-Host "`n[$($r.Section)]" -ForegroundColor Cyan
            $lastSection = $r.Section
        }
        $symbol = '?'; $color = 'Yellow'
        switch ($r.Status) {
            'Pass'   { $symbol = if ($Ascii) { '[OK]' } else { [string][char]0x2713 }; $color = 'Green' }
            'Action' { $symbol = if ($Ascii) { '[ACTION]' } else { [string][char]0x2717 }; $color = 'Red' }
            'Review' { $symbol = if ($Ascii) { '[REVIEW]' } else { '!' }; $color = 'Yellow' }
            'Unknown'{ $symbol = if ($Ascii) { '[UNKNOWN]' } else { '?' }; $color = 'Yellow' }
        }
        Write-Host ("{0} {1,-7} {2}: {3}" -f $symbol, $r.Status.ToUpperInvariant(), $r.Name, $r.Detail) -ForegroundColor $color
    }
    $counts = @{}
    foreach ($status in @('Pass','Action','Review','Unknown')) {
        $counts[$status] = @($Results | Where-Object Status -eq $status).Count
    }
    $summary = if ($counts.Action -gt 0) { 'ACTION REQUIRED' }
        elseif ($counts.Unknown -gt 0) { 'INCOMPLETE - unknown evidence' }
        elseif ($counts.Review -gt 0) { 'REVIEW REQUIRED' }
        elseif ($Results.Count -eq 0) { 'INCOMPLETE - no checks returned' }
        else { 'OBSERVED CHECKS PASSED' }
    Write-Host ("`n{0} | Pass {1}, Action {2}, Review {3}, Unknown {4}" -f $summary,
        $counts.Pass, $counts.Action, $counts.Review, $counts.Unknown) -ForegroundColor $(if ($counts.Action) { 'Red' } else { 'Yellow' })
    Write-Host 'No tenant settings changed. This report is evidence, not authorization or a complete migration approval.'
    if ($PassThru) { $Results }
}

function Get-SafeErrorText {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $msg = [string]$ErrorRecord.Exception.Message
    $msg = $msg -replace '(?i)(Bearer\s+)[A-Za-z0-9._~+/=-]+', '$1[redacted]'
    $msg = $msg -replace '(?i)((?:access_token|refresh_token|client_secret)\s*[:=]\s*)[^\s,;]+', '$1[redacted]'
    $msg = $msg -replace '[\r\n]+', ' '
    if ($msg.Length -gt 300) { $msg = $msg.Substring(0,300) + '...' }
    return $msg
}

function Assert-GraphReadUri {
    param([Parameter(Mandatory)][string]$Uri)
    $parsed = [uri]$Uri
    if ($parsed.Scheme -ne 'https' -or $parsed.Host -ne 'graph.microsoft.com' -or
        -not $parsed.IsDefaultPort -or $parsed.UserInfo -or $parsed.Fragment -or
        $parsed.AbsolutePath -notmatch '^/(beta|v1\.0)/') {
        throw 'Rejected Graph URL outside the supported Microsoft Graph global endpoint.'
    }
}

function Invoke-ReadOnlyGraphGet {
    param([Parameter(Mandatory)][string]$Uri, [hashtable]$Headers = @{})
    Assert-GraphReadUri -Uri $Uri
    # No mutation methods, request body, automatic permission escalation or credential fallback.
    Invoke-MgGraphRequest -Method GET -Uri $Uri -Headers $Headers -OutputType PSObject -ErrorAction Stop
}

function Invoke-ReadOnlyGraphCollection {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers = @{},
        [ValidateRange(1,1000)][int]$MaxPages = 100,
        [ValidateRange(1,100000)][int]$MaxItems = 5000
    )
    $items = [System.Collections.Generic.List[object]]::new()
    $pages = 0; $next = $Uri; $complete = $true; $reason = ''
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    while ($next) {
        if ($pages -ge $MaxPages) { $complete = $false; $reason = 'Page limit reached'; break }
        if (-not $seen.Add($next)) { $complete = $false; $reason = 'Repeated nextLink'; break }
        try {
            $page = Invoke-ReadOnlyGraphGet -Uri $next -Headers $Headers
            $pages++
            if (-not (Test-DataProperty $page 'value')) { throw 'Collection response omitted value.' }
            $value = Get-DataValue $page 'value'
            if ($null -eq $value) { throw 'Collection response returned a null value.' }
            if ($value -isnot [System.Collections.IEnumerable] -or $value -is [string] -or $value -is [System.Collections.IDictionary]) {
                throw 'Collection response value was not an array or collection.'
            }
            foreach ($entry in $value) {
                if ($null -eq $entry) { throw 'Collection response contained a null item.' }
                if ($items.Count -ge $MaxItems) { $complete = $false; $reason = 'Item limit reached'; break }
                $items.Add($entry)
            }
            if (-not $complete) { break }
            $next = [string](Get-DataValue $page '@odata.nextLink')
            if ($next -and $items.Count -ge $MaxItems) { $complete = $false; $reason = 'Item limit reached with more pages'; break }
        } catch {
            $complete = $false; $reason = Get-SafeErrorText $_; break
        }
    }
    [pscustomobject]@{ Items = $items.ToArray(); Complete = $complete; Pages = $pages; Reason = $reason }
}

function Save-ReadOnlyEvidence {
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][object]$Value, [switch]$Force)
    $fullPath = [IO.Path]::GetFullPath($Path)
    if ((Test-Path -LiteralPath $fullPath) -and -not $Force) { throw 'Evidence file exists. Choose another path or explicitly use -ForceExport.' }
    $parent = Split-Path -Parent $fullPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'Evidence output directory does not exist. Create it first.' }
    $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $fullPath -Encoding utf8 -ErrorAction Stop
}
