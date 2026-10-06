#requires -Version 7.2
<#
.SYNOPSIS
Offline tests for shared preflight helpers and production read-only boundaries.
.DESCRIPTION
Dot-sources the common helper, replaces Invoke-MgGraphRequest with local fixtures,
and writes evidence only inside a disposable temporary directory. No Microsoft
Graph module, tenant, AD, Exchange, service or network connection is used.
AST checks are a useful static guard, not proof of effective live permissions or
successful device, mailbox, Room Finder or source-of-authority migration.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$scriptRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts'
$commonPath = Join-Path $scriptRoot 'ReadOnlyCheck.Common.ps1'
$testRoot = Join-Path ([IO.Path]::GetTempPath()) ('teamssoa-common-fixture-' + [guid]::NewGuid())
$script:Passed = 0
$script:Failed = 0
$script:Failures = [System.Collections.Generic.List[string]]::new()
$script:GraphCalls = [System.Collections.Generic.List[object]]::new()
$script:GraphPages = [System.Collections.Generic.Dictionary[string,object]]::new([StringComparer]::Ordinal)

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}
function Assert-Throws {
    param([scriptblock]$Body, [string]$Message)
    $thrown = $false
    try { & $Body | Out-Null } catch { $thrown = $true }
    Assert-True $thrown $Message
}
function Test-Case {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        $script:Passed++
        Write-Host "[OK] $Name" -ForegroundColor Green
    } catch {
        $script:Failed++
        $detail = "$Name : $($_.Exception.Message)"
        $script:Failures.Add($detail)
        Write-Host "[FAIL] $detail" -ForegroundColor Red
    }
}
function Reset-GraphFixture {
    $script:GraphCalls.Clear()
    $script:GraphPages.Clear()
}
function Invoke-MgGraphRequest {
    [CmdletBinding()]
    param([string]$Method, [string]$Uri, [hashtable]$Headers, [string]$OutputType)
    $script:GraphCalls.Add([pscustomobject]@{ Method=$Method; Uri=$Uri; Headers=$Headers; OutputType=$OutputType })
    if ($Method -cne 'GET') { throw 'FIXTURE SENTINEL: a non-GET request was attempted.' }
    if (-not $script:GraphPages.ContainsKey($Uri)) { throw 'FIXTURE SENTINEL: request has no local fixture; no network fallback exists.' }
    $response = $script:GraphPages[$Uri]
    if ($response -is [scriptblock]) { & $response; return }
    return $response
}
function Get-ReportText {
    param([AllowEmptyCollection()][object[]]$Rows)
    $output = @(Write-CheckReport -Title 'Offline fixture report' -Results $Rows -Ascii 6>&1)
    ($output | ForEach-Object { $_.ToString() }) -join "`n"
}
function Get-ConstantCommandArgument {
    param([System.Management.Automation.Language.CommandAst]$Command, [string]$Name)
    for ($index = 1; $index -lt $Command.CommandElements.Count; $index++) {
        $element = $Command.CommandElements[$index]
        if ($element -isnot [System.Management.Automation.Language.CommandParameterAst] -or $element.ParameterName -ine $Name) { continue }
        $argument = $element.Argument
        if ($null -eq $argument -and $index + 1 -lt $Command.CommandElements.Count) { $argument = $Command.CommandElements[$index + 1] }
        if ($argument -is [System.Management.Automation.Language.StringConstantExpressionAst]) { return $argument.Value }
        return $null
    }
    return $null
}

try {
    New-Item -Path $testRoot -ItemType Directory | Out-Null
    . $commonPath
    $firstUri = 'https://graph.microsoft.com/v1.0/groups?$top=2'
    $secondUri = 'https://graph.microsoft.com/v1.0/groups?$skiptoken=fixture2'
    $thirdUri = 'https://graph.microsoft.com/v1.0/groups?$skiptoken=fixture3'

    foreach ($inputKind in @('Dictionary','PSObject')) {
        Test-Case "$inputKind property presence distinguishes null, false and empty from missing" {
            $source = @{ NullValue=$null; FalseValue=$false; EmptyValue=@(); ArrayValue=@('one','two') }
            if ($inputKind -eq 'PSObject') { $source = [pscustomobject]$source }
            foreach ($name in @('NullValue','FalseValue','EmptyValue','ArrayValue')) {
                Assert-True (Test-DataProperty -InputObject $source -Name $name) "Present $name was treated as absent."
            }
            Assert-True (-not (Test-DataProperty -InputObject $source -Name 'Missing')) 'Missing property was treated as present.'
            Assert-True ($null -eq (Get-DataValue -InputObject $source -Name 'NullValue')) 'Null property was changed.'
            Assert-True ($null -eq (Get-DataValue -InputObject $source -Name 'Missing')) 'Missing property did not return null.'
            $boolean = Get-DataValue -InputObject $source -Name 'FalseValue'
            Assert-True ($boolean -is [bool] -and -not $boolean) 'Scalar false was wrapped, dropped or converted.'
            $empty = Get-DataValue -InputObject $source -Name 'EmptyValue'
            Assert-True ($empty -is [array] -and $empty.Count -eq 0) 'Empty array collapsed to null or a nested non-empty array.'
            $many = Get-DataValue -InputObject $source -Name 'ArrayValue'
            Assert-True ($many -is [array] -and $many.Count -eq 2 -and $many[0] -eq 'one' -and $many[1] -eq 'two') 'Array lost its shape or values.'
        }
    }
    Test-Case 'Null source has no properties and returns null values' {
        Assert-True (-not (Test-DataProperty -InputObject $null -Name 'value')) 'Null source was treated as present.'
        Assert-True ($null -eq (Get-DataValue -InputObject $null -Name 'value')) 'Null source did not yield null.'
    }
    Test-Case 'Single item, true, zero and empty string retain scalar or array type' {
        $source = @{ Single=@('one'); Enabled=$true; Zero=0; Blank='' }
        $single = Get-DataValue $source 'Single'
        Assert-True ($single -is [array] -and $single.Count -eq 1 -and $single[0] -eq 'one') 'Single-item array collapsed to scalar.'
        $enabled = Get-DataValue $source 'Enabled'
        Assert-True ($enabled -is [bool] -and $enabled) 'True was wrapped or converted.'
        Assert-True ((Get-DataValue $source 'Zero') -ceq 0) 'Zero changed.'
        Assert-True ((Get-DataValue $source 'Blank') -is [string] -and (Get-DataValue $source 'Blank').Length -eq 0) 'Empty string changed.'
    }
    Test-Case 'Complete empty collection returns an empty typed Items array' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = [pscustomobject]@{ value=@() }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri
        Assert-True ($result.Complete -and $result.Pages -eq 1 -and $result.Items -is [array] -and $result.Items.Count -eq 0 -and $result.Reason -eq '') 'Empty complete response was incomplete, null or non-empty.'
        Assert-True ($script:GraphCalls.Count -eq 1 -and $script:GraphCalls[0].Method -ceq 'GET' -and $script:GraphCalls[0].OutputType -eq 'PSObject') 'Read wrapper did not use the expected GET shape.'
    }
    Test-Case 'Multiple pages preserve ordered items and forward read headers' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = [pscustomobject]@{ value=@([pscustomobject]@{id='one'},[pscustomobject]@{id='two'}); '@odata.nextLink'=$secondUri }
        $script:GraphPages[$secondUri] = [pscustomobject]@{ value=@([pscustomobject]@{id='three'}) }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri -Headers @{ ConsistencyLevel='eventual' }
        Assert-True ($result.Complete -and $result.Pages -eq 2 -and ($result.Items.id -join ',') -eq 'one,two,three') 'Multipage items or completeness changed.'
        Assert-True ($script:GraphCalls.Count -eq 2 -and @($script:GraphCalls | Where-Object { $_.Method -cne 'GET' -or $_.Headers.ConsistencyLevel -ne 'eventual' }).Count -eq 0) 'Headers or GET method changed between pages.'
    }
    Test-Case 'Empty intermediate page with nextLink still reads later members' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = @{ value=@(); '@odata.nextLink'=$secondUri }
        $script:GraphPages[$secondUri] = @{ value=@([pscustomobject]@{id='later'}) }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri
        Assert-True ($result.Complete -and $result.Pages -eq 2 -and $result.Items.Count -eq 1 -and $result.Items[0].id -eq 'later') 'Empty first page was misread as a complete empty inventory.'
    }
    Test-Case 'Partial read failure preserves earlier evidence and is incomplete' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = @{ value=@([pscustomobject]@{id='one'}); '@odata.nextLink'=$secondUri }
        $script:GraphPages[$secondUri] = { throw 'Fixture denied; Bearer secretfixture access_token=secretfixture' }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri
        Assert-True (-not $result.Complete -and $result.Pages -eq 1 -and $result.Items.Count -eq 1 -and $result.Items[0].id -eq 'one') 'Partial failure became a complete or empty inventory.'
        Assert-True ($result.Reason -match 'Fixture denied' -and $result.Reason -notmatch 'secretfixture') 'Read error was absent or exposed token-like material.'
    }
    foreach ($badKind in @('Missing','Null')) {
        Test-Case "$badKind collection value is incomplete evidence" {
            Reset-GraphFixture
            $script:GraphPages[$firstUri] = if ($badKind -eq 'Missing') { [pscustomobject]@{} } else { [pscustomobject]@{value=$null} }
            $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri
            Assert-True (-not $result.Complete -and $result.Items.Count -eq 0 -and $result.Reason -match 'value') 'Malformed collection was counted as complete empty evidence.'
        }
    }
    foreach ($badValue in @($false, 'not-an-array', @{id='scalar'})) {
        Test-Case "Scalar collection value of type $($badValue.GetType().Name) is incomplete evidence" {
            Reset-GraphFixture
            $script:GraphPages[$firstUri] = [pscustomobject]@{ value=$badValue }
            $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri
            Assert-True (-not $result.Complete -and $result.Items.Count -eq 0) 'Non-array collection value was accepted as complete evidence.'
        }
    }
    Test-Case 'Null collection entry cannot become complete membership evidence' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = [pscustomobject]@{ value=@([pscustomobject]@{id='known'},$null,[pscustomobject]@{id='later'}) }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri
        Assert-True (-not $result.Complete -and $result.Reason -match 'null' -and @($result.Items | Where-Object { $null -eq $_ }).Count -eq 0) 'Null member was accepted as complete evidence.'
        Assert-True ($result.Items.Count -le 1 -and $script:GraphCalls.Count -eq 1) 'Read continued beyond malformed collection evidence.'
    }
    Test-Case 'Page cap leaves a partial inventory and never requests the next page' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = @{ value=@([pscustomobject]@{id='one'}); '@odata.nextLink'=$secondUri }
        $script:GraphPages[$secondUri] = @{ value=@([pscustomobject]@{id='two'}); '@odata.nextLink'=$thirdUri }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri -MaxPages 1
        Assert-True (-not $result.Complete -and $result.Pages -eq 1 -and $result.Items.Count -eq 1 -and $result.Reason -eq 'Page limit reached' -and $script:GraphCalls.Count -eq 1) 'Page limit was skipped or counted as complete.'
    }
    Test-Case 'Within-page item cap never silently truncates as complete' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = @{ value=@([pscustomobject]@{id='one'},[pscustomobject]@{id='two'},[pscustomobject]@{id='three'}) }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri -MaxItems 2
        Assert-True (-not $result.Complete -and $result.Items.Count -eq 2 -and $result.Reason -eq 'Item limit reached') 'Within-page truncation was counted as complete.'
    }
    Test-Case 'Exact item cap on a final page remains complete' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = @{ value=@([pscustomobject]@{id='one'},[pscustomobject]@{id='two'}) }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri -MaxItems 2
        Assert-True ($result.Complete -and $result.Items.Count -eq 2) 'A complete exact-limit collection was counted as truncated.'
    }
    Test-Case 'Exact item cap with another page remains incomplete without requesting it' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = @{ value=@([pscustomobject]@{id='one'}); '@odata.nextLink'=$secondUri }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri -MaxItems 1
        Assert-True (-not $result.Complete -and $result.Reason -match 'more pages' -and $script:GraphCalls.Count -eq 1) 'Next page or complete state escaped the item cap.'
    }
    Test-Case 'Repeated nextLink cannot loop or duplicate evidence' {
        Reset-GraphFixture
        $script:GraphPages[$firstUri] = @{ value=@([pscustomobject]@{id='one'}); '@odata.nextLink'=$secondUri }
        $script:GraphPages[$secondUri] = @{ value=@([pscustomobject]@{id='two'}); '@odata.nextLink'=$firstUri }
        $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri
        Assert-True (-not $result.Complete -and $result.Reason -eq 'Repeated nextLink' -and $result.Pages -eq 2 -and $result.Items.Count -eq 2 -and $script:GraphCalls.Count -eq 2) 'Repeated link was followed, duplicated or silently accepted.'
    }
    foreach ($allowedUri in @('https://graph.microsoft.com/v1.0/users','https://graph.microsoft.com/beta/groups?$select=id','https://graph.microsoft.com:443/beta/groups')) {
        Test-Case "Supported global Graph URI accepted: $allowedUri" {
            Assert-GraphReadUri -Uri $allowedUri
        }
    }
    $unsafeUris = @(
        'http://graph.microsoft.com/v1.0/users',
        'https://example.invalid/v1.0/users',
        'https://graph.microsoft.com.example.invalid/v1.0/users',
        'https://graph.microsoft.com@evil.invalid/v1.0/users',
        'https://fixture:secret@graph.microsoft.com/v1.0/users',
        'https://graph.microsoft.com:444/v1.0/users',
        'https://graph.microsoft.com/v2.0/users',
        'https://graph.microsoft.com/users',
        'https://graph.microsoft.com/beta/../users',
        'https://graph.microsoft.com/v1.0/users#fixture',
        '/v1.0/users',
        '//graph.microsoft.com/v1.0/users'
    )
    foreach ($unsafeUri in $unsafeUris) {
        Test-Case "Unsafe direct URI and nextLink rejected before request: $unsafeUri" {
            Reset-GraphFixture
            Assert-Throws { Invoke-ReadOnlyGraphGet -Uri $unsafeUri } 'Unsafe initial URI was accepted.'
            Assert-True ($script:GraphCalls.Count -eq 0) 'Unsafe URI reached the Graph stub.'
            $script:GraphPages[$firstUri] = @{ value=@([pscustomobject]@{id='safe-first-page'}); '@odata.nextLink'=$unsafeUri }
            $result = Invoke-ReadOnlyGraphCollection -Uri $firstUri
            Assert-True (-not $result.Complete -and $result.Items.Count -eq 1 -and $result.Pages -eq 1 -and $script:GraphCalls.Count -eq 1) 'Hostile nextLink was requested or inventory was marked complete.'
        }
    }
    Test-Case 'Page/item cap parameter ranges reject unbounded or invalid values' {
        foreach ($parameters in @(@{MaxPages=0},@{MaxPages=1001},@{MaxItems=0},@{MaxItems=100001})) {
            Assert-Throws { Invoke-ReadOnlyGraphCollection -Uri $firstUri @parameters } 'Invalid collection bound was accepted.'
        }
    }
    Test-Case 'Unknown, Review, Action and no-check reports never claim all checks passed' {
        $pass = New-CheckResult -Section 'Fixture' -Name 'Known' -Status Pass -Detail 'Read evidence.'
        foreach ($status in @('Unknown','Review','Action')) {
            $row = New-CheckResult -Section 'Fixture' -Name 'Unresolved' -Status $status -Detail 'Fixture condition.'
            $text = Get-ReportText -Rows @($pass,$row)
            Assert-True ($text -notmatch 'OBSERVED CHECKS PASSED') "$status report claimed success."
            Assert-True ($text -match "\[$($status.ToUpperInvariant())\]" -and $text -match 'No tenant settings changed') "$status marker or evidence limitation was absent."
        }
        $text = Get-ReportText -Rows @()
        Assert-True ($text -match 'INCOMPLETE - no checks returned' -and $text -notmatch 'OBSERVED CHECKS PASSED') 'Empty report claimed success.'
    }
    Test-Case 'Pass-only report is bounded evidence and PassThru returns unchanged rows' {
        $pass = New-CheckResult -Section 'Fixture' -Name 'Known' -Status Pass -Detail 'Read evidence.' -Evidence @{Observed=$false}
        $text = Get-ReportText -Rows @($pass)
        Assert-True ($text -match '\[OK\]' -and $text -match 'OBSERVED CHECKS PASSED' -and $text -match 'not authorization') 'Pass summary or limitation was absent.'
        $rows = @(Write-CheckReport -Title 'Offline fixture' -Results @($pass) -Ascii -PassThru 6>$null)
        Assert-True ($rows.Count -eq 1 -and [object]::ReferenceEquals($rows[0],$pass) -and $rows[0].Evidence.Observed -is [bool] -and -not $rows[0].Evidence.Observed) 'PassThru altered row count, object identity or false evidence.'
    }
    Test-Case 'Unicode pass marker is a checkmark' {
        $pass = New-CheckResult -Section 'Fixture' -Name 'Known' -Status Pass -Detail 'Read evidence.'
        $output = @(Write-CheckReport -Title 'Offline fixture' -Results @($pass) 6>&1)
        $text = ($output | ForEach-Object { $_.ToString() }) -join "`n"
        Assert-True ($text.Contains([string][char]0x2713)) 'Unicode pass checkmark was absent.'
    }
    Test-Case 'Invalid status cannot enter report data' {
        Assert-Throws { New-CheckResult -Section Fixture -Name Invalid -Status Success -Detail Invalid } 'Unrecognised status was accepted.'
    }
    Test-Case 'Evidence JSON preserves false, null, empty arrays and nested values' {
        $path = Join-Path $testRoot 'evidence.json'
        Save-ReadOnlyEvidence -Path $path -Value ([pscustomobject]@{Enabled=$false;NullValue=$null;Empty=@();Nested=@{Ids=@('one','two')}})
        $saved = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        Assert-True ($saved.Enabled -is [bool] -and -not $saved.Enabled -and $null -eq $saved.NullValue -and $saved.Empty -is [array] -and $saved.Empty.Count -eq 0 -and ($saved.Nested.Ids -join ',') -eq 'one,two') 'JSON export changed evidence values.'
    }
    Test-Case 'Evidence never overwrites an existing file without explicit Force' {
        $path = Join-Path $testRoot 'existing.json'
        Save-ReadOnlyEvidence -Path $path -Value @{ Original=$true }
        $hash = (Get-FileHash -LiteralPath $path).Hash
        Assert-Throws { Save-ReadOnlyEvidence -Path $path -Value @{ Replacement=$true } } 'Existing file was overwritten without Force.'
        Assert-True ((Get-FileHash -LiteralPath $path).Hash -eq $hash) 'Rejected export changed file content.'
        Save-ReadOnlyEvidence -Path $path -Value @{ Replacement=$true } -Force
        Assert-True ((Get-Content -LiteralPath $path -Raw | ConvertFrom-Json).Replacement -eq $true) 'Explicit forced overwrite did not write the intended evidence.'
    }
    Test-Case 'Missing evidence parent directory fails without creating paths' {
        $parent = Join-Path $testRoot 'does-not-exist'
        Assert-Throws { Save-ReadOnlyEvidence -Path (Join-Path $parent 'evidence.json') -Value @{Fixture=$true} } 'Missing parent directory was silently created.'
        Assert-True (-not (Test-Path -LiteralPath $parent)) 'Helper created a missing directory.'
    }
    Test-Case 'Caught error details redact credentials, flatten lines and cap size' {
        $record = $null
        try { throw ("Bearer tokenfixture access_token=accessfixture refresh_token=refreshfixture client_secret=secretfixture`r`n" + ('long' * 200)) } catch { $record = $_ }
        $detail = Get-SafeErrorText -ErrorRecord $record
        Assert-True ($detail -notmatch 'tokenfixture|accessfixture|refreshfixture|secretfixture|[\r\n]' -and $detail.Length -le 303 -and $detail.EndsWith('...')) 'Error sanitization exposed fixture credentials, multiline output or excess detail.'
    }

    $productionScripts = @(Get-ChildItem -LiteralPath $scriptRoot -Filter '*.ps1' -File -Recurse | Sort-Object FullName)
    Test-Case 'Production scripts are present for complete static scan' {
        Assert-True ($productionScripts.Count -ge 4) 'Expected shared helper and three collectors were not present.'
    }
    foreach ($scriptFile in $productionScripts) {
        Test-Case "AST syntax and tenant mutation boundaries: $($scriptFile.Name)" {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptFile.FullName, [ref]$tokens, [ref]$errors)
            Assert-True ($errors.Count -eq 0) ("PowerShell parser errors: " + (($errors | ForEach-Object Message) -join '; '))
            $commands = @($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]}, $true))
            $mutations = @($commands | Where-Object {
                $name = ($_.GetCommandName() -split '\\')[-1]
                ($name -ine 'Invoke-MgGraphRequest' -and $name -match '^(Set|Add|Remove|Disable|Enable|Start|Stop|Update|New|Clear|Reset|Grant|Revoke|Restore|Move|Suspend|Resume|Invoke)-(Mg|AD|ADSync|DistributionGroup|Mailbox|Recipient|CalendarProcessing|Place|Transport|Organization|Authentication|ConditionalAccess|Service|Team|Cs|UnifiedGroup|AzureAD|Msol|Intune|Device)') -or
                $name -match '^(Install|Update)-Module$'
            })
            Assert-True ($mutations.Count -eq 0) ("Tenant/service mutation or automatic module install call found: " + (($mutations | ForEach-Object { $_.Extent.Text }) -join '; '))
            $otherHttp = @($commands | Where-Object { ($_.GetCommandName() -split '\\')[-1] -in @('Invoke-WebRequest','Invoke-RestMethod','curl','wget','Start-BitsTransfer') })
            Assert-True ($otherHttp.Count -eq 0) 'Unreviewed HTTP/network command bypasses the GET-only Graph wrapper.'
            $graphRequests = @($commands | Where-Object { ($_.GetCommandName() -split '\\')[-1] -eq 'Invoke-MgGraphRequest' })
            foreach ($request in $graphRequests) {
                Assert-True ((Get-ConstantCommandArgument -Command $request -Name 'Method') -ceq 'GET') 'Graph request lacks explicit literal GET.'
                $bodyParameters = @($request.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -in @('Body','InputFile') })
                Assert-True ($bodyParameters.Count -eq 0) 'GET-only request contains a request body/input file.'
            }
            if ($scriptFile.Name -eq 'ReadOnlyCheck.Common.ps1') { Assert-True ($graphRequests.Count -eq 1) 'Expected exactly one central direct Graph request.' }
            else { Assert-True ($graphRequests.Count -eq 0) 'Collector bypasses the central Graph wrapper.' }
        }
    }
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host "`nCommon helper offline tests: $script:Passed passed, $script:Failed failed. No tenant or network connected." -ForegroundColor Cyan
Write-Host 'Static guards and local fixtures do not establish live tenant readiness or migration acceptance.'
if ($script:Failed) { $script:Failures | Write-Host; exit 1 }
