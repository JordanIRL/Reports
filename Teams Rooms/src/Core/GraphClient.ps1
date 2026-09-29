# Read-only Microsoft Graph access. Every request made by the tool goes through this file.
# GET is the only permitted method; the single exception is POST to /$batch, and every request
# inside a batch is built here with method GET.

$script:MtrGraphRoot = 'https://graph.microsoft.com'

function Resolve-MtrGraphUri {
    param([Parameter(Mandatory)][string]$Uri)
    if ($Uri -match '^https://') { return $Uri }
    return '{0}/{1}' -f $script:MtrGraphRoot, $Uri.TrimStart('/')
}

function Get-MtrGraphErrorInfo {
    param([Parameter(Mandatory)]$ErrorRecord)

    $status = $null
    $retryAfter = $null
    $response = $ErrorRecord.Exception.Response
    if ($response) {
        try { $status = [int]$response.StatusCode } catch { $status = $null }
        try {
            if ($response.Headers.RetryAfter.Delta) { $retryAfter = [int][math]::Ceiling($response.Headers.RetryAfter.Delta.TotalSeconds) }
        }
        catch { $retryAfter = $null }
    }

    $message = $ErrorRecord.Exception.Message
    $code = $null
    if ($ErrorRecord.ErrorDetails -and $ErrorRecord.ErrorDetails.Message) {
        try {
            $parsed = $ErrorRecord.ErrorDetails.Message | ConvertFrom-Json -ErrorAction Stop
            if ($parsed.error) { $code = $parsed.error.code; $message = $parsed.error.message }
        }
        catch { $message = $ErrorRecord.ErrorDetails.Message }
    }

    if (-not $status) {
        switch -Regex ($ErrorRecord.Exception.Message) {
            '\b(4\d\d|5\d\d)\b'      { $status = [int]$Matches[1]; break }
            'TooManyRequests'        { $status = 429; break }
            'Forbidden'              { $status = 403; break }
            'Unauthorized'           { $status = 401; break }
            'NotFound'               { $status = 404; break }
            'BadRequest'             { $status = 400; break }
            'ServiceUnavailable'     { $status = 503; break }
        }
    }

    [pscustomobject]@{ Status = $status; RetryAfter = $retryAfter; Code = $code; Message = $message }
}

function Invoke-MtrGraphRequestWithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [ValidateSet('GET', 'POST')][string]$Method = 'GET',
        [string]$Body,
        [hashtable]$Headers,
        [int]$MaxRetries = 6
    )

    $resolved = Resolve-MtrGraphUri -Uri $Uri
    if ($Method -eq 'POST' -and $resolved -notmatch '/(v1\.0|beta)/\$batch$') {
        throw "Read-only guard: POST is only permitted to the Graph `$batch endpoint (attempted '$resolved')."
    }

    for ($attempt = 1; ; $attempt++) {
        try {
            $params = @{ Uri = $resolved; Method = $Method; OutputType = 'PSObject'; ErrorAction = 'Stop' }
            if ($Headers) { $params.Headers = $Headers }
            if ($Body) { $params.Body = $Body; $params.ContentType = 'application/json' }
            return Invoke-MgGraphRequest @params
        }
        catch {
            $info = Get-MtrGraphErrorInfo -ErrorRecord $_
            $transient = $info.Status -eq 429 -or ($info.Status -ge 500 -and $info.Status -le 599)
            if ($transient -and $attempt -le $MaxRetries) {
                $delay = if ($info.RetryAfter) { $info.RetryAfter } else { [math]::Min(60, [math]::Pow(2, $attempt)) }
                Write-Verbose "Graph $($info.Status) on $resolved - retrying in $delay s (attempt $attempt)"
                Start-Sleep -Seconds $delay
                continue
            }
            throw
        }
    }
}

function Invoke-MtrGraphGet {
    <#
    .SYNOPSIS
        GET a Graph resource. With -All, follows @odata.nextLink and emits every item of the collection.
        Without -All, returns the single object (or the first page's items for a collection).
        Collection items are emitted one by one, so wrap calls in @() when an array is needed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Uri,
        [switch]$All,
        [switch]$Eventual,
        [int]$MaxPages = 1000
    )

    $headers = if ($Eventual) { @{ ConsistencyLevel = 'eventual' } } else { $null }
    $response = Invoke-MtrGraphRequestWithRetry -Uri $Uri -Method GET -Headers $headers

    if ($null -eq $response) { return }
    if ($response.PSObject.Properties.Name -notcontains 'value') { return $response }

    $items = [System.Collections.Generic.List[object]]::new()
    foreach ($item in (Get-MtrArray $response.value)) { $items.Add($item) }
    $next = $response.'@odata.nextLink'
    $page = 1
    while ($All -and $next -and $page -lt $MaxPages) {
        $response = Invoke-MtrGraphRequestWithRetry -Uri $next -Method GET -Headers $headers
        foreach ($item in (Get-MtrArray $response.value)) { $items.Add($item) }
        $next = $response.'@odata.nextLink'
        $page++
    }
    # Items are written to the pipeline one by one (callers wrap with @() or Get-MtrArray).
    $items.ToArray()
}

function Invoke-MtrGraphBatch {
    <#
    .SYNOPSIS
        Runs many GET requests through Graph JSON batching (20 per call).
    .PARAMETER Requests
        Objects with Id and Url (relative to the version root, e.g. '/users/{id}?$select=id').
        Optional Eventual = $true adds ConsistencyLevel: eventual.
    .PARAMETER FollowNextLink
        Page through collection results that return @odata.nextLink.
    .OUTPUTS
        Hashtable keyed by request Id -> [pscustomobject]@{ Status; Body; Items; Error }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Requests,
        [ValidateSet('v1.0', 'beta')][string]$Version = 'v1.0',
        [switch]$FollowNextLink,
        [int]$MaxRetries = 6
    )

    $results = @{}
    $Requests = Get-MtrArray $Requests
    if (-not $Requests.Count) { return $results }

    $queue = [System.Collections.Generic.Queue[object]]::new()
    foreach ($r in $Requests) { $queue.Enqueue($r) }
    $attempts = @{}

    while ($queue.Count -gt 0) {
        $chunk = [System.Collections.Generic.List[object]]::new()
        while ($queue.Count -gt 0 -and $chunk.Count -lt 20) { $chunk.Add($queue.Dequeue()) }

        $batchRequests = foreach ($r in $chunk) {
            $entry = [ordered]@{ id = [string]$r.Id; method = 'GET'; url = [string]$r.Url }
            if ($r.Eventual) { $entry.headers = @{ ConsistencyLevel = 'eventual' } }
            $entry
        }
        foreach ($br in $batchRequests) {
            if ($br.method -ne 'GET') { throw 'Read-only guard: batch contains a non-GET request.' }
        }
        $body = @{ requests = Get-MtrArray $batchRequests } | ConvertTo-Json -Depth 6 -Compress

        $response = Invoke-MtrGraphRequestWithRetry -Uri "$Version/`$batch" -Method POST -Body $body
        $maxWait = 0
        foreach ($item in (Get-MtrArray $response.responses)) {
            $id = [string]$item.id
            $status = [int]$item.status
            if ($status -eq 429 -or $status -ge 500) {
                $attempts[$id] = 1 + [int]$attempts[$id]
                if ($attempts[$id] -le $MaxRetries) {
                    $wait = 5
                    if ($item.headers -and $item.headers.'Retry-After') { $wait = [int]$item.headers.'Retry-After' }
                    $maxWait = [math]::Max($maxWait, $wait)
                    $queue.Enqueue(($chunk | Where-Object { [string]$_.Id -eq $id } | Select-Object -First 1))
                    continue
                }
            }

            $result = [pscustomobject]@{ Status = $status; Body = $item.body; Items = $null; Error = $null }
            if ($status -ge 200 -and $status -lt 300) {
                if ($item.body -and $item.body.PSObject.Properties.Name -contains 'value') {
                    $list = [System.Collections.Generic.List[object]]::new()
                    foreach ($v in (Get-MtrArray $item.body.value)) { $list.Add($v) }
                    $next = $item.body.'@odata.nextLink'
                    while ($FollowNextLink -and $next) {
                        $page = Invoke-MtrGraphRequestWithRetry -Uri $next -Method GET
                        foreach ($v in (Get-MtrArray $page.value)) { $list.Add($v) }
                        $next = $page.'@odata.nextLink'
                    }
                    $result.Items = $list.ToArray()
                }
            }
            else {
                $result.Error = if ($item.body.error) { '{0}: {1}' -f $item.body.error.code, $item.body.error.message } else { "HTTP $status" }
            }
            $results[$id] = $result
        }
        if ($maxWait -gt 0) {
            Write-Verbose "Batch throttled - waiting $maxWait s"
            Start-Sleep -Seconds $maxWait
        }
    }
    $results
}
