# Self-contained HTML report (no external resources) so it can be shared offline.

function ConvertTo-MtrHtml {
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return '' }
    [System.Net.WebUtility]::HtmlEncode([string]$Value)
}

function New-MtrHtmlReport {
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Findings,
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rooms,
        [Parameter(Mandatory)]$Model,
        [Parameter(Mandatory)]$Context,
        [Parameter(Mandatory)]$Baseline,
        [Parameter(Mandatory)][string]$Path
    )
    $h = { param($v) ConvertTo-MtrHtml $v }
    $severities = 'Critical', 'High', 'Medium', 'Low', 'Info', 'Pass'
    $counts = @{}
    foreach ($s in $severities) { $counts[$s] = @($Findings | Where-Object Severity -eq $s).Count }
    $sorted = @($Findings | Sort-Object SeverityRank, Category, CheckId)
    $categories = @($sorted | ForEach-Object Category | Sort-Object -Unique)
    $meta = $Context.Meta
    $collected = ConvertTo-MtrDateTime $meta.CollectedAt

    $sb = [System.Text.StringBuilder]::new()
    $add = { param([string]$s) $null = $sb.Append($s) }

    & $add @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Teams Rooms Audit</title>
<style>
:root{--bg:#f7f7f8;--fg:#1d1d1f;--muted:#5f6368;--card:#fff;--line:#e3e3e6;--crit:#b00020;--high:#d93025;--med:#e37400;--low:#1a73e8;--info:#5f6368;--pass:#188038;--code:#f1f3f4}
@media (prefers-color-scheme:dark){:root{--bg:#161618;--fg:#e8e8ea;--muted:#a0a0a8;--card:#202024;--line:#34343a;--code:#2a2a30;--low:#8ab4f8;--info:#a0a0a8;--pass:#81c995}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif}
header,main{max-width:1280px;margin:0 auto;padding:16px}h1{font-size:22px;margin:8px 0}h2{font-size:18px;margin:28px 0 10px}
.meta{color:var(--muted);font-size:13px}.cards{display:flex;flex-wrap:wrap;gap:10px;margin-top:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 16px;min-width:110px;cursor:pointer}.card b{display:block;font-size:22px}
.sev{display:inline-block;min-width:64px;text-align:center;border-radius:4px;padding:1px 6px;font-size:12px;font-weight:600;color:#fff}
.Critical{background:var(--crit)}.High{background:var(--high)}.Medium{background:var(--med)}.Low{background:var(--low)}.Info{background:var(--info)}.Pass{background:var(--pass)}
details{background:var(--card);border:1px solid var(--line);border-radius:8px;margin:6px 0}summary{cursor:pointer;padding:10px 12px;list-style:none;display:flex;gap:10px;align-items:baseline;flex-wrap:wrap}
summary::-webkit-details-marker{display:none}.id{color:var(--muted);font-family:Consolas,monospace;font-size:12px}.cat{color:var(--muted);font-size:12px}
.body{padding:0 14px 12px;border-top:1px solid var(--line)}.body p{margin:8px 0}.lbl{font-weight:600}
pre{background:var(--code);padding:8px;border-radius:6px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}
ul.obj{max-height:260px;overflow:auto;margin:4px 0;padding-left:20px}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);font-size:12.5px}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{position:sticky;top:0;background:var(--card);cursor:pointer;white-space:nowrap}.wrap{max-height:640px;overflow:auto;border-radius:8px}
.controls{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}input[type=search]{padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);min-width:260px}
select{padding:5px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg)}
.OK{color:var(--pass);font-weight:600}.Failed{color:var(--high);font-weight:600}.Partial{color:var(--med);font-weight:600}.Skipped{color:var(--muted);font-weight:600}
a{color:var(--low)}.note{color:var(--muted);font-size:12.5px}
</style></head><body>
<header>
<h1>Microsoft Teams Rooms - tenant audit</h1>
<div class="meta">Tenant: <b>$(& $h $meta.TenantName)</b> ($(& $h $meta.TenantId)) &middot; Collected: $(& $h ($(if ($collected) { $collected.ToString('yyyy-MM-dd HH:mm') + ' UTC' }))) &middot; Run by: $(& $h $meta.RunBy) &middot; Baseline: $(& $h $Baseline.BaselineDate) &middot; Tool: $(& $h $meta.ToolVersion)</div>
<div class="meta">Read-only audit. Teams Rooms accounts: $((Get-MtrCount $Model.MtrAccounts)) &middot; Devices: $((Get-MtrCount $Model.Devices)) &middot; Room mailboxes: $((Get-MtrCount $Context.Exchange.RoomMailboxes)) &middot; Room lists: $((Get-MtrCount $Context.Exchange.RoomLists))</div>
<div class="cards">
"@
    foreach ($s in $severities) { & $add "<div class='card' onclick=""setSev('$s')""><span class='sev $s'>$s</span><b>$($counts[$s])</b></div>" }
    & $add '</div></header><main>'

    # Coverage
    & $add '<h2>Coverage</h2><p class="note">What could and could not be read. A section marked Failed or Partial may hide issues - absence of findings there is not a pass.</p><div class="wrap"><table><tr><th>Section</th><th>Item</th><th>Status</th><th>Detail</th></tr>'
    foreach ($c in (Get-MtrArray $Context.Coverage)) { & $add "<tr><td>$(& $h $c.Section)</td><td>$(& $h $c.Item)</td><td class='$(& $h $c.Status)'>$(& $h $c.Status)</td><td>$(& $h $c.Detail)</td></tr>" }
    & $add '</table></div>'

    # Findings
    & $add '<h2>Findings</h2><div class="controls"><input type="search" id="q" placeholder="Filter findings (text, room, policy)..." oninput="filt()"><select id="sev" onchange="filt()"><option value="">All severities</option>'
    foreach ($s in $severities) { & $add "<option>$s</option>" }
    & $add '</select><select id="cat" onchange="filt()"><option value="">All categories</option>'
    foreach ($c in $categories) { & $add "<option>$(& $h $c)</option>" }
    & $add '</select><span class="note" id="shown"></span></div><div id="findings">'
    foreach ($f in $sorted) {
        & $add "<details class='f' data-sev='$($f.Severity)' data-cat='$(& $h $f.Category)'><summary><span class='sev $($f.Severity)'>$($f.Severity)</span><span class='id'>$(& $h $f.CheckId)</span><span>$(& $h $f.Title)</span><span class='cat'>$(& $h $f.Category)$(if ($f.Target -and $f.Target -ne 'Tenant') { ' &middot; ' + (& $h $f.Target) })</span></summary><div class='body'>"
        if ($f.Detail) { & $add "<p>$(& $h $f.Detail)</p>" }
        if ($f.Impact) { & $add "<p><span class='lbl'>Why it matters:</span> $(& $h $f.Impact)</p>" }
        if ($f.Recommendation) { & $add "<p><span class='lbl'>Recommendation:</span> $(& $h $f.Recommendation)</p>" }
        if ($f.FixLocation -and $f.FixLocation -ne 'None') { & $add "<p><span class='lbl'>Where to fix:</span> $(& $h $f.FixLocation)</p>" }
        $objects = Get-MtrArray $f.AffectedObjects
        if ($objects.Count) {
            & $add "<p class='lbl'>Affected ($($objects.Count)):</p><ul class='obj'>"
            foreach ($o in ($objects | Select-Object -First 300)) { & $add "<li>$(& $h $o)</li>" }
            if ($objects.Count -gt 300) { & $add "<li>... $($objects.Count - 300) more in Findings.csv</li>" }
            & $add '</ul>'
        }
        if ($f.VerifyCommand.Count) { & $add "<p class='lbl'>Verify (read-only):</p><pre>$(& $h ($f.VerifyCommand -join [Environment]::NewLine))</pre>" }
        if ($f.RemediationCommand.Count) { & $add "<p class='lbl'>Suggested fix (not run - also in Remediation-Plan.ps1):</p><pre>$(& $h ((@($f.RemediationCommand) | Select-Object -First 60) -join [Environment]::NewLine))</pre>" }
        if ($f.Reference) { & $add "<p><a href='$(& $h $f.Reference)' target='_blank' rel='noopener'>Microsoft Learn</a></p>" }
        & $add '</div></details>'
    }
    & $add '</div>'

    # Rooms
    & $add '<h2>Room inventory</h2><div class="controls"><input type="search" id="rq" placeholder="Filter rooms..." oninput="rfilt()"></div><div class="wrap"><table id="rooms"><thead><tr>'
    $columns = @('Classification', 'UserPrincipalName', 'Evidence', 'LicenseTier', 'SyncedFromAD', 'MailboxType', 'RoomLists', 'Building', 'City', 'Floor', 'Capacity', 'MTREnabled', 'TimeZone', 'Platforms', 'Devices', 'LastSignIn', 'ConditionalAccess', 'PasswordlessStatus', 'PasswordlessDetail')
    foreach ($col in $columns) { & $add "<th onclick='sortT(this)'>$col</th>" }
    & $add '</tr></thead><tbody>'
    foreach ($r in $Rooms) {
        & $add '<tr>'
        foreach ($col in $columns) { & $add "<td>$(& $h $r.$col)</td>" }
        & $add '</tr>'
    }
    & $add '</tbody></table></div>'

    # CA matrix
    if ($Context.ConditionalAccess) {
        $evals = @(Get-MtrCaEvaluation -Model $Model -Context $Context -Baseline $Baseline)
        & $add '<h2>Conditional Access vs. Teams Rooms</h2><p class="note">Every enabled or report-only policy that includes or excludes at least one room account.</p><div class="wrap"><table><tr><th>Policy</th><th>State</th><th>Teams Rooms policy</th><th>Applies to rooms</th><th>Rooms excluded</th><th>Platforms</th><th>Issues</th></tr>'
        foreach ($e in ($evals | Sort-Object @{ e = { (Get-MtrCount $_.Issues) }; Descending = $true }, Name)) {
            $issues = @($e.Issues | ForEach-Object { '[{0}] {1}' -f $_.Severity, $_.Title }) -join '; '
            & $add "<tr><td>$(& $h $e.Name)</td><td>$(& $h $e.State)</td><td>$(if ($e.IsDedicated) { 'Yes' } else { '' })</td><td>$((Get-MtrCount $e.Applies))</td><td>$((Get-MtrCount $e.Excluded))</td><td>$(& $h ($e.Platforms -join ', '))$(if ($e.LegacyOnly) { ' (legacy auth only)' })</td><td>$(& $h $issues)</td></tr>"
        }
        & $add '</table></div>'
    }

    # Manual checks
    & $add '<h2>Manual checks (not visible through APIs)</h2><div class="wrap"><table><tr><th>Where</th><th>Check</th></tr>'
    foreach ($m in $Baseline.ManualChecks) { & $add "<tr><td>$(& $h $m.Area)</td><td>$(& $h $m.Check) <a href='$(& $h $m.Link)' target='_blank' rel='noopener'>docs</a></td></tr>" }
    & $add '</table></div>'

    & $add @'
<p class="note">Generated by Invoke-MtrTenantAudit. The tool only reads configuration; suggested commands have not been run.</p>
</main>
<script>
function filt(){var q=document.getElementById('q').value.toLowerCase(),s=document.getElementById('sev').value,c=document.getElementById('cat').value,n=0;
document.querySelectorAll('#findings details').forEach(function(d){var ok=(!s||d.dataset.sev===s)&&(!c||d.dataset.cat===c)&&(!q||d.textContent.toLowerCase().indexOf(q)>=0);d.style.display=ok?'':'none';if(ok)n++;});
document.getElementById('shown').textContent=n+' shown';}
function setSev(s){document.getElementById('sev').value=s;filt();document.getElementById('findings').scrollIntoView();}
function rfilt(){var q=document.getElementById('rq').value.toLowerCase();document.querySelectorAll('#rooms tbody tr').forEach(function(r){r.style.display=(!q||r.textContent.toLowerCase().indexOf(q)>=0)?'':'none';});}
function sortT(th){var t=th.closest('table'),i=Array.prototype.indexOf.call(th.parentNode.children,th),b=t.tBodies[0],rows=Array.prototype.slice.call(b.rows),asc=th.dataset.asc!=='1';
rows.sort(function(a,c){var x=a.cells[i].textContent,y=c.cells[i].textContent,nx=parseFloat(x),ny=parseFloat(y);if(!isNaN(nx)&&!isNaN(ny))return asc?nx-ny:ny-nx;return asc?x.localeCompare(y):y.localeCompare(x);});
rows.forEach(function(r){b.appendChild(r);});th.dataset.asc=asc?'1':'0';}
filt();
</script></body></html>
'@
    Set-Content -Path $Path -Value $sb.ToString() -Encoding utf8
}
