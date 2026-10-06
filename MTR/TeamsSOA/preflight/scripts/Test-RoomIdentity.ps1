#requires -Version 7.2
<#
Read-only Entra room preflight. All Graph requests are GET.
Default delegated scopes: User.Read.All, Group.Read.All, Domain.Read.All.
Optional federation details: Domain-InternalFederation.Read.All.
Optional tenant protection read: OnPremDirectorySynchronization.Read.All (Global Administrator).
Optional SOA GETs: only on a reused connection with already-approved SOA ReadWrite scope.
No new SOA write-capable consent is requested by this script.
Sources: https://learn.microsoft.com/graph/api/user-list-transitivememberof
https://learn.microsoft.com/graph/api/user-list-licensedetails
https://learn.microsoft.com/entra/identity/hybrid/how-to-user-source-of-authority-configure
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][guid]$TenantId,
    [ValidatePattern('^[^@\s]+@[^@\s]+$')][string]$RoomUpn = 'mtr@meetingrooms.ie',
    [ValidateSet('Before','After')][string]$Phase = 'Before',
    [switch]$UseExistingConnection,
    [switch]$IncludeFederationDetails,
    [switch]$IncludeTenantSyncProtection,
    [switch]$IncludeSoaStatus,
    [guid[]]$RoomListObjectId = @(),
    [switch]$SkipDynamicGroupScan,
    [switch]$PasswordlessMigrationConfirmed,
    [ValidateRange(1,1000)][int]$MaxPages = 100,
    [ValidateRange(1,100000)][int]$MaxItems = 5000,
    [string]$BaselinePath,
    [string]$ExportPath,
    [switch]$ForceExport,
    [switch]$Ascii,
    [switch]$PassThru
)
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'ReadOnlyCheck.Common.ps1')
$Checks = [System.Collections.Generic.List[object]]::new()
$OwnedConnection = $false
$Snapshot = [ordered]@{
    SchemaVersion = 1; Producer = 'Test-RoomIdentity'; TenantId = $TenantId.ToString()
    RoomUpn = $RoomUpn; CapturedAtUtc = [datetime]::UtcNow.ToString('o'); Phase = $Phase
    User = $null; Groups = @(); LicenceDetails = @(); DynamicSyncRules = @(); SoaStates = @()
    TenantSyncProtection = $null
    Completeness = [ordered]@{ User = $false; Membership = $false; Licences = $false; DynamicGroups = $false }
}
function Add-Result {
    param([string]$Section,[string]$Name,[string]$Status,[string]$Detail,[object]$Evidence)
    $Checks.Add((New-CheckResult -Section $Section -Name $Name -Status $Status -Detail $Detail -Evidence $Evidence))
}
function Get-BoundedCollection {
    param([string]$Uri,[hashtable]$Headers = @{})
    Invoke-ReadOnlyGraphCollection -Uri $Uri -Headers $Headers -MaxPages $MaxPages -MaxItems $MaxItems
}
function Read-SoaState {
    param([ValidateSet('users','groups')][string]$Kind,[guid]$Id,[string[]]$GrantedScopes)
    $needed = if ($Kind -eq 'users') { 'User-OnPremisesSyncBehavior.ReadWrite.All' } else { 'Group-OnPremisesSyncBehavior.ReadWrite.All' }
    if ($GrantedScopes -notcontains $needed) {
        Add-Result 'SOA state' "$Kind/$Id" 'Unknown' "GET requires the already-approved $needed scope. It was not requested or added."
        return
    }
    try {
        # Current User/Group SOA production guides explicitly use v1.0.
        $state = Invoke-ReadOnlyGraphGet -Uri ('https://graph.microsoft.com/v1.0/{0}/{1}/onPremisesSyncBehavior?$select=isCloudManaged' -f $Kind,$Id)
        $cloud = Get-DataValue $state 'isCloudManaged'
        if ($cloud -isnot [bool]) { throw 'SOA response omitted a Boolean isCloudManaged.' }
        $Snapshot.SoaStates += [pscustomobject]@{ Kind=$Kind; Id=$Id.ToString(); IsCloudManaged=$cloud }
        $status = if ($Phase -eq 'After' -and -not $cloud) { 'Action' } else { 'Pass' }
        $detail = if ($cloud) { 'isCloudManaged=true observed.' } else { 'isCloudManaged=false observed. Correlate with synchronized/native-cloud state and any pending rollback; this flag alone does not prove AD authority.' }
        Add-Result 'SOA state' "$Kind/$Id" $status $detail $state
    } catch { Add-Result 'SOA state' "$Kind/$Id" 'Unknown' (Get-SafeErrorText $_) }
}

try {
    if ($ExportPath -and $BaselinePath -and [IO.Path]::GetFullPath($ExportPath) -eq [IO.Path]::GetFullPath($BaselinePath)) {
        throw 'ExportPath must not overwrite the baseline, even with ForceExport.'
    }
    if ($IncludeSoaStatus -and -not $UseExistingConnection) {
        throw 'For optional SOA GETs, use -UseExistingConnection with an already-approved SOA permission. This script will not request write-capable SOA consent.'
    }
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Install Microsoft.Graph.Authentication through your approved module workflow, then rerun. No modules are installed automatically.'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $context = Get-MgContext -ErrorAction Stop
    if ($UseExistingConnection) {
        if ($null -eq $context) { throw 'No existing Graph connection. Connect with the documented read scopes first or omit -UseExistingConnection.' }
    } else {
        if ($null -ne $context) { throw 'An existing Graph context is present. Use -UseExistingConnection or disconnect it yourself; this script will not replace it.' }
        $Scopes = @('User.Read.All','Group.Read.All','Domain.Read.All')
        if ($IncludeFederationDetails) { $Scopes += 'Domain-InternalFederation.Read.All' }
        if ($IncludeTenantSyncProtection) { $Scopes += 'OnPremDirectorySynchronization.Read.All' }
        Connect-MgGraph -TenantId $TenantId.ToString() -Scopes $Scopes -Environment Global -ContextScope Process -NoWelcome -ErrorAction Stop
        $OwnedConnection = $true
        $context = Get-MgContext -ErrorAction Stop
    }
    if ([string](Get-DataValue $context 'TenantId') -ne $TenantId.ToString()) { throw 'Graph context tenant does not match -TenantId. No resource reads performed.' }
    if ([string](Get-DataValue $context 'AuthType') -ne 'Delegated') { throw 'This collector requires delegated access; it will not substitute app-only or another credential.' }
    if ([string](Get-DataValue $context 'Environment') -ne 'Global') { throw 'This package supports the Microsoft Graph global endpoint only. No resource reads performed.' }
    $GrantedScopes = Get-DataValue $context 'Scopes'
    Add-Result 'Connection' 'Tenant and access mode' 'Pass' "Expected tenant $TenantId; delegated global connection verified."
    if ($null -eq $GrantedScopes -or @($GrantedScopes).Count -eq 0) {
        Add-Result 'Connection' 'Advertised permission mode' 'Unknown' 'Context omitted scope evidence. The script still uses GET only; inspect actual grants and operator roles.'
    } elseif (@($GrantedScopes | Where-Object { $_ -match 'ReadWrite|\.Write\.' }).Count -gt 0) {
        Add-Result 'Connection' 'Existing permission breadth' 'Review' 'The context advertises write-capable scopes. This script uses GET only; reusing it does not narrow existing grants.'
    } else {
        Add-Result 'Connection' 'Advertised permission mode' 'Pass' 'No write-capable scope name observed in context. Existing app grants and operator roles require separate review.'
    }

    $encodedUpn = [uri]::EscapeDataString($RoomUpn)
    $user = Invoke-ReadOnlyGraphGet -Uri ('https://graph.microsoft.com/beta/users/{0}?$select=id,displayName,userPrincipalName,mail,accountEnabled,onPremisesSyncEnabled,onPremisesImmutableId,onPremisesLastSyncDateTime,assignedLicenses' -f $encodedUpn)
    $uidText = [string](Get-DataValue $user 'id'); $uid = [guid]::Empty
    if (-not [guid]::TryParse($uidText,[ref]$uid) -or $uid -eq [guid]::Empty) { throw 'User read did not return a valid object ID. Further target reads stopped.' }
    $Snapshot.User = $user; $Snapshot.Completeness.User = $true
    Add-Result 'Room account' 'Exact identity' 'Pass' "$RoomUpn resolved to $uid. Preserve this object ID." $user
    $actualUpn = [string](Get-DataValue $user 'userPrincipalName')
    Add-Result 'Room account' 'UPN' $(if ($actualUpn -ieq $RoomUpn) { 'Pass' } else { 'Action' }) "Requested $RoomUpn; observed $actualUpn."
    $enabled = Get-DataValue $user 'accountEnabled'
    $enabledStatus = if ($enabled -isnot [bool]) { 'Unknown' } elseif ($enabled) { 'Pass' } else { 'Action' }
    Add-Result 'Room account' 'Account enabled' $enabledStatus "Observed value: $enabled. Null/missing is not treated as enabled."
    $sync = Get-DataValue $user 'onPremisesSyncEnabled'
    $isSynchronized = $sync -is [bool] -and $sync
    if (-not (Test-DataProperty $user 'onPremisesSyncEnabled')) {
        Add-Result 'Room account' 'Synchronization state' 'Unknown' 'Property omitted; authority cannot be inferred.'
    } elseif ($null -ne $sync -and $sync -isnot [bool]) {
        Add-Result 'Room account' 'Synchronization state' 'Unknown' 'Synchronization metadata was not Boolean/null; authority cannot be inferred.'
    } elseif ($isSynchronized) {
        Add-Result 'Room account' 'Synchronization state' $(if ($Phase -eq 'Before') {'Pass'} else {'Action'}) 'onPremisesSyncEnabled=true. Expected before transfer; after transfer investigate state and propagation.'
    } else {
        Add-Result 'Room account' 'Synchronization state' 'Review' 'Sync is false/null. That alone does not distinguish a native cloud account, SOA conversion or incomplete rollback.'
    }
    $anchor = [string](Get-DataValue $user 'onPremisesImmutableId')
    Add-Result 'Room account' 'Source anchor baseline' $(if ($isSynchronized -and -not $anchor) {'Action'} elseif ($anchor) {'Pass'} else {'Review'}) $(if ($anchor) {'Existing immutable ID captured; do not clear it.'} else {'No immutable ID returned; verify source matching before any change.'}) $anchor

    try {
        $licences = Get-BoundedCollection -Uri ('https://graph.microsoft.com/beta/users/{0}/licenseDetails?$select=skuId,skuPartNumber,servicePlans' -f $uid)
        $Snapshot.LicenceDetails = $licences.Items; $Snapshot.Completeness.Licences = $licences.Complete
        if (-not $licences.Complete) { throw "Licence read incomplete: $($licences.Reason)" }
        $roomLicences = @($licences.Items | Where-Object { [string](Get-DataValue $_ 'skuPartNumber') -match '^(Microsoft_Teams_Rooms_(Pro|Basic)|MTR_PREM|MEETING_ROOM)$' })
        if ($licences.Items.Count -eq 0) {
            Add-Result 'Licensing' 'Room licence' 'Action' 'No licence details returned from a complete read. A Teams Rooms licence is required.'
        } elseif ($roomLicences.Count -eq 0) {
            Add-Result 'Licensing' 'Room licence' 'Review' ('No recognized Rooms SKU in: ' + (($licences.Items | ForEach-Object { Get-DataValue $_ 'skuPartNumber' }) -join ', ') + '. Verify current/custom SKU entitlement; this is not proof of no valid licence.')
        } else {
            Add-Result 'Licensing' 'Room licence assignment' 'Pass' (($roomLicences | ForEach-Object { Get-DataValue $_ 'skuPartNumber' }) -join ', ')
            $teamsPlans = @(foreach ($licence in $roomLicences) {
                foreach ($plan in (Get-DataValue $licence 'servicePlans')) {
                    if ([string](Get-DataValue $plan 'servicePlanName') -eq 'TEAMS1') { $plan }
                }
            })
            if ($teamsPlans.Count -eq 0) { Add-Result 'Licensing' 'Teams service provisioning' 'Review' 'No TEAMS1 plan label found; verify service-plan health against the actual Rooms product.' }
            elseif (@($teamsPlans | Where-Object { [string](Get-DataValue $_ 'provisioningStatus') -eq 'Success' }).Count -gt 0) { Add-Result 'Licensing' 'Teams service provisioning' 'Pass' 'A TEAMS1 service plan reports Success. This does not prove device sign-in or other service health.' }
            elseif (@($teamsPlans | Where-Object { -not [string](Get-DataValue $_ 'provisioningStatus') }).Count -gt 0) { Add-Result 'Licensing' 'Teams service provisioning' 'Unknown' 'At least one TEAMS1 provisioning status is missing; health is unresolved.' }
            else { Add-Result 'Licensing' 'Teams service provisioning' 'Action' ('No successful TEAMS1 provisioning: ' + (($teamsPlans | ForEach-Object { Get-DataValue $_ 'provisioningStatus' }) -join ', ')) }
        }
    } catch { Add-Result 'Licensing' 'Licence evidence' 'Unknown' (Get-SafeErrorText $_) }

    $memberships = Get-BoundedCollection -Uri ('https://graph.microsoft.com/beta/users/{0}/transitiveMemberOf?$select=id,displayName&$count=true' -f $uid) -Headers @{ ConsistencyLevel='eventual' }
    $Snapshot.Completeness.Membership = $memberships.Complete
    Add-Result 'Group dependencies' 'Visible membership read' $(if ($memberships.Complete) {'Pass'} else {'Unknown'}) "$($memberships.Items.Count) objects across $($memberships.Pages) pages. $($memberships.Reason)"
    $groups = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in $memberships.Items) {
        $type = [string](Get-DataValue $entry '@odata.type')
        if ($type -eq '#microsoft.graph.directoryRole') { Add-Result 'Role hygiene' 'Administrative role membership' 'Action' ('Room has an observed directory role reference: ' + [string](Get-DataValue $entry 'id') + '. Investigate before SOA.') $entry }
        elseif ($type -eq '#microsoft.graph.group') {
            try {
                $gid = [guid]([string](Get-DataValue $entry 'id'))
                $g = Invoke-ReadOnlyGraphGet -Uri ('https://graph.microsoft.com/beta/groups/{0}?$select=id,displayName,onPremisesSyncEnabled,groupTypes,mailEnabled,securityEnabled,membershipRule,visibility' -f $gid)
                if ([string](Get-DataValue $g 'id') -ne $gid.ToString()) { throw 'Group identity mismatch or missing ID.' }
                foreach ($property in @('onPremisesSyncEnabled','groupTypes','mailEnabled','securityEnabled')) {
                    if (-not (Test-DataProperty $g $property)) { throw "Group metadata omitted $property; dependency classification is incomplete." }
                }
                $groupSync = Get-DataValue $g 'onPremisesSyncEnabled'
                if ($null -ne $groupSync -and $groupSync -isnot [bool]) { throw 'Group synchronization metadata was not Boolean/null.' }
                if ((Get-DataValue $g 'mailEnabled') -isnot [bool] -or (Get-DataValue $g 'securityEnabled') -isnot [bool]) { throw 'Group mail/security classification was not Boolean.' }
                $groupTypes = Get-DataValue $g 'groupTypes'
                if ($groupTypes -isnot [System.Collections.IEnumerable] -or $groupTypes -is [string] -or $groupTypes -is [System.Collections.IDictionary]) { throw 'Group type metadata was not an array.' }
                $groups.Add($g)
            } catch { $Snapshot.Completeness.Membership = $false; Add-Result 'Group dependencies' 'Group metadata' 'Unknown' (Get-SafeErrorText $_) }
        } elseif (-not $type) { $Snapshot.Completeness.Membership = $false; Add-Result 'Group dependencies' 'Limited membership record' 'Unknown' 'Membership record omitted its type; classification is incomplete.' $entry }
    }
    $Snapshot.Groups = $groups.ToArray()
    $adGroups = @($groups | Where-Object { (Get-DataValue $_ 'onPremisesSyncEnabled') -eq $true })
    Add-Result 'Group dependencies' 'AD-managed references' $(if ($adGroups.Count) {'Review'} elseif ($Snapshot.Completeness.Membership) {'Pass'} else {'Unknown'}) $(if ($adGroups.Count) { "$($adGroups.Count) AD-synchronized groups: " + (($adGroups | ForEach-Object { Get-DataValue $_ 'displayName' } | Select-Object -First 10) -join ', ') + '. Keep room AD object/sync scope until dependencies are resolved.' } else { 'No AD-synchronized group found in the fully read visible membership data; hidden membership remains a manual limit.' }) $adGroups
    Add-Result 'Role hygiene' 'Full privilege and hidden membership' 'Review' 'This token does not establish every eligible/PIM role or hidden membership. Verify the room is non-administrative and reconcile AD/Exchange membership separately.'

    if ($SkipDynamicGroupScan) { Add-Result 'Dynamic groups' 'Sync-state rules' 'Unknown' 'Scan explicitly skipped; inspect rules manually before migration.' }
    else {
        $filter = [uri]::EscapeDataString("groupTypes/any(c:c eq 'DynamicMembership')")
        $dynamic = Get-BoundedCollection -Uri ('https://graph.microsoft.com/beta/groups?$filter={0}&$select=id,displayName,membershipRule,membershipRuleProcessingState&$top=999&$count=true' -f $filter) -Headers @{ ConsistencyLevel='eventual' }
        foreach ($dynamicGroup in $dynamic.Items) {
            $dynamicId = [guid]::Empty
            if (-not [guid]::TryParse([string](Get-DataValue $dynamicGroup 'id'),[ref]$dynamicId) -or $dynamicId -eq [guid]::Empty -or
                -not (Test-DataProperty $dynamicGroup 'membershipRule') -or [string]::IsNullOrWhiteSpace([string](Get-DataValue $dynamicGroup 'membershipRule'))) {
                $dynamic.Complete = $false
                $dynamic.Reason = 'At least one dynamic group omitted its identity or rule; sync-state rule coverage is incomplete.'
                break
            }
        }
        $Snapshot.Completeness.DynamicGroups = $dynamic.Complete
        $rules = @($dynamic.Items | Where-Object { [string](Get-DataValue $_ 'membershipRule') -match '(?i)\bdirSyncEnabled\b' })
        $Snapshot.DynamicSyncRules = $rules
        $ruleStatus = if (-not $dynamic.Complete) {'Unknown'} elseif ($rules.Count) {'Review'} else {'Pass'}
        Add-Result 'Dynamic groups' 'Sync-state rules' $ruleStatus "$($rules.Count) dirSyncEnabled rules found among $($dynamic.Items.Count) visible dynamic groups. $($dynamic.Reason) Check additions/removals and licence/CA targeting; lexical matching is not a policy simulation." $rules
        foreach ($r in ($rules | Select-Object -First 20)) { Add-Result 'Dynamic groups' ([string](Get-DataValue $r 'displayName')) 'Review' ([string](Get-DataValue $r 'membershipRule')) $r }
    }

    try {
        $domainName = $RoomUpn.Split('@')[-1]
        $domain = Invoke-ReadOnlyGraphGet -Uri ('https://graph.microsoft.com/beta/domains/{0}?$select=id,isVerified,authenticationType' -f [uri]::EscapeDataString($domainName))
        if ([string](Get-DataValue $domain 'id') -ine $domainName) { throw 'Domain identity mismatch or missing ID.' }
        $verified = Get-DataValue $domain 'isVerified'
        Add-Result 'Authentication eligibility' 'Verified domain' $(if ($verified -isnot [bool]) {'Unknown'} elseif ($verified) {'Pass'} else {'Action'}) "Observed isVerified=$verified."
        $auth = [string](Get-DataValue $domain 'authenticationType')
        if ($auth -eq 'Managed') { Add-Result 'Authentication eligibility' 'Domain' 'Pass' "$domainName reports Managed. PHS versus PTA does not change this passwordless room's SOA procedure." $domain }
        elseif ($auth -eq 'Federated') {
            Add-Result 'Authentication eligibility' 'Domain' 'Review' "$domainName reports Federated. Establish whether AD FS restrictions or third-party AD/password dependencies apply to this account; no provider is guessed." $domain
            if ($IncludeFederationDetails) {
                $fed = Get-BoundedCollection -Uri ('https://graph.microsoft.com/beta/domains/{0}/federationConfiguration' -f [uri]::EscapeDataString($domainName))
                Add-Result 'Authentication eligibility' 'Federation metadata' $(if ($fed.Complete) {'Review'} else {'Unknown'}) "Read $($fed.Items.Count) configurations. $($fed.Reason) Issuer/name metadata alone is not definitive proof of provider or this room's effective path." $fed.Items
            }
        } else { Add-Result 'Authentication eligibility' 'Domain' 'Unknown' "Unrecognized/missing authenticationType: $auth" }
    } catch { Add-Result 'Authentication eligibility' 'Domain evidence' 'Unknown' (Get-SafeErrorText $_) }

    if ($IncludeSoaStatus) {
        Read-SoaState -Kind users -Id $uid -GrantedScopes $GrantedScopes
        foreach ($id in $RoomListObjectId) { Read-SoaState -Kind groups -Id $id -GrantedScopes $GrantedScopes }
    } else { Add-Result 'SOA state' 'Exact SOA flag' 'Unknown' 'Not requested. Optional -IncludeSoaStatus requires -UseExistingConnection and an already-approved write-capable SOA scope; sync labels alone do not prove authority.' }
    if ($IncludeTenantSyncProtection) {
        try {
            $configs = Get-BoundedCollection -Uri 'https://graph.microsoft.com/beta/directory/onPremisesSynchronization?$select=id,features'
            if (-not $configs.Complete -or $configs.Items.Count -ne 1) { throw 'Tenant sync configuration was incomplete or not exactly one object.' }
            $config = $configs.Items[0]; $features = Get-DataValue $config 'features'
            $flag = Get-DataValue $features 'blockCloudObjectTakeoverThroughHardMatchEnabled'
            if ($flag -isnot [bool]) { throw 'Takeover-protection flag omitted or not Boolean.' }
            $Snapshot.TenantSyncProtection = $config
            Add-Result 'Rollback preparation' 'Tenant hard-match protection' $(if ($flag) {'Pass'} else {'Review'}) "Observed protection=$flag. This is a read only; a rollback protection change requires separate delegated permission and Global Administrator." $config
        } catch { Add-Result 'Rollback preparation' 'Tenant hard-match protection' 'Unknown' (Get-SafeErrorText $_) }
    } else { Add-Result 'Rollback preparation' 'Tenant hard-match protection' 'Review' 'Not requested. A rollback administrator must record the current flag and plan the controlled tenant-wide protection change.' }

    Add-Result 'Manual evidence' 'Passwordless migration' 'Review' $(if ($PasswordlessMigrationConfirmed) {'Administrator confirmation recorded. Verify current Pro Management completion/health and all shared endpoints; no live device API was called.'} else {'Verify completed passwordless migration in Pro Management. Remote device-code sign-in alone does not prove conversion.'})
    Add-Result 'Manual evidence' 'Device and Exchange prerequisites' 'Review' 'Use the EXO collector and a controlled reboot/calendar/meeting test. Do not fully sign out or reset the Android room merely to test SOA. Remaining Exchange workloads and provisioning automation require separate review.'

    if ($BaselinePath) {
        try {
            $b = Get-Content -LiteralPath $BaselinePath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            if ((Get-DataValue $b 'Producer') -ne 'Test-RoomIdentity' -or (Get-DataValue $b 'SchemaVersion') -ne 1) { throw 'Baseline is not a supported identity collector snapshot.' }
            if ((Get-DataValue $b 'Phase') -ne 'Before') { throw 'BaselinePath must point to a Before snapshot.' }
            if ([string](Get-DataValue $b 'TenantId') -ne $TenantId.ToString() -or [string](Get-DataValue $b 'RoomUpn') -ine $RoomUpn) { throw 'Baseline tenant/room does not match this invocation.' }
            $beforeUser = Get-DataValue $b 'User'
            if ([string](Get-DataValue $beforeUser 'id') -ne $uid.ToString()) { Add-Result 'Baseline comparison' 'User object ID' 'Action' 'Original user object ID changed or is missing. Stop and reconcile identity.' }
            else { Add-Result 'Baseline comparison' 'User object ID' 'Pass' 'Original Entra user object ID preserved.' }
            $beforeGroups = @(foreach ($group in (Get-DataValue $b 'Groups')) { [string](Get-DataValue $group 'id') }) | Sort-Object
            $nowGroups = @($groups | ForEach-Object { [string](Get-DataValue $_ 'id') } | Sort-Object)
            if (-not (Get-DataValue (Get-DataValue $b 'Completeness') 'Membership') -or -not $Snapshot.Completeness.Membership) { Add-Result 'Baseline comparison' 'Membership' 'Unknown' 'Before or current membership evidence is incomplete.' }
            elseif (($beforeGroups -join '|') -eq ($nowGroups -join '|')) { Add-Result 'Baseline comparison' 'Visible group IDs' 'Pass' 'Visible group IDs preserved. Dynamic evaluation and policy applicability still require review.' }
            else { Add-Result 'Baseline comparison' 'Visible group IDs' 'Review' 'Membership differs. Reconcile additions/removals with dynamic rules, licensing and CA before acceptance.' }
        } catch { Add-Result 'Baseline comparison' 'Baseline file' 'Unknown' (Get-SafeErrorText $_) }
    }
} catch { Add-Result 'Read failure' 'Collector incomplete' 'Unknown' (Get-SafeErrorText $_) }
finally {
    if ($OwnedConnection) { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null }
}
if ($ExportPath) {
    try {
        if ($BaselinePath -and [IO.Path]::GetFullPath($ExportPath) -eq [IO.Path]::GetFullPath($BaselinePath)) { throw 'ExportPath must not overwrite the baseline, even with ForceExport.' }
        Save-ReadOnlyEvidence -Path $ExportPath -Value $Snapshot -Force:$ForceExport
        Add-Result 'Local evidence' 'Snapshot' 'Pass' "Saved $ExportPath. Review completeness flags; contains tenant identifiers, not credentials."
    }
    catch { Add-Result 'Local evidence' 'Snapshot' 'Action' (Get-SafeErrorText $_) }
}
Write-CheckReport -Title "READ-ONLY Entra room preflight: $RoomUpn ($Phase)" -Results $Checks.ToArray() -Ascii:$Ascii -PassThru:$PassThru
