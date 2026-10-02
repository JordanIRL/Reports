#Requires -Version 7.2
#Requires -Modules Microsoft.Graph.Authentication, MicrosoftTeams

<#
.SYNOPSIS
    Identifies why Start transcription was unavailable to a participant in a Microsoft Teams meeting.

.DESCRIPTION
    Evaluates each control that can remove transcription from a participant who is not the organiser:

      - Organising tenant and participant identity (member, guest, external)
      - Participant and organiser Teams meeting policies (AllowTranscription, Copilot, ExplicitRecordingConsent)
      - Settings stored on the online meeting (allowTranscription, end-to-end encryption, who can present,
        designated presenters, meeting template, sensitivity label, meeting type)
      - Participant role recorded in the meeting attendance report(s)
      - Organiser licensing that exposes the 'Who can record and transcribe' meeting option
      - Location-based routing on the participant's calling policy
      - Transcripts created for the meeting (optional)

    Each result is classified as:
      Blocker   Confirmed cause.
      Possible  Setting that produces the same behaviour but is not exposed by any API.
      Info      Context relevant to the outcome.
      Pass      Control checked and not blocking.

.PARAMETER JoinWebUrl
    Join link of the meeting exactly as it appears in the invitation.

.PARAMETER UserUpn
    UPN or email address of the participant who could not start transcription.

.PARAMETER OrganiserUpn
    UPN of the meeting organiser. Required for short-format join links (https://teams.microsoft.com/meet/...),
    which do not carry the organiser's object ID.

.PARAMETER OccurrenceDate
    Local date of the occurrence to examine in a recurring meeting. Every attendance report is examined when omitted.

.PARAMETER TenantId
    Tenant ID for the app-only Microsoft Graph connection.

.PARAMETER ClientId
    Application (client) ID of the app registration used for Microsoft Graph.

.PARAMETER CertificateThumbprint
    Thumbprint of the app registration's certificate in the current user's or local machine certificate store.

.PARAMETER CheckTranscripts
    Lists transcripts created for the meeting. Requires OnlineMeetingTranscript.Read.All and the Teams meeting
    setting EnableGraphTranscriptAccess = True.

.PARAMETER ReportPath
    Writes the full result as JSON.

.PARAMETER PassThru
    Returns the result object to the pipeline.

.EXAMPLE
    .\Get-TeamsTranscriptionBlocker.ps1 -JoinWebUrl 'https://teams.microsoft.com/l/meetup-join/19%3ameeting_...' `
        -UserUpn 'aoife.murphy@contoso.ie' -TenantId $tenantId -ClientId $appId -CertificateThumbprint $thumbprint

.EXAMPLE
    .\Get-TeamsTranscriptionBlocker.ps1 -JoinWebUrl 'https://teams.microsoft.com/meet/34125678901?p=AbCdEf' `
        -UserUpn 'aoife.murphy@contoso.ie' -OrganiserUpn 'cian.walsh@contoso.ie' -OccurrenceDate 2026-09-29 `
        -CheckTranscripts -ReportPath .\transcription-diagnosis.json

.NOTES
    Microsoft Graph application permissions (admin consent):
        OnlineMeetings.Read.All, OnlineMeetingArtifact.Read.All, User.Read.All
        Optional: OnlineMeetingTranscript.Read.All (-CheckTranscripts), InformationProtectionPolicy.Read.All (label names)

    The app registration must be covered by a Teams application access policy granted to the organiser:
        New-CsApplicationAccessPolicy -Identity 'Meeting-Diagnostics' -AppIds '<ClientId>' -Description 'Meeting diagnostics'
        Grant-CsApplicationAccessPolicy -PolicyName 'Meeting-Diagnostics' -Identity '<organiser UPN>'
        Grant-CsApplicationAccessPolicy -PolicyName 'Meeting-Diagnostics' -Global

    Teams PowerShell: Teams Administrator or Global Reader.

    Online meeting settings are returned as currently stored on the meeting. Policy values are the current
    effective assignments for the participant and the organiser.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^https://')]
    [string]$JoinWebUrl,

    [Parameter(Mandatory)]
    [string]$UserUpn,

    [Alias('OrganizerUpn')]
    [string]$OrganiserUpn,

    [datetime]$OccurrenceDate,

    [string]$TenantId,

    [string]$ClientId,

    [string]$CertificateThumbprint,

    [switch]$CheckTranscripts,

    [string]$ReportPath,

    [switch]$PassThru
)

$ErrorActionPreference = 'Stop'

#region Helpers

$script:Findings = [System.Collections.Generic.List[object]]::new()

function Add-Finding {
    param(
        [Parameter(Mandatory)][ValidateSet('Blocker', 'Possible', 'Info', 'Pass')][string]$Status,
        [Parameter(Mandatory)][string]$Area,
        [Parameter(Mandatory)][string]$Check,
        [Parameter(Mandatory)][string]$Detail,
        [string]$Remediation = ''
    )
    $script:Findings.Add([pscustomobject]@{
            Status      = $Status
            Area        = $Area
            Check       = $Check
            Detail      = $Detail
            Remediation = $Remediation
        })
}

function Get-Value {
    param($Object, [Parameter(Mandatory)][string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) { return $Object[$Name] }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-GraphErrorMessage {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $raw = if ($ErrorRecord.ErrorDetails) { $ErrorRecord.ErrorDetails.Message } else { $null }
    if ($raw) {
        try {
            $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
            if ($parsed.error.message) { return [string]$parsed.error.message }
        }
        catch {
            Write-Verbose "Graph error body is not JSON: $($_.Exception.Message)"
        }
        return [string]$raw
    }
    return [string]$ErrorRecord.Exception.Message
}

function Test-GraphNotFound {
    param([Parameter(Mandatory)][System.Management.Automation.ErrorRecord]$ErrorRecord)
    $response = Get-Value $ErrorRecord.Exception 'Response'
    $statusCode = Get-Value $response 'StatusCode'
    if ($null -ne $statusCode) { return ([int]$statusCode -eq 404) }
    return ($ErrorRecord.Exception.Message -match 'NotFound|Not Found|\b404\b')
}

function Invoke-GraphGet {
    param([Parameter(Mandatory)][string]$Uri)
    return Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType HashTable -ErrorAction Stop
}

function Get-GraphCollection {
    param([Parameter(Mandatory)][string]$Uri)
    $next = $Uri
    while ($next) {
        $page = Invoke-GraphGet -Uri $next
        foreach ($item in @($page['value'])) {
            if ($null -ne $item) { $item }
        }
        $next = $page['@odata.nextLink']
    }
}

function ConvertTo-LocalDate {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    return ([datetime]$Value).ToLocalTime().Date
}

function ConvertTo-InlineText {
    param($InputObject)
    if ($null -eq $InputObject) { return '' }
    $pairs = foreach ($property in $InputObject.PSObject.Properties) {
        if ($null -ne $property.Value -and "$($property.Value)" -ne '') {
            '{0}={1}' -f $property.Name, $property.Value
        }
    }
    return ($pairs -join ', ')
}

function Get-JoinUrlContext {
    param([Parameter(Mandatory)][string]$Url)
    $query = ([uri]$Url).Query
    if (-not $query) { return $null }
    foreach ($pair in ($query.TrimStart('?') -split '&')) {
        $parts = $pair -split '=', 2
        if ($parts.Count -ne 2 -or $parts[0] -ne 'context') { continue }
        $json = $parts[1]
        for ($i = 0; $i -lt 3 -and $json -notmatch '^\s*\{'; $i++) {
            $json = [uri]::UnescapeDataString($json)
        }
        try {
            $context = $json | ConvertFrom-Json -ErrorAction Stop
            return [pscustomobject]@{
                TenantId    = [string](Get-Value $context 'Tid')
                OrganiserId = [string](Get-Value $context 'Oid')
            }
        }
        catch {
            return $null
        }
    }
    return $null
}

function Get-DirectoryUser {
    param([Parameter(Mandatory)][string]$Identity)
    $select = 'id,displayName,userPrincipalName,mail,userType,accountEnabled'
    try {
        return Invoke-GraphGet -Uri ('v1.0/users/{0}?$select={1}' -f [uri]::EscapeDataString($Identity), $select)
    }
    catch {
        if (-not (Test-GraphNotFound -ErrorRecord $_)) { throw }
    }
    if ($Identity -match '@') {
        $filter = "mail eq '{0}'" -f $Identity.Replace("'", "''")
        $result = Invoke-GraphGet -Uri ('v1.0/users?$filter={0}&$select={1}' -f [uri]::EscapeDataString($filter), $select)
        $match = @($result['value'])
        if ($match.Count -ge 1 -and $null -ne $match[0]) { return $match[0] }
    }
    return $null
}

function Get-EffectivePolicy {
    param(
        [Parameter(Mandatory)][string]$Identity,
        [Parameter(Mandatory)][string]$PolicyType
    )
    $assignment = @(Get-CsUserPolicyAssignment -Identity $Identity -PolicyType $PolicyType -ErrorAction Stop) |
        Select-Object -First 1
    $name = [string](Get-Value $assignment 'PolicyName')
    if (-not $name) {
        return [pscustomobject]@{ Name = 'Global'; Source = 'Org-wide default' }
    }
    $source = @(Get-Value $assignment 'PolicySource') | Select-Object -First 1
    $sourceText = switch ([string](Get-Value $source 'AssignmentType')) {
        'Group' { 'Group ({0})' -f (Get-Value $source 'Reference') }
        'Direct' { 'Direct' }
        default { 'Assigned' }
    }
    return [pscustomobject]@{ Name = $name; Source = $sourceText }
}

function Test-AdvancedMeetingLicence {
    param([Parameter(Mandatory)][string]$UserId)
    foreach ($sku in @(Get-GraphCollection -Uri "v1.0/users/$UserId/licenseDetails")) {
        if ([string]$sku['skuPartNumber'] -match 'TEAMS_PREMIUM|365_COPILOT') { return $true }
        foreach ($plan in @($sku['servicePlans'])) {
            if ([string]$plan['servicePlanName'] -match '^TEAMSPRO_|^M365_COPILOT' -and
                [string]$plan['provisioningStatus'] -ne 'Disabled') {
                return $true
            }
        }
    }
    return $false
}

#endregion

#region Diagnosis

function Invoke-TranscriptionDiagnosis {
    param(
        [Parameter(Mandatory)][string]$JoinWebUrl,
        [Parameter(Mandatory)][string]$UserUpn,
        [string]$OrganiserUpn,
        [Nullable[datetime]]$OccurrenceDate,
        [switch]$CheckTranscripts
    )

    $result = [ordered]@{
        GeneratedUtc     = (Get-Date).ToUniversalTime().ToString('o')
        JoinWebUrl       = $JoinWebUrl
        Participant      = $null
        Organiser        = $null
        Meeting          = $null
        ParticipantPolicy = $null
        OrganiserPolicy  = $null
        Attendance       = @()
        Transcripts      = @()
    }

    $homeTenantId = [string](Get-MgContext).TenantId

    # Organising tenant
    $urlContext = Get-JoinUrlContext -Url $JoinWebUrl
    if ($urlContext -and $urlContext.TenantId -and $urlContext.TenantId -ne $homeTenantId) {
        Add-Finding -Status Blocker -Area 'Identity' -Check 'Organising tenant' `
            -Detail "The meeting was organised in tenant $($urlContext.TenantId). Participants from outside the organiser's organisation cannot start transcription, and the meeting's policies and options belong to that tenant." `
            -Remediation "A participant from the organising organisation starts transcription and shares the transcript."
        return $result
    }

    # Participant
    $participant = Get-DirectoryUser -Identity $UserUpn
    if (-not $participant) {
        Add-Finding -Status Blocker -Area 'Identity' -Check 'Participant account' `
            -Detail "No member or guest account matching '$UserUpn' exists in this tenant. Participants joining from another organisation or anonymously cannot start transcription." `
            -Remediation 'A participant from the organising organisation starts transcription.'
    }
    elseif ([string]$participant['userType'] -eq 'Guest') {
        Add-Finding -Status Blocker -Area 'Identity' -Check 'Participant account' `
            -Detail "$($participant['userPrincipalName']) is a guest account. Guests cannot start transcription." `
            -Remediation 'A member of the organising organisation starts transcription, or the participant joins with a member account.'
    }
    else {
        Add-Finding -Status Pass -Area 'Identity' -Check 'Participant account' `
            -Detail "$($participant['userPrincipalName']) is a member account in the organising tenant."
        if ($participant['accountEnabled'] -eq $false) {
            Add-Finding -Status Info -Area 'Identity' -Check 'Participant sign-in' -Detail 'The participant account is currently disabled.'
        }
    }
    $result.Participant = $participant

    # Organiser
    $organiserKey = if ($OrganiserUpn) { $OrganiserUpn }
    elseif ($urlContext -and $urlContext.OrganiserId) { $urlContext.OrganiserId }
    else { $null }
    if (-not $organiserKey) {
        throw 'The join URL does not carry the organiser ID. Supply -OrganiserUpn.'
    }
    $organiser = Get-DirectoryUser -Identity $organiserKey
    if (-not $organiser) {
        throw "Organiser '$organiserKey' was not found in this tenant."
    }
    $result.Organiser = $organiser
    $organiserId = [string]$organiser['id']
    $isOrganiser = $participant -and ([string]$participant['id'] -eq $organiserId)

    # Online meeting
    $filter = "JoinWebUrl eq '{0}'" -f $JoinWebUrl.Replace("'", "''")
    $meetingLookupUri = 'v1.0/users/{0}/onlineMeetings?$filter={1}' -f $organiserId, [uri]::EscapeDataString($filter)
    try {
        $lookup = Invoke-GraphGet -Uri $meetingLookupUri
    }
    catch {
        $message = Get-GraphErrorMessage -ErrorRecord $_
        if ($message -match 'application access policy|not allowed to perform operations') {
            throw "Microsoft Graph denied access to the organiser's online meetings. Grant a Teams application access policy that includes this app to the organiser (Grant-CsApplicationAccessPolicy). Detail: $message"
        }
        throw "Online meeting lookup failed: $message"
    }
    $meeting = @($lookup['value']) | Where-Object { $null -ne $_ } | Select-Object -First 1
    if (-not $meeting) {
        throw "No online meeting owned by $($organiser['userPrincipalName']) matches the join URL. Confirm the organiser and use the join link exactly as it appears in the invitation."
    }

    $meetingId = [string]$meeting['id']
    $meetingPath = 'v1.0/users/{0}/onlineMeetings/{1}' -f $organiserId, [uri]::EscapeDataString($meetingId)
    $labelAssignment = $meeting['sensitivityLabelAssignment']
    $labelId = [string](Get-Value $labelAssignment 'sensitivityLabelId')

    $result.Meeting = [ordered]@{
        Subject              = $meeting['subject']
        MeetingId            = $meetingId
        MeetingType          = $meeting['meetingType']
        Created              = $meeting['creationDateTime']
        Start                = $meeting['startDateTime']
        End                  = $meeting['endDateTime']
        AllowTranscription   = $meeting['allowTranscription']
        AllowRecording       = $meeting['allowRecording']
        RecordAutomatically  = $meeting['recordAutomatically']
        AllowedPresenters    = $meeting['allowedPresenters']
        EndToEndEncryption   = $meeting['isEndToEndEncryptionEnabled']
        MeetingTemplateId    = $meeting['meetingTemplateId']
        SensitivityLabelId   = $labelId
        MeetingOptionsWebUrl = $meeting['meetingOptionsWebUrl']
    }

    # Meeting-level transcription
    if ($meeting['allowTranscription'] -eq $false) {
        Add-Finding -Status Blocker -Area 'Meeting' -Check 'Meeting-level transcription' `
            -Detail 'allowTranscription is False on the online meeting, which removes Start transcription for every participant.' `
            -Remediation 'The organiser re-enables transcription for the meeting; if the meeting was created by an application, correct the application so it no longer sets allowTranscription to False.'
    }
    else {
        Add-Finding -Status Pass -Area 'Meeting' -Check 'Meeting-level transcription' -Detail 'allowTranscription is True on the online meeting.'
    }

    if ($meeting['allowRecording'] -eq $false) {
        Add-Finding -Status Info -Area 'Meeting' -Check 'Meeting-level recording' -Detail 'allowRecording is False on the online meeting.'
    }

    # End-to-end encryption
    if ($meeting['isEndToEndEncryptionEnabled'] -eq $true) {
        Add-Finding -Status Blocker -Area 'Meeting' -Check 'End-to-end encryption' `
            -Detail 'The meeting is end-to-end encrypted. Live captions and transcription are unavailable in end-to-end encrypted meetings.' `
            -Remediation "The organiser turns off end-to-end encryption, or MeetingEndToEndEncryption is set to Disabled in the organiser's enhanced encryption policy."
    }
    else {
        Add-Finding -Status Pass -Area 'Meeting' -Check 'End-to-end encryption' -Detail 'The meeting is not end-to-end encrypted.'
    }

    # Who can present
    $allowedPresenters = [string]$meeting['allowedPresenters']
    $invitees = @(Get-Value (Get-Value $meeting 'participants') 'attendees')
    $invitedEntry = $invitees | Where-Object {
        $null -ne $_ -and (
            ($participant -and [string](Get-Value (Get-Value (Get-Value $_ 'identity') 'user') 'id') -eq [string]$participant['id']) -or
            ([string](Get-Value $_ 'upn') -ieq $UserUpn)
        )
    } | Select-Object -First 1
    $invitedRole = [string](Get-Value $invitedEntry 'role')

    if ($isOrganiser) {
        Add-Finding -Status Pass -Area 'Role' -Check 'Who can present' -Detail 'The participant is the organiser.'
    }
    elseif ($invitedRole -ieq 'coorganizer') {
        Add-Finding -Status Pass -Area 'Role' -Check 'Who can present' -Detail 'The participant is a co-organiser of the meeting.'
    }
    else {
        switch ($allowedPresenters) {
            'organizer' {
                Add-Finding -Status Blocker -Area 'Role' -Check 'Who can present' `
                    -Detail "Who can present is set to the organiser only. Every other participant joins as an attendee, and attendees cannot start transcription." `
                    -Remediation 'The organiser changes Who can present, promotes the participant to presenter, or adds them as a co-organiser.'
            }
            'roleIsPresenter' {
                if ($invitedRole -ieq 'presenter') {
                    Add-Finding -Status Pass -Area 'Role' -Check 'Who can present' -Detail 'Who can present is set to specific people and the participant is designated as a presenter.'
                }
                else {
                    Add-Finding -Status Blocker -Area 'Role' -Check 'Who can present' `
                        -Detail 'Who can present is set to specific people and the participant is not one of them, so they joined as an attendee. Attendees cannot start transcription.' `
                        -Remediation 'The organiser adds the participant as a presenter or co-organiser.'
                }
            }
            'organization' {
                Add-Finding -Status Pass -Area 'Role' -Check 'Who can present' -Detail "Who can present is set to people in the organiser's organisation."
            }
            { $_ -in @('everyone', '') } {
                Add-Finding -Status Pass -Area 'Role' -Check 'Who can present' -Detail 'Who can present is set to everyone.'
            }
            default {
                Add-Finding -Status Info -Area 'Role' -Check 'Who can present' -Detail "allowedPresenters returned '$allowedPresenters'."
            }
        }
    }

    # Attendance (role at the time of the meeting)
    $reportsUri = "$meetingPath/attendanceReports"
    $reports = @()
    try {
        $reports = @(Get-GraphCollection -Uri $reportsUri)
    }
    catch {
        Add-Finding -Status Info -Area 'Attendance' -Check 'Attendance reports' `
            -Detail "Attendance reports could not be read: $(Get-GraphErrorMessage -ErrorRecord $_)"
    }
    if ($OccurrenceDate) {
        $reports = @($reports | Where-Object { (ConvertTo-LocalDate $_['meetingStartDateTime']) -eq $OccurrenceDate.Date })
    }

    $attendanceRows = foreach ($report in $reports) {
        try {
            $detail = Invoke-GraphGet -Uri ('{0}/{1}?$expand=attendanceRecords' -f $reportsUri, [uri]::EscapeDataString([string]$report['id']))
        }
        catch {
            Add-Finding -Status Info -Area 'Attendance' -Check 'Attendance report' `
                -Detail "Attendance report $($report['id']) could not be read: $(Get-GraphErrorMessage -ErrorRecord $_)"
            continue
        }
        $record = @($detail['attendanceRecords']) | Where-Object {
            $null -ne $_ -and (
                ($participant -and [string](Get-Value (Get-Value $_ 'identity') 'id') -eq [string]$participant['id']) -or
                ([string]$_['emailAddress'] -ieq $UserUpn) -or
                ($participant -and $participant['mail'] -and [string]$_['emailAddress'] -ieq [string]$participant['mail'])
            )
        } | Select-Object -First 1

        [pscustomobject]@{
            ReportId               = [string]$report['id']
            MeetingStart           = $report['meetingStartDateTime']
            MeetingEnd             = $report['meetingEndDateTime']
            ParticipantFound       = [bool]$record
            Role                   = [string](Get-Value $record 'role')
            ParticipantTenantId    = [string](Get-Value (Get-Value $record 'identity') 'tenantId')
            TotalAttendanceSeconds = Get-Value $record 'totalAttendanceInSeconds'
        }
    }
    $attendanceRows = @($attendanceRows)
    $result.Attendance = $attendanceRows

    if ($attendanceRows.Count -eq 0) {
        $scope = if ($OccurrenceDate) { "for $($OccurrenceDate.ToString('yyyy-MM-dd'))" } else { 'for this meeting' }
        Add-Finding -Status Info -Area 'Attendance' -Check 'Participant role at the time' `
            -Detail "No attendance report is available $scope, so the participant's role during the meeting cannot be confirmed. Reports depend on the organiser's AllowEngagementReport policy and the meeting's attendance report option."
    }
    else {
        foreach ($row in $attendanceRows) {
            $when = if ($row.MeetingStart) { ([datetime]$row.MeetingStart).ToLocalTime().ToString('yyyy-MM-dd HH:mm') } else { $row.ReportId }
            if (-not $row.ParticipantFound) { continue }
            if ($row.ParticipantTenantId -and $row.ParticipantTenantId -ne $homeTenantId) {
                Add-Finding -Status Blocker -Area 'Attendance' -Check "Participant identity ($when)" `
                    -Detail "The participant joined with an identity from tenant $($row.ParticipantTenantId), outside the organiser's organisation." `
                    -Remediation 'The participant joins with their account in the organising tenant.'
            }
            elseif ($row.Role -ieq 'Attendee') {
                Add-Finding -Status Blocker -Area 'Attendance' -Check "Participant role ($when)" `
                    -Detail 'The attendance report records the participant as Attendee. Attendees cannot start transcription.' `
                    -Remediation 'The organiser makes the participant a presenter or co-organiser, or changes Who can present.'
            }
            elseif ($row.Role) {
                Add-Finding -Status Pass -Area 'Attendance' -Check "Participant role ($when)" -Detail "The attendance report records the participant as $($row.Role)."
            }
        }
        if (-not ($attendanceRows | Where-Object ParticipantFound)) {
            Add-Finding -Status Info -Area 'Attendance' -Check 'Participant role at the time' `
                -Detail 'The participant is not listed in the available attendance report(s). They joined under another identity, did not join the examined occurrence, or their attendance is hidden from reports.'
        }
    }

    # Policies
    $participantPolicy = $null
    if ($participant -and [string]$participant['userType'] -ne 'Guest') {
        try {
            $assignment = Get-EffectivePolicy -Identity ([string]$participant['userPrincipalName']) -PolicyType 'TeamsMeetingPolicy'
            $policy = Get-CsTeamsMeetingPolicy -Identity $assignment.Name -ErrorAction Stop
            $participantPolicy = [ordered]@{
                Name               = $assignment.Name
                Source             = $assignment.Source
                AllowTranscription = Get-Value $policy 'AllowTranscription'
            }
            if ($participantPolicy.AllowTranscription -ne $true) {
                Add-Finding -Status Blocker -Area 'Policy' -Check 'Participant transcription policy' `
                    -Detail "The participant's meeting policy '$($assignment.Name)' ($($assignment.Source)) has transcription turned off." `
                    -Remediation "Assign a meeting policy with AllowTranscription = True to the participant."
            }
            else {
                Add-Finding -Status Pass -Area 'Policy' -Check 'Participant transcription policy' `
                    -Detail "Meeting policy '$($assignment.Name)' ($($assignment.Source)) allows transcription."
            }
        }
        catch {
            Add-Finding -Status Info -Area 'Policy' -Check 'Participant transcription policy' -Detail "Policy could not be read: $($_.Exception.Message)"
        }

        try {
            $callingAssignment = Get-EffectivePolicy -Identity ([string]$participant['userPrincipalName']) -PolicyType 'TeamsCallingPolicy'
            $callingPolicy = Get-CsTeamsCallingPolicy -Identity $callingAssignment.Name -ErrorAction Stop
            if ((Get-Value $callingPolicy 'PreventTollBypass') -eq $true) {
                Add-Finding -Status Possible -Area 'Policy' -Check 'Location-based routing' `
                    -Detail "The participant's calling policy '$($callingAssignment.Name)' has PreventTollBypass enabled. Participants subject to location-based routing cannot start transcription." `
                    -Remediation 'Confirm whether location-based routing applied to the participant at the time.'
            }
        }
        catch {
            Add-Finding -Status Info -Area 'Policy' -Check 'Location-based routing' -Detail "Calling policy could not be read: $($_.Exception.Message)"
        }
    }
    $result.ParticipantPolicy = $participantPolicy

    $organiserPolicy = $null
    try {
        $assignment = Get-EffectivePolicy -Identity ([string]$organiser['userPrincipalName']) -PolicyType 'TeamsMeetingPolicy'
        $policy = Get-CsTeamsMeetingPolicy -Identity $assignment.Name -ErrorAction Stop
        $organiserPolicy = [ordered]@{
            Name                        = $assignment.Name
            Source                      = $assignment.Source
            AllowTranscription          = Get-Value $policy 'AllowTranscription'
            Copilot                     = [string](Get-Value $policy 'Copilot')
            ExplicitRecordingConsent    = [string](Get-Value $policy 'ExplicitRecordingConsent')
            DesignatedPresenterRoleMode = [string](Get-Value $policy 'DesignatedPresenterRoleMode')
            AllowEngagementReport       = [string](Get-Value $policy 'AllowEngagementReport')
        }

        if ($organiserPolicy.AllowTranscription -ne $true) {
            Add-Finding -Status Blocker -Area 'Policy' -Check 'Organiser transcription policy' `
                -Detail "The organiser's meeting policy '$($assignment.Name)' ($($assignment.Source)) has transcription turned off, which removes transcription for every participant in meetings they organise." `
                -Remediation 'Assign the organiser a meeting policy with AllowTranscription = True.'
        }
        else {
            Add-Finding -Status Pass -Area 'Policy' -Check 'Organiser transcription policy' `
                -Detail "Meeting policy '$($assignment.Name)' ($($assignment.Source)) allows transcription."
        }

        if ($organiserPolicy.Copilot -eq 'EnabledWithTranscript') {
            Add-Finding -Status Pass -Area 'Meeting options' -Check 'Allow Copilot' `
                -Detail "The organiser's policy enforces Copilot 'During and after the meeting', so Copilot cannot be turned off for the meeting."
        }
        else {
            Add-Finding -Status Possible -Area 'Meeting options' -Check 'Allow Copilot' `
                -Detail "The organiser's policy (Copilot = '$($organiserPolicy.Copilot)') lets them set Allow Copilot to Off, which turns off recording and transcription for everyone. This meeting option is not exposed through Microsoft Graph." `
                -Remediation "Confirm with the organiser; set Copilot = EnabledWithTranscript in the organiser's meeting policy to prevent it."
        }

        if ($organiserPolicy.ExplicitRecordingConsent -eq 'Enabled') {
            Add-Finding -Status Possible -Area 'Policy' -Check 'Explicit recording consent' `
                -Detail 'The organiser requires participant agreement for recording and transcription. A participant who declines becomes view-only and cannot start transcription. Consent choices are recorded in the attendance report and the Purview audit log (MeetingParticipantDetail).' `
                -Remediation 'Check the participant''s consent choice in the attendance report or Purview audit log.'
        }
    }
    catch {
        Add-Finding -Status Info -Area 'Policy' -Check 'Organiser policy' -Detail "Policy could not be read: $($_.Exception.Message)"
    }
    $result.OrganiserPolicy = $organiserPolicy

    # Who can record and transcribe (Teams Premium / Microsoft 365 Copilot organisers)
    try {
        $hasAdvancedLicence = Test-AdvancedMeetingLicence -UserId $organiserId
        if ($hasAdvancedLicence) {
            Add-Finding -Status Possible -Area 'Meeting options' -Check 'Who can record and transcribe' `
                -Detail "A Teams Premium or Microsoft 365 Copilot licence is assigned to the organiser, which exposes 'Who can record and transcribe'. 'Organizers and co-organizers' blocks presenters; 'No one' blocks everyone. This meeting option is not exposed through Microsoft Graph." `
                -Remediation "Confirm in the organiser's Meeting options; enforce 'Organizers, co-organizers, and presenters' with a meeting sensitivity label or locked meeting template."
        }
        else {
            Add-Finding -Status Pass -Area 'Meeting options' -Check 'Who can record and transcribe' `
                -Detail "The organiser holds no Teams Premium or Microsoft 365 Copilot licence, so 'Who can record and transcribe' is not available to them."
        }
    }
    catch {
        Add-Finding -Status Info -Area 'Meeting options' -Check 'Who can record and transcribe' `
            -Detail "Organiser licences could not be read: $(Get-GraphErrorMessage -ErrorRecord $_)"
    }

    # Meeting template
    $templateId = [string]$meeting['meetingTemplateId']
    if ($templateId) {
        $template = $null
        foreach ($getter in @('Get-CsTeamsMeetingTemplateConfiguration', 'Get-CsTeamsFirstPartyMeetingTemplateConfiguration')) {
            if ($template) { break }
            try {
                $configuration = & $getter -ErrorAction Stop
                $template = @(Get-Value $configuration 'TeamsMeetingTemplates') |
                    Where-Object { [string](Get-Value $_ 'Name') -eq $templateId } |
                    Select-Object -First 1
            }
            catch {
                Write-Verbose "$getter unavailable: $($_.Exception.Message)"
            }
        }
        if ($template) {
            $options = @(Get-Value $template 'TeamsMeetingOptions')
            $relevant = @($options | Where-Object { (ConvertTo-InlineText $_) -match 'Record|Transcri|Copilot|Presenter|Encrypt' } |
                ForEach-Object { ConvertTo-InlineText $_ })
            $optionText = if ($relevant.Count -gt 0) { $relevant -join ' | ' } else { 'No recording, transcription, Copilot, presenter or encryption options defined.' }
            Add-Finding -Status Info -Area 'Meeting options' -Check 'Meeting template' `
                -Detail "Created from template '$((Get-Value $template 'Description'))' ($templateId). Relevant options: $optionText"
        }
        else {
            Add-Finding -Status Info -Area 'Meeting options' -Check 'Meeting template' `
                -Detail "Created from template $templateId. Template settings could not be resolved."
        }
    }

    # Sensitivity label
    if ($labelId) {
        $labelName = $null
        try {
            $label = Invoke-GraphGet -Uri ("beta/security/informationProtection/sensitivityLabels/{0}" -f [uri]::EscapeDataString($labelId))
            $labelName = [string]$label['name']
        }
        catch {
            Write-Verbose "Sensitivity label name not resolved: $(Get-GraphErrorMessage -ErrorRecord $_)"
        }
        $labelText = if ($labelName) { "'$labelName' ($labelId)" } else { $labelId }
        Add-Finding -Status Possible -Area 'Meeting options' -Check 'Sensitivity label' `
            -Detail "Sensitivity label $labelText is applied. A meeting label can enforce Who can present, Who can record and transcribe, and end-to-end encryption, overriding the organiser." `
            -Remediation 'Review the label''s Teams meeting settings in Microsoft Purview.'
    }

    # Meeting type
    if ([string]$meeting['meetingType'] -eq 'broadcast') {
        Add-Finding -Status Info -Area 'Meeting' -Check 'Meeting type' `
            -Detail 'The meeting is an event. Transcription in webinars and town halls is governed by the Teams events policy (TranscriptionForWebinar / TranscriptionForTownhall).'
    }

    # Transcripts
    if ($CheckTranscripts) {
        try {
            $transcripts = @(Get-GraphCollection -Uri "$meetingPath/transcripts")
            if ($OccurrenceDate) {
                $transcripts = @($transcripts | Where-Object { (ConvertTo-LocalDate $_['createdDateTime']) -eq $OccurrenceDate.Date })
            }
            $result.Transcripts = @($transcripts | ForEach-Object {
                    [pscustomobject]@{ Id = $_['id']; Created = $_['createdDateTime']; Ended = $_['endDateTime'] }
                })
            if ($transcripts.Count -gt 0) {
                $times = ($transcripts | ForEach-Object { ([datetime]$_['createdDateTime']).ToLocalTime().ToString('yyyy-MM-dd HH:mm') }) -join ', '
                Add-Finding -Status Info -Area 'Transcripts' -Check 'Transcripts created' `
                    -Detail "$($transcripts.Count) transcript(s) created: $times. Transcription was available to at least one participant."
            }
            else {
                Add-Finding -Status Info -Area 'Transcripts' -Check 'Transcripts created' -Detail 'No transcripts were created for the examined meeting or occurrence.'
            }
        }
        catch {
            Add-Finding -Status Info -Area 'Transcripts' -Check 'Transcripts created' `
                -Detail "Transcripts could not be listed: $(Get-GraphErrorMessage -ErrorRecord $_). Listing requires OnlineMeetingTranscript.Read.All and EnableGraphTranscriptAccess = True (Set-CsTeamsMeetingConfiguration)."
        }
    }

    return $result
}

#endregion

#region Connections

$graphContext = Get-MgContext
if (-not $graphContext -or [string]$graphContext.AuthType -eq 'Delegated') {
    if (-not ($TenantId -and $ClientId -and $CertificateThumbprint)) {
        throw 'An app-only Microsoft Graph session is required. Supply -TenantId, -ClientId and -CertificateThumbprint, or run Connect-MgGraph with an application credential first.'
    }
    Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -CertificateThumbprint $CertificateThumbprint -NoWelcome | Out-Null
    $graphContext = Get-MgContext
}

$grantedRoles = @($graphContext.Scopes)
$requiredRoles = [System.Collections.Generic.List[object]]::new()
$requiredRoles.Add(@{ Name = 'OnlineMeetings.Read.All'; Alternatives = @('OnlineMeetings.ReadWrite.All') })
$requiredRoles.Add(@{ Name = 'OnlineMeetingArtifact.Read.All'; Alternatives = @() })
$requiredRoles.Add(@{ Name = 'User.Read.All'; Alternatives = @('User.ReadWrite.All', 'Directory.Read.All', 'Directory.ReadWrite.All') })
if ($CheckTranscripts) {
    $requiredRoles.Add(@{ Name = 'OnlineMeetingTranscript.Read.All'; Alternatives = @() })
}
foreach ($role in $requiredRoles) {
    $present = $grantedRoles -contains $role.Name -or [bool]($role.Alternatives | Where-Object { $grantedRoles -contains $_ })
    if (-not $present) {
        Write-Warning "Microsoft Graph application permission not present in the current token: $($role.Name)"
    }
}

try {
    $teamsTenant = Get-CsTenant -ErrorAction Stop
}
catch {
    Connect-MicrosoftTeams -ErrorAction Stop | Out-Null
    $teamsTenant = Get-CsTenant -ErrorAction Stop
}
if ([string]$teamsTenant.TenantId -ne [string]$graphContext.TenantId) {
    throw "Teams PowerShell is connected to tenant $($teamsTenant.TenantId) but Microsoft Graph is connected to $($graphContext.TenantId)."
}

#endregion

#region Output

$diagnosisParameters = @{
    JoinWebUrl       = $JoinWebUrl
    UserUpn          = $UserUpn
    OrganiserUpn     = $OrganiserUpn
    CheckTranscripts = $CheckTranscripts
}
if ($PSBoundParameters.ContainsKey('OccurrenceDate')) {
    $diagnosisParameters['OccurrenceDate'] = $OccurrenceDate
}
$diagnosis = Invoke-TranscriptionDiagnosis @diagnosisParameters

$severityOrder = @{ Blocker = 0; Possible = 1; Info = 2; Pass = 3 }
$orderedFindings = @($script:Findings | Sort-Object -Property @{ Expression = { $severityOrder[$_.Status] } }, Area)

$blockers = @($orderedFindings | Where-Object Status -eq 'Blocker')
$possibles = @($orderedFindings | Where-Object Status -eq 'Possible')
$verdict = if ($blockers.Count -gt 0) {
    'Confirmed: ' + (($blockers | ForEach-Object { $_.Check }) -join '; ')
}
elseif ($possibles.Count -gt 0) {
    'No confirmed blocker. Unverified causes: ' + (($possibles | ForEach-Object { $_.Check }) -join '; ')
}
else {
    'No blocking condition found in policy or meeting configuration. Remaining causes are policy propagation delay or client state.'
}

$diagnosis.Findings = $orderedFindings
$diagnosis.Verdict = $verdict

Write-Host ''
Write-Host 'Teams transcription diagnosis' -ForegroundColor Cyan
if ($diagnosis.Meeting) {
    Write-Host ('  Meeting     : {0}' -f $diagnosis.Meeting.Subject)
    Write-Host ('  Scheduled   : {0} to {1} (UTC)' -f $diagnosis.Meeting.Start, $diagnosis.Meeting.End)
}
if ($diagnosis.Organiser) {
    Write-Host ('  Organiser   : {0}' -f $diagnosis.Organiser['userPrincipalName'])
}
Write-Host ('  Participant : {0}' -f $(if ($diagnosis.Participant) { $diagnosis.Participant['userPrincipalName'] } else { $UserUpn }))
Write-Host ''

foreach ($finding in $orderedFindings) {
    $colour = switch ($finding.Status) {
        'Blocker' { 'Red' }
        'Possible' { 'Yellow' }
        'Info' { 'Gray' }
        default { 'Green' }
    }
    Write-Host ('[{0,-8}] {1} - {2}' -f $finding.Status, $finding.Area, $finding.Check) -ForegroundColor $colour
    Write-Host ('           {0}' -f $finding.Detail)
    if ($finding.Remediation) {
        Write-Host ('           Action: {0}' -f $finding.Remediation) -ForegroundColor DarkGray
    }
}

Write-Host ''
Write-Host ('Verdict: {0}' -f $verdict) -ForegroundColor $(if ($blockers.Count -gt 0) { 'Red' } elseif ($possibles.Count -gt 0) { 'Yellow' } else { 'Green' })

if ($ReportPath) {
    $directory = Split-Path -Path $ReportPath -Parent
    if ($directory -and -not (Test-Path -Path $directory)) {
        New-Item -Path $directory -ItemType Directory -Force | Out-Null
    }
    $diagnosis | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Encoding utf8
    Write-Host "Report written to $ReportPath" -ForegroundColor DarkGray
}

if ($PassThru) {
    [pscustomobject]$diagnosis
}

#endregion
