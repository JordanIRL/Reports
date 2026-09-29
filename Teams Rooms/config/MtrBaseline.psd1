# Microsoft Teams Rooms baseline used by Invoke-MtrTenantAudit.ps1.
# Values reflect Microsoft Learn guidance as of BaselineDate. When Microsoft changes guidance
# (new version floors, new unsupported CA controls, etc.) update this file - no code changes needed.
@{
    BaselineDate = '2026-09-28'

    Licensing = @{
        # Matched against subscribedSkus.skuPartNumber
        TeamsRoomsSkuPattern      = '(?i)Teams_Rooms|MEETING_ROOM|^MTR_'
        TeamsRoomsBasicSkuPattern = '(?i)Teams_Rooms_Basic'
        TeamsRoomsProSkuPattern   = '(?i)Teams_Rooms_Pro'
        SharedDeviceSkuPattern    = '(?i)^MCOCAP|Teams_Shared_Device|Teams_Shared_Space'
        # Enterprise per-user suites are not authorized for shared meeting devices
        UserSuiteSkuPattern       = '(?i)^(SPE_E3|SPE_E5|SPE_F1|SPE_F3|ENTERPRISEPACK|ENTERPRISEPREMIUM|STANDARDPACK|M365_F1|O365_BUSINESS|SPB|Microsoft_365_E|Office_365_E|M365_E)'
        # Matched against servicePlanName inside a SKU / licenseDetails
        MtrServicePlanPattern     = '(?i)^(MTRProManagement|Teams_Rooms_Pro|Teams_Rooms_Basic|Teams_Room_Pro|Teams_Room_Basic|MTR_|MEETING_ROOM)'
        IntunePlanPattern         = '(?i)^INTUNE_A'
        EntraP1PlanPattern        = '(?i)^AAD_PREMIUM'
        TeamsPlanPattern          = '(?i)^TEAMS1$|^TEAMS_GOV$'
        BasicMaxLicenses          = 25
    }

    CalendarProcessing = @(
        @{ Property = 'AutomateProcessing';             Expected = 'AutoAccept'; Severity = 'High';   Reason = 'Without AutoAccept the room does not book itself; organizers get no decision and the device calendar can miss meetings.' }
        @{ Property = 'DeleteComments';                 Expected = $false;       Severity = 'High';   Reason = 'The meeting body is needed to render join buttons for third-party (Zoom, Webex) meetings on the room.' }
        @{ Property = 'ProcessExternalMeetingMessages'; Expected = $true;        Severity = 'High';   Reason = 'Needed for invites from external organizers and external meetings forwarded by internal users.' }
        @{ Property = 'DeleteSubject';                  Expected = $false;       Severity = 'Medium'; Reason = 'Keeps the meeting subject on the room calendar and the device home screen.' }
        @{ Property = 'RemovePrivateProperty';          Expected = $false;       Severity = 'Medium'; Reason = 'Keeps the organizer''s private flag so private meetings are handled correctly on the device.' }
        @{ Property = 'AllowRecurringMeetings';         Expected = $true;        Severity = 'Medium'; Reason = 'Recurring meetings are declined otherwise.' }
        @{ Property = 'AddOrganizerToSubject';          Expected = $false;       Severity = 'Low';    Reason = 'Prevents the organizer name overwriting the subject shown on the device.' }
        @{ Property = 'DeleteAttachments';              Expected = $true;        Severity = 'Low';    Reason = 'Teams Rooms cannot open attachments; deleting them avoids storing content on the room calendar.' }
        @{ Property = 'AddAdditionalResponse';          Expected = $true;        Severity = 'Info';   Reason = 'Optional: tells organizers in the acceptance that this is a Teams Room.' }
    )

    ConditionalAccess = @{
        # Resources Teams Rooms need. A policy targeting any of these (or All / Office365) is relevant to rooms.
        RelevantApplicationIds = @(
            'All'
            'Office365'
            'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'   # Microsoft Teams Services
            '00000002-0000-0ff1-ce00-000000000000'   # Office 365 Exchange Online
            '00000003-0000-0ff1-ce00-000000000000'   # Office 365 SharePoint Online
            '0000000a-0000-0000-c000-000000000000'   # Microsoft Intune
            'd4ebce55-015a-49b5-a083-c84d1797ae8c'   # Microsoft Intune Enrollment
            '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'   # Device Registration Service
        )
        # Must never be blocked for room accounts
        RequiredResources = @(
            @{ Id = 'Office365';                            Name = 'Office 365' }
            @{ Id = 'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe'; Name = 'Microsoft Teams Services' }
            @{ Id = '00000003-0000-0ff1-ce00-000000000000'; Name = 'Office 365 SharePoint Online' }
            @{ Id = 'd4ebce55-015a-49b5-a083-c84d1797ae8c'; Name = 'Microsoft Intune Enrollment' }
            @{ Id = '01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9'; Name = 'Device Registration Service' }
        )
        UnsupportedBuiltInControls = @{
            domainJoinedDevice  = 'Require Microsoft Entra hybrid joined device'
            approvedApplication = 'Require approved client app'
            compliantApplication = 'Require app protection policy'
            passwordChange      = 'Require password change'
            riskRemediation     = 'Require risk remediation'
        }
    }

    # Entra sign-in error codes seen on room accounts and what they usually mean for a Teams Room
    SignInErrorCodes = @{
        '50055'  = @{ Severity = 'High';   Meaning = 'Password expired' }
        '50133'  = @{ Severity = 'High';   Meaning = 'Session invalid because the password expired or was changed' }
        '50053'  = @{ Severity = 'High';   Meaning = 'Account locked (too many bad passwords)' }
        '50057'  = @{ Severity = 'High';   Meaning = 'Account disabled' }
        '50076'  = @{ Severity = 'High';   Meaning = 'MFA required by policy - not supported for Teams Rooms' }
        '50079'  = @{ Severity = 'High';   Meaning = 'MFA registration required - not possible on a Teams Room' }
        '50074'  = @{ Severity = 'High';   Meaning = 'Strong authentication required' }
        '50158'  = @{ Severity = 'High';   Meaning = 'External security challenge not satisfied' }
        '53000'  = @{ Severity = 'High';   Meaning = 'Conditional Access requires a compliant/managed device' }
        '53001'  = @{ Severity = 'High';   Meaning = 'Conditional Access requires a hybrid joined device (not supported for Teams Rooms)' }
        '53003'  = @{ Severity = 'High';   Meaning = 'Blocked by Conditional Access' }
        '50126'  = @{ Severity = 'Medium'; Meaning = 'Invalid username or password (a device may still hold an old password)' }
        '50173'  = @{ Severity = 'Medium'; Meaning = 'Grant revoked, usually after a password change - the device must sign in again' }
        '700082' = @{ Severity = 'Medium'; Meaning = 'Refresh token expired due to inactivity (device offline for a long time)' }
        '50105'  = @{ Severity = 'Medium'; Meaning = 'Account not assigned to the application' }
    }
    # Interrupts that are part of normal sign-in flows
    BenignSignInErrorCodes = @('50058', '50140', '16000', '16001', '50199', '81010', '81012', '50097', '50125')

    Versions = @{
        WindowsMinBuildForPasswordless  = '10.0.26100.8655'
        WindowsAppMinForPasswordless    = '5.6.135.0'
        AndroidAppMinForPasswordless    = '1.0.96.2026129709'   # 1449/1.0.96.2026129709
        AndroidAppMinForEwsRetirement   = '1.0.96.2026249711'   # 1449/1.0.96.2026249711
        AuthenticatorMinForPasswordless = '6.2605.3066'
        AndroidMinOsVersion             = '10'
        EwsRetirementDate               = '2026-10-01'
        MinModuleVersions = @{
            'Microsoft.Graph.Authentication' = '2.25.0'
            'ExchangeOnlineManagement'       = '3.7.2'
            'MicrosoftTeams'                 = '7.8.1'
        }
    }

    Devices = @{
        LogitechManufacturerPattern = '(?i)logitech'
        AndroidPanelModelPattern    = '(?i)scheduler|panel'
        AutopilotMtrGroupTagPrefix  = 'MTR-'
        AospEnrollmentTypes         = @('androidAOSPUserOwnedDeviceEnrollment', 'androidAOSPUserlessDeviceEnrollment')
        TeamsRoomsAppNamePattern    = '(?i)teams\s*rooms|microsoft teams|com\.microsoft\.skype\.teams'
        AuthenticatorAppNamePattern = '(?i)authenticator|com\.azure\.authenticator'
        LapsTemplatePattern         = '(?i)LAPS|Local admin password'
    }

    Thresholds = @{
        DeviceStaleDays          = 7
        AospTokenWarningDays     = 90
        RoomListMaxMembers       = 50
        MtrGroupRatio            = 0.8
        DirSyncStaleHours        = 3
        DeviceQuotaWarningMargin = 5
        SignInsPerAccount        = 100
        PasswordExpiryWarnDays   = 14
    }

    Links = @{
        ConditionalAccess  = 'https://learn.microsoft.com/microsoftteams/rooms/conditional-access-and-compliance-for-devices'
        SupportedCA        = 'https://learn.microsoft.com/microsoftteams/rooms/supported-ca-and-compliance-policies'
        ResourceAccount    = 'https://learn.microsoft.com/microsoftteams/rooms/create-resource-account'
        Passwordless       = 'https://learn.microsoft.com/microsoftteams/rooms/passwordlessentraresourceaccounts'
        SetAsResource      = 'https://learn.microsoft.com/microsoftteams/rooms/set-as-resource-account-for-shared-teams-devices'
        AospEnrollment     = 'https://learn.microsoft.com/microsoftteams/devices/teams-aosp-enrollment'
        AndroidAuth        = 'https://learn.microsoft.com/microsoftteams/devices/authentication-best-practices-for-android-devices'
        AutopilotAutologin = 'https://learn.microsoft.com/microsoftteams/rooms/autopilot-autologin'
        EntraJoin          = 'https://learn.microsoft.com/microsoftteams/rooms/mtrw-entraid-join'
        Licensing          = 'https://learn.microsoft.com/microsoftteams/rooms/rooms-licensing'
        RoomsPlan          = 'https://learn.microsoft.com/microsoftteams/rooms/rooms-plan'
        RoomFinder         = 'https://learn.microsoft.com/outlook/troubleshoot/calendaring/configure-room-finder-rooms-workspaces'
        PlacesFinder       = 'https://learn.microsoft.com/microsoft-365/places/enable-places-finder'
        SetPlaceV3         = 'https://learn.microsoft.com/microsoft-365/places/powershell/set-placev3'
        EwsDeprecation     = 'https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/deprecation-of-ews-exchange-online'
        ReleaseNotes       = 'https://learn.microsoft.com/microsoftteams/rooms/rooms-release-note'
        WindowsUpdates     = 'https://learn.microsoft.com/skypeforbusiness/manage/skype-room-systems-v2/updates'
        TimeZone           = 'https://learn.microsoft.com/exchange/troubleshoot/user-and-shared-mailboxes/incorrect-missing-time-zone-settings'
        DynamicGroups      = 'https://learn.microsoft.com/entra/identity/users/groups-dynamic-membership'
        SecurityDefaults   = 'https://learn.microsoft.com/entra/fundamentals/security-defaults'
        Laps               = 'https://learn.microsoft.com/microsoftteams/rooms/laps-authentication'
        IpPhonePolicy      = 'https://learn.microsoft.com/microsoftteams/devices/teams-android-devices-user-interface'
        RoomsPrep          = 'https://learn.microsoft.com/microsoftteams/rooms/rooms-prep'
        RemoteSignIn       = 'https://learn.microsoft.com/microsoftteams/devices/remote-provision-remote-login'
    }

    ManualChecks = @(
        @{ Area = 'Pro Management Portal'; Check = 'Planning > Resource Accounts: confirm the Secured column (Set as Resource) for every room account.'; Link = 'https://learn.microsoft.com/microsoftteams/rooms/set-as-resource-account-for-shared-teams-devices' }
        @{ Area = 'Pro Management Portal'; Check = 'Planning > Resource Accounts > Migration: review password-less eligibility and migration status. Pilot a few rooms first.'; Link = 'https://learn.microsoft.com/microsoftteams/rooms/passwordlessentraresourceaccounts' }
        @{ Area = 'Pro Management Portal'; Check = 'Planning > Autopilot Devices: confirm each Windows MTR has a resource account assigned for Autologin.'; Link = 'https://learn.microsoft.com/microsoftteams/rooms/autopilot-autologin' }
        @{ Area = 'Teams Admin Center'; Check = 'Teams devices: review health, firmware and Teams app versions for Android rooms, touch consoles and panels (the Graph device API used to report this was retired).'; Link = 'https://learn.microsoft.com/microsoftteams/devices/device-management' }
        @{ Area = 'Logitech Sync'; Check = 'Confirm Logitech firmware is current for Rally Bar / RoomMate / Tap devices; AOSP enrollment and password-less need recent firmware.'; Link = 'https://www.logitech.com/en-us/video-collaboration/sync.html' }
        @{ Area = 'On-prem AD'; Check = 'For synced room accounts: PasswordNeverExpires = True, no fine-grained password policy forcing expiry, "User must change password at next logon" cleared.'; Link = 'https://learn.microsoft.com/microsoftteams/rooms/create-resource-account' }
        @{ Area = 'Entra ID'; Check = 'SSPR: ensure "Require users to register when signing in" does not apply to room accounts (not readable via Graph).'; Link = 'https://learn.microsoft.com/microsoftteams/rooms/conditional-access-and-compliance-for-devices' }
        @{ Area = 'Device'; Check = 'Windows MTRs behind a proxy: password-less migration does not yet support proxied devices; Pro Management agent may need per-user proxy settings.'; Link = 'https://learn.microsoft.com/microsoftteams/rooms/rooms-prep' }
        @{ Area = 'Device'; Check = 'Windows MTR local Admin account: rotate the default password, ideally with Windows LAPS.'; Link = 'https://learn.microsoft.com/microsoftteams/rooms/laps-authentication' }
    )
}
