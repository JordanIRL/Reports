# Identity (ID) checks: account state, password expiry (cloud and synced), sync health, auth methods,
# roles, stale accounts, sign-in failures, tenant settings that interrupt room sign-in, password-less readiness.

function Get-MtrPasswordlessReadiness {
    param([Parameter(Mandatory)]$Account, [Parameter(Mandatory)]$Baseline)
    $v = $Baseline.Versions
    $reasons = [System.Collections.Generic.List[string]]::new()
    $unknown = [System.Collections.Generic.List[string]]::new()
    if (-not $Account.HasMtrLicense -and -not ($Account.IsPanelOnly -and $Account.HasSharedDeviceLicense)) { $reasons.Add('no Teams Rooms license') }
    elseif ($Account.LicenseTier -eq 'Basic') { $reasons.Add('Teams Rooms Pro needed (migration runs from the Pro Management Portal)') }
    elseif ($Account.LicenseTier -eq 'Legacy/Other') { $unknown.Add('confirm the license gives Pro Management Portal access') }

    $devices = @($Account.Devices | Where-Object { $_.Platform -in 'Windows', 'Android' -and -not $_.IsPanel })
    if (-not $devices.Count) { $unknown.Add('no managed device found') }
    foreach ($d in $devices) {
        if ($d.Platform -eq 'Windows') {
            if ($d.JoinType -eq 'hybridAzureADJoined' -or $d.TrustType -eq 'ServerAd') { $reasons.Add("$($d.Name): hybrid joined (Entra join required)") }
            elseif (-not ($d.JoinType -eq 'azureADJoined' -or $d.TrustType -eq 'AzureAd')) { $unknown.Add("$($d.Name): join type unknown") }
            $os = ConvertTo-MtrVersion $d.OsVersion
            if (-not $os) { $unknown.Add("$($d.Name): OS build unknown") }
            elseif ($os -lt (ConvertTo-MtrVersion $v.WindowsMinBuildForPasswordless)) { $reasons.Add("$($d.Name): OS $($d.OsVersion) < $($v.WindowsMinBuildForPasswordless)") }
            $app = ConvertTo-MtrVersion $d.TeamsAppVersion
            if (-not $app) { $unknown.Add("$($d.Name): Teams Rooms app version not reported") }
            elseif ($app -lt (ConvertTo-MtrVersion $v.WindowsAppMinForPasswordless)) { $reasons.Add("$($d.Name): app $($d.TeamsAppVersion) < $($v.WindowsAppMinForPasswordless)") }
        }
        else {
            $os = ConvertTo-MtrVersion $d.OsVersion
            if ($os -and $os.Major -lt [int]$v.AndroidMinOsVersion) { $reasons.Add("$($d.Name): Android $($d.OsVersion) < $($v.AndroidMinOsVersion)") }
            $app = ConvertTo-MtrVersion $d.TeamsAppVersion
            if (-not $app) { $unknown.Add("$($d.Name): Teams app version not reported (check TAC)") }
            elseif ($app -lt (ConvertTo-MtrVersion $v.AndroidAppMinForPasswordless)) { $reasons.Add("$($d.Name): Teams app $($d.TeamsAppVersion) too old") }
            $auth = ConvertTo-MtrVersion $d.AuthenticatorVersion
            if (-not $auth) { $unknown.Add("$($d.Name): Authenticator version not reported") }
            elseif ($auth -lt (ConvertTo-MtrVersion $v.AuthenticatorMinForPasswordless)) { $reasons.Add("$($d.Name): Authenticator $($d.AuthenticatorVersion) too old") }
        }
    }

    $lastAuth = @($Account.SignIns | Where-Object { $_.ErrorCode -in '0', '' } | Sort-Object { ConvertTo-MtrDateTime $_.CreatedDateTime } -Descending | Select-Object -First 1)
    $usesPassword = if ($lastAuth.Count -and (Get-MtrCount $lastAuth[0].AuthMethods)) { [bool](@($lastAuth[0].AuthMethods) -match 'Password').Count } else { $null }

    $status = if ($reasons.Count) { 'Not ready' } elseif ($unknown.Count) { 'Verify' } else { 'Ready' }
    [pscustomobject]@{
        Status       = $status
        Reasons      = Get-MtrArray $reasons
        Unknown      = Get-MtrArray $unknown
        UsesPassword = $usesPassword
        Summary      = if ($reasons.Count) { $reasons -join '; ' } elseif ($unknown.Count) { 'Verify: ' + ($unknown -join '; ') } else { 'Meets visible prerequisites' }
    }
}

function Test-MtrIdentity {
    param([Parameter(Mandatory)]$Model, [Parameter(Mandatory)]$Context, [Parameter(Mandatory)]$Baseline, [Parameter(Mandatory)]$Settings)
    $links = $Baseline.Links
    $mtr = Get-MtrArray $Model.MtrAccounts
    $now = $Settings.Now
    $tenant = $Context.Tenant
    $extra = $Context.Identity.Extra

    # ID-01 UPN must match primary SMTP
    $mismatch = @($mtr | Where-Object { $_.PrimarySmtpAddress -and $_.UserPrincipalName -and $_.PrimarySmtpAddress -ne $_.UserPrincipalName })
    if ($mismatch.Count) {
        $synced = @($mismatch | Where-Object IsSynced).Count
        New-MtrFinding -CheckId 'ID-01' -Severity High -Category 'Identity' -Title 'Room account UPN does not match its primary SMTP address' `
            -Target "$($mismatch.Count) accounts" -AffectedObjects @($mismatch | ForEach-Object { '{0} (SMTP {1})' -f $_.UserPrincipalName, $_.PrimarySmtpAddress }) `
            -Impact 'Microsoft requires the Teams Rooms resource account UPN to match its SMTP address; mismatches cause calendar and sign-in problems.' `
            -Recommendation 'Align UPN and primary SMTP. For synced accounts change the UPN (or primary proxyAddress) on-prem and let sync update Entra/EXO.' `
            -FixLocation $(if ($synced) { 'On-prem AD' } else { 'Entra ID' }) -Reference $links.ResourceAccount `
            -VerifyCommand @($mismatch | Where-Object IsSynced | ForEach-Object { "Get-ADUser -Identity $(ConvertTo-MtrPsLiteral $_.User.onPremisesSamAccountName) -Properties UserPrincipalName,mail,proxyAddresses | Select-Object UserPrincipalName,mail,proxyAddresses" })
    }

    # ID-02 Disabled
    $disabled = @($mtr | Where-Object { -not $_.AccountEnabled })
    if ($disabled.Count) {
        New-MtrFinding -CheckId 'ID-02' -Severity High -Category 'Identity' -Title 'Teams Rooms account is disabled' `
            -Target "$($disabled.Count) accounts" -AffectedObjects @($disabled | ForEach-Object UserPrincipalName) `
            -Impact 'The device cannot sign in.' -Recommendation 'Enable the account (on-prem for synced accounts) or retire the room and its license.' `
            -FixLocation $(if (@($disabled | Where-Object IsSynced).Count) { 'On-prem AD' } else { 'Entra ID' }) `
            -RemediationCommand @($disabled | ForEach-Object { if ($_.IsSynced) { "Enable-ADAccount -Identity $(ConvertTo-MtrPsLiteral $_.User.onPremisesSamAccountName)" } else { "Update-MgUser -UserId $(ConvertTo-MtrPsLiteral $_.Id) -AccountEnabled:`$true" } })
    }

    # ID-03 Password expiry
    if ($tenant) {
        $domains = @{}
        foreach ($d in (Get-MtrArray $tenant.Domains)) { $domains[$d.id.ToLowerInvariant()] = $d }
        $cloudPolicyForSynced = [bool]$tenant.SyncFeatures.cloudPasswordPolicyForPasswordSyncedUsersEnabled
        $cloudAtRisk = [System.Collections.Generic.List[object]]::new()
        $verifyOnPrem = [System.Collections.Generic.List[object]]::new()
        foreach ($a in $mtr) {
            $domain = $domains[[string]$a.UpnDomain.ToLowerInvariant()]
            $policies = [string]$a.User.passwordPolicies
            $neverExpiresInCloud = $policies -match 'DisablePasswordExpiration'
            $validity = if ($domain -and $domain.passwordValidityPeriodInDays) { [int64]$domain.passwordValidityPeriodInDays } else { $null }
            $cloudExpires = $validity -and $validity -lt 2147483647
            $lastChange = ConvertTo-MtrDateTime $a.User.lastPasswordChangeDateTime
            if (-not $a.IsSynced -or $cloudPolicyForSynced) {
                if (-not $neverExpiresInCloud -and $cloudExpires) {
                    $daysLeft = if ($lastChange) { [math]::Floor(($lastChange.AddDays($validity) - $now).TotalDays) } else { $null }
                    $cloudAtRisk.Add([pscustomobject]@{ Account = $a; DaysLeft = $daysLeft })
                }
            }
            if ($a.IsSynced) {
                $federated = $domain -and $domain.authenticationType -eq 'Federated'
                $ageDays = if ($lastChange) { [math]::Floor(($now - $lastChange).TotalDays) } else { $null }
                $expiryErrors = @($a.SignIns | Where-Object { $_.ErrorCode -in '50055', '50133' }).Count
                $estimatedExpiring = $Settings.OnPremMaxPasswordAgeDays -and $null -ne $ageDays -and $ageDays -ge ($Settings.OnPremMaxPasswordAgeDays - $Baseline.Thresholds.PasswordExpiryWarnDays)
                $verifyOnPrem.Add([pscustomobject]@{ Account = $a; Federated = $federated; AgeDays = $ageDays; ExpiryErrors = $expiryErrors; EstimatedExpiring = [bool]$estimatedExpiring })
            }
        }
        if ($cloudAtRisk.Count) {
            $worst = ($cloudAtRisk | Where-Object { $null -ne $_.DaysLeft } | Measure-Object -Property DaysLeft -Minimum).Minimum
            $sev = if ($null -ne $worst -and $worst -lt 0) { 'Critical' } else { 'High' }
            New-MtrFinding -CheckId 'ID-03' -Severity $sev -Category 'Identity' -Title 'Room account passwords expire under the cloud password policy' `
                -Target "$($cloudAtRisk.Count) accounts" `
                -AffectedObjects @($cloudAtRisk | ForEach-Object { '{0} ({1})' -f $_.Account.UserPrincipalName, $(if ($null -eq $_.DaysLeft) { 'expiry unknown' } elseif ($_.DaysLeft -lt 0) { "expired $(-$_.DaysLeft) days ago" } else { "expires in $($_.DaysLeft) days" }) }) `
                -Detail $(if ($cloudPolicyForSynced) { 'The tenant enforces cloud password expiry for password-synced users (CloudPasswordPolicyForPasswordSyncedUsersEnabled), so synced rooms are included.' } else { 'Cloud-only accounts without DisablePasswordExpiration.' }) `
                -Impact 'When the password expires the device signs out and cannot sign back in without someone on site.' `
                -Recommendation 'Set "password never expires" on every Teams Rooms account (a documented requirement for shared Teams devices).' `
                -FixLocation 'Entra ID' -Reference $links.ResourceAccount `
                -RemediationCommand @($cloudAtRisk | ForEach-Object { "Update-MgUser -UserId $(ConvertTo-MtrPsLiteral $_.Account.UserPrincipalName) -PasswordPolicies DisablePasswordExpiration" })
        }
        if ($verifyOnPrem.Count) {
            $escalated = @($verifyOnPrem | Where-Object { $_.ExpiryErrors -or $_.EstimatedExpiring })
            $anyFederated = @($verifyOnPrem | Where-Object Federated).Count -gt 0
            $sev = if ($escalated.Count) { 'High' } elseif ($anyFederated) { 'Medium' } else { 'Low' }
            $samList = @($verifyOnPrem | ForEach-Object { $_.Account.User.onPremisesSamAccountName } | Where-Object { $_ })
            $samLiteral = ($samList | ForEach-Object { ConvertTo-MtrPsLiteral $_ }) -join ','
            New-MtrFinding -CheckId 'ID-04' -Severity $sev -Category 'Identity' -Title 'Verify on-prem "password never expires" for synced room accounts' `
                -Target "$($verifyOnPrem.Count) synced accounts" `
                -AffectedObjects @($verifyOnPrem | ForEach-Object { '{0}{1}{2}{3}' -f $_.Account.UserPrincipalName, $(if ($null -ne $_.AgeDays) { " (password age $($_.AgeDays) d)" }), $(if ($_.Federated) { ' [federated domain]' }), $(if ($_.ExpiryErrors) { ' [password-expired sign-in errors seen]' }) }) `
                -Detail ('These accounts are synced from AD, so password expiry is governed on-prem and cannot be read through Graph. {0}{1}' -f `
                    $(if ($anyFederated) { 'Some UPN domains are federated: an expired on-prem password blocks the room immediately. ' } else { 'With password hash sync the cloud keeps accepting the synced hash, but pass-through authentication or a forced change on-prem will still break the room. ' }),
                    $(if ($escalated.Count) { "$($escalated.Count) account(s) show expiry sign-in errors or exceed the password age you supplied." } else { '' })) `
                -Impact 'An expired password signs the room out until someone re-enters a new password on the device.' `
                -Recommendation 'On-prem: set PasswordNeverExpires, make sure no fine-grained password policy applies, and clear "User must change password at next logon".' `
                -FixLocation 'On-prem AD' -Reference $links.ResourceAccount `
                -VerifyCommand @(
                    "@($samLiteral) | ForEach-Object { Get-ADUser -Identity `$_ -Properties PasswordNeverExpires,PasswordLastSet,pwdLastSet,msDS-UserPasswordExpiryTimeComputed,msDS-ResultantPSO } |",
                    "    Select-Object SamAccountName,PasswordNeverExpires,PasswordLastSet,@{n='MustChangeAtLogon';e={`$_.pwdLastSet -eq 0}},@{n='FineGrainedPolicy';e={`$_.'msDS-ResultantPSO'}}"
                ) `
                -RemediationCommand @($samList | ForEach-Object { "Set-ADUser -Identity $(ConvertTo-MtrPsLiteral $_) -PasswordNeverExpires `$true" })
        }
        if ($tenant.SyncFeatures -and $tenant.SyncFeatures.userForcePasswordChangeOnLogonEnabled -and @($mtr | Where-Object IsSynced).Count) {
            New-MtrFinding -CheckId 'ID-05' -Severity Low -Category 'Identity' -Title 'Forced password change on next logon is synced to the cloud' `
                -Detail 'UserForcePasswordChangeOnLogonEnabled is on: ticking "User must change password at next logon" on-prem also forces the change in Entra ID.' `
                -Impact 'If this flag is set on a room account, the device cannot complete sign-in.' `
                -Recommendation 'Never set "User must change password at next logon" on room accounts (the verify command in ID-04 reports it).' -FixLocation 'On-prem AD'
        }

        # ID-06 Directory sync health
        if ($tenant.OnPremisesSyncEnabled) {
            $lastSync = ConvertTo-MtrDateTime $tenant.OnPremisesLastSyncDateTime
            if ($lastSync -and ($now - $lastSync).TotalHours -gt $Baseline.Thresholds.DirSyncStaleHours) {
                New-MtrFinding -CheckId 'ID-06' -Severity High -Category 'Identity' -Title "Directory synchronization last ran $([math]::Round(($now - $lastSync).TotalHours)) hours ago" `
                    -Impact 'On-prem changes to room accounts and room lists (which are managed in AD) will not reach Microsoft 365.' `
                    -Recommendation 'Check the Entra Connect / Cloud Sync server.' -FixLocation 'On-prem AD'
            }
        }
    }
    $provErrors = @($mtr | Where-Object { (Get-MtrCount $_.User.onPremisesProvisioningErrors) })
    if ($provErrors.Count) {
        New-MtrFinding -CheckId 'ID-07' -Severity High -Category 'Identity' -Title 'Directory sync provisioning errors on room accounts' `
            -AffectedObjects @($provErrors | ForEach-Object { '{0}: {1}' -f $_.UserPrincipalName, ((@($_.User.onPremisesProvisioningErrors) | ForEach-Object { "$($_.propertyCausingError) $($_.category)" }) -join '; ') }) `
            -Impact 'Attribute changes (for example UPN or proxyAddresses) are not being applied.' -Recommendation 'Resolve the duplicate attribute on-prem.' -FixLocation 'On-prem AD'
    }

    # ID-08 Authentication methods on room accounts
    $unexpected = [System.Collections.Generic.List[string]]::new()
    $deviceBound = [System.Collections.Generic.List[string]]::new()
    foreach ($a in $mtr) {
        foreach ($m in (Get-MtrArray $a.AuthMethods)) {
            $type = ([string]$m.Type) -replace '^#microsoft\.graph\.', '' -replace 'AuthenticationMethod$', ''
            if ($type -eq 'password') { continue }
            $label = '{0}: {1}{2}' -f $a.UserPrincipalName, $type, $(if ($m.DisplayName) { " ($($m.DisplayName))" })
            $deviceNames = @($a.Devices | ForEach-Object { $_.Name; $_.Model } | Where-Object { $_ })
            $matchesDevice = $m.DisplayName -and @($deviceNames | Where-Object { $m.DisplayName -like "*$_*" -or $_ -like "*$($m.DisplayName)*" }).Count
            if ($type -in 'windowsHelloForBusiness', 'platformCredential' -or $matchesDevice) { $deviceBound.Add($label) } else { $unexpected.Add($label) }
        }
    }
    if ($unexpected.Count) {
        New-MtrFinding -CheckId 'ID-08' -Severity Medium -Category 'Identity' -Title 'MFA methods registered on Teams Rooms accounts' -AffectedObjects $unexpected `
            -Detail 'Phone, email, Authenticator or OATH methods are registered on shared room accounts.' `
            -Impact 'Someone completed MFA registration as the room (often a technician''s phone). That person can now satisfy MFA for the room account, and registration prompts break device sign-in.' `
            -Recommendation 'Confirm who registered each method, remove it, and exclude room accounts from registration campaigns and SSPR registration. Methods created by password-less migration (device-bound) are expected.' `
            -FixLocation 'Entra ID' -Reference $links.ConditionalAccess
    }
    if ($deviceBound.Count) {
        New-MtrFinding -CheckId 'ID-09' -Severity Info -Category 'Identity' -Title 'Device-bound credentials on room accounts (password-less)' -AffectedObjects $deviceBound `
            -Detail 'These look like device-bound credentials created by password-less migration. After migrating, rotate or scramble the room password.' -Reference $links.Passwordless
    }

    # ID-10 Directory roles
    $roles = @($mtr | Where-Object { (Get-MtrCount $_.DirectoryRoles) -or (Get-MtrCount $_.RoleAssignments) })
    if ($roles.Count) {
        New-MtrFinding -CheckId 'ID-10' -Severity High -Category 'Identity' -Title 'Teams Rooms accounts hold Entra admin roles' `
            -AffectedObjects @($roles | ForEach-Object { '{0}: {1}' -f $_.UserPrincipalName, ((@($_.DirectoryRoles) + @($_.RoleAssignments | ForEach-Object Role) | Sort-Object -Unique) -join ', ') }) `
            -Impact 'A shared device account with a password known to technicians should never be privileged.' `
            -Recommendation 'Remove the role assignments.' -FixLocation 'Entra ID'
    }

    # ID-11 Stale accounts
    $haveActivity = @($mtr | Where-Object { $_.User.PSObject.Properties.Name -contains 'signInActivity' })
    if ($haveActivity.Count) {
        $stale = @($haveActivity | Where-Object { -not $_.LastSignIn -or ($now - $_.LastSignIn).TotalDays -gt $Settings.StaleDays })
        if ($stale.Count) {
            New-MtrFinding -CheckId 'ID-11' -Severity Medium -Category 'Identity' -Title "Teams Rooms accounts with no sign-in for more than $($Settings.StaleDays) days" `
                -Target "$($stale.Count) accounts" -AffectedObjects @($stale | ForEach-Object { '{0} (last {1})' -f $_.UserPrincipalName, $(if ($_.LastSignIn) { $_.LastSignIn.ToString('yyyy-MM-dd') } else { 'never' }) }) `
                -Impact 'The room device is offline, signed out, or signed in with a different account; a license may be wasted.' `
                -Recommendation 'Check the device in Teams Admin Center / Pro Management Portal. Retire unused accounts and reclaim the license.' -FixLocation 'Teams Admin Center'
        }
    }

    # ID-12 Sign-in failures
    $codes = $Baseline.SignInErrorCodes
    $benign = Get-MtrArray $Baseline.BenignSignInErrorCodes
    $failures = @{}
    $caFailures = @{}
    foreach ($a in $mtr) {
        foreach ($s in (Get-MtrArray $a.SignIns)) {
            if (-not $s.ErrorCode -or $s.ErrorCode -eq '0' -or $s.ErrorCode -in $benign) { continue }
            if (-not $failures[$s.ErrorCode]) { $failures[$s.ErrorCode] = @{ Accounts = @{}; Reason = $s.FailureReason; Count = 0 } }
            $failures[$s.ErrorCode].Count++
            $failures[$s.ErrorCode].Accounts[$a.UserPrincipalName] = $true
            foreach ($p in (Get-MtrArray $s.FailedCaPolicies)) {
                if (-not $caFailures[$p.DisplayName]) { $caFailures[$p.DisplayName] = @{} }
                $caFailures[$p.DisplayName][$a.UserPrincipalName] = $true
            }
        }
    }
    foreach ($code in $failures.Keys) {
        $known = Get-MtrPropertyValue $codes $code
        $sev = if ($known) { $known.Severity } else { 'Low' }
        $meaning = if ($known) { $known.Meaning } else { $failures[$code].Reason }
        New-MtrFinding -CheckId 'ID-12' -Severity $sev -Category 'Identity' -Title "Sign-in failures on room accounts: $code - $meaning" `
            -Target "$($failures[$code].Accounts.Count) accounts" -AffectedObjects @($failures[$code].Accounts.Keys) `
            -Detail ("{0} failed sign-ins in the last {1} days. Entra reason: {2}" -f $failures[$code].Count, $Settings.SignInLookbackDays, $failures[$code].Reason) `
            -Recommendation 'Open the Entra sign-in logs for these accounts; the related Conditional Access / password findings usually explain the cause.' -FixLocation 'Entra ID'
    }
    foreach ($policy in $caFailures.Keys) {
        New-MtrFinding -CheckId 'ID-13' -Severity High -Category 'Conditional Access' -Title "Conditional Access policy '$policy' is failing room sign-ins" `
            -AffectedObjects @($caFailures[$policy].Keys) -Detail 'Observed in sign-in logs (appliedConditionalAccessPolicies result = failure).' `
            -Impact 'Rooms are being blocked or challenged by this policy right now.' `
            -Recommendation 'Exclude room accounts from this policy and cover them with a dedicated Teams Rooms policy.' -FixLocation 'Entra ID' -Reference $links.ConditionalAccess
    }

    # Tenant settings that interrupt room sign-in
    if ($extra -and $extra.SecurityDefaults -and $extra.SecurityDefaults.isEnabled) {
        # Critical once rooms exist; with none identified it is a readiness problem, and DISC-00 covers missed rooms.
        New-MtrFinding -CheckId 'ID-14' -Severity $(if ($mtr.Count) { 'Critical' } else { 'Medium' }) -Category 'Identity' -Title 'Security defaults are enabled' `
            -Detail $(if ($mtr.Count) { "Affects all $($mtr.Count) Teams Rooms accounts." } else { 'No Teams Rooms accounts were identified, so nothing is affected yet. This becomes Critical as soon as Teams Rooms sign in to this tenant (or if discovery missed them - see DISC-00).' }) `
            -Impact 'Security defaults require every account to register for and use MFA, which Teams Rooms accounts cannot do; Conditional Access cannot be used alongside them.' `
            -Recommendation 'Replace security defaults with Conditional Access policies, excluding room accounts from user MFA and covering them with a dedicated Teams Rooms policy.' `
            -FixLocation 'Entra ID' -Reference $links.SecurityDefaults
    }
    $campaign = if ($extra -and $extra.AuthMethodsPolicy -and $extra.AuthMethodsPolicy.RegistrationEnforcement) { $extra.AuthMethodsPolicy.RegistrationEnforcement.authenticationMethodsRegistrationCampaign } else { $null }
    if ($campaign -and $campaign.state -in 'enabled', 'default') {
        $excluded = @($campaign.excludeTargets | ForEach-Object id)
        $included = @($campaign.includeTargets | ForEach-Object id)
        $hit = @($mtr | Where-Object {
                $acct = $_
                $in = ($included -contains 'all_users') -or (@($included | Where-Object { $_ -eq $acct.Id -or $_ -in $acct.GroupIds }).Count -gt 0)
                $out = @($excluded | Where-Object { $_ -eq $acct.Id -or $_ -in $acct.GroupIds }).Count -gt 0
                $in -and -not $out
            })
        if ($hit.Count) {
            New-MtrFinding -CheckId 'ID-15' -Severity Medium -Category 'Identity' -Title "Authenticator registration campaign ($($campaign.state)) targets room accounts" `
                -Target "$($hit.Count) accounts" -AffectedObjects @($hit | ForEach-Object UserPrincipalName) `
                -Impact 'Registration prompts during sign-in are not supported on Teams devices and can block sign-in.' `
                -Recommendation 'Add the Teams Rooms group to the campaign exclusions.' -FixLocation 'Entra ID' -Reference $links.ConditionalAccess
        }
    }
    $drp = if ($extra) { $extra.DeviceRegistrationPolicy } else { $null }
    if ($drp) {
        if ($drp.multiFactorAuthConfiguration -eq 'required') {
            New-MtrFinding -CheckId 'ID-16' -Severity High -Category 'Identity' -Title 'MFA is required to register or join devices' `
                -Detail 'Device settings: "Require Multifactor Authentication to register or join devices" is enabled.' `
                -Impact 'Room accounts cannot do MFA, so Android Teams devices cannot register and Windows rooms cannot be Entra-joined with the resource account.' `
                -Recommendation 'Turn the device setting off and, if needed, use a Conditional Access policy on the "Register or join devices" user action that excludes the Teams Rooms group.' -FixLocation 'Entra ID'
        }
        $quota = [int]$drp.userDeviceQuota
        if ($quota -gt 0) {
            $near = @($mtr | Where-Object { $null -ne $_.RegisteredDeviceCount -and $_.RegisteredDeviceCount -ge ($quota - $Baseline.Thresholds.DeviceQuotaWarningMargin) })
            if ($near.Count) {
                New-MtrFinding -CheckId 'ID-17' -Severity Medium -Category 'Identity' -Title "Room accounts near the per-user device limit ($quota)" `
                    -AffectedObjects @($near | ForEach-Object { '{0}: {1} devices' -f $_.UserPrincipalName, $_.RegisteredDeviceCount }) `
                    -Impact 'Rooms re-register on reset or replacement; hitting the limit blocks registration and sign-in.' `
                    -Recommendation 'Delete stale device objects for these accounts.' -FixLocation 'Entra ID'
            }
        }
    }

    # ID-18 Password-less readiness summary
    if ($mtr.Count) {
        $readiness = @($mtr | ForEach-Object { [pscustomobject]@{ Account = $_; R = Get-MtrPasswordlessReadiness -Account $_ -Baseline $Baseline } })
        $ready = @($readiness | Where-Object { $_.R.Status -eq 'Ready' })
        $notReady = @($readiness | Where-Object { $_.R.Status -eq 'Not ready' })
        $verify = @($readiness | Where-Object { $_.R.Status -eq 'Verify' })
        New-MtrFinding -CheckId 'ID-18' -Severity Info -Category 'Identity' -Title "Password-less readiness: $($ready.Count) ready, $($verify.Count) to verify, $($notReady.Count) not ready" `
            -AffectedObjects @($notReady | ForEach-Object { '{0}: {1}' -f $_.Account.UserPrincipalName, $_.R.Summary }) `
            -Detail 'Password-less resource accounts replace the stored password with a device-bound credential (migrated from the Pro Management Portal). Per-room status is in Rooms.csv. App versions are only visible when Intune reports them; confirm in TAC/PMP.' `
            -Recommendation 'Fix the blocking items, pilot the migration on a few rooms from Pro Management Portal > Planning > Resource Accounts > Migration, then rotate the room passwords.' `
            -FixLocation 'Pro Management Portal' -Reference $links.Passwordless
    }
}
