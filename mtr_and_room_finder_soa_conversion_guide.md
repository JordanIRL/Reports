# Microsoft Teams Rooms (MTR) & Room Finder Distribution Lists: Cloud-Only SOA Conversion Guide

**Environment Profile:**
* **Sync Engine:** Microsoft Entra Connect Sync (Supported Version `2.5.76.0+` / `2.5.190.0+` recommended)
* **Authentication Method:** Password Hash Synchronization (PHS)
* **Post-Conversion AD Strategy:** Permanent deletion of on-premises Active Directory objects and cleanup of stale `onPremises*` cloud attributes

---

## 1. Critical Rules & Gotchas to Know

### 1.1 Convert Groups First, Users Second
Once an MTR resource account has its Source of Authority (SOA) converted to Entra ID (`isCloudManaged = true`), it can no longer be added to or managed by any group whose SOA is still on-premises Active Directory. You **must** convert your Room Finder distribution lists (`RoomList`)—and any other synced security or distribution groups the MTR accounts belong to—to cloud-managed **before** converting the MTR user accounts.

### 1.2 Room Lists Remain Managed in Exchange Online (Not the Entra Portal)
When you convert a synced mail-enabled distribution list (`RoomList`) to `isCloudManaged = true`, its source changes to **Cloud** in Entra ID. However, because distribution lists are Exchange Online objects, their properties and memberships remain **read-only** in the Microsoft Entra admin center and Microsoft Graph. After SOA conversion, all modifications (adding/removing rooms, updating SMTP aliases, or changing owners) must be performed via **Exchange Online PowerShell** (`Set-DistributionGroup`, `Add-DistributionGroupMember`) or the **Exchange Admin Center (EAC)**.

### 1.3 Zero-Downtime MTR Sign-In (The PHS Advantage)
Because you use Password Hash Synchronization (PHS), Entra ID already stores the synchronized password hash for each MTR resource account. Setting `isCloudManaged = true` and subsequently deleting the on-premises AD user **will not** invalidate existing Entra refresh tokens or reset password hashes. Your physical MTR consoles and compute units will remain signed in throughout the cutover.

### 1.4 The "Premature AD Deletion" Trap (`blockOnPremisesSync`)
**Never delete the on-premises AD user or group immediately after running the Graph SOA conversion command.**
* When you set `isCloudManaged = true` via Microsoft Graph, the change occurs in Entra ID first. Your local Entra Connect Sync server does not know the object is cloud-managed until it runs an import cycle and stamps `blockOnPremisesSync = true` onto the object inside the **Microsoft Entra ID Connector Space**.
* If you delete the AD object *before* Entra Connect pulls down `blockOnPremisesSync = true`, Entra Connect will treat the AD deletion as authoritative and move your MTR account and Room List into the Entra ID recycle bin (Deleted Users).

### 1.5 Collateral Group Membership Loss on AD Deletion
Before deleting an MTR user in Active Directory, inspect its `memberOf` attribute in AD.
* If the MTR account is still a member of **any** group that remains AD-synced (`isCloudManaged = false`)—such as an AD-synced Intune configuration group, Conditional Access exclusion group, or licensing group—deleting the user in AD removes its Distinguished Name from that AD group.
* On the next sync cycle, Entra Connect will synchronize that group's updated membership list and **remove your cloud MTR account from the group in Entra ID**. Either convert those groups to cloud-managed first or migrate the MTR accounts into cloud-native groups before deleting the AD user.

### 1.6 Entra Connect Version Nuance (`2.5.190.0+` Recommended)
While Entra Connect `2.5.76.0` is the minimum version that supports `isCloudManaged`, if you have **Exchange Hybrid writeback** enabled in Entra Connect, verify you are running version **`2.5.190.0` or later**. Earlier `2.5.x` builds contained a known issue where Entra Connect attempted to write cloud Exchange attribute changes back to AD on `isCloudManaged` objects, resulting in export errors.

### 1.7 `isCloudManaged` vs. `IsExchangeCloudManaged`
* Setting `isCloudManaged = true` via Microsoft Graph transfers the **entire object SOA** (both Entra ID identity attributes and Exchange Online attributes) to the cloud.
* Setting `Set-Mailbox -IsExchangeCloudManaged $true` in Exchange Online PowerShell only transfers **Exchange attributes** while leaving the identity synced from AD. Because your goal is full cloud-only management and on-premises AD object deletion, always use the Microsoft Graph `isCloudManaged` method.

### 1.8 Clearing Stale `onPremises*` Attributes After AD Deletion
After you convert an MTR user's SOA and delete the on-premises AD account, the Entra ID user object becomes cloud-managed (`OnPremisesSyncEnabled : $null`), **but** it still retains seven historical `onPremises*` attributes (`onPremisesImmutableId`, `onPremisesSecurityIdentifier`, `onPremisesDistinguishedName`, `onPremisesDomainName`, `onPremisesSamAccountName`, `onPremisesUserPrincipalName`, and `onPremisesObjectIdentifier`). Clear these attributes via Microsoft Graph Beta after deleting the AD object so the MTR account is identical to a cloud-born account and can never accidentally soft-match or hard-match against a future AD object.

---

## 2. Pre-Flight Checklist

| Check Area | Requirement / Action |
| :--- | :--- |
| **Sync Engine Version** | **Microsoft Entra Connect Sync:** Version `2.5.76.0` minimum (`2.5.190.0+` recommended if Exchange Hybrid writeback is enabled). |
| **Admin Roles Required** | **Hybrid Identity Administrator** (least-privileged role to read/write SOA).<br>**Application Administrator** or **Cloud Application Administrator** (required once to grant admin consent to the Graph permissions).<br>**Exchange Administrator** (to verify and manage `RoomList` and `RoomMailbox` objects in Exchange Online). |
| **Microsoft Graph Scopes** | `Group-OnPremisesSyncBehavior.ReadWrite.All`, `User-OnPremisesSyncBehavior.ReadWrite.All`, `Group.ReadWrite.All`, and `User.ReadWrite.All`. |
| **AD Group Scope** | All on-premises `RoomList` distribution groups must be set to **Universal** group scope in Active Directory before conversion. |
| **MTR Mailbox Location** | Verify all MTR resource mailboxes are already hosted in **Exchange Online** (`RoomMailbox`), not on an on-premises Exchange server. |
| **Network / 802.1X Dependencies** | Confirm your MTR devices do not use their AD user credentials for on-premises RADIUS/NPS 802.1X network authentication or on-premises Skype for Business voice routing. |
| **Group Memberships Audit** | Document all on-premises groups the MTR accounts belong to (Conditional Access groups, Intune policy groups, licensing groups). Either convert those groups' SOA first or migrate those assignments to cloud-native groups. |

---

## 3. Pilot Testing Matrix

Perform the conversion on **one test Room List** and **one test MTR account** first, and validate the following before executing in bulk:

1. **Entra ID & Exchange Sync State:** Confirm `onPremisesSyncEnabled` changes from `True` to `null` in Entra ID, and `IsDirSynced` changes to `False` in Exchange Online.
2. **MTR Device Health & Sign-In:** Reboot the pilot MTR device after AD deletion and confirm it signs back into Microsoft Teams, loads its calendar, and shows as **Healthy** in the Teams Admin Center and Microsoft Teams Rooms Pro Management portal.
3. **Cloud Attribute Editing:**
   * Modify an identity property on the MTR account in Entra ID (such as `OfficeLocation` or `JobTitle`).
   * Modify an Exchange property in Exchange Online PowerShell (`Set-CalendarProcessing` or `Set-Place` capacity/building tags).
   * Add and remove a test room from the converted `RoomList` via `Add-DistributionGroupMember` / `Remove-DistributionGroupMember` in Exchange Online PowerShell.
4. **Room Finder & Microsoft Places Visibility:** Open Outlook (Web or New Outlook) and Teams Calendar, launch **Room Finder**, select the pilot building/Room List, and confirm the pilot room appears with accurate capacity and availability.
5. **End-to-End Calendar Booking:** Book a Teams meeting inviting the pilot MTR, verify the room auto-accepts the invite (`AutomateProcessing : AutoAccept`), and join the meeting from the physical MTR console.

---

## 4. Step-by-Step Guide (SOA Conversion + AD Deletion)

### Step 1: Audit On-Premises Group Memberships and Export Baseline Backups
Prevent accidental removal from synced policy or licensing groups when AD objects are deleted, and create a complete rollback snapshot.

1. On a machine with the Active Directory PowerShell module, check the Entra Connect version and list all AD groups your target MTR account belongs to:
   ```powershell
   # Run on Entra Connect Server to verify version (2.5.76.0+ required, 2.5.190.0+ recommended)
   (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Azure AD Connect").Version

   # Check all AD group memberships for the pilot MTR account
   $MtrSamAccountName = "mtr-confroom1"
   Get-ADPrincipalGroupMembership -Identity $MtrSamAccountName |
       Select-Object Name, GroupScope, GroupCategory, DistinguishedName
   ```
   *Action:* Any group listed here (other than `Domain Users` and the `RoomList` you are converting) that is synced to Entra ID will drop the MTR account when you delete the AD user. Replace any AD-synced licensing, Intune, or Conditional Access group memberships with cloud-native Entra groups before proceeding.

2. Check that your target `RoomList` distribution group is set to **Universal** scope in Active Directory. If it is `Global` or `DomainLocal`, convert it to `Universal` and wait for a delta sync before continuing:
   ```powershell
   Get-ADGroup -Identity "bldg1-rooms" | Select-Object Name, GroupScope, GroupCategory
   # If not Universal, run:
   # Set-ADGroup -Identity "bldg1-rooms" -GroupScope Universal
   ```

3. Connect to Exchange Online PowerShell and export a baseline backup of all Room Lists and MTR mailboxes:
   ```powershell
   Connect-ExchangeOnline

   # Export all RoomLists and their current members
   $RoomLists = Get-DistributionGroup -RecipientTypeDetails RoomList
   $RoomLists | Select-Object DisplayName,PrimarySmtpAddress,ExternalDirectoryObjectId,IsDirSynced |
       Export-Csv -Path ".\RoomLists_Baseline.csv" -NoTypeInformation

   foreach ($List in $RoomLists) {
       Get-DistributionGroupMember -Identity $List.PrimarySmtpAddress |
           Select-Object @{N="RoomList";E={$List.PrimarySmtpAddress}}, Name, PrimarySmtpAddress, ExternalDirectoryObjectId |
           Export-Csv -Path ".\RoomListMembers_Baseline.csv" -NoTypeInformation -Append
   }

   # Export all Room Mailboxes, CalendarProcessing, and Place properties
   $Rooms = Get-Mailbox -RecipientTypeDetails RoomMailbox
   $Rooms | Select-Object DisplayName,UserPrincipalName,ExternalDirectoryObjectId,IsDirSynced,EmailAddresses |
       Export-Csv -Path ".\Rooms_Mailbox_Baseline.csv" -NoTypeInformation

   $Rooms | ForEach-Object { Get-CalendarProcessing -Identity $_.UserPrincipalName } |
       Export-Clixml -Path ".\Rooms_CalendarProcessing_Baseline.xml"

   $Rooms | ForEach-Object { Get-Place -Identity $_.UserPrincipalName } |
       Export-Clixml -Path ".\Rooms_Place_Baseline.xml"
   ```

---

### Step 2: Connect to Microsoft Graph with SOA Permissions
Requires the **Hybrid Identity Administrator** role; initial consent requires **Application Administrator** or **Cloud Application Administrator**.

1. Open **PowerShell 7** (`pwsh`) and connect to Microsoft Graph with the required user and group SOA scopes:
   ```powershell
   Connect-MgGraph -Scopes "Group-OnPremisesSyncBehavior.ReadWrite.All", "User-OnPremisesSyncBehavior.ReadWrite.All", "Group.ReadWrite.All", "User.ReadWrite.All"
   ```
2. Complete the browser sign-in prompt and accept the permissions consent prompt.
3. Verify that all four scopes are active in your session:
   ```powershell
   (Get-MgContext).Scopes
   ```

---

### Step 3: Convert the Room Finder Distribution List SOA to Entra ID
Always convert groups before converting the MTR user accounts.

1. Look up the Entra ID Object ID of your target `RoomList` distribution group and verify its current sync behavior:
   ```powershell
   $RoomListMail = "bldg1-rooms@yourdomain.com"
   $Group = Get-MgGroup -Filter "mail eq '$RoomListMail'" -Property Id,DisplayName,OnPremisesSyncEnabled
   $GroupId = $Group.Id

   # Verify current state (Expected: OnPremisesSyncEnabled = True, isCloudManaged = False)
   $Group | Select-Object Id, DisplayName, OnPremisesSyncEnabled
   Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/onPremisesSyncBehavior?`$select=isCloudManaged"
   ```
2. Convert the `RoomList` group's SOA to Entra ID:
   ```powershell
   $Body = @{ isCloudManaged = $true } | ConvertTo-Json
   Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/onPremisesSyncBehavior" -Body $Body -ContentType "application/json"
   ```
3. Verify the group SOA conversion succeeded in Entra ID:
   ```powershell
   Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/onPremisesSyncBehavior?`$select=isCloudManaged"
   Get-MgGroup -GroupId $GroupId -Property Id,DisplayName,OnPremisesSyncEnabled | Select-Object DisplayName,OnPremisesSyncEnabled
   ```
   *Expected result:* `isCloudManaged` is `True` and `OnPremisesSyncEnabled` is blank (`$null`).

---

### Step 4: Convert the MTR Resource Account SOA to Entra ID
Transfers identity and Exchange Online mailbox SOA while keeping the PHS password hash intact.

1. Retrieve the Entra ID Object ID of your pilot MTR account and inspect its current state:
   ```powershell
   $MtrUpn = "mtr-confroom1@yourdomain.com"
   $User = Get-MgUser -UserId $MtrUpn -Property Id,DisplayName,UserPrincipalName,OnPremisesSyncEnabled
   $UserId = $User.Id

   # Verify current state (Expected: OnPremisesSyncEnabled = True, isCloudManaged = False)
   $User | Select-Object Id, UserPrincipalName, OnPremisesSyncEnabled
   Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId/onPremisesSyncBehavior?`$select=isCloudManaged"
   ```
2. Convert the MTR user account's SOA to Entra ID:
   ```powershell
   $Body = @{ isCloudManaged = $true } | ConvertTo-Json
   Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$UserId/onPremisesSyncBehavior" -Body $Body -ContentType "application/json"
   ```
3. Verify the user SOA conversion succeeded in Entra ID:
   ```powershell
   Invoke-MgGraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/users/$UserId/onPremisesSyncBehavior?`$select=isCloudManaged"
   Get-MgUser -UserId $UserId -Property UserPrincipalName,OnPremisesSyncEnabled | Select-Object UserPrincipalName,OnPremisesSyncEnabled
   ```
   *Expected result:* `isCloudManaged` is `True` and `OnPremisesSyncEnabled` is blank (`$null`).

---

### Step 5: Run Entra Connect Delta Sync and Verify Connector Space State
**CRITICAL:** Do not delete the AD objects until `blockOnPremisesSync` equals `true` in Synchronization Service Manager.

1. Sign in to your **Microsoft Entra Connect Sync** server, open PowerShell as Administrator, and trigger a delta synchronization cycle:
   ```powershell
   Start-ADSyncSyncCycle -PolicyType Delta
   ```
2. Open **Synchronization Service Manager** (`miisclient.exe`) on the Entra Connect server and wait for the **Delta Import**, **Delta Synchronization**, and **Export** operations to show `success`.
3. Confirm the Entra Connect engine has registered the SOA block for **both** the group and the MTR user before you touch Active Directory:
   * Select the **Connectors** tab at the top.
   * Right-click the **Microsoft Entra ID** connector (named `tenant.onmicrosoft.com - AAD`) and select **Search Connector Space**.
   * Set the **Scope** dropdown to **RDN** (or **DN or anchor**), search for the object, double-click it, and view the **Attributes** tab.
   * Confirm that the **`blockOnPremisesSync`** attribute is present and its value is **`true`** for both the Room List group and the MTR user.

---

### Step 6: Verify Exchange Online Cloud Management
Wait 5 to 15 minutes for Entra-to-Exchange forward sync to complete.

1. In your Exchange Online PowerShell session, verify that `IsDirSynced` has changed to `False` on both the `RoomList` distribution group and the MTR `RoomMailbox`:
   ```powershell
   Get-DistributionGroup -Identity "bldg1-rooms@yourdomain.com" |
       Format-List DisplayName, RecipientTypeDetails, IsDirSynced

   Get-Mailbox -Identity "mtr-confroom1@yourdomain.com" |
       Format-List DisplayName, RecipientTypeDetails, IsDirSynced, IsExchangeCloudManaged
   ```
2. Perform a test write against both objects in Exchange Online PowerShell to confirm full cloud authority:
   ```powershell
   # Test modifying the RoomList in Exchange Online
   Set-DistributionGroup -Identity "bldg1-rooms@yourdomain.com" -HiddenFromAddressListsEnabled $false

   # Test modifying the MTR Place metadata in Exchange Online
   Set-Place -Identity "mtr-confroom1@yourdomain.com" -DisplayDeviceName "Teams Room Panel"
   ```
   *Expected result:* Both commands execute cleanly without any on-premises directory sync restriction errors.

---

### Step 7: Delete the On-Premises Active Directory Objects and Sync
Safe to execute **only** after Step 5 and Step 6 pass verification.

1. On your Active Directory domain controller or admin workstation, remove accidental deletion protection (if enabled) and delete the on-premises `RoomList` group and MTR user account:
   ```powershell
   # Remove protection from accidental deletion and delete the on-premises RoomList group
   Get-ADGroup -Identity "bldg1-rooms" | Set-ADObject -ProtectedFromAccidentalDeletion $false
   Remove-ADGroup -Identity "bldg1-rooms" -Confirm:$false

   # Remove protection from accidental deletion and delete the on-premises MTR user
   Get-ADUser -Identity "mtr-confroom1" | Set-ADObject -ProtectedFromAccidentalDeletion $false
   Remove-ADUser -Identity "mtr-confroom1" -Confirm:$false
   ```
2. On your **Microsoft Entra Connect Sync** server, run another delta sync cycle so Entra Connect processes the local AD deletions:
   ```powershell
   Start-ADSyncSyncCycle -PolicyType Delta
   ```
3. Verify in Microsoft Graph PowerShell that the cloud MTR user and Room List remain active (not in Deleted Items) and in Exchange Online that the room is still a member of the Room List:
   ```powershell
   Get-MgUser -UserId $UserId | Select-Object DisplayName, UserPrincipalName, AccountEnabled
   Get-MgGroup -GroupId $GroupId | Select-Object DisplayName, Mail
   Get-DistributionGroupMember -Identity "bldg1-rooms@yourdomain.com" | Select-Object Name, PrimarySmtpAddress
   ```

---

### Step 8: Clear Stale On-Premises Attributes from the MTR Account in Entra ID
Removes leftover AD identifiers (`ImmutableId`, `SID`, `DN`, `SAMAccountName`) so the MTR account is 100% cloud-native.

1. In your **PowerShell 7** Microsoft Graph session, inspect the leftover on-premises attributes still stamped on the cloud MTR user:
   ```powershell
   $OnPremProps = @(
       "Id", "UserPrincipalName", "OnPremisesDistinguishedName", "OnPremisesDomainName",
       "OnPremisesImmutableId", "OnPremisesObjectIdentifier", "OnPremisesSamAccountName",
       "OnPremisesSecurityIdentifier", "OnPremisesUserPrincipalName"
   )
   Get-MgUser -UserId $UserId -Property $OnPremProps | Format-List $OnPremProps
   ```
2. Send a `PATCH` request to the Microsoft Graph `beta` endpoint to set all seven `onPremises*` properties to `$null`:
   ```powershell
   $ClearOnPremBody = @{
       onPremisesDistinguishedName  = $null
       onPremisesDomainName         = $null
       onPremisesImmutableId        = $null
       onPremisesObjectIdentifier   = $null
       onPremisesSamAccountName     = $null
       onPremisesSecurityIdentifier = $null
       onPremisesUserPrincipalName  = $null
   } | ConvertTo-Json

   Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/users/$UserId" -Body $ClearOnPremBody -ContentType "application/json"
   ```
   *(Note: Alternatively, if you have the `ADSyncTools` module version `2.5.0+` installed, you can run `Clear-ADSyncToolsOnPremisesAttribute -Id $UserId -All -Verbose`.)*

3. Re-run the `Get-MgUser` verification command from sub-step 1 above:
   ```powershell
   Get-MgUser -UserId $UserId -Property $OnPremProps | Format-List $OnPremProps
   ```
   *Expected result:* All seven `OnPremises*` attributes now return empty (`$null`), completing the conversion to a pure cloud-only identity.

---

## 5. Rollback Procedure (If Needed Before AD Deletion)

If you encounter an unexpected issue during pilot testing **before** deleting the on-premises AD objects and clearing the `onPremises*` attributes, you can revert the SOA back to on-premises Active Directory:

1. **Revert the MTR User Account First (Users before Groups when rolling back):**
   ```powershell
   $RevertBody = @{ isCloudManaged = $false } | ConvertTo-Json
   Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$UserId/onPremisesSyncBehavior" -Body $RevertBody -ContentType "application/json"
   ```
2. **Revert the RoomList Group Second:**
   ```powershell
   $RevertBody = @{ isCloudManaged = $false } | ConvertTo-Json
   Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/onPremisesSyncBehavior" -Body $RevertBody -ContentType "application/json"
   ```
3. **Run an Entra Connect Delta Sync:**
   ```powershell
   Start-ADSyncSyncCycle -PolicyType Delta
   ```

---

## 6. Bonus: Bulk SOA Conversion & Cleanup PowerShell Script

Once your pilot passes all checks in Section 3, you can use this two-phase PowerShell 7 script to convert your remaining Room Lists and MTR accounts in bulk.

```powershell
<#
.SYNOPSIS
    Bulk SOA Conversion Script for RoomList Distribution Groups and MTR Accounts.
.DESCRIPTION
    Phase 1 converts RoomLists and MTR users to isCloudManaged = $true.
    Wait for Entra Connect Delta Sync (blockOnPremisesSync = true) and AD deletion before running Phase 2.
    Phase 2 clears the stale onPremises* attributes from converted MTR users.
#>

# ==============================================================================
# CONFIGURATION: Define your target RoomLists and MTR UPNs
# ==============================================================================
$RoomListEmails = @(
    "bldg1-rooms@yourdomain.com",
    "bldg2-rooms@yourdomain.com"
)

$MtrUserUpns = @(
    "mtr-confroom1@yourdomain.com",
    "mtr-confroom2@yourdomain.com",
    "mtr-boardroom1@yourdomain.com"
)

Connect-MgGraph -Scopes "Group-OnPremisesSyncBehavior.ReadWrite.All", "User-OnPremisesSyncBehavior.ReadWrite.All", "Group.ReadWrite.All", "User.ReadWrite.All"

# ==============================================================================
# PHASE 1A: Convert RoomList Groups to Cloud-Managed
# ==============================================================================
$SoaBody = @{ isCloudManaged = $true } | ConvertTo-Json

foreach ($Mail in $RoomListEmails) {
    $Group = Get-MgGroup -Filter "mail eq '$Mail'" -Property Id,DisplayName,OnPremisesSyncEnabled
    if ($null -ne $Group) {
        Write-Host "Converting RoomList SOA: $($Group.DisplayName) ($Mail)..." -ForegroundColor Cyan
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/groups/$($Group.Id)/onPremisesSyncBehavior" -Body $SoaBody -ContentType "application/json"
    } else {
        Write-Warning "RoomList not found for mail: $Mail"
    }
}

# ==============================================================================
# PHASE 1B: Convert MTR Resource Accounts to Cloud-Managed
# ==============================================================================
foreach ($Upn in $MtrUserUpns) {
    try {
        $User = Get-MgUser -UserId $Upn -Property Id,DisplayName,UserPrincipalName,OnPremisesSyncEnabled -ErrorAction Stop
        Write-Host "Converting MTR User SOA: $($User.UserPrincipalName)..." -ForegroundColor Cyan
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/v1.0/users/$($User.Id)/onPremisesSyncBehavior" -Body $SoaBody -ContentType "application/json"
    } catch {
        Write-Warning "MTR User not found or error occurred for: $Upn - $_"
    }
}

Write-Host "`nSTOP HERE BEFORE PHASE 2:" -ForegroundColor Yellow
Write-Host "1. Run 'Start-ADSyncSyncCycle -PolicyType Delta' on your Entra Connect server." -ForegroundColor Yellow
Write-Host "2. Confirm 'blockOnPremisesSync = true' in Synchronization Service Manager." -ForegroundColor Yellow
Write-Host "3. Delete the corresponding AD groups and AD user objects, then run another Delta Sync." -ForegroundColor Yellow

# ==============================================================================
# PHASE 2: Clear Stale On-Premises Attributes (Run ONLY after AD Deletion & Sync)
# ==============================================================================
<# Uncomment and run this block after AD objects are deleted and synced:

$ClearOnPremBody = @{
    onPremisesDistinguishedName  = $null
    onPremisesDomainName         = $null
    onPremisesImmutableId        = $null
    onPremisesObjectIdentifier   = $null
    onPremisesSamAccountName     = $null
    onPremisesSecurityIdentifier = $null
    onPremisesUserPrincipalName  = $null
} | ConvertTo-Json

foreach ($Upn in $MtrUserUpns) {
    try {
        $User = Get-MgUser -UserId $Upn -Property Id,UserPrincipalName -ErrorAction Stop
        Write-Host "Clearing stale onPremises attributes for: $($User.UserPrincipalName)..." -ForegroundColor Green
        Invoke-MgGraphRequest -Method PATCH -Uri "https://graph.microsoft.com/beta/users/$($User.Id)" -Body $ClearOnPremBody -ContentType "application/json"
    } catch {
        Write-Warning "Failed to clear onPremises attributes for: $Upn - $_"
    }
}
#>
```