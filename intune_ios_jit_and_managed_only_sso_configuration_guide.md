# Intune iOS Configuration Guide: Supervised iPhones with JIT Registration & Managed-App-Only Seamless SSO

This guide provides the end-to-end configuration templates for Supervised iPhones enrolled via **Automated Device Enrollment (ADE)** with **User Affinity**, **Just-in-Time (JIT) registration**, and **Microsoft Enterprise SSO** restricted strictly to Intune-managed apps with automatic sign-in.

---

## 1. Prerequisites & Enrollment Baseline

Before applying the SSO and App Configuration policies, ensure your baseline enrollment environment meets these requirements:

1. **ADE Enrollment Profile:**
   * **Enroll with User Affinity** must be selected.
   * **Authentication method** must be set to **Setup Assistant with modern authentication**.
2. **Microsoft Authenticator Deployment:**
   * Sync **Microsoft Authenticator** via Apple Business Manager (VPP) and assign it as **Required** (Device licensing) to your target group so it installs automatically during enrollment.
3. **Do Not Push Company Portal as Required:**
   * With JIT registration and Setup Assistant with modern authentication, the Intune Company Portal app is not needed for device registration and can cause conflicting sign-in prompts if pushed alongside Authenticator.
4. **Active iOS Compliance Policy:**
   * Ensure at least one **iOS/iPadOS Compliance Policy** is assigned to the target user or device group. JIT compliance checks will loop or fail if no compliance policy is assigned.
5. **All Target Apps Deployed as Managed VPP Apps:**
   * Both the `Enable_SSO_On_All_ManagedApps` flag and the **Managed devices** App Configuration channel require apps to be installed via Intune as managed (ideally VPP) apps.

---

## 2. Device Configuration Profile: SSO App Extension (JIT + Auto-Login)

JIT registration and the Microsoft Enterprise SSO plug-in are configured in a **Device Configuration Profile**.

### Navigation Path
1. Sign in to the **Microsoft Intune admin center**.
2. Go to **Devices → iOS/iPadOS → Configuration → Create → New policy**.
3. Set **Profile type** to **Templates**, select **Device features**, and click **Create**.
4. Name the profile (e.g., `iOS - Entra SSO Extension & JIT - Managed Apps Only`), click **Next**, and select **Single sign-on app extension**.

### Base Settings
* **SSO app extension type:** `Microsoft Entra ID`
* **Enable shared device mode:** `Not configured` *(Must remain unconfigured for User Affinity devices)*
* **App bundle ID:** Leave ** completely blank** *(Do not list `com.microsoft.authenticator` or Microsoft 365 bundle IDs here, as doing so breaks MSAL token brokering and JIT).*

### Additional Configuration (Key-Value Pairs)
> **Critical:** Ensure there are **no leading or trailing spaces** when copying and pasting keys or values. A single trailing space in `{{DEVICEREGISTRATION}}` will silently break JIT registration.

| Key | Type | Value | Purpose |
| :--- | :--- | :--- | :--- |
| `device_registration` | String | `{{DEVICEREGISTRATION}}` | Triggers JIT registration via Microsoft Authenticator. |
| `Enable_SSO_On_All_ManagedApps` | Integer | `1` | Automatically enables the SSO extension for all MDM-managed apps pushed via Intune without needing an explicit bundle ID allowlist. |
| `AppBlockList` | String | `com.apple.mobilesafari` | Blocks standalone Safari from using SSO so users cannot auto-sign in to unmanaged web sessions. *(Leaves `com.apple.SafariViewService` unblocked so embedded in-app webviews still work).* |
| `browser_sso_interaction_enabled` | Integer | `1` | Enables SSO bootstrap for Conditional Access and in-app webviews. |
| `disable_explicit_app_prompt` | Integer | `1` | Suppresses redundant sign-in prompts on apps requesting protocol-level authentication. |
| `disable_explicit_app_prompt_and_autologin` | Integer | `1` | Bypasses the account picker and **automatically signs the user in** when a single Entra ID session exists on the device. |

> **Note on `disable_explicit_native_app_prompt`:** Do **not** add `disable_explicit_native_app_prompt` if you use Intune App Protection Policies (MAM), as it conflicts with MAM enforcement on MSAL apps.

---

## 3. Managed App Configuration Policy (Microsoft 365 & Intune SDK Apps)

To pass the enrolled user's identity directly to managed apps, suppress personal account sign-ins, and automatically bind the user's account, create a **Managed devices** App Configuration Policy.

### Navigation Path
1. In the **Microsoft Intune admin center**, go to **Apps → Manage apps → Configuration → Create → Managed devices**.
2. Name the policy (e.g., `iOS - M365 Managed App Auto-Sign-In`), set **Platform** to `iOS/iPadOS`, and select your target managed VPP app (e.g., Microsoft Outlook, Teams, OneDrive, Edge).
3. Click **Next** and choose **Enter XML data** for the **Configuration settings format**.

### XML Configuration Payload

```xml
<dict>
  <key>IntuneMAMUPN</key>
  <string>{{userprincipalname}}</string>
  <key>IntuneMAMOID</key>
  <string>{{userid}}</string>
  <key>IntuneMAMDeviceID</key>
  <string>{{deviceID}}</string>
  <key>IntuneMAMAllowedAccountsOnly</key>
  <string>Enabled</string>
  <key>IntuneMAMRequireAccounts</key>
  <string>Enabled</string>
</dict>
```

### Key Reference
* **`IntuneMAMUPN` (`{{userprincipalname}}`):** Pre-populates the user's Entra ID UPN from the enrollment record.
* **`IntuneMAMOID` (`{{userid}}`):** Passes the user's Entra Object ID to ensure accurate account matching and MAM policy binding.
* **`IntuneMAMDeviceID` (`{{deviceID}}`):** Passes the Intune Device ID so M365 and Intune SDK apps immediately recognize the device as MDM-managed.
* **`IntuneMAMAllowedAccountsOnly` (`Enabled`):** Blocks users from adding personal accounts (e.g., personal Gmail or Outlook.com) inside the managed app.
* **`IntuneMAMRequireAccounts` (`Enabled`):** Enforces automatic sign-in with the organizational account defined by `IntuneMAMUPN`.

---

## 4. Blocking Unmanaged Apps from Using MSAL Broker SSO

Because apps built with the Microsoft Authentication Library (MSAL) communicate directly with the Microsoft Authenticator broker on iOS, an unmanaged MSAL app downloaded from the personal Apple App Store can still request a token from Authenticator even when `Enable_SSO_On_All_ManagedApps` is configured.

To ensure **only** managed apps can authenticate, enforce one or both of the following controls:

### Option A: Restrict Unmanaged App Installations (Supervised Device Restrictions)
* In your **iOS Device Restrictions** profile, block access to the personal App Store (or require VPP-only installations) so users can only install apps provided via Intune.

### Option B: Enforce Conditional Access + App Protection Policies
1. Create an **iOS App Protection Policy** targeting your organization's apps.
2. Create a **Microsoft Entra Conditional Access Policy** targeting **All cloud apps** on the **iOS** platform.
3. Under **Grant** controls, select **Require device to be marked as compliant** AND **Require app protection policy**.
   * Unmanaged apps lacking the Intune MDM App Configuration payload will fail the grant check and be blocked from receiving tokens.

---

## 5. Expected User Experience & Verification Checklist

### Expected Sign-In Flow
1. **ADE Setup Assistant:** The user signs in once with their Entra ID credentials during the initial iPhone setup screen.
2. **First Managed App Launch:** When the user opens their first managed app (e.g., Outlook), JIT registration triggers silently via the SSO extension and prompts for MFA once to register the device and seed the Primary Refresh Token (PRT) in the iPhone's Secure Enclave.
3. **Subsequent Managed Apps:** Every other managed app reads `IntuneMAMUPN` and the shared SSO token. Depending on the app's UI, it either signs in with zero touches or presents a pre-selected account requiring a single tap on **Continue**—with zero email, password, or MFA prompts.
4. **Unmanaged Safari Sessions:** Opening standalone Safari and browsing to `portal.office.com` will **not** trigger automatic SSO.

### Verification & Troubleshooting Steps
* **Verify SSO Payload Delivery on the iPhone:**
  Go to **Settings → General → VPN & Device Management → Management Profile → More Details** and confirm **Single Sign-On Extensions** is listed.
* **Verify JIT Registration Inside Authenticator:**
  Open **Microsoft Authenticator**, tap the menu icon (top-left) → **Settings → Device Registration**, and confirm the device shows as registered to your tenant.
* **Verify App Configuration Delivery in Intune:**
  In the Intune admin center, go to **Devices → iOS/iPadOS → [Select Device] → App configuration** and verify the policy status shows **Succeeded**.
* **Inspect Local MAM/AppConfig Logs on the Device:**
  Open **Microsoft Edge** on the iPhone, navigate to `about:intunehelp`, tap **Get Started → Share Logs**, and inspect `IntuneMAMDiagnostics.txt` under the `AppConfig` section to confirm `IntuneMAMUPN` and `IntuneMAMAllowedAccountsOnly` were applied locally.