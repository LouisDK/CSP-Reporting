# Creating and Configuring a Multi-Tenant App Registration for CSP Reporting

This guide walks through the process of creating and configuring an Azure AD App Registration for the CSP Reporting solution. The App Registration is a critical component that enables secure, automated access to Microsoft Graph API across multiple tenant environments.

## Understanding the Role of App Registration in CSP Reporting

The CSP Reporting solution uses a multi-tenant App Registration to:

1. **Authenticate to Microsoft Graph API** across multiple tenants without user interaction
2. **Access security and compliance data** including MFA status, audit logs, and directory information
3. **Operate as a background service** using app-only authentication (client credentials flow)
4. **Maintain security boundaries** between tenants while using a single application identity

## Part 1: Creating the App Registration

### Step 1: Register the Application

1. Sign in to the [Azure Portal](https://portal.azure.com) as an administrator in your management tenant
2. Navigate to **Azure Active Directory** > **App registrations**
3. Click **+ New registration**
4. Configure the application:
   - **Name**: "CSP Reporting Solution" (or your preferred name)
   - **Supported account types**: Select "Accounts in any organizational directory (Any Azure AD directory - Multitenant)"
   - **Redirect URI**: Leave blank (not needed for daemon apps)
5. Click **Register**

### Step 2: Note Important Information

After registration, you'll be taken to the app's overview page. Make note of:

- **Application (client) ID** - You'll need this for the `ClientId` parameter in the Config.psd1 file
- **Directory (tenant) ID** - Your management tenant ID

### Step 3: Configure Authentication

The CSP Reporting solution supports two authentication methods:

#### Option A: Certificate Authentication (Recommended)

1. Navigate to **Certificates & secrets** in the left menu
2. Under **Certificates**, click **+ Upload certificate**
3. You can generate a certificate using our `Setup-CSPCertificates.ps1` script:
   ```powershell
   .\Setup-CSPCertificates.ps1 -CertificatePassword (ConvertTo-SecureString -String "YourSecurePassword" -AsPlainText -Force)
   ```
4. Upload the generated .cer file (public key)
5. Make note of the certificate thumbprint

#### Option B: Client Secret Authentication (Alternative)

1. Navigate to **Certificates & secrets** in the left menu
2. Under **Client secrets**, click **+ New client secret**
3. Enter a description (e.g., "CSP Reporting Secret") and select an expiration time
4. Click **Add**
5. **IMPORTANT**: Copy the secret value immediately, as you won't be able to see it again

### Step 4: Request API Permissions

1. Navigate to **API permissions** in the left menu
2. Click **+ Add a permission**
3. Select **Microsoft Graph**
4. Choose **Application permissions** (not Delegated)
5. Add the following permissions:
   - **User.Read.All** - For user information and MFA status
   - **AuditLog.Read.All** - For audit log data
   - **Directory.Read.All** - For tenant directory information
   - **Reports.Read.All** - For usage reports
6. Click **Add permissions**
7. Click **Grant admin consent for [Your Org]** to approve these permissions in your tenant

## Part 2: Configuring the CSP Reporting Solution

After creating the App Registration, you need to configure the CSP Reporting solution to use it:

### Step 1: Update the Configuration File

Edit the `Config.psd1` file to include your App Registration details:

```powershell
# App Registration Details
AppRegistration = @{
    # The application (client) ID of the app registration
    ClientId = "YOUR-APPLICATION-CLIENT-ID"
    
    # The name of the app registration (for reference only)
    AppName = "CSP Reporting App"
}
```

### Step 2: Configure Tenant Authentication

For each tenant, configure the authentication method in the `Config.psd1` file:

```powershell
# Tenant Configurations
TenantConfigs = @(
    # Example tenant with certificate authentication
    @{
        TenantId = "tenant1.onmicrosoft.com"
        TenantName = "Tenant 1"
        CertificatePath = ".\Certificates\Tenant1.pfx"
        CertificatePassword = $null  # Set this in your script
        AuthMethod = "Certificate"
    },
    
    # Example tenant with client secret authentication
    @{
        TenantId = "tenant2.onmicrosoft.com"
        TenantName = "Tenant 2"
        AuthMethod = "ClientSecret"
        ClientSecret = $null  # Set this in your script
    }
)
```

## Part 3: Granting Admin Consent in Client Tenants

For the CSP Reporting solution to access data in client tenants, admin consent must be granted in each tenant:

### Option 1: Using the Admin Consent URL

1. Run the `Grant-CSPAdminConsent.ps1` script to generate admin consent URLs:
   ```powershell
   .\Grant-CSPAdminConsent.ps1
   ```
2. The script will display an admin consent URL for each tenant
3. Send this URL to the tenant administrator
4. When they access the URL and click **Accept**, your application will be registered in their tenant

### Option 2: Testing Admin Consent Status

You can test if admin consent has been granted in a tenant:

```powershell
.\Grant-CSPAdminConsent.ps1 -TestOnly
```

This will attempt to authenticate to each tenant and verify if the required permissions have been granted.

## Part 4: Security Best Practices

When working with App Registrations that have access to multiple tenants, follow these security best practices:

### 1. Use Certificate Authentication

Certificate-based authentication is more secure than client secrets:

- Certificates can't be easily intercepted in transit
- Private keys can be securely stored with proper access controls
- No need to rotate secrets as frequently

Use our `Setup-CSPCertificates.ps1` script to generate and configure certificates:

```powershell
.\Setup-CSPCertificates.ps1 -CertificatePassword (ConvertTo-SecureString -String "YourSecurePassword" -AsPlainText -Force)
```

### 2. Secure Credential Storage

- Store certificate passwords and client secrets securely
- Consider using a secure vault or encrypted storage
- Never hardcode secrets in scripts or configuration files

### 3. Regular Credential Rotation

- Rotate client secrets regularly (every 30-90 days)
- Update certificates before they expire
- Use the `Setup-CSPCertificates.ps1` script with the `-Force` parameter to replace existing certificates

### 4. Audit and Monitor

- Regularly review the permissions granted to your App Registration
- Monitor for suspicious activities in the Azure AD audit logs
- Implement logging in your scripts to track authentication and API calls

## Part 5: Troubleshooting Common Issues

### Authentication Failures

If you experience authentication failures:

1. **Invalid Client ID**: Verify the Application (client) ID in your configuration
2. **Certificate Issues**:
   - Check if the certificate has expired
   - Verify the certificate thumbprint matches the one in Azure AD
   - Ensure the certificate password is correct
3. **Client Secret Issues**:
   - Verify the client secret hasn't expired
   - Check if the secret was copied correctly (no extra spaces)
4. **Tenant ID Issues**: Confirm the tenant ID or domain name is correct

### Permission Issues

If your application can't access certain data:

1. **Missing Admin Consent**: Verify admin consent has been granted in the tenant
2. **Insufficient Permissions**: Check if all required permissions are granted
3. **Conditional Access Policies**: Check for tenant policies that might restrict access

You can use the `Test-CSPAdminConsent` function from the Utilities module to verify permissions:

```powershell
Import-Module .\Modules\Utilities.psm1
Test-CSPAdminConsent -TenantId "tenant.onmicrosoft.com" -ClientId "your-client-id"
```

### Consent Issues

If a tenant administrator reports an error during consent:

1. **Administrator Privileges**: Verify they have Global Administrator or Privileged Role Administrator rights
2. **Consent Blocked**: Check if there are tenant policies blocking third-party app consent
3. **URL Issues**: Verify the admin consent URL is correct and not truncated

## Part 6: Managing App Registration Lifecycle

### Monitoring and Maintenance

1. **Certificate Expiration**: Monitor certificate expiration dates and renew before they expire
2. **Permission Changes**: If Microsoft Graph API permissions change, update your App Registration
3. **Tenant Offboarding**: When a tenant is no longer managed, consider revoking access

### Scaling to More Tenants

As you add more tenants to your CSP Reporting solution:

1. Update the `Config.psd1` file with new tenant details
2. Generate certificates for new tenants using `Setup-CSPCertificates.ps1`
3. Obtain admin consent in new tenants using `Grant-CSPAdminConsent.ps1`

## Conclusion

The App Registration is the foundation of the CSP Reporting solution's ability to securely access Microsoft Graph API across multiple tenants. By following this guide, you've created and configured an App Registration that enables automated reporting while maintaining security and compliance.

With proper configuration and security practices, your CSP Reporting solution can scale to monitor and report on dozens or hundreds of tenants without requiring manual authentication or intervention for each tenant.

For more information on using the CSP Reporting solution, refer to the main README.md file and explore the example scripts in the Examples directory.