# Multi-Tenant Microsoft Graph API Reporting Solution

A PowerShell-based solution for automating Microsoft Graph API queries across multiple tenant environments for Managed Service Providers (MSPs). This solution retrieves security and compliance data, including MFA status and audit logs, from client tenants where permissions have been granted.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Authentication Methods](#authentication-methods)
- [Report Types](#report-types)
- [Scheduling](#scheduling)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Additional Documentation](#additional-documentation)
- [Contributing](#contributing)

## Features

- **Multi-tenant Support**: Connect to multiple Microsoft 365 tenants using a single application registration
- **Flexible Authentication**: Support for both certificate-based and client secret authentication
- **Comprehensive Reporting**: Generate reports for MFA status, audit logs, directory information, and usage
- **Customizable Output**: Export reports in CSV, JSON, or both formats
- **Automated Scheduling**: Set up scheduled tasks to automate report generation
- **Error Handling**: Robust error handling and logging for reliable operation
- **Modular Design**: Easily extendable with additional report types

## Prerequisites

- PowerShell Core 7.0 or later
- Microsoft Graph PowerShell SDK
- Administrative access to create an app registration in Azure AD
- Appropriate permissions granted in each tenant

## Installation

1. Clone or download this repository to your local machine
2. Install required PowerShell modules:

```powershell
Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
```

3. Create an app registration in Azure AD with the required permissions (see [App Registration Setup](#app-registration-setup))
4. Update the `Config.psd1` file with your app registration and tenant details

## Configuration

### App Registration Setup

For detailed instructions on creating and configuring the App Registration, please refer to our comprehensive [App Registration Guide](AppRegistration-Guide.md).

1. Sign in to the [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** > **App registrations**
3. Click **New registration**
4. Enter a name for the application (e.g., "CSP Reporting")
5. Set the supported account type to **Accounts in any organizational directory (Any Azure AD directory - Multitenant)**
6. Click **Register**
7. Note the **Application (client) ID** for use in the configuration file

### Required Permissions

Add the following application permissions to your app registration:

- `User.Read.All` - For user information and MFA status
- `AuditLog.Read.All` - For audit log data
- `Directory.Read.All` - For tenant directory information
- `Reports.Read.All` - For usage reports

After adding the permissions, grant admin consent in each tenant where you want to use the application.

### Certificate Authentication Setup (Recommended)

For a streamlined certificate setup process, use our dedicated script:

```powershell
.\Setup-CSPCertificates.ps1 -CertificatePassword (ConvertTo-SecureString -String "YourSecurePassword" -AsPlainText -Force)
```

Alternatively, you can manually generate a certificate:

```powershell
Import-Module .\Modules\Utilities.psm1
$certPassword = ConvertTo-SecureString -String "YourSecurePassword" -AsPlainText -Force
New-CSPSelfSignedCertificate -CertificateName "CSPReporting" -CertificatePath ".\Certificates\CSPReporting.pfx" -CertificatePassword $certPassword -ExpiryYears 2
```

Then upload the certificate to your app registration in Azure AD:
- In the Azure Portal, navigate to your app registration
- Go to **Certificates & secrets**
- Click **Upload certificate**
- Select the public certificate file (.cer) and upload it

### Configuration File

Update the `Config.psd1` file with your app registration and tenant details:

```powershell
# App Registration Details
AppRegistration = @{
    ClientId = "YOUR_APPLICATION_CLIENT_ID"
    AppName = "CSP Reporting App"
}

# Tenant Configurations
TenantConfigs = @(
    @{
        TenantId = "tenant1.onmicrosoft.com"
        TenantName = "Tenant 1"
        CertificatePath = ".\Certificates\Tenant1.pfx"
        CertificatePassword = $null  # Set this in your script
        AuthMethod = "Certificate"
    },
    @{
        TenantId = "tenant2.onmicrosoft.com"
        TenantName = "Tenant 2"
        AuthMethod = "ClientSecret"
        ClientSecret = $null  # Set this in your script
    }
)
```

## Usage

### Basic Usage

Run the main script to generate reports for all configured tenants:

```powershell
.\Start-CSPReporting.ps1
```

### Specify Report Types

Generate specific report types:

```powershell
.\Start-CSPReporting.ps1 -ReportTypes MFA,AuditLog
```

Available report types:
- `MFA` - MFA status report
- `AuditLog` - Audit log report
- `DirectoryInfo` - Directory information report
- `UsageReports` - Usage reports
- `All` - All report types (default)

### Specify Output Format

Choose the output format:

```powershell
.\Start-CSPReporting.ps1 -OutputFormat JSON
```

Available output formats:
- `CSV` - CSV format (default)
- `JSON` - JSON format
- `Both` - Both CSV and JSON formats

### Use a Different Configuration File

Specify a different configuration file:

```powershell
.\Start-CSPReporting.ps1 -ConfigPath ".\CustomConfig.psd1"
```

## Authentication Methods

The solution supports two authentication methods:

### Certificate-Based Authentication (Recommended)

Certificate-based authentication is more secure and doesn't require periodic secret rotation. To use certificate-based authentication:

1. Generate a self-signed certificate (see [Certificate Authentication Setup](#certificate-authentication-setup-recommended))
2. Upload the certificate to your app registration
3. Configure the tenant to use certificate authentication in the configuration file

For detailed guidance on certificate management, refer to the [App Registration Guide - Certificate Authentication](AppRegistration-Guide.md#option-a-certificate-authentication-recommended) section.

### Client Secret Authentication

Client secret authentication is simpler to set up but requires periodic secret rotation. To use client secret authentication:

1. Create a client secret in your app registration:
   - In the Azure Portal, navigate to your app registration
   - Go to **Certificates & secrets**
   - Click **New client secret**
   - Enter a description and select an expiration period
   - Click **Add**
   - Copy the secret value (you won't be able to see it again)
2. Configure the tenant to use client secret authentication in the configuration file

For more details, see the [App Registration Guide - Client Secret Authentication](AppRegistration-Guide.md#option-b-client-secret-authentication-alternative) section.

## Report Types

### MFA Status Report

The MFA status report provides information about the MFA status of users in the tenant, including:

- User display name and UPN
- Account status (enabled/disabled)
- User type (member/guest)
- MFA status (enabled/disabled)
- MFA methods used

### Audit Log Report

The audit log report provides information about audit events in the tenant, including:

- Activity date and time
- Activity display name
- Category
- Initiated by (user or application)
- Result and reason

### Directory Information Report

The directory information report provides information about the tenant, including:

- Tenant name and ID
- Verified and unverified domains
- User, group, and application counts
- Technical and security notification emails

### Usage Reports

The usage reports provide information about Microsoft 365 service usage, including:

- User principal name and display name
- Last activation and activity dates
- Products assigned and used

## Scheduling

Use the scheduling script to set up automated report generation:

```powershell
# Create a daily scheduled task to run at 3:00 AM
.\Schedule-CSPReporting.ps1 -Action Create -Frequency Daily -Time "03:00" -ReportTypes All

# Update an existing scheduled task
.\Schedule-CSPReporting.ps1 -Action Update -Frequency Weekly -Time "04:00" -ReportTypes MFA,AuditLog

# Remove a scheduled task
.\Schedule-CSPReporting.ps1 -Action Remove
```

## Troubleshooting

### Common Issues

#### Authentication Failures

- Verify that the app registration has the required permissions
- Ensure that admin consent has been granted in each tenant
- Check that the certificate or client secret is valid and not expired
- Verify that the tenant ID is correct

For detailed troubleshooting steps, see the [App Registration Guide - Troubleshooting Common Issues](AppRegistration-Guide.md#part-5-troubleshooting-common-issues) section.

#### Missing Data in Reports

- Verify that the app registration has the required permissions
- Check the log files for any errors or warnings
- Ensure that the tenant has the required licenses for the data you're trying to retrieve

### Logging

The solution logs detailed information to help with troubleshooting:

- Log files are stored in the `Logs` directory by default
- Each run creates a transcript log with detailed information
- Use the `-Verbose` parameter for more detailed console output

## Security Considerations

- **Secure Storage**: Store certificates and client secrets securely
- **Least Privilege**: Grant only the required permissions to the app registration
- **Regular Rotation**: Rotate client secrets regularly
- **Audit Logging**: Monitor access to the reports and configuration files
- **Secure Transmission**: Ensure that reports are transmitted securely

For comprehensive security best practices, refer to the [App Registration Guide - Security Best Practices](AppRegistration-Guide.md#part-4-security-best-practices) section.

## Additional Documentation

- [App Registration Guide](AppRegistration-Guide.md) - Detailed guide for creating and configuring the App Registration, including security best practices and troubleshooting
- [Setup-CSPCertificates.ps1](Setup-CSPCertificates.ps1) - Script for setting up certificates for authentication
- [Grant-CSPAdminConsent.ps1](Grant-CSPAdminConsent.ps1) - Script for granting admin consent in each tenant
- [Examples/Generate-TenantReport.ps1](Examples/Generate-TenantReport.ps1) - Example script for generating reports for a specific tenant
- [Examples/Export-ReportsToDB.ps1](Examples/Export-ReportsToDB.ps1) - Example script for exporting reports to a SQL database

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.