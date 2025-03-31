# Multi-Tenant Microsoft Graph API Reporting Framework

A robust, enterprise-grade PowerShell framework for automating Microsoft Graph API operations across multiple tenant environments. Designed specifically for Managed Service Providers (MSPs) and organizations managing multiple Microsoft 365 tenants, this solution provides comprehensive security and compliance reporting, advanced error handling, and seamless resumability for mission-critical operations.

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Authentication Methods](#authentication-methods)
- [Report Types](#report-types)
- [Scheduling](#scheduling)
- [Resilient Operations](#resilient-operations)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Additional Documentation](#additional-documentation)
- [Contributing](#contributing)

## Features

- **Multi-tenant Support**: Connect to multiple Microsoft 365 tenants using a single application registration
- **Flexible Authentication**: Support for both certificate-based and client secret authentication
- **Comprehensive Reporting**: Generate reports for MFA status, audit logs, directory information, and usage
- **Resumable Operations**: Automatically resume operations from where they left off after interruptions
- **Intelligent Pagination**: Handle large datasets efficiently with automatic pagination and batch processing
- **Robust Error Handling**: Advanced retry logic with exponential backoff for API rate limiting
- **Progress Reporting**: Detailed progress tracking for long-running operations
- **Incremental Saving**: Prevent data loss by saving report data incrementally
- **Customizable Output**: Export reports in CSV, JSON, or both formats
- **Automated Scheduling**: Set up scheduled tasks to automate report generation
- **Certificate Management**: Automatic certificate validation and renewal detection
- **Modular Design**: Easily extend with additional report types or custom functionality
- **Tenant Isolation**: Errors in one tenant don't affect operations in others

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

This enhanced script now includes:
- Certificate validation to detect expired certificates
- Automatic renewal detection
- Configuration backup before making changes
- Detailed progress reporting

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

# Report Settings
ReportSettings = @{
    # Number of days back to retrieve audit logs
    DaysBack = 30
    
    # Include disabled users in MFA report
    IncludeDisabledUsers = $false
    
    # Include guest users in MFA report
    IncludeGuestUsers = $true
}

# Logging Settings
LoggingSettings = @{
    # Enable logging
    EnableLogging = $true
    
    # Log file path
    LogFilePath = ".\Logs\CSPReporting.log"
    
    # Log level
    LogLevel = "INFO"
}
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

### Resumable Operations

Enable resumable operations to continue from where you left off after interruptions:

```powershell
# Initial run with state path specified
.\Start-CSPReporting.ps1 -StatePath ".\State\CSPReporting_State.xml"

# Resume from previous state
.\Start-CSPReporting.ps1 -StatePath ".\State\CSPReporting_State.xml" -Resume
```

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
.\Schedule-CSPReporting.ps1 -Action Update -Frequency Weekly -Time "04:00" -ReportTypes MFA,AuditLog -StatePath ".\State\CSPReporting_State.xml"

# Remove a scheduled task
.\Schedule-CSPReporting.ps1 -Action Remove
```

## Resilient Operations

This framework implements several features to ensure reliable operation, even in challenging scenarios:

### Automatic Resumability

The framework continuously tracks progress during report generation, allowing operations to be resumed from where they left off after interruptions:

- **State Management**: Detailed state tracking for each tenant and report type
- **Incremental Saving**: Report data is saved incrementally to prevent data loss
- **Checkpoint System**: Progress checkpoints enable precise resumption

### Intelligent Pagination

For large datasets, the framework automatically handles pagination to prevent memory issues:

- **Batch Processing**: Data is processed in batches to maintain performance
- **Efficient Memory Usage**: Streaming data processing avoids loading entire datasets into memory
- **Automatic Buffer Management**: Buffer sizes adjust dynamically based on data volume

### Advanced Error Handling

The framework includes sophisticated error handling capabilities:

- **Retry Logic**: Automatic retries with exponential backoff for transient errors
- **Rate Limit Management**: Intelligent handling of API rate limiting
- **Error Isolation**: Errors in one tenant don't affect operations in others
- **Detailed Diagnostics**: Comprehensive error information for troubleshooting

### Progress Reporting

Real-time progress tracking provides visibility into long-running operations:

- **Operation Status**: Current status of each operation
- **Progress Percentage**: Completion percentage for each report
- **Time Estimates**: Estimated time remaining for operations
- **Tenant Isolation**: Separate progress tracking for each tenant

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

#### API Rate Limiting

The framework automatically handles rate limiting, but you can fine-tune:
- Consider spreading large operations across multiple time periods
- Lower batch sizes for very large tenants
- Check logs for persistent rate limiting issues

### Logging

The solution provides comprehensive logging for troubleshooting:

- **Structured Logging**: All operations produce detailed logs with severity levels
- **Verbosity Control**: Configure the level of detail in logs
- **Transcript Logging**: Full transcript of operations for debugging
- **Console Output**: Real-time status information during execution

Log files are stored in the `Logs` directory by default, and each run creates a transcript log with detailed information. Use the `-Verbose` parameter for more detailed console output.

## Security Considerations

- **Secure Storage**: Store certificates and client secrets securely
- **Least Privilege**: Grant only the required permissions to the app registration
- **Regular Rotation**: Rotate client secrets regularly
- **Audit Logging**: Monitor access to the reports and configuration files
- **Secure Transmission**: Ensure that reports are transmitted securely
- **Certificate Management**: Monitor certificate expiry and rotation

For comprehensive security best practices, refer to the [App Registration Guide - Security Best Practices](AppRegistration-Guide.md#part-4-security-best-practices) section.

## Additional Documentation

- [App Registration Guide](AppRegistration-Guide.md) - Detailed guide for creating and configuring the App Registration, including security best practices and troubleshooting
- [Setup-CSPCertificates.ps1](Setup-CSPCertificates.ps1) - Script for setting up certificates for authentication
- [Grant-CSPAdminConsent.ps1](Grant-CSPAdminConsent.ps1) - Script for granting admin consent in each tenant
- [Examples/Generate-TenantReport.ps1](Examples/Generate-TenantReport.ps1) - Example script for generating reports for a specific tenant
- [Examples/Export-ReportsToDB.ps1](Examples/Export-ReportsToDB.ps1) - Example script for exporting reports to a SQL database
- [Design.md](Design.md) - Detailed design documentation for the framework

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Extensibility

The framework is designed to be easily extended with additional functionality:

- **Custom Report Types**: Add new report types by creating additional functions in the Reports module
- **Data Enrichment**: Extend reports with additional data from other sources
- **Integration Points**: Integrate with other systems via the extensible output mechanisms
- **Custom Authentication**: Add support for additional authentication methods
- **Pipeline Integration**: Incorporate into CI/CD pipelines for automated compliance checks

This modular architecture allows you to adapt the framework to your specific requirements without modifying the core components.