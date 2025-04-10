<#
.SYNOPSIS
    Configuration file for CSP Reporting solution.

.DESCRIPTION
    This file contains the configuration settings for the CSP Reporting solution,
    including tenant configurations, app registration details, and report settings.

.NOTES
    File Name      : Config.psd1
    Format         : PowerShell Data File (.psd1)
    
    IMPORTANT: This file contains sensitive information. Ensure it is properly secured.
    Consider using a secure vault or encrypted storage for production environments.
#>

@{
    # App Registration Details
    AppRegistration = @{
        # The application (client) ID of the app registration
        ClientId = "00000000-0000-0000-0000-000000000000"
        
        # The name of the app registration (for reference only)
        AppName = "CSP Reporting App"
    }
    
    # Tenant Configurations
    # Each tenant entry contains the details needed to connect to that tenant
    TenantConfigs = @(
        # Example tenant with certificate authentication
        @{
            # The tenant ID (GUID) or domain name
            TenantId = "tenant1.onmicrosoft.com"
            
            # The display name of the tenant (for reporting purposes)
            TenantName = "Tenant 1"
            
            # The path to the certificate file (.pfx) for certificate-based authentication
            CertificatePath = ".\Certificates\Tenant1.pfx"
            
            # The password for the certificate file (should be a secure string in production)
            # Use: $securePassword = ConvertTo-SecureString -String "YourPassword" -AsPlainText -Force
            CertificatePassword = $null
            
            # The authentication method to use for this tenant
            # Valid values: "Certificate", "ClientSecret"
            AuthMethod = "Certificate"
            
            # The client secret for client secret authentication (if using ClientSecret method)
            # Use: $secureSecret = ConvertTo-SecureString -String "YourClientSecret" -AsPlainText -Force
            ClientSecret = $null
        },
        
        # Example tenant with client secret authentication
        @{
            TenantId = "tenant2.onmicrosoft.com"
            TenantName = "Tenant 2"
            AuthMethod = "ClientSecret"
            ClientSecret = $null  # Should be a secure string in production
        }
        
        # Add more tenant configurations as needed
    )
    
    # Default Authentication Method
    # Valid values: "Certificate", "ClientSecret"
    DefaultAuthMethod = "Certificate"
    
    # Output Path for Reports
    # The path where reports will be saved
    OutputPath = ".\Reports"
    
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
        # Valid values: "INFO", "WARNING", "ERROR", "DEBUG"
        LogLevel = "INFO"
    }
}