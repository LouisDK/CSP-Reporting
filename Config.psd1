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
    
    # Tenant Configurations
    # Each tenant entry contains the details needed to connect to that tenant
    TenantConfigs = @(
        @{
            # The tenant ID (GUID) or domain name
            TenantId = "83cf691f-ded3-4441-ad78-e4a088441fc0" #"charteredgroup.onmicrosoft.com"
            
            # The display name of the tenant (for reporting purposes)
            TenantName = "Chartered Group"

            # The application (client) ID of the App Registration in this tenant
            ClientId = "09a8682e-8cf3-4960-aba2-377a056dc6ef"
            
            # The path to the certificate file (.pfx) for certificate-based authentication
            CertificatePath = ".\Certificates\CSPauditCertPP.pfx"
            
            # The password for the certificate file (should be a secure string in production)
            # Use: $securePassword = ConvertTo-SecureString -String "YourPassword" -AsPlainText -Force
            CertificatePassword = "D9)fnQ7C1*P5cd%B5D0)F1y,sB3O"
            
            # The authentication method to use for this tenant
            # Valid values: "Certificate", "ClientSecret"
            AuthMethod = "Certificate"
            
            # The client secret for client secret authentication (if using ClientSecret method)
            # Use: $secureSecret = ConvertTo-SecureString -String "YourClientSecret" -AsPlainText -Force
            ClientSecret = $null

            # Optional: List of reports to run for this tenant. Valid options: "MFA", "AuditLog", "DirectoryInfo", "UsageReports", "All"
            ReportsToRun = @("MFA")
        }
        
        @{
            TenantId = "5da736f8-138e-4b36-adab-2236f975b6f1"
            TenantName = "Netsurit"
            AuthMethod = "Certificate"
            ClientId = "08616068-6348-4055-9c17-f04d332f23fc"
            CertificatePath = ".\Certificates\Netsurit_CSPLDK.pfx"
            CertificatePassword = "King123!@#"
        } 

        #@{
        #     TenantId = "harith.onmicrosoft.com"
        #     TenantName = "Harith"
        #     AuthMethod = "ClientSecret"
        #     ClientSecret = ""  # Should be a secure string in production
        # }
        
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