<#
.SYNOPSIS
    Script for setting up certificates for CSP Reporting solution.

.DESCRIPTION
    This script helps with generating and configuring certificates for authentication
    with Microsoft Graph API across multiple tenants.

.NOTES
    File Name      : Setup-CSPCertificates.ps1
    Prerequisite   : PowerShell Core 7.0 or later

.EXAMPLE
    .\Setup-CSPCertificates.ps1 -ConfigPath .\Config.psd1 -CertificatePassword (ConvertTo-SecureString -String "YourSecurePassword" -AsPlainText -Force)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\Config.psd1",
    
    [Parameter(Mandatory = $false)]
    [string]$CertificatesPath = ".\Certificates",
    
    [Parameter(Mandatory = $false)]
    [SecureString]$CertificatePassword,
    
    [Parameter(Mandatory = $false)]
    [int]$ExpiryYears = 2,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

#region Script Initialization
# Set strict mode to catch common errors
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script root path
$ScriptPath = $PSScriptRoot
$ModulesPath = Join-Path -Path $ScriptPath -ChildPath "Modules"

# Import required modules
try {
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Utilities.psm1") -Force
    
    # Check if Microsoft Graph module is installed
    if (-not (Get-Module -Name Microsoft.Graph -ListAvailable)) {
        Write-Warning "Microsoft Graph PowerShell SDK is not installed. Installing..."
        Install-Module -Name Microsoft.Graph -Scope CurrentUser -Force
    }
}
catch {
    Write-Error "Failed to import required modules: $_"
    exit 1
}
#endregion

#region Load Configuration
try {
    Write-Verbose "Loading configuration from $ConfigPath"
    $Config = Import-PowerShellDataFile -Path $ConfigPath
    
    # Validate configuration
    if (-not $Config.ContainsKey("TenantConfigs")) {
        throw "Required configuration setting 'TenantConfigs' is missing"
    }
}
catch {
    Write-Error "Failed to load configuration: $_"
    exit 1
}
#endregion

#region Main Execution
try {
    # Create certificates directory if it doesn't exist
    if (-not (Test-Path -Path $CertificatesPath)) {
        New-Item -Path $CertificatesPath -ItemType Directory -Force | Out-Null
        Write-Verbose "Created certificates directory: $CertificatesPath"
    }
    
    # Prompt for certificate password if not provided
    if (-not $CertificatePassword) {
        $CertificatePassword = Read-Host -Prompt "Enter certificate password" -AsSecureString
    }
    
    # Process each tenant
    foreach ($tenantConfig in $Config.TenantConfigs) {
        try {
            Write-Host "Processing tenant: $($tenantConfig.TenantName)" -ForegroundColor Cyan
            
            # Skip tenants not using certificate authentication
            if ($tenantConfig.AuthMethod -ne "Certificate") {
                Write-Host "  Tenant $($tenantConfig.TenantName) is not using certificate authentication. Skipping." -ForegroundColor Yellow
                continue
            }
            
            # Determine certificate path
            $certFileName = "CSP_$($tenantConfig.TenantName -replace '[^a-zA-Z0-9]', '_').pfx"
            $certPath = Join-Path -Path $CertificatesPath -ChildPath $certFileName
            
            # Check if certificate already exists
            if (Test-Path -Path $certPath) {
                if ($Force) {
                    Write-Host "  Certificate already exists. Overwriting..." -ForegroundColor Yellow
                }
                else {
                    Write-Host "  Certificate already exists. Use -Force to overwrite." -ForegroundColor Yellow
                    continue
                }
            }
            
            # Generate certificate
            Write-Host "  Generating certificate for tenant $($tenantConfig.TenantName)..." -ForegroundColor Yellow
            $certResult = New-CSPSelfSignedCertificate -CertificateName "CSP_$($tenantConfig.TenantName)" -CertificatePath $certPath -CertificatePassword $CertificatePassword -ExpiryYears $ExpiryYears
            
            if (-not $certResult.Success) {
                Write-Error "Failed to generate certificate for tenant $($tenantConfig.TenantName): $($certResult.Error)"
                continue
            }
            
            # Export public certificate for Azure AD upload
            $publicCertPath = $certPath -replace '\.pfx$', '.cer'
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($certPath, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            $certData = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes($publicCertPath, $certData)
            
            Write-Host "  Certificate generated successfully:" -ForegroundColor Green
            Write-Host "    Private Key (PFX): $certPath" -ForegroundColor Green
            Write-Host "    Public Key (CER): $publicCertPath" -ForegroundColor Green
            Write-Host "    Thumbprint: $($certResult.Thumbprint)" -ForegroundColor Green
            Write-Host "    Valid Until: $($certResult.NotAfter)" -ForegroundColor Green
            
            # Update configuration
            Write-Host "  Updating configuration..." -ForegroundColor Yellow
            $tenantConfig.CertificatePath = $certPath
            
            Write-Host "  Next steps:" -ForegroundColor Cyan
            Write-Host "    1. Upload the public certificate ($publicCertPath) to your app registration in Azure AD" -ForegroundColor Cyan
            Write-Host "    2. Grant admin consent for the application in tenant $($tenantConfig.TenantId)" -ForegroundColor Cyan
        }
        catch {
            Write-Error "Error processing tenant $($tenantConfig.TenantName): $_"
        }
    }
    
    # Save updated configuration
    Write-Host "Saving updated configuration..." -ForegroundColor Yellow
    $configContent = @"
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
        ClientId = "$($Config.AppRegistration.ClientId)"
        
        # The name of the app registration (for reference only)
        AppName = "$($Config.AppRegistration.AppName)"
    }
    
    # Tenant Configurations
    # Each tenant entry contains the details needed to connect to that tenant
    TenantConfigs = @(
"@

    foreach ($tenantConfig in $Config.TenantConfigs) {
        $configContent += @"
        
        @{
            # The tenant ID (GUID) or domain name
            TenantId = "$($tenantConfig.TenantId)"
            
            # The display name of the tenant (for reporting purposes)
            TenantName = "$($tenantConfig.TenantName)"
            
"@

        if ($tenantConfig.AuthMethod -eq "Certificate") {
            $configContent += @"
            # The path to the certificate file (.pfx) for certificate-based authentication
            CertificatePath = "$($tenantConfig.CertificatePath)"
            
            # The password for the certificate file (should be a secure string in production)
            # Use: `$securePassword = ConvertTo-SecureString -String "YourPassword" -AsPlainText -Force
            CertificatePassword = `$null
            
            # The authentication method to use for this tenant
            # Valid values: "Certificate", "ClientSecret"
            AuthMethod = "Certificate"
            
            # The client secret for client secret authentication (if using ClientSecret method)
            ClientSecret = `$null
"@
        }
        else {
            $configContent += @"
            # The authentication method to use for this tenant
            # Valid values: "Certificate", "ClientSecret"
            AuthMethod = "ClientSecret"
            
            # The client secret for client secret authentication
            # Use: `$secureSecret = ConvertTo-SecureString -String "YourClientSecret" -AsPlainText -Force
            ClientSecret = `$null
"@
        }

        $configContent += @"
        }
"@
    }

    $configContent += @"
    )
    
    # Default Authentication Method
    # Valid values: "Certificate", "ClientSecret"
    DefaultAuthMethod = "$($Config.DefaultAuthMethod)"
    
    # Output Path for Reports
    # The path where reports will be saved
    OutputPath = "$($Config.OutputPath)"
    
    # Report Settings
    ReportSettings = @{
        # Number of days back to retrieve audit logs
        DaysBack = $($Config.ReportSettings.DaysBack)
        
        # Include disabled users in MFA report
        IncludeDisabledUsers = `$$($Config.ReportSettings.IncludeDisabledUsers.ToString().ToLower())
        
        # Include guest users in MFA report
        IncludeGuestUsers = `$$($Config.ReportSettings.IncludeGuestUsers.ToString().ToLower())
    }
    
    # Logging Settings
    LoggingSettings = @{
        # Enable logging
        EnableLogging = `$$($Config.LoggingSettings.EnableLogging.ToString().ToLower())
        
        # Log file path
        LogFilePath = "$($Config.LoggingSettings.LogFilePath)"
        
        # Log level
        # Valid values: "INFO", "WARNING", "ERROR", "DEBUG"
        LogLevel = "$($Config.LoggingSettings.LogLevel)"
    }
}
"@

    # Save the updated configuration
    $configContent | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
    
    Write-Host "Certificate setup completed successfully." -ForegroundColor Green
    Write-Host "Remember to upload the public certificates to your app registration in Azure AD and grant admin consent in each tenant." -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during certificate setup: $_"
}
#endregion