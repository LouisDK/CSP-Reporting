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
    
    # Use our utility function to check and install required modules
    $requiredModules = @("Microsoft.Graph")
    $moduleCheck = Test-CSPModuleAvailability -ModuleNames $requiredModules -InstallIfMissing
    
    if ($moduleCheck | Where-Object { -not $_.Available }) {
        $missingModules = $moduleCheck | Where-Object { -not $_.Available } | Select-Object -ExpandProperty ModuleName
        throw "One or more required modules could not be installed: $($missingModules -join ', ')"
    }
}
catch {
    Write-CSPLog -Message "Failed to import required modules: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
#endregion

#region Load Configuration
try {
    Write-CSPLog -Message "Loading configuration from $ConfigPath" -Level "INFO"
    
    if (-not (Test-Path -Path $ConfigPath)) {
        throw "Configuration file not found at path: $ConfigPath"
    }
    
    $Config = Import-PowerShellDataFile -Path $ConfigPath
    
    # Validate configuration more thoroughly
    $requiredSettings = @("TenantConfigs", "AppRegistration")
    foreach ($setting in $requiredSettings) {
        if (-not $Config.ContainsKey($setting)) {
            throw "Required configuration setting '$setting' is missing"
        }
    }
    
    # Validate app registration
    if (-not $Config.AppRegistration.ContainsKey("ClientId")) {
        throw "Required configuration setting 'AppRegistration.ClientId' is missing"
    }
    
    # Validate tenant configs
    if ($Config.TenantConfigs.Count -eq 0) {
        throw "No tenant configurations found in configuration file"
    }
    
    foreach ($tenantConfig in $Config.TenantConfigs) {
        if (-not $tenantConfig.ContainsKey("TenantId")) {
            throw "Required configuration setting 'TenantId' is missing in one of the tenant configurations"
        }
        
        if (-not $tenantConfig.ContainsKey("TenantName")) {
            throw "Required configuration setting 'TenantName' is missing in tenant configuration for $($tenantConfig.TenantId)"
        }
    }
}
catch {
    Write-CSPLog -Message "Failed to load configuration: $($_.Exception.Message)" -Level "ERROR"
    exit 1
}
#endregion

#region Main Execution
try {
    # Create certificates directory if it doesn't exist
    if (-not (Test-Path -Path $CertificatesPath)) {
        New-Item -Path $CertificatesPath -ItemType Directory -Force | Out-Null
        Write-CSPLog -Message "Created certificates directory: $CertificatesPath" -Level "INFO"
    }
    
    # Prompt for certificate password if not provided
    if (-not $CertificatePassword) {
        $CertificatePassword = Read-Host -Prompt "Enter certificate password" -AsSecureString
        
        if ($null -eq $CertificatePassword -or $CertificatePassword.Length -eq 0) {
            throw "Certificate password is required"
        }
    }
    
    # Calculate total tenants for progress reporting
    $tenantCount = ($Config.TenantConfigs | Where-Object {
        -not $_.ContainsKey("AuthMethod") -or $_.AuthMethod -eq "Certificate"
    }).Count
    
    $currentTenant = 0
    $successCount = 0
    $skippedCount = 0
    $failedCount = 0
    
    # Process each tenant
    foreach ($tenantConfig in $Config.TenantConfigs) {
        try {
            # Skip tenants not using certificate authentication
            $authMethod = if ($tenantConfig.ContainsKey("AuthMethod")) {
                $tenantConfig.AuthMethod
            } else {
                $Config.DefaultAuthMethod
            }
            
            if ($authMethod -ne "Certificate") {
                Write-CSPLog -Message "Tenant $($tenantConfig.TenantName) is not using certificate authentication. Skipping." -Level "INFO"
                $skippedCount++
                continue
            }
            
            $currentTenant++
            $percentComplete = [Math]::Floor(($currentTenant / $tenantCount) * 100)
            
            Write-CSPLog -Message "Processing tenant: $($tenantConfig.TenantName) ($currentTenant of $tenantCount)" -Level "INFO"
            Write-Progress -Activity "Setting up certificates" -Status "Processing tenant $($tenantConfig.TenantName)" -PercentComplete $percentComplete
            
            # Determine certificate path
            $certFileName = "CSP_$($tenantConfig.TenantName -replace '[^a-zA-Z0-9]', '_').pfx"
            $certPath = Join-Path -Path $CertificatesPath -ChildPath $certFileName
            $publicCertPath = $certPath -replace '\.pfx$', '.cer'
            
            # Check if certificate already exists and validate it
            $certificateExists = $false
            $certificateValid = $false
            
            if (Test-Path -Path $certPath) {
                $certificateExists = $true
                
                # Check if the certificate is valid and not expired
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $cert.Import($certPath, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
                    
                    if ($cert.NotAfter -gt (Get-Date)) {
                        $certificateValid = $true
                        $expiresIn = ($cert.NotAfter - (Get-Date)).Days
                        
                        Write-CSPLog -Message "Certificate for tenant $($tenantConfig.TenantName) already exists and is valid for $expiresIn more days." -Level "INFO"
                    }
                    else {
                        Write-CSPLog -Message "Certificate for tenant $($tenantConfig.TenantName) exists but has expired. Will be regenerated." -Level "WARNING"
                    }
                }
                catch {
                    Write-CSPLog -Message "Certificate for tenant $($tenantConfig.TenantName) exists but could not be loaded (incorrect password?). Will be regenerated if -Force is specified." -Level "WARNING"
                }
            }
            
            # Determine if we need to generate a new certificate
            $generateNew = $false
            
            if (-not $certificateExists) {
                $generateNew = $true
                Write-CSPLog -Message "No certificate exists for tenant $($tenantConfig.TenantName). Will generate new certificate." -Level "INFO"
            }
            elseif (-not $certificateValid) {
                if ($Force) {
                    $generateNew = $true
                    Write-CSPLog -Message "Certificate for tenant $($tenantConfig.TenantName) is invalid or expired. Will generate new certificate." -Level "INFO"
                }
                else {
                    Write-CSPLog -Message "Certificate for tenant $($tenantConfig.TenantName) is invalid or expired. Use -Force to regenerate." -Level "WARNING"
                    $skippedCount++
                    continue
                }
            }
            elseif ($Force) {
                $generateNew = $true
                Write-CSPLog -Message "Certificate for tenant $($tenantConfig.TenantName) is valid, but -Force flag is set. Will regenerate." -Level "INFO"
            }
            else {
                Write-CSPLog -Message "Certificate for tenant $($tenantConfig.TenantName) is valid. Skipping generation." -Level "INFO"
                
                # Update configuration to ensure certificate path is set correctly
                if ($tenantConfig.CertificatePath -ne $certPath) {
                    Write-CSPLog -Message "Updating configuration with correct certificate path." -Level "INFO"
                    $tenantConfig.CertificatePath = $certPath
                }
                
                $successCount++
                continue
            }
            
            # Generate certificate if needed
            if ($generateNew) {
                Write-CSPLog -Message "Generating certificate for tenant $($tenantConfig.TenantName)..." -Level "INFO"
                
                # Use retry logic for certificate generation
                $retries = 0
                $maxRetries = 2
                $success = $false
                
                while (-not $success -and $retries -le $maxRetries) {
                    try {
                        if ($retries -gt 0) {
                            Write-CSPLog -Message "Retry attempt $retries for certificate generation..." -Level "INFO"
                        }
                        
                        $certResult = New-CSPSelfSignedCertificate -CertificateName "CSP_$($tenantConfig.TenantName)" -CertificatePath $certPath -CertificatePassword $CertificatePassword -ExpiryYears $ExpiryYears
                        
                        if (-not $certResult.Success) {
                            throw "Certificate generation failed: $($certResult.Error)"
                        }
                        
                        $success = $true
                    }
                    catch {
                        $retries++
                        if ($retries -le $maxRetries) {
                            Write-CSPLog -Message "Error during certificate generation: $($_.Exception.Message). Retrying..." -Level "WARNING"
                            Start-Sleep -Seconds 2
                        }
                        else {
                            throw
                        }
                    }
                }
                
                # Export public certificate for Azure AD upload
                try {
                    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
                    $cert.Import($certPath, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
                    $certData = $cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                    [System.IO.File]::WriteAllBytes($publicCertPath, $certData)
                    
                    Write-CSPLog -Message "Certificate for tenant $($tenantConfig.TenantName) generated successfully:" -Level "INFO"
                    Write-CSPLog -Message "  Private Key (PFX): $certPath" -Level "INFO"
                    Write-CSPLog -Message "  Public Key (CER): $publicCertPath" -Level "INFO"
                    Write-CSPLog -Message "  Thumbprint: $($certResult.Thumbprint)" -Level "INFO"
                    Write-CSPLog -Message "  Valid Until: $($certResult.NotAfter)" -Level "INFO"
                    
                    # Update configuration
                    $tenantConfig.CertificatePath = $certPath
                    $successCount++
                }
                catch {
                    Write-CSPLog -Message "Error exporting public certificate: $($_.Exception.Message)" -Level "ERROR"
                    $failedCount++
                    continue
                }
            }
            
            # Display next steps
            Write-CSPLog -Message "Next steps for tenant $($tenantConfig.TenantName):" -Level "INFO"
            Write-CSPLog -Message "  1. Upload the public certificate ($publicCertPath) to your app registration in Azure AD" -Level "INFO"
            Write-CSPLog -Message "  2. Grant admin consent for the application in tenant $($tenantConfig.TenantId)" -Level "INFO"
        }
        catch {
            Write-CSPLog -Message "Error processing tenant $($tenantConfig.TenantName): $($_.Exception.Message)" -Level "ERROR"
            $failedCount++
        }
    }
    
    # Complete progress bar
    Write-Progress -Activity "Setting up certificates" -Completed
    
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

    # Create a backup of the original config file
    $backupPath = "$ConfigPath.bak"
    try {
        Copy-Item -Path $ConfigPath -Destination $backupPath -Force
        Write-CSPLog -Message "Created backup of original configuration at $backupPath" -Level "INFO"
    }
    catch {
        Write-CSPLog -Message "Warning: Could not create backup of original configuration: $($_.Exception.Message)" -Level "WARNING"
    }
    
    # Save the updated configuration with error handling
    try {
        $configContent | Out-File -FilePath $ConfigPath -Encoding UTF8 -Force
        Write-CSPLog -Message "Updated configuration file saved successfully" -Level "INFO"
    }
    catch {
        Write-CSPLog -Message "Error saving updated configuration: $($_.Exception.Message)" -Level "ERROR"
        
        # Try to restore from backup
        if (Test-Path -Path $backupPath) {
            try {
                Copy-Item -Path $backupPath -Destination $ConfigPath -Force
                Write-CSPLog -Message "Restored original configuration from backup" -Level "INFO"
            }
            catch {
                Write-CSPLog -Message "Failed to restore configuration from backup: $($_.Exception.Message)" -Level "ERROR"
            }
        }
    }
    
    # Display summary
    Write-CSPLog -Message "Certificate setup completed" -Level "INFO"
    Write-CSPLog -Message "Summary:" -Level "INFO"
    Write-CSPLog -Message "  Total tenants processed: $tenantCount" -Level "INFO"
    Write-CSPLog -Message "  Certificates created/updated: $successCount" -Level "INFO"
    Write-CSPLog -Message "  Tenants skipped: $skippedCount" -Level "INFO"
    Write-CSPLog -Message "  Failures: $failedCount" -Level "INFO"
    
    if ($successCount -gt 0) {
        Write-CSPLog -Message "Next steps:" -Level "INFO"
        Write-CSPLog -Message "1. Upload the public certificates (.cer files) to your app registration in Azure AD" -Level "INFO"
        Write-CSPLog -Message "2. Use Grant-CSPAdminConsent.ps1 to grant admin consent in each tenant" -Level "INFO"
    }
}
catch {
    Write-CSPLog -Message "An error occurred during certificate setup: $($_.Exception.Message)" -Level "ERROR"
    Write-Progress -Activity "Setting up certificates" -Status "Error" -Completed
    exit 1
}
#endregion