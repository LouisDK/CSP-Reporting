<#
.SYNOPSIS
    Script for granting admin consent for the CSP Reporting application in each tenant.

.DESCRIPTION
    This script helps with granting admin consent for the CSP Reporting application
    in each tenant by generating admin consent URLs and testing if consent has been granted.
    It now includes automated consent capabilities and improved UI.

.NOTES
    File Name      : Grant-CSPAdminConsent.ps1
    Prerequisite   : PowerShell Core 7.0 or later
                    Microsoft Graph PowerShell SDK

.EXAMPLE
    .\Grant-CSPAdminConsent.ps1 -ConfigPath .\Config.psd1

.EXAMPLE
    .\Grant-CSPAdminConsent.ps1 -ConfigPath .\Config.psd1 -TestOnly

.EXAMPLE
    .\Grant-CSPAdminConsent.ps1 -ConfigPath .\Config.psd1 -AutoConsent
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\Config.psd1",
    
    [Parameter(Mandatory = $false)]
    [switch]$TestOnly,

    [Parameter(Mandatory = $false)]
    [switch]$AutoConsent
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
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Auth.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Utilities.psm1") -Force
    
    # Initialize terminal colors for enhanced UI
    Initialize-CSPTerminalColors
    
    # Check and install required modules using the enhanced module management
    $requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
    $moduleResults = Initialize-CSPModules -ModuleNames $requiredModules
    
    $failedModules = $moduleResults | Where-Object { $_.Status -eq "Error" }
    if ($failedModules) {
        foreach ($module in $failedModules) {
            Write-CSPLog -Message "Failed to initialize module $($module.ModuleName): $($module.ErrorMessage)" -Level "ERROR" -UseColor
        }
        exit 1
    }
}
catch {
    Write-CSPLog -Message "Failed to import required modules: $($_.Exception.Message)" -Level "ERROR" -UseColor
    exit 1
}
#endregion

#region Load Configuration
try {
    Write-CSPLog -Message "Loading configuration from $ConfigPath" -Level "INFO" -UseColor
    
    if (-not (Test-Path -Path $ConfigPath)) {
        throw "Configuration file not found at path: $ConfigPath"
    }
    
    $Config = Import-PowerShellDataFile -Path $ConfigPath
    
    # Validate configuration
    $requiredSettings = @("AppRegistration", "TenantConfigs")
    foreach ($setting in $requiredSettings) {
        if (-not $Config.ContainsKey($setting)) {
            throw "Required configuration setting '$setting' is missing"
        }
    }
    
    # Validate app registration
    if (-not $Config.AppRegistration.ContainsKey("ClientId")) {
        throw "Required configuration setting 'AppRegistration.ClientId' is missing"
    }
    
    Write-CSPLog -Message "Configuration loaded successfully" -Level "SUCCESS" -UseColor
}
catch {
    Write-CSPLog -Message "Failed to load configuration: $($_.Exception.Message)" -Level "ERROR" -UseColor
    exit 1
}
#endregion

#region Helper Functions
function Get-AdminConsentUrl {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $false)]
        [string]$RedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient"
    )
    
    try {
        # Define the required permissions
        $requiredScopes = @(
            "https://graph.microsoft.com/User.Read.All",
            "https://graph.microsoft.com/AuditLog.Read.All",
            "https://graph.microsoft.com/Directory.Read.All",
            "https://graph.microsoft.com/Reports.Read.All"
        )
        
        # URL encode the scopes
        $scopesEncoded = [System.Web.HttpUtility]::UrlEncode($requiredScopes -join " ")
        
        # Build the admin consent URL
        $adminConsentUrl = "https://login.microsoftonline.com/$TenantId/adminconsent?client_id=$ClientId&redirect_uri=$RedirectUri&scope=$scopesEncoded"
        
        return $adminConsentUrl
    }
    catch {
        Write-CSPLog -Message "Error in Get-AdminConsentUrl: $($_.Exception.Message)" -Level "ERROR" -UseColor
        return $null
    }
}
#endregion

#region Main Execution
try {
    # Add System.Web for URL encoding
    Add-Type -AssemblyName System.Web
    
    # Display script header
    Write-CSPColorMessage -Message "`n===== CSP Reporting Admin Consent Tool =====" -Type Info
    Write-CSPColorMessage -Message "This tool will help you grant admin consent for the CSP Reporting application in each tenant.`n" -ForegroundColor White
    
    # Process each tenant
    $totalTenants = $Config.TenantConfigs.Count
    $currentTenant = 0
    $successCount = 0
    $failCount = 0
    
    foreach ($tenantConfig in $Config.TenantConfigs) {
        try {
            $currentTenant++
            $percentComplete = [Math]::Floor(($currentTenant / $totalTenants) * 100)
            
            Write-CSPColorMessage -Message "`nProcessing tenant $currentTenant of $totalTenants - $($tenantConfig.TenantName)" -Type Info
            
            # Generate admin consent URL (for manual consent if needed)
            $adminConsentUrl = Get-AdminConsentUrl -TenantId $tenantConfig.TenantId -ClientId $Config.AppRegistration.ClientId
            
            if (-not $adminConsentUrl) {
                Write-CSPLog -Message "Failed to generate admin consent URL for tenant $($tenantConfig.TenantName)" -Level "ERROR" -UseColor
                $failCount++
                continue
            }
            
            # Prepare authentication parameters
            $authParams = @{
                TenantId = $tenantConfig.TenantId
                ClientId = $Config.AppRegistration.ClientId
            }
            
            # Handle authentication credentials
            if ($tenantConfig.AuthMethod -eq "Certificate") {
                if (-not $tenantConfig.CertificatePath -or -not (Test-Path -Path $tenantConfig.CertificatePath)) {
                    Write-CSPLog -Message "Certificate path is invalid or not provided for tenant $($tenantConfig.TenantName)" -Level "WARNING" -UseColor
                    Write-CSPLog -Message "Manual consent URL: $adminConsentUrl" -Level "INFO" -UseColor
                    $failCount++
                    continue
                }
                
                # Prompt for certificate password if not provided
                if (-not $tenantConfig.CertificatePassword) {
                    $certPassword = Read-Host -Prompt "Enter certificate password for tenant $($tenantConfig.TenantName)" -AsSecureString
                }
                else {
                    $certPassword = $tenantConfig.CertificatePassword
                }
                
                $authParams.CertificatePath = $tenantConfig.CertificatePath
                $authParams.CertificatePassword = $certPassword
                $authParams.AuthMethod = "Certificate"
            }
            else {
                # Prompt for client secret if not provided
                if (-not $tenantConfig.ClientSecret) {
                    $clientSecret = Read-Host -Prompt "Enter client secret for tenant $($tenantConfig.TenantName)" -AsSecureString
                }
                else {
                    $clientSecret = $tenantConfig.ClientSecret
                }
                
                $authParams.ClientSecret = $clientSecret
                $authParams.AuthMethod = "ClientSecret"
            }
            
            # Test if admin consent has been granted
            if ($TestOnly -or $PSCmdlet.ShouldProcess($tenantConfig.TenantName, "Test admin consent")) {
                Write-CSPLog -Message "Testing if admin consent has been granted..." -Level "INFO" -UseColor
                
                # Authenticate to the tenant
                $authResult = Connect-CSPTenant @authParams
                
                if (-not $authResult.Success) {
                    Write-CSPLog -Message "Authentication failed for tenant $($tenantConfig.TenantName): $($authResult.ErrorMessage)" -Level "WARNING" -UseColor
                    Write-CSPLog -Message "Manual consent URL: $adminConsentUrl" -Level "INFO" -UseColor
                    Write-CSPLog -Message "Please visit this URL in a browser while signed in as a Global Administrator of the tenant to grant admin consent." -Level "INFO" -UseColor
                    $failCount++
                    continue
                }
                
                # Test admin consent
                $consentTest = Test-CSPAdminConsent -TenantId $tenantConfig.TenantId -ClientId $Config.AppRegistration.ClientId
                
                # Disconnect from the tenant
                Disconnect-CSPTenant
                
                if ($consentTest.Success) {
                    Write-CSPLog -Message "Admin consent has been granted for tenant $($tenantConfig.TenantName)" -Level "SUCCESS" -UseColor
                    $successCount++
                }
                else {
                    Write-CSPLog -Message "Admin consent has not been granted for tenant $($tenantConfig.TenantName)" -Level "WARNING" -UseColor
                    
                    # If AutoConsent is specified, try to automate the consent process
                    if ($AutoConsent) {
                        Write-CSPLog -Message "Attempting to automate admin consent..." -Level "INFO" -UseColor
                        
                        $consentParams = @{
                            ClientId = $Config.AppRegistration.ClientId
                            PartnerTenantId = $tenantConfig.TenantId  # This is actually the tenant we're granting consent to
                            CustomerTenantId = $tenantConfig.TenantId  # Same as partner tenant in this case
                            AppDisplayName = if ($Config.AppRegistration.AppName) { $Config.AppRegistration.AppName } else { "CSP Reporting App" }
                        }
                        
                        # Add authentication parameters based on auth method
                        if ($tenantConfig.AuthMethod -eq "Certificate") {
                            $consentParams.CertificatePath = $tenantConfig.CertificatePath
                            $consentParams.CertificatePassword = $certPassword
                        }
                        else {
                            $consentParams.ClientSecret = $clientSecret
                        }
                        
                        # Invoke the automated consent
                        $consentResult = Invoke-CSPAdminConsent @consentParams
                        
                        if ($consentResult.Success) {
                            Write-CSPLog -Message "Successfully initiated automated admin consent" -Level "SUCCESS" -UseColor
                            Write-CSPLog -Message "Request ID: $($consentResult.RequestId)" -Level "INFO" -UseColor
                            $successCount++
                        }
                        else {
                            Write-CSPLog -Message "Failed to automate admin consent: $($consentResult.Message)" -Level "WARNING" -UseColor
                            Write-CSPLog -Message "Manual consent URL: $adminConsentUrl" -Level "INFO" -UseColor
                            Write-CSPLog -Message "Please visit this URL in a browser while signed in as a Global Administrator of the tenant to grant admin consent." -Level "INFO" -UseColor
                            $failCount++
                        }
                    }
                    else {
                        Write-CSPLog -Message "Manual consent URL: $adminConsentUrl" -Level "INFO" -UseColor
                        Write-CSPLog -Message "Please visit this URL in a browser while signed in as a Global Administrator of the tenant to grant admin consent." -Level "INFO" -UseColor
                        $failCount++
                    }
                }
            }
            elseif ($AutoConsent) {
                # Try automated consent without testing first
                Write-CSPLog -Message "Attempting to automate admin consent..." -Level "INFO" -UseColor
                
                $consentParams = @{
                    ClientId = $Config.AppRegistration.ClientId
                    PartnerTenantId = $tenantConfig.TenantId
                    CustomerTenantId = $tenantConfig.TenantId
                    AppDisplayName = if ($Config.AppRegistration.AppName) { $Config.AppRegistration.AppName } else { "CSP Reporting App" }
                }
                
                # Add authentication parameters based on auth method
                if ($tenantConfig.AuthMethod -eq "Certificate") {
                    $consentParams.CertificatePath = $tenantConfig.CertificatePath
                    $consentParams.CertificatePassword = $certPassword
                }
                else {
                    $consentParams.ClientSecret = $clientSecret
                }
                
                # Invoke the automated consent
                $consentResult = Invoke-CSPAdminConsent @consentParams
                
                if ($consentResult.Success) {
                    Write-CSPLog -Message "Successfully initiated automated admin consent" -Level "SUCCESS" -UseColor
                    Write-CSPLog -Message "Request ID: $($consentResult.RequestId)" -Level "INFO" -UseColor
                    $successCount++
                }
                else {
                    Write-CSPLog -Message "Failed to automate admin consent: $($consentResult.Message)" -Level "WARNING" -UseColor
                    Write-CSPLog -Message "Manual consent URL: $adminConsentUrl" -Level "INFO" -UseColor
                    Write-CSPLog -Message "Please visit this URL in a browser while signed in as a Global Administrator of the tenant to grant admin consent." -Level "INFO" -UseColor
                    $failCount++
                }
            }
            else {
                # Just provide the consent URL
                Write-CSPLog -Message "Manual consent URL: $adminConsentUrl" -Level "INFO" -UseColor
                Write-CSPLog -Message "Please visit this URL in a browser while signed in as a Global Administrator of the tenant to grant admin consent." -Level "INFO" -UseColor
            }
        }
        catch {
            Write-CSPLog -Message "Error processing tenant $($tenantConfig.TenantName): $($_.Exception.Message)" -Level "ERROR" -UseColor
            $failCount++
        }
    }
    
    # Display summary
    Write-CSPColorMessage -Message "`n===== Admin Consent Process Summary =====" -Type Info
    Write-CSPLog -Message "Total tenants processed: $totalTenants" -Level "INFO" -UseColor
    Write-CSPLog -Message "Successful operations: $successCount" -Level "SUCCESS" -UseColor
    Write-CSPLog -Message "Failed operations: $failCount" -Level "WARNING" -UseColor
    
    if ($failCount -gt 0) {
        Write-CSPLog -Message "`nFor tenants where automated consent failed, please use the manual consent URLs provided above." -Level "INFO" -UseColor
        Write-CSPLog -Message "Visit each URL in a browser while signed in as a Global Administrator of the respective tenant." -Level "INFO" -UseColor
    }
    
    # Restore terminal colors
    Set-CSPTerminalColors -RestoreOriginal
    
    Write-CSPColorMessage -Message "`nAdmin consent process completed." -Type Success
}
catch {
    Write-CSPLog -Message "An error occurred during admin consent process: $($_.Exception.Message)" -Level "ERROR" -UseColor
    
    # Restore terminal colors
    Set-CSPTerminalColors -RestoreOriginal
}
#endregion