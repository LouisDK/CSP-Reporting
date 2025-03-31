<#
.SYNOPSIS
    Script for granting admin consent for the CSP Reporting application in each tenant.

.DESCRIPTION
    This script helps with granting admin consent for the CSP Reporting application
    in each tenant by generating admin consent URLs and testing if consent has been granted.

.NOTES
    File Name      : Grant-CSPAdminConsent.ps1
    Prerequisite   : PowerShell Core 7.0 or later
                     Microsoft Graph PowerShell SDK

.EXAMPLE
    .\Grant-CSPAdminConsent.ps1 -ConfigPath .\Config.psd1
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\Config.psd1",
    
    [Parameter(Mandatory = $false)]
    [switch]$TestOnly
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
}
catch {
    Write-Error "Failed to load configuration: $_"
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
        Write-Error "Error in Get-AdminConsentUrl: $_"
        return $null
    }
}
#endregion

#region Main Execution
try {
    # Add System.Web for URL encoding
    Add-Type -AssemblyName System.Web
    
    # Process each tenant
    foreach ($tenantConfig in $Config.TenantConfigs) {
        try {
            Write-Host "Processing tenant: $($tenantConfig.TenantName)" -ForegroundColor Cyan
            
            # Generate admin consent URL
            $adminConsentUrl = Get-AdminConsentUrl -TenantId $tenantConfig.TenantId -ClientId $Config.AppRegistration.ClientId
            
            if (-not $adminConsentUrl) {
                Write-Error "Failed to generate admin consent URL for tenant $($tenantConfig.TenantName)"
                continue
            }
            
            # Test if admin consent has been granted
            if ($TestOnly -or $PSCmdlet.ShouldProcess($tenantConfig.TenantName, "Test admin consent")) {
                Write-Host "  Testing if admin consent has been granted..." -ForegroundColor Yellow
                
                # Authenticate to the tenant
                $authParams = @{
                    TenantId = $tenantConfig.TenantId
                    ClientId = $Config.AppRegistration.ClientId
                }
                
                if ($tenantConfig.AuthMethod -eq "Certificate") {
                    if (-not $tenantConfig.CertificatePath -or -not (Test-Path -Path $tenantConfig.CertificatePath)) {
                        Write-Warning "  Certificate path is invalid or not provided for tenant $($tenantConfig.TenantName)"
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
                
                $authResult = Connect-CSPTenant @authParams
                
                if (-not $authResult.Success) {
                    Write-Warning "  Authentication failed for tenant $($tenantConfig.TenantName): $($authResult.ErrorMessage)"
                    Write-Host "  Admin consent URL: $adminConsentUrl" -ForegroundColor Yellow
                    Write-Host "  Please visit this URL in a browser while signed in as a Global Administrator of the tenant to grant admin consent." -ForegroundColor Yellow
                    continue
                }
                
                # Test admin consent
                $consentTest = Test-CSPAdminConsent -TenantId $tenantConfig.TenantId -ClientId $Config.AppRegistration.ClientId
                
                # Disconnect from the tenant
                Disconnect-CSPTenant
                
                if ($consentTest.Success) {
                    Write-Host "  Admin consent has been granted for tenant $($tenantConfig.TenantName)" -ForegroundColor Green
                }
                else {
                    Write-Warning "  Admin consent has not been granted for tenant $($tenantConfig.TenantName)"
                    Write-Host "  Admin consent URL: $adminConsentUrl" -ForegroundColor Yellow
                    Write-Host "  Please visit this URL in a browser while signed in as a Global Administrator of the tenant to grant admin consent." -ForegroundColor Yellow
                }
            }
            else {
                Write-Host "  Admin consent URL: $adminConsentUrl" -ForegroundColor Yellow
                Write-Host "  Please visit this URL in a browser while signed in as a Global Administrator of the tenant to grant admin consent." -ForegroundColor Yellow
            }
        }
        catch {
            Write-Error "Error processing tenant $($tenantConfig.TenantName): $_"
        }
    }
    
    Write-Host "Admin consent process completed." -ForegroundColor Green
    Write-Host "Remember to visit the admin consent URLs in a browser while signed in as a Global Administrator of each tenant to grant admin consent." -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during admin consent process: $_"
}
#endregion