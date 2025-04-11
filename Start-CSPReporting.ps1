<#
.SYNOPSIS
    Main script for CSP Reporting solution that orchestrates the multi-tenant Microsoft Graph API reporting process.

.DESCRIPTION
    This script is the entry point for the CSP Reporting solution. It handles:
    - Loading configuration
    - Authentication to multiple tenants
    - Collecting data from Microsoft Graph API
    - Generating reports
    - Storing output in the specified format
    
    Supports resumable operations to recover from errors without starting from scratch.

.NOTES
    File Name      : Start-CSPReporting.ps1
    Prerequisite   : PowerShell Core 7.0 or later
                     Microsoft Graph PowerShell SDK
                     Appropriate permissions in each tenant

.EXAMPLE
    .\Start-CSPReporting.ps1 -ConfigPath .\Config.psd1 -ReportTypes MFA,AuditLog -OutputFormat CSV

.EXAMPLE
    .\Start-CSPReporting.ps1 -ConfigPath .\Config.psd1 -ReportTypes All -StatePath .\State\CSPReporting_State.xml -Resume
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\Config.psd1",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("MFA", "AuditLog", "DirectoryInfo", "UsageReports", "All")]
    [string[]]$ReportTypes = @("All"),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$OutputFormat = "CSV",

    [Parameter(Mandatory = $false)]
    [string]$StatePath,
    
    [Parameter(Mandatory = $false)]
    [switch]$Resume,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force,
    [Parameter(Mandatory = $false)]
    [switch]$ForceFresh
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

    # Import utility modules
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "StateManagement.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "LoggingAndProgress.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "ApiHelpers.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "CertificateUtils.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "ModuleManagement.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "ConsentUtils.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "ReportingUtils.psm1") -Force

    # Import data extraction modules
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/Identity.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/SecurityPosture.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/PrivilegedAccess.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/Applications.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/DeviceManagement.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/GetPolicyData.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/RiskAndAudit.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/Usage.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "DataExtraction/GetTenantInfo.psm1") -Force

    # Check if Microsoft Graph module is installed using our utility function
    $requiredModules = @("Microsoft.Graph")
    $moduleCheck = Test-CSPModuleAvailability -ModuleNames $requiredModules -InstallIfMissing
    
    if ($moduleCheck | Where-Object { -not $_.Available }) {
        throw "One or more required modules could not be installed: $($moduleCheck | Where-Object { -not $_.Available } | Select-Object -ExpandProperty ModuleName)"
    }
}
catch {
    Write-Error "Failed to import required modules: $_"
    exit 1
}
#endregion

#region Load Configuration
try {
    Write-CSPLog -Message "Loading configuration from $ConfigPath" -Level "INFO"
    $Config = Import-PowerShellDataFile -Path $ConfigPath
    
    # Validate configuration - extended validation for all required settings
    $requiredSettings = @(
        "TenantConfigs",
        "OutputPath",
        "DefaultAuthMethod",
        "ReportSettings"
    )
    
    foreach ($setting in $requiredSettings) {
        if (-not $Config.ContainsKey($setting)) {
            throw "Required configuration setting '$setting' is missing"
        }
    }
    
    # Validate per-tenant app registration settings
    foreach ($tenantConfig in $Config.TenantConfigs) {
        if (-not $tenantConfig.ContainsKey("ClientId")) {
            throw "Required configuration setting 'ClientId' is missing in tenant configuration for $($tenantConfig.TenantName)"
        }
    }
    
    # Validate tenant configurations
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
        
        $authMethod = if ($tenantConfig.ContainsKey("AuthMethod")) { 
            $tenantConfig.AuthMethod 
        } else { 
            $Config.DefaultAuthMethod 
        }
        
        # Validate authentication method requirements
        if ($authMethod -eq "Certificate") {
            if (-not $tenantConfig.ContainsKey("CertificatePath")) {
                throw "Certificate authentication method specified for tenant $($tenantConfig.TenantName), but CertificatePath is missing"
            }
            
            if (-not (Test-Path -Path $tenantConfig.CertificatePath)) {
                throw "Certificate file not found at path: $($tenantConfig.CertificatePath) for tenant $($tenantConfig.TenantName)"
            }
        }
        elseif ($authMethod -eq "ClientSecret") {
            if (-not $tenantConfig.ContainsKey("ClientSecret") -and -not $Force) {
                throw "Client secret authentication method specified for tenant $($tenantConfig.TenantName), but ClientSecret is missing"
            }
        }
        else {
            throw "Invalid authentication method specified for tenant $($tenantConfig.TenantName): $authMethod. Valid values are 'Certificate' or 'ClientSecret'."
        }
    }
    
    # Validate report settings
    $reportSettingsValidations = @{
        "DaysBack" = @{ Type = "Int"; DefaultValue = 30 }
        "IncludeDisabledUsers" = @{ Type = "Bool"; DefaultValue = $false }
        "IncludeGuestUsers" = @{ Type = "Bool"; DefaultValue = $true }
    }
    
    foreach ($setting in $reportSettingsValidations.Keys) {
        if (-not $Config.ReportSettings.ContainsKey($setting)) {
            Write-CSPLog -Message "Report setting '$setting' not found, using default value: $($reportSettingsValidations[$setting].DefaultValue)" -Level "WARNING"
            $Config.ReportSettings[$setting] = $reportSettingsValidations[$setting].DefaultValue
        }
    }
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $Config.OutputPath)) {
        New-Item -Path $Config.OutputPath -ItemType Directory -Force | Out-Null
        Write-CSPLog -Message "Created output directory: $($Config.OutputPath)" -Level "INFO"
    }
    
    # Create state directory if state path is specified
    if ($StatePath) {
        $stateDir = Split-Path -Path $StatePath -Parent
        if (-not (Test-Path -Path $stateDir)) {
            New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
            Write-CSPLog -Message "Created state directory: $stateDir" -Level "INFO"
        }
    }
}
catch {
    Write-Error "Failed to load configuration: $_"
    exit 1
}
#endregion

#region Main Execution
try {
    # Initialize state for resumability
    if ($StatePath) {
        $stateInit = Initialize-CSPProcessState -StatePath $StatePath
        if ($Resume -and $stateInit.ResumedFromSave) {
            Write-CSPLog -Message "Resuming execution from saved state" -Level "INFO"
        }
        else {
            Write-CSPLog -Message "Initialized new process state" -Level "INFO"
        }
    }
    
    # Initialize logging
    $logSettings = @{
        LogFilePath = Join-Path -Path $Config.OutputPath -ChildPath "CSPReporting_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        Level = "INFO"
    }
    
    if ($Config.ContainsKey("LoggingSettings")) {
        if ($Config.LoggingSettings.ContainsKey("LogFilePath")) {
            $logSettings.LogFilePath = $Config.LoggingSettings.LogFilePath
        }
        
        if ($Config.LoggingSettings.ContainsKey("LogLevel")) {
            $logSettings.Level = $Config.LoggingSettings.LogLevel
        }
    }
    
    Start-Transcript -Path $logSettings.LogFilePath -Append
    
    Write-CSPLog -Message "Starting CSP Reporting process at $(Get-Date)" -Level "INFO"
    
    # Calculate total operations for progress reporting
    $totalTenants = $Config.TenantConfigs.Count
    $reportsToRun = if ($ReportTypes -contains "All") {
        @("MFA", "AuditLog", "DirectoryInfo", "UsageReports")
    } else {
        $ReportTypes
    }
    $totalReports = $totalTenants * $reportsToRun.Count
    $currentOperation = 0
    
    # Process each tenant
    foreach ($tenantConfig in $Config.TenantConfigs) {
    
        # Determine reports to run for this tenant
        $tenantReportsToRun = if ($tenantConfig.ContainsKey("ReportsToRun")) {
            if ($tenantConfig.ReportsToRun -contains "All") {
                @("MFA", "AuditLog", "DirectoryInfo", "UsageReports")
            } else {
                $tenantConfig.ReportsToRun
            }
        } else {
            $reportsToRun
        }
        try {
            # Update process state for this tenant
            if ($StatePath) {
                Update-CSPProcessState -TenantId $tenantConfig.TenantId -TenantName $tenantConfig.TenantName -Status "Started"
            }
            
            Write-CSPLog -Message "Processing tenant: $($tenantConfig.TenantName)" -Level "INFO"
            
            # Check if we should skip this tenant (if resuming and it's already completed)
            $skipTenant = $false
            if ($Resume -and $StatePath) {
                $tenantState = Get-CSPProcessState -TenantId $tenantConfig.TenantId
                if ($tenantState -and $tenantState.Status -eq "Completed") {
                    Write-CSPLog -Message "Tenant $($tenantConfig.TenantName) was already processed successfully. Skipping." -Level "INFO"
                    $skipTenant = $true
                }
            }
            
            if (-not $skipTenant) {
                # Authenticate to the tenant
                $authParams = @{
                    TenantId = $tenantConfig.TenantId
                    ClientId = $tenantConfig.ClientId
                    Verbose = $true  # Add verbose output for debugging
                }
                
                Write-CSPLog -Message "Using ClientId: $($tenantConfig.ClientId)" -Level "DEBUG"
                Write-CSPLog -Message "TenantId: $($tenantConfig.TenantId)" -Level "DEBUG"
                Write-CSPLog -Message "TenantName: $($tenantConfig.TenantName)" -Level "DEBUG"
                Write-CSPLog -Message "AuthMethod: $authMethod" -Level "DEBUG"
                Write-CSPLog -Message "CertificatePath: $($tenantConfig.CertificatePath)" -Level "DEBUG"
                Write-CSPLog -Message "CertificatePassword: $($tenantConfig.CertificatePassword)" -Level "DEBUG"
                Write-CSPLog -Message "ClientSecret: $($tenantConfig.ClientSecret)" -Level "DEBUG"
                
                # Add authentication method parameters
                $authMethod = if ($tenantConfig.ContainsKey("AuthMethod")) { 
                    $tenantConfig.AuthMethod 
                } else { 
                    $Config.DefaultAuthMethod 
                }
                
                if ($authMethod -eq "Certificate") {
                    $authParams.CertificatePath = $tenantConfig.CertificatePath

                    # Convert plain text password to SecureString if necessary
                    if ($tenantConfig.CertificatePassword -is [string]) {
                        $secureCertPassword = ConvertTo-SecureString -String $tenantConfig.CertificatePassword -AsPlainText -Force
                        $authParams.CertificatePassword = $secureCertPassword
                    } elseif ($tenantConfig.CertificatePassword -is [System.Security.SecureString]) {
                        $authParams.CertificatePassword = $tenantConfig.CertificatePassword
                    } else {
                        throw "CertificatePassword must be either a plain text string or a SecureString"
                    }

                    $authParams.AuthMethod = "Certificate"
                }
                else {
                    # Create a PSCredential object for client secret authentication
                    if ($tenantConfig.ClientSecret -is [string]) {
                        $secureSecret = ConvertTo-SecureString -String $tenantConfig.ClientSecret -AsPlainText -Force
                        $authParams.ClientSecretCredential = New-Object System.Management.Automation.PSCredential($tenantConfig.ClientId, $secureSecret)
                    } elseif ($tenantConfig.ClientSecret -is [SecureString]) {
                        $authParams.ClientSecretCredential = New-Object System.Management.Automation.PSCredential($Config.AppRegistration.ClientId, $tenantConfig.ClientSecret)
                    } else {
                        throw "ClientSecret must be either a string or a SecureString"
                    }
                    $authParams.AuthMethod = "ClientSecret"
                }
                
                # For ClientSecret authentication, bypass Connect-CSPTenant and use Connect-MgGraph directly
                if ($authMethod -eq "ClientSecret") {
                    try {
                        Write-CSPLog -Message "Attempting direct authentication with Connect-MgGraph using ClientId method..." -Level "DEBUG"
                        
                        # Based on our test, Method 2 (using ClientId parameter directly) works best
                        $clientId = $Config.AppRegistration.ClientId
                        $tenantId = $tenantConfig.TenantId
                        
                        Write-CSPLog -Message "Connecting with ClientId=$clientId, TenantId=$tenantId" -Level "DEBUG"
                        Connect-MgGraph -ClientId $clientId -TenantId $tenantId
                        
                        # Create success result
                        $authResult = @{
                            Success = $true
                            Connection = Get-MgContext
                        }
                        
                        Write-CSPLog -Message "Direct authentication with Connect-MgGraph successful" -Level "DEBUG"
                    }
                    catch {
                        Write-CSPLog -Message "Direct authentication with Connect-MgGraph failed: $_" -Level "ERROR"
                        $authResult = @{
                            Success = $false
                            ErrorMessage = "Direct authentication with Connect-MgGraph failed: $_"
                        }
                    }
                }
                else {
                    # Use Connect-CSPTenant for certificate authentication
                    try {
                        Write-CSPLog -Message "Attempting authentication with Connect-CSPTenant..." -Level "DEBUG"
                        $authResult = Connect-CSPTenant @authParams
                        Write-CSPLog -Message "Authentication with Connect-CSPTenant successful" -Level "DEBUG"
                    }
                    catch {
                        Write-CSPLog -Message "Authentication with Connect-CSPTenant failed: $_" -Level "ERROR"
                        $authResult = @{
                            Success = $false
                            ErrorMessage = "Authentication with Connect-CSPTenant failed: $_"
                        }
                    }
                }
                
                if (-not $authResult.Success) {
                    Write-CSPLog -Message "Authentication failed for tenant $($tenantConfig.TenantName): $($authResult.ErrorMessage)" -Level "ERROR"
                    
                    # Update state to failed
                    if ($StatePath) {
                        Update-CSPProcessState -TenantId $tenantConfig.TenantId -TenantName $tenantConfig.TenantName -Status "Failed" -Data @{
                            Error = "Authentication failed: $($authResult.ErrorMessage)"
                        }
                    }
                    
                # Verify connected tenant context
                $connectionTest = Test-CSPConnection
                if (-not $connectionTest.Connected -or $connectionTest.TenantId -ne $tenantConfig.TenantId) {
                    Write-CSPLog -Message "Connected tenant '$($connectionTest.TenantId)' does not match expected tenant '$($tenantConfig.TenantId)'. Skipping this tenant." -Level "ERROR"
                    continue
                }
                    continue
                }
                
                Write-CSPLog -Message "Successfully authenticated to tenant $($tenantConfig.TenantName)" -Level "INFO"
                
                # v2 Data Extraction
                $tenantRawData = @{}
                $tenantRawData.TenantId = $tenantConfig.TenantId
                $tenantRawData.TenantName = $tenantConfig.TenantName

                Write-CSPLog -Message "Starting v2 data extraction for tenant $($tenantConfig.TenantName)" -Level "INFO"
# --- Enhanced Restartability: Setup Cache Paths ---
$cacheBase = Join-Path $Config.OutputPath "_Cache"
$runDate = Get-Date -Format "yyyy-MM-dd"
# Sanitize tenant name for filesystem (replace invalid chars with _)
$sanitizedTenantName = $tenantConfig.TenantName -replace '[\\/:*?"<>|]', '_'
$tenantCacheDir = Join-Path $cacheBase $runDate | Join-Path -ChildPath $sanitizedTenantName
if (-not (Test-Path $tenantCacheDir)) {
    New-Item -Path $tenantCacheDir -ItemType Directory -Force | Out-Null
}

# Tenant Info (with cache)
$tenantInfoCache = Join-Path $tenantCacheDir "TenantInfo.json"
if (-not $ForceFresh -and (Test-Path $tenantInfoCache)) {
    Write-CSPLog -Message "Loading cached tenant info for $($tenantConfig.TenantName) from $tenantInfoCache" -Level "INFO"
    $tenantRawData.TenantInfo = Get-Content -Path $tenantInfoCache | ConvertFrom-Json
} else {
    Write-CSPLog -Message "Extracting tenant info..." -Level "INFO"
    $tenantRawData.TenantInfo = Get-CSPTenantInfo
    if ($tenantRawData.TenantInfo) {
        $tenantRawData.TenantInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath $tenantInfoCache -Encoding UTF8
        Write-CSPLog -Message "Saved extracted tenant info for $($tenantConfig.TenantName) to $tenantInfoCache" -Level "INFO"
    }
}
                # Domain Info (with cache)
                $domainInfoCache = Join-Path $tenantCacheDir "DomainInfo.json"
                if (-not $ForceFresh -and (Test-Path $domainInfoCache)) {
                    Write-CSPLog -Message "Loading cached domain info for $($tenantConfig.TenantName) from $domainInfoCache" -Level "INFO"
                    $tenantRawData.DomainInfo = Get-Content -Path $domainInfoCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting domain info..." -Level "INFO"
                    $tenantRawData.DomainInfo = Get-CSPDomainInfo
                    if ($tenantRawData.DomainInfo) {
                        $tenantRawData.DomainInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath $domainInfoCache -Encoding UTF8
                        Write-CSPLog -Message "Saved extracted domain info for $($tenantConfig.TenantName) to $domainInfoCache" -Level "INFO"
                    }
                }

                # Organization Info (with cache)
                $orgInfoCache = Join-Path $tenantCacheDir "OrganizationInfo.json"
                if (-not $ForceFresh -and (Test-Path $orgInfoCache)) {
                    Write-CSPLog -Message "Loading cached organization info for $($tenantConfig.TenantName) from $orgInfoCache" -Level "INFO"
                    $tenantRawData.OrganizationInfo = Get-Content -Path $orgInfoCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting organization info..." -Level "INFO"
                    $tenantRawData.OrganizationInfo = Get-CSPOrganizationInfo
                    if ($tenantRawData.OrganizationInfo) {
                        $tenantRawData.OrganizationInfo | ConvertTo-Json -Depth 10 | Out-File -FilePath $orgInfoCache -Encoding UTF8
                        Write-CSPLog -Message "Saved extracted organization info for $($tenantConfig.TenantName) to $orgInfoCache" -Level "INFO"
                    }
                }
                
                # Users and related (with cache)
                $usersCache = Join-Path $tenantCacheDir "Users.json"
                if (-not $ForceFresh -and (Test-Path $usersCache)) {
                    Write-CSPLog -Message "Loading cached users for $($tenantConfig.TenantName) from $usersCache" -Level "INFO"
                    $tenantRawData.Users = Get-Content -Path $usersCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting users..." -Level "INFO"
                    $tenantRawData.Users = Get-CSPUserData
                    if ($tenantRawData.Users) {
                        $tenantRawData.Users | ConvertTo-Json -Depth 10 | Out-File -FilePath $usersCache -Encoding UTF8
                        Write-CSPLog -Message "Saved extracted users for $($tenantConfig.TenantName) to $usersCache" -Level "INFO"
                    }
                }

                # User Auth Methods (with cache) - Depends on Users data
                $userAuthMethodsCache = Join-Path $tenantCacheDir "UserAuthMethods.json"
                if (-not $ForceFresh -and (Test-Path $userAuthMethodsCache)) {
                    Write-CSPLog -Message "Loading cached user auth methods for $($tenantConfig.TenantName) from $userAuthMethodsCache" -Level "INFO"
                    $tenantRawData.UserAuthMethods = Get-Content -Path $userAuthMethodsCache | ConvertFrom-Json
                } else {
                    # Ensure Users data is available before calling
                    if ($null -ne $tenantRawData.Users) {
                        Write-CSPLog -Message "Extracting user authentication methods..." -Level "INFO"
                        $tenantRawData.UserAuthMethods = Get-CSPUserAuthMethods -Users $tenantRawData.Users
                        if ($tenantRawData.UserAuthMethods) {
                            $tenantRawData.UserAuthMethods | ConvertTo-Json -Depth 10 | Out-File -FilePath $userAuthMethodsCache -Encoding UTF8
                            Write-CSPLog -Message "Saved extracted user auth methods for $($tenantConfig.TenantName) to $userAuthMethodsCache" -Level "INFO"
                        }
                    } else {
                        Write-CSPLog -Message "Skipping user authentication methods extraction because user data is missing." -Level "WARNING"
                        $tenantRawData.UserAuthMethods = @{} # Or appropriate empty value
                    }
                }

                # Directory Roles (with cache)
                $dirRolesCache = Join-Path $tenantCacheDir "DirectoryRoles.json"
                if (-not $ForceFresh -and (Test-Path $dirRolesCache)) {
                    Write-CSPLog -Message "Loading cached directory roles for $($tenantConfig.TenantName) from $dirRolesCache" -Level "INFO"
                    $tenantRawData.DirectoryRoles = Get-Content -Path $dirRolesCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting directory roles..." -Level "INFO"
                    $tenantRawData.DirectoryRoles = Get-CSPDirectoryRoles
                    if ($tenantRawData.DirectoryRoles) {
                        $tenantRawData.DirectoryRoles | ConvertTo-Json -Depth 10 | Out-File -FilePath $dirRolesCache -Encoding UTF8
                        Write-CSPLog -Message "Saved extracted directory roles for $($tenantConfig.TenantName) to $dirRolesCache" -Level "INFO"
                    }
                }

                # PIM Assignments (with cache)
                $pimCache = Join-Path $tenantCacheDir "PIMAssignments.json"
                if (-not $ForceFresh -and (Test-Path $pimCache)) {
                    Write-CSPLog -Message "Loading cached PIM assignments for $($tenantConfig.TenantName) from $pimCache" -Level "INFO"
                    $tenantRawData.PIMAssignments = Get-Content -Path $pimCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting PIM assignments..." -Level "INFO"
                    $tenantRawData.PIMAssignments = Get-CSPPIMAssignments
                    # Save even if skipped, to cache the skip reason
                    if ($tenantRawData.PIMAssignments) {
                        $tenantRawData.PIMAssignments | ConvertTo-Json -Depth 10 | Out-File -FilePath $pimCache -Encoding UTF8
                        # Log differently if skipped
                        if ($tenantRawData.PIMAssignments.PSObject.Properties.Name -contains 'SkippedReason') {
                             Write-CSPLog -Message "Saved PIM assignment skip status for $($tenantConfig.TenantName) to $pimCache" -Level "INFO"
                        } else {
                             Write-CSPLog -Message "Saved extracted PIM assignments for $($tenantConfig.TenantName) to $pimCache" -Level "INFO"
                        }
                    }
                }
                
                # Policies (with cache)
                $caPoliciesCache = Join-Path $tenantCacheDir "ConditionalAccessPolicies.json"
                if (-not $ForceFresh -and (Test-Path $caPoliciesCache)) {
                    Write-CSPLog -Message "Loading cached conditional access policies for $($tenantConfig.TenantName) from $caPoliciesCache" -Level "INFO"
                    $tenantRawData.ConditionalAccessPolicies = Get-Content -Path $caPoliciesCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting conditional access policies..." -Level "INFO"
                    $tenantRawData.ConditionalAccessPolicies = Get-CSPConditionalAccessPolicies
                    if ($tenantRawData.ConditionalAccessPolicies) {
                        $tenantRawData.ConditionalAccessPolicies | ConvertTo-Json -Depth 10 | Out-File -FilePath $caPoliciesCache -Encoding UTF8
                        Write-CSPLog -Message "Saved extracted conditional access policies for $($tenantConfig.TenantName) to $caPoliciesCache" -Level "INFO"
                    }
                }
                # TODO: Add Auth Method Policies, Auth Strengths, Authorization Policy (with caching)
                
                # Applications (with cache)
                $appsCache = Join-Path $tenantCacheDir "Applications.json"
                if (-not $ForceFresh -and (Test-Path $appsCache)) {
                    Write-CSPLog -Message "Loading cached applications for $($tenantConfig.TenantName) from $appsCache" -Level "INFO"
                    $tenantRawData.Applications = Get-Content -Path $appsCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting applications..." -Level "INFO"
                    $tenantRawData.Applications = Get-CSPApplicationData
                    if ($tenantRawData.Applications) {
                        $tenantRawData.Applications | ConvertTo-Json -Depth 10 | Out-File -FilePath $appsCache -Encoding UTF8
                        Write-CSPLog -Message "Saved extracted applications for $($tenantConfig.TenantName) to $appsCache" -Level "INFO"
                    }
                }
# Service Principals (with cache)
$spCache = Join-Path $tenantCacheDir "ServicePrincipals.json"
if (-not $ForceFresh -and (Test-Path $spCache)) {
    Write-CSPLog -Message "Loading cached service principals for $($tenantConfig.TenantName) from $spCache" -Level "INFO"
    $tenantRawData.ServicePrincipals = Get-Content -Path $spCache | ConvertFrom-Json
} else {
    Write-CSPLog -Message "Extracting service principals..." -Level "INFO"
    $tenantRawData.ServicePrincipals = Get-CSPServicePrincipalData
    if ($tenantRawData.ServicePrincipals) {
        $tenantRawData.ServicePrincipals | ConvertTo-Json -Depth 10 | Out-File -FilePath $spCache -Encoding UTF8
        Write-CSPLog -Message "Saved extracted service principals for $($tenantConfig.TenantName) to $spCache" -Level "INFO"
    }
}
# TODO: Add App Role Assignments (with caching)
                # TODO: Add App Role Assignments
                
                # Devices (with cache)
                $devicesCache = Join-Path $tenantCacheDir "ManagedDevices.json"
                if (-not $ForceFresh -and (Test-Path $devicesCache)) {
                    Write-CSPLog -Message "Loading cached managed devices for $($tenantConfig.TenantName) from $devicesCache" -Level "INFO"
                    $tenantRawData.Devices = Get-Content -Path $devicesCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting managed devices..." -Level "INFO"
                    $tenantRawData.Devices = Get-CSPManagedDeviceData
                    # Handle potential license issues for Intune data gracefully
                    if ($tenantRawData.Devices) {
                         if ($tenantRawData.Devices.PSObject.Properties.Name -contains 'SkippedReason') {
                             $tenantRawData.Devices | ConvertTo-Json -Depth 10 | Out-File -FilePath $devicesCache -Encoding UTF8
                             Write-CSPLog -Message "Saved managed devices skip status for $($tenantConfig.TenantName) to $devicesCache" -Level "INFO"
                         } else {
                             $tenantRawData.Devices | ConvertTo-Json -Depth 10 | Out-File -FilePath $devicesCache -Encoding UTF8
                             Write-CSPLog -Message "Saved extracted managed devices for $($tenantConfig.TenantName) to $devicesCache" -Level "INFO"
                         }
                    } else {
                         # Handle cases where function might return $null or empty on error/skip
                         Write-CSPLog -Message "No managed device data extracted or saved for $($tenantConfig.TenantName)." -Level "INFO"
                         # Optionally save an empty marker to cache
                         @{ SkippedReason = "No data returned" } | ConvertTo-Json -Depth 10 | Out-File -FilePath $devicesCache -Encoding UTF8
                    }
                }
                
                # Security (with cache)
                $riskyUsersCache = Join-Path $tenantCacheDir "RiskyUsers.json"
                if (-not $ForceFresh -and (Test-Path $riskyUsersCache)) {
                    Write-CSPLog -Message "Loading cached risky users for $($tenantConfig.TenantName) from $riskyUsersCache" -Level "INFO"
                    $tenantRawData.RiskyUsers = Get-Content -Path $riskyUsersCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting risky users..." -Level "INFO"
                    $tenantRawData.RiskyUsers = Get-CSPRiskyUsers
                    # Handle potential license issues for Identity Protection data gracefully
                    if ($tenantRawData.RiskyUsers) {
                         if ($tenantRawData.RiskyUsers.PSObject.Properties.Name -contains 'SkippedReason') {
                             $tenantRawData.RiskyUsers | ConvertTo-Json -Depth 10 | Out-File -FilePath $riskyUsersCache -Encoding UTF8
                             Write-CSPLog -Message "Saved risky users skip status for $($tenantConfig.TenantName) to $riskyUsersCache" -Level "INFO"
                         } else {
                             $tenantRawData.RiskyUsers | ConvertTo-Json -Depth 10 | Out-File -FilePath $riskyUsersCache -Encoding UTF8
                             Write-CSPLog -Message "Saved extracted risky users for $($tenantConfig.TenantName) to $riskyUsersCache" -Level "INFO"
                         }
                    } else {
                         Write-CSPLog -Message "No risky user data extracted or saved for $($tenantConfig.TenantName)." -Level "INFO"
                         @{ SkippedReason = "No data returned" } | ConvertTo-Json -Depth 10 | Out-File -FilePath $riskyUsersCache -Encoding UTF8
                    }
                }

                # Risk Detections (with cache)
                $riskDetectionsCache = Join-Path $tenantCacheDir "RiskDetections.json"
                if (-not $ForceFresh -and (Test-Path $riskDetectionsCache)) {
                    Write-CSPLog -Message "Loading cached risk detections for $($tenantConfig.TenantName) from $riskDetectionsCache" -Level "INFO"
                    $tenantRawData.RiskDetections = Get-Content -Path $riskDetectionsCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting risk detections..." -Level "INFO"
                    $tenantRawData.RiskDetections = Get-CSPRiskDetections
                    # Handle potential license issues for Identity Protection data gracefully
                    if ($tenantRawData.RiskDetections) {
                         if ($tenantRawData.RiskDetections.PSObject.Properties.Name -contains 'SkippedReason') {
                             $tenantRawData.RiskDetections | ConvertTo-Json -Depth 10 | Out-File -FilePath $riskDetectionsCache -Encoding UTF8
                             Write-CSPLog -Message "Saved risk detections skip status for $($tenantConfig.TenantName) to $riskDetectionsCache" -Level "INFO"
                         } else {
                             $tenantRawData.RiskDetections | ConvertTo-Json -Depth 10 | Out-File -FilePath $riskDetectionsCache -Encoding UTF8
                             Write-CSPLog -Message "Saved extracted risk detections for $($tenantConfig.TenantName) to $riskDetectionsCache" -Level "INFO"
                         }
                    } else {
                         Write-CSPLog -Message "No risk detection data extracted or saved for $($tenantConfig.TenantName)." -Level "INFO"
                         @{ SkippedReason = "No data returned" } | ConvertTo-Json -Depth 10 | Out-File -FilePath $riskDetectionsCache -Encoding UTF8
                    }
                }

                # Security Defaults (with cache)
                $secDefaultsCache = Join-Path $tenantCacheDir "SecurityDefaults.json"
                if (-not $ForceFresh -and (Test-Path $secDefaultsCache)) {
                    Write-CSPLog -Message "Loading cached security defaults for $($tenantConfig.TenantName) from $secDefaultsCache" -Level "INFO"
                    $tenantRawData.SecurityDefaults = Get-Content -Path $secDefaultsCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting security defaults..." -Level "INFO"
                    $tenantRawData.SecurityDefaults = Get-CSPSecurityDefaults
                    if ($tenantRawData.SecurityDefaults) {
                        $tenantRawData.SecurityDefaults | ConvertTo-Json -Depth 10 | Out-File -FilePath $secDefaultsCache -Encoding UTF8
                        Write-CSPLog -Message "Saved extracted security defaults for $($tenantConfig.TenantName) to $secDefaultsCache" -Level "INFO"
                    }
                }
                
                # Audit Logs (with cache)
                $dirAuditCache = Join-Path $tenantCacheDir "DirectoryAuditLogs.json"
                if (-not $ForceFresh -and (Test-Path $dirAuditCache)) {
                    Write-CSPLog -Message "Loading cached directory audit logs for $($tenantConfig.TenantName) from $dirAuditCache" -Level "INFO"
                    $tenantRawData.DirectoryAuditLogs = Get-Content -Path $dirAuditCache | ConvertFrom-Json
                } else {
                    Write-CSPLog -Message "Extracting directory audit logs (DaysBack: $($Config.ReportSettings.DaysBack))..." -Level "INFO"
                    $tenantRawData.DirectoryAuditLogs = Get-CSPDirectoryAuditLogs -DaysBack $Config.ReportSettings.DaysBack
                    if ($tenantRawData.DirectoryAuditLogs) {
                        $tenantRawData.DirectoryAuditLogs | ConvertTo-Json -Depth 10 | Out-File -FilePath $dirAuditCache -Encoding UTF8
                        Write-CSPLog -Message "Saved extracted directory audit logs for $($tenantConfig.TenantName) to $dirAuditCache" -Level "INFO"
                    }
                }
# Sign-In Logs (with cache)
$signInCache = Join-Path $tenantCacheDir "SignInLogs.json"
if (-not $ForceFresh -and (Test-Path $signInCache)) {
    Write-CSPLog -Message "Loading cached sign-in logs for $($tenantConfig.TenantName) from $signInCache" -Level "INFO"
    $tenantRawData.SignInLogs = Get-Content -Path $signInCache | ConvertFrom-Json
} else {
    Write-CSPLog -Message "Extracting sign-in logs (DaysBack: $($Config.ReportSettings.DaysBack))..." -Level "INFO"
    $tenantRawData.SignInLogs = Get-CSPSignInLogs -DaysBack $Config.ReportSettings.DaysBack
    if ($tenantRawData.SignInLogs) {
        $tenantRawData.SignInLogs | ConvertTo-Json -Depth 10 | Out-File -FilePath $signInCache -Encoding UTF8
        Write-CSPLog -Message "Saved extracted sign-in logs for $($tenantConfig.TenantName) to $signInCache" -Level "INFO"
    }
}
                $tenantRawData.SignInLogs = Get-CSPSignInLogs -DaysBack $Config.ReportSettings.DaysBack

                # Optionally save raw data to disk (future enhancement)

                # Run Analysis
                Write-CSPLog -Message "Starting v2 analysis for tenant $($tenantConfig.TenantName)" -Level "INFO"
                $insights = Invoke-CSPTenantAnalysis -RawData $tenantRawData -Config $Config

                # Save Insights JSON
                $insightsPath = Join-Path -Path $Config.OutputPath -ChildPath "$($tenantConfig.TenantName)_Insights.json"
                $insights | ConvertTo-Json -Depth 10 | Out-File -FilePath $insightsPath -Encoding UTF8
                Write-CSPLog -Message "Saved Insights JSON to $insightsPath" -Level "INFO"

                # Generate reports
                foreach ($reportType in $tenantReportsToRun) {
                    $currentOperation++
                    $overallProgress = [Math]::Floor(($currentOperation / $totalReports) * 100)
                    
                    # Check if we should skip this report (if resuming and it's already completed)
                    $skipReport = $false
                    if ($Resume -and $StatePath) {
                        $reportState = Get-CSPProcessState -TenantId $tenantConfig.TenantId -ReportType $reportType
                        if ($reportState -and $reportState.Status -eq "Completed") {
                            Write-CSPLog -Message "Report $reportType for tenant $($tenantConfig.TenantName) was already generated successfully. Skipping." -Level "INFO"
                            $skipReport = $true
                        }
                    }
                    
                    if (-not $skipReport) {
                        Write-CSPLog -Message "Generating $reportType report for tenant $($tenantConfig.TenantName)..." -Level "INFO"
                        Write-Progress -Activity "CSP Reporting Process" -Status "Tenant $($tenantConfig.TenantName) - $reportType report ($currentOperation of $totalReports)" -PercentComplete $overallProgress
                        
                        # Common parameters for all report types
                        $reportParams = @{
                            TenantId = $tenantConfig.TenantId
                            TenantName = $tenantConfig.TenantName
                            OutputPath = $Config.OutputPath
                            OutputFormat = $OutputFormat
                        }
                        
                        # Add state path if specified
                        if ($StatePath) {
                            $reportParams.StatePath = $StatePath
                            $reportParams.Resume = $Resume
                        }
                        
                        # Add report-specific parameters
                        switch ($reportType) {
                            "MFA" {
                                $reportParams.IncludeDisabledUsers = $Config.ReportSettings.IncludeDisabledUsers
                                $reportParams.IncludeGuestUsers = $Config.ReportSettings.IncludeGuestUsers
                                $reportResult = Get-CSPMFAReport @reportParams
                            }
                            "AuditLog" {
                                $reportParams.DaysBack = $Config.ReportSettings.DaysBack
                                $reportResult = Get-CSPAuditLogReport @reportParams
                            }
                            "DirectoryInfo" {
                                $reportResult = Get-CSPDirectoryReport @reportParams
                            }
                            "UsageReports" {
                                $period = switch ($Config.ReportSettings.DaysBack) {
                                    { $_ -le 7 } { "D7" }
                                    { $_ -le 30 } { "D30" }
                                    { $_ -le 90 } { "D90" }
                                    default { "D180" }
                                }
                                $reportParams.Period = $period
                                $reportResult = Get-CSPUsageReport @reportParams
                            }
                        }
                        
                        if ($null -eq $reportResult) {
                            Write-CSPLog -Message "Failed to generate $reportType report for tenant $($tenantConfig.TenantName)" -Level "ERROR"
                        }
                        else {
                            Write-CSPLog -Message "Successfully generated $reportType report for tenant $($tenantConfig.TenantName)" -Level "INFO"
                        }
                    }
                }
                
                # Disconnect from the tenant
                Disconnect-CSPTenant
                
                # Update tenant state to completed
                if ($StatePath) {
                    Update-CSPProcessState -TenantId $tenantConfig.TenantId -TenantName $tenantConfig.TenantName -Status "Completed"
                }
            }
        }
        catch {
            Write-CSPLog -Message "Error processing tenant $($tenantConfig.TenantName): $($_.Exception.Message)" -Level "ERROR"
            
            # Update tenant state to failed
            if ($StatePath) {
                Update-CSPProcessState -TenantId $tenantConfig.TenantId -TenantName $tenantConfig.TenantName -Status "Failed" -Data @{
                    Error = $_.Exception.Message
                }
            }
            
            # Attempt to disconnect from the tenant if an error occurred
            try {
                Disconnect-CSPTenant -ErrorAction SilentlyContinue
            }
            catch {
                # Ignore any errors during disconnect
            }
        }
    }
    
    Write-Progress -Activity "CSP Reporting Process" -Status "Completed" -Completed
    Write-CSPLog -Message "CSP Reporting process completed at $(Get-Date)" -Level "INFO"
}
catch {
    Write-CSPLog -Message "An error occurred during the CSP Reporting process: $($_.Exception.Message)" -Level "ERROR"
    Write-Progress -Activity "CSP Reporting Process" -Status "Error" -Completed
}
finally {
    # Clean up and finalize
    Stop-Transcript
}
#endregion