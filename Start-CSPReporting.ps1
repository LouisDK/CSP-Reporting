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
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Auth.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Reports.psm1") -Force
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Utilities.psm1") -Force
    
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
        "AppRegistration", 
        "ReportSettings"
    )
    
    foreach ($setting in $requiredSettings) {
        if (-not $Config.ContainsKey($setting)) {
            throw "Required configuration setting '$setting' is missing"
        }
    }
    
    # Validate app registration settings
    if (-not $Config.AppRegistration.ContainsKey("ClientId")) {
        throw "Required configuration setting 'AppRegistration.ClientId' is missing"
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
                    ClientId = $Config.AppRegistration.ClientId
                }
                
                # Add authentication method parameters
                $authMethod = if ($tenantConfig.ContainsKey("AuthMethod")) { 
                    $tenantConfig.AuthMethod 
                } else { 
                    $Config.DefaultAuthMethod 
                }
                
                if ($authMethod -eq "Certificate") {
                    $authParams.CertificatePath = $tenantConfig.CertificatePath
                    $authParams.CertificatePassword = $tenantConfig.CertificatePassword
                    $authParams.AuthMethod = "Certificate"
                }
                else {
                    $authParams.ClientSecret = $tenantConfig.ClientSecret
                    $authParams.AuthMethod = "ClientSecret"
                }
                
                # Use retry logic for authentication
                $authResult = Invoke-CSPWithRetry -ScriptBlock {
                    Connect-CSPTenant @authParams
                } -ActivityName "Authenticate to tenant $($tenantConfig.TenantName)" -MaxRetries 2
                
                if (-not $authResult.Success) {
                    Write-CSPLog -Message "Authentication failed for tenant $($tenantConfig.TenantName): $($authResult.ErrorMessage)" -Level "ERROR"
                    
                    # Update state to failed
                    if ($StatePath) {
                        Update-CSPProcessState -TenantId $tenantConfig.TenantId -TenantName $tenantConfig.TenantName -Status "Failed" -Data @{
                            Error = "Authentication failed: $($authResult.ErrorMessage)"
                        }
                    }
                    
                    continue
                }
                
                Write-CSPLog -Message "Successfully authenticated to tenant $($tenantConfig.TenantName)" -Level "INFO"
                
                # Generate reports
                foreach ($reportType in $reportsToRun) {
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