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

.NOTES
    File Name      : Start-CSPReporting.ps1
    Prerequisite   : PowerShell Core 7.0 or later
                     Microsoft Graph PowerShell SDK
                     Appropriate permissions in each tenant

.EXAMPLE
    .\Start-CSPReporting.ps1 -ConfigPath .\Config.psd1 -ReportTypes MFA,AuditLog -OutputFormat CSV
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
    $requiredSettings = @("TenantConfigs", "OutputPath", "DefaultAuthMethod")
    foreach ($setting in $requiredSettings) {
        if (-not $Config.ContainsKey($setting)) {
            throw "Required configuration setting '$setting' is missing"
        }
    }
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $Config.OutputPath)) {
        New-Item -Path $Config.OutputPath -ItemType Directory -Force | Out-Null
        Write-Verbose "Created output directory: $($Config.OutputPath)"
    }
}
catch {
    Write-Error "Failed to load configuration: $_"
    exit 1
}
#endregion

#region Main Execution
try {
    # Initialize logging
    $logFile = Join-Path -Path $Config.OutputPath -ChildPath "CSPReporting_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $logFile -Append
    
    Write-Host "Starting CSP Reporting process at $(Get-Date)" -ForegroundColor Green
    
    # Process each tenant
    foreach ($tenantConfig in $Config.TenantConfigs) {
        try {
            Write-Host "Processing tenant: $($tenantConfig.TenantName)" -ForegroundColor Cyan
            
            # Authenticate to the tenant
            $authParams = @{
                TenantId = $tenantConfig.TenantId
                ClientId = $Config.AppRegistration.ClientId
                CertificatePath = $tenantConfig.CertificatePath
                CertificatePassword = $tenantConfig.CertificatePassword
                ClientSecret = $tenantConfig.ClientSecret
                AuthMethod = if ($tenantConfig.AuthMethod) { $tenantConfig.AuthMethod } else { $Config.DefaultAuthMethod }
            }
            
            $authResult = Connect-CSPTenant @authParams
            
            if (-not $authResult.Success) {
                Write-Warning "Authentication failed for tenant $($tenantConfig.TenantName): $($authResult.ErrorMessage)"
                continue
            }
            
            Write-Verbose "Successfully authenticated to tenant $($tenantConfig.TenantName)"
            
            # Determine which reports to generate
            $reportsToRun = if ($ReportTypes -contains "All") {
                @("MFA", "AuditLog", "DirectoryInfo", "UsageReports")
            } else {
                $ReportTypes
            }
            
            # Generate reports
            foreach ($reportType in $reportsToRun) {
                Write-Host "  Generating $reportType report..." -ForegroundColor Yellow
                
                $reportParams = @{
                    TenantId = $tenantConfig.TenantId
                    TenantName = $tenantConfig.TenantName
                    OutputPath = $Config.OutputPath
                    OutputFormat = $OutputFormat
                    DaysBack = $Config.ReportSettings.DaysBack
                }
                
                switch ($reportType) {
                    "MFA" {
                        Get-CSPMFAReport @reportParams
                    }
                    "AuditLog" {
                        Get-CSPAuditLogReport @reportParams
                    }
                    "DirectoryInfo" {
                        Get-CSPDirectoryReport @reportParams
                    }
                    "UsageReports" {
                        Get-CSPUsageReport @reportParams
                    }
                }
                
                Write-Host "  Completed $reportType report" -ForegroundColor Green
            }
            
            # Disconnect from the tenant
            Disconnect-CSPTenant
        }
        catch {
            Write-Error "Error processing tenant $($tenantConfig.TenantName): $_"
        }
    }
    
    Write-Host "CSP Reporting process completed at $(Get-Date)" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during the CSP Reporting process: $_"
}
finally {
    # Clean up and finalize
    Stop-Transcript
}
#endregion