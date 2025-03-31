<#
.SYNOPSIS
    Sample script for generating reports for a specific tenant.

.DESCRIPTION
    This script demonstrates how to use the CSP Reporting solution to generate
    reports for a specific tenant. It can be used as a template for creating
    custom reporting scripts.

.NOTES
    File Name      : Generate-TenantReport.ps1
    Prerequisite   : PowerShell Core 7.0 or later
                     Microsoft Graph PowerShell SDK
                     CSP Reporting solution

.EXAMPLE
    .\Generate-TenantReport.ps1 -TenantId "contoso.onmicrosoft.com" -ReportTypes MFA,AuditLog -OutputFormat CSV
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$TenantId,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("MFA", "AuditLog", "DirectoryInfo", "UsageReports", "All")]
    [string[]]$ReportTypes = @("All"),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$OutputFormat = "CSV",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "..\Config.psd1",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath,
    
    [Parameter(Mandatory = $false)]
    [int]$DaysBack = 30
)

#region Script Initialization
# Set strict mode to catch common errors
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script root path
$ScriptPath = $PSScriptRoot
$RootPath = Split-Path -Path $ScriptPath -Parent
$ModulesPath = Join-Path -Path $RootPath -ChildPath "Modules"

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
    $requiredSettings = @("AppRegistration", "TenantConfigs")
    foreach ($setting in $requiredSettings) {
        if (-not $Config.ContainsKey($setting)) {
            throw "Required configuration setting '$setting' is missing"
        }
    }
    
    # Find the tenant configuration
    $tenantConfig = $Config.TenantConfigs | Where-Object { $_.TenantId -eq $TenantId }
    
    if (-not $tenantConfig) {
        throw "Tenant $TenantId not found in configuration"
    }
    
    # Set output path
    if (-not $OutputPath) {
        $OutputPath = $Config.OutputPath
    }
    
    # Create output directory if it doesn't exist
    if (-not (Test-Path -Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        Write-Verbose "Created output directory: $OutputPath"
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
    $logFile = Join-Path -Path $OutputPath -ChildPath "TenantReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
    Start-Transcript -Path $logFile -Append
    
    Write-Host "Starting report generation for tenant $($tenantConfig.TenantName) at $(Get-Date)" -ForegroundColor Green
    
    # Authenticate to the tenant
    Write-Host "Authenticating to tenant $($tenantConfig.TenantName)..." -ForegroundColor Cyan
    
    $authParams = @{
        TenantId = $tenantConfig.TenantId
        ClientId = $Config.AppRegistration.ClientId
    }
    
    if ($tenantConfig.AuthMethod -eq "Certificate") {
        if (-not $tenantConfig.CertificatePath -or -not (Test-Path -Path $tenantConfig.CertificatePath)) {
            throw "Certificate path is invalid or not provided for tenant $($tenantConfig.TenantName)"
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
        throw "Authentication failed for tenant $($tenantConfig.TenantName): $($authResult.ErrorMessage)"
    }
    
    Write-Host "Successfully authenticated to tenant $($tenantConfig.TenantName)" -ForegroundColor Green
    
    # Determine which reports to generate
    $reportsToRun = if ($ReportTypes -contains "All") {
        @("MFA", "AuditLog", "DirectoryInfo", "UsageReports")
    } else {
        $ReportTypes
    }
    
    # Generate reports
    foreach ($reportType in $reportsToRun) {
        Write-Host "Generating $reportType report..." -ForegroundColor Yellow
        
        $reportParams = @{
            TenantId = $tenantConfig.TenantId
            TenantName = $tenantConfig.TenantName
            OutputPath = $OutputPath
            OutputFormat = $OutputFormat
        }
        
        switch ($reportType) {
            "MFA" {
                Get-CSPMFAReport @reportParams
            }
            "AuditLog" {
                $reportParams.DaysBack = $DaysBack
                Get-CSPAuditLogReport @reportParams
            }
            "DirectoryInfo" {
                Get-CSPDirectoryReport @reportParams
            }
            "UsageReports" {
                Get-CSPUsageReport @reportParams
            }
        }
        
        Write-Host "Completed $reportType report" -ForegroundColor Green
    }
    
    # Disconnect from the tenant
    Disconnect-CSPTenant
    
    Write-Host "Report generation for tenant $($tenantConfig.TenantName) completed at $(Get-Date)" -ForegroundColor Green
    
    # Display report location
    Write-Host "Reports saved to: $OutputPath" -ForegroundColor Green
}
catch {
    Write-Error "An error occurred during report generation: $_"
}
finally {
    # Clean up and finalize
    Stop-Transcript
}
#endregion