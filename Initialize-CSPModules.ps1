<#
.SYNOPSIS
    Helper script to initialize and validate all required modules for the CSP Reporting framework.

.DESCRIPTION
    This script demonstrates the enhanced module management capabilities of the CSP Reporting framework.
    It checks for all required modules, installs or updates them as needed, and removes older versions.
    This functionality was inspired by the module management approach from the alternative script.

.NOTES
    File Name      : Initialize-CSPModules.ps1
    Prerequisite   : PowerShell Core 7.0 or later

.EXAMPLE
    .\Initialize-CSPModules.ps1

.EXAMPLE
    .\Initialize-CSPModules.ps1 -Force
#>

[CmdletBinding()]
param (
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

# Import Utilities module which contains our module management functions
try {
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Utilities.psm1") -Force
    
    # Initialize terminal colors for enhanced UI
    Initialize-CSPTerminalColors
}
catch {
    Write-Host "Failed to import Utilities module: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
#endregion

#region Main Execution
try {
    # Display script header
    Write-CSPColorMessage -Message "`n===== CSP Reporting Module Initialization =====" -Type Info
    Write-CSPColorMessage -Message "This script will check and initialize all required modules for the CSP Reporting framework.`n" -ForegroundColor White
    
    # Define required modules
    $requiredModules = @(
        "Microsoft.Graph.Authentication",
        "Microsoft.Graph.Applications", 
        "Microsoft.Graph.Identity.DirectoryManagement",
        "Microsoft.Graph.Users",
        "Microsoft.Graph.Reports",
        "Microsoft.Graph.Identity.SignIns"
    )
    
    Write-CSPLog -Message "Checking for $($requiredModules.Count) required modules..." -Level "INFO" -UseColor
    
    # Initialize modules
    $moduleResults = Initialize-CSPModules -ModuleNames $requiredModules -Force:$Force
    
    # Display results
    Write-CSPColorMessage -Message "`n===== Module Initialization Results =====" -Type Info
    
    $installedCount = ($moduleResults | Where-Object { $_.Status -eq "Installed" }).Count
    $updatedCount = ($moduleResults | Where-Object { $_.Status -eq "Updated" }).Count
    $upToDateCount = ($moduleResults | Where-Object { $_.Status -eq "UpToDate" }).Count
    $errorCount = ($moduleResults | Where-Object { $_.Status -eq "Error" }).Count
    
    Write-CSPLog -Message "Modules installed: $installedCount" -Level "INFO" -UseColor
    Write-CSPLog -Message "Modules updated: $updatedCount" -Level "INFO" -UseColor
    Write-CSPLog -Message "Modules already up to date: $upToDateCount" -Level "INFO" -UseColor
    
    if ($errorCount -gt 0) {
        Write-CSPLog -Message "Modules with errors: $errorCount" -Level "ERROR" -UseColor
        $moduleResults | Where-Object { $_.Status -eq "Error" } | ForEach-Object {
            Write-CSPLog -Message "  - $($_.ModuleName): $($_.ErrorMessage)" -Level "ERROR" -UseColor
        }
    }
    
    Write-CSPColorMessage -Message "`nModule details:" -ForegroundColor White
    $moduleResults | Format-Table -Property ModuleName, Status, Version, @{Name="Previous Version"; Expression={$_.PreviousVersion}} -AutoSize
    
    # Final message
    if ($errorCount -eq 0) {
        Write-CSPLog -Message "`nAll required modules have been successfully initialized" -Level "SUCCESS" -UseColor
        Write-CSPLog -Message "The CSP Reporting framework is ready to use" -Level "SUCCESS" -UseColor
    }
    else {
        Write-CSPLog -Message "`nSome modules could not be initialized properly" -Level "WARNING" -UseColor
        Write-CSPLog -Message "Please resolve the issues before using the CSP Reporting framework" -Level "WARNING" -UseColor
    }
    
    # Restore terminal colors
    Set-CSPTerminalColors -RestoreOriginal
}
catch {
    Write-CSPLog -Message "An error occurred during module initialization: $($_.Exception.Message)" -Level "ERROR" -UseColor
    
    # Restore terminal colors
    Set-CSPTerminalColors -RestoreOriginal
    exit 1
}
#endregion