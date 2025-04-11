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
    # Create a log file for debugging
    $logFile = Join-Path -Path $PSScriptRoot -ChildPath "module_init_debug.log"
    "Debug log started at $(Get-Date)" | Out-File -FilePath $logFile -Force
    
    # Function to write to both console and log file
    function Write-DebugLog {
        param([string]$Message)
        $Message | Out-File -FilePath $logFile -Append
        Write-Host $Message
    }
    
    Write-DebugLog "===== CSP Reporting Module Initialization ====="
    Write-DebugLog "This script will check and initialize all required modules for the CSP Reporting framework.`n"
    
    # Define required modules
    $requiredModules = @(
        @{ ModuleName = "Microsoft.Graph.Authentication"; RequiredVersion = "2.25.0" },
        @{ ModuleName = "Microsoft.Graph.Applications"; RequiredVersion = "2.25.0" },
        @{ ModuleName = "Microsoft.Graph.Identity.DirectoryManagement"; RequiredVersion = "2.25.0" },
        @{ ModuleName = "Microsoft.Graph.Users"; RequiredVersion = "2.25.0" },
        @{ ModuleName = "Microsoft.Graph.Reports"; RequiredVersion = "2.25.0" },
        @{ ModuleName = "Microsoft.Graph.Identity.SignIns"; RequiredVersion = "2.25.0" }
    )
    
    Write-CSPLog -Message "Checking for $($requiredModules.Count) required modules..." -Level "INFO" -UseColor
    
    # Initialize modules
    $moduleResults = Initialize-CSPModules -ModuleSpecs $requiredModules -Force:$Force
    
    # Display results
    Write-CSPColorMessage -Message "`n===== Module Initialization Results =====" -Type Info
    
    # Debug: Log the module results to understand what's being returned
    Write-DebugLog "Module results type: $($moduleResults.GetType().FullName)"
    Write-DebugLog "Module results count: $($moduleResults.Count)"
    Write-DebugLog "Module results dump:"
    
    $index = 0
    foreach ($result in $moduleResults) {
        Write-DebugLog "Result [$index]:"
        if ($null -eq $result) {
            Write-DebugLog "  - NULL RESULT"
            $index++
            continue
        }
        # Get properties safely
        $memberProps = $result | Get-Member -MemberType Properties
        if ($null -eq $memberProps) {
            $properties = "No properties found"
            Write-DebugLog "  - Properties: None (object type: $($result.GetType().FullName))"
        } else {
            $properties = $memberProps.Name -join ', '
            Write-DebugLog "  - Properties: $properties"
        }
        Write-DebugLog "  - Properties: $properties"
        
        # Only check for specific properties if we have properties
        if ($properties -ne "No properties found") {
            # Check if ModuleName property exists
            if (Get-Member -InputObject $result -Name "ModuleName" -MemberType Properties) {
                Write-DebugLog "  - ModuleName: $($result.ModuleName)"
            } else {
                Write-DebugLog "  - NO ModuleName property"
            }
            
            # Check if Status property exists
            if (Get-Member -InputObject $result -Name "Status" -MemberType Properties) {
                Write-DebugLog "  - Status: $($result.Status)"
            } else {
                Write-DebugLog "  - NO Status property"
            }
        } else {
            Write-DebugLog "  - Cannot check for specific properties as object has no properties"
        }
        
        # Dump the object as JSON
        try {
            $json = $result | ConvertTo-Json -Depth 1 -ErrorAction Stop
            Write-DebugLog "  - JSON: $json"
        } catch {
            Write-DebugLog "  - Could not convert to JSON: $($_.Exception.Message)"
            Write-DebugLog "  - ToString: $($result.ToString())"
        }
        
        $index++
    }
    
    # Add null check and property validation
    if ($null -eq $moduleResults) {
        Write-CSPLog -Message "Module results is null" -Level "ERROR" -UseColor
        $installedCount = 0
        $updatedCount = 0
        $upToDateCount = 0
        $errorCount = 0
    } else {
        # Only process objects that have a Status property
        $validModules = $moduleResults | Where-Object {
            $_ -ne $null -and
            $_.GetType().Name -eq "PSCustomObject" -and
            (Get-Member -InputObject $_ -Name "Status" -MemberType Properties)
        }
        
        Write-DebugLog "Found $($validModules.Count) valid module objects with Status property"
        
        $installedCount = ($validModules | Where-Object { $_.Status -eq "Installed" }).Count
        $updatedCount = ($validModules | Where-Object { $_.Status -eq "Updated" }).Count
        $upToDateCount = ($validModules | Where-Object { $_.Status -eq "UpToDate" }).Count
        $errorCount = ($validModules | Where-Object { $_.Status -eq "Error" }).Count
    }
    
    Write-CSPLog -Message "Modules installed: $installedCount" -Level "INFO" -UseColor
    Write-CSPLog -Message "Modules updated: $updatedCount" -Level "INFO" -UseColor
    Write-CSPLog -Message "Modules already up to date: $upToDateCount" -Level "INFO" -UseColor
    
    if ($errorCount -gt 0) {
        Write-CSPLog -Message "Modules with errors: $errorCount" -Level "ERROR" -UseColor
        $validModules | Where-Object { $_.Status -eq "Error" } | ForEach-Object {
            Write-CSPLog -Message "  - $($_.ModuleName): $($_.ErrorMessage)" -Level "ERROR" -UseColor
        }
    }
    
    Write-CSPColorMessage -Message "`nModule details:" -ForegroundColor White
    $validModules | Format-Table -Property ModuleName, Status, Version, @{Name="Previous Version"; Expression={$_.PreviousVersion}} -AutoSize
    
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
    # Get detailed error information
    $errorMessage = $_.Exception.Message
    $errorType = $_.Exception.GetType().FullName
    $errorPosition = $_.InvocationInfo.PositionMessage
    
    Write-DebugLog "ERROR: An error occurred during module initialization: $errorMessage"
    Write-DebugLog "ERROR: Error type: $errorType"
    Write-DebugLog "ERROR: Error position: $errorPosition"
    Write-DebugLog "ERROR: Full exception: $($_ | Out-String)"
    
    # If it's a property not found error, provide more specific guidance
    if ($errorMessage -like "*property*cannot be found*") {
        Write-DebugLog "ERROR: This appears to be a property access error. Check if all objects have the expected properties."
        
        # If we have $moduleResults, inspect it
        if ($moduleResults) {
            Write-DebugLog "Module results inspection in error handler:"
            Write-DebugLog "Module results type: $($moduleResults.GetType().FullName)"
            Write-DebugLog "Module results count: $($moduleResults.Count)"
            
            $index = 0
            foreach ($result in $moduleResults) {
                Write-DebugLog "Error handler - Result [$index]:"
                if ($result -ne $null) {
                    # Get properties safely
                    $memberProps = $result | Get-Member -MemberType Properties
                    if ($null -eq $memberProps) {
                        $properties = "No properties found"
                        Write-DebugLog "  - Properties: None (object type: $($result.GetType().FullName))"
                    } else {
                        $properties = $memberProps.Name -join ', '
                        Write-DebugLog "  - Properties: $properties"
                    }
                    
                    # Dump the object as string
                    Write-DebugLog "  - ToString: $($result.ToString())"
                    Write-DebugLog "  - GetType: $($result.GetType().FullName)"
                    
                    # Try to access properties safely
                    if ($properties -ne "No properties found") {
                        foreach ($prop in $memberProps.Name) {
                            try {
                                $value = $result.$prop
                                Write-DebugLog "  - $prop = $value"
                            } catch {
                                $exMsg = $_.Exception.Message
                                Write-DebugLog "  - Could not access property $prop`: $exMsg"
                            }
                        }
                    } else {
                        Write-DebugLog "  - No properties to access"
                    }
                } else {
                    Write-DebugLog "  - NULL RESULT"
                }
                $index++
            }
        } else {
            Write-DebugLog "No module results available for inspection"
        }
    }
    
    # Restore terminal colors
    Set-CSPTerminalColors -RestoreOriginal
    exit 1
}
#endregion