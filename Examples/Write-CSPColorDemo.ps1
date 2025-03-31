<#
.SYNOPSIS
    Demonstrates the enhanced color messaging capabilities of the CSP Reporting framework.

.DESCRIPTION
    This script showcases the visual terminal output features incorporated from the alternative script,
    making it easier for users to see how to use color-coded output in their own scripts.

.NOTES
    File Name      : Write-CSPColorDemo.ps1
    Prerequisite   : PowerShell Core 7.0 or later

.EXAMPLE
    .\Examples\Write-CSPColorDemo.ps1
#>

[CmdletBinding()]
param()

# Script root path and import utility module
$ScriptPath = $PSScriptRoot
$ParentPath = Split-Path -Path $ScriptPath -Parent
$ModulesPath = Join-Path -Path $ParentPath -ChildPath "Modules"

# Import Utilities module
try {
    Import-Module -Name (Join-Path -Path $ModulesPath -ChildPath "Utilities.psm1") -Force
    
    # Initialize terminal colors
    Initialize-CSPTerminalColors
}
catch {
    Write-Host "Failed to import Utilities module: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

#region Demonstrations

# Display header
Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host "  CSP Reporting Color Messaging Demonstration" -ForegroundColor Cyan
Write-Host "==============================================`n" -ForegroundColor Cyan

# Section 1: Basic Write-CSPLog with UseColor
Write-Host "Demonstration 1: Basic Write-CSPLog with UseColor" -ForegroundColor Magenta
Write-Host "------------------------------------------------" -ForegroundColor Magenta

Write-CSPLog -Message "This is an INFO message with color" -Level "INFO" -UseColor
Write-CSPLog -Message "This is a SUCCESS message with color" -Level "SUCCESS" -UseColor
Write-CSPLog -Message "This is a WARNING message with color" -Level "WARNING" -UseColor
Write-CSPLog -Message "This is an ERROR message with color" -Level "ERROR" -UseColor
Write-CSPLog -Message "This is a DEBUG message with color" -Level "DEBUG" -UseColor

Write-Host "`nSame messages without color:" -ForegroundColor Gray
Write-CSPLog -Message "This is an INFO message without color" -Level "INFO"
Write-CSPLog -Message "This is a SUCCESS message without color" -Level "SUCCESS"
Write-CSPLog -Message "This is a WARNING message without color" -Level "WARNING"
Write-CSPLog -Message "This is an ERROR message without color" -Level "ERROR"
Write-CSPLog -Message "This is a DEBUG message without color" -Level "DEBUG"

# Section 2: Write-CSPColorMessage with predefined types
Write-Host "`n`nDemonstration 2: Write-CSPColorMessage with predefined types" -ForegroundColor Magenta
Write-Host "--------------------------------------------------------" -ForegroundColor Magenta

Write-CSPColorMessage -Message "This is an Info message with cyan background" -Type Info
Write-CSPColorMessage -Message "This is a Success message with green background" -Type Success
Write-CSPColorMessage -Message "This is a Warning message with yellow background" -Type Warning
Write-CSPColorMessage -Message "This is an Error message with red background" -Type Error

# Section 3: Write-CSPColorMessage with custom colors
Write-Host "`n`nDemonstration 3: Write-CSPColorMessage with custom colors" -ForegroundColor Magenta
Write-Host "-------------------------------------------------------" -ForegroundColor Magenta

Write-CSPColorMessage -Message "White text on blue background" -ForegroundColor White -BackgroundColor Blue
Write-CSPColorMessage -Message "Yellow text on dark green background" -ForegroundColor Yellow -BackgroundColor DarkGreen
Write-CSPColorMessage -Message "Magenta text on gray background" -ForegroundColor Magenta -BackgroundColor Gray
Write-CSPColorMessage -Message "Cyan text on dark red background" -ForegroundColor Cyan -BackgroundColor DarkRed

# Section 4: Terminal Color Manipulation
Write-Host "`n`nDemonstration 4: Terminal Color Manipulation" -ForegroundColor Magenta
Write-Host "-----------------------------------------" -ForegroundColor Magenta

Write-Host "Original terminal colors"

# Change terminal colors
Set-CSPTerminalColors -ForegroundColor Yellow -BackgroundColor DarkBlue
Write-Host "Terminal colors changed to yellow text on dark blue background"
Write-Host "Notice how this text appears with the new colors"
Write-Host "Multiple lines of text will use these colors"
Write-Host "Until we restore the original colors"

# Restore original colors
Set-CSPTerminalColors -RestoreOriginal
Write-Host "Original terminal colors restored"

# Section 5: Practical Examples
Write-Host "`n`nDemonstration 5: Practical Examples" -ForegroundColor Magenta
Write-Host "-----------------------------------" -ForegroundColor Magenta

# Example of a status indicator
Write-Host "`nExample: Status indicators for operations"
Write-CSPColorMessage -Message " SUCCESS " -Type Success
Write-Host " Operation completed successfully" -ForegroundColor Gray
Write-CSPColorMessage -Message " WARNING " -Type Warning
Write-Host " Some issues were encountered" -ForegroundColor Gray
Write-CSPColorMessage -Message " ERROR " -Type Error
Write-Host " Operation failed" -ForegroundColor Gray
Write-CSPColorMessage -Message " INFO " -Type Info
Write-Host " Additional information available" -ForegroundColor Gray

# Example of a process with status updates
Write-Host "`nExample: Process with status updates"
Write-CSPLog -Message "Starting tenant processing operation..." -Level "INFO" -UseColor
Write-CSPLog -Message "Connecting to tenant 'contoso.onmicrosoft.com'..." -Level "INFO" -UseColor
Write-CSPLog -Message "Connection established successfully" -Level "SUCCESS" -UseColor
Write-CSPLog -Message "Retrieving user data..." -Level "INFO" -UseColor
Write-CSPLog -Message "Certificate will expire in 30 days" -Level "WARNING" -UseColor
Write-CSPLog -Message "Retrieved data for 250 users" -Level "SUCCESS" -UseColor
Write-CSPLog -Message "Failed to retrieve audit logs: Access denied" -Level "ERROR" -UseColor
Write-CSPLog -Message "Operation completed with warnings" -Level "WARNING" -UseColor

# Section 6: Incorporating in scripts
Write-Host "`n`nIncorporating in Your Scripts" -ForegroundColor Magenta
Write-Host "---------------------------" -ForegroundColor Magenta
Write-Host "To use these color messaging capabilities in your scripts:"
Write-Host "1. Import the Utilities module: Import-Module -Name 'Modules\Utilities.psm1'"
Write-Host "2. Initialize terminal colors: Initialize-CSPTerminalColors"
Write-Host "3. Use Write-CSPLog with -UseColor or Write-CSPColorMessage in your scripts"
Write-Host "4. Restore terminal colors at the end: Set-CSPTerminalColors -RestoreOriginal"

# Footer
Write-Host "`n======================================================" -ForegroundColor Cyan
Write-Host "  End of Color Messaging Demonstration" -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# Restore terminal colors (important to do at the end of scripts)
Set-CSPTerminalColors -RestoreOriginal

#endregion