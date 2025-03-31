<#
.SYNOPSIS
    Script for scheduling the CSP Reporting solution.

.DESCRIPTION
    This script sets up scheduled tasks to automate the execution of the CSP Reporting solution.
    It can create, update, or remove scheduled tasks for different reporting frequencies.

.NOTES
    File Name      : Schedule-CSPReporting.ps1
    Prerequisite   : PowerShell Core 7.0 or later
                     Administrative privileges (for creating scheduled tasks)

.EXAMPLE
    .\Schedule-CSPReporting.ps1 -Action Create -Frequency Daily -Time "03:00" -ReportTypes MFA,AuditLog
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Create", "Update", "Remove")]
    [string]$Action,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Daily", "Weekly", "Monthly")]
    [string]$Frequency = "Daily",
    
    [Parameter(Mandatory = $false)]
    [string]$Time = "03:00",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("MFA", "AuditLog", "DirectoryInfo", "UsageReports", "All")]
    [string[]]$ReportTypes = @("All"),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$OutputFormat = "CSV",
    
    [Parameter(Mandatory = $false)]
    [string]$TaskName = "CSP_Reporting",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = ".\Config.psd1",
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

#region Script Initialization
# Set strict mode to catch common errors
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Script root path
$ScriptPath = $PSScriptRoot
$MainScriptPath = Join-Path -Path $ScriptPath -ChildPath "Start-CSPReporting.ps1"

# Check if running with administrative privileges
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Warning "This script requires administrative privileges to create scheduled tasks."
    Write-Warning "Please run PowerShell as Administrator and try again."
    exit 1
}

# Check if the main script exists
if (-not (Test-Path -Path $MainScriptPath)) {
    Write-Error "Main script not found: $MainScriptPath"
    exit 1
}
#endregion

#region Helper Functions
function Get-TaskTrigger {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Frequency,
        
        [Parameter(Mandatory = $true)]
        [string]$Time
    )
    
    try {
        # Parse the time
        $timeComponents = $Time -split ":"
        $hour = [int]$timeComponents[0]
        $minute = [int]$timeComponents[1]
        
        # Create the trigger based on frequency
        switch ($Frequency) {
            "Daily" {
                $trigger = New-ScheduledTaskTrigger -Daily -At "$hour`:$minute"
            }
            "Weekly" {
                $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At "$hour`:$minute"
            }
            "Monthly" {
                $trigger = New-ScheduledTaskTrigger -Monthly -DaysOfMonth 1 -At "$hour`:$minute"
            }
            default {
                throw "Unsupported frequency: $Frequency"
            }
        }
        
        return $trigger
    }
    catch {
        Write-Error "Error in Get-TaskTrigger: $_"
        return $null
    }
}
#endregion

#region Main Execution
try {
    # Prepare the command to run
    $pwshPath = (Get-Command pwsh).Source
    $reportTypesArg = $ReportTypes -join ","
    
    $scriptArguments = "-ExecutionPolicy Bypass -NoProfile -File `"$MainScriptPath`" -ConfigPath `"$ConfigPath`" -ReportTypes $reportTypesArg -OutputFormat $OutputFormat"
    
    # Create the action
    $taskAction = New-ScheduledTaskAction -Execute $pwshPath -Argument $scriptArguments -WorkingDirectory $ScriptPath
    
    # Create the principal (run with highest privileges)
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Create the settings
    $taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    
    # Handle the requested action
    switch ($Action) {
        "Create" {
            # Check if the task already exists
            $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            
            if ($existingTask -and -not $Force) {
                Write-Warning "A scheduled task with the name '$TaskName' already exists."
                Write-Warning "Use -Action Update to update the existing task or -Force to overwrite it."
                exit 1
            }
            
            # Create the trigger
            $taskTrigger = Get-TaskTrigger -Frequency $Frequency -Time $Time
            
            if (-not $taskTrigger) {
                Write-Error "Failed to create task trigger."
                exit 1
            }
            
            # Register the task
            if ($existingTask -and $Force) {
                Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            }
            
            $task = Register-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings
            
            Write-Host "Scheduled task '$TaskName' created successfully." -ForegroundColor Green
            Write-Host "Task will run $Frequency at $Time." -ForegroundColor Green
        }
        "Update" {
            # Check if the task exists
            $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            
            if (-not $existingTask) {
                Write-Warning "No scheduled task with the name '$TaskName' exists."
                Write-Warning "Use -Action Create to create a new task."
                exit 1
            }
            
            # Create the trigger
            $taskTrigger = Get-TaskTrigger -Frequency $Frequency -Time $Time
            
            if (-not $taskTrigger) {
                Write-Error "Failed to create task trigger."
                exit 1
            }
            
            # Update the task
            $task = Set-ScheduledTask -TaskName $TaskName -Action $taskAction -Trigger $taskTrigger -Principal $taskPrincipal -Settings $taskSettings
            
            Write-Host "Scheduled task '$TaskName' updated successfully." -ForegroundColor Green
            Write-Host "Task will run $Frequency at $Time." -ForegroundColor Green
        }
        "Remove" {
            # Check if the task exists
            $existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
            
            if (-not $existingTask) {
                Write-Warning "No scheduled task with the name '$TaskName' exists."
                exit 0
            }
            
            # Remove the task
            Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
            
            Write-Host "Scheduled task '$TaskName' removed successfully." -ForegroundColor Green
        }
    }
}
catch {
    Write-Error "An error occurred: $_"
    exit 1
}
#endregion