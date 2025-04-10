<#
.SYNOPSIS
    Logging and progress reporting functions for CSP Reporting.
#>

function Write-CSPProgress {
    <#
    .SYNOPSIS
        Writes progress information.
    .DESCRIPTION
        Writes progress information for a long-running operation.
    .PARAMETER Activity
        The activity description.
    .PARAMETER Status
        The current status.
    .PARAMETER PercentComplete
        The percentage complete.
    .PARAMETER TenantId
        The tenant ID for which progress is being reported.
    .PARAMETER ReportType
        The report type for which progress is being reported.
    .PARAMETER Completed
        If specified, indicates that the operation is complete.
    .EXAMPLE
        Write-CSPProgress -Activity "Retrieving MFA Status" -Status "Processing user 10 of 100" -PercentComplete 10 -TenantId "tenant1.onmicrosoft.com" -ReportType "MFA"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        
        [Parameter(Mandatory = $true)]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [int]$PercentComplete = -1,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportType,
        
        [Parameter(Mandatory = $false)]
        [switch]$Completed
    )
    
    try {
        # Update process state if tenant and report type are provided
        if ($TenantId -and $ReportType) {
            $tenantName = if ($script:ProcessState.ProcessedTenants[$TenantId]) {
                $script:ProcessState.ProcessedTenants[$TenantId].TenantName
            } else {
                $TenantId
            }
            
            $state = "InProgress"
            if ($Completed) {
                $state = "Completed"
            }
            
            Update-CSPProcessState -TenantId $TenantId -TenantName $tenantName -ReportType $ReportType -Status $state -Data @{
                PercentComplete = $PercentComplete
                Status = $Status
            }
        }
        
        # Write progress
        if ($Completed) {
            Write-Progress -Activity $Activity -Completed
        }
        else {
            Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
        }
    }
    catch {
        Write-Error "Error in Write-CSPProgress: $_"
    }
}

function Write-CSPLog {
    <#
    .SYNOPSIS
        Writes a log message to a log file and optionally to the console.
    .DESCRIPTION
        Writes a log message to a log file and optionally to the console with timestamp and severity level.
    .PARAMETER Message
        The message to log.
    .PARAMETER Level
        The severity level of the message. Valid values are "INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS".
    .PARAMETER LogFilePath
        The path to the log file. If not provided, no file logging will occur.
    .PARAMETER NoConsole
        If specified, the message will not be written to the console.
    .PARAMETER UseColor
        If specified, use color-coded console output.
    .EXAMPLE
        Write-CSPLog -Message "Processing tenant" -Level "INFO" -LogFilePath "C:\Logs\CSPReporting.log"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory = $false)]
        [string]$LogFilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseColor
    )
    
    try {
        # Format the log message
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
        
        # Write to console if not suppressed
        if (-not $NoConsole) {
            if ($UseColor) {
                # Use color coding based on level
                switch ($Level) {
                    "INFO" { Write-CSPColorMessage -Message $logMessage -ForegroundColor White }
                    "WARNING" { Write-CSPColorMessage -Message $logMessage -ForegroundColor Yellow }
                    "ERROR" { Write-CSPColorMessage -Message $logMessage -ForegroundColor Red }
                    "DEBUG" { Write-CSPColorMessage -Message $logMessage -ForegroundColor Gray }
                    "SUCCESS" { Write-CSPColorMessage -Message $logMessage -ForegroundColor Green }
                    default { Write-Host $logMessage }
                }
            }
            else {
                # Use standard Write-Host with colors
                switch ($Level) {
                    "INFO" { Write-Host $logMessage -ForegroundColor White }
                    "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
                    "ERROR" { Write-Host $logMessage -ForegroundColor Red }
                    "DEBUG" { Write-Host $logMessage -ForegroundColor Gray }
                    "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
                    default { Write-Host $logMessage }
                }
            }
        }
        
        # Write to log file if path is provided
        if ($LogFilePath) {
            # Create the directory if it doesn't exist
            $logDir = Split-Path -Path $LogFilePath -Parent
            if (-not (Test-Path -Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            
            # Append to the log file
            Add-Content -Path $LogFilePath -Value $logMessage -Encoding UTF8
        }
    }
    catch {
        Write-Error "Error in Write-CSPLog: $_"
    }
}

# The rest of the console color functions remain unchanged
# (Initialize-CSPTerminalColors, Set-CSPTerminalColors, Write-CSPColorMessage)

Export-ModuleMember -Function Write-CSPProgress, Write-CSPLog, Initialize-CSPTerminalColors, Set-CSPTerminalColors, Write-CSPColorMessage