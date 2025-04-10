<#
.SYNOPSIS
    State management functions for CSP Reporting.
#>

function Initialize-CSPProcessState {
    <#
    .SYNOPSIS
        Initializes or resets the process state tracking.
    .DESCRIPTION
        Initializes or resets the process state used for tracking progress and enabling resumability.
    .PARAMETER StatePath
        Optional path to save the state to disk for persistence across PowerShell sessions.
    .EXAMPLE
        Initialize-CSPProcessState
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$StatePath
    )
    
    try {
        # Initialize process state
        $script:ProcessState = @{
            CurrentTenant = $null
            CurrentReport = $null
            ProcessedTenants = @{}
            StartTime = Get-Date
            LastProgressUpdate = $null
            StatePath = $StatePath
        }
        
        # If state path is provided, check if a previous state exists
        if ($StatePath -and (Test-Path -Path $StatePath)) {
            try {
                $savedState = Import-Clixml -Path $StatePath
                
                # Validate the saved state
                if ($savedState.ProcessedTenants -and $savedState.StartTime) {
                    $script:ProcessState = $savedState
                    $script:ProcessState.LastProgressUpdate = Get-Date
                    
                    return @{
                        Success = $true
                        ResumedFromSave = $true
                        Message = "Process state restored from $StatePath"
                    }
                }
            }
            catch {
                Write-Warning "Could not restore process state from $StatePath. Starting fresh."
            }
        }
        
        return @{
            Success = $true
            ResumedFromSave = $false
            Message = "Process state initialized"
        }
    }
    catch {
        Write-Error "Error in Initialize-CSPProcessState: $_"
        return @{
            Success = $false
            ResumedFromSave = $false
            Message = "Failed to initialize process state: $_"
        }
    }
}

function Update-CSPProcessState {
    <#
    .SYNOPSIS
        Updates the process state with progress information.
    .DESCRIPTION
        Updates the process state to track progress of tenant processing and report generation.
        This enables resumability and progress reporting.
    .PARAMETER TenantId
        The ID of the tenant being processed.
    .PARAMETER TenantName
        The name of the tenant being processed.
    .PARAMETER ReportType
        The type of report being processed.
    .PARAMETER Status
        The status of the process (Started, InProgress, Completed, Failed).
    .PARAMETER Data
        Additional data to store with the process state (e.g., last processed item).
    .EXAMPLE
        Update-CSPProcessState -TenantId "tenant1.onmicrosoft.com" -TenantName "Tenant 1" -ReportType "MFA" -Status "Started"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantName,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportType,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Started", "InProgress", "Completed", "Failed")]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [object]$Data = $null
    )
    
    try {
        # Update current tenant
        $script:ProcessState.CurrentTenant = @{
            TenantId = $TenantId
            TenantName = $TenantName
        }
        
        # Update current report if provided
        if ($ReportType) {
            $script:ProcessState.CurrentReport = $ReportType
        }
        
        # Initialize tenant entry if it doesn't exist
        if (-not $script:ProcessState.ProcessedTenants[$TenantId]) {
            $script:ProcessState.ProcessedTenants[$TenantId] = @{
                TenantName = $TenantName
                Reports = @{}
                Status = "InProgress"
                StartTime = Get-Date
                EndTime = $null
            }
        }
        
        # Update tenant status
        if ($Status -eq "Completed" -or $Status -eq "Failed") {
            $script:ProcessState.ProcessedTenants[$TenantId].Status = $Status
            $script:ProcessState.ProcessedTenants[$TenantId].EndTime = Get-Date
        }
        
        # Update report status if report type is provided
        if ($ReportType) {
            if (-not $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType]) {
                $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType] = @{
                    Status = $Status
                    StartTime = Get-Date
                    EndTime = $null
                    Data = $Data
                }
            }
            else {
                $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType].Status = $Status
                
                if ($Status -eq "Completed" -or $Status -eq "Failed") {
                    $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType].EndTime = Get-Date
                }
                
                if ($Data) {
                    $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType].Data = $Data
                }
            }
        }
        
        # Save state if path is provided
        if ($script:ProcessState.StatePath) {
            # Only save every 10 seconds to avoid excessive disk I/O
            $now = Get-Date
            if (-not $script:ProcessState.LastProgressUpdate -or
                ($now - $script:ProcessState.LastProgressUpdate).TotalSeconds -ge 10) {
                
                $script:ProcessState.LastProgressUpdate = $now
                
                # Clone the state to avoid reference issues
                $stateToSave = [pscustomobject]@{
                    CurrentTenant = $script:ProcessState.CurrentTenant
                    CurrentReport = $script:ProcessState.CurrentReport
                    ProcessedTenants = $script:ProcessState.ProcessedTenants.Clone()
                    StartTime = $script:ProcessState.StartTime
                    LastProgressUpdate = $script:ProcessState.LastProgressUpdate
                    StatePath = $script:ProcessState.StatePath
                }
                
                # Save to file
                $stateToSave | Export-Clixml -Path $script:ProcessState.StatePath -Force
            }
        }
        
        return @{
            Success = $true
            Message = "Process state updated"
        }
    }
    catch {
        Write-Error "Error in Update-CSPProcessState: $_"
        return @{
            Success = $false
            Message = "Failed to update process state: $_"
        }
    }
}

function Get-CSPProcessState {
    <#
    .SYNOPSIS
        Gets the current process state.
    .DESCRIPTION
        Gets the current process state for tracking progress and enabling resumability.
    .PARAMETER TenantId
        Optional tenant ID to get state for a specific tenant.
    .PARAMETER ReportType
        Optional report type to get state for a specific report.
    .EXAMPLE
        Get-CSPProcessState
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportType
    )
    
    try {
        if ($TenantId -and $ReportType) {
            # Return specific report state for tenant
            if ($script:ProcessState.ProcessedTenants[$TenantId] -and
                $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType]) {
                return $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType]
            }
            return $null
        }
        elseif ($TenantId) {
            # Return tenant state
            return $script:ProcessState.ProcessedTenants[$TenantId]
        }
        else {
            # Return full state
            return $script:ProcessState
        }
    }
    catch {
        Write-Error "Error in Get-CSPProcessState: $_"
        return $null
    }
}

Export-ModuleMember -Function Initialize-CSPProcessState, Update-CSPProcessState, Get-CSPProcessState