<#
.SYNOPSIS
    Device analysis functions for CSP Reporting v2.
.DESCRIPTION
    Analyzes Intune managed device data to generate findings and summary metrics.
#>

function Analyze-CSPDevices {
    <#
    .SYNOPSIS
        Analyzes device compliance and activity.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Devices,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Analyze-CSPDevices"

    $findings = @()

    foreach ($device in $Devices) {
        # Non-compliant device
        if ($device.complianceState -ne "compliant") {
            $findings += @{
                FindingID = "DEV-001"
                Category = "Device Compliance"
                Severity = "Medium"
                Title = "Non-Compliant Device Detected"
                Description = "Device '$($device.deviceName)' assigned to '$($device.userPrincipalName)' is in state '$($device.complianceState)'."
                Details = @{
                    DeviceName = $device.deviceName
                    UserPrincipalName = $device.userPrincipalName
                    ComplianceState = $device.complianceState
                    LastSync = $device.lastSyncDateTime
                }
                Recommendation = "Investigate this device's compliance issues and remediate as needed."
            }
        }

        # Optional: check last sync date (e.g., >30 days ago)
        if ($device.lastSyncDateTime) {
            $lastSync = [datetime]$device.lastSyncDateTime
            $daysSinceSync = (Get-Date) - $lastSync
            if ($daysSinceSync.TotalDays -gt 30) {
                $findings += @{
                    FindingID = "DEV-002"
                    Category = "Device Compliance"
                    Severity = "Low"
                    Title = "Device Not Synced Recently"
                    Description = "Device '$($device.deviceName)' has not synced in over 30 days."
                    Details = @{
                        DeviceName = $device.deviceName
                        UserPrincipalName = $device.userPrincipalName
                        LastSync = $lastSync.ToString("s")
                        DaysSinceSync = [math]::Round($daysSinceSync.TotalDays,1)
                    }
                    Recommendation = "Verify if this device is still in use or should be retired."
                }
            }
        }
    }

    return $findings
}

Export-ModuleMember -Function Analyze-CSPDevices