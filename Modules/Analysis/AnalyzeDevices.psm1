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
    Write-Verbose "[Analyze-CSPDevices] Entry"
    Write-Debug   "[Analyze-CSPDevices] Parameter count: $($PSBoundParameters.Count)"
    Write-Debug   "[Analyze-CSPDevices] Devices count: $(@($Devices).Count)"
    Write-Debug   "[Analyze-CSPDevices] Config keys: $($Config.Keys -join ', ')"

    $findings = @()
    $now = Get-Date

    # Determine stale threshold
    $staleDays = 30
    if ($Config.ContainsKey('DeviceStaleDays') -and $Config.DeviceStaleDays -is [int] -and $Config.DeviceStaleDays -gt 0) {
        $staleDays = $Config.DeviceStaleDays
        Write-Debug "[Analyze-CSPDevices] Using DeviceStaleDays from config: $staleDays"
    } else {
        Write-Debug "[Analyze-CSPDevices] Using default stale threshold: $staleDays"
    }

    # Handle missing or incomplete device data
    if (-not $Devices -or $Devices.Count -eq 0) {
        Write-Verbose "[Analyze-CSPDevices] No device data provided or Intune not licensed."
        $findings += @{
            FindingID     = "DEV-000"
            Category      = "Device Compliance"
            Severity      = "Informational"
            Title         = "No Device Data Available"
            Description   = "Device compliance data is missing, unavailable, or Intune is not licensed for this tenant."
            Details       = @{
                Reason = if ($null -eq $Devices) { "Devices parameter is null" } elseif ($Devices.Count -eq 0) { "Devices array is empty" } else { "Unknown" }
            }
            Recommendation = "Verify Intune licensing and data extraction configuration. If Intune is not in use, this finding can be ignored."
        }
        Write-Verbose "[Analyze-CSPDevices] Exit (no device data). Findings count: $($findings.Count)"
        return $findings
    }

    foreach ($device in $Devices) {
        # Defensive: skip if device object is null or missing key properties
        if ($null -eq $device) {
            Write-Debug "[Analyze-CSPDevices] Skipping null device object."
            continue
        }
        $deviceName = $device.deviceName
        $userPrincipalName = $device.userPrincipalName
        $complianceState = $device.complianceState
        $lastSyncDateTime = $device.lastSyncDateTime

        # Non-compliant device
        if ($complianceState -and $complianceState -ne "compliant") {
            $finding = @{
                FindingID     = "DEV-001"
                Category      = "Device Compliance"
                Severity      = "Medium"
                Title         = "Non-Compliant Device Detected"
                Description   = "Device '$deviceName' assigned to '$userPrincipalName' is in state '$complianceState'."
                Details       = @{
                    DeviceName         = $deviceName
                    UserPrincipalName  = $userPrincipalName
                    ComplianceState    = $complianceState
                    LastSync           = $lastSyncDateTime
                }
                Recommendation = "Investigate this device's compliance issues and remediate as needed."
            }
            $findings += $finding
            Write-Debug "[Analyze-CSPDevices] Added finding DEV-001 for device '$deviceName'."
        }

        # Stale device (not synced in $staleDays)
        if ($lastSyncDateTime) {
            try {
                $lastSync = [datetime]$lastSyncDateTime
                $daysSinceSync = ($now - $lastSync).TotalDays
                if ($daysSinceSync -gt $staleDays) {
                    $finding = @{
                        FindingID     = "DEV-002"
                        Category      = "Device Compliance"
                        Severity      = "Low"
                        Title         = "Device Not Synced Recently"
                        Description   = "Device '$deviceName' has not synced in over $staleDays days."
                        Details       = @{
                            DeviceName        = $deviceName
                            UserPrincipalName = $userPrincipalName
                            LastSync          = $lastSync.ToString("s")
                            DaysSinceSync     = [math]::Round($daysSinceSync,1)
                        }
                        Recommendation = "Verify if this device is still in use or should be retired."
                    }
                    $findings += $finding
                    Write-Debug "[Analyze-CSPDevices] Added finding DEV-002 for device '$deviceName'."
                }
            } catch {
                Write-Debug "[Analyze-CSPDevices] Could not parse lastSyncDateTime for device '$deviceName'."
            }
        } else {
            Write-Debug "[Analyze-CSPDevices] Device '$deviceName' missing lastSyncDateTime."
        }
    }

    Write-Verbose "[Analyze-CSPDevices] Exit. Findings count: $($findings.Count)"
    return $findings
}

Export-ModuleMember -Function Analyze-CSPDevices