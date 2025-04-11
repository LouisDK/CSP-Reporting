<#
.SYNOPSIS
    Device data extraction functions for CSP Reporting v2.
.DESCRIPTION
    Retrieves Intune managed device data from Microsoft Graph API.
    Implements paging, retry, defensive error handling, and debug logging.
#>

function Get-CSPManagedDeviceData {
    <#
    .SYNOPSIS
        Retrieves all Intune managed devices.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPManagedDeviceData"

    [array]$allDevices = @()
    [string]$baseUrl = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
    [string]$selectProps = "id,deviceName,operatingSystem,complianceState,managementAgent,ownerType,deviceType,azureADDeviceId,serialNumber,model,manufacturer,joinType,lastSyncDateTime,accountEnabled"
    [string]$url = "$baseUrl`?$select=$selectProps&$count=true"
    $headers = @{ "ConsistencyLevel" = "eventual" }

    try {
        do {
            Write-Verbose "Requesting managed devices from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get Managed Devices" -MaxRetries 3

            if ($response.value) {
                $allDevices += $response.value
                Write-Verbose "Retrieved $($response.value.Count) devices, total so far: $($allDevices.Count)"
            } else {
                Write-Verbose "No devices returned in this page."
            }

            $url = $response.'@odata.nextLink'
        } while ($url)
        Write-Verbose "Total managed devices retrieved: $($allDevices.Count)"
        return $allDevices
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match "license" -or $msg -match "Intune" -or $msg -match "not enabled" -or $msg -match "not licensed") {
            Write-Warning "Managed device extraction skipped: Intune not licensed or enabled for this tenant."
            return @{ SkippedReason = "Intune not licensed or enabled" }
        } else {
            Write-Warning "Error retrieving managed devices: $msg"
            return @()
        }
    }
}

Export-ModuleMember -Function Get-CSPManagedDeviceData