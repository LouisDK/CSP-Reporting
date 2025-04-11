<#
.SYNOPSIS
    Security data extraction functions for CSP Reporting v2.
.DESCRIPTION
    Retrieves Identity Protection risk data and Security Defaults status from Microsoft Graph API.
    Implements paging, retry, defensive error handling, and debug logging.
#>

function Get-CSPRiskyUsers {
    <#
    .SYNOPSIS
        Retrieves risky users. Requires Identity Protection P2 license.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPRiskyUsers"

    [array]$allRiskyUsers = @()
    [string]$baseUrl = "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers"
    [string]$selectProps = "id,isDeleted,isProcessing,riskLevel,riskState,riskDetail,riskLastUpdatedDateTime,userDisplayName,userPrincipalName"
    [string]$url = "$baseUrl`?$select=$selectProps&$count=true"
    $headers = @{ "ConsistencyLevel" = "eventual" }

    try {
        do {
            Write-Verbose "Requesting risky users from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get Risky Users" -MaxRetries 3

            if ($response.value) {
                $allRiskyUsers += $response.value
                Write-Verbose "Retrieved $($response.value.Count) risky users, total so far: $($allRiskyUsers.Count)"
            } else {
                Write-Verbose "No risky users returned in this page."
            }

            $url = $response.'@odata.nextLink'
        } while ($url)
        Write-Verbose "Total risky users retrieved: $($allRiskyUsers.Count)"
        return $allRiskyUsers
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match "AadPremiumLicenseRequired" -or $msg -match "license" -or $msg -match "Identity Protection") {
            Write-Warning "Risky user extraction skipped: Identity Protection P1/P2 license not present or feature not enabled."
            return @{ SkippedReason = "Identity Protection license missing or feature disabled" }
        } else {
            Write-Warning "Error retrieving risky users: $msg"
            return @()
        }
    }
}

function Get-CSPRiskDetections {
    <#
    .SYNOPSIS
        Retrieves risk detections. Requires Identity Protection P2 license.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Called Get-CSPRiskDetections"
    # Implementation to be added
}

function Get-CSPSecurityDefaults {
    <#
    .SYNOPSIS
        Retrieves Security Defaults policy status.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Called Get-CSPSecurityDefaults"
    # Implementation to be added
}

Export-ModuleMember -Function Get-CSPRiskyUsers, Get-CSPRiskDetections, Get-CSPSecurityDefaults