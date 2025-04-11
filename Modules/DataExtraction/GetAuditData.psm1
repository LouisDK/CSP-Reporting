<#
.SYNOPSIS
    Audit log data extraction functions for CSP Reporting v2.
.DESCRIPTION
    Retrieves Directory Audit logs and Sign-in logs from Microsoft Graph API.
    Implements paging, retry, defensive error handling, and debug logging.
#>

function Get-CSPDirectoryAuditLogs {
    <#
    .SYNOPSIS
        Retrieves directory audit logs.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 2
    )
    Write-Verbose "Starting Get-CSPDirectoryAuditLogs"

    $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $filter = "activityDateTime ge $startDate"
    $url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$filter"
    $headers = @{ "ConsistencyLevel" = "eventual" }

    $allLogs = @()

    try {
        do {
            Write-Verbose "Requesting directory audit logs from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get Directory Audit Logs" -MaxRetries 3

            if ($response.value) {
                $allLogs += $response.value
                Write-Verbose "Retrieved $($response.value.Count) logs, total so far: $($allLogs.Count)"
            }

            $url = $response.'@odata.nextLink'
        } while ($url)

        return $allLogs
    }
    catch {
        Write-Warning "Error retrieving directory audit logs: $($_.Exception.Message)"
        return @()
    }
}

function Get-CSPSignInLogs {
    <#
    .SYNOPSIS
        Retrieves sign-in logs.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$DaysBack = 2
    )
    Write-Verbose "Starting Get-CSPSignInLogs"

    $startDate = (Get-Date).AddDays(-$DaysBack).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $filter = "createdDateTime ge $startDate"
    $url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?`$filter=$filter"
    $headers = @{ "ConsistencyLevel" = "eventual" }

    $allLogs = @()

    try {
        do {
            Write-Verbose "Requesting sign-in logs from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get Sign-In Logs" -MaxRetries 3

            if ($response.value) {
                $allLogs += $response.value
                Write-Verbose "Retrieved $($response.value.Count) logs, total so far: $($allLogs.Count)"
            }

            $url = $response.'@odata.nextLink'
        } while ($url)

        return $allLogs
    }
    catch {
        Write-Warning "Error retrieving sign-in logs: $($_.Exception.Message)"
        return @()
    }
}

Export-ModuleMember -Function Get-CSPDirectoryAuditLogs, Get-CSPSignInLogs