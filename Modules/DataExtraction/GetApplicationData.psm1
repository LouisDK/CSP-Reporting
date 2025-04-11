<#
.SYNOPSIS
    Application data extraction functions for CSP Reporting v2.
.DESCRIPTION
    Retrieves App Registrations, Service Principals, and App Role Assignments from Microsoft Graph API.
    Implements paging, retry, defensive error handling, and debug logging.
#>

function Get-CSPApplicationData {
    <#
    .SYNOPSIS
        Retrieves all App Registrations.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPApplicationData"

    [array]$allApps = @()
    [string]$baseUrl = "https://graph.microsoft.com/v1.0/applications"
    [string]$selectProps = "id,appId,displayName,createdDateTime,signInAudience,appRoles,requiredResourceAccess,keyCredentials,passwordCredentials,createdBy,owners"
    [string]$url = "$baseUrl`?$select=$selectProps&$count=true"
    $headers = @{ "ConsistencyLevel" = "eventual" }

    try {
        do {
            Write-Verbose "Requesting applications from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get Applications" -MaxRetries 3

            if ($response.value) {
                $allApps += $response.value
                Write-Verbose "Retrieved $($response.value.Count) applications, total so far: $($allApps.Count)"
            } else {
                Write-Verbose "No applications returned in this page."
            }

            $url = $response.'@odata.nextLink'
        } while ($url)
        Write-Verbose "Total applications retrieved: $($allApps.Count)"
        return $allApps
    }
    catch {
        Write-Warning "Error retrieving applications: $($_.Exception.Message)"
        return @()
    }
}

function Get-CSPServicePrincipalData {
    <#
    .SYNOPSIS
        Retrieves all Service Principals.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPServicePrincipalData"

    [array]$allSPs = @()
    [string]$baseUrl = "https://graph.microsoft.com/v1.0/servicePrincipals"
    [string]$selectProps = "id,appId,displayName,createdDateTime,accountEnabled,appOwnerOrganizationId,appRoles,servicePrincipalType,signInAudience,owners,keyCredentials,passwordCredentials"
    [string]$url = "$baseUrl`?$select=$selectProps&$count=true"
    $headers = @{ "ConsistencyLevel" = "eventual" }

    try {
        do {
            Write-Verbose "Requesting service principals from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get Service Principals" -MaxRetries 3

            if ($response.value) {
                $allSPs += $response.value
                Write-Verbose "Retrieved $($response.value.Count) service principals, total so far: $($allSPs.Count)"
            } else {
                Write-Verbose "No service principals returned in this page."
            }

            $url = $response.'@odata.nextLink'
        } while ($url)
        Write-Verbose "Total service principals retrieved: $($allSPs.Count)"
        return $allSPs
    }
    catch {
        Write-Warning "Error retrieving service principals: $($_.Exception.Message)"
        return @()
    }
}

function Get-CSPAppRoleAssignments {
    <#
    .SYNOPSIS
        Retrieves App Role Assignments and OAuth2 Permission Grants.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Called Get-CSPAppRoleAssignments"
    # Implementation to be added
}

Export-ModuleMember -Function Get-CSPApplicationData, Get-CSPServicePrincipalData, Get-CSPAppRoleAssignments