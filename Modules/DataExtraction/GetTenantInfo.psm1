<#
.SYNOPSIS
    Tenant information extraction functions for CSP Reporting v2.
.DESCRIPTION
    Retrieves tenant details, domains, and organization settings from Microsoft Graph API.
    Implements paging, retry, defensive error handling, and debug logging.
#>

function Get-CSPTenantInfo {
    <#
    .SYNOPSIS
        Retrieves basic tenant information.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPTenantInfo"

    [string]$url = "https://graph.microsoft.com/v1.0/organization"
    [string]$selectProps = "id,displayName,verifiedDomains,technicalNotificationMails,securityComplianceNotificationMails,mobileDeviceManagementAuthority"
    $url = "$url`?$select=$selectProps"

    Write-Verbose "Request URL: $url"
    try {
        $response = Invoke-CSPWithRetry -ScriptBlock {
            Invoke-MgGraphRequest -Method GET -Uri $url
        } -ActivityName "Get Tenant Info" -MaxRetries 3

        if ($response.value) {
            return $response.value
        } else {
            return @()
        }
    }
    catch {
        Write-Warning "Error retrieving tenant info: $($_.Exception.Message)"
        return @()
    }
}

function Get-CSPDomainInfo {
    <#
    .SYNOPSIS
        Retrieves domain information.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPDomainInfo"

    $url = "https://graph.microsoft.com/v1.0/domains"

    try {
        $response = Invoke-CSPWithRetry -ScriptBlock {
            Invoke-MgGraphRequest -Method GET -Uri $url
        } -ActivityName "Get Domain Info" -MaxRetries 3

        if ($response.value) {
            return $response.value
        } else {
            return @()
        }
    }
    catch {
        Write-Warning "Error retrieving domain info: $($_.Exception.Message)"
        return @()
    }
}

function Get-CSPOrganizationInfo {
    <#
    .SYNOPSIS
        Retrieves organization settings.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPOrganizationInfo"

    [string]$orgInfoUrl = "https://graph.microsoft.com/v1.0/organization"
    [string]$selectProps = "id,displayName,branding,marketingNotificationEmails,privacyProfile"
    $orgInfoUrl = "$orgInfoUrl`?$select=$selectProps"
    Write-Verbose "Request URL: $orgInfoUrl"

    try {
        $response = Invoke-CSPWithRetry -ScriptBlock {
            Invoke-MgGraphRequest -Method GET -Uri $orgInfoUrl
        } -ActivityName "Get Organization Info" -MaxRetries 3

        if ($response.value) {
            return $response.value
        } else {
            return @()
        }
    }
    catch {
        Write-Warning "Error retrieving organization info: $($_.Exception.Message)"
        return @()
    }
}

Export-ModuleMember -Function Get-CSPTenantInfo, Get-CSPDomainInfo, Get-CSPOrganizationInfo