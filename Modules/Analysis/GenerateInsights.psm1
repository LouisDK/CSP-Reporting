<#
.SYNOPSIS
    Insights generation orchestrator for CSP Reporting v2.
.DESCRIPTION
    Coordinates analysis modules to produce structured Insights JSON per tenant.
#>

function Invoke-CSPTenantAnalysis {
    <#
    .SYNOPSIS
        Runs all analysis functions and generates Insights JSON object.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$RawData,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Invoke-CSPTenantAnalysis"

    $tenantId = $RawData.TenantId
    $tenantName = $RawData.TenantName

    # Call analysis functions
    $identityFindings = Find-CSPAdminsWithoutMFA -Users $RawData.Users -UserAuthMethods $RawData.UserAuthMethods -DirectoryRoles $RawData.DirectoryRoles -Config $Config
    $guestFindings = Find-CSPStaleGuestAccounts -Users $RawData.Users -Config $Config
    $caFindings = Analyze-CSPConditionalAccessPolicies -Policies $RawData.ConditionalAccessPolicies -Config $Config
    $appFindings = Analyze-CSPApplications -Applications $RawData.Applications -ServicePrincipals $RawData.ServicePrincipals -Config $Config
    $securityFindings = Analyze-CSPSecurity -RiskyUsers $RawData.RiskyUsers -RiskDetections $RawData.RiskDetections -SecurityDefaults $RawData.SecurityDefaults -Config $Config
    $deviceFindings = Analyze-CSPDevices -Devices $RawData.Devices -Config $Config

    $allFindings = @()
    $allFindings += $identityFindings
    $allFindings += $guestFindings
    $allFindings += $caFindings
    $allFindings += $appFindings
    $allFindings += $securityFindings
    $allFindings += $deviceFindings

    # Calculate summary metrics
    $totalUsers = ($RawData.Users).Count
    $enabledUsers = ($RawData.Users | Where-Object { $_.accountEnabled }).Count
    $guestUsers = ($RawData.Users | Where-Object { $_.userType -eq "Guest" }).Count
    $mfaEnabledUsers = 0
    foreach ($user in $RawData.Users) {
        $authMethods = $RawData.UserAuthMethods[$user.id]
        $hasMFA = $false
        if ($authMethods) {
            foreach ($method in $authMethods) {
                if ($method.AdditionalProperties -and $method.AdditionalProperties["@odata.type"] -match "AuthenticationMethod") {
                    $hasMFA = $true
                    break
                }
            }
        }
        if ($hasMFA) { $mfaEnabledUsers++ }
    }
    $mfaPercent = if ($enabledUsers -gt 0) { [math]::Round(($mfaEnabledUsers / $enabledUsers) * 100, 1) } else { 0 }

    $summary = @{
        TotalUsers = $totalUsers
        EnabledUsers = $enabledUsers
        GuestUsers = $guestUsers
        MFAEnabledPercent = $mfaPercent
        AdminRoleAssignments = ($RawData.DirectoryRoles | ForEach-Object { $_.Members.Count } | Measure-Object -Sum).Sum
        AdminsWithoutMFA = ($identityFindings | Where-Object { $_.FindingID -eq "ADM-001" }).Count
        ConditionalAccessPolicies = ($RawData.ConditionalAccessPolicies).Count
        RiskyCAPolicies = ($caFindings | Where-Object { $_.FindingID -eq "CA-003" }).Count
        HighRiskApps = ($appFindings | Where-Object { $_.FindingID -eq "APP-001" }).Count
        StaleGuests = ($guestFindings).Count
        SecurityDefaultsEnabled = $RawData.SecurityDefaults.isEnabled
        LegacyAuthBlocked = $true # Placeholder, detailed check needed
        CompliantDevicePercent = 0 # Placeholder, can be calculated if needed
    }

    $insights = @{
        TenantId = $tenantId
        TenantName = $tenantName
        ReportTimestamp = (Get-Date).ToString("s")
        SummaryMetrics = $summary
        Findings = $allFindings
    }

    Write-Verbose "Completed Invoke-CSPTenantAnalysis"
    return $insights
}

Export-ModuleMember -Function Invoke-CSPTenantAnalysis