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
    Write-Verbose "[Invoke-CSPTenantAnalysis] Starting analysis orchestration"

    $tenantId = $RawData.TenantId
    $tenantName = $RawData.TenantName

    # Defensive: Ensure required keys exist
    foreach ($key in @("Users","UserAuthMethods","DirectoryRoles","ConditionalAccessPolicies","Applications","ServicePrincipals","RiskyUsers","RiskDetections","SecurityDefaults","Devices")) {
        if (-not $RawData.ContainsKey($key)) {
            Write-Warning "[Invoke-CSPTenantAnalysis] RawData missing key: $key"
            $RawData[$key] = @()
        }
    }

    # --- Analysis Progress Setup ---
    $analysisSteps = @(
        @{ Name = "Identity Analysis";        Action = { Find-CSPAdminsWithoutMFA -RawData $RawData -Config $Config };         Var = "identityFindings" },
        @{ Name = "Guest Account Analysis";   Action = { Find-CSPStaleGuestAccounts -RawData $RawData -Config $Config };       Var = "guestFindings" },
        @{ Name = "CA Policy Analysis";       Action = { Analyze-CSPConditionalAccessPolicies -Policies $RawData.ConditionalAccessPolicies -Config $Config };                   Var = "caFindings" },
        @{ Name = "Application Analysis";     Action = {
            Analyze-CSPApplications `
                -Applications ($RawData.Applications   | ForEach-Object { $_ } ) `
                -ServicePrincipals ($RawData.ServicePrincipals | ForEach-Object { $_ }) `
                -AppRoleAssignments ($RawData.AppRoleAssignments  | ForEach-Object { $_ }) `
                -OAuth2PermissionGrants ($RawData.OAuth2PermissionGrants | ForEach-Object { $_ }) `
                -Config $Config
        }; Var = "appFindings" },
        @{ Name = "Security/Risk Analysis";   Action = { Analyze-CSPSecurity -RiskyUsers $RawData.RiskyUsers -RiskDetections $RawData.RiskDetections -SecurityDefaults $RawData.SecurityDefaults -Config $Config }; Var = "securityFindings" },
        @{ Name = "Device Compliance Analysis"; Action = { Analyze-CSPDevices -Devices $RawData.Devices -Config $Config };                                                      Var = "deviceFindings" }
    )
    $stepCount = $analysisSteps.Count
    $stepNum = 0
    $findingsVars = @{}

    foreach ($step in $analysisSteps) {
        $stepNum++
        $progressMsg = "($stepNum of $stepCount) $($step.Name)..."
        Write-Progress -Activity "Tenant Analysis: $tenantName" -Status $progressMsg -PercentComplete ([math]::Round(($stepNum-1)/$stepCount*100))
        Write-CSPLog -Message "Starting $($step.Name) for $tenantName" -Level "INFO"
        try {
            $result = & $step.Action
            $findingsVars[$step.Var] = $result
            Write-CSPLog -Message "Completed $($step.Name) for $tenantName. Findings: $($result.Count)" -Level "INFO"
        } catch {
            Write-Warning "[Invoke-CSPTenantAnalysis] Error in $($step.Name): $_"
            $findingsVars[$step.Var] = @()
        }
    }
    Write-Progress -Activity "Tenant Analysis: $tenantName" -Status "Completed" -PercentComplete 100 -Completed

    $identityFindings = $findingsVars["identityFindings"]
    $guestFindings    = $findingsVars["guestFindings"]
    $caFindings       = $findingsVars["caFindings"]
    $appFindings      = $findingsVars["appFindings"]
    $securityFindings = $findingsVars["securityFindings"]
    $deviceFindings   = $findingsVars["deviceFindings"]

    $allFindings = @()
    $allFindings += $identityFindings
    $allFindings += $guestFindings
    $allFindings += $caFindings
    $allFindings += $appFindings
    $allFindings += $securityFindings
    $allFindings += $deviceFindings

    # --- Summary Metrics Calculation ---
    Write-Verbose "[Invoke-CSPTenantAnalysis] Calculating summary metrics"
    $totalUsers = 0
    $enabledUsers = 0
    $guestUsers = 0
    $mfaEnabledUsers = 0
    if ($RawData.Users) {
        $totalUsers = ($RawData.Users).Count
        $enabledUsers = ($RawData.Users | Where-Object { $_.accountEnabled }).Count
        $guestUsers = ($RawData.Users | Where-Object { $_.userType -eq "Guest" }).Count
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
    }
    $mfaPercent = if ($enabledUsers -gt 0) { [math]::Round(($mfaEnabledUsers / $enabledUsers) * 100, 1) } else { $null }

    # Admin role assignments
    $adminRoleAssignments = $null
    if ($RawData.DirectoryRoles) {
        $adminRoleAssignments = ($RawData.DirectoryRoles | ForEach-Object { $_.Members.Count } | Measure-Object -Sum).Sum
    }

    # Admins without MFA
    $adminsWithoutMFA = $null
    if ($identityFindings) {
        $adminsWithoutMFA = ($identityFindings | Where-Object { $_.FindingID -eq "ADM-001" }).Count
    }

    # Conditional Access Policies
    $caPolicyCount = $null
    if ($RawData.ConditionalAccessPolicies) {
        $caPolicyCount = ($RawData.ConditionalAccessPolicies).Count
    }

    # Risky CA Policies
    $riskyCAPolicies = $null
    if ($caFindings) {
        $riskyCAPolicies = ($caFindings | Where-Object { $_.FindingID -eq "CA-003" }).Count
    }

    # High Risk Apps
    $highRiskApps = $null
    if ($appFindings) {
        $highRiskApps = ($appFindings | Where-Object { $_.FindingID -eq "APP-001" }).Count
    }

    # Stale Guests
    $staleGuests = $null
    if ($guestFindings) {
        $staleGuests = ($guestFindings).Count
    }

    # Security Defaults Enabled
    $securityDefaultsEnabled = $null
    if ($RawData.SecurityDefaults -and $RawData.SecurityDefaults.ContainsKey("isEnabled")) {
        $securityDefaultsEnabled = $RawData.SecurityDefaults.isEnabled
    }

    # --- Legacy Auth Blocked ---
    $legacyAuthBlocked = $null
    try {
        if ($securityDefaultsEnabled -eq $true) {
            $legacyAuthBlocked = $true
            Write-Verbose "[Invoke-CSPTenantAnalysis] Security Defaults enabled, legacy auth is blocked."
        } elseif ($RawData.ConditionalAccessPolicies) {
            $legacyBlocked = $false
            foreach ($policy in $RawData.ConditionalAccessPolicies) {
                if ($policy.state -eq "enabled" -and $policy.conditions -and $policy.conditions.clientAppTypes) {
                    if ($policy.conditions.clientAppTypes -contains "exchangeActiveSync" -or $policy.conditions.clientAppTypes -contains "other") {
                        if ($policy.grantControls -and $policy.grantControls.builtInControls -contains "block") {
                            $legacyBlocked = $true
                            break
                        }
                    }
                }
            }
            $legacyAuthBlocked = $legacyBlocked
            Write-Verbose "[Invoke-CSPTenantAnalysis] Legacy auth blocked by CA policy: $legacyAuthBlocked"
        }
    } catch {
        Write-Warning "[Invoke-CSPTenantAnalysis] Error determining LegacyAuthBlocked: $_"
        $legacyAuthBlocked = $null
    }

    # --- Device Compliance Percent ---
    $compliantDevicePercent = $null
    try {
        if ($RawData.Devices -and $RawData.Devices.Count -gt 0) {
            $compliant = ($RawData.Devices | Where-Object { $_.complianceState -eq "compliant" }).Count
            $totalDevices = $RawData.Devices.Count
            $compliantDevicePercent = if ($totalDevices -gt 0) { [math]::Round(($compliant / $totalDevices) * 100, 1) } else { $null }
        }
    } catch {
        Write-Warning "[Invoke-CSPTenantAnalysis] Error calculating CompliantDevicePercent: $_"
        $compliantDevicePercent = $null
    }

    $summary = @{
        TotalUsers = $totalUsers
        EnabledUsers = $enabledUsers
        GuestUsers = $guestUsers
        MFAEnabledPercent = $mfaPercent
        AdminRoleAssignments = $adminRoleAssignments
        AdminsWithoutMFA = $adminsWithoutMFA
        ConditionalAccessPolicies = $caPolicyCount
        RiskyCAPolicies = $riskyCAPolicies
        HighRiskApps = $highRiskApps
        StaleGuests = $staleGuests
        SecurityDefaultsEnabled = $securityDefaultsEnabled
        LegacyAuthBlocked = $legacyAuthBlocked
        CompliantDevicePercent = $compliantDevicePercent
    }

    $insights = @{
        TenantId = $tenantId
        TenantName = $tenantName
        ReportTimestamp = (Get-Date).ToString("s")
        SummaryMetrics = $summary
        Findings = $allFindings
    }

    Write-Verbose "[Invoke-CSPTenantAnalysis] Completed analysis orchestration"
    return $insights
}

Export-ModuleMember -Function Invoke-CSPTenantAnalysis