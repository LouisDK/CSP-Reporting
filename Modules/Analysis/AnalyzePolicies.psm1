<#
.SYNOPSIS
    Policy analysis functions for CSP Reporting v2.
.DESCRIPTION
    Analyzes Conditional Access and related policies to generate findings and summary metrics.
#>

function Analyze-CSPConditionalAccessPolicies {
    <#
    .SYNOPSIS
        Analyzes Conditional Access policies for gaps and risks.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Policies,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Analyze-CSPConditionalAccessPolicies"
    Write-CSPLog -Message "Analyze-CSPConditionalAccessPolicies: Entry. Policy count: $($Policies.Count)" -Level "DEBUG"

    $findings = @()
    $legacyAuthKeywords = @("exchangeActiveSync", "basicAuthentication", "legacyProtocol", "imap", "pop", "smtp", "mapi", "autodiscover", "activesync")
    $weakGrantControls = $Config.WeakGrantControls
    if (-not $weakGrantControls) { $weakGrantControls = @("requirePasswordChange", "requireCompliantDevice") }

    foreach ($policy in $Policies) {
        Write-Verbose "Analyzing policy: $($policy.displayName)"
        Write-CSPLog -Message "Analyzing policy: $($policy.displayName)" -Level "DEBUG"

        # Disabled policy
        if ($policy.state -ne "enabled") {
            $findings += @{
                FindingID = "CA-001"
                Category = "Conditional Access"
                Severity = "Medium"
                Title = "Disabled Conditional Access Policy"
                Description = "The policy '$($policy.displayName)' is disabled."
                Details = @{
                    PolicyName = $policy.displayName
                    State = $policy.state
                }
                Recommendation = "Review if this policy should be enabled to enforce security controls."
            }
            Write-CSPLog -Message "Policy '$($policy.displayName)' is disabled." -Level "INFO"
        }

        # Targets all users without exclusions
        $targetsAllUsers = $false
        try {
            $users = $policy.conditions.users
            if ($users.includeUsers -contains "All" -and (!$users.excludeUsers -or $users.excludeUsers.Count -eq 0)) {
                $targetsAllUsers = $true
            }
        } catch {}
        if ($targetsAllUsers) {
            $findings += @{
                FindingID = "CA-002"
                Category = "Conditional Access"
                Severity = "High"
                Title = "Policy targets all users without exclusions"
                Description = "The policy '$($policy.displayName)' applies to all users without exclusions, which may be overly broad."
                Details = @{
                    PolicyName = $policy.displayName
                }
                Recommendation = "Review scope of this policy. Consider excluding break-glass accounts or service accounts."
            }
            Write-CSPLog -Message "Policy '$($policy.displayName)' targets all users without exclusions." -Level "WARNING"
        }

        # Weak grant controls (no MFA, or only weak controls)
        $requiresMFA = $false
        $hasOnlyWeakControls = $false
        try {
            if ($policy.grantControls -and $policy.grantControls.builtInControls) {
                if ($policy.grantControls.builtInControls -contains "mfa") {
                    $requiresMFA = $true
                } elseif ($policy.grantControls.builtInControls | Where-Object { $weakGrantControls -contains $_ }) {
                    $hasOnlyWeakControls = $true
                }
            }
        } catch {}
        if (-not $requiresMFA) {
            $findings += @{
                FindingID = "CA-003"
                Category = "Conditional Access"
                Severity = "High"
                Title = "Conditional Access policy does not enforce MFA"
                Description = "The policy '$($policy.displayName)' does not require Multi-Factor Authentication."
                Details = @{
                    PolicyName = $policy.displayName
                }
                Recommendation = "Update this policy to require MFA to improve security."
            }
            Write-CSPLog -Message "Policy '$($policy.displayName)' does not enforce MFA." -Level "WARNING"
        } elseif ($hasOnlyWeakControls) {
            $findings += @{
                FindingID = "CA-004"
                Category = "Conditional Access"
                Severity = "Medium"
                Title = "Conditional Access policy uses only weak grant controls"
                Description = "The policy '$($policy.displayName)' uses only weak grant controls: $($policy.grantControls.builtInControls -join ', ')."
                Details = @{
                    PolicyName = $policy.displayName
                    GrantControls = $policy.grantControls.builtInControls
                }
                Recommendation = "Strengthen grant controls for this policy. Consider requiring MFA or other strong controls."
            }
            Write-CSPLog -Message "Policy '$($policy.displayName)' uses only weak grant controls." -Level "INFO"
        }

        # Detect if legacy authentication is allowed
        $allowsLegacyAuth = $false
        try {
            # If the policy conditions include legacy protocols and grantControls do not block, flag it
            if ($policy.conditions.clientAppTypes) {
                if ($policy.conditions.clientAppTypes -contains "exchangeActiveSync" -or $policy.conditions.clientAppTypes -contains "other") {
                    # Check if grant controls block legacy auth
                    if (-not ($policy.grantControls.builtInControls -contains "block")) {
                        $allowsLegacyAuth = $true
                    }
                }
            }
            # Additional heuristic: if the policy does not explicitly block legacy protocols, and session controls are weak
            if ($policy.conditions.applications -and $policy.conditions.applications.includeApplications) {
                foreach ($app in $policy.conditions.applications.includeApplications) {
                    if ($legacyAuthKeywords | Where-Object { $app -like "*$_*" }) {
                        $allowsLegacyAuth = $true
                    }
                }
            }
        } catch {}
        if ($allowsLegacyAuth) {
            $findings += @{
                FindingID = "CA-005"
                Category = "Conditional Access"
                Severity = "High"
                Title = "Conditional Access policy allows legacy authentication"
                Description = "The policy '$($policy.displayName)' may allow legacy authentication protocols, which are less secure."
                Details = @{
                    PolicyName = $policy.displayName
                    ClientAppTypes = $policy.conditions.clientAppTypes
                }
                Recommendation = "Update this policy to block legacy authentication protocols."
            }
            Write-CSPLog -Message "Policy '$($policy.displayName)' allows legacy authentication." -Level "WARNING"
        }
    }

    Write-Verbose "Analyze-CSPConditionalAccessPolicies completed. Findings: $($findings.Count)"
    Write-CSPLog -Message "Analyze-CSPConditionalAccessPolicies: Exit. Findings count: $($findings.Count)" -Level "DEBUG"
    return $findings
}

function Analyze-CSPSSPRPolicy {
    <#
    .SYNOPSIS
        Analyzes SSPR (Self-Service Password Reset) enablement and configuration.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$RawData,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Analyze-CSPSSPRPolicy"
    Write-CSPLog -Message "Analyze-CSPSSPRPolicy: Entry." -Level "DEBUG"

    $findings = @()
    $authMethodPolicies = $RawData.AuthMethodPolicies
    $authorizationPolicy = $RawData.AuthorizationPolicy

    # SSPR enablement check
    $ssprEnabled = $null
    try {
        if ($authMethodPolicies -and $authMethodPolicies.selfServicePasswordReset) {
            $ssprEnabled = $authMethodPolicies.selfServicePasswordReset.state
        } elseif ($authorizationPolicy -and $authorizationPolicy.allowedToUseSSPR -ne $null) {
            $ssprEnabled = $authorizationPolicy.allowedToUseSSPR
        }
    } catch {}

    if ($ssprEnabled -eq $null) {
        $findings += @{
            FindingID = "SSPR-001"
            Category = "Tenant Configuration"
            Severity = "Medium"
            Title = "Unable to determine SSPR enablement"
            Description = "Could not determine if Self-Service Password Reset (SSPR) is enabled for the tenant."
            Details = @{}
            Recommendation = "Verify SSPR configuration in Azure AD portal."
        }
        Write-CSPLog -Message "Unable to determine SSPR enablement." -Level "WARNING"
    } elseif ($ssprEnabled -eq $false -or $ssprEnabled -eq "disabled") {
        $findings += @{
            FindingID = "SSPR-002"
            Category = "Tenant Configuration"
            Severity = "High"
            Title = "SSPR is not enabled"
            Description = "Self-Service Password Reset (SSPR) is not enabled for users in this tenant."
            Details = @{
                SSPRState = $ssprEnabled
            }
            Recommendation = "Enable SSPR to allow users to reset their passwords securely."
        }
        Write-CSPLog -Message "SSPR is not enabled." -Level "WARNING"
    } else {
        $findings += @{
            FindingID = "SSPR-003"
            Category = "Tenant Configuration"
            Severity = "Informational"
            Title = "SSPR is enabled"
            Description = "Self-Service Password Reset (SSPR) is enabled for users in this tenant."
            Details = @{
                SSPRState = $ssprEnabled
            }
            Recommendation = "No action required."
        }
        Write-CSPLog -Message "SSPR is enabled." -Level "INFO"
    }

    Write-Verbose "Analyze-CSPSSPRPolicy completed. Findings: $($findings.Count)"
    Write-CSPLog -Message "Analyze-CSPSSPRPolicy: Exit. Findings count: $($findings.Count)" -Level "DEBUG"
    return $findings
}

function Analyze-CSPAuthorizationPolicy {
    <#
    .SYNOPSIS
        Analyzes Authorization Policy settings relevant to security posture.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$RawData,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Analyze-CSPAuthorizationPolicy"
    Write-CSPLog -Message "Analyze-CSPAuthorizationPolicy: Entry." -Level "DEBUG"

    $findings = @()
    $authorizationPolicy = $RawData.AuthorizationPolicy

    if (-not $authorizationPolicy) {
        $findings += @{
            FindingID = "AUTH-001"
            Category = "Tenant Configuration"
            Severity = "Medium"
            Title = "Authorization Policy data missing"
            Description = "Authorization Policy data is missing or incomplete."
            Details = @{}
            Recommendation = "Ensure Authorization Policy data is collected from the tenant."
        }
        Write-CSPLog -Message "Authorization Policy data missing." -Level "WARNING"
        Write-Verbose "Analyze-CSPAuthorizationPolicy completed. Findings: $($findings.Count)"
        Write-CSPLog -Message "Analyze-CSPAuthorizationPolicy: Exit. Findings count: $($findings.Count)" -Level "DEBUG"
        return $findings
    }

    # allowLegacyServicePrincipalLogins
    if ($authorizationPolicy.allowLegacyServicePrincipalLogins -eq $true) {
        $findings += @{
            FindingID = "AUTH-002"
            Category = "Tenant Configuration"
            Severity = "High"
            Title = "Legacy Service Principal Logins Allowed"
            Description = "The tenant allows legacy service principal logins, which is a security risk."
            Details = @{
                allowLegacyServicePrincipalLogins = $authorizationPolicy.allowLegacyServicePrincipalLogins
            }
            Recommendation = "Disable legacy service principal logins to improve security."
        }
        Write-CSPLog -Message "Legacy service principal logins are allowed." -Level "WARNING"
    }

    # allowedToUseSSPR
    if ($authorizationPolicy.allowedToUseSSPR -eq $false) {
        $findings += @{
            FindingID = "AUTH-003"
            Category = "Tenant Configuration"
            Severity = "Medium"
            Title = "SSPR is blocked by Authorization Policy"
            Description = "The Authorization Policy blocks users from using Self-Service Password Reset (SSPR)."
            Details = @{
                allowedToUseSSPR = $authorizationPolicy.allowedToUseSSPR
            }
            Recommendation = "Allow users to use SSPR for better password management."
        }
        Write-CSPLog -Message "SSPR is blocked by Authorization Policy." -Level "WARNING"
    }

    # blockMsolPowerShell
    if ($authorizationPolicy.blockMsolPowerShell -eq $true) {
        $findings += @{
            FindingID = "AUTH-004"
            Category = "Tenant Configuration"
            Severity = "Informational"
            Title = "MSOL PowerShell is blocked"
            Description = "The tenant blocks the use of MSOL PowerShell, which is recommended for security."
            Details = @{
                blockMsolPowerShell = $authorizationPolicy.blockMsolPowerShell
            }
            Recommendation = "No action required."
        }
        Write-CSPLog -Message "MSOL PowerShell is blocked." -Level "INFO"
    } elseif ($authorizationPolicy.blockMsolPowerShell -eq $false) {
        $findings += @{
            FindingID = "AUTH-005"
            Category = "Tenant Configuration"
            Severity = "Medium"
            Title = "MSOL PowerShell is not blocked"
            Description = "The tenant does not block the use of MSOL PowerShell, which may expose legacy management endpoints."
            Details = @{
                blockMsolPowerShell = $authorizationPolicy.blockMsolPowerShell
            }
            Recommendation = "Block MSOL PowerShell to reduce attack surface."
        }
        Write-CSPLog -Message "MSOL PowerShell is not blocked." -Level "WARNING"
    }

    Write-Verbose "Analyze-CSPAuthorizationPolicy completed. Findings: $($findings.Count)"
    Write-CSPLog -Message "Analyze-CSPAuthorizationPolicy: Exit. Findings count: $($findings.Count)" -Level "DEBUG"
    return $findings
}

Export-ModuleMember -Function Analyze-CSPConditionalAccessPolicies, Analyze-CSPSSPRPolicy, Analyze-CSPAuthorizationPolicy