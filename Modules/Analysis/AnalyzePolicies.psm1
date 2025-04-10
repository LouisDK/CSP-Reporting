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

    $findings = @()

    foreach ($policy in $Policies) {
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
        }

        # Weak grant controls (no MFA)
        $requiresMFA = $false
        try {
            if ($policy.grantControls -and $policy.grantControls.builtInControls) {
                if ($policy.grantControls.builtInControls -contains "mfa") {
                    $requiresMFA = $true
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
        }

        # Placeholder: check for legacy auth allowed (complex, depends on conditions)
        # For now, just note that detailed parsing is needed
    }

    return $findings
}

Export-ModuleMember -Function Analyze-CSPConditionalAccessPolicies