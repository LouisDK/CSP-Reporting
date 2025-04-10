<#
.SYNOPSIS
    Security analysis functions for CSP Reporting v2.
.DESCRIPTION
    Analyzes risk detections, risky users, and tenant security settings to generate findings and summary metrics.
#>

function Analyze-CSPSecurity {
    <#
    .SYNOPSIS
        Analyzes security posture, risk data, and security defaults.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$RiskyUsers,
        [Parameter(Mandatory = $true)]
        [array]$RiskDetections,
        [Parameter(Mandatory = $true)]
        [hashtable]$SecurityDefaults,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Analyze-CSPSecurity"

    $findings = @()

    # Risky Users
    foreach ($user in $RiskyUsers) {
        if ($user.riskLevel -in @("high", "medium") -and $user.riskState -eq "active") {
            $findings += @{
                FindingID = "RISK-001"
                Category = "Identity Protection"
                Severity = "High"
                Title = "Risky User Detected"
                Description = "User '$($user.userPrincipalName)' is flagged as risky with risk level '$($user.riskLevel)'."
                Details = @{
                    UserPrincipalName = $user.userPrincipalName
                    RiskLevel = $user.riskLevel
                    RiskState = $user.riskState
                    LastUpdated = $user.riskLastUpdatedDateTime
                }
                Recommendation = "Investigate this user for potential compromise. Consider remediation actions like password reset or blocking sign-in."
            }
        }
    }

    # Risk Detections
    foreach ($detection in $RiskDetections) {
        if ($detection.riskLevel -eq "high" -and $detection.riskState -eq "active") {
            $findings += @{
                FindingID = "RISK-002"
                Category = "Identity Protection"
                Severity = "High"
                Title = "High Risk Sign-in Detected"
                Description = "A high risk sign-in was detected for user '$($detection.userPrincipalName)'."
                Details = @{
                    UserPrincipalName = $detection.userPrincipalName
                    RiskEventType = $detection.riskEventType
                    ActivityDateTime = $detection.activityDateTime
                    IPAddress = $detection.ipAddress
                    Location = $detection.location
                }
                Recommendation = "Investigate this sign-in event. Consider blocking the user or requiring password reset."
            }
        }
    }

    # Security Defaults
    try {
        if ($SecurityDefaults.isEnabled -eq $false) {
            $findings += @{
                FindingID = "CFG-001"
                Category = "Tenant Configuration"
                Severity = "Medium"
                Title = "Security Defaults Disabled"
                Description = "Microsoft's baseline security policies (Security Defaults) are currently disabled."
                Details = @{
                    Setting = "Security Defaults"
                    Status = "Disabled"
                }
                Recommendation = "Enable Security Defaults or ensure equivalent Conditional Access policies are in place."
            }
        }
    } catch {}

    return $findings
}

Export-ModuleMember -Function Analyze-CSPSecurity