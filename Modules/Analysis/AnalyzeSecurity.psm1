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

    Write-Verbose "[Analyze-CSPSecurity] ENTRY"
    Write-Debug   "[Analyze-CSPSecurity] Parameters: RiskyUsers=$($RiskyUsers.Count), RiskDetections=$($RiskDetections.Count), SecurityDefaults keys=$($SecurityDefaults.Keys.Count), Config keys=$($Config.Keys.Count)"

    $findings = @()
    $findingCount = 0

    # --- Risky Users Analysis ---
    if ($null -eq $RiskyUsers -or $RiskyUsers.Count -eq 0) {
        Write-Verbose "[Analyze-CSPSecurity] No RiskyUsers data found or feature not licensed."
        $findings += @{
            FindingID     = "RISK-INFO-001"
            Category      = "Identity Protection"
            Severity      = "Informational"
            Title         = "No Risky Users Data"
            Description   = "Risky Users data is unavailable. This may indicate that Azure AD Identity Protection is not licensed or no risky users were detected."
            Details       = @{
                DataStatus = if ($null -eq $RiskyUsers) { "Null" } else { "Empty" }
            }
            Recommendation = "Verify Azure AD Identity Protection licensing and data collection. If not licensed, consider enabling for enhanced risk detection."
        }
        $findingCount++
    } else {
        foreach ($user in $RiskyUsers) {
            if ($user.riskLevel -in @("high", "medium") -and $user.riskState -eq "active") {
                Write-Debug "[Analyze-CSPSecurity] Risky user detected: $($user.userPrincipalName) ($($user.riskLevel))"
                $findings += @{
                    FindingID     = "RISK-001"
                    Category      = "Identity Protection"
                    Severity      = if ($user.riskLevel -eq "high") { "High" } else { "Medium" }
                    Title         = "Risky User Detected"
                    Description   = "User '$($user.userPrincipalName)' is flagged as risky with risk level '$($user.riskLevel)'."
                    Details       = @{
                        UserPrincipalName = $user.userPrincipalName
                        RiskLevel         = $user.riskLevel
                        RiskState         = $user.riskState
                        LastUpdated       = $user.riskLastUpdatedDateTime
                        UserId            = $user.id
                    }
                    Recommendation = "Investigate this user for potential compromise. Consider remediation actions like password reset or blocking sign-in."
                }
                $findingCount++
            }
        }
    }

    # --- Risk Detections Analysis ---
    if ($null -eq $RiskDetections -or $RiskDetections.Count -eq 0) {
        Write-Verbose "[Analyze-CSPSecurity] No RiskDetections data found or feature not licensed."
        $findings += @{
            FindingID     = "RISK-INFO-002"
            Category      = "Identity Protection"
            Severity      = "Informational"
            Title         = "No Risk Detections Data"
            Description   = "Risk Detections data is unavailable. This may indicate that Azure AD Identity Protection is not licensed or no risk detections were found."
            Details       = @{
                DataStatus = if ($null -eq $RiskDetections) { "Null" } else { "Empty" }
            }
            Recommendation = "Verify Azure AD Identity Protection licensing and data collection. If not licensed, consider enabling for enhanced risk detection."
        }
        $findingCount++
    } else {
        foreach ($detection in $RiskDetections) {
            if ($detection.riskLevel -eq "high" -and $detection.riskState -eq "active") {
                Write-Debug "[Analyze-CSPSecurity] High risk sign-in detected: $($detection.userPrincipalName) ($($detection.riskEventType))"
                $findings += @{
                    FindingID     = "RISK-002"
                    Category      = "Identity Protection"
                    Severity      = "High"
                    Title         = "High Risk Sign-in Detected"
                    Description   = "A high risk sign-in was detected for user '$($detection.userPrincipalName)'."
                    Details       = @{
                        UserPrincipalName = $detection.userPrincipalName
                        RiskEventType     = $detection.riskEventType
                        ActivityDateTime  = $detection.activityDateTime
                        IPAddress         = $detection.ipAddress
                        Location          = $detection.location
                        DetectionId       = $detection.id
                    }
                    Recommendation = "Investigate this sign-in event. Consider blocking the user or requiring password reset."
                }
                $findingCount++
            }
        }
    }

    # --- Security Defaults Analysis ---
    try {
        if ($null -eq $SecurityDefaults -or $SecurityDefaults.Count -eq 0) {
            Write-Verbose "[Analyze-CSPSecurity] SecurityDefaults data missing or incomplete."
            $findings += @{
                FindingID     = "CFG-INFO-001"
                Category      = "Tenant Configuration"
                Severity      = "Informational"
                Title         = "Security Defaults Data Unavailable"
                Description   = "Security Defaults configuration data is missing or incomplete for this tenant."
                Details       = @{
                    DataStatus = if ($null -eq $SecurityDefaults) { "Null" } else { "Empty" }
                }
                Recommendation = "Verify that Security Defaults configuration data is being collected. If not available, ensure the necessary permissions and API calls are in place."
            }
            $findingCount++
        } elseif ($SecurityDefaults.isEnabled -eq $false) {
            Write-Verbose "[Analyze-CSPSecurity] Security Defaults are disabled."
            $findings += @{
                FindingID     = "CFG-001"
                Category      = "Tenant Configuration"
                Severity      = "Medium"
                Title         = "Security Defaults Disabled"
                Description   = "Microsoft's baseline security policies (Security Defaults) are currently disabled for this tenant."
                Details       = @{
                    Setting = "Security Defaults"
                    Status  = "Disabled"
                }
                Recommendation = "Evaluate enabling Security Defaults if no Conditional Access policies providing equivalent or stronger protections are in place. Security Defaults enforce MFA for admins, block legacy auth, and protect privileged actions."
            }
            $findingCount++
        } elseif ($SecurityDefaults.isEnabled -eq $true) {
            Write-Verbose "[Analyze-CSPSecurity] Security Defaults are enabled."
            # No finding needed for enabled state, but could add a positive informational finding if desired.
        } else {
            Write-Verbose "[Analyze-CSPSecurity] SecurityDefaults.isEnabled is not a boolean value."
            $findings += @{
                FindingID     = "CFG-INFO-002"
                Category      = "Tenant Configuration"
                Severity      = "Informational"
                Title         = "Security Defaults State Unknown"
                Description   = "Unable to determine if Security Defaults are enabled or disabled due to unexpected data format."
                Details       = @{
                    RawValue = $SecurityDefaults.isEnabled
                }
                Recommendation = "Review Security Defaults configuration and ensure data is collected in the expected format."
            }
            $findingCount++
        }
    } catch {
        Write-Verbose "[Analyze-CSPSecurity] Exception occurred while analyzing SecurityDefaults: $_"
        $findings += @{
            FindingID     = "CFG-INFO-003"
            Category      = "Tenant Configuration"
            Severity      = "Informational"
            Title         = "Security Defaults Analysis Error"
            Description   = "An error occurred while analyzing Security Defaults configuration."
            Details       = @{
                Error = $_.Exception.Message
            }
            Recommendation = "Review error details and ensure Security Defaults data is available and correctly formatted."
        }
        $findingCount++
    }

    Write-Verbose "[Analyze-CSPSecurity] Total findings generated: $($findings.Count)"
    Write-Debug   "[Analyze-CSPSecurity] EXIT"

    return $findings
}

Export-ModuleMember -Function Analyze-CSPSecurity