<#
.SYNOPSIS
    Application analysis functions for CSP Reporting v2.
.DESCRIPTION
    Analyzes App Registrations and Service Principals to generate findings and summary metrics.
#>

function Analyze-CSPApplications {
    <#
    .SYNOPSIS
        Analyzes applications and service principals for risky permissions and credential issues.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Applications,
        [Parameter(Mandatory = $true)]
        [array]$ServicePrincipals,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Analyze-CSPApplications"

    $findings = @()
    $highRiskPerms = $Config.HighRiskAppPermissions
    $expiryDays = $Config.CredentialExpiryWarningDays

    $now = Get-Date

    foreach ($app in ($Applications + $ServicePrincipals)) {
        # Check permissions
        $permissions = @()

        if ($app.requiredResourceAccess) {
            foreach ($res in $app.requiredResourceAccess) {
                if ($res.resourceAccess) {
                    foreach ($perm in $res.resourceAccess) {
                        $permissions += $perm.value
                    }
                }
            }
        }

        foreach ($perm in $permissions) {
            if ($highRiskPerms -contains $perm) {
                $findings += @{
                    FindingID = "APP-001"
                    Category = "Application Security"
                    Severity = "High"
                    Title = "Application with Excessive Permissions"
                    Description = "The application '$($app.displayName)' has been granted the '$perm' permission, which is considered high risk."
                    Details = @{
                        ApplicationName = $app.displayName
                        AppID = $app.appId
                        Permission = $perm
                    }
                    Recommendation = "Review the necessity of the '$perm' permission for this application. Apply least privilege."
                }
            }
        }

        # Check credential expiry
        $creds = @()
        if ($app.keyCredentials) { $creds += $app.keyCredentials }
        if ($app.passwordCredentials) { $creds += $app.passwordCredentials }

        foreach ($cred in $creds) {
            if ($cred.endDateTime) {
                $expiry = [datetime]$cred.endDateTime
                $daysLeft = ($expiry - $now).TotalDays
                if ($daysLeft -le $expiryDays) {
                    $findings += @{
                        FindingID = "APP-002"
                        Category = "Application Security"
                        Severity = "Medium"
                        Title = "Application Credential Expiring Soon"
                        Description = "The application '$($app.displayName)' has a credential expiring in $([math]::Round($daysLeft,1)) days."
                        Details = @{
                            ApplicationName = $app.displayName
                            AppID = $app.appId
                            CredentialType = if ($cred.customKeyIdentifier) { "Certificate" } else { "Client Secret" }
                            ExpiryDate = $expiry.ToString("s")
                        }
                        Recommendation = "Rotate or renew this credential before it expires to avoid service disruption."
                    }
                }
            }
        }
    }

    return $findings
}

Export-ModuleMember -Function Analyze-CSPApplications