<#
.SYNOPSIS
    Identity analysis functions for CSP Reporting v2.
.DESCRIPTION
    Analyzes user, MFA, guest, and privileged access data to generate findings and summary metrics.
#>

function Find-CSPAdminsWithoutMFA {
    <#
    .SYNOPSIS
        Identifies privileged accounts without MFA enabled.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Users,
        [Parameter(Mandatory = $true)]
        [hashtable]$UserAuthMethods,
        [Parameter(Mandatory = $true)]
        [array]$DirectoryRoles,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Find-CSPAdminsWithoutMFA"

    $findings = @()

    foreach ($role in $DirectoryRoles) {
        if ($Config.AdminRoles -notcontains $role.displayName) { continue }

        foreach ($member in $role.Members) {
            $user = $Users | Where-Object { $_.id -eq $member.id }
            if (-not $user) { continue }

            $authMethods = $UserAuthMethods[$user.id]
            $hasMFA = $false

            if ($authMethods) {
                foreach ($method in $authMethods) {
                    if ($method.AdditionalProperties -and $method.AdditionalProperties["@odata.type"] -match "AuthenticationMethod") {
                        $hasMFA = $true
                        break
                    }
                }
            }

            if (-not $hasMFA) {
                $finding = @{
                    FindingID = "ADM-001"
                    Category = "Privileged Access"
                    Severity = "Critical"
                    Title = "Privileged account without MFA"
                    Description = "The user '$($user.userPrincipalName)' holds the '$($role.displayName)' role but does not have Multi-Factor Authentication enabled."
                    Details = @{
                        UserPrincipalName = $user.userPrincipalName
                        UserID = $user.id
                        RoleName = $role.displayName
                        MFAStatus = "Not Enabled"
                    }
                    Recommendation = "Immediately enforce MFA for this account using Conditional Access policies or per-user MFA settings. Review necessity of permanent privileged role; consider PIM."
                }
                $findings += $finding
            }
        }
    }

    return $findings
}

function Find-CSPStaleGuestAccounts {
    <#
    .SYNOPSIS
        Identifies guest accounts inactive beyond threshold.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Users,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Find-CSPStaleGuestAccounts"

    $findings = @()
    $thresholdDays = $Config.StaleGuestThresholdDays

    foreach ($user in $Users) {
        if ($user.userType -ne "Guest") { continue }

        $lastSignIn = $null
        if ($user.signInActivity -and $user.signInActivity.lastSignInDateTime) {
            $lastSignIn = [datetime]$user.signInActivity.lastSignInDateTime
        }

        if (-not $lastSignIn) { continue }

        $daysInactive = (Get-Date) - $lastSignIn
        if ($daysInactive.TotalDays -gt $thresholdDays) {
            $finding = @{
                FindingID = "GUEST-001"
                Category = "Identity Management"
                Severity = "Low"
                Title = "Inactive Guest Account"
                Description = "The guest user '$($user.userPrincipalName)' has not signed in for over $thresholdDays days."
                Details = @{
                    UserPrincipalName = $user.userPrincipalName
                    LastSignIn = $lastSignIn.ToString("s")
                    DaysInactive = [math]::Round($daysInactive.TotalDays, 1)
                }
                Recommendation = "Review if this guest user still requires access. Consider implementing Access Reviews or removing inactive guests."
            }
            $findings += $finding
        }
    }

    return $findings
}

Export-ModuleMember -Function Find-CSPAdminsWithoutMFA, Find-CSPStaleGuestAccounts