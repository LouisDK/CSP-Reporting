<#
.SYNOPSIS
    Identity analysis functions for CSP Reporting v2.
.DESCRIPTION
    Analyzes user, MFA, guest, and privileged access data to generate findings and summary metrics.
#>

function Find-CSPAdminsWithoutMFA {
    <#
    .SYNOPSIS
        Identifies privileged accounts (static and PIM) without MFA enabled.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$RawData,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Find-CSPAdminsWithoutMFA"

    $findings = @()
    $adminRoles = $Config.AdminRoles

    # Helper: Check if user has any strong auth method
    function Test-StrongAuth {
        param($authMethods)
        if (-not $authMethods) { return $false }
        foreach ($method in $authMethods) {
            $type = $method.AdditionalProperties?["@odata.type"]
            if ($type -match "Fido2" -or $type -match "AuthenticatorApp" -or $type -match "Certificate" -or $type -match "HardwareOath") {
                return $true
            }
            # If design requires, treat all methods as strong except SMS/Voice
            if ($type -match "MicrosoftAuthenticator" -or $type -match "Fido2" -or $type -match "Certificate" -or $type -match "HardwareOath") {
                return $true
            }
        }
        return $false
    }

    # Helper: Check if user has any auth method at all
    function Test-AnyAuth {
        param($authMethods)
        if (-not $authMethods) { return $false }
        foreach ($method in $authMethods) {
            $type = $method.AdditionalProperties?["@odata.type"]
            if ($type -match "AuthenticationMethod") {
                return $true
            }
        }
        return $false
    }

    $Users = $RawData.Users
    $UserAuthMethods = $RawData.UserAuthMethods
    $DirectoryRoles = $RawData.DirectoryRoles
    $PIMAssignments = $RawData.PIMAssignments

    # 1. Static (Permanent) Role Assignments
    foreach ($role in $DirectoryRoles) {
        if ($adminRoles -notcontains $role.displayName) { continue }
        foreach ($member in $role.Members) {
            $user = $Users | Where-Object { $_.id -eq $member.id }
            if (-not $user) { continue }
            $authMethods = $UserAuthMethods[$user.id]
            $hasStrongMFA = Test-StrongAuth $authMethods
            if (-not $hasStrongMFA) {
                Write-Verbose "User $($user.userPrincipalName) in $($role.displayName) (static) lacks strong MFA"
                $finding = @{
                    FindingID = "ADM-001"
                    Category = "Privileged Access"
                    Severity = "Critical"
                    Title = "Permanent privileged account without MFA"
                    Description = "The user '$($user.userPrincipalName)' holds the '$($role.displayName)' role as a permanent assignment but does not have a strong Multi-Factor Authentication method registered."
                    Details = @{
                        UserPrincipalName = $user.userPrincipalName
                        UserID = $user.id
                        RoleName = $role.displayName
                        MFAStatus = "Not Enabled"
                        AssignmentType = "Permanent"
                    }
                    Recommendation = "Immediately enforce strong MFA for this account. Review necessity of permanent privileged role; consider converting to PIM eligible assignment."
                }
                $findings += $finding
            }
        }
    }

    # 2. PIM Active Assignments
    if ($PIMAssignments -and $PIMAssignments.Active) {
        foreach ($assignment in $PIMAssignments.Active) {
            if ($adminRoles -notcontains $assignment.RoleDisplayName) { continue }
            $user = $Users | Where-Object { $_.id -eq $assignment.PrincipalId }
            if (-not $user) { continue }
            $authMethods = $UserAuthMethods[$user.id]
            $hasStrongMFA = Test-StrongAuth $authMethods
            if (-not $hasStrongMFA) {
                Write-Verbose "User $($user.userPrincipalName) in $($assignment.RoleDisplayName) (PIM Active) lacks strong MFA"
                $finding = @{
                    FindingID = "ADM-002"
                    Category = "Privileged Access"
                    Severity = "High"
                    Title = "Active PIM privileged account without MFA"
                    Description = "The user '$($user.userPrincipalName)' has an active PIM assignment for the '$($assignment.RoleDisplayName)' role but does not have a strong Multi-Factor Authentication method registered."
                    Details = @{
                        UserPrincipalName = $user.userPrincipalName
                        UserID = $user.id
                        RoleName = $assignment.RoleDisplayName
                        MFAStatus = "Not Enabled"
                        AssignmentType = "PIM Active"
                    }
                    Recommendation = "Enforce strong MFA for this account. Review PIM activation requirements and ensure MFA is required for activation."
                }
                $findings += $finding
            }
        }
    } elseif ($PIMAssignments -and $PIMAssignments.SkippedReason) {
        Write-Verbose "PIMAssignments skipped: $($PIMAssignments.SkippedReason)"
    }

    # 3. PIM Eligible Assignments (optional: lower severity)
    if ($PIMAssignments -and $PIMAssignments.Eligible) {
        foreach ($assignment in $PIMAssignments.Eligible) {
            if ($adminRoles -notcontains $assignment.RoleDisplayName) { continue }
            $user = $Users | Where-Object { $_.id -eq $assignment.PrincipalId }
            if (-not $user) { continue }
            $authMethods = $UserAuthMethods[$user.id]
            $hasAnyAuth = Test-AnyAuth $authMethods
            if (-not $hasAnyAuth) {
                Write-Verbose "User $($user.userPrincipalName) in $($assignment.RoleDisplayName) (PIM Eligible) has no auth methods"
                $finding = @{
                    FindingID = "ADM-003"
                    Category = "Privileged Access"
                    Severity = "Medium"
                    Title = "Eligible PIM privileged account without MFA"
                    Description = "The user '$($user.userPrincipalName)' is eligible for the '$($assignment.RoleDisplayName)' role via PIM but does not have any Multi-Factor Authentication method registered."
                    Details = @{
                        UserPrincipalName = $user.userPrincipalName
                        UserID = $user.id
                        RoleName = $assignment.RoleDisplayName
                        MFAStatus = "Not Enabled"
                        AssignmentType = "PIM Eligible"
                    }
                    Recommendation = "Ensure all eligible privileged users have at least one strong MFA method registered before activation."
                }
                $findings += $finding
            }
        }
    }

    Write-Verbose "Find-CSPAdminsWithoutMFA completed. Findings: $($findings.Count)"
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
        [hashtable]$RawData,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Find-CSPStaleGuestAccounts"

    $findings = @()
    $thresholdDays = $Config.StaleGuestThresholdDays
    $Users = $RawData.Users

    foreach ($user in $Users) {
        if ($user.userType -ne "Guest") { continue }
        $lastSignIn = $null
        if ($user.signInActivity -and $user.signInActivity.lastSignInDateTime) {
            $lastSignIn = [datetime]$user.signInActivity.lastSignInDateTime
        }
        if (-not $lastSignIn) {
            Write-Verbose "Guest $($user.userPrincipalName) missing lastSignInDateTime, skipping"
            continue
        }
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

    Write-Verbose "Find-CSPStaleGuestAccounts completed. Findings: $($findings.Count)"
    return $findings
}

function Find-CSPWeakAuthMethods {
    <#
    .SYNOPSIS
        Identifies users (especially admins) relying only on weak authentication methods.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$RawData,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Find-CSPWeakAuthMethods"

    $findings = @()
    $Users = $RawData.Users
    $UserAuthMethods = $RawData.UserAuthMethods
    $adminRoles = $Config.AdminRoles
    $DirectoryRoles = $RawData.DirectoryRoles

    # Build a set of admin user IDs
    $adminUserIds = @{}
    foreach ($role in $DirectoryRoles) {
        if ($adminRoles -notcontains $role.displayName) { continue }
        foreach ($member in $role.Members) {
            $adminUserIds[$member.id] = $true
        }
    }

    foreach ($user in $Users) {
        $authMethods = $UserAuthMethods[$user.id]
        if (-not $authMethods) { continue }
        $hasStrong = $false
        $hasWeak = $false
        foreach ($method in $authMethods) {
            $type = $method.AdditionalProperties?["@odata.type"]
            if ($type -match "Fido2" -or $type -match "AuthenticatorApp" -or $type -match "Certificate" -or $type -match "HardwareOath") {
                $hasStrong = $true
            }
            if ($type -match "Sms" -or $type -match "Voice") {
                $hasWeak = $true
            }
        }
        if ($hasWeak -and -not $hasStrong) {
            $isAdmin = $adminUserIds.ContainsKey($user.id)
            $finding = @{
                FindingID = "IDM-002"
                Category = "Authentication"
                Severity = $([string]::Format("{0}", $(if ($isAdmin) { "High" } else { "Medium" })))
                Title = "User relies only on weak authentication methods"
                Description = "The user '$($user.userPrincipalName)' is registered only for weak authentication methods (SMS/Voice) and has not registered any strong methods (Authenticator App, FIDO2, etc.)."
                Details = @{
                    UserPrincipalName = $user.userPrincipalName
                    UserID = $user.id
                    IsAdmin = $isAdmin
                    RegisteredMethods = ($authMethods | ForEach-Object { $_.AdditionalProperties?["@odata.type"] }) -join ", "
                }
                Recommendation = "Require registration of strong authentication methods for all users, especially privileged accounts. Disable SMS/Voice as primary MFA where possible."
            }
            $findings += $finding
        }
    }

    Write-Verbose "Find-CSPWeakAuthMethods completed. Findings: $($findings.Count)"
    return $findings
}

function Find-CSPEffectivePIM {
    <#
    .SYNOPSIS
        Identifies permanent admin assignments that could be managed by PIM.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$RawData,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Find-CSPEffectivePIM"

    $findings = @()
    $Users = $RawData.Users
    $DirectoryRoles = $RawData.DirectoryRoles
    $adminRoles = $Config.AdminRoles

    # Build a set of PIM-eligible user/role pairs
    $pimEligible = @{}
    if ($RawData.PIMAssignments -and $RawData.PIMAssignments.Eligible) {
        foreach ($assignment in $RawData.PIMAssignments.Eligible) {
            $key = "$($assignment.PrincipalId)|$($assignment.RoleDisplayName)"
            $pimEligible[$key] = $true
        }
    }

    foreach ($role in $DirectoryRoles) {
        if ($adminRoles -notcontains $role.displayName) { continue }
        foreach ($member in $role.Members) {
            $user = $Users | Where-Object { $_.id -eq $member.id }
            if (-not $user) { continue }
            $key = "$($user.id)|$($role.displayName)"
            if (-not $pimEligible.ContainsKey($key)) {
                $finding = @{
                    FindingID = "PIM-001"
                    Category = "Privileged Access"
                    Severity = "Medium"
                    Title = "Permanent admin assignment could be managed by PIM"
                    Description = "The user '$($user.userPrincipalName)' holds the '$($role.displayName)' role as a permanent assignment, but this role could be managed via Privileged Identity Management (PIM) for better security."
                    Details = @{
                        UserPrincipalName = $user.userPrincipalName
                        UserID = $user.id
                        RoleName = $role.displayName
                        AssignmentType = "Permanent"
                    }
                    Recommendation = "Convert this permanent privileged role assignment to a PIM eligible assignment to reduce standing privilege and improve security."
                }
                $findings += $finding
            }
        }
    }

    Write-Verbose "Find-CSPEffectivePIM completed. Findings: $($findings.Count)"
    return $findings
}

Export-ModuleMember -Function Find-CSPAdminsWithoutMFA, Find-CSPStaleGuestAccounts, Find-CSPWeakAuthMethods, Find-CSPEffectivePIM