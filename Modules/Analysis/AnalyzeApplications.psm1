<#
.SYNOPSIS
    Application analysis functions for CSP Reporting v2.
.DESCRIPTION
    Analyzes App Registrations and Service Principals to generate findings and summary metrics.
#>

function Analyze-CSPApplications {
    <#
    .SYNOPSIS
        Analyzes applications and service principals for risky permissions and credential issues, aligned with v2 design goals.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Applications,
        [Parameter(Mandatory = $true)]
        [array]$ServicePrincipals,
        [Parameter(Mandatory = $true)]
        [array]$AppRoleAssignments,
        [Parameter(Mandatory = $true)]
        [array]$OAuth2PermissionGrants,
        [Parameter(Mandatory = $true)]
        [hashtable]$Config
    )
    Write-Verbose "Starting Analyze-CSPApplications"
    Write-Verbose "Applications: $($Applications.Count), ServicePrincipals: $($ServicePrincipals.Count), AppRoleAssignments: $($AppRoleAssignments.Count), OAuth2PermissionGrants: $($OAuth2PermissionGrants.Count)"

    $findings = @()
    $highRiskPerms = $Config.HighRiskAppPermissions
    $expiryDays = $Config.CredentialExpiryWarningDays
    $now = Get-Date

    # Helper: Get granted permissions for a service principal
    function Get-GrantedPermissions {
        param(
            [Parameter(Mandatory = $true)][string]$AppObjectId
        )
        $granted = @()
        foreach ($assignment in $AppRoleAssignments) {
            if ($assignment.PrincipalId -eq $AppObjectId) {
                $granted += @{
                    Type = "Application"
                    Permission = $assignment.AppRoleId
                    ResourceId = $assignment.ResourceId
                    GrantedBy = "AdminConsent"
                }
            }
        }
        foreach ($grant in $OAuth2PermissionGrants) {
            if ($grant.ClientId -eq $AppObjectId) {
                $granted += @{
                    Type = "Delegated"
                    Permission = $grant.Scope
                    ResourceId = $grant.ResourceId
                    GrantedBy = if ($grant.ConsentType -eq "AllPrincipals") { "AdminConsent" } else { "UserConsent" }
                }
            }
        }
        return $granted
    }

    # Analyze each application/service principal
    $allApps = $Applications + $ServicePrincipals
    Write-Verbose "Total objects to analyze: $($allApps.Count)"

    foreach ($app in $allApps) {
        Write-Verbose "Analyzing app: $($app.displayName) ($($app.appId))"

        # 1. Permission Analysis
        $requestedPermissions = @()
        if ($app.requiredResourceAccess) {
            foreach ($res in $app.requiredResourceAccess) {
                if ($res.resourceAccess) {
                    foreach ($perm in $res.resourceAccess) {
                        $requestedPermissions += @{
                            ResourceAppId = $res.resourceAppId
                            Id = $perm.id
                            Type = $perm.type # "Role" (application) or "Scope" (delegated)
                            Value = $perm.value
                        }
                    }
                }
            }
        }
        Write-Verbose "Requested permissions: $($requestedPermissions.Count)"

        # Get granted permissions
        $grantedPermissions = Get-GrantedPermissions -AppObjectId $app.id
        Write-Verbose "Granted permissions: $($grantedPermissions.Count)"

        # Map high-risk permissions (requested and granted)
        foreach ($perm in $requestedPermissions) {
            if ($highRiskPerms -contains $perm.Value) {
                $findings += @{
                    FindingID = "APP-001"
                    Category = "Application Security"
                    Severity = "High"
                    Title = "Application Requests High-Risk Permission"
                    Description = "The application '$($app.displayName)' requests the '$($perm.Value)' permission, which is considered high risk."
                    Details = @{
                        ApplicationName = $app.displayName
                        AppID = $app.appId
                        Permission = $perm.Value
                        PermissionType = if ($perm.Type -eq "Role") { "Application" } else { "Delegated" }
                        Requested = $true
                        Granted = $false
                    }
                    Recommendation = "Review the necessity of the '$($perm.Value)' permission for this application. Apply least privilege."
                }
                Write-Verbose "High-risk requested permission found: $($perm.Value)"
            }
        }

        foreach ($grant in $grantedPermissions) {
            # For AppRoleAssignments, Permission is AppRoleId (GUID); for OAuth2PermissionGrants, Permission is Scope (space-separated list)
            if ($grant.Type -eq "Application") {
                # Map AppRoleId to permission value if possible (requires lookup, skipped if not available)
                $permValue = $grant.Permission
                if ($highRiskPerms -contains $permValue) {
                    $findings += @{
                        FindingID = "APP-001"
                        Category = "Application Security"
                        Severity = "High"
                        Title = "Application Granted High-Risk Application Permission"
                        Description = "The application '$($app.displayName)' has been granted the application permission '$permValue', which is considered high risk."
                        Details = @{
                            ApplicationName = $app.displayName
                            AppID = $app.appId
                            Permission = $permValue
                            PermissionType = "Application"
                            GrantedBy = $grant.GrantedBy
                            Requested = $false
                            Granted = $true
                        }
                        Recommendation = "Review the necessity of the '$permValue' permission for this application. Apply least privilege."
                    }
                    Write-Verbose "High-risk granted application permission found: $permValue"
                }
            } elseif ($grant.Type -eq "Delegated") {
                foreach ($scope in $grant.Permission -split " ") {
                    if ($highRiskPerms -contains $scope) {
                        $findings += @{
                            FindingID = "APP-001"
                            Category = "Application Security"
                            Severity = "High"
                            Title = "Application Granted High-Risk Delegated Permission"
                            Description = "The application '$($app.displayName)' has been granted the delegated permission '$scope', which is considered high risk."
                            Details = @{
                                ApplicationName = $app.displayName
                                AppID = $app.appId
                                Permission = $scope
                                PermissionType = "Delegated"
                                GrantedBy = $grant.GrantedBy
                                Requested = $false
                                Granted = $true
                            }
                            Recommendation = "Review the necessity of the '$scope' permission for this application. Apply least privilege."
                        }
                        Write-Verbose "High-risk granted delegated permission found: $scope"
                    }
                }
            }
        }

        # 2. Credential Expiry Checks
        $creds = @()
        if ($app.keyCredentials) { $creds += $app.keyCredentials }
        if ($app.passwordCredentials) { $creds += $app.passwordCredentials }
        Write-Verbose "Credentials found: $($creds.Count)"

        foreach ($cred in $creds) {
            try {
                if ($null -eq $cred.endDateTime) {
                    Write-Verbose "Credential missing endDateTime, skipping."
                    continue
                }
                $expiry = [datetime]$cred.endDateTime
                $daysLeft = ($expiry - $now).TotalDays
                $credType = if ($cred.customKeyIdentifier) { "Certificate" } else { "Client Secret" }
                if ($daysLeft -lt 0) {
                    $findings += @{
                        FindingID = "APP-002"
                        Category = "Application Security"
                        Severity = "High"
                        Title = "Application Credential Expired"
                        Description = "The application '$($app.displayName)' has an expired $credType credential."
                        Details = @{
                            ApplicationName = $app.displayName
                            AppID = $app.appId
                            CredentialType = $credType
                            ExpiryDate = $expiry.ToString("s")
                            DaysExpired = [math]::Round([math]::Abs($daysLeft),1)
                        }
                        Recommendation = "Remove or rotate expired credentials to reduce risk of compromise."
                    }
                    Write-Verbose "Expired credential found for $($app.displayName): $credType expired $([math]::Round([math]::Abs($daysLeft),1)) days ago."
                } elseif ($daysLeft -le $expiryDays) {
                    $findings += @{
                        FindingID = "APP-002"
                        Category = "Application Security"
                        Severity = "Medium"
                        Title = "Application Credential Expiring Soon"
                        Description = "The application '$($app.displayName)' has a $credType credential expiring in $([math]::Round($daysLeft,1)) days."
                        Details = @{
                            ApplicationName = $app.displayName
                            AppID = $app.appId
                            CredentialType = $credType
                            ExpiryDate = $expiry.ToString("s")
                            DaysToExpiry = [math]::Round($daysLeft,1)
                        }
                        Recommendation = "Rotate or renew this credential before it expires to avoid service disruption."
                    }
                    Write-Verbose "Credential expiring soon for $($app.displayName): $credType expires in $([math]::Round($daysLeft,1)) days."
                }
            } catch {
                Write-Verbose "Error processing credential for $($app.displayName): $_"
            }
        }
    }

    Write-Verbose "Total findings generated: $($findings.Count)"
    return $findings
}

Export-ModuleMember -Function Analyze-CSPApplications