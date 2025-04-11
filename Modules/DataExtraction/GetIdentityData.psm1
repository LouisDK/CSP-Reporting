<#
.SYNOPSIS
    Identity data extraction functions for CSP Reporting v2.
.DESCRIPTION
    Retrieves users, groups, authentication methods, directory roles, and PIM assignments from Microsoft Graph API.
    Implements paging, retry, defensive error handling, and debug logging.
#>

function Get-CSPUserData {
    <#
    .SYNOPSIS
        Retrieves all users with key properties.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPUserData"

    $allUsers = @()
    $baseUrl = "https://graph.microsoft.com/v1.0/users"
    $selectProps = "id,userPrincipalName,displayName,accountEnabled,userType,creationDateTime,assignedLicenses,signInActivity"
    $url = "$baseUrl`?$select=$selectProps&$count=true"
    $headers = @{ "ConsistencyLevel" = "eventual" }

    try {
        do {
            Write-Verbose "Requesting users from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get Users" -MaxRetries 3

            if ($response.value) {
                $allUsers += $response.value
                Write-Verbose "Retrieved $($response.value.Count) users, total so far: $($allUsers.Count)"
            } else {
                Write-Verbose "No users returned in this page."
            }

            $url = $response.'@odata.nextLink'
        } while ($url)

        Write-Verbose "Total users retrieved: $($allUsers.Count)"
        return $allUsers
    }
    catch {
        Write-Warning "Error retrieving users: $($_.Exception.Message)"
        return @()
    }
}

function Get-CSPGroupData {
    <#
    .SYNOPSIS
        Retrieves all groups with key properties.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Called Get-CSPGroupData"
    # Implementation to be added
}

function Get-CSPUserAuthMethods {
    <#
    .SYNOPSIS
        Retrieves authentication methods for all users.
    .PARAMETER Users
        Array of user objects (from Get-CSPUserData).
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Users
    )
    Write-Verbose "Starting Get-CSPUserAuthMethods for $($Users.Count) users"

    $userAuthMethods = @{}

    foreach ($user in $Users) {
        try {
            Write-Verbose "Retrieving auth methods for user: $($user.userPrincipalName)"
            $methods = Invoke-CSPWithRetry -ScriptBlock {
                Get-MgUserAuthenticationMethod -UserId $user.id
            } -ActivityName "Get Auth Methods for $($user.userPrincipalName)" -MaxRetries 3

            $userAuthMethods[$user.id] = $methods
        }
        catch {
            Write-Warning "Error retrieving auth methods for user $($user.userPrincipalName): $($_.Exception.Message)"
            $userAuthMethods[$user.id] = @()
        }
    }

    return $userAuthMethods
}

function Get-CSPDirectoryRoles {
    <#
    .SYNOPSIS
        Retrieves directory roles and their members.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPDirectoryRoles"

    $allRoles = @()
    $url = "https://graph.microsoft.com/v1.0/directoryRoles?`$count=true"
    $headers = @{ "ConsistencyLevel" = "eventual" }
    
    try {
        do {
            Write-Verbose "Requesting directory roles from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get Directory Roles" -MaxRetries 3

            if ($response.value) {
                $allRoles += $response.value
                Write-Verbose "Retrieved $($response.value.Count) roles, total so far: $($allRoles.Count)"
            }

            $url = $response.'@odata.nextLink'
        } while ($url)

        # For each role, get members
        foreach ($role in $allRoles) {
            $roleMembers = @()
            $membersUrl = "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members"

            do {
                Write-Verbose "Requesting members for role $($role.displayName) from: $membersUrl"
                $memResponse = Invoke-CSPWithRetry -ScriptBlock {
                    Invoke-MgGraphRequest -Method GET -Uri $membersUrl
                } -ActivityName "Get Members for Role $($role.displayName)" -MaxRetries 3

                if ($memResponse.value) {
                    $roleMembers += $memResponse.value
                }

                $membersUrl = $memResponse.'@odata.nextLink'
            } while ($membersUrl)

            $role | Add-Member -MemberType NoteProperty -Name Members -Value $roleMembers
        }

        return $allRoles
    }
    catch {
        Write-Warning "Error retrieving directory roles: $($_.Exception.Message)"
        return @()
    }
}

function Get-CSPPIMAssignments {
    <#
    .SYNOPSIS
        Retrieves PIM eligible and active role assignments.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPPIMAssignments"

    $result = @{
        Eligible = @()
        Active = @()
    }

    try {
        # Eligible assignments
        $url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances?`$count=true"
        $headers = @{ "ConsistencyLevel" = "eventual" }
        
        do {
            Write-Verbose "Requesting PIM eligible assignments from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get PIM Eligible Assignments" -MaxRetries 3

            if ($response.value) {
                $result.Eligible += $response.value
            }

            $url = $response.'@odata.nextLink'
        } while ($url)

        # Active assignments
        $url = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances?`$count=true"
        
        do {
            Write-Verbose "Requesting PIM active assignments from: $url"
            $response = Invoke-CSPWithRetry -ScriptBlock {
                Invoke-MgGraphRequest -Method GET -Uri $url -Headers $headers
            } -ActivityName "Get PIM Active Assignments" -MaxRetries 3

            if ($response.value) {
                $result.Active += $response.value
            }

            $url = $response.'@odata.nextLink'
        } while ($url)

        return $result
    }
    catch {
        $msg = $_.Exception.Message
        if ($msg -match "AadPremiumLicenseRequired" -or $msg -match "license") {
            Write-Warning "PIM assignments skipped: required Microsoft Entra ID P2 or Governance license not present."
            $result.SkippedReason = "License missing"
        } else {
            Write-Warning "Error retrieving PIM assignments: $msg"
        }
        return $result
    }
}

Export-ModuleMember -Function Get-CSPUserData, Get-CSPGroupData, Get-CSPUserAuthMethods, Get-CSPDirectoryRoles, Get-CSPPIMAssignments