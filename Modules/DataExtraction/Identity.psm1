<#
.SYNOPSIS
    Identity-related data extraction functions for CSP Reporting v2.
.DESCRIPTION
    Provides orchestration and exports for identity data extraction, including users, groups, authentication methods, directory roles, and PIM assignments.
    All extraction logic is implemented in GetIdentityData.psm1; this module provides a convenience wrapper and exports all relevant functions.
#>

# Import the granular extraction functions (assumed to be in the same module path)
# If module auto-loading is configured, this is not strictly necessary, but explicit for clarity.
Import-Module -Name (Join-Path $PSScriptRoot 'GetIdentityData.psm1') -Force

function Get-CSPIdentityData {
    <#
    .SYNOPSIS
        Orchestrates extraction of all identity-related data for a tenant.
    .DESCRIPTION
        Calls all granular identity extraction functions and returns a hashtable with all results.
    #>
    [CmdletBinding()]
    param ()
    Write-Verbose "Starting Get-CSPIdentityData (orchestration)"

    $users = Get-CSPUserData
    $groups = Get-CSPGroupData
    $userAuthMethods = Get-CSPUserAuthMethods -Users $users
    $directoryRoles = Get-CSPDirectoryRoles
    $pimAssignments = Get-CSPPIMAssignments

    return @{
        Users = $users
        Groups = $groups
        UserAuthMethods = $userAuthMethods
        DirectoryRoles = $directoryRoles
        PIMAssignments = $pimAssignments
    }
}

Export-ModuleMember -Function `
    Get-CSPUserData, `
    Get-CSPGroupData, `
    Get-CSPUserAuthMethods, `
    Get-CSPDirectoryRoles, `
    Get-CSPPIMAssignments, `
    Get-CSPIdentityData