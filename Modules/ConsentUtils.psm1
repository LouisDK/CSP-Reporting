<#
.SYNOPSIS
    Admin consent utility functions for CSP Reporting.
#>

function Test-CSPAdminConsent {
    <#
    .SYNOPSIS
        Tests if admin consent has been granted for the application in a tenant.
    .DESCRIPTION
        Tests if admin consent has been granted for the application in a tenant by attempting to access a resource that requires admin consent.
    .PARAMETER TenantId
        The tenant ID (GUID) or domain name of the tenant.
    .PARAMETER ClientId
        The application (client) ID of the app registration.
    .EXAMPLE
        Test-CSPAdminConsent -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId
    )
    
    try {
        # Check if connected to the correct tenant
        $connectionTest = Test-CSPConnection
        
        if (-not $connectionTest.Connected -or $connectionTest.TenantId -ne $TenantId) {
            throw "Not connected to the correct tenant. Please connect to tenant $TenantId first."
        }
        
        # Try to access a resource that requires admin consent
        try {
            # Get organization information (requires Directory.Read.All)
            $organization = Get-MgOrganization -ErrorAction Stop
            
            # If we get here, admin consent has been granted
            return @{
                Success = $true
                Message = "Admin consent has been granted for application $ClientId in tenant $TenantId"
            }
        }
        catch {
            # Check if the error is due to insufficient permissions
            if ($_.Exception.Message -like "*Authorization_RequestDenied*" -or 
                $_.Exception.Message -like "*insufficient privileges*" -or
                $_.Exception.Message -like "*Access is denied*") {
                return @{
                    Success = $false
                    Message = "Admin consent has not been granted for application $ClientId in tenant $TenantId"
                    Error = $_.Exception.Message
                }
            }
            else {
                # Some other error occurred
                throw $_
            }
        }
    }
    catch {
        Write-Error "Error in Test-CSPAdminConsent: $_"
        return @{
            Success = $false
            Message = "Error testing admin consent: $_"
            Error = $_.Exception.Message
        }
    }
}


Export-ModuleMember -Function Test-CSPAdminConsent