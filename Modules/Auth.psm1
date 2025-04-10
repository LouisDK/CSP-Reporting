<#
.SYNOPSIS
    Authentication module for CSP Reporting solution.

.DESCRIPTION
    This module provides functions for authenticating to Microsoft Graph API
    across multiple tenants using either certificate-based or client secret authentication.

.NOTES
    File Name      : Auth.psm1
    Prerequisite   : PowerShell Core 7.0 or later
                     Microsoft Graph PowerShell SDK
#>

#region Module Variables
# Store the current connection state
$script:CurrentConnection = $null
#endregion

#region Public Functions
function Connect-CSPTenant {
    <#
    .SYNOPSIS
        Authenticates to a tenant using Microsoft Graph API.
    
    .DESCRIPTION
        Authenticates to a tenant using either certificate-based authentication (preferred)
        or client secret authentication as a fallback.
    
    .PARAMETER TenantId
        The tenant ID (GUID) or domain name of the tenant to connect to.
    
    .PARAMETER ClientId
        The application (client) ID of the app registration.
    
    .PARAMETER CertificatePath
        The path to the certificate file (.pfx) for certificate-based authentication.
    
    .PARAMETER CertificatePassword
        The password for the certificate file.
    
    .PARAMETER ClientSecret
        The client secret for client secret authentication.
    
    .PARAMETER AuthMethod
        The authentication method to use. Valid values are "Certificate" or "ClientSecret".
        Default is "Certificate".
    
    .EXAMPLE
        Connect-CSPTenant -TenantId "contoso.onmicrosoft.com" -ClientId "12345678-1234-1234-1234-123456789012" -CertificatePath ".\cert.pfx" -CertificatePassword $securePassword -AuthMethod "Certificate"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $false)]
        [string]$CertificatePath,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$CertificatePassword,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]$ClientSecretCredential,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Certificate", "ClientSecret")]
        [string]$AuthMethod = "Certificate"
    )
    
    try {
        Write-Verbose "Connecting to tenant $TenantId using $AuthMethod authentication"
        
        # Define the required permissions
        $requiredScopes = @(
            "https://graph.microsoft.com/.default"
        )
        
        # Prepare the result object
        $result = @{
            Success = $false
            ErrorMessage = ""
            Connection = $null
        }
        
        # Connect based on the authentication method
        switch ($AuthMethod) {
            "Certificate" {
                if (-not $CertificatePath -or -not (Test-Path -Path $CertificatePath)) {
                    throw "Certificate path is invalid or not provided"
                }
                
                if (-not $CertificatePassword) {
                    throw "Certificate password is required for certificate authentication"
                }
                
                try {
                    # Load the certificate
                    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
                        $CertificatePath,
                        $CertificatePassword,
                        [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable
                    )
                    
                    # Connect to Microsoft Graph
                    $connection = Connect-MgGraph -TenantId $TenantId -ClientId $ClientId -Certificate $certificate
                    
                    $result.Success = $true
                    $result.Connection = $connection
                }
                catch {
                    $result.ErrorMessage = "Certificate authentication failed: $_"
                    Write-Error $result.ErrorMessage
                }
            }
            "ClientSecret" {
                if (-not $ClientSecretCredential) {
                    throw "Client secret credential is required for client secret authentication"
                }
                
                try {
                    # Extract client ID and secret from the credential
                    $clientId = $ClientSecretCredential.UserName
                    $clientSecret = $ClientSecretCredential.GetNetworkCredential().Password
                    
                    Write-Verbose "Connecting with Client Secret: TenantId=$TenantId, ClientId=$clientId"
                    
                    # Create a secure string from the client secret
                    $secureClientSecret = ConvertTo-SecureString -String $clientSecret -AsPlainText -Force
                    
                    # Create a PSCredential object with the client ID as the username and the client secret as the password
                    $credential = New-Object System.Management.Automation.PSCredential($clientId, $secureClientSecret)
                    
                    # Connect to Microsoft Graph using the credential
                    $connection = Connect-MgGraph -TenantId $TenantId -ClientSecretCredential $credential -Scopes $requiredScopes
                    
                    $result.Success = $true
                    $result.Connection = $connection
                }
                catch {
                    $result.ErrorMessage = "Client secret authentication failed: $_"
                    Write-Error $result.ErrorMessage
                }
            }
            default {
                throw "Unsupported authentication method: $AuthMethod"
            }
        }
        
        # Store the current connection if successful
        if ($result.Success) {
            $script:CurrentConnection = @{
                TenantId = $TenantId
                Connection = $result.Connection
            }
        }
        
        return $result
    }
    catch {
        Write-Error "Error in Connect-CSPTenant: $_"
        return @{
            Success = $false
            ErrorMessage = "Error in Connect-CSPTenant: $_"
            Connection = $null
        }
    }
}

function Disconnect-CSPTenant {
    <#
    .SYNOPSIS
        Disconnects from the current Microsoft Graph API session.
    
    .DESCRIPTION
        Disconnects from the current Microsoft Graph API session and clears the stored connection.
    
    .EXAMPLE
        Disconnect-CSPTenant
    #>
    [CmdletBinding()]
    param ()
    
    try {
        # Disconnect from Microsoft Graph
        Disconnect-MgGraph -ErrorAction SilentlyContinue
        
        # Clear the stored connection
        $script:CurrentConnection = $null
        
        Write-Verbose "Disconnected from Microsoft Graph API"
        return $true
    }
    catch {
        Write-Error "Error in Disconnect-CSPTenant: $_"
        return $false
    }
}

function Test-CSPConnection {
    <#
    .SYNOPSIS
        Tests if there is an active connection to Microsoft Graph API.
    
    .DESCRIPTION
        Tests if there is an active connection to Microsoft Graph API and returns the connection details.
    
    .EXAMPLE
        Test-CSPConnection
    #>
    [CmdletBinding()]
    param ()
    
    try {
        # Check if there is an active connection
        $context = Get-MgContext -ErrorAction SilentlyContinue
        
        if ($null -eq $context) {
            Write-Verbose "No active connection to Microsoft Graph API"
            return @{
                Connected = $false
                TenantId = $null
                AppId = $null
            }
        }
        
        Write-Verbose "Active connection to Microsoft Graph API found"
        return @{
            Connected = $true
            TenantId = $context.TenantId
            AppId = $context.AppId
        }
    }
    catch {
        Write-Error "Error in Test-CSPConnection: $_"
        return @{
            Connected = $false
            TenantId = $null
            AppId = $null
            Error = $_
        }
    }
}

function Get-CSPAuthToken {
    <#
    .SYNOPSIS
        Gets an authentication token for Microsoft Graph API.
    
    .DESCRIPTION
        Gets an authentication token for Microsoft Graph API using the current connection.
        This is useful for making direct REST API calls to Microsoft Graph.
    
    .EXAMPLE
        $token = Get-CSPAuthToken
    #>
    [CmdletBinding()]
    param ()
    
    try {
        # Check if there is an active connection
        $connectionTest = Test-CSPConnection
        
        if (-not $connectionTest.Connected) {
            throw "No active connection to Microsoft Graph API"
        }
        
        # Get the authentication token
        $token = Get-MgAccessToken
        
        return $token
    }
    catch {
        Write-Error "Error in Get-CSPAuthToken: $_"
        return $null
    }
}
#endregion

# Export public functions
Export-ModuleMember -Function Connect-CSPTenant, Disconnect-CSPTenant, Test-CSPConnection, Get-CSPAuthToken