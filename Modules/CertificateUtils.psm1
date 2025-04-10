<#
.SYNOPSIS
    Certificate management utility functions for CSP Reporting.
#>

function New-CSPSelfSignedCertificate {
    <#
    .SYNOPSIS
        Creates a new self-signed certificate for authentication.
    .DESCRIPTION
        Creates a new self-signed certificate for authentication with Microsoft Graph API.
        The certificate is exported to a PFX file with the specified password.
    .PARAMETER CertificateName
        The name of the certificate.
    .PARAMETER CertificatePath
        The path where the certificate will be exported.
    .PARAMETER CertificatePassword
        The password for the certificate file.
    .PARAMETER ExpiryYears
        The number of years until the certificate expires. Default is 2.
    .EXAMPLE
        New-CSPSelfSignedCertificate -CertificateName "CSPReporting" -CertificatePath "C:\Certs\CSPReporting.pfx" -CertificatePassword (ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force) -ExpiryYears 2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CertificateName,
        
        [Parameter(Mandatory = $true)]
        [string]$CertificatePath,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$CertificatePassword,
        
        [Parameter(Mandatory = $false)]
        [int]$ExpiryYears = 2
    )
    
    try {
        # Create the certificate directory if it doesn't exist
        $certDir = Split-Path -Path $CertificatePath -Parent
        if (-not (Test-Path -Path $certDir)) {
            New-Item -Path $certDir -ItemType Directory -Force | Out-Null
        }
        
        # Calculate expiry date
        $notAfter = (Get-Date).AddYears($ExpiryYears)
        
        # Create the self-signed certificate
        $cert = New-SelfSignedCertificate -Subject "CN=$CertificateName" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotAfter $notAfter
        
        # Export the certificate to a PFX file
        Export-PfxCertificate -Cert "Cert:\CurrentUser\My\$($cert.Thumbprint)" -FilePath $CertificatePath -Password $CertificatePassword -Force | Out-Null
        
        # Return the certificate information
        return @{
            Success = $true
            Thumbprint = $cert.Thumbprint
            Subject = $cert.Subject
            NotBefore = $cert.NotBefore
            NotAfter = $cert.NotAfter
            CertificatePath = $CertificatePath
        }
    }
    catch {
        Write-Error "Error in New-CSPSelfSignedCertificate: $_"
        return @{
            Success = $false
            Error = $_.Exception.Message
        }
    }
}

function Get-CSPCertificateThumbprint {
    <#
    .SYNOPSIS
        Gets the thumbprint of a certificate.
    .DESCRIPTION
        Gets the thumbprint of a certificate from a PFX file.
    .PARAMETER CertificatePath
        The path to the certificate file (.pfx).
    .PARAMETER CertificatePassword
        The password for the certificate file.
    .EXAMPLE
        Get-CSPCertificateThumbprint -CertificatePath "C:\Certs\CSPReporting.pfx" -CertificatePassword (ConvertTo-SecureString -String "P@ssw0rd" -AsPlainText -Force)
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CertificatePath,
        
        [Parameter(Mandatory = $true)]
        [SecureString]$CertificatePassword
    )
    
    try {
        # Check if the certificate file exists
        if (-not (Test-Path -Path $CertificatePath)) {
            throw "Certificate file not found: $CertificatePath"
        }
        
        # Load the certificate
        $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
        $certificate.Import($CertificatePath, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        
        # Return the thumbprint
        return $certificate.Thumbprint
    }
    catch {
        Write-Error "Error in Get-CSPCertificateThumbprint: $_"
        return $null
    }
}

Export-ModuleMember -Function New-CSPSelfSignedCertificate, Get-CSPCertificateThumbprint