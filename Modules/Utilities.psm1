<#
.SYNOPSIS
    Utilities module for CSP Reporting solution.

.DESCRIPTION
    This module provides common utility functions for the CSP Reporting solution.

.NOTES
    File Name      : Utilities.psm1
    Prerequisite   : PowerShell Core 7.0 or later
#>

#region Public Functions
function Write-CSPLog {
    <#
    .SYNOPSIS
        Writes a log message to a log file and optionally to the console.
    
    .DESCRIPTION
        Writes a log message to a log file and optionally to the console with timestamp and severity level.
    
    .PARAMETER Message
        The message to log.
    
    .PARAMETER Level
        The severity level of the message. Valid values are "INFO", "WARNING", "ERROR", "DEBUG".
    
    .PARAMETER LogFilePath
        The path to the log file. If not provided, no file logging will occur.
    
    .PARAMETER NoConsole
        If specified, the message will not be written to the console.
    
    .EXAMPLE
        Write-CSPLog -Message "Processing tenant" -Level "INFO" -LogFilePath "C:\Logs\CSPReporting.log"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory = $false)]
        [string]$LogFilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole
    )
    
    try {
        # Format the log message
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
        
        # Write to console if not suppressed
        if (-not $NoConsole) {
            switch ($Level) {
                "INFO" {
                    Write-Host $logMessage -ForegroundColor White
                }
                "WARNING" {
                    Write-Host $logMessage -ForegroundColor Yellow
                }
                "ERROR" {
                    Write-Host $logMessage -ForegroundColor Red
                }
                "DEBUG" {
                    Write-Host $logMessage -ForegroundColor Gray
                }
                default {
                    Write-Host $logMessage
                }
            }
        }
        
        # Write to log file if path is provided
        if ($LogFilePath) {
            # Create the directory if it doesn't exist
            $logDir = Split-Path -Path $LogFilePath -Parent
            if (-not (Test-Path -Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }
            
            # Append to the log file
            Add-Content -Path $LogFilePath -Value $logMessage -Encoding UTF8
        }
    }
    catch {
        Write-Error "Error in Write-CSPLog: $_"
    }
}

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

function Test-CSPModuleAvailability {
    <#
    .SYNOPSIS
        Tests if required modules are available.
    
    .DESCRIPTION
        Tests if required modules are available and installs them if necessary.
    
    .PARAMETER ModuleNames
        The names of the modules to check.
    
    .PARAMETER InstallIfMissing
        If specified, missing modules will be installed.
    
    .EXAMPLE
        Test-CSPModuleAvailability -ModuleNames "Microsoft.Graph", "Az.Accounts" -InstallIfMissing
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ModuleNames,
        
        [Parameter(Mandatory = $false)]
        [switch]$InstallIfMissing
    )
    
    try {
        $results = @()
        
        foreach ($moduleName in $ModuleNames) {
            $moduleAvailable = Get-Module -Name $moduleName -ListAvailable
            
            if ($moduleAvailable) {
                $results += [PSCustomObject]@{
                    ModuleName = $moduleName
                    Available = $true
                    Version = ($moduleAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
                    Installed = $false
                }
            }
            else {
                if ($InstallIfMissing) {
                    Write-Verbose "Installing module $moduleName"
                    Install-Module -Name $moduleName -Scope CurrentUser -Force
                    
                    $moduleAvailable = Get-Module -Name $moduleName -ListAvailable
                    
                    $results += [PSCustomObject]@{
                        ModuleName = $moduleName
                        Available = $true
                        Version = ($moduleAvailable | Sort-Object Version -Descending | Select-Object -First 1).Version
                        Installed = $true
                    }
                }
                else {
                    $results += [PSCustomObject]@{
                        ModuleName = $moduleName
                        Available = $false
                        Version = $null
                        Installed = $false
                    }
                }
            }
        }
        
        return $results
    }
    catch {
        Write-Error "Error in Test-CSPModuleAvailability: $_"
        return $null
    }
}
#endregion

# Export public functions
Export-ModuleMember -Function Write-CSPLog, Test-CSPAdminConsent, New-CSPSelfSignedCertificate, Get-CSPCertificateThumbprint, Test-CSPModuleAvailability