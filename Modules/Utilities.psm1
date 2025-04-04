<#
.SYNOPSIS
    Utilities module for CSP Reporting solution.

.DESCRIPTION
    This module provides common utility functions for the CSP Reporting solution.

.NOTES
    File Name      : Utilities.psm1
    Prerequisite   : PowerShell Core 7.0 or later
#>

#region Module Variables
# Store the state of the current operation for resumability
$script:ProcessState = @{
    CurrentTenant = $null
    CurrentReport = $null
    ProcessedTenants = @{}
    StartTime = $null
    LastProgressUpdate = $null
}

# Store the original terminal colors
$script:OriginalForegroundColor = $null
$script:OriginalBackgroundColor = $null

#region Public Functions
function Initialize-CSPProcessState {
    <#
    .SYNOPSIS
        Initializes or resets the process state tracking.
    
    .DESCRIPTION
        Initializes or resets the process state used for tracking progress and enabling resumability.
    
    .PARAMETER StatePath
        Optional path to save the state to disk for persistence across PowerShell sessions.
    
    .EXAMPLE
        Initialize-CSPProcessState
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$StatePath
    )
    
    try {
        # Initialize process state
        $script:ProcessState = @{
            CurrentTenant = $null
            CurrentReport = $null
            ProcessedTenants = @{}
            StartTime = Get-Date
            LastProgressUpdate = $null
            StatePath = $StatePath
        }
        
        # If state path is provided, check if a previous state exists
        if ($StatePath -and (Test-Path -Path $StatePath)) {
            try {
                $savedState = Import-Clixml -Path $StatePath
                
                # Validate the saved state
                if ($savedState.ProcessedTenants -and $savedState.StartTime) {
                    $script:ProcessState = $savedState
                    $script:ProcessState.LastProgressUpdate = Get-Date
                    
                    return @{
                        Success = $true
                        ResumedFromSave = $true
                        Message = "Process state restored from $StatePath"
                    }
                }
            }
            catch {
                Write-Warning "Could not restore process state from $StatePath. Starting fresh."
            }
        }
        
        return @{
            Success = $true
            ResumedFromSave = $false
            Message = "Process state initialized"
        }
    }
    catch {
        Write-Error "Error in Initialize-CSPProcessState: $_"
        return @{
            Success = $false
            ResumedFromSave = $false
            Message = "Failed to initialize process state: $_"
        }
    }
}

function Update-CSPProcessState {
    <#
    .SYNOPSIS
        Updates the process state with progress information.
    
    .DESCRIPTION
        Updates the process state to track progress of tenant processing and report generation.
        This enables resumability and progress reporting.
    
    .PARAMETER TenantId
        The ID of the tenant being processed.
    
    .PARAMETER TenantName
        The name of the tenant being processed.
    
    .PARAMETER ReportType
        The type of report being processed.
    
    .PARAMETER Status
        The status of the process (Started, InProgress, Completed, Failed).
    
    .PARAMETER Data
        Additional data to store with the process state (e.g., last processed item).
    
    .EXAMPLE
        Update-CSPProcessState -TenantId "tenant1.onmicrosoft.com" -TenantName "Tenant 1" -ReportType "MFA" -Status "Started"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$TenantName,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportType,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Started", "InProgress", "Completed", "Failed")]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [object]$Data = $null
    )
    
    try {
        # Update current tenant
        $script:ProcessState.CurrentTenant = @{
            TenantId = $TenantId
            TenantName = $TenantName
        }
        
        # Update current report if provided
        if ($ReportType) {
            $script:ProcessState.CurrentReport = $ReportType
        }
        
        # Initialize tenant entry if it doesn't exist
        if (-not $script:ProcessState.ProcessedTenants[$TenantId]) {
            $script:ProcessState.ProcessedTenants[$TenantId] = @{
                TenantName = $TenantName
                Reports = @{}
                Status = "InProgress"
                StartTime = Get-Date
                EndTime = $null
            }
        }
        
        # Update tenant status
        if ($Status -eq "Completed" -or $Status -eq "Failed") {
            $script:ProcessState.ProcessedTenants[$TenantId].Status = $Status
            $script:ProcessState.ProcessedTenants[$TenantId].EndTime = Get-Date
        }
        
        # Update report status if report type is provided
        if ($ReportType) {
            if (-not $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType]) {
                $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType] = @{
                    Status = $Status
                    StartTime = Get-Date
                    EndTime = $null
                    Data = $Data
                }
            }
            else {
                $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType].Status = $Status
                
                if ($Status -eq "Completed" -or $Status -eq "Failed") {
                    $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType].EndTime = Get-Date
                }
                
                if ($Data) {
                    $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType].Data = $Data
                }
            }
        }
        
        # Save state if path is provided
        if ($script:ProcessState.StatePath) {
            # Only save every 10 seconds to avoid excessive disk I/O
            $now = Get-Date
            if (-not $script:ProcessState.LastProgressUpdate -or
                ($now - $script:ProcessState.LastProgressUpdate).TotalSeconds -ge 10) {
                
                $script:ProcessState.LastProgressUpdate = $now
                
                # Clone the state to avoid reference issues
                $stateToSave = [pscustomobject]@{
                    CurrentTenant = $script:ProcessState.CurrentTenant
                    CurrentReport = $script:ProcessState.CurrentReport
                    ProcessedTenants = $script:ProcessState.ProcessedTenants.Clone()
                    StartTime = $script:ProcessState.StartTime
                    LastProgressUpdate = $script:ProcessState.LastProgressUpdate
                    StatePath = $script:ProcessState.StatePath
                }
                
                # Save to file
                $stateToSave | Export-Clixml -Path $script:ProcessState.StatePath -Force
            }
        }
        
        return @{
            Success = $true
            Message = "Process state updated"
        }
    }
    catch {
        Write-Error "Error in Update-CSPProcessState: $_"
        return @{
            Success = $false
            Message = "Failed to update process state: $_"
        }
    }
}

function Get-CSPProcessState {
    <#
    .SYNOPSIS
        Gets the current process state.
    
    .DESCRIPTION
        Gets the current process state for tracking progress and enabling resumability.
    
    .PARAMETER TenantId
        Optional tenant ID to get state for a specific tenant.
    
    .PARAMETER ReportType
        Optional report type to get state for a specific report.
    
    .EXAMPLE
        Get-CSPProcessState
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportType
    )
    
    try {
        if ($TenantId -and $ReportType) {
            # Return specific report state for tenant
            if ($script:ProcessState.ProcessedTenants[$TenantId] -and
                $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType]) {
                return $script:ProcessState.ProcessedTenants[$TenantId].Reports[$ReportType]
            }
            return $null
        }
        elseif ($TenantId) {
            # Return tenant state
            return $script:ProcessState.ProcessedTenants[$TenantId]
        }
        else {
            # Return full state
            return $script:ProcessState
        }
    }
    catch {
        Write-Error "Error in Get-CSPProcessState: $_"
        return $null
    }
}

function Write-CSPProgress {
    <#
    .SYNOPSIS
        Writes progress information.
    
    .DESCRIPTION
        Writes progress information for a long-running operation.
    
    .PARAMETER Activity
        The activity description.
    
    .PARAMETER Status
        The current status.
    
    .PARAMETER PercentComplete
        The percentage complete.
    
    .PARAMETER TenantId
        The tenant ID for which progress is being reported.
    
    .PARAMETER ReportType
        The report type for which progress is being reported.
    
    .PARAMETER Completed
        If specified, indicates that the operation is complete.
    
    .EXAMPLE
        Write-CSPProgress -Activity "Retrieving MFA Status" -Status "Processing user 10 of 100" -PercentComplete 10 -TenantId "tenant1.onmicrosoft.com" -ReportType "MFA"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Activity,
        
        [Parameter(Mandatory = $true)]
        [string]$Status,
        
        [Parameter(Mandatory = $false)]
        [int]$PercentComplete = -1,
        
        [Parameter(Mandatory = $false)]
        [string]$TenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$ReportType,
        
        [Parameter(Mandatory = $false)]
        [switch]$Completed
    )
    
    try {
        # Update process state if tenant and report type are provided
        if ($TenantId -and $ReportType) {
            $tenantName = if ($script:ProcessState.ProcessedTenants[$TenantId]) {
                $script:ProcessState.ProcessedTenants[$TenantId].TenantName
            } else {
                $TenantId
            }
            
            $state = "InProgress"
            if ($Completed) {
                $state = "Completed"
            }
            
            Update-CSPProcessState -TenantId $TenantId -TenantName $tenantName -ReportType $ReportType -Status $state -Data @{
                PercentComplete = $PercentComplete
                Status = $Status
            }
        }
        
        # Write progress
        if ($Completed) {
            Write-Progress -Activity $Activity -Completed
        }
        else {
            Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
        }
    }
    catch {
        Write-Error "Error in Write-CSPProgress: $_"
    }
}

function Invoke-CSPWithRetry {
    <#
    .SYNOPSIS
        Invokes a command with retry logic.
    
    .DESCRIPTION
        Invokes a command with retry logic for handling transient errors and rate limiting.
    
    .PARAMETER ScriptBlock
        The script block to invoke.
    
    .PARAMETER MaxRetries
        The maximum number of retry attempts.
    
    .PARAMETER RetryDelaySeconds
        The delay between retry attempts in seconds.
    
    .PARAMETER RetryStatusCodes
        HTTP status codes that should trigger a retry.
    
    .PARAMETER ActivityName
        The name of the activity for progress reporting.
    
    .EXAMPLE
        Invoke-CSPWithRetry -ScriptBlock { Get-MgUser -UserId "user@contoso.com" } -MaxRetries 3 -RetryDelaySeconds 2
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRetries = 3,
        
        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 2,
        
        [Parameter(Mandatory = $false)]
        [int[]]$RetryStatusCodes = @(429, 503, 504),
        
        [Parameter(Mandatory = $false)]
        [string]$ActivityName = "API Operation",
        
        [Parameter(Mandatory = $false)]
        [object]$ArgumentList
    )
    
    try {
        $retryCount = 0
        $success = $false
        $result = $null
        $lastError = $null
        
        while (-not $success -and $retryCount -le $MaxRetries) {
            try {
                if ($retryCount -gt 0) {
                    Write-CSPLog -Message "Retry attempt $retryCount of $MaxRetries for $ActivityName" -Level "INFO"
                    
                    # Progressive back-off for retries
                    $delay = $RetryDelaySeconds * [Math]::Pow(2, $retryCount - 1)
                    Write-CSPLog -Message "Waiting $delay seconds before retry..." -Level "INFO"
                    Start-Sleep -Seconds $delay
                }
                
                # Execute the command
                if ($ArgumentList) {
                    $result = & $ScriptBlock $ArgumentList
                } else {
                    $result = & $ScriptBlock
                }
                $success = $true
            }
            catch {
                $lastError = $_
                
                # Check if the error is due to rate limiting or a transient error
                $statusCode = $null
                
                # Try to extract status code from different exception types
                if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
                    $statusCode = [int]$_.Exception.Response.StatusCode
                }
                elseif ($_.Exception.Message -match "Response status code does not indicate success: (\d+)") {
                    $statusCode = [int]$Matches[1]
                }
                
                if ($statusCode -and $RetryStatusCodes -contains $statusCode) {
                    $retryCount++
                    
                    # For 429 (Too Many Requests), check for Retry-After header
                    if ($statusCode -eq 429 -and $_.Exception.Response.Headers["Retry-After"]) {
                        $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"]
                        Write-CSPLog -Message "Rate limit hit. Retry-After header suggests waiting $retryAfter seconds." -Level "WARNING"
                        Start-Sleep -Seconds $retryAfter
                    }
                    
                    Write-CSPLog -Message "Transient error (Status Code: $statusCode) in $ActivityName. Retrying..." -Level "WARNING"
                }
                else {
                    # Non-retryable error
                    $errorMessage = $_.Exception.Message
                    Write-CSPLog -Message "Non-retryable error in $ActivityName. Error: $errorMessage" -Level "ERROR"
                    throw
                }
            }
        }
        
        if (-not $success) {
            Write-CSPLog -Message "Failed after $MaxRetries retry attempts: $lastError" -Level "ERROR"
            throw $lastError
        }
        
        return $result
    }
    catch {
        Write-Error "Error in Invoke-CSPWithRetry: $_"
        throw
    }
}

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
        [ValidateSet("INFO", "WARNING", "ERROR", "DEBUG", "SUCCESS")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory = $false)]
        [string]$LogFilePath,
        
        [Parameter(Mandatory = $false)]
        [switch]$NoConsole,
        
        [Parameter(Mandatory = $false)]
        [switch]$UseColor
    )
    
    try {
        # Format the log message
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $logMessage = "[$timestamp] [$Level] $Message"
        
        # Write to console if not suppressed
        if (-not $NoConsole) {
            if ($UseColor) {
                # Use color coding based on level
                switch ($Level) {
                    "INFO" { Write-CSPColorMessage -Message $logMessage -ForegroundColor White }
                    "WARNING" { Write-CSPColorMessage -Message $logMessage -ForegroundColor Yellow }
                    "ERROR" { Write-CSPColorMessage -Message $logMessage -ForegroundColor Red }
                    "DEBUG" { Write-CSPColorMessage -Message $logMessage -ForegroundColor Gray }
                    "SUCCESS" { Write-CSPColorMessage -Message $logMessage -ForegroundColor Green }
                    default { Write-Host $logMessage }
                }
            }
            else {
                # Use standard Write-Host with colors
                switch ($Level) {
                    "INFO" { Write-Host $logMessage -ForegroundColor White }
                    "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
                    "ERROR" { Write-Host $logMessage -ForegroundColor Red }
                    "DEBUG" { Write-Host $logMessage -ForegroundColor Gray }
                    "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
                    default { Write-Host $logMessage }
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

#region New Functions from Alternative Script

function Initialize-CSPTerminalColors {
    <#
    .SYNOPSIS
        Initializes the terminal colors for color-coded output.
    
    .DESCRIPTION
        Saves the current terminal foreground and background colors to restore them later.
    
    .EXAMPLE
        Initialize-CSPTerminalColors
    #>
    [CmdletBinding()]
    param()
    
    try {
        $script:OriginalForegroundColor = $Host.UI.RawUI.ForegroundColor
        $script:OriginalBackgroundColor = $Host.UI.RawUI.BackgroundColor
        
        Write-Verbose "Initialized terminal colors. Original FG: $($script:OriginalForegroundColor), BG: $($script:OriginalBackgroundColor)"
        
        return $true
    }
    catch {
        Write-Error "Error initializing terminal colors: $_"
        return $false
    }
}

function Set-CSPTerminalColors {
    <#
    .SYNOPSIS
        Sets the terminal colors for color-coded output.
    
    .DESCRIPTION
        Sets the foreground and/or background colors of the terminal.
    
    .PARAMETER ForegroundColor
        The foreground color to set.
    
    .PARAMETER BackgroundColor
        The background color to set.
    
    .PARAMETER RestoreOriginal
        If specified, restores the original terminal colors.
    
    .EXAMPLE
        Set-CSPTerminalColors -ForegroundColor White -BackgroundColor Blue
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$ForegroundColor,
        
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$BackgroundColor,
        
        [Parameter(Mandatory = $false)]
        [switch]$RestoreOriginal
    )
    
    try {
        if ($RestoreOriginal) {
            if ($script:OriginalForegroundColor -ne $null) {
                $Host.UI.RawUI.ForegroundColor = $script:OriginalForegroundColor
            }
            
            if ($script:OriginalBackgroundColor -ne $null) {
                $Host.UI.RawUI.BackgroundColor = $script:OriginalBackgroundColor
            }
        }
        else {
            if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
                $Host.UI.RawUI.ForegroundColor = $ForegroundColor
            }
            
            if ($PSBoundParameters.ContainsKey('BackgroundColor')) {
                $Host.UI.RawUI.BackgroundColor = $BackgroundColor
            }
        }
        
        return $true
    }
    catch {
        Write-Error "Error setting terminal colors: $_"
        return $false
    }
}

function Write-CSPColorMessage {
    <#
    .SYNOPSIS
        Writes a colored message to the console.
    
    .DESCRIPTION
        Writes a message to the console with the specified colors, restoring the original colors afterward.
    
    .PARAMETER Message
        The message to write.
    
    .PARAMETER ForegroundColor
        The foreground color for the message.
    
    .PARAMETER BackgroundColor
        The background color for the message.
    
    .PARAMETER Type
        A predefined color scheme type. Valid values are "Info", "Warning", "Error", "Success".
    
    .EXAMPLE
        Write-CSPColorMessage -Message "This is an error" -Type Error
    
    .EXAMPLE
        Write-CSPColorMessage -Message "Custom colors" -ForegroundColor Yellow -BackgroundColor Blue
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$ForegroundColor,
        
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$BackgroundColor,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Type
    )
    
    try {
        # Initialize colors if not already done
        if ($script:OriginalForegroundColor -eq $null -or $script:OriginalBackgroundColor -eq $null) {
            Initialize-CSPTerminalColors
        }
        
        # Save current colors to restore
        $currentFG = $Host.UI.RawUI.ForegroundColor
        $currentBG = $Host.UI.RawUI.BackgroundColor
        
        # Set colors based on type or parameters
        if ($Type) {
            switch ($Type) {
                "Info" {
                    $Host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::Black
                    $Host.UI.RawUI.BackgroundColor = [System.ConsoleColor]::Cyan
                }
                "Warning" {
                    $Host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::Black
                    $Host.UI.RawUI.BackgroundColor = [System.ConsoleColor]::Yellow
                }
                "Error" {
                    $Host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::Black
                    $Host.UI.RawUI.BackgroundColor = [System.ConsoleColor]::Red
                }
                "Success" {
                    $Host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::Black
                    $Host.UI.RawUI.BackgroundColor = [System.ConsoleColor]::Green
                }
            }
        }
        else {
            if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
                $Host.UI.RawUI.ForegroundColor = $ForegroundColor
            }
            
            if ($PSBoundParameters.ContainsKey('BackgroundColor')) {
                $Host.UI.RawUI.BackgroundColor = $BackgroundColor
            }
        }
        
        # Write the message
        Write-Host $Message
        
        # Restore colors
        $Host.UI.RawUI.ForegroundColor = $currentFG
        $Host.UI.RawUI.BackgroundColor = $currentBG
        
        return $true
    }
    catch {
        # In case of error, try to restore colors
        try {
            $Host.UI.RawUI.ForegroundColor = $currentFG
            $Host.UI.RawUI.BackgroundColor = $currentBG
        }
        catch {}
        
        Write-Error "Error writing colored message: $_"
        return $false
    }
}

function Initialize-CSPModules {
    <#
    .SYNOPSIS
        Initializes required PowerShell modules for CSP reporting.
    
    .DESCRIPTION
        Checks if required modules are installed, installs them if not, removes older versions,
        checks for updates, and imports the modules. This provides a more comprehensive module
        management approach compared to Test-CSPModuleAvailability.
    
    .PARAMETER ModuleNames
        An array of module names to initialize.
    
    .PARAMETER Force
        Forces reinstallation of modules even if they already exist.
    
    .EXAMPLE
        Initialize-CSPModules -ModuleNames "Microsoft.Graph", "Az.Accounts"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string[]]$ModuleNames,
        
        [Parameter(Mandatory = $false)]
        [switch]$Force
    )
    
    try {
        # Initialize results
        $results = @()
        
        # Process each module
        foreach ($moduleName in $ModuleNames) {
            # Capture output but don't add to results
            $null = Write-CSPLog -Message "Checking if module '$moduleName' is installed..." -Level "INFO" -UseColor
            Write-CSPLog -Message "Checking if module '$moduleName' is installed..." -Level "INFO" -UseColor
            
            try {
                # Check if module is installed
                $moduleInstalled = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue
                
                if (!$moduleInstalled -or $Force) {
                    $null = Write-CSPLog -Message "Module '$moduleName' is not installed or reinstall forced. Installing now..." -Level "WARNING" -UseColor
                    
                    # Ensure NuGet provider is installed
                    if (-not (Get-PackageProvider -Name NuGet -ListAvailable -ErrorAction SilentlyContinue)) {
                        $null = Write-CSPLog -Message "Installing NuGet package provider..." -Level "INFO" -UseColor
                        Install-PackageProvider -Name NuGet -Force -Scope CurrentUser | Out-Null
                    }
                    
                    # Set PSGallery as trusted
                    $galleryStatus = Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue
                    if ($galleryStatus.InstallationPolicy -ne "Trusted") {
                        $null = Write-CSPLog -Message "Setting PSGallery as trusted repository..." -Level "INFO" -UseColor
                        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
                    }
                    
                    # Install the module
                    Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                    $null = Write-CSPLog -Message "Module '$moduleName' installed successfully" -Level "SUCCESS" -UseColor
                    
                    $moduleInstalled = Get-InstalledModule -Name $moduleName -ErrorAction SilentlyContinue
                    $results += [PSCustomObject]@{
                        ModuleName = $moduleName
                        Status = "Installed"
                        Version = $moduleInstalled.Version
                        LatestVersion = $moduleInstalled.Version
                    }
                }
                else {
                    $null = Write-CSPLog -Message "Module '$moduleName' is already installed" -Level "SUCCESS" -UseColor
                    
                    # Check for duplicate versions
                    $null = Write-CSPLog -Message "Checking for duplicate versions of module '$moduleName'..." -Level "INFO" -UseColor
                    $moduleVersions = Get-InstalledModule -Name $moduleName -AllVersions
                    
                    if ($moduleVersions.Count -gt 1) {
                        $null = Write-CSPLog -Message "Found $($moduleVersions.Count) versions of module '$moduleName'. Removing older versions..." -Level "WARNING" -UseColor
                        $latestVersion = $moduleVersions | Sort-Object -Property Version -Descending | Select-Object -First 1
                        $olderVersions = $moduleVersions | Where-Object { $_.Version -ne $latestVersion.Version }
                        
                        foreach ($olderVersion in $olderVersions) {
                            $null = Write-CSPLog -Message "Removing version $($olderVersion.Version) of module '$moduleName'..." -Level "INFO" -UseColor
                            Uninstall-Module -Name $moduleName -RequiredVersion $olderVersion.Version -Force -ErrorAction SilentlyContinue
                        }
                        
                        $null = Write-CSPLog -Message "Older versions of module '$moduleName' removed" -Level "SUCCESS" -UseColor
                    }
                    else {
                        $null = Write-CSPLog -Message "Only one version of module '$moduleName' found" -Level "INFO" -UseColor
                    }
                    
                    # Check for updates
                    $null = Write-CSPLog -Message "Checking for updates to module '$moduleName'..." -Level "INFO" -UseColor
                    $currentVersion = $moduleInstalled.Version
                    $latestVersion = (Find-Module -Name $moduleName -ErrorAction SilentlyContinue).Version
                    
                    if ($latestVersion -gt $currentVersion) {
                        $null = Write-CSPLog -Message "Update available for module '$moduleName'. Current: $currentVersion, Latest: $latestVersion" -Level "WARNING" -UseColor
                        $null = Write-CSPLog -Message "Installing latest version of module '$moduleName'..." -Level "INFO" -UseColor
                        
                        # Install the latest version
                        Install-Module -Name $moduleName -Scope CurrentUser -Force -AllowClobber
                        $null = Write-CSPLog -Message "Module '$moduleName' updated to version $latestVersion" -Level "SUCCESS" -UseColor
                        
                        $results += [PSCustomObject]@{
                            ModuleName = $moduleName
                            Status = "Updated"
                            Version = $latestVersion
                            PreviousVersion = $currentVersion
                        }
                    }
                    else {
                        $null = Write-CSPLog -Message "Module '$moduleName' is up to date (version $currentVersion)" -Level "SUCCESS" -UseColor
                        
                        $results += [PSCustomObject]@{
                            ModuleName = $moduleName
                            Status = "UpToDate"
                            Version = $currentVersion
                            LatestVersion = $latestVersion
                        }
                    }
                }
                
                # Import the module
                $null = Write-CSPLog -Message "Importing module '$moduleName'..." -Level "INFO" -UseColor
                
                if (-not (Get-Module -Name $moduleName)) {
                    Import-Module -Name $moduleName -ErrorAction Stop
                    $null = Write-CSPLog -Message "Module '$moduleName' imported successfully" -Level "SUCCESS" -UseColor
                }
                else {
                    $null = Write-CSPLog -Message "Module '$moduleName' is already imported" -Level "SUCCESS" -UseColor
                }
            }
            catch {
                $null = Write-CSPLog -Message "Error processing module '$moduleName': $($_.Exception.Message)" -Level "ERROR" -UseColor
                $results += [PSCustomObject]@{
                    ModuleName = $moduleName
                    Status = "Error"
                    ErrorMessage = $_.Exception.Message
                }
            }
        }
        
        # Validate results before returning
        $null = Write-CSPLog -Message "Validating module results before returning..." -Level "INFO" -UseColor
        $validatedResults = @()
        foreach ($result in $results) {
            if ($null -eq $result) {
                $null = Write-CSPLog -Message "Found null result in module results" -Level "WARNING" -UseColor
                continue
            }
            # Ensure Status property exists
            if (-not (Get-Member -InputObject $result -Name "Status" -MemberType Properties)) {
                $null = Write-CSPLog -Message "Result for module does not have Status property, adding default Error status" -Level "WARNING" -UseColor
                $result | Add-Member -MemberType NoteProperty -Name "Status" -Value "Error" -Force
                $result | Add-Member -MemberType NoteProperty -Name "ErrorMessage" -Value "Status property was missing" -Force
            }
            
            $validatedResults += $result
        }
        
        $null = Write-CSPLog -Message "Returning $($validatedResults.Count) validated module results" -Level "INFO" -UseColor
        
        # Restore original Write-CSPLog function
        if (Test-Path "Function:\script:OriginalWrite-CSPLog") {
            Copy-Item -Path "Function:\script:OriginalWrite-CSPLog" -Destination "Function:\Write-CSPLog" -Force
            Remove-Item -Path "Function:\script:OriginalWrite-CSPLog" -Force
        }
        
        return $validatedResults
    }
    catch {
        # Restore original Write-CSPLog function even if there's an error
        if (Test-Path "Function:\script:OriginalWrite-CSPLog") {
            Copy-Item -Path "Function:\script:OriginalWrite-CSPLog" -Destination "Function:\Write-CSPLog" -Force
            Remove-Item -Path "Function:\script:OriginalWrite-CSPLog" -Force
        }
        
        $null = Write-CSPLog -Message "Error in Initialize-CSPModules: $($_.Exception.Message)" -Level "ERROR" -UseColor
        throw
    }
}

function Invoke-CSPAdminConsent {
    <#
    .SYNOPSIS
        Grants admin consent for the app in a customer tenant.
    
    .DESCRIPTION
        Automates the process of granting admin consent for a multi-tenant app in a customer tenant,
        similar to the consent automation in the alternative script.
    
    .PARAMETER ClientId
        The application (client) ID of the CSP application.
    
    .PARAMETER ClientSecret
        The client secret of the CSP application. Required for client secret authentication.
    
    .PARAMETER CertificatePath
        The path to the certificate file for certificate-based authentication.
    
    .PARAMETER CertificatePassword
        The password for the certificate. Required for certificate-based authentication.
    
    .PARAMETER PartnerTenantId
        The tenant ID of the partner (CSP) tenant.
    
    .PARAMETER CustomerTenantId
        The tenant ID of the customer tenant where consent is needed.
    
    .PARAMETER AppDisplayName
        The display name to use for the app in the customer tenant.
    
    .PARAMETER RequiredScopes
        Array of required Microsoft Graph API permission scopes.
    
    .EXAMPLE
        Invoke-CSPAdminConsent -ClientId "00000000-0000-0000-0000-000000000000" -ClientSecret $secureClientSecret -PartnerTenantId "partner.onmicrosoft.com" -CustomerTenantId "customer.onmicrosoft.com" -AppDisplayName "CSP Reporting App"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$ClientId,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$ClientSecret,
        
        [Parameter(Mandatory = $false)]
        [string]$CertificatePath,
        
        [Parameter(Mandatory = $false)]
        [SecureString]$CertificatePassword,
        
        [Parameter(Mandatory = $true)]
        [string]$PartnerTenantId,
        
        [Parameter(Mandatory = $true)]
        [string]$CustomerTenantId,
        
        [Parameter(Mandatory = $false)]
        [string]$AppDisplayName = "CSP Reporting App",
        
        [Parameter(Mandatory = $false)]
        [string[]]$RequiredScopes = @(
            "Directory.Read.All",
            "Directory.AccessAsUser.All",
            "User.Read",
            "AuditLog.Read.All",
            "Reports.Read.All"
        )
    )
    
    try {
        # Verify that one authentication method is provided
        if ((-not $ClientSecret) -and (-not ($CertificatePath -and $CertificatePassword))) {
            throw "Either ClientSecret or CertificatePath and CertificatePassword must be provided"
        }
        
        Write-CSPLog -Message "Starting admin consent process for app $ClientId in tenant $CustomerTenantId" -Level "INFO" -UseColor
        
        # Check if Microsoft Graph Authentication module is available
        Write-CSPLog -Message "Checking for required PowerShell modules..." -Level "INFO" -UseColor
        $requiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Applications")
        $missingModules = $requiredModules | Where-Object { -not (Get-Module -Name $_ -ListAvailable) }
        
        if ($missingModules) {
            Write-CSPLog -Message "Installing required modules: $($missingModules -join ', ')" -Level "WARNING" -UseColor
            foreach ($module in $missingModules) {
                Install-Module -Name $module -Scope CurrentUser -Force
            }
        }
        
        # Get admin consent URL
        $baseUrl = "https://login.microsoftonline.com/$CustomerTenantId/adminconsent"
        $params = @{
            client_id = $ClientId
            redirect_uri = "https://portal.azure.com"
            state = [Guid]::NewGuid().ToString()
        }
        
        $queryString = [System.Web.HttpUtility]::ParseQueryString([String]::Empty)
        foreach ($key in $params.Keys) {
            $queryString.Add($key, $params[$key])
        }
        
        $uriBuilder = New-Object System.UriBuilder($baseUrl)
        $uriBuilder.Query = $queryString.ToString()
        $consentUrl = $uriBuilder.Uri.ToString()
        
        Write-CSPLog -Message "Admin consent URL for manual consent (if automation fails):" -Level "INFO" -UseColor
        Write-CSPLog -Message $consentUrl -Level "INFO" -UseColor
        
        # Get access token for partner tenant
        Write-CSPLog -Message "Authenticating to partner tenant ($PartnerTenantId)..." -Level "INFO" -UseColor
        
        if ($ClientSecret) {
            # Client secret auth
            $tokenBody = @{
                grant_type    = "client_credentials"
                client_id     = $ClientId
                client_secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($ClientSecret))
                scope         = "https://graph.microsoft.com/.default"
            }
            
            $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$PartnerTenantId/oauth2/v2.0/token" -Method Post -Body $tokenBody
            $accessToken = $tokenResponse.access_token
        }
        else {
            # Certificate auth
            $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
            $cert.Import($CertificatePath, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
            
            Connect-MgGraph -ClientId $ClientId -TenantId $PartnerTenantId -Certificate $cert
            $accessToken = (Get-MgContext).AccessToken
        }
        
        if (-not $accessToken) {
            throw "Failed to obtain access token from partner tenant"
        }
        
        Write-CSPLog -Message "Successfully authenticated to partner tenant" -Level "SUCCESS" -UseColor
        
        # Build HTTP request to grant consent
        Write-CSPLog -Message "Requesting admin consent for app in customer tenant..." -Level "INFO" -UseColor
        
        $headers = @{
            "Authorization" = "Bearer $accessToken"
            "Content-Type"  = "application/json"
        }
        
        # Format scopes as required by the API
        $formattedScopes = $RequiredScopes | ForEach-Object { "https://graph.microsoft.com/$_" }
        
        $body = @{
            clientId    = $ClientId
            displayName = $AppDisplayName
            scopes      = $formattedScopes
        } | ConvertTo-Json
        
        # Make the API call to grant consent
        $url = "https://graph.microsoft.com/v1.0/tenants/$CustomerTenantId/adminConsentRequests"
        
        try {
            $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $body
            Write-CSPLog -Message "Admin consent request submitted successfully" -Level "SUCCESS" -UseColor
            Write-CSPLog -Message "Request ID: $($response.id)" -Level "INFO" -UseColor
            
            return @{
                Success = $true
                RequestId = $response.id
                Message = "Admin consent request submitted successfully"
            }
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            $message = $_.ErrorDetails.Message
            
            Write-CSPLog -Message "Failed to submit admin consent request. Status code: $statusCode" -Level "ERROR" -UseColor
            Write-CSPLog -Message "Error message: $message" -Level "ERROR" -UseColor
            Write-CSPLog -Message "Please use the manual consent URL provided earlier" -Level "WARNING" -UseColor
            
            return @{
                Success = $false
                StatusCode = $statusCode
                Message = $message
                ManualConsentUrl = $consentUrl
            }
        }
    }
    catch {
        Write-CSPLog -Message "Error in Invoke-CSPAdminConsent: $($_.Exception.Message)" -Level "ERROR" -UseColor
        return @{
            Success = $false
            Error = $_.Exception.Message
            ManualConsentUrl = $consentUrl
        }
    }
}

#endregion

# Export public functions
Export-ModuleMember -Function Write-CSPLog, Test-CSPAdminConsent, New-CSPSelfSignedCertificate, Get-CSPCertificateThumbprint, Test-CSPModuleAvailability, Initialize-CSPProcessState, Update-CSPProcessState, Get-CSPProcessState, Write-CSPProgress, Invoke-CSPWithRetry, Initialize-CSPTerminalColors, Set-CSPTerminalColors, Write-CSPColorMessage, Initialize-CSPModules, Invoke-CSPAdminConsent